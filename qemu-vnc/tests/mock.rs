//! The D-Bus half, against a stand-in for QEMU.
//!
//! `qemu-vnc` is a D-Bus *client*: it reads a VM's consoles, listens to their
//! scanouts, and sends input back. These tests drive the real [`Server`] over a
//! real bus against [`MockQemu`], so what is exercised is the whole path — the
//! proxies in `qemu-display`, the signal names, the property types, the
//! peer-to-peer listener connection — rather than the callbacks behind it.
//!
//! That is what the unit tests in `display.rs` and `input.rs` were standing in
//! for. They are gone; these replace them.
//!
//! Every test needs a session bus. A machine without one does not fail: the
//! tests skip, because the absence of a bus says nothing about the code.

mod common;
// A crate root resolves its modules from the directory it is in, so `mod qemu`
// would look for `tests/qemu.rs`. The mock lives in `tests/mock/` with this
// file, because it belongs to this binary alone: it is the only test that
// builds a stand-in for QEMU, and the others should not pay to compile one.
#[path = "mock/qemu.rs"]
mod qemu;

use std::io::{self, Write};
use std::time::Duration;

use qemu::{Key, MockQemu, Mouse};
use common::rfb_client;
use qemu_display::{ClipboardSelection, MouseButton};
use qemu_vnc::server::{Server, Share};

/// The console size the tests use: small enough that a frame is a few thousand
/// bytes, big enough that a rectangle is a rectangle.
const WIDTH: u16 = 64;
const HEIGHT: u16 = 32;

/// The same, as the mock reports it.
const SIZE: (u32, u32) = (WIDTH as u32, HEIGHT as u32);

/// The console most tests use. The mock has
/// [`qemu::CONSOLES`] of them, and the second is there so a test
/// can prove that a console switch did something.
const FIRST: u32 = 0;

/// How long to wait for something that should have happened already.
const PATIENCE: Duration = Duration::from_secs(5);

/// How many times a test asks again before it gives up.
///
/// The wait is a poll, not a sleep, so a test that is going to succeed usually
/// succeeds on the first or second try; the count only decides how long a
/// failure takes to be reported.
const ATTEMPTS: usize = 40;

/// A mock QEMU with its console, and the connection a client talks to it on.
///
/// The two ends of a peer-to-peer socket pair, which is what
/// `--dbus-p2p-fd` gives the real program: no well-known name to own, no bus
/// to be absent, and nothing shared between parallel tests.
async fn mock() -> (MockQemu, zbus::Connection) {
    MockQemu::start(SIZE)
        .await
        .expect("the mock to export its interfaces")
}

/// Run a test body, skipping it when there is no bus to run it on.
///
/// The `mut` form binds the mock mutably, for the tests that resize a console
/// before pushing a frame to it.
macro_rules! on_a_bus {
    (|$mock:ident, $connection:ident| $body:block) => {
        async_io::block_on(async {
            let ($mock, $connection) = mock().await;
            async move $body.await
        });
    };
    (|mut $mock:ident, $connection:ident| $body:block) => {
        async_io::block_on(async {
            // The `mut` has to be here and not in the closure's pattern: `|mut x|`
            // destructures an argument, and the binding it makes is not the
            // mutable local this `let` creates.
            let (mut $mock, $connection) = mock().await;
            async move $body.await
        });
    };
}

/// Wait for the server to hold `n` clients, polling rather than sleeping.
async fn wait_for_clients(server: &Server, n: usize) {
    for _ in 0..ATTEMPTS {
        if server.clients().len() == n {
            return;
        }
        async_io::Timer::after(Duration::from_millis(25)).await;
    }
    panic!(
        "the server still holds {} clients, not {n}: {:#?}",
        server.clients().len(),
        server.clients()
    );
}

/// A client that goes away is forgotten, and its name says so.
///
/// **This path had no test at all**, which is why a symptom seen once in the
/// reference-client fixture — a client task ending with `client read error:
/// disconnected` and nothing in the log saying the server had noticed — could
/// not be localised: there was nothing to compare it against. Everything the
/// disconnect path does is asserted here instead, so that if the shape ever
/// comes back it has a reference.
///
/// The assertion is on `server.clients()`, which is what the rest of the server
/// reads: a client left in that table keeps getting damage notifications and
/// keeps being handed work for a socket nobody is reading. The event is the
/// other half, because the two are separate acts and either could be dropped
/// while the other happened.
#[test]
fn a_client_that_goes_away_is_forgotten() {
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a read timeout");
        wait_for_clients(&server, 1).await;

        // Gone, without a goodbye: a client that is killed, or a viewer that
        // loses its network, does not send anything first.
        drop(client);
        wait_for_clients(&server, 0).await;
    });
}

/// The server can hang up on a client that has not said anything yet.
///
/// The other direction, and a different piece of code: the server holds a
/// shutdown handle and shuts the socket down, which has to wake the task
/// wherever it is parked. If that does not work the client sits there until the
/// read times out or never, and the table entry outlives the request -- the
/// same leak from the other end.
///
/// This test is written **without a handshake on purpose**. It is the case that
/// failed, and it is the common one: a client that connects and then goes quiet
/// is a port scanner, a misconfigured viewer or a hung one, and it is exactly
/// what `disconnect_client` exists for.
#[test]
fn a_client_the_server_hangs_up_on_is_forgotten() {
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        // **No handshake.** This is the case that was broken, and it is the
        // common one in production: a client that opens a connection and then
        // says nothing is a port scanner, a misconfigured viewer or a hung
        // one, and it is exactly what `disconnect_client` is for. Before the
        // fix the shutdown handle did not exist until the handshake finished
        // and the `Terminate` event was queued for a task parked on the
        // handshake, so the call did nothing and the entry stayed in the table
        // for the life of the process.
        let (_client, _addr) = listener_for(&server).await;
        wait_for_clients(&server, 1).await;

        let id = server.clients()[0].id;
        server.disconnect_client(id);
        wait_for_clients(&server, 0).await;
    });
}

/// A client that goes away mid-session does not stop the console.
///
/// The disconnect tests above cover the bookkeeping. This covers the thing that
/// actually matters when it goes wrong: **one client's departure must not stop
/// the others**. The fixture's symptom was a task ending and no evidence that
/// the console still worked afterwards, so this sends a frame while a second
/// client is connected and disconnects the first, and asserts the second is
/// still served.
///
/// Two clients rather than one-then-another, because the failure this is for is
/// a shared one -- a console-wide flag, a poisoned lock, a drained event queue
/// -- and a sequential test cannot produce it.
#[test]
fn one_client_leaving_does_not_stop_the_others() {
    on_a_bus!(|mut mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut leaver, _a) = listener_for(&server).await;
        let (mut stayer, _b) = listener_for(&server).await;
        for c in [&mut leaver, &mut stayer] {
            handshake(c);
            c.set_read_timeout(Some(Duration::from_millis(500)))
                .expect("a read timeout");
        }
        rfb_client::send_set_encodings(&mut leaver, &[rfb_client::encoding::RAW]);
        rfb_client::send_set_encodings(&mut stayer, &[rfb_client::encoding::RAW]);
        wait_for_clients(&server, 2).await;
        mock.resize(FIRST, (1280, 800));

        // A first frame, so both clients have seen the console work and the
        // staying one has a frame to compare against later.
        mock.scanout(FIRST, desktop(1280, 800))
            .await
            .expect("the first screen");
        for c in [&mut leaver, &mut stayer] {
            let mut reader = rfb_client::SyncReader::new(4);
            let mut decoders = rfb_client::Decoders::new();
            rfb_client::request_update(c, 0, 0, 1280, 800);
            let _ = reader.read_update(c);
            let _ = rfb_client::try_read_update_rects(c, &mut decoders);
        }

        // The first one leaves, mid-session, having already been served.
        drop(leaver);
        wait_for_clients(&server, 1).await;

        // And the console still reaches the one that stayed.
        let mut screen = desktop(1280, 800);
        for y in 0..800usize {
            for x in 640..704usize {
                let o = (y * 1280 + x) * 4;
                screen[o] = 0xff;
                screen[o + 1] = 0x00;
                screen[o + 2] = 0xff;
                screen[o + 3] = 0x00;
            }
        }
        mock.update(FIRST, (0, 0, 1280, 800), screen)
            .await
            .expect("the repaint");

        let mut decoders = rfb_client::Decoders::new();
        rfb_client::request_update(&mut stayer, 0, 0, 1280, 800);
        let rects = rfb_client::try_read_update_rects(&mut stayer, &mut decoders).unwrap_or_else(
            |e| panic!("the client that stayed was not served after the other left: {e}"),
        );
        assert!(
            rects.iter().any(|r| r.encoding >= 0),
            "the console stopped updating when the first client disconnected: no \
             rectangle came back at all, so the console's update path is gated on \
             the client list rather than on who is reading"
        );
    });
}

/// A server attached to the mock's console, as `main.rs` attaches one.
///
/// This is the part the unit tests could not do: `add_graphic_console` reads
/// the console's `Width` and `Height` over the bus and then registers the
/// listener, which is what gives the mock a connection to push pixels down.
async fn server_for(mock: &MockQemu, connection: &zbus::Connection) -> Server {
    server_with_console(mock, connection, [FIRST]).await
}

/// A server with `consoles` graphic consoles added, as `main.rs` adds them.
///
/// This is the part the unit tests could not do: `add_graphic_console` reads
/// the console's `Width` and `Height` over the bus and then registers the
/// listener, which is what gives the mock a connection to push pixels down.
/// Registering more than one is what a console switch needs.
async fn server_with_console(
    mock: &MockQemu,
    connection: &zbus::Connection,
    consoles: impl IntoIterator<Item = u32>,
) -> Server {
    let server = Server::new(connection, "mock", Share::Ignore)
        .await
        .expect("a server");
    let added: Vec<u32> = consoles.into_iter().collect();
    for index in &added {
        server
            .add_graphic_console(*index)
            .await
            .expect("the console to be added");
    }
    for index in added {
        mock.wait_registered(index).await;
    }
    server
}

/// A listening socket for the server, and a client already connected to it.
///
/// The server's own accept loop is `main.rs`'s, which the library does not
/// own, so a test opens the socket and hands the connection over itself.
async fn listener_for(server: &Server) -> (std::net::TcpStream, std::net::SocketAddr) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let addr = listener.local_addr().expect("an address");
    let client = std::net::TcpStream::connect(addr).expect("a connection");
    let (stream, _peer) = listener.accept().expect("the connection");
    server.add_client(stream, addr).expect("the client to be added");
    // The client is served by a task of its own, which needs a moment to reach
    // the handshake before the test writes to it.
    async_io::Timer::after(Duration::from_millis(50)).await;
    (client, addr)
}

/// The RFB handshake, for a client of the server under test.
fn handshake(client: &mut std::net::TcpStream) {
    assert_eq!(rfb_client::read_server_version(client), "RFB 003.008");
    rfb_client::negotiate_version(client, "RFB 003.008\n");
    assert_eq!(rfb_client::read_security_types(client, false), vec![1]);
    rfb_client::select_security_type(client, 1);
    assert_eq!(rfb_client::read_security_result(client), 0);
    rfb_client::send_client_init(client, true);
    let (width, height, _) = rfb_client::read_server_init(client);
    assert_eq!((width, height), (WIDTH, HEIGHT));
}

/// Ask for the whole console.
fn request_picture(client: &mut std::net::TcpStream) {
    rfb_client::send_set_encodings(client, &[rfb_client::encoding::RAW]);
    rfb_client::request_update(client, 0, 0, WIDTH, HEIGHT);
}

/// Ask for the console until pixels arrive, and return them decoded into RGB
/// the way `format` says its bytes should be read.
///
/// The first thing it does is throw away whatever the server has already sent,
/// then ask. Both halves are load-bearing, and the reason is the same: the
/// console's pixels arrive on the D-Bus listener's task and the client's
/// messages on its own, so between the two the server can build an update using
/// the pixel format it was using *before* the client asked for another. That
/// update is legal — from the server's side the new format is not in effect
/// until it has read the message — but a test that decodes the first rectangle
/// to arrive with the new format is reading bytes in an order they were not
/// written in, and reports the channels swapped. It only loses under load,
/// which is the worst way for a test to be wrong: it passes on a fast machine
/// and fails on a slow one, and reads as a flake rather than a bug.
///
/// Asking is what fixes it, because a *non-incremental* request is answered
/// unconditionally and the answer is built after every client message queued
/// ahead of it — so it is post-format by construction. Draining first is what
/// stops the already-queued pre-format push from being read in its place, which
/// is a mistake that looks exactly like the first and is not fixed by the
/// second.
fn read_decoded(
    client: &mut std::net::TcpStream,
    format: &qemu_vnc::rfb::PixelFormat,
) -> Vec<[u8; 3]> {
    // Everything the server has already sent: the acknowledgements, and any
    // update it built before the format change took effect. A read that times
    // out is the signal that the socket is quiet, which is what ends this.
    let mut saw: Vec<i32> = Vec::new();
    for _ in 0..16 {
        match rfb_client::try_read_rect(client) {
            Ok((rect, _)) => saw.push(rect.encoding),
            Err(_) => break,
        }
    }
    for _ in 0..40 {
        rfb_client::request_full_update(client, 0, 0, WIDTH, HEIGHT);
        if let Ok((rect, _mask)) = rfb_client::try_read_rect(client) {
            saw.push(rect.encoding);
            if rect.encoding == rfb_client::encoding::RAW {
                return rfb_client::decode_pixels(&rect.pixels, format);
            }
        }
    }
    // What it saw, because "no pixels arrived" on its own is the message that
    // made this helper's earlier version of itself undebuggable: it cannot
    // distinguish "the server sent nothing" from "the server sent things that
    // were not pixels", and those have opposite causes.
    panic!("no pixels arrived; the rectangles seen were {saw:?}");
}

/// Ask for the console until a rectangle with `encoding` arrives, decoded into
/// RGB the way `format` says its bytes should be read.
fn read_decoded_with(
    client: &mut std::net::TcpStream,
    format: &qemu_vnc::rfb::PixelFormat,
    encoding: i32,
) -> Vec<[u8; 3]> {
    let mut decoders = rfb_client::Decoders::new();
    for _ in 0..40 {
        // Read every rectangle of whatever arrives, before asking: the server
        // pushes an update when the console draws, and a reply that is already
        // on its way would be left unread behind a request.
        match rfb_client::try_read_update_rects(client, &mut decoders) {
            Ok(rects) if !rects.is_empty() => {
                let encodings: Vec<i32> = rects.iter().map(|r| r.encoding).collect();
                eprintln!("DBG saw {encodings:?}");
                if let Some(rect) = rects.into_iter().find(|r| r.encoding == encoding) {
                    return rfb_client::decode_pixels(&rect.pixels, format);
                }
                continue;
            }
            _ => {}
        }
        rfb_client::request_update(client, 0, 0, WIDTH, HEIGHT);
    }
    eprintln!("DBG gave up waiting for encoding {encoding}");
    panic!("no rectangle arrived with encoding {encoding}");
}

/// Read and discard the acknowledgements the server sends for a client's
/// `SetPixelFormat` and `SetEncodings`.
///
/// Each is a rectangle with the framebuffer's size and no pixels, and a test
/// that wants pixels afterwards has to get past them. Reading them also makes
/// sure the server has processed the messages that provoked them, which is
/// what a real client does by reading before it asks.
fn drain_acks(client: &mut std::net::TcpStream) {
    for _ in 0..8 {
        let mut decoders = rfb_client::Decoders::new();
        if rfb_client::try_read_update_rects(client, &mut decoders).is_err() {
            break;
        }
    }
}

/// Ask for the console until an update with `wanted` pixels arrives.
///
/// A real viewer asks again after every update, and so must this client: the
/// server sends one update per request, so a request made before the guest drew
/// is answered with what was on screen then. Asking in a loop is also what
/// makes the second read a *test* of the damage tracking rather than a race:
/// the old pixels would come back first, and the wait is what proves the
/// rectangle did.
async fn request_until(client: &mut std::net::TcpStream, wanted: &[u8]) -> Vec<u8> {
    for _ in 0..ATTEMPTS {
        rfb_client::request_update(client, 0, 0, WIDTH, HEIGHT);
        if let Ok(pixels) = rfb_client::try_read_update(client)
            && pixels == wanted
        {
            return pixels;
        }
        async_io::Timer::after(Duration::from_millis(10)).await;
    }
    panic!("the client was never sent the pixels it asked for");
}

/// A frame of the test's pixels, in the `x8r8g8b8` the mock pushes.
fn frame() -> Vec<u8> {
    frame_tinted(0x7f)
}

/// A frame like [`frame`] with the marked pixels in a different shade.
///
/// Needed whenever a test draws twice and expects two frames out. The server
/// finds damage by comparing each update against a copy of the surface, so a
/// repaint of **identical** pixels is not damage at all — which is the point
/// of the comparison, and a trap for a test whose subject is something else.
/// A test that means to be about deferral, or about the interval, or about the
/// encoder, has to make the second draw actually differ, or it will sit waiting
/// for a frame the server is right not to send.
fn frame_tinted(red: u8) -> Vec<u8> {
    (0..(WIDTH as usize * HEIGHT as usize))
        .flat_map(|i| {
            if i % 4 == 0 {
                [red, 0x00, 0x00, 0x00]
            } else {
                [0x00; 4]
            }
        })
        .collect()
}

/// Wait for a condition and return what it saw.
///
/// `what` is called over and over and `ready` says whether what it returned is
/// what the test is waiting for. `waiting` goes in the failure: a test that
/// waits for three things in a row and fails has to say *which*, and a message
/// that only names the last value seen makes that guesswork.
async fn wait_for<T: std::fmt::Debug>(
    waiting: &str,
    mut what: impl FnMut() -> T,
    ready: impl Fn(&T) -> bool,
) -> T {
    let deadline = async_io::Timer::after(PATIENCE);
    futures::pin_mut!(deadline);
    loop {
        let seen = what();
        if ready(&seen) {
            return seen;
        }
        if futures::poll!(&mut deadline).is_ready() {
            panic!("never {waiting}; last seen: {seen:?}");
        }
        async_io::Timer::after(Duration::from_millis(10)).await;
    }
}

#[test]
fn a_client_of_the_server_sees_a_scanout_of_the_console() {
    // The whole path in one test: the mock pushes a scanout over the
    // peer-to-peer connection, the server composites it, and a VNC client gets
    // the pixels back over a socket.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);
            request_picture(&mut client);

            // Nothing has been drawn yet, so the console is black.
            let black = rfb_client::read_update(&mut client);
            assert_eq!(black, vec![0; WIDTH as usize * HEIGHT as usize * 4]);

            // Now the guest draws, which is the mock pushing a scanout.
            mock.scanout(FIRST, frame()).await.expect("the scanout arrives");
            let pixels = request_until(&mut client, &frame()).await;
            assert_eq!(pixels, frame(), "the scanout should reach the client");
    });
}

#[test]
fn only_the_damaged_part_of_a_console_is_sent_again() {
    // A scanout is the whole console; an update is a rectangle of it. What
    // proves the damage tracking is the second one: the client must be sent
    // the rectangle, not the whole console again.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);
            request_picture(&mut client);
            let _ = rfb_client::try_read_update(&mut client);

            // One pixel, in the middle of the console.
            mock.update(
                FIRST,
                (10, 10, 1, 1),
                vec![0x11, 0x22, 0x33, 0x00],
            )
                .await
                .expect("the update arrives");
            let pixels = request_until(&mut client, &[0x11, 0x22, 0x33, 0x00]).await;
            assert_eq!(
                pixels,
                vec![0x11, 0x22, 0x33, 0x00],
                "only the damaged pixel should have been sent, got {} bytes: {pixels:02x?}",
                pixels.len()
            );
    });
}

#[test]
fn a_key_from_the_client_arrives_at_the_console() {
    // The input path, the other way round: a key on the wire becomes a
    // `Keyboard.PressKey` on the bus.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);

            rfb_client::send_key(&mut client, 0x41, true);
            rfb_client::send_key(&mut client, 0x41, false);
            rfb_client::send_key(&mut client, 0x42, true);

            let keys = wait_for("the keys reached the console", || mock.keys(), |keys| keys.len() >= 3).await;
            assert_eq!(
                keys,
                vec![
                    Key {
                        // 0x41 is the keysym for A. The client is keymap
                        // independent, so what the console gets is a *QEMU key
                        // number*: keycodemapdb's AT set 1 scancode for A is
                        // `0x1e`, which is 30. `qemu-vnc/c/input.c` converts the
                        // same way with `qemu_input_map_linux_to_qnum[lnx]`.
                        keycode: 30,
                        down: true
                    },
                    Key {
                        keycode: 30,
                        down: false
                    },
                    Key {
                        // 0x42 is B, scancode `0x30`, 48.
                        keycode: 48,
                        down: true
                    },
                ],
                "the keysyms should become key numbers, and their order should hold"
            );
    });
}

/// The reported fault: `1`..`7` typed the wrong keys.
///
/// **The regression test for the user's report.** The keysyms a browser sends
/// for those digits must reach the console as scancodes 2..8 -- the numbers
/// whose own Linux keys are `1`..`7`. With the old `+ 8` offset they arrived as
/// 10..16, which QEMU decodes as `9`, `0`, `-`, `=`, Backspace, Tab and `q`.
#[test]
fn the_reported_digits_arrive_as_their_own_keys() {
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);

        for ch in '1'..='7' {
            rfb_client::send_key(&mut client, ch as u32, true);
        }

        let keys = wait_for(
            "the digits reached the console",
            || mock.keys(),
            |keys| keys.len() >= 7,
        )
        .await;
        assert_eq!(
            keys.iter().map(|key| key.keycode).collect::<Vec<_>>(),
            vec![2, 3, 4, 5, 6, 7, 8],
            "pressing 1..7 must send each digit's own scancode"
        );
    });
}

/// An extended key event already carries the QEMU key number.
///
/// noVNC sends the AT set 1 scancode there (with the `0xe0` prefix re-encoded
/// as `0x80`), and QEMU's own VNC server uses that field as the key number
/// without translating it. The client prefers this message whenever the server
/// advertises the extension, so it is the path a browser actually takes.
#[test]
fn an_extended_key_event_arrives_as_the_number_it_carries() {
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);

        // The browser takes this path: `1`..`7` are 0x02..0x08 (which the old
        // X11-keycode translation turned into zero entries and dropped), and
        // `Up` is 0xc8 (AT set 1 `0xe0 0x48`).
        for qnum in 0x02u32..=0x08 {
            let digit = char::from(b'1' + (qnum as u8 - 0x02));
            rfb_client::send_extended_key(&mut client, digit as u32, qnum, true);
        }
        rfb_client::send_extended_key(&mut client, 0xff52, 0xc8, true);

        let keys = wait_for(
            "the extended keys reached the console",
            || mock.keys(),
            |keys| keys.len() >= 8,
        )
        .await;
        assert_eq!(
            keys.iter().map(|key| key.keycode).collect::<Vec<_>>(),
            vec![0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xc8],
            "the extended keycode field must not be translated"
        );
    });
}

#[test]
fn a_mouse_button_from_the_client_arrives_at_the_console() {
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);

            // The left button, held: down, a move, and up.
            rfb_client::send_pointer(&mut client, 0b0000_0001, 5, 6);
            rfb_client::send_pointer(&mut client, 0b0000_0001, 7, 8);
            rfb_client::send_pointer(&mut client, 0b0000_0000, 9, 10);

            let mouse = wait_for("the mouse events reached the console", || mock.mouse(), |mouse| mouse.len() >= 5).await;
            assert_eq!(
                mouse,
                vec![
                    Mouse::Button {
                        button: MouseButton::Left,
                        down: true
                    },
                    // Every event carries the position, and only the buttons
                    // are edges: holding the button down does not repeat it.
                    Mouse::Abs { x: 5, y: 6 },
                    Mouse::Abs { x: 7, y: 8 },
                    Mouse::Button {
                        button: MouseButton::Left,
                        down: false
                    },
                    Mouse::Abs { x: 9, y: 10 },
                ],
                "the console has an absolute pointing device, so a move is a position"
            );
    });
}

#[test]
fn a_move_without_a_button_is_a_position_and_not_a_delta() {
    // The same test with the pointer property in the other state: this is what
    // the `is_absolute` read is for, and it is the thing a relative console
    // would get wrong.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);
            rfb_client::send_pointer(&mut client, 0b0000_0000, 3, 4);
            let mouse = wait_for("the mouse move reached the console", || mock.mouse(), |mouse| !mouse.is_empty()).await;
            assert_eq!(mouse, vec![Mouse::Abs { x: 3, y: 4 }]);
    });
}

#[test]
fn the_clipboard_reaches_the_client() {
    // The clipboard path from the guest to a viewer: the mock emits the signals
    // QEMU does, and the client asks for the data.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
            let clipboard =
                qemu_vnc::clipboard::Clipboard::register(server.connection(), server.downgrade())
                    .await
                    .expect("the clipboard peer to register");
            server.set_clipboard(clipboard);
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);

            mock.offer_clipboard("from the guest")
                .await
                .expect("the guest offers its clipboard");
            let text = wait_for(
                "saw the clipboard reach the client",
                || rfb_client::try_read_cut_text(&mut client),
                |text| text.is_ok(),
            )
            .await
            .expect("the clipboard reached the client");
            assert_eq!(text, "from the guest");
    });
}

#[test]
fn a_cut_text_from_the_client_is_offered_to_the_console() {
    // The other direction: a viewer sets the clipboard, and the server offers
    // it to the guest.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
            let clipboard =
                qemu_vnc::clipboard::Clipboard::register(server.connection(), server.downgrade())
                    .await
                    .expect("the clipboard peer to register");
            server.set_clipboard(clipboard);
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);

            rfb_client::send_cut_text(&mut client, "from the viewer");

            let grabs = wait_for(
                "saw the client grab the clipboard",
                || mock.grabs(),
                |grabs| !grabs.is_empty(),
            )
            .await;
            let grab = &grabs[0];
            assert_eq!(grab.selection, ClipboardSelection::Clipboard);
            assert_eq!(
                grab.mimes,
                vec!["text/plain;charset=utf-8"],
                "the mime type is the only one the C server offers"
            );
    });
}

#[test]
fn a_resize_from_the_client_reaches_the_console() {
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);
            rfb_client::send_set_desktop_size(&mut client, 800, 600);

            let ui_info = wait_for(
                "saw the resize reach the console",
                || mock.recorded().ui_info,
                |sizes: &Vec<(u32, u32)>| !sizes.is_empty(),
            )
            .await;
            assert_eq!(ui_info[0], (800, 600));
    });
}

// --- The cases the display unit tests covered, over the bus -----------------
//
// Each of these replaces one test in `display.rs`. What is asserted is the
// *behaviour* and not the error text: a scanout the server cannot read is a
// property of the pixels the client ends up with, and the message the server
// logs about it is not something a client can see.

#[test]
fn a_scanout_in_another_format_reaches_the_client_expanded() {
    // A console whose guest asked for `r5g6b5`: the server expands it to the
    // format it sends, and the client sees red rather than the guest's two
    // bytes.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        request_picture(&mut client);

        // One red pixel, `r5g6b5`, at the origin; the rest of the console is
        // whatever a scanout of that format leaves it as, so the whole console
        // is filled with it.
        let red = 0xf800u16.to_le_bytes();
        let mut data = Vec::new();
        for _ in 0..(WIDTH as usize * HEIGHT as usize) {
            data.extend_from_slice(&red);
        }
        mock.scanout_as(FIRST, qemu::PIXMAN_R5G6B5, data)
            .await
            .expect("the scanout arrives");
        let pixels = request_until(&mut client, &red_frame()).await;
        assert_eq!(pixels.len(), WIDTH as usize * HEIGHT as usize * 4);
    });
}

/// The console all red, in the format the server sends.
fn red_frame() -> Vec<u8> {
    (0..(WIDTH as usize * HEIGHT as usize))
        .flat_map(|_| [0x00, 0x00, 0xff, 0x00])
        .collect()
}

#[test]
fn a_scanout_with_an_alpha_byte_reaches_the_client_without_it() {
    // The `x8r8g8b8` scanout above is a pass-through: the bytes the mock sends
    // are the bytes the client gets, because the two formats are the same
    // little-endian layout with only the fourth byte to disagree. The case that
    // is not a pass-through is the alpha: a console that sends `a8r8g8b8` has
    // real data in the fourth byte, and the client's `x8r8g8b8` leaves it
    // unused, so it has to be cleared rather than passed through.
    //
    // This is also where the channel order is pinned down, because the bytes
    // below are written the way a person writes a colour — red, green, blue —
    // and a server that got the order wrong would return them unchanged and
    // look correct.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        request_picture(&mut client);

        // One pixel: red 0x11, green 0x22, blue 0x33, fully opaque.
        let mut data = Vec::new();
        for _ in 0..(WIDTH as usize * HEIGHT as usize) {
            data.extend_from_slice(&[0x11, 0x22, 0x33, 0xff]);
        }
        mock.scanout_as(FIRST, qemu::PIXMAN_A8R8G8B8, data)
            .await
            .expect("the scanout arrives");

        let opaque: [u8; 4] = [0x11, 0x22, 0x33, 0xff];
        let pixels = request_until(&mut client, &flat_frame([0x11, 0x22, 0x33, 0x00])).await;
        assert_eq!(
            &pixels[0..3],
            &opaque[..3],
            "the three colour bytes should survive in the order the format has them"
        );
        assert_eq!(
            pixels[3], 0,
            "the alpha of an a8r8g8b8 console is dropped: x8r8g8b8 leaves that \
             byte unused, and a viewer may render it as opaque black"
        );
    });
}

#[test]
fn a_scanout_the_server_can_not_read_leaves_the_console_alone() {
    // A format with no pixman equivalent. The server refuses it, and what
    // matters to a viewer is that the console is left as it was rather than
    // turned into something unreadable.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        request_picture(&mut client);
        let _ = rfb_client::read_update(&mut client);

        // A good scanout first, so there is something to lose.
        mock.scanout(FIRST, frame()).await.expect("the scanout arrives");
        let pixels = request_until(&mut client, &frame()).await;
        assert_eq!(pixels.len(), WIDTH as usize * HEIGHT as usize * 4);

        // And then one the server cannot read.
        mock.scanout_as(FIRST, qemu::PIXMAN_UNUSABLE, vec![0xff; 64])
            .await
            .expect("the mock pushed what it was asked to");
        // Ask a few times: if the bad scanout had been accepted, one of these
        // would come back with it.
        for _ in 0..5 {
            rfb_client::request_full_update(&mut client, 0, 0, WIDTH, HEIGHT);
            if let Ok(pixels) = rfb_client::try_read_update(&mut client) {
                assert_eq!(
                    pixels,
                    frame(),
                    "an unusable scanout must not change what the client sees"
                );
            }
        }
    });
}

#[test]
fn an_update_outside_the_console_leaves_it_alone() {
    // An update that runs off the edge of the surface. The client must not be
    // sent a rectangle that reads past the end of its own framebuffer.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        request_picture(&mut client);
        let _ = rfb_client::read_update(&mut client);

        // From the last pixel, two wide.
        mock.update(
            FIRST,
            (WIDTH as i32 - 1, 0, 2, 1),
            vec![0x11; 8],
        )
        .await
        .expect("the mock pushed what it was asked to");
        for _ in 0..5 {
            rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
            if let Ok(pixels) = rfb_client::try_read_update(&mut client) {
                assert_eq!(
                    pixels,
                    vec![0; WIDTH as usize * HEIGHT as usize * 4],
                    "an out of bounds update must not be composited"
                );
            }
        }
    });
}

#[test]
fn the_cursor_the_console_defines_reaches_the_client() {
    // The cursor is a pseudo-encoding rectangle, so the client has to ask for
    // it before the server will send one.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        rfb_client::send_set_encodings(
            &mut client,
            &[
                rfb_client::encoding::RAW,
                rfb_client::encoding::RICH_CURSOR,
                rfb_client::encoding::CURSOR_WITH_ALPHA,
            ],
        );
        rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
        let _ = rfb_client::try_read_update(&mut client);

        // A 9x2 cursor whose first and ninth pixel are opaque, in a8r8g8b8.
        let data: Vec<u8> = (0..9 * 2)
            .flat_map(|i| {
                let alpha = if i == 0 || i == 8 { 0xff } else { 0x00 };
                [0, 0, 0, alpha]
            })
            .collect();
        mock.cursor(FIRST, (9, 2), (1, 1), data)
            .await
            .expect("the cursor arrives");

        // A cursor update is a rectangle with a cursor encoding in it, and the
        // pixels are the mask followed by the shape.
        let mut sent = None;
        for _ in 0..ATTEMPTS {
            rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
            if let Ok(sent_rect) = rfb_client::try_read_rect(&mut client) {
                sent = Some(sent_rect);
                break;
            }
            async_io::Timer::after(Duration::from_millis(10)).await;
        }
        let (rect, mask) = sent.expect("the cursor to reach the client");
        assert_eq!(
            (rect.width, rect.height),
            (9, 2),
            "the cursor keeps the size the console gave it"
        );
        assert_eq!(
            (rect.x, rect.y),
            (1, 1),
            "and its hotspot, which the rectangle carries in place of a position"
        );
        assert_eq!(
            rect.encoding,
            rfb_client::encoding::RICH_CURSOR,
            "and it arrives as the encoding that says to expect a mask"
        );
        // The mask is a bitmap: one bit per pixel, most significant bit first,
        // each row starting on a byte boundary. The opaque pixels of the
        // console's cursor are the first and the ninth, and both are in the
        // first row of nine, so the first row is two bytes, both set, and the
        // second row is empty.
        assert_eq!(mask.len(), 2 * 2, "a row of bits, padded to a whole byte");
        assert_eq!(mask[0], 0b1000_0000, "the first pixel of the first row");
        assert_eq!(
            mask[1], 0b1000_0000,
            "the ninth pixel, which is the first of the second byte"
        );
        assert_eq!(
            &mask[2..],
            &[0, 0],
            "the second row of the cursor is transparent throughout"
        );
        // And the shape carries no alpha: the transparency was moved out of the
        // pixels and into that mask, which is what the mask is for.
        assert!(
            rect.pixels.chunks(4).all(|pixel| pixel[3] == 0),
            "the shape's alpha belongs in the mask, not in the pixels"
        );
    });
}

#[test]
fn ctrl_alt_two_switches_the_client_to_the_other_console() {
    // The C server lets a client move between the VM's consoles with
    // Ctrl+Alt-N, and the mock has two so that there is somewhere to go.
    //
    // What makes this a test rather than a sequence of events that happens to
    // work: the two consoles are given *different* pixels, the blue one is
    // pushed only to the second, and the blue pixels may only reach the client
    // after the switch. Push it to the wrong console, or send the wrong key,
    // and the client stays on black and the test fails.
    on_a_bus!(|mock, connection| {
        let second = FIRST + 1;
        let server = server_with_console(&mock, &connection, [FIRST, second]).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        request_picture(&mut client);

        // The first console: the usual test pattern.
        mock.scanout(FIRST, frame()).await.expect("the scanout arrives");
        let pixels = request_until(&mut client, &frame()).await;
        assert_eq!(pixels, frame(), "the first console's pixels");

        // The second: one flat colour, pushed to the second console only.
        let blue = flat_frame([0xff, 0x00, 0x00, 0x00]);
        mock.scanout(second, blue.clone())
            .await
            .expect("the scanout arrives");

        // The client is still on the first console, so the second one's pixels
        // must not show up however often it asks.
        for _ in 0..5 {
            rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
            if let Ok(pixels) = rfb_client::try_read_update(&mut client) {
                assert_ne!(
                    pixels, blue,
                    "a client on the first console must not be sent the second one's pixels"
                );
            }
        }

        // Ctrl+Alt-2 is the switch. The digits are 1-based, as in the C server,
        // so 2 is the second console, and both modifiers have to still be held
        // when the digit goes down.
        press(&mut client, 0x32);

        let pixels = request_until(&mut client, &blue).await;
        assert_eq!(
            pixels, blue,
            "after Ctrl+Alt-2 the client should be looking at the second console"
        );
    });
}

#[test]
fn ctrl_alt_one_brings_the_client_back_to_the_first_console() {
    // The other half of the same thing, and the half that catches a switch that
    // works one way: the client is put on the second console and has to be able
    // to come back.
    on_a_bus!(|mock, connection| {
        let second = FIRST + 1;
        let server = server_with_console(&mock, &connection, [FIRST, second]).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        request_picture(&mut client);

        let blue = flat_frame([0xff, 0x00, 0x00, 0x00]);
        mock.scanout(FIRST, frame()).await.expect("the first scanout");
        mock.scanout(second, blue.clone())
            .await
            .expect("the second scanout");
        let _ = request_until(&mut client, &frame()).await;

        // To the second, then back to the first.
        press(&mut client, 0x32);
        let _ = request_until(&mut client, &blue).await;
        press(&mut client, 0x31);
        let pixels = request_until(&mut client, &frame()).await;
        assert_eq!(
            pixels,
            frame(),
            "Ctrl+Alt-1 should bring the client back to the first console"
        );
    });
}

/// Ctrl+Alt+`N` also works when the client sends only key numbers.
///
/// An `ExtendedKeyEvent` may carry no symbol at all, only the QEMU key number:
/// `0x1d` Ctrl, `0x38` Alt, `0x03` for `2`. The shortcut must not depend on a
/// symbol the client did not send.
#[test]
fn ctrl_alt_number_switches_consoles_from_key_numbers() {
    on_a_bus!(|mock, connection| {
        let second = FIRST + 1;
        let server = server_with_console(&mock, &connection, [FIRST, second]).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        request_picture(&mut client);

        let blue = flat_frame([0xff, 0x00, 0x00, 0x00]);
        mock.scanout(FIRST, frame()).await.expect("the first scanout");
        mock.scanout(second, blue.clone())
            .await
            .expect("the second scanout");
        let _ = request_until(&mut client, &frame()).await;

        press_number(&mut client, 0x03); // Ctrl+Alt+2
        let pixels = request_until(&mut client, &blue).await;
        assert_eq!(
            pixels, blue,
            "the key-number-only shortcut should switch consoles"
        );
    });
}

/// Press and release `key`, with Control and Alt held down.
fn press(client: &mut std::net::TcpStream, key: u32) {
    rfb_client::send_key(client, 0xffe3, true); // Control_L
    rfb_client::send_key(client, 0xffe9, true); // Alt_L
    rfb_client::send_key(client, key, true);
    rfb_client::send_key(client, key, false);
    rfb_client::send_key(client, 0xffe3, false);
    rfb_client::send_key(client, 0xffe9, false);
}

/// Press and release a QEMU key number, with Ctrl and Alt key numbers held.
fn press_number(client: &mut std::net::TcpStream, digit: u32) {
    // No keysym, only the key number: the shape an `ExtendedKeyEvent` can take.
    rfb_client::send_extended_key(client, 0, 0x1d, true); // Control_L
    rfb_client::send_extended_key(client, 0, 0x38, true); // Alt_L
    rfb_client::send_extended_key(client, 0, digit, true);
    rfb_client::send_extended_key(client, 0, digit, false);
    rfb_client::send_extended_key(client, 0, 0x1d, false);
    rfb_client::send_extended_key(client, 0, 0x38, false);
}

/// A console of `size` filled with one `x8r8g8b8` colour.
fn flat_frame(pixel: [u8; 4]) -> Vec<u8> {
    (0..(WIDTH as usize * HEIGHT as usize))
        .flat_map(|_| pixel)
        .collect()
}

// --- The audio acknowledgement, over a socket ------------------------------
//
// This is the one thing the audio path could not be tested for: whether a
// server *has* audio is the server's business, and the acknowledgement is sent
// by the client task rather than by the bare session the other tests use. It
// needs a real `Server`, and it is here for that reason.

#[test]
fn a_client_of_a_server_with_audio_is_told_so() {
    // The acknowledgement answers the pseudo-encoding, not the enable: a client
    // learns the server has audio when its `SetEncodings` is answered, and the
    // enable that follows starts the samples. The two are separate, and a test
    // that sent only the enable would be waiting for a message that only ever
    // comes in answer to the other.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        server.set_audio(Some(audio_server(&server)));
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);

        // The viewer asks for the audio pseudo-encoding, as QEMU's viewers do.
        rfb_client::send_set_encodings(
            &mut client,
            &[rfb_client::encoding::RAW, rfb_client::encoding::AUDIO],
        );
        let (rect, _) = wait_for(
            "saw the audio acknowledgement",
            || rfb_client::try_read_rect(&mut client),
            |seen| {
                matches!(
                    seen,
                    Ok((rect, _)) if rect.encoding == rfb_client::encoding::AUDIO
                )
            },
        )
        .await
        .expect("the audio acknowledgement to reach the client");
        assert_eq!(
            (rect.width, rect.height),
            (WIDTH, HEIGHT),
            "QEMU's acknowledgements carry the framebuffer's size"
        );

        // And the enable is answered with the beginning of the stream, which is
        // what tells the client samples are on their way.
        rfb_client::send_audio_command(&mut client, qemu_vnc::rfb::audio::ENABLE);
        let sub = wait_for(
            "saw the start of the audio stream",
            || rfb_client::try_read_audio_sub(&mut client),
            |sub| matches!(sub, Ok(sub) if *sub == qemu_vnc::rfb::audio::BEGIN),
        )
        .await
        .expect("the start of the stream to reach the client");
        assert_eq!(sub, qemu_vnc::rfb::audio::BEGIN);
    });
}

#[test]
fn a_client_of_a_server_without_audio_is_not_told() {
    // The other half, and the one that makes the first a test rather than a
    // fixed expectation: a server with no audio behind it must not
    // acknowledge, because a client that took the acknowledgement for a promise
    // would then wait for samples that are never coming.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);

        // The client asks for the audio encoding, the desktop size, and one
        // encoding QEMU does acknowledge. The third is the point: without it
        // the answer would be an empty set, and an empty set cannot tell "the
        // server declined to acknowledge these" from "the server sent nothing
        // at all" — which is the difference between a test and a tautology.
        rfb_client::send_set_encodings(
            &mut client,
            &[
                rfb_client::encoding::RAW,
                rfb_client::encoding::AUDIO,
                rfb_client::encoding::DESKTOP_SIZE,
                rfb_client::encoding::EXTENDED_KEY_EVENT,
            ],
        );
        let mut seen = Vec::new();
        for _ in 0..ATTEMPTS {
            match rfb_client::try_read_rect(&mut client) {
                Ok((rect, _)) => {
                    assert_ne!(
                        rect.encoding,
                        rfb_client::encoding::AUDIO,
                        "a server with no audio must not acknowledge it"
                    );
                    seen.push(rect.encoding);
                }
                Err(_) => break,
            }
        }
        // Only the extended key event, which is one of the two rectangles QEMU
        // acknowledges at all. `DesktopSize` is not among them: QEMU sends that
        // one when the frame buffer actually changes size.
        assert_eq!(
            seen,
            vec![rfb_client::encoding::EXTENDED_KEY_EVENT],
            "only the acknowledgements QEMU sends should be sent, and nothing else"
        );

        // And the enable is not answered either: there is no stream to start.
        rfb_client::send_audio_command(&mut client, qemu_vnc::rfb::audio::ENABLE);
        if let Ok(sub) = rfb_client::try_read_audio_sub(&mut client) {
            assert_ne!(
                sub,
                qemu_vnc::rfb::audio::BEGIN,
                "a server with no audio must not start a stream"
            );
        }
    });
}

/// An audio server that plays into the server's own event channel, so the
/// samples reach the clients.
fn audio_server(server: &Server) -> qemu_vnc::audio::AudioServer {
    let server = server.clone();
    qemu_vnc::audio::AudioServer::new(
        Box::new(qemu_vnc::audio::NullSink::new()),
        move |out| match out {
            qemu_vnc::audio::Out::Samples(source, samples) => server.broadcast_audio(source, samples),
            qemu_vnc::audio::Out::Begin => server.broadcast_audio_begin(),
            qemu_vnc::audio::Out::End => server.broadcast_audio_end(),
        },
    )
}

// --- The format a client asked for is the format it gets --------------------
//
// This is the other half of the resampler, and the bug it closes is the reason
// the plumbing had to be built at all. The samples used to reach the client
// exactly as QEMU sent them, while the client had been told — and had itself
// asked for — a different format entirely.

#[test]
fn a_client_is_sent_the_format_it_asked_for() {
    // The guest is a mono U8 stream at 48 kHz; the client asks for stereo S16
    // at 44.1 kHz, which is QEMU's own default and the commonest thing a
    // viewer does. All three of width, channels and rate have to be converted,
    // and the client has to get what it asked for rather than what the guest
    // happened to produce.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        server.set_audio(Some(audio_server(&server)));
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        // S16, stereo, 44.1 kHz: format byte 3, two channels. It goes before
        // the enable, which is the order a viewer sends them in.
        rfb_client::send_audio_format(&mut client, 3, 2, 44_100);
        start_audio(&mut client).await;

        // What the guest sends: a mono U8 tone at 48 kHz.
        let guest = qemu_vnc::rfb::audio::Format {
            sample: qemu_vnc::rfb::audio::Sample::U8,
            channels: 1,
            frequency: 48_000,
            be: false,
        };
        let samples = u8_tone(guest, 1_000, 0.5);
        server.broadcast_audio(guest, samples);

        let block = wait_for(
            "saw the samples reach the client",
            || rfb_client::try_read_audio_data(&mut client),
            |block| matches!(block, Ok(block) if !block.is_empty()),
        )
        .await
        .expect("the samples to reach the client");

        // What comes back has to be in the client's format: 16-bit stereo
        // frames, whatever the guest sent.
        assert_eq!(
            block.len() % 4,
            0,
            "the client asked for 16-bit stereo, so the blocks should be whole \\
             frames of four bytes: got {} bytes",
            block.len()
        );
        // And the rate was converted, so a second of the guest's audio is
        // about 44.1/48 as many frames as the guest produced.
        let got_frames = (block.len() / 4) as f64;
        let expected = 0.5 * 44_100.0;
        assert!(
            (got_frames - expected).abs() < expected * 0.25,
            "half a second at 48000 should be about {expected} frames at 44100, \\
             got {got_frames}"
        );
    });
}

#[test]
fn a_client_that_asked_for_nothing_gets_qemus_default_format() {
    // QEMU sets `vs->as` to S16, 44.1 kHz, stereo before the client says
    // anything, and the backend converts to it. A client that never sent
    // `SetFormat` is therefore sent that, not the guest's format — which is
    // what this port used to get wrong, and what makes the default a promise
    // the server has to keep.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        server.set_audio(Some(audio_server(&server)));
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        start_audio(&mut client).await;

        let guest = qemu_vnc::rfb::audio::Format {
            sample: qemu_vnc::rfb::audio::Sample::U8,
            channels: 1,
            frequency: 48_000,
            be: false,
        };
        server.broadcast_audio(guest, u8_tone(guest, 1_000, 0.5));
        let block = wait_for(
            "saw the samples reach the client",
            || rfb_client::try_read_audio_data(&mut client),
            |block| matches!(block, Ok(block) if !block.is_empty()),
        )
        .await
        .expect("the samples to reach the client");

        assert_eq!(
            block.len() % 4,
            0,
            "the default format is 16-bit stereo, so the blocks should be \\
             whole frames of four bytes: got {} bytes",
            block.len()
        );
        assert!(
            block.len() > 1_000,
            "and there should be a decent amount of it, not {} bytes",
            block.len()
        );
    });
}

/// Get a client from the handshake to receiving audio, asking for no format of
/// its own.
async fn start_audio(client: &mut std::net::TcpStream) {
    start_audio_in(client, None).await
}

/// [`start_audio`], for a client that asks for a format.
///
/// The order is the protocol's and none of it can be skipped:
///
/// 1. the client announces the audio pseudo-encoding in its `SetEncodings` —
///    which *replaces* the set rather than adding to it, so a later
///    `SetEncodings` without the audio takes the client back out of the audio
///    business, and the server is right to stop answering it;
/// 2. the server acknowledges, as a framebuffer update of its own, and only if
///    it has audio to send. Skipping this does not fail loudly — the
///    acknowledgement is still in the socket, and an audio reader looking at it
///    says "not an audio message" for ever;
/// 3. the format, which is what the samples will be converted to;
/// 4. the enable, which starts the stream.
async fn start_audio_in(client: &mut std::net::TcpStream, format: Option<(u8, u8, u32)>) {
    rfb_client::send_set_encodings(
        client,
        &[rfb_client::encoding::RAW, rfb_client::encoding::AUDIO],
    );
    // No update is requested here, and that is deliberate. The answer to
    // `SetEncodings` is a framebuffer update of pseudo-encoding rectangles, and
    // reading one of those as though it carried pixels — which is what
    // `try_read_update` does — eats a rectangle header, waits for bytes that
    // are not coming, and leaves the stream out of step. The rectangle reader
    // knows a pseudo-encoding carries no payload, and is what belongs here.
    wait_for(
        "saw the audio acknowledgement",
        || rfb_client::try_read_rect(client),
        |rect| {
            matches!(
                rect,
                Ok((rect, _)) if rect.encoding == rfb_client::encoding::AUDIO
            )
        },
    )
    .await
    .expect("the audio acknowledgement to reach the client");
    if let Some((sample, channels, frequency)) = format {
        rfb_client::send_audio_format(client, sample, channels, frequency);
    }
    rfb_client::send_audio_command(client, qemu_vnc::rfb::audio::ENABLE);
    wait_for(
        "saw the start of the audio stream",
        || rfb_client::try_read_audio_sub(client),
        |sub| matches!(sub, Ok(sub) if *sub == qemu_vnc::rfb::audio::BEGIN),
    )
    .await
    .expect("the stream to start");
}

/// A tone in `format` at 16-bit scale, as the guest would send it.
fn u8_tone(
    format: qemu_vnc::rfb::audio::Format,
    frequency: u32,
    seconds: f64,
) -> Vec<u8> {
    let frames = (f64::from(format.frequency) * seconds) as usize;
    (0..frames)
        .map(|frame| {
            let phase = 2.0
                * std::f64::consts::PI
                * f64::from(frequency)
                * frame as f64
                / f64::from(format.frequency);
            (phase.sin() * 100.0) as i8 as u8
        })
        .collect()
}

#[test]
fn a_client_is_told_when_the_stream_ends_and_hears_the_rest_of_it() {
    // The end of a stream is where a resampler loses audio. It holds a partial
    // chunk back so that the next block carries on from it, and at the end of a
    // stream there is no next block — so the tail has to be released, and the
    // client told the stream is over rather than left waiting for samples that
    // are not coming.
    //
    // The block sent here is shorter than the resampler's chunk on purpose: it
    // is entirely held back, and without the flush the client would get nothing
    // at all and never an `END`.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        server.set_audio(Some(audio_server(&server)));
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        // A rate that differs, so the samples are on their way through a
        // resampler rather than being passed straight through.
        start_audio_in(&mut client, Some((3, 2, 48_000))).await;

        let guest = qemu_vnc::rfb::audio::Format {
            sample: qemu_vnc::rfb::audio::Sample::S16,
            channels: 2,
            frequency: 44_100,
            be: false,
        };
        // Far less than the resampler's 1024-frame chunk.
        server.broadcast_audio(guest, u8_tone(guest, 1_000, 0.005));
        // Let the client read the (empty, everything is held back) data message
        // and settle before the stream ends.
        async_io::Timer::after(Duration::from_millis(50)).await;

        server.broadcast_audio_end();

        // The rest of the audio, and then the end of the stream.
        let tail = wait_for(
            "saw the tail of the stream",
            || rfb_client::try_read_audio_data(&mut client),
            |tail| matches!(tail, Ok(tail) if !tail.is_empty()),
        )
        .await
        .expect("the audio the client was still owed to reach it");
        assert_eq!(
            tail.len() % 4,
            0,
            "the tail should be whole 16-bit stereo frames: {} bytes",
            tail.len()
        );

        let sub = wait_for(
            "saw the end of the stream",
            || rfb_client::try_read_audio_sub(&mut client),
            |sub| matches!(sub, Ok(qemu_vnc::rfb::audio::END)),
        )
        .await
        .expect("the end of the stream to reach the client");
        assert_eq!(sub, qemu_vnc::rfb::audio::END);
    });
}

#[test]
fn the_audio_gate_follows_whether_the_vm_has_an_audio_device() {
    // Both answers, because one of them proves nothing on its own: a gate that
    // always said "no" would pass a test that only ever asks about a VM
    // without audio, which is the mistake it is standing in for.
    for (audio, expected) in [(false, false), (true, true)] {
        let (mock, connection) = async_io::block_on(async {
            MockQemu::start_with_audio(SIZE, audio)
                .await
                .expect("the mock")
        });
        let display = async_io::block_on(async {
            qemu_display::Display::new(&connection, None::<&str>)
                .await
                .expect("the display")
        });
        assert_eq!(
            display.has_audio(),
            expected,
            "a VM with audio={audio} should report has_audio() == {expected}"
        );
        // The object manager was read either way: the clipboard is in it.
        let has_clipboard = async_io::block_on(async {
            display.clipboard().await.expect("the clipboard lookup").is_some()
        });
        assert!(has_clipboard, "the object manager should have been read");
        drop(mock);
    }
}

#[test]
fn samples_pushed_over_the_dbus_listener_reach_a_vnc_client() {
    // The one hop that had never run. Every other audio test starts at
    // `broadcast_audio`, which is the *far* end of the D-Bus side: the file
    // descriptor handoff, the second peer-to-peer connection and the dispatch
    // into `AudioOutHandler::write` were all skipped, so a VM that could not
    // push a single sample would still have passed all of them.
    //
    // Both halves run here and the same bytes have to come out the other side.
    // The D-Bus half is the real `qemu_display::Audio` over the real mock, and
    // the RFB half is a real client that negotiated audio, so what is asserted
    // is the whole chain rather than either end of it.
    async_io::block_on(async {
        let (mock, connection) = MockQemu::start_with_audio(SIZE, true)
            .await
            .expect("the mock to export its interfaces");
        let server = server_for(&mock, &connection).await;

        // What `main.rs` does, in the order it does it: build the audio
        // interface, hand it an `AudioServer`, and only then serve clients.
        let mut iface = qemu_display::Audio::new(&connection, None::<&str>)
            .await
            .expect("the VM's audio interface");
        let target = server.clone();
        let audio = qemu_vnc::audio::AudioServer::new(
            Box::new(qemu_vnc::audio::NullSink::new()),
            move |out| match out {
                qemu_vnc::audio::Out::Samples(source, samples) => {
                    target.broadcast_audio(source, samples)
                }
                qemu_vnc::audio::Out::Begin => target.broadcast_audio_begin(),
                qemu_vnc::audio::Out::End => target.broadcast_audio_end(),
            },
        );
        server.set_audio(Some(audio.clone()));
        iface
            .register_out_listener(audio)
            .await
            .expect("the audio out listener to be registered");
        mock.wait_audio_registered().await;

        // A client that has asked for audio, so it is owed samples.
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        start_audio(&mut client).await;

        // What the guest produces: signed 16-bit stereo at 44.1 kHz, which is
        // what a client that asked for no format of its own gets told it will
        // be sent, so nothing has to be converted and the bytes can be
        // compared exactly. A ramp rather than a tone, so a block that arrived
        // out of order or twice could not be mistaken for the right one.
        let samples: Vec<u8> = (0..4_096u32).map(|i| (i % 251) as u8).collect();
        // Before, not after: the counters are global and other tests in this
        // binary push audio too, so what can be asserted is that these two moved
        // across this push -- never what they are. Both ends of the chain in one
        // test, which is the only place they can be compared.
        let captured = qemu_vnc::counters::counters().audio_captured.total();
        let sent = qemu_vnc::counters::counters().audio_sent.total();
        mock.push_audio(1, 16, true, 44_100, 2, &samples)
            .await
            .expect("the samples to be pushed over the listener");

        let block = wait_for(
            "saw samples pushed over D-Bus reach the client",
            || rfb_client::try_read_audio_data(&mut client),
            |block| matches!(block, Ok(block) if !block.is_empty()),
        )
        .await
        .expect("the samples to reach the client");

        assert_eq!(
            block.len(),
            samples.len(),
            "every byte a VM pushed should reach the client unchanged"
        );
        assert_eq!(
            block, samples,
            "the client's block should be the guest's samples, byte for byte"
        );

        // The counters have to have moved on both sides. `audio_captured`
        // without `audio_sent` is the VM's audio arriving and going nowhere,
        // which is a fault this test can see and a log line could not name.
        assert!(
            qemu_vnc::counters::counters().audio_captured.total() > captured,
            "the samples arrived but audio_captured did not move"
        );
        assert!(
            qemu_vnc::counters::counters().audio_sent.total() > sent,
            "the samples reached the client but audio_sent did not move, so \
             audio_captured alone would have looked like a working path"
        );
    });
}

#[test]
fn a_guest_that_pauses_and_starts_again_is_still_audible() {
    // **Audio was a one-shot: only the first stream ever reached a client.**
    //
    // A guest that stops its audio and starts it again -- two tracks of a playlist
    // and the silence between them -- reports a `SetEnabled(false)` and then a
    // `SetEnabled(true)`, and QEMU answers each with `VNC_MSG_SERVER_QEMU_AUDIO_END`
    // and `VNC_MSG_SERVER_QEMU_AUDIO_BEGIN`. Two things here stopped that working:
    //
    // The end set `enabled = false` on every client. `send_audio_data` drops
    // anything for a client that is not enabled, and nothing re-enabled it: the
    // client had already sent its `Enable` and had no reason to send a second.
    // In QEMU `AUD_CNOTIFY_DISABLE` does not touch `vs->audio_enabled`, because
    // that is the *client's* setting and only the client's `Disable` clears it.
    //
    // And nothing sent the second `BEGIN` anyway. The start of a stream used to
    // arrive as an empty block of samples, and `main.rs` dropped empty blocks on
    // the way to the clients -- right for audio, fatal for the signal, so a
    // client was told `BEGIN` exactly once, when it asked. That is now
    // `Out::Begin`.
    async_io::block_on(async {
        let (mock, connection) = MockQemu::start_with_audio(SIZE, true)
            .await
            .expect("the mock");
        let server = server_for(&mock, &connection).await;
        let mut iface = qemu_display::Audio::new(&connection, None::<&str>)
            .await
            .expect("the VM's audio interface");
        let target = server.clone();
        let audio = qemu_vnc::audio::AudioServer::new(
            Box::new(qemu_vnc::audio::NullSink::new()),
            move |out| match out {
                qemu_vnc::audio::Out::Samples(source, samples) => {
                    target.broadcast_audio(source, samples)
                }
                qemu_vnc::audio::Out::Begin => target.broadcast_audio_begin(),
                qemu_vnc::audio::Out::End => target.broadcast_audio_end(),
            },
        );
        server.set_audio(Some(audio.clone()));
        iface
            .register_out_listener(audio)
            .await
            .expect("the listener to be registered");
        mock.wait_audio_registered().await;

        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        start_audio(&mut client).await;

        // Turn the stream off and on, which is what a pause is.
        server.broadcast_audio_end();
        let sub = wait_for(
            "saw the end of the first stream",
            || rfb_client::try_read_audio_sub(&mut client),
            |sub| matches!(sub, Ok(qemu_vnc::rfb::audio::END)),
        )
        .await
        .expect("the end of the stream to reach the client");
        assert_eq!(sub, qemu_vnc::rfb::audio::END);

        server.broadcast_audio_begin();
        let sub = wait_for(
            "saw the start of the second stream",
            || rfb_client::try_read_audio_sub(&mut client),
            |sub| matches!(sub, Ok(qemu_vnc::rfb::audio::BEGIN)),
        )
        .await
        .expect("the start of the stream to reach the client");
        assert_eq!(
            sub,
            qemu_vnc::rfb::audio::BEGIN,
            "a client must be told a stream began, not only that one did"
        );

        // And the audio after the pause must actually arrive, which is the part
        // that was broken: `BEGIN` on its own would pass while every block was
        // still being dropped for a client that had been disabled.
        let block = vec![0x5Au8; 4_000];
        server.broadcast_audio(guest_format(), block.clone());
        let got = wait_for(
            "saw samples after the pause reach the client",
            || rfb_client::try_read_audio_data(&mut client),
            |data| matches!(data, Ok(data) if !data.is_empty()),
        )
        .await
        .expect("the samples after the pause to reach the client");
        assert_eq!(
            got, block,
            "the second stream must be delivered whole, not dropped for a client \
             that was disabled when the first one ended"
        );
    });
}

/// The format `broadcast_audio` is called with above: what a 44.1 kHz stereo
/// signed 16-bit guest produces, which is the default the client is told.
fn guest_format() -> qemu_vnc::rfb::audio::Format {
    qemu_vnc::rfb::audio::Format {
        sample: qemu_vnc::rfb::audio::Sample::S16,
        channels: 2,
        frequency: 44_100,
        be: false,
    }
}

#[test]
fn a_float_stream_is_heard_as_the_float_it_is() {
    // **The white-noise fault.** A VM whose audio engine hands over IEEE floats
    // -- which is what a PulseAudio-backed one does, and what `dbus`'s own
    // audiodev does -- was heard as full-scale static, and the capture at the
    // same time was loud enough that `volumedetect` was not flat, so "the
    // samples are arriving" was never in question.
    //
    // Two fields of `Init` said what the samples were and this port read
    // neither. `is_float`: the bit pattern of a float is a large integer, so
    // reading `0.14` as an unsigned 32-bit gave about 305 million, and every
    // sample saturated on the way down to the client's 16 bits. `be`: the samples
    // have to be decoded, and decoding needs to know which way round they are,
    // so the byte order could no longer be the accident it had been. Before it
    // was carried on the format, `read` and `write` both worked big-endian,
    // which made an integer stream round-trip to the VM's own bytes whatever
    // they were -- right on a little-endian machine, and by luck.
    //
    // The numbers below are the point of the test: a tone is compared sample for
    // sample against the conversion it should be, so a return to saturation is a
    // failure rather than something only a listener would notice.
    async_io::block_on(async {
        let (mock, connection) = MockQemu::start_with_audio(SIZE, true)
            .await
            .expect("the mock");
        let server = server_for(&mock, &connection).await;
        let mut iface = qemu_display::Audio::new(&connection, None::<&str>)
            .await
            .expect("the VM's audio interface");
        let target = server.clone();
        let audio = qemu_vnc::audio::AudioServer::new(
            Box::new(qemu_vnc::audio::NullSink::new()),
            move |out| match out {
                qemu_vnc::audio::Out::Samples(source, samples) => {
                    target.broadcast_audio(source, samples)
                }
                qemu_vnc::audio::Out::Begin => target.broadcast_audio_begin(),
                qemu_vnc::audio::Out::End => target.broadcast_audio_end(),
            },
        );
        server.set_audio(Some(audio.clone()));
        iface
            .register_out_listener(audio)
            .await
            .expect("the listener to be registered");
        mock.wait_audio_registered().await;

        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        start_audio(&mut client).await;

        // A quarter-second of a 1 kHz tone at full scale, as 32-bit floats.
        let frames = 11_025;
        let floats: Vec<f32> = (0..frames * 2)
            .map(|i| {
                (2.0 * std::f64::consts::PI * 1_000.0 * (i / 2) as f64 / 44_100.0).sin() as f32
            })
            .collect();
        let bytes: Vec<u8> = floats.iter().flat_map(|f| f.to_le_bytes()).collect();
        mock.push_audio_as(1, 32, false, true, 44_100, 2, &bytes)
            .await
            .expect("the float samples to be pushed");

        let block = wait_for(
            "the float samples to reach the client",
            || rfb_client::try_read_audio_data(&mut client),
            |block| matches!(block, Ok(block) if !block.is_empty()),
        )
        .await
        .expect("the samples to reach the client");

        // The client asked for no format of its own, so QEMU's default: signed
        // 16-bit stereo in the VM's own byte order.
        let got: Vec<i16> = block
            .chunks_exact(2)
            .map(|b| i16::from_le_bytes([b[0], b[1]]))
            .collect();
        assert_eq!(got.len(), floats.len(), "every sample should survive");
        for (i, (sample, value)) in got.iter().zip(floats.iter()).enumerate() {
            // QEMU's float conversion multiplies by int32's full scale and then
            // shifts down to the target width, so the scale for S16 is 2^15 and
            // the down-shift floors. Multiplying by 32767 and rounding is the
            // approximation this test used to assert, and it is off by two at
            // the bottom of the range.
            let want = (f64::from(*value) * 32_768.0)
                .floor()
                .clamp(-32_768.0, 32_767.0) as i16;
            assert!(
                (i32::from(*sample) - i32::from(want)).abs() <= 1,
                "sample {i}: the client was sent {sample}, and {value} at full \
                 scale is {want}. A large difference is saturation, which is what \
                 reading a float as an integer looks like"
            );
        }
        // And it is a tone, not a square wave: the values cannot all be at the
        // ends of the range.
        let at_the_end = got.iter().filter(|s| **s == i16::MAX || **s == i16::MIN).count();
        assert!(
            at_the_end * 20 < got.len(),
            "{at_the_end} of {} samples are at full scale, which is a square wave, \
             not a sine",
            got.len()
        );
    });
}

#[test]
fn a_block_the_resampler_can_not_convert_sends_nothing_at_all() {
    // The shape QEMU actually sends, and the one that broke a real client.
    //
    // `NSamples` is 480 frames -- ten milliseconds at 48 kHz -- and the
    // converter holds a whole `RESAMPLE_CHUNK` of 1024 input frames before it
    // can emit. So a client that negotiates a rate the VM is not producing gets
    // an empty conversion for most blocks. Those were written as
    // `255, 1, 2, 0, 0, 0, 0`: a `DATA` message carrying no samples, which is
    // not in the protocol, and which `audio_sent` counted as audio delivered.
    //
    // QEMU's own VNC server cannot produce this case at all, which is the whole
    // difference between it and this port: it registers each client's capture in
    // the format that client negotiated, so its backend converts ahead of the
    // capture and every block arrives whole. Here the guest's native format
    // arrives over D-Bus and each client is converted separately, so the
    // buffering is unavoidable and the empty case has to be dropped rather than
    // sent.
    async_io::block_on(async {
        let (mock, connection) = MockQemu::start_with_audio(SIZE, true)
            .await
            .expect("the mock");
        let server = server_for(&mock, &connection).await;
        let mut iface = qemu_display::Audio::new(&connection, None::<&str>)
            .await
            .expect("the VM's audio interface");
        let target = server.clone();
        let audio = qemu_vnc::audio::AudioServer::new(
            Box::new(qemu_vnc::audio::NullSink::new()),
            move |out| match out {
                qemu_vnc::audio::Out::Samples(source, samples) => {
                    target.broadcast_audio(source, samples)
                }
                qemu_vnc::audio::Out::Begin => target.broadcast_audio_begin(),
                qemu_vnc::audio::Out::End => target.broadcast_audio_end(),
            },
        );
        server.set_audio(Some(audio.clone()));
        iface
            .register_out_listener(audio)
            .await
            .expect("the listener to be registered");
        mock.wait_audio_registered().await;

        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        // The client asks for 48 kHz while the VM produces 44.1, which is what
        // makes the conversion resample rather than pass through.
        rfb_client::send_audio_format(&mut client, 3, 2, 48_000);
        start_audio(&mut client).await;

        // One ten-millisecond block of stereo S16 at 44.1 kHz: 441 frames.
        let block = vec![0u8; 441 * 4];
        mock.push_audio(1, 16, true, 44_100, 2, &block)
            .await
            .expect("the block to be pushed");

        // Time enough for the server to have answered, so an absent message is a
        // real absence and not a race.
        async_io::Timer::after(Duration::from_millis(300)).await;
        let got = rfb_client::try_read_audio_data(&mut client);
        assert!(
            matches!(got, Err(ref e) if e.kind() == io::ErrorKind::WouldBlock),
            "a block the resampler could not convert should send nothing at all, \
             and the client got {got:?} -- an empty `DATA` message is not in the \
             protocol and a client is entitled to choke on it"
        );
        // Nothing is asserted about `audio_sent_bytes` here. It is a global
        // counter and this binary runs its tests in parallel, so another test
        // pushing audio moves it between any two reads -- an earlier version of
        // this test asserted it had not moved, and passed alone and failed in
        // the suite. The client's own socket is this test's alone, which is why
        // the assertion above can be exact and this one could not.
    });
}

#[test]
fn dropping_the_audio_handle_closes_the_listener() {
    // Why `main.rs` keeps its `Audio` in a binding instead of letting it fall
    // out of a `match` arm.
    //
    // `Audio` holds the peer-to-peer connection to the peer's
    // `AudioOutListener`, and holds nothing else that refers to it. Drop it and
    // the socket closes -- while the server still believes it has audio, still
    // answers a client asking for it, and captures nothing but the empty file
    // `--audio-dump` leaves behind. That is not a shape this suite could see
    // from the happy path: the test above keeps the handle alive, which is the
    // arrangement that works, so the bug was invisible until a real QEMU said
    // the capture was zero bytes long.
    //
    // So this asserts the failure instead, and names the reason a later change
    // that tidies the handle's scope has to reckon with.
    async_io::block_on(async {
        let (mock, connection) = MockQemu::start_with_audio(SIZE, true)
            .await
            .expect("the mock");
        let server = server_for(&mock, &connection).await;
        {
            let mut iface = qemu_display::Audio::new(&connection, None::<&str>)
                .await
                .expect("the VM's audio interface");
            let target = server.clone();
            let audio = qemu_vnc::audio::AudioServer::new(
                Box::new(qemu_vnc::audio::NullSink::new()),
                move |out| match out {
                    qemu_vnc::audio::Out::Samples(source, samples) => {
                        target.broadcast_audio(source, samples)
                    }
                    qemu_vnc::audio::Out::Begin => target.broadcast_audio_begin(),
                qemu_vnc::audio::Out::End => target.broadcast_audio_end(),
                },
            );
            iface
                .register_out_listener(audio)
                .await
                .expect("the listener to be registered");
            mock.wait_audio_registered().await;
        }
        // `iface` is gone, which is all it takes.
        let pushed = mock.push_audio(1, 16, true, 44_100, 2, &[7u8; 64]).await;
        assert!(
            pushed.is_err(),
            "the peer's samples went somewhere after the handle was dropped, so \
             `Audio` is not what keeps that connection alive and the reason \
             `main.rs` holds it is wrong"
        );
    });
}

#[test]
fn a_client_that_asks_for_the_other_byte_order_gets_its_colours() {
    // A client is free to ask for a pixel format whose byte order is the
    // reverse of the one the server announced, and this one does: `red_shift:
    // 0`, so red is the *first* byte of a pixel, where the server's own x8r8g8b8
    // has blue. This is the format a real viewer asked for in the log that
    // started this, and the frame it got was unreadable.
    //
    // The bug was `value.to_be_bytes()` in the conversion, against a function
    // that refuses big endian clients: every colour went out with its channels
    // in the wrong three bytes. A red pixel left as `[0, 0, 0, 255]`, which
    // this client decodes as black, so the console arrived blank.
    //
    // It survived because no test had ever asked for a format other than the
    // server's own — the decoders here all assume x8r8g8b8, and a server
    // converting to the format it already holds has nothing to get wrong.
    let wanted = qemu_vnc::rfb::PixelFormat {
        bits_per_pixel: 32,
        depth: 24,
        big_endian: false,
        true_colour: true,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 0,
        green_shift: 8,
        blue_shift: 16,
    };
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        rfb_client::send_set_pixel_format(&mut client, &wanted);
        // Raw, so this is about the conversion and nothing else.
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        mock.scanout(FIRST, frame()).await.expect("the scanout arrives");

        // The server pushes an update when the console draws, without being
        // asked, so this reads what arrives rather than asking for it.
        let got = read_decoded(&mut client, &wanted);
        assert!(!got.is_empty(), "some pixels arrived");
        for (i, pixel) in got.iter().enumerate() {
            let want = frame()[i * 4 + 2]; // red, which is byte 2 in x8r8g8b8
            assert_eq!(
                pixel[0], want,
                "pixel {i} should be red {want}, decoded as {pixel:?}"
            );
        }
    });
}

#[test]
fn a_client_in_the_other_byte_order_gets_the_whole_console_over_zrle() {
    // The end-to-end version of the width bug, in the format the viewer in the
    // log actually used: 32 bits per pixel, depth 24, red in the *first* byte.
    //
    // Every ZRLE pixel for such a client is three bytes, and this crate was
    // writing four for the solid and raw tiles while getting the palette
    // entries right. That is the worst possible shape for a decoder: the
    // first tile reads correctly and every field after it is a byte out of
    // step, so the client cannot follow the stream and shows nothing at all.
    //
    // It asks for ZRLE specifically, because the raw path would not notice.
    let wanted = qemu_vnc::rfb::PixelFormat {
        bits_per_pixel: 32,
        depth: 24,
        big_endian: false,
        true_colour: true,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 0,
        green_shift: 8,
        blue_shift: 16,
    };
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        rfb_client::send_set_pixel_format(&mut client, &wanted);
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::ZRLE]);
        // Read the acknowledgements the server sends for the pixel format and
        // the encodings. They carry no pixels, and without them a console that
        // draws immediately is served with the encodings the client had when it
        // connected rather than the ones it has just announced.
        // Read the acknowledgements, so the server has the encodings before it
        // serves anything: a console that draws while the client is still
        // announcing itself is served with the encodings it had at connect.
        drain_acks(&mut client);
        // The screen has more than sixteen colours in a tile, so the raw path
        // is taken as well as the palette and solid ones.
        mock.scanout(FIRST, noisy_frame()).await.expect("the scanout arrives");

        let got = read_decoded_with(&mut client, &wanted, rfb_client::encoding::ZRLE);
        assert!(!got.is_empty(), "the console arrived");
        let frame = noisy_frame();
        for (i, pixel) in got.iter().enumerate() {
            // x8r8g8b8 is B, G, R.
            let want = [frame[i * 4 + 2], frame[i * 4 + 1], frame[i * 4]];
            assert_eq!(
                *pixel, want,
                "pixel {i} of {}: got {pixel:?} against {want:?}",
                got.len()
            );
        }
    });
}

#[test]
fn a_client_in_the_other_byte_order_gets_the_whole_console_over_hextile() {
    // The same frame through the zlib encoding, whose pixels have the same
    // three-byte rule. A fix in one encoder and not the other would show up
    // here and nowhere else.
    let wanted = qemu_vnc::rfb::PixelFormat {
        bits_per_pixel: 32,
        depth: 24,
        big_endian: false,
        true_colour: true,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 0,
        green_shift: 8,
        blue_shift: 16,
    };
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        rfb_client::send_set_pixel_format(&mut client, &wanted);
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::ZLIB]);
        drain_acks(&mut client);
        mock.scanout(FIRST, noisy_frame()).await.expect("the scanout arrives");

        let got = read_decoded_with(&mut client, &wanted, rfb_client::encoding::ZLIB);
        assert!(!got.is_empty(), "the console arrived");
        let frame = noisy_frame();
        for (i, pixel) in got.iter().enumerate() {
            let want = [frame[i * 4 + 2], frame[i * 4 + 1], frame[i * 4]];
            assert_eq!(*pixel, want, "pixel {i}: got {pixel:?} against {want:?}");
        }
    });
}

/// A frame with more than sixteen colours in every 64x64 tile, so the ZRLE
/// encoder has to fall back to raw tiles, plus a flat region for a solid one.
fn noisy_frame() -> Vec<u8> {
    noisy_frame_of(WIDTH, HEIGHT)
}

/// A screen of `width` by `height` with a flat band, a two-colour checkerboard
/// and a noisy region, so all three ZRLE tile kinds go out.
fn noisy_frame_of(width: u16, height: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(width as usize * height as usize * 4);
    for y in 0..height as usize {
        for x in 0..width as usize {
            let (r, g, b) = if y < height as usize / 5 {
                // A flat band: a solid tile.
                (0x20, 0x40, 0x60)
            } else if y < height as usize / 2 {
                if (x / 8 + y / 8) % 2 == 0 {
                    (0xff, 0xff, 0xff)
                } else {
                    (0, 0, 0)
                }
            } else {
                // Enough distinct colours per tile to force the raw path.
                let n = (x * 7 + y * 13) as u8;
                (n, (n >> 3).wrapping_mul(5), (n ^ 0x5a).wrapping_mul(3))
            };
            data.extend_from_slice(&[b, g, r, 0]);
        }
    }
    data
}

/// The path of the reference client, built from the upstream libvncclient
/// sources, or `None` when it has not been built.
///
/// The decoders in `tests/common` were written by the same hand as the
/// encoders, so every round trip through them proves the two agree and nothing
/// more. Three encoders shipped broken while all of them were green, which is
/// what this is for: a decoder from somewhere else entirely, asked whether it
/// can read what we send.
///
/// Set `QEMU_VNC_REFCLIENT` to the binary. Without it the test is skipped
/// rather than passed, because a skipped test that looks green is how the last
/// three bugs survived.
fn reference_client() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("QEMU_VNC_REFCLIENT")?;
    let path = std::path::PathBuf::from(path);
    if path.exists() { Some(path) } else { None }
}

fn vncrs_witness() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("QEMU_VNC_VNCRS_WITNESS")?;
    let path = std::path::PathBuf::from(path);
    if path.exists() { Some(path) } else { None }
}

#[test]
fn a_reference_client_can_read_our_zrle() {
    // The whole point: libvncclient's own ZRLE decoder, asked to read a frame
    // from this server. It prints how many pixels it decoded and how many were
    // not black; a screen of anything but black is the pass condition.
    assert!(reference_client().is_some() || {
        eprintln!("skipped: set QEMU_VNC_REFCLIENT to a libvncclient binary");
        true
    });
    let Some(program) = reference_client() else { return };

    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        mock.scanout(FIRST, noisy_frame()).await.expect("the scanout");

        // Tight is **not** in this list, and it must not be: this witness is
        // libvncclient, which has no client-side Tight support at all and reports
        // an all-black screen for it. Tight has its own test on vnc-rs --
        // `a_reference_client_can_read_our_tight` -- because adding it here once
        // looked like this port failing when it was the witness being unable to
        // read the encoding.
        for (name, encoding) in [("zrle", "16"), ("hextile", "5"), ("raw", "0")] {
            let text = run_reference_client(&server, &program, encoding).await;
            println!("--- {name} ---\n{text}");
            assert!(
                text.contains("VERDICT: ok"),
                "the reference client did not get a picture over {name}: {text}"
            );
        }
    });
}

/// **The reference client's pixel format is part of this test, not an
/// afterthought.** `refclient` sends `SetPixelFormat` by hand, asking for red
/// in the **low** byte, and without it libvncclient cannot read QEMU's ZRLE or
/// this server's -- see PORTING.md, "The witness was built wrong twice". Two
/// separate mistakes, both in the witness and neither in the port:
///
/// - libvncclient built without zlib has `case rfbEncodingZRLE:` **compiled
///   out**, so encoding 16 falls through to `default:` and it prints "Unknown
///   rect encoding 16" and reports no picture;
/// - with zlib it segfaults instead, because it picks the ZRLE variant from the
///   client's colour masks. The server's default format -- `rshift 16, gshift 8,
///   bshift 0`, byte for byte what QEMU announces via
///   `qemu_default_pixelformat(32)` -- has no zero byte in the client's pixel,
///   so libvncclient expects **four** bytes a pixel where QEMU, and this port,
///   always write **three**.
///
/// Asking for red in the low byte puts the client on the three-byte path, which
/// is what production's viewer asked for, and then libvncclient decodes this
/// server's ZRLE to the same picture it gets from raw and hextile. It is a
/// client-side choice and it belongs in the client; the test would be worthless
/// without it and gave a confident all-black for a stream that was correct.
///
/// Run `program` as a client of this server, and return what it printed.
///
/// The accept loop that turns a listening socket into a served client lives in
/// `main.rs`, so the test has to do it: spawn the client, accept its connection,
/// and hand the stream over.
async fn run_reference_client(server: &Server, program: &std::path::Path, encoding: &str) -> String {
    // Bind before spawning, so the client cannot start before there is
    // something to connect to.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let child = std::process::Command::new(program)
        .arg("127.0.0.1")
        .arg(port.to_string())
        .arg(encoding)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the reference client to start");
    let (stream, peer) = listener.accept().expect("the client's connection");
    server.add_client(stream, peer).expect("the client to be added");
    // The client's task now runs on this executor, so waiting for the process
    // here would block the very thread that has to serve it. Hand the wait to a
    // thread of its own and let the reactor keep running.
    let out = std::thread::spawn(move || child.wait_with_output())
        .join()
        .expect("the wait to finish")
        .expect("the client to finish");
    // **How it ended, always.** A client that segfaults produces no stdout and
    // a handshake on stderr, and "no picture" is what a decoder that quietly
    // gave up also produces; the two are indistinguishable in the text above and
    // they mean completely different things -- one is our stream crashing their
    // client, the other is their client declining to read it. This report said
    // "every pixel is black" for a run in which the process was killed by a
    // signal, and it took a rebuild of libvncclient to find that out.
    let how = match out.status.code() {
        Some(0) => "exited 0".to_owned(),
        Some(c) => format!("**exited {c}**"),
        // `ExitStatusExt` for the signal, which is std::os::unix only and
        // this file is unix-only anyway: the whole RFB stack is TCP.
        None => format!("**killed by signal {}**", std::os::unix::process::ExitStatusExt::signal(&out.status).unwrap_or(0)),
    };
    format!(
        "{}\n--- stderr ---\n{}\n--- how it ended ---\n{how}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A test that serves a frame and *waits*, so that a client outside this
/// process can connect to it.
///
/// The reference client is spawned from inside a test rather than run beside
/// one, because spawning a process that then blocks while we wait for it
/// deadlocks the single-threaded executor this crate's tests run on. So the
/// other half is a test of its own: this one serves, prints its port, and the
/// client is run from a shell.
///
/// Enabled by `QEMU_VNC_SERVE=1`; without it there is nothing to do.
#[test]
fn serve_a_frame_for_an_external_client() {
    if std::env::var_os("QEMU_VNC_SERVE").is_none() {
        return;
    }
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("an address").port();
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                "qemu_vnc=debug,qemu_vnc::display=trace",
            ))
            .with_writer(std::io::stderr)
            .init();
        // A screen the size of a real console rather than the mock's 64x32:
        // ZRLE only kicks in for rectangles worth compressing, and a 64x32
        // screen has one tile and no palette in it. The console has to be
        // resized as well as fed, or the mock announces 64x32 with the data
        // of a 320x200 screen and the two disagree.
        let mut mock = mock;
        mock.resize(FIRST, (320, 200));
        mock.scanout(FIRST, noisy_frame_of(320, 200))
            .await
            .expect("the scanout");
        // Give the server a moment to apply it, then look at what it holds.
        async_io::Timer::after(Duration::from_millis(200)).await;
        for display in server.displays() {
            if display.index() != FIRST { continue; }
            let handle = display.framebuffer();
            let seen = handle.with(|fb| (fb.dimensions(), fb.data()[..16].to_vec()));

            println!("FRAMEBUFFER {seen:?}");
        }
        println!("PORT {port}");
        use std::io::Write;
        std::io::stdout().flush().expect("flush");

        for _ in 0..4 {
            let Ok((stream, peer)) = listener.accept() else {
                break;
            };
            server.add_client(stream, peer).expect("the client to be added");
            // Give the server a moment to serve each one, then wait for the
            // next. The client runs for a few seconds on its own.
            std::thread::sleep(std::time::Duration::from_secs(8));
        }
    });
}

/// The same, for Tight's **full-colour** sub-encoding — the one added last, and
/// the one a real viewer rejected with `zlib inflate failed`.
///
/// An in-tree decoder round-trips it, and **that is not evidence**: the decoder
/// and the encoder were both written from the same reading of the format, so a
/// shared misreading passes both. This is the lesson twice over — the in-tree
/// decoder was written to match the encoder I had just written, which is the
/// definition of testing a thing against itself. libvncclient is a third
/// implementation and the one real viewers are built from.
#[test]
fn a_reference_client_can_read_our_tight() {
    assert!(reference_client().is_some() || {
        eprintln!("skipped: set QEMU_VNC_REFCLIENT to a libvncclient binary");
        true
    });
    let Some(program) = reference_client() else { return };

    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        // Three frames, so each Tight sub-encoding is tried on its own:
        // uniform -> fill, few colours -> palette, many colours -> full colour.
        let (w, h) = (WIDTH as usize, HEIGHT as usize);
        let mut flat = Vec::new();
        for _ in 0..(w * h) {
            flat.extend_from_slice(&[0x60, 0x40, 0x20, 0]);
        }
        let few = {
            let mut d = Vec::new();
            for y in 0..h {
                for x in 0..w {
                    if (x / 4 + y / 4) % 2 == 0 {
                        d.extend_from_slice(&[0x10, 0x20, 0x30, 0]);
                    } else {
                        d.extend_from_slice(&[0xc0, 0x50, 0x90, 0]);
                    }
                }
            }
            d
        };
        for (label, frame) in [
            ("fill", flat),
            ("palette", few),
            ("full colour", noisy_frame()),
        ] {
            mock.scanout(FIRST, frame).await.expect("the scanout");
            let text = run_reference_client(&server, &program, "7").await;
            let black = text.contains("every pixel is black");
            println!("--- tight, {label} ---\n{text}");
            println!("RESULT {label}: {}", if black { "BLACK" } else { "ok" });
        }
    });
}

/// A console that draws is not answered without a request, and is answered
/// with one.
///
/// This is QEMU's rule, and the test is here because the alternative was tried
/// and cost a hundred per cent of a core.
///
/// `vs->update` is assigned in exactly two places in `ui/vnc.c`:
///
/// ```c
///     vs->update = VNC_STATE_UPDATE_NONE;            // vnc_update_client, every job
///     vs->update = VNC_STATE_UPDATE_INCREMENTAL;     // framebuffer_update_request
///     vs->update = VNC_STATE_UPDATE_FORCE;           // a non-incremental request
/// ```
///
/// So `INCREMENTAL` means *a request is outstanding*, not *the client once
/// asked*, and between one update and the next QEMU holds no state that permits
/// another. It never sends an unsolicited frame. An earlier version of this test
/// asserted the opposite, on the strength of a comment here that read "the
/// client is in the incremental state its last request left it in" as though the
/// state persisted. It does not; the line above clears it.
///
/// What that push bought and what it cost:
///
/// * Bought: a client that asks exactly once, is answered, and then never asks
///   again still sees later frames. There is a report of exactly that — a black
///   screen on a working connection, from a real "no image" — and it is why the
///   push was written. The fault it was written for turned out to have a
///   different cause, found later: rectangles on the wire that no client could
///   read past. A client that has stopped asking is usually a client whose last
///   update it could not use.
/// * Cost: the frame rate stopped being the client's to choose. QEMU's is
///   bounded by the client's request rate, so a viewer struggling to decode asks
///   less often and the server's CPU falls with it — self-regulating. Pushing
///   makes the frame rate ours instead, so a console drawing at sixty frames a
///   second costs thirty-three encodes a second whether or not the client can
///   use one of them, and there is no feedback from the client's difficulty back
///   into that number.
///
/// The first half of this test is the half that matters for the CPU: the
/// console draws, nothing is sent, and the absence is asserted rather than
/// assumed. A test that only checked the second half would pass on the old
/// behaviour too, since the old behaviour also answered a request.
#[test]
fn a_console_that_draws_is_not_answered_without_a_request() {
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        // The console starts black.
        mock.scanout(FIRST, vec![0u8; WIDTH as usize * HEIGHT as usize * 4])
            .await
            .expect("the first scanout");
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);

        // The client asks, incrementally, as a viewer does, and is answered.
        rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
        let black = rfb_client::try_read_update(&mut client).expect("the first update");
        assert_eq!(black, vec![0; WIDTH as usize * HEIGHT as usize * 4]);

        // Now the guest draws, and the client does not ask again. Nothing is
        // sent: this is the assertion that costs nothing to make and is the
        // whole of the CPU argument. Several refresh intervals go by, which is
        // several chances to send and every one of them taken.
        mock.scanout(FIRST, frame())
            .await
            .expect("the second scanout");
        for _ in 0..6 {
            if let Ok(pixels) = rfb_client::try_read_update(&mut client) {
                panic!(
                    "the server sent {} pixels after the console drew with no request \
                     outstanding. QEMU does not do this, and it is why a guest drawing at \
                     sixty frames a second cost a whole core whatever the client could keep \
                     up with",
                    pixels.len()
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(60));
        }

        // And with a request, the very same damage is delivered. Without this
        // half the test would be satisfied by a server that never sends
        // anything, which is a server with a blank screen.
        rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
        let mut delivered = false;
        for _ in 0..40 {
            match rfb_client::try_read_update(&mut client) {
                Ok(pixels) => {
                    assert_eq!(
                        pixels,
                        frame(),
                        "the damage that arrived before the request should have reached \
                         the client, intact"
                    );
                    delivered = true;
                    break;
                }
                Err(_) => continue,
            }
        }
        assert!(
            delivered,
            "the client asked for the update the console had already produced and never \
             got it. The rule is that a request makes a frame owed, not that a request is \
             the only thing that ever does"
        );
    });
}

#[test]
fn a_reference_client_can_read_our_tight_at_productions_size() {
    // **Restored as recorded, and that is how the file had it.** `size_witness`
    // is `async fn`, so calling it bare built a future and dropped it: the
    // body never ran, which is why the original run of this test finished in
    // 0.00s and the compiler flagged an unused `Future`. `block_on` is what
    // every other async helper in this file is called through.
    async_io::block_on(size_witness("tight"));
}

/// The control for the test above, and the reason it can be read at all.
///
/// **Without this, "Tight failed at 1280x800" does not mean Tight is wrong.** It
/// could equally mean the witness cannot manage a screen that size, or that
/// something in the path is wrong at every encoding. Running ZRLE at the same
/// size separates those: ZRLE reads it, so the size and the harness are fine and
/// the fault is in the Tight path; ZRLE does not, and neither conclusion is
/// available.
#[test]
fn a_reference_client_can_read_our_zrle_at_productions_size() {
    // **Restored as recorded, and that is how the file had it.** `size_witness`
    // is `async fn`, so calling it bare built a future and dropped it: the
    // body never ran, which is why the original run of this test finished in
    // 0.00s and the compiler flagged an unused `Future`. `block_on` is what
    // every other async helper in this file is called through.
    async_io::block_on(size_witness("zrle"));
}

/// One 1280x800 round trip, over whichever encoding the caller names.
///
/// Split out because the two calls have to differ in exactly one thing -- the
/// encoding -- and a shared body that took the encoding as a parameter was the
/// obvious way to guarantee that.
async fn size_witness(encoding: &str) {
    let Some(program) = vncrs_witness() else {
        eprintln!("skipped: set QEMU_VNC_VNCRS_WITNESS to the vnc-rs witness binary");
        return;
    };

    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        return;
    }
    {
        let (w, h) = (1280u32, 800u32);
        let (mock, connection) = MockQemu::start((w, h))
            .await
            .expect("the mock to export its interfaces");
        let server = Server::new(&connection, "mock", Share::Ignore)
            .await
            .expect("a server");
        server
            .add_graphic_console(FIRST)
            .await
            .expect("the console to be added");
        mock.wait_registered(FIRST).await;

        // Video-shaped: a sky gradient, a noisy band, and a flat wall. More than
        // 256 colours overall, which is what forces the full-colour
        // sub-encoding rather than the palette.
        let mut frame = vec![0u8; (w * h * 4) as usize];
        for y in 0..h {
            for x in 0..w {
                let o = ((y * w) + x) as usize * 4;
                let rgb = if y < h / 5 {
                    // A flat band: one colour, so the encoder sees a solid rect.
                    [0x20u8, 0x40, 0x60]
                } else if y < h / 2 {
                    // A checkerboard.
                    if (x / 8 + y / 8) % 2 == 0 { [0xff, 0xff, 0xff] } else { [0, 0, 0] }
                } else {
                    // Noise, which is what forces the palette over.
                    let n = (x as u8).wrapping_mul(7).wrapping_add((y as u8).wrapping_mul(13));
                    [n, (n >> 3).wrapping_mul(5), (n ^ 0x5a).wrapping_mul(3)]
                };
                // x8r8g8b8 is B, G, R, unused.
                frame[o] = rgb[2];
                frame[o + 1] = rgb[1];
                frame[o + 2] = rgb[0];
                frame[o + 3] = 0;
            }
        }
        mock.scanout(FIRST, frame).await.expect("the scanout");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let child = std::process::Command::new(&program)
            .arg("127.0.0.1")
            .arg(port.to_string())
            .arg(encoding)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the witness to start");
        let (stream, peer) = listener.accept().expect("the witness's connection");
        server.add_client(stream, peer).expect("the client to be added");
        let out = std::thread::spawn(move || child.wait_with_output())
            .join()
            .expect("the wait to finish")
            .expect("the witness to finish");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        println!("--- {encoding}, 1280x800 ---\\n{text}");
        assert!(
            text.contains("VERDICT: ok"),
            "an independent decoder could not read our {encoding} at production's \\
             size: {text}"
        );
    }
}

/// Serve the real server on a real port, for a reference client to connect to.
///
/// Every other test here talks to the server with a decoder this project
/// wrote, which is the one thing that cannot catch a wire-format bug: a
/// decoder written by the same hand as the encoder only proves the two agree.
/// The independent decoder is libvncclient, and it is a program, not a
/// function: it needs a server that stays up while it runs, so it cannot be
/// driven from inside a test body without deadlocking the executor that has to
/// serve it.
///
/// So this is a test that serves rather than asserts. It does nothing unless
/// `QEMU_VNC_SERVE` is set, in which case it prints `PORT <n>` on stdout and
/// then accepts connections until it is killed. Run it, then point a real
/// client at the port:
///
/// ```text
/// QEMU_VNC_SERVE=1 cargo test -p qemu-vnc --test mock serve_for_a_reference_client -- --nocapture
/// ```
#[test]
fn serve_for_a_reference_client() {
    if std::env::var("QEMU_VNC_SERVE").is_err() {
        // Nothing to serve, and nothing to assert: the value of this is that
        // another program can connect, which a return code cannot express.
        return;
    }
    async_io::block_on(async {
        // A console big enough that ZRLE has to tile it, and with a
        // sub-rectangle in the middle of a row so a mis-ordered tile shows up
        // as a picture with a band out of place rather than as noise.
        let (width, height) = (320u32, 200u32);
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                std::env::var("QEMU_VNC_LOG").unwrap_or_else(|_| "qemu_vnc=info".into()),
            ))
            .with_writer(std::io::stderr)
            .try_init();
        let (mut mock, connection) = mock().await;
        let server = Server::new(&connection, "mock", Share::Ignore)
            .await
            .expect("a server");
        let console = server
            .add_graphic_console(FIRST)
            .await
            .expect("the console to be added");
        mock.resize(FIRST, (width, height));
        mock.wait_registered(FIRST).await;
        mock.scanout(FIRST, desktop(width as u16, height as u16))
            .await
            .expect("the scanout to be sent");
        // And then, continuously, the shape the production log shows after the
        // first frame: thin strips at the bottom of the screen, which is a
        // taskbar redrawing itself. The first frame is a full-screen rectangle
        // and renders; everything after it is 320x13, encoded differently. A
        // client that renders the first and then stops has to be failing on the
        // second, so the second is what a reference client has to be shown.
        //
        // A task of its own, because the strips have to arrive *after* a client
        // has taken the first frame. Pushed before one connects, they are
        // absorbed into the initial full-screen damage and never appear as the
        // rectangles they are — which is exactly what happened the first time
        // this was tried, and it looked like a pass.

        let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let addr = socket.local_addr().expect("an address");
        server.add_listener(qemu_vnc::server::ListenerInfo {
            addr,
            auth: "None".into(),
            websocket: false,
        });
        println!("PORT {addr}");
        io::stdout().flush().expect("the port to be printed");

        // The heartbeat, on its own thread, exactly as `main.rs` runs it.
        //
        // Without it this fixture is a black box: the reference client can report
        // "147 incremental requests sent, 2 rectangles received" and there is
        // nothing on the other side of that to tell a server that is not sending
        // from a client that is not reading. That is the same mistake §8 records
        // about `encode_ms` — a diagnostic asked for after the fact, from a
        // report of a symptom nobody could interpret. `updates_per_interval` and
        // `client_events_per_interval` answer it in one line.
        //
        // `serve_for_a_reference_client` has now been run twice with a client
        // that never saw a strip, and this is what would have said why.
        std::thread::Builder::new()
            .name("heartbeat".into())
            .spawn(|| {
                async_io::block_on(qemu_vnc::counters::heartbeat(async {
                    futures::future::pending::<()>().await;
                }))
            })
            .expect("the heartbeat to start");

        // The accept loop, which is `main.rs`'s: the library does not own it.
        // Non-blocking, so that it can also drive the strip pusher below — the
        // reference client is a separate process and has to be fed while it is
        // reading, which a blocking accept cannot do.
        socket.set_nonblocking(true).expect("a non-blocking listener");
        let mut since_strip = std::time::Instant::now();
        let mut round = 0u32;
        loop {
            match socket.accept() {
                Ok((stream, addr)) => {
                    if let Err(e) = server.add_client(stream, addr) {
                        eprintln!("failed to add a client: {e}");
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("accept failed: {e}");
                    break;
                }
            }
            // A thin strip at the bottom of the screen, which is a taskbar
            // redrawing itself, every 400ms. The first frame is a full-screen
            // rectangle; everything after it is 320x13. A client that renders the
            // first and then stops has to be failing on the second, so the second
            // is what a reference client has to be shown — and it has to arrive
            // *after* a client has taken the first frame, which is why this is in
            // the accept loop and not before it.
            if since_strip.elapsed() >= std::time::Duration::from_millis(400) {
                since_strip = std::time::Instant::now();
                let top = 162 + (round % 2) as i32;
                let mut strip = Vec::new();
                for row in 0..13u32 {
                    for x in 0..(width as i32) {
                        let n = ((x as u32).wrapping_mul(2654435761) >> 20) as u8;
                        strip.extend_from_slice(&[
                            n.wrapping_add((round as u8).wrapping_add(row as u8)),
                            0x40,
                            0x60,
                            0,
                        ]);
                    }
                }
                if mock
                    .update(FIRST, (0, top, width as i32, 13), strip)
                    .await
                    .is_err()
                {
                    break;
                }
                round += 1;
            }
            async_io::Timer::after(std::time::Duration::from_millis(20)).await;
        }
        drop(console);
    });
}

/// A frame that looks like a desktop rather than a test pattern.
///
/// A gradient with text-like detail in it, a flat panel, and a band of noise.
/// The three shapes are there because they drive the three ZRLE tile
/// sub-encodings, and because a decoder that gets the tile order or the tile
/// size wrong shows it as a picture with a band in the wrong place, which is a
/// different failure from a picture of noise.
fn desktop(width: u16, height: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(width as usize * height as usize * 4);
    for y in 0..height as usize {
        for x in 0..width as usize {
            let (r, g, b) = if y < 40 {
                // A flat title bar: one solid tile.
                (0x20, 0x40, 0x60)
            } else if y < height as usize - 30 {
                // A gradient with a repeating mark in it: many colours per
                // tile, but neighbouring pixels agree.
                let band = ((x / 8 + y / 8) % 3) as u16;
                let t = (x * 255 / width.max(1) as usize) as u16;
                (
                    (t / 2 + band * 20) as u8,
                    (t + band * 30) as u8,
                    (255 - t / 2) as u8,
                )
            } else {
                // A checkerboard: a palette, and a strict test of index order.
                if (x / 4 + y / 4) % 2 == 0 {
                    (0xff, 0xff, 0xff)
                } else {
                    (0, 0, 0)
                }
            };
            data.extend_from_slice(&[b, g, r, 0]);
        }
    }
    data
}

/// A client that announces every pseudo-encoding gets a stream it can walk.
///
/// The bug this catches is not a decoding bug, which is why nothing here
/// decodes a pixel. It is that the server used to acknowledge six
/// pseudo-encodings with bare rectangles, two of which
/// (`ExtendedDesktopSize` at -308 and `Led` at -261) are followed by a payload
/// the specification and QEMU both write. A client reads that payload whether
/// or not it was sent, so the rectangle after it is consumed as payload and
/// every byte after *that* is read at the wrong offset. The failure a user sees
/// is a viewer that connects, negotiates, and shows a blank screen, because it
/// decoded nonsense and gave up — with nothing in the server's log to say so.
///
/// So the assertion is the only one that matters here: the stream must stay in
/// sync. `SyncReader` walks the message structure with a table of what each
/// encoding carries, and if the server emits a rectangle whose length the table
/// cannot resolve — or a payload-free rectangle for an encoding that has a
/// payload — the walk fails, which is exactly what a real client does.
#[test]
fn the_stream_stays_in_sync_when_every_pseudo_encoding_is_announced() {
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        mock.wait_registered(FIRST).await;

        // Everything a real viewer announces, and then some: the two that
        // desynchronised the stream, the payload-free ones, and the ones with
        // payloads of their own.
        rfb_client::send_set_encodings(
            &mut client,
            &[
                rfb_client::encoding::RAW,
                rfb_client::encoding::ZRLE,
                rfb_client::encoding::DESKTOP_SIZE,
                rfb_client::encoding::RICH_CURSOR,
                rfb_client::encoding::CURSOR_WITH_ALPHA,
                rfb_client::encoding::EXTENDED_KEY_EVENT,
                rfb_client::encoding::LED,
                rfb_client::encoding::EXTENDED_DESKTOP_SIZE,
                rfb_client::encoding::AUDIO,
            ],
        );
        // Something to send, so the walk reaches a rectangle with pixels in it.
        // Without this the server has nothing to volunteer and the read below
        // blocks — which is a hang, not a failure, and a test that can hang is a
        // test that will.
        mock.scanout(FIRST, noisy_frame_of(WIDTH, HEIGHT))
            .await
            .expect("the scanout to be sent");

        // Every message the server volunteers, read as a stranger would read
        // them: the acknowledgements first, then the frame. A read that runs
        // out of time is not a failure — the server is entitled to say nothing
        // more — so it means "ask again" rather than "give up". The budget is
        // in attempts of ask-then-read, not in reads, because a loaded machine
        // is slow and slow is not broken: only a stream that does not add up
        // is a fault, and that ends the walk at once.
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("a read timeout");
        let mut reader = rfb_client::SyncReader::new(4);
        let mut seen: Vec<i32> = Vec::new();
        let mut walked = 0;
        let mut pixels = 0;
        let mut payload = false;
        for _ in 0..ATTEMPTS {
            rfb_client::request_full_update(&mut client, 0, 0, WIDTH, HEIGHT);
            let rects = match reader.read_update(&mut client) {
                Ok(rects) => rects,
                Err(e) if rfb_client::SyncReader::is_idle(&e) => continue,
                Err(e) => panic!(
                    "the stream stopped making sense after {walked} message(s), \
                     having seen encodings {seen:?}: {e}"
                ),
            };
            walked += 1;
            seen.extend(rects.iter().map(|r| r.encoding));
            // A rectangle that carries pixels, whichever encoding was chosen.
            // Not "a ZRLE": the client announced ZRLE *and* raw, and which one
            // the server picks is its own policy, which this test has no
            // business constraining. The test is `>= 0` and not `> 0` because
            // raw *is* zero, and a rectangle full of pixels is exactly what
            // this is looking for.
            if rects.iter().any(|r| r.encoding >= 0) {
                pixels += 1;
            }
            // A rectangle whose payload a reader has to be given, which is the
            // one that broke production. The walk must not stop at the frame to
            // look for it: the resize reply and the frame go out as separate
            // messages and either can be first, so stopping at the frame would
            // make this assertion a race that a loaded machine wins.
            if rects
                .iter()
                .any(|r| r.encoding == rfb_client::encoding::EXTENDED_DESKTOP_SIZE)
            {
                payload = true;
            }
            // Both halves seen: the walk is now known to have handled a
            // rectangle with a payload *and* one with pixels, in one stream.
            if pixels > 0 && payload {
                break;
            }
        }
        assert!(
            walked > 0,
            "the server sent nothing at all after the encodings were announced"
        );
        assert!(
            pixels > 0,
            "the walk never reached a rectangle with pixels, so it proved \
             nothing about what follows the acknowledgements; saw {seen:?}"
        );
        // `ExtendedDesktopSize` is expected here, and it is worth saying why,
        // because it is the encoding that broke production. QEMU's
        // `vnc_set_encodings()` calls `vnc_desktop_resize()` first thing, and
        // that sends this rectangle *with* its twenty bytes of screen
        // description. The fault was never that rectangle; it was a second one,
        // bare, sent as though it were an acknowledgement. So the positive
        // statement is that a payload-carrying rectangle appeared, a rectangle
        // with pixels appeared, and the walk was still in step afterwards —
        // which is only possible if the payload was written, since a reader
        // consumes those bytes either way.
        assert!(
            payload,
            "the resize reply never arrived, so the walk never had to step over \
             a payload: {seen:?}"
        );
        assert!(
            !seen.contains(&rfb_client::encoding::LED),
            "the LED state rectangle carries a byte we have no reason to send, \
             and the walk only survived it by luck: {seen:?}"
        );
    });
}

/// The acknowledgements are the payload-free ones and no others.
///
/// QEMU acknowledges exactly two encodings, in `send_ext_key_event_ack()` and
/// `send_ext_audio_ack()`, and both write a rectangle and stop. The list here
/// is checked against QEMU's rather than against this port's own idea of what
/// is safe, because the port's idea is what was wrong.
#[test]
fn only_the_payload_free_pseudo_encodings_are_acknowledged() {
    // QEMU's vnc.c: send_ext_key_event_ack() and send_ext_audio_ack() are the
    // only two functions that write a FramebufferUpdate rectangle with a
    // pseudo-encoding and nothing after it.
    let qemu_acknowledges: &[i32] = &[-258, -259];
    let ours: Vec<i32> = qemu_vnc::rfb::protocol::Encoding::ACKNOWLEDGED
        .iter()
        .map(|e| qemu_vnc::rfb::protocol::Encoding::number(*e))
        .collect();
    assert_eq!(
        ours,
        qemu_acknowledges.to_vec(),
        "the acknowledged set has drifted from QEMU's; every addition needs a \
         reason it is payload-free, and every removal needs a reason it is not"
    );
}

/// The encodings that carry a payload cannot be sent bare, and the guard says so.
///
/// The panic in `add_pseudo_encoding` is the only thing standing between a
/// future change and the desynchronised stream this port shipped, so it is
/// tested rather than assumed: each of the payload-carrying encodings must be
/// refused, and the two payload-free ones must be accepted.
#[test]
fn a_bare_rectangle_is_refused_for_every_encoding_that_carries_a_payload() {
    use qemu_vnc::rfb::{protocol::Encoding, FramebufferUpdate};
    // Every encoding QEMU or the specification gives a payload to, with the
    // number each one uses. `ExtendedDesktopSize` is the one that broke the
    // stream in production; `Led` is the one that would have, next.
    let with_payload: &[(Encoding, i32)] = &[
        (Encoding::ExtendedDesktopSize, -308),
        (Encoding::Led, -261),
        (Encoding::RichCursor, -239),
        (Encoding::CursorWithAlpha, -314),
        (Encoding::DesktopName, -307),
        (Encoding::Fence, -312),
    ];
    for (encoding, number) in with_payload {
        assert_eq!(
            Encoding::number(*encoding),
            *number,
            "{encoding:?} moved, so the table in this test is stale"
        );
        assert!(
            !encoding.is_payload_free(),
            "{encoding:?} ({number}) carries a payload, so a bare rectangle for it \
             would desynchronise the client's stream"
        );
        // And the guard the server actually has.
        let refused = std::panic::catch_unwind(|| {
            let mut fbu = FramebufferUpdate::new(None);
            fbu.add_pseudo_encoding(*encoding, 64, 32);
        });
        assert!(
            refused.is_err(),
            "add_pseudo_encoding accepted {encoding:?}, which is not payload-free"
        );
    }
    for encoding in Encoding::ACKNOWLEDGED {
        assert!(
            encoding.is_payload_free(),
            "{encoding:?} is acknowledged but is not payload-free"
        );
        // Not refused: a payload-free encoding is legal, and the guard must not
        // stop the two QEMU sends.
        let mut fbu = FramebufferUpdate::new(None);
        fbu.add_pseudo_encoding(*encoding, 64, 32);
    }
}

/// The stream walk can tell a desynchronised stream from a sound one.
///
/// Without this, `the_stream_stays_in_sync_…` proves nothing: it passed when
/// the only thing standing between it and a broken stream was a panic in the
/// server, which is a different mechanism and could be satisfied by a server
/// that sent a bare rectangle *and* had a guard. So the walk is pointed at a
/// stream that is wrong on purpose — the twelve bytes of a bare
/// `ExtendedDesktopSize` rectangle, which is what this port used to send, and
/// then a rectangle with real pixels in it — and it has to fail.
///
/// The failure is a client's failure, verbatim: it reads the next rectangle's
/// header as the payload it was owed, and is then decoding at the wrong
/// offset. libvncclient's response to the same bytes is to give up, which is
/// why the user saw a blank screen rather than a corrupted one.
#[test]
fn the_stream_walk_detects_a_bare_rectangle_for_an_encoding_with_a_payload() {
    let width = WIDTH;
    let height = HEIGHT;
    let raw_body = vec![0u8; width as usize * height as usize * 4];

    // What the server used to send: a bare rectangle for an encoding whose
    // payload the reader is owed, followed by an ordinary frame.
    let broken = rfb_client::update_bytes(
        &[
            (0, 0, width, height, rfb_client::encoding::EXTENDED_DESKTOP_SIZE),
            (0, 0, width, height, rfb_client::encoding::RAW),
        ],
        &[&[], &raw_body],
    );
    let mut reader = rfb_client::SyncReader::new(4);
    let rects = reader
        .read_update(&mut &broken[..])
        .expect("the walk reads what is there, however wrong it is");

    // This is the failure, and it is worse than an error. The reader consumed
    // the frame's twelve-byte header and eight bytes of its geometry as the
    // screen description it was owed, so it reports a rectangle the server
    // never sent: 64x32 at 64,32, where 64x32 at 0,0 was sent. Nothing says
    // "malformed". A client that trusts its reader goes on to draw that
    // rectangle, and every rectangle after it is read at the wrong offset too.
    assert_eq!(
        (rects[1].width, rects[1].height),
        (0, 0),
        "expected the frame's geometry to have been eaten as the screen \
         description, and it was not: the walk reported {:?}",
        rects[1]
    );
    assert_ne!(
        rects[1..],
        [rfb_client::WireRect {
            x: 0,
            y: 0,
            width,
            height,
            encoding: rfb_client::encoding::RAW,
        }],
        "the walk reported a rectangle the server never sent, which is the \
         whole failure: a client that draws it is drawing the wrong bytes at the \
         wrong place and has no way to tell. It reported {:?}.",
        rects[1]
    );

    // The same stream with the payload written, which is what QEMU's
    // `vnc_desktop_resize_ext()` does and what this port's resize path already
    // did. The walk reaches the frame, and the frame is the frame.
    // One screen, three bytes of padding, and the sixteen-byte screen
    // description: the whole payload, all twenty bytes of it.
    let mut payload = vec![1u8, 0, 0, 0];
    payload.extend_from_slice(&[0u8; 16]);
    let mut good = rfb_client::update_bytes(
        &[(0, 0, width, height, rfb_client::encoding::EXTENDED_DESKTOP_SIZE)],
        &[&payload],
    );
    let fixed = rfb_client::update_bytes(
        &[(0, 0, width, height, rfb_client::encoding::RAW)],
        &[&raw_body],
    );
    good.extend_from_slice(&fixed);
    let mut rest = &good[..];
    let mut reader = rfb_client::SyncReader::new(4);
    let announced = reader
        .read_update(&mut rest)
        .expect("with the payload written, the announcement should read");
    assert_eq!(announced.len(), 1);
    assert_eq!(
        announced[0].encoding,
        rfb_client::encoding::EXTENDED_DESKTOP_SIZE
    );
    let frame = reader
        .read_update(&mut rest)
        .expect("and then the walk should reach the frame");
    assert_eq!(
        frame,
        vec![rfb_client::WireRect {
            x: 0,
            y: 0,
            width,
            height,
            encoding: rfb_client::encoding::RAW,
        }],
        "the frame should come back as the frame that was sent"
    );
    // And nothing is left over, which is the property being claimed: every byte
    // the server wrote was consumed as something.
    assert!(rest.is_empty(), "{} bytes left over", rest.len());
}

/// A request that is not incremental is answered even when nothing is damaged.
///
/// This is a protocol requirement, not a nicety, and it is the one a viewer
/// leans on hardest: a client that has just connected sends `incremental: 0`
/// for the whole screen because it has nothing to show, and a client that has
/// lost the frame it was drawing asks again the same way. Either way the server
/// owes it the rectangle, whatever the server believes has changed.
///
/// QEMU says so in six lines. `framebuffer_update_request()` marks the
/// requested rectangle dirty on the non-incremental branch and sets
/// `VNC_STATE_UPDATE_FORCE`, and `vnc_update_client()`'s
///
/// ```c
/// if (!vs->has_dirty && vs->update != VNC_STATE_UPDATE_FORCE) {
///     return 0;
/// }
/// ```
///
/// lets it past the damage check. Treating the flag as a hint instead — which is
/// what this port did — means the answer depends on whether some *earlier* push
/// already consumed the damage. That is how a viewer connects, asks for a
/// frame, and is sent nothing: no error, no log line, a blank window.
///
/// The test is written so the damage really is gone first: a scanout, then a
/// drain of everything the server sends until the socket is quiet. Whatever
/// follows is then the answer to the request, with no pending damage to hide
/// behind.
#[test]
fn a_request_that_is_not_incremental_is_answered_with_nothing_pending() {
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        mock.scanout(FIRST, frame())
            .await
            .expect("the scanout arrives");

        // Everything the server volunteers, until it says nothing more. After
        // this the console has drawn and the server has sent it, so the damage
        // is spent — which is the state a client is in after connecting, and
        // the state in which a hint-only server answers nothing.
        for _ in 0..16 {
            if rfb_client::try_read_rect(&mut client).is_err() {
                break;
            }
        }

        // Now ask for the whole screen, not incrementally.
        rfb_client::request_full_update(&mut client, 0, 0, WIDTH, HEIGHT);
        let (rect, _mask) = rfb_client::try_read_rect(&mut client)
            .expect("a non-incremental request must be answered even with nothing pending");
        assert_eq!(
            rect.encoding,
            rfb_client::encoding::RAW,
            "the answer should be the rectangle that was asked for"
        );
        assert_eq!((rect.width, rect.height), (WIDTH, HEIGHT));
        assert_eq!(
            rect.pixels,
            frame(),
            "and it should be the console as it stands"
        );
    });
}

/// A client that announces a resize encoding late is still told the size.
///
/// The console can draw — and the server can therefore start pushing an update
/// — before the client's `SetEncodings` has been read: the console's pixels
/// arrive on the D-Bus listener's task and the client's messages on its own,
/// and neither waits for the other. At that point the client has announced
/// nothing, so there is no encoding to announce the size in.
///
/// The size must therefore stay *unrecorded* until it has been sent, or the
/// next update finds nothing to do and the client is never told — for the rest
/// of the connection — that the framebuffer is not the size in its `ServerInit`.
/// A viewer that gets this wrong shows a window of the wrong size, or a window
/// with no image in it, with nothing in the log.
///
/// Written to force the ordering rather than to wait for it: the client
/// announces its resize encoding *after* a frame has already been delivered, so
/// the first update really does happen with nothing announced.
#[test]
fn a_client_that_announces_a_resize_encoding_late_is_still_told_the_size() {
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        // No resize encoding yet: this is the whole point.
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        mock.scanout(FIRST, frame())
            .await
            .expect("the first scanout arrives");
        // Take everything the server volunteers, so the first update has
        // definitely happened and the damage is spent.
        for _ in 0..16 {
            if rfb_client::try_read_rect(&mut client).is_err() {
                break;
            }
        }

        // Now the client says which resize encoding it wants, and asks again.
        rfb_client::send_set_encodings(
            &mut client,
            &[
                rfb_client::encoding::RAW,
                rfb_client::encoding::EXTENDED_DESKTOP_SIZE,
            ],
        );
        //
        // The second frame is *tinted differently*. Redrawing the same pixels is
        // not damage — the server compares each update against its own copy of
        // the surface and finds nothing that differs — so sending `frame()`
        // twice used to owe a second frame and now does not. This test is about
        // the deadline delivering what is owed, so what it owes has to exist.
        // Damage, so an update happens at all.
        mock.scanout(FIRST, frame_tinted(0x3c))
            .await
            .expect("the second scanout arrives");

        // The size is announced in the encoding the client asked for, with its
        // payload, which is what makes it readable rather than a lie.
        let mut reader = rfb_client::SyncReader::new(4);
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("a read timeout");
        let mut announced = false;
        for _ in 0..ATTEMPTS {
            rfb_client::request_full_update(&mut client, 0, 0, WIDTH, HEIGHT);
            let Ok(rects) = reader.read_update(&mut client) else {
                continue;
            };
            if rects
                .iter()
                .any(|r| r.encoding == rfb_client::encoding::EXTENDED_DESKTOP_SIZE)
            {
                announced = true;
                break;
            }
        }
        assert!(
            announced,
            "the client announced ExtendedDesktopSize after a frame had already \
             been sent and was never told the size, because the size was \
             recorded when there was no encoding to say it in"
        );
    });
}

/// Damage that arrives too soon to send is deferred, not dropped.
///
/// The rate limit used to be a `thread::sleep` on the client's own task, which
/// held up its input handling as well as the update. It is now a deadline, and
/// the run loop's select waits on it — which is the only thing making this safe.
/// A deferral that waits for the next request or the next console event instead
/// would lose frames: the guest can draw once and then go quiet, and there may
/// be no further event. That is a dropped frame, which on a console that drew
/// once looks exactly like a console that never drew.
///
/// So the test draws, lets the interval refuse the update, and then asserts the
/// frame arrives on the deadline alone. It asks first, because a request is
/// what makes a frame owed at all: this server does not push frames nobody
/// asked for, and QEMU does not either.
#[test]
fn damage_the_interval_defers_is_still_delivered() {
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);

        // A request, because that is how a client gets anything at all. QEMU
        // sends nothing without one: `vs->update` is set to
        // `VNC_STATE_UPDATE_NONE` every time a job is queued and only
        // `framebuffer_update_request` sets it back. This test used to rely on
        // the server pushing an unasked-for frame, which no client may assume
        // and this server no longer does.
        rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);

        // The first draw, which is sent: a new client has no `last_update`, so
        // the interval has nothing to measure against.
        mock.scanout(FIRST, frame())
            .await
            .expect("the first scanout arrives");
        let (first, _) = rfb_client::try_read_rect(&mut client).expect("the first frame");
        assert_eq!(first.encoding, rfb_client::encoding::RAW);

        // A second request, and *then* the second draw. The order is the whole
        // of the deferral: a request with no damage behind it finds nothing to
        // send and sets no deadline, and the draw that follows sets one that is
        // in the future. So the frame is owed the moment the request is read
        // and arrives on the deadline rather than at once — and nothing after
        // this point asks for it or draws anything, so the deadline is the only
        // thing that can deliver it.
        //
        // The request is needed because the first frame was sent, and sending a
        // frame clears the request: QEMU's `vs->update = VNC_STATE_UPDATE_NONE`
        // runs on every job, so one request buys one update. A test that drew
        // again without asking expected a frame that is not owed, and hung
        // waiting for it.
        //
        // The second frame is *tinted differently*. Redrawing the same pixels
        // is not damage — the server compares the update against its copy of
        // the surface and finds nothing that differs — so sending `frame()`
        // twice used to owe a second frame and now does not. This test is about
        // the deadline delivering what is owed, so what it owes has to exist.
        rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
        mock.scanout(FIRST, frame_tinted(0x3c))
            .await
            .expect("the second scanout arrives");

        // Nothing else happens: no request, no further draw. The frame has to
        // arrive on the deadline alone. The generous budget is the point — a
        // test that failed at 40ms would be testing the interval rather than
        // the delivery.
        let mut delivered = false;
        for _ in 0..ATTEMPTS {
            if let Ok((rect, _)) = rfb_client::try_read_rect(&mut client)
                && rect.encoding == rfb_client::encoding::RAW
            {
                delivered = true;
                break;
            }
        }
        assert!(
            delivered,
            "the second draw was deferred and then never sent, so the client is \
             left showing the first frame for ever. The deadline is what must \
             deliver it, since no request and no further damage is coming."
        );
    });
}

/// A client cannot make the server work harder by asking more often.
///
/// This is the property the rate limit exists for, and it is the one the
/// non-incremental request threatened. Honouring `incremental: 0` is required —
/// the client is saying it has nothing to show — and it means every such
/// request marks the whole framebuffer as needing an update. If a request also
/// *sent*, a client asking in a loop would buy a full-screen encode per
/// question, and one full-screen ZRLE frame of a real console was measured at
/// tens of milliseconds. A hundred requests inside one encode is a saturated
/// core and a viewer that cannot keep up.
///
/// So requests schedule and the interval decides, which is QEMU's structure:
/// `vnc_refresh_rect()` sets the client's update state and the console refresh
/// timer is what calls `vnc_update_client()`.
///
/// Measured over a burst far faster than any interval: the number of frames the
/// client receives must be a small fraction of the number it asked for, and
/// must not grow with the size of the burst.
#[test]
fn a_burst_of_requests_buys_far_fewer_frames_than_it_asked_for() {
    const REQUESTS: usize = 60;
    on_a_bus!(|mut mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        // Enough content that an update is not instant, so a burst can land
        // inside one frame's worth of work — which is the case being tested.
        mock.resize(FIRST, (320, 200));
        mock.scanout(FIRST, noisy_frame_of(320, 200))
            .await
            .expect("the scanout arrives");
        // Drain the first frame, so what follows is the burst's doing.
        for _ in 0..ATTEMPTS {
            if rfb_client::try_read_rect(&mut client).is_err() {
                break;
            }
        }

        // The burst: as fast as the socket takes it, non-incremental, which is
        // the request that marks everything as damaged.
        let started = std::time::Instant::now();
        for _ in 0..REQUESTS {
            rfb_client::request_full_update(&mut client, 0, 0, 320, 200);
        }
        let mut frames = 0;
        while let Ok((rect, _)) = rfb_client::try_read_rect(&mut client) {
            if rect.encoding == rfb_client::encoding::RAW {
                frames += 1;
            }
        }
        let elapsed = started.elapsed();
        println!(
            "DBG {REQUESTS} requests bought {frames} full-screen frames in \
             {elapsed:.2?}"
        );
        assert!(
            frames * 4 < REQUESTS,
            "{REQUESTS} requests bought {frames} full-screen frames in {elapsed:.2?}: \
             the client's asking is still setting the rate, which is what the \
             interval is for"
        );
    });
}

/// The counters move, so a heartbeat reporting them would say something.
///
/// A counter nobody bumps is the same as no counter, and this one is easy to
/// leave unwired: the bump is a line in a hot path, it compiles whether or not
/// it is there, and nothing else in the suite would notice its absence. This is
/// the test that makes the diagnostic real, and it matters more than usual here
/// because the diagnostic exists to explain a symptom — a saturated core — that
/// no other observation has been able to account for.
///
/// Only the *totals* are asserted, never the rates: the counters are process
/// globals and the suite runs in parallel, so an exact number would be a race.
/// A total is monotonic, so "greater than zero" is a fact and "greater than the
/// last time" is not.
#[test]
fn the_server_counts_what_it_did() {
    on_a_bus!(|mock, connection| {
        use qemu_vnc::counters::counters;
        let before = counters().updates_sent.sample().0;
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        mock.scanout(FIRST, frame())
            .await
            .expect("the scanout arrives");
        // The shared reader, which sets the read timeout the socket needs and
        // asks for a full update so the answer is not left waiting on damage.
        let pixels = read_decoded(&mut client, &qemu_vnc::rfb::PixelFormat::rgb8888());
        assert!(!pixels.is_empty(), "the client got pixels to count");
        let counts = counters();
        assert!(
            counts.updates_sent.sample().0 > before,
            "no framebuffer update was counted, so the heartbeat would report a \
             server that never sent anything even when it did"
        );
        assert!(
            counts.bytes_sent.sample().0 > 0,
            "an update was counted but no bytes, so one of the two is unwired"
        );
        assert!(
            counts.client_events.sample().0 > 0,
            "the client's messages were not counted, so the heartbeat could not \
             tell a client that is talking from one that has gone quiet"
        );
        assert!(
            counts.client_loop.sample().0 > 0,
            "the client's own loop was not counted, so the one loop that could \
             plausibly be spinning would be invisible"
        );
        assert!(
            counts.dbus_messages.sample().0 > 0,
            "the console's messages were not counted, so a guest that is drawing \
             and a guest that is not would look the same"
        );
        assert!(
            counts.clients.sample().0 > 0,
            "no client was counted, so the heartbeat could not say whether \
             anyone is attached"
        );
    });
}

/// The counters divide the client's thread into the encoder and everything else.
///
/// The finding that asked for them: `encode_ms_per_interval` fell from 1121
/// to 974 on the production log — 1.74 ms an update, against a conversion
/// fix measured at 0.95 ms — while `vnc-client-0` moved from 30.9% to
/// 30.0%. **45% of a measured CPU saving did not become CPU.** Either
/// something outside the encode is taking the rest, or `encode_ms` is not
/// what the thread spends, and one subtraction decides which.
///
/// So this drives a client that draws continuously, through a real update
/// path, and asserts that `update_nanos + idle_nanos` is *at least* the
/// encode — because that is the arithmetic the heartbeat will do, and a
/// counter that does not satisfy it makes the subtraction meaningless. The
/// encode is inside the update path by construction, so anything else is a
/// wiring fault.
///
/// `update_nanos >= encode_nanos` is the assertion that matters and it is
/// one line. The exact split is not asserted: the update path also contains
/// `Damage::rects` and the clones, and how much that is depends on the
/// number of rectangles, which is the thing being measured.
#[test]
fn the_counters_cover_the_encode_and_the_rest_of_the_thread() {
    // No `mut`: `scanout` and `update` both take `&self`, so a mutable binding
    // here would be one nothing writes to, and the compiler says so.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        let mut reader = rfb_client::SyncReader::new(4);

        // Take the first screen so what follows is a real update.
        mock.scanout(FIRST, frame())
            .await
            .expect("the first screen");
        rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
        let _ = reader.read_update(&mut client);

        let before = qemu_vnc::counters::report();
        // A handful of updates, so the numbers are not one sample.
        for tint in 0..4u8 {
            rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
            mock.update(
                FIRST,
                (0, 0, WIDTH as i32, HEIGHT as i32),
                frame_tinted(tint.wrapping_mul(37).wrapping_add(1)),
            )
            .await
            .expect("a draw");
            let _ = reader.read_update(&mut client);
        }
        let after = qemu_vnc::counters::report();

        let update = after.update_ms - before.update_ms;
        let encode = after.encode_ms - before.encode_ms;
        let idle = after.idle_ms - before.idle_ms;

        assert!(
            update >= encode,
            "update_ms was {update} and encode_ms {encode}: the encode is inside the \\
             update path, so this subtraction is what makes \\
             `top - update_ms_per_interval` meaningful, and a path that reports \\
             less than the encode inside it is not measuring the path."
        );
        assert!(
            idle > 0,
            "idle_ms was {idle} over four updates. The client task spends most of \\
             its life in the select! waiting on the socket and the deadline, and \\
             a zero here means idle_nanos is not being bumped — which would \\
             leave the whole thread attributed to the encoder and make this \\
             pair of counters agree with each other for the wrong reason."
        );
    });
}

/// Damage that arrives after the first frame reaches a client that keeps asking.
///
/// This is the shape of everything that came after the first frame in the
/// production logs, and the shape a real viewer lives in. The first frame is a
/// full-screen rectangle. After that the console sends thin strips — a taskbar
/// redrawing itself, `1280x13` at the bottom of the screen — and the client is
/// sitting there having asked for incremental updates, waiting to be told.
///
/// A reference client pointed at a server doing this, asking 147 times in
/// fifteen seconds, received the first frame and nothing else. Not one strip.
/// So this is the reproduction, written the way a viewer behaves: ask, read,
/// ask again, and require that damage pushed *after* the first frame arrives.
///
/// Every read goes through [`rfb_client::SyncReader`], including the first. The
/// server answers `SetEncodings` with an `ExtendedDesktopSize` pseudo-rectangle,
/// whose twenty-byte screen description a reader has to be told about; a reader
/// that does not know that reads the payload as the next header, and every
/// message after it is nonsense. Mixing a reader that skips those payloads with
/// one that does not desynchronises the stream *in the test*, which is how the
/// first two versions of this test reported a server fault that was in fact
/// their own — the trap `PORTING.md` §8 is about, met again.
#[test]
fn damage_after_the_first_frame_reaches_a_client_that_keeps_asking() {
    on_a_bus!(|mut mock, connection| {
        // The server's own account of what it is doing, because this test is
        // about where a rectangle goes once the console has drawn it and the
        // reader is entitled to nothing more than a row of numbers.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                std::env::var("QEMU_VNC_LOG").unwrap_or_else(|_| "qemu_vnc=info".into()),
            ))
            .with_writer(std::io::stderr)
            .try_init();
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .expect("a read timeout");
        rfb_client::send_set_encodings(
            &mut client,
            &[rfb_client::encoding::ZRLE, rfb_client::encoding::ZLIB],
        );
        mock.resize(FIRST, (320, 200));
        let mut reader = rfb_client::SyncReader::new(4);

        // A helper that asks for one update and reports what came back, so the
        // first frame and the strips are read the same way.
        let ask = |client: &mut std::net::TcpStream, reader: &mut rfb_client::SyncReader| {
            rfb_client::request_update(client, 0, 0, 320, 200);
            reader.read_update(client).ok()
        };

        // The first frame, and take it, so what follows is not absorbed into it.
        mock.scanout(FIRST, desktop(320, 200))
            .await
            .expect("the first scanout");
        let mut first_seen = false;
        for _ in 0..ATTEMPTS {
            if let Some(rects) = ask(&mut client, &mut reader)
                && rects.iter().any(|r| {
                    r.encoding == rfb_client::encoding::ZRLE || r.encoding == rfb_client::encoding::ZLIB
                })
            {
                first_seen = true;
                break;
            }
        }
        assert!(first_seen, "the first frame never arrived, so nothing after it can be tested");

        // Now a thin strip at the bottom, which is what a taskbar does, and the
        // client asking for it the way a viewer does: incrementally, repeatedly.
        // Thirteen rows, because the update says thirteen: a rectangle's byte
        // count is `rows * stride`, and building one row's worth of it produces
        // `Truncated pixel data` — the server refusing a message that lies
        // about its own length, which is correct and which the first version of
        // this test took for a server fault.
        let mut strip = Vec::with_capacity(320 * 13 * 4);
        for row in 0..13u32 {
            for x in 0..320usize {
                let n = ((x as u32).wrapping_mul(2654435761) >> 20) as u8;
                strip.extend_from_slice(&[n.wrapping_add(row as u8), 0x40, 0x60, 0]);
            }
        }

        // Drain the first update *before* the strip is drawn. Damage that
        // arrives before a client has taken its first frame is absorbed into
        // that frame — which is correct, and which means a strip pushed here
        // would never appear as a rectangle at all. An earlier version of this
        // test did exactly that and reported a server fault for the hour it
        // took to notice the console had sent nothing wrong.
        rfb_client::request_update(&mut client, 0, 0, 320, 200);
        let _ = rfb_client::read_raw_zlib_rect(&mut client);

        mock.update(FIRST, (0, 162, 320, 13), strip)
            .await
            .expect("the strip to be sent");

        let mut arrived = false;
        let mut saw: Vec<String> = Vec::new();
        for _ in 0..ATTEMPTS {
            if let Some(rects) = ask(&mut client, &mut reader) {
                for rect in &rects {
                    if saw.len() < 6 {
                        saw.push(format!(
                            "{}x{} at {},{} enc={}",
                            rect.width, rect.height, rect.x, rect.y, rect.encoding
                        ));
                    }
                    if rect.encoding >= 0 && rect.height < 200 {
                        arrived = true;
                    }
                }
                if arrived {
                    break;
                }
            }
        }
        assert!(
            arrived,
            "the console drew a 320x13 strip and a client that kept asking for \
             updates never got it. Every update after the first frame is this \
             shape, which is why a viewer can show the desktop perfectly and then \
             never see it change. What the client saw: {saw:?}"
        );
    });
}

/// A zlib rectangle's length field is on the wire, and the wire is the claim.
///
/// The full-screen frame in the production logs was ZRLE, which has always
/// written its 32-bit length, and it rendered perfectly. Every update after it
/// was a thin strip encoded as zlib, and none of them ever appeared: the server
/// did not write the length, so the viewer read four bytes of the zlib stream
/// as one, waited for a length's worth of bytes that were never coming, and gave
/// up asking. The screen stayed on the first frame while the guest carried on
/// redrawing its taskbar behind it.
///
/// Nothing caught it, and the reason is worth stating precisely. The test
/// client's zlib arm did not read the length either. Server and test agreed, so
/// every zlib test in the suite passed; the suite was checking that the encoder
/// and the decoder shared one mistake, which is one function written twice. A
/// decoder is not a witness for the wire, and neither is one that shares the
/// encoder's assumption about it.
///
/// So this reads the rectangle as *bytes* and says what they are, rather than
/// handing them to a decoder that would be glad of either arrangement. Three
/// things are asserted, in the order the format states them, and the third is
/// the one that would have caught it on its own: after the rectangle, the next
/// four bytes are still a message header. A missing or wrong length shifts the
/// stream, and a shifted stream is not a rectangle.
///
/// The mutation check is in `the_length_field_is_what_fails_when_it_is_removed`.
#[test]
fn a_zlib_rectangle_puts_its_length_on_the_wire() {
    on_a_bus!(|mut mock, connection| {
        // The server's own account of itself, on the theory that a test which
        // says "nothing arrived" and cannot say why is a test that has run out
        // of ways to be wrong.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                std::env::var("QEMU_VNC_LOG").unwrap_or_else(|_| "qemu_vnc=info".into()),
            ))
            .with_writer(std::io::stderr)
            .try_init();
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a read timeout");
        // zlib and nothing else, so that whatever arrives is a zlib rectangle
        // and the walk below cannot be satisfied by a different encoding.
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::ZLIB]);
        mock.resize(FIRST, (320, 200));

        // A full screen first, and taken, before the strip is drawn. Two things
        // depend on the order. The scanout is what resizes the *surface* — the
        // resize above only changes what the mock announces, and a strip
        // pushed against a 64x32 surface is rejected as out of bounds, which is
        // correct and looks like a server that never sent anything. And damage
        // that arrives before a client has taken its first frame is absorbed
        // into that frame, so a strip pushed first never appears as a rectangle
        // of its own at all.
        mock.scanout(FIRST, desktop(320, 200))
            .await
            .expect("the first screen");
        rfb_client::request_update(&mut client, 0, 0, 320, 200);
        let _ = rfb_client::read_raw_zlib_rect(&mut client);

        let mut strip = Vec::with_capacity(320 * 13 * 4);
        for row in 0..13u32 {
            for x in 0..320usize {
                let n = ((x as u32).wrapping_mul(2654435761) >> 20) as u8;
                strip.extend_from_slice(&[n.wrapping_add(row as u8), 0x40, 0x60, 0]);
            }
        }
        mock.update(FIRST, (0, 162, 320, 13), strip)
            .await
            .expect("the strip to be sent");

        // One inflater for the whole connection, fed rectangle by rectangle,
        // which is what a real client does and what makes this a check on the
        // lengths rather than on any one rectangle in isolation. libvncclient
        // initialises `decompStream` on the first zlib rectangle and then never
        // resets it (`zlib.c`: `if (client->decompStreamInited == FALSE)`), and
        // it reads exactly `nBytes` before inflating. Nothing anywhere requires
        // the stream to *end* at a rectangle boundary, and a first draft of this
        // test that used a fresh `ZlibDecoder` per rectangle and demanded
        // `read_to_end` failed on a correct server for demanding exactly that.
        let mut inflate = flate2::Decompress::new(false);
        let mut out = vec![0u8; 320 * 200 * 4 + 64];
        let mut strip_bytes = None;
        for _ in 0..ATTEMPTS {
            rfb_client::request_update(&mut client, 0, 0, 320, 200);
            let rect = match rfb_client::read_raw_zlib_rect(&mut client) {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::InvalidData
                    ) =>
                {
                    continue
                }
                Err(e) => panic!("reading the update failed: {e}"),
            };
            assert_eq!(
                rect.declared as usize,
                rect.body.len(),
                "the rectangle's length field and its body disagree, which is the same \
                 fault as no length field at all: the client reads the length first and \
                 takes the body from that"
            );
            eprintln!(
                "PROBE rect {}x{} at {},{} declared={} body={}",
                rect.width,
                rect.height,
                rect.x,
                rect.y,
                rect.declared,
                rect.body.len()
            );
            let before = inflate.total_out();
            inflate
                .decompress(&rect.body, &mut out, flate2::FlushDecompress::None)
                .expect("the body is a zlib stream");
            let produced = (inflate.total_out() - before) as usize;
            if (rect.x, rect.y, rect.width, rect.height) == (0, 162, 320, 13) {
                // A hextile stream is not `width * height * 4`. It is one
                // sub-encoding byte per tile followed by the tile's pixels, with
                // the tile clipped at the right and bottom edges — so a 320x13
                // rectangle is twenty tiles of thirteen rows, and 16660 bytes,
                // not 16640. `a_hextile_stream_is_a_sub_encoding_byte_per_tile`
                // in `encodings.rs` is where that arithmetic is written down;
                // the first draft of this test asserted the naive figure and
                // failed by exactly the number of tiles, which looked for a
                // while like a compressor emitting twenty stray bytes.
                let tiles_x = (rect.width as usize).div_ceil(16);
                let tiles_y = (rect.height as usize).div_ceil(16);
                let want: usize = (0..tiles_y)
                    .flat_map(|ty| (0..tiles_x).map(move |tx| (tx, ty)))
                    .map(|(tx, ty)| {
                        let tw = (rect.width as usize - tx * 16).min(16);
                        let th = (rect.height as usize - ty * 16).min(16);
                        1 + tw * th * 4
                    })
                    .sum();
                assert_eq!(
                    produced,
                    want,
                    "the rectangle's length said {} bytes and the body was {} of them, \
                     but inflating it produced {produced} bytes where {want} are the \
                     tiles — so the length is right, the body is not",
                    rect.declared,
                    rect.body.len(),
                );
                strip_bytes = Some(rect.body.len());
                break;
            }
        }
        let strip_bytes = strip_bytes.expect(
            "no 320x13 zlib rectangle arrived. The console drew the strip and a client \
             asking for zlib never received it, so whatever this test is about, it was not \
             about",
        );

        // The last and the decisive one: the stream is still in step. If the
        // length had been missing, the four bytes read as one would have been
        // the head of the zlib stream, the body would have been the wrong span
        // of it, and this header would be the middle of somebody's pixels.
        //
        // Which needs something to be *sent*, because a server with no damage
        // and a client that has just been answered has nothing to say, and a
        // read that times out here says nothing about alignment. A second strip
        // is drawn so that the next message is really there to be found at the
        // wrong offset rather than not there at all.
        let mut second = Vec::with_capacity(320 * 13 * 4);
        for row in 0..13u32 {
            for x in 0..320usize {
                let n = ((x as u32).wrapping_mul(2654435761) >> 20) as u8;
                second.extend_from_slice(&[n.wrapping_add(row as u8), 0x50, 0x30, 0]);
            }
        }
        mock.update(FIRST, (0, 100, 320, 13), second)
            .await
            .expect("the second strip to be sent");
        rfb_client::request_update(&mut client, 0, 0, 320, 200);
        let mut next = [0u8; 4];
        rfb_client::read_exact(&mut client, &mut next)
            .unwrap_or_else(|e| panic!("the message after the rectangle could not be read: {e}"));
        assert_eq!(
            next[0],
            0,
            "after a {strip_bytes}-byte zlib rectangle the stream is at message type {}, \
             not a FramebufferUpdate, and the next four bytes are {next:02x?}. That is \
             pixel data: the length field is missing or wrong and everything after it is \
             being read from the wrong offset",
            next[0]
        );
    });
}

/// Two damaged regions go out as two rectangles, not as the box around them.
///
/// This is the whole of the CPU argument, and it is worth being exact about what
/// it is not. The encoding of a full 1280x800 frame is 23 ms and the encoding of
/// a 64x64 one is 0.02 ms, so a client that is sent the bounding box of two
/// small changes is paying for a thousand times the pixels it needed to send.
///
/// It used to be sent. `Damage` accumulated with `old.union(rect)`, so
/// `(0, 0, 64, 64)` and `(1200, 700, 64, 64)` became `1264x764` — nearly the
/// whole screen — and a guest running video while a taskbar clock ticks damages
/// several separate regions per frame, which is the ordinary case and not an
/// edge one. QEMU walks a dirty *bitmap* and emits one rectangle per run of
/// dirty pixels; a merged list of rectangles is not a bitmap, but for damage
/// that arrives as separate regions it captures the whole of the difference.
///
/// The test asserts the rectangle *count* and the rectangle *geometry*, because
/// a test that only checked that "some update arrived" would pass on the old
/// code and prove nothing. Two rectangles of 64x64, at the two places, is not
/// something a bounding box can produce.
#[test]
fn separate_damaged_regions_are_sent_as_separate_rectangles() {
    on_a_bus!(|mut mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a read timeout");
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::ZRLE]);
        mock.resize(FIRST, (1280, 800));
        let mut reader = rfb_client::SyncReader::new(4);

        // Take the first screen, so what follows is not absorbed into it.
        mock.scanout(FIRST, desktop(1280, 800))
            .await
            .expect("the first screen");
        rfb_client::request_update(&mut client, 0, 0, 1280, 800);
        let _ = reader.read_update(&mut client);

        // Two corners, 64x64 each, far apart. A guest doing this is a video
        // window and a clock, or a terminal and a notification.
        let strip = |seed: u8| -> Vec<u8> {
            let mut v = Vec::with_capacity(64 * 64 * 4);
            for row in 0..64u32 {
                for x in 0..64usize {
                    v.extend_from_slice(&[
                        (x as u8).wrapping_add(row as u8).wrapping_add(seed),
                        0x40,
                        0x60,
                        0,
                    ]);
                }
            }
            v
        };
        mock.update(FIRST, (0, 0, 64, 64), strip(0))
            .await
            .expect("the top-left corner");
        mock.update(FIRST, (1200, 700, 64, 64), strip(1))
            .await
            .expect("the bottom-right corner");

        // One message, two rectangles.
        rfb_client::request_update(&mut client, 0, 0, 1280, 800);
        let rects = reader
            .read_update(&mut client)
            .expect("the two regions should be answered");
        let drawn: Vec<_> = rects
            .iter()
            .filter(|r| r.encoding >= 0)
            .map(|r| (r.x, r.y, r.width, r.height))
            .collect();

        assert!(
            !drawn.is_empty(),
            "nothing arrived at all, so the two regions were never answered"
        );
        assert_eq!(
            drawn.len(),
            2,
            "two damaged regions produced {} rectangles {drawn:?} rather than two. A \\
             client sent the bounding box of a video window and a taskbar clock is sent \\
             the whole screen between them, which is the difference between 0.04 ms and \\
             23 ms of encoding for the same two changes",
            drawn.len()
        );
        for (x, y) in [(0u16, 0u16), (1200, 700)] {
            assert!(
                drawn.contains(&(x, y, 64, 64)),
                "no 64x64 rectangle at {x},{y} in {drawn:?}"
            );
        }
        // And nothing spanning the gap between them.
        assert!(
            !drawn.iter().any(|&(_x, _y, w, h)| w > 64 || h > 64),
            "a rectangle {drawn:?} is larger than either region, so the two were merged \\
             into something covering the space between them"
        );
    });
}

/// Damaged regions that share an edge are one rectangle, not two.
///
/// The companion to `separate_damaged_regions_are_sent_as_separate_rectangles`,
/// and the reason `Rect::touches` counts adjacency as well as overlap. A dirty
/// *bitmap* has no such question — bits that touch are one run — so a list of
/// rectangles standing in for a bitmap has to answer it, or a guest that walks a
/// cursor across the screen in sixteen-pixel steps sends sixteen rectangles
/// where QEMU sends one.
///
/// This one also found that `touches` was untested: merging on overlap only
/// instead of overlap-or-adjacency passed the entire suite, because every other
/// test's damage either overlapped properly or was far apart.
#[test]
fn damaged_regions_that_touch_are_merged_into_one() {
    on_a_bus!(|mut mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a read timeout");
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::ZRLE]);
        mock.resize(FIRST, (320, 200));
        let mut reader = rfb_client::SyncReader::new(4);

        mock.scanout(FIRST, desktop(320, 200))
            .await
            .expect("the first screen");
        rfb_client::request_update(&mut client, 0, 0, 320, 200);
        let _ = reader.read_update(&mut client);

        // Two rectangles sharing an edge: the second starts exactly where the
        // first ends, in x. A cursor step, and a common damage pattern.
        let block = |base: u8| -> Vec<u8> {
            let mut v = Vec::with_capacity(32 * 32 * 4);
            for row in 0..32u32 {
                for x in 0..32usize {
                    v.extend_from_slice(&[
                        (x as u8).wrapping_add(row as u8).wrapping_add(base),
                        0x40,
                        0x60,
                        0,
                    ]);
                }
            }
            v
        };
        mock.update(FIRST, (0, 0, 32, 32), block(0))
            .await
            .expect("the left half");
        mock.update(FIRST, (32, 0, 32, 32), block(1))
            .await
            .expect("the right half");

        rfb_client::request_update(&mut client, 0, 0, 320, 200);
        let rects = reader
            .read_update(&mut client)
            .expect("the touching regions should be answered");
        let drawn: Vec<_> = rects
            .iter()
            .filter(|r| r.encoding >= 0)
            .map(|r| (r.x, r.y, r.width, r.height))
            .collect();

        assert_eq!(
            drawn,
            vec![(0, 0, 64, 32)],
            "two regions sharing an edge should be one 64x32 rectangle, not {drawn:?}. \\
             A cursor dragged across the screen damages a new strip every step, and \\
             sending each as its own rectangle is a per-rectangle header on the wire for \\
             damage that is contiguous"
        );
    });
}

/// A repaint of pixels that did not change is not damage, and costs nothing.
///
/// **The guest's rectangle is a claim, not a fact.** A guest that repaints a
/// window repaints the unchanged parts of it too, and QEMU does not send those:
/// `vnc_refresh_server_surface` walks the guest's dirty map, `memcmp`s each block
/// against its own copy of the surface, and marks the client dirty only where
/// the bytes differ.
///
/// ```c
/// if (memcmp(server_ptr, guest_ptr, _cmp_bytes) == 0) {
///     continue;                    // the guest said dirty; nothing changed
/// }
/// memcpy(server_ptr, guest_ptr, _cmp_bytes);
/// QTAILQ_FOREACH(vs, &vd->clients) { set_bit(x, vs->dirty[y]); }
/// ```
///
/// Sending what the guest said anyway is not a small waste. The measurement that
/// prompted this was 388,030 pixels per update at 19.7 ms of encoding each, and
/// a decoder-driven guest repaints its output window in full every frame while
/// most of it is inter-frame repetition. The comparison costs a `memcmp` and a
/// `memcpy` over the update — about 0.2 ms for 388,000 pixels — against those
/// 19.7.
///
/// The assertion is **that nothing arrives**, which is the only thing this test
/// can honestly assert: there is no frame to check the pixels of, because the
/// whole claim is that there is no frame. `only_the_pixels_that_changed_are_sent`
/// is the positive case, because a suite with only this one in it would pass on
/// a server that never sends anything.
#[test]
fn a_repaint_of_identical_pixels_is_not_damage() {
    on_a_bus!(|mut mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a read timeout");
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        mock.resize(FIRST, (1280, 800));
        let mut reader = rfb_client::SyncReader::new(4);

        // The first screen, taken, so what follows is not absorbed into it.
        mock.scanout(FIRST, desktop(1280, 800))
            .await
            .expect("the first screen");
        rfb_client::request_update(&mut client, 0, 0, 1280, 800);
        let _ = reader.read_update(&mut client);

        // Now the guest repaints the whole screen with **exactly the same
        // pixels**. This is what a guest does every frame it draws over
        // unchanged content, and it is the case that is pure cost if the
        // rectangle is believed.
        mock.update(FIRST, (0, 0, 1280, 800), desktop(1280, 800))
            .await
            .expect("the identical repaint");

        // A client that keeps asking must still get nothing. Several requests,
        // because one asked for too early is answered before the repaint has
        // been applied, and a test that asked once would be testing that race
        // rather than the comparison.
        let mut arrived = false;
        for _ in 0..3 {
            rfb_client::request_update(&mut client, 0, 0, 1280, 800);
            if let Ok(rects) = reader.read_update(&mut client)
                && rects.iter().any(|r| r.encoding >= 0)
            {
                arrived = true;
                break;
            }
        }
        assert!(
            !arrived,
            "an update carrying pixels that were already on screen produced a \
             framebuffer update. The guest's rectangle is a claim and the server \
             has to check it against its own copy of the surface, or every \
             repaint of unchanged content costs full price to encode and to send."
        );
    });
}

/// Only the pixels that changed are sent, and only their rectangle.
///
/// The positive half of `a_repaint_of_identical_pixels_is_not_damage`. The
/// update here claims the whole screen and differs in one 64-pixel column, which
/// is the shape video produces: a large claimed rectangle, a small real change.
///
/// The geometry **is** the assertion. 800 rows of one changed column is what a
/// per-row implementation emits, and 64x800 at x=640 is what it should be — and
/// the two are indistinguishable if the test only checks that "an update
/// arrived".
/// A console offered a shared map reaches the client without a single
/// `Scanout` or `Update` message.
///
/// **This is the test that the map path needed and did not have.** Every other
/// mock method hands the client its pixels in a D-Bus message, so a port that
/// never called `set_map_listener` passed every one of them — the interface,
/// the handler trait and the `mmap` helper all existed and none of it was
/// reachable. "Compiles" and "is called" look identical from inside a test
/// suite, which is the whole reason this omission survived the entire life of
/// the port.
///
/// It is deliberately two assertions rather than one, because they can fail
/// separately and mean different things:
///
/// - the `interfaces` property **names** the map interface. An empty list fails
///   here, and it fails *quietly in production*: the interface is served,
///   QEMU never asks for a map, and nothing anywhere reports an error.
/// - the pixels **arrive**, drawn into a memory file and named by four
///   integers. That is the only part that proves the two halves are wired
///   together; the property alone would pass with a broken handler behind it.
#[test]
fn a_console_offered_a_shared_map_reaches_the_client_without_any_pixels_on_the_bus() {
    on_a_bus!(|mut mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a read timeout");
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        mock.resize(FIRST, (1280, 800));

        // The map interface has to be advertised, or QEMU -- and this test --
        // will never use it.
        let advertised = mock
            .listener_interfaces(FIRST)
            .await
            .expect("the client serves an interfaces property");
        assert!(
            advertised
                .iter()
                .any(|i| i == "org.qemu.Display1.Listener.Unix.Map"),
            "the client reports {advertised:?}, so it is not asking for a shared map. \
             It still works -- this is exactly how the port ran for its whole life, \
             with every update crossing the bus as pixels -- but nothing will tell \
             you that from the outside, which is why this assertion exists."
        );

        let mut decoders = rfb_client::Decoders::new();

        // The whole desktop through the mapping, in one `ScanoutMap`...
        let mut screen = desktop(1280, 800);
        mock.scanout_map(FIRST, screen.clone())
            .await
            .expect("the map is offered");
        // ...and a band of it repainted through `UpdateMap`, with the pixels
        // written into the mapping first and never sent.
        for y in 0..800usize {
            for x in 640..704usize {
                let o = (y * 1280 + x) * 4;
                screen[o] = 0xff;
                screen[o + 1] = 0x00;
                screen[o + 2] = 0xff;
                screen[o + 3] = 0x00;
            }
        }
        let mut band = Vec::with_capacity(64 * 4 * 800);
        for y in 0..800usize {
            band.extend_from_slice(&screen[(y * 1280 + 640) * 4..(y * 1280 + 704) * 4]);
        }
        mock.update_map(FIRST, (640, 0, 64, 800), &band)
            .await
            .expect("the mapped update");

        // And the client has the whole desktop, with the band repainted.
        rfb_client::request_update(&mut client, 0, 0, 1280, 800);
        let rects = rfb_client::try_read_update_rects(&mut client, &mut decoders)
            .expect("the client should have been sent the mapped pixels");
        let drawn: Vec<_> = rects
            .iter()
            .filter(|r| r.encoding >= 0)
            .map(|r| (r.x, r.y, r.width, r.height))
            .collect();
        assert_eq!(
            drawn,
            vec![(0, 0, 1280, 800)],
            "a console mapped in full and then given one 64x800 mapped update \
             produced {drawn:?} rather than one full-screen rectangle. The mapping \
             was offered and named, but the pixels in it did not reach the client."
        );

        // **The pixels, not just the geometry.** A full-screen rectangle in the
        // right place with the wrong contents is a rectangle the client draws as
        // noise, and the geometry assertion above would not notice.
        let full = rects
            .iter()
            .find(|r| r.encoding >= 0)
            .expect("the full-screen rectangle");
        assert_eq!(full.pixels.len(), 1280 * 800 * 4);
        // The band is *the repaint*, not the desktop: `desktop` has no magenta,
        // so a client showing the pre-mapping content would still look
        // plausible and this is the assertion that can tell the two apart.
        for y in [0usize, 1, 400, 799] {
            let o = (y * 1280 + 640) * 4;
            assert_eq!(
                &full.pixels[o..o + 4],
                &[0xff, 0x00, 0xff, 0x00],
                "the client was sent the desktop's pixel at 640,{y} rather than the \
                 repaint, so the bytes the mock wrote into the mapping never \
                 reached it. The geometry is right, which is what makes this the \
                 assertion that matters: the rectangle is full-screen either way."
            );
        }
        // And a pixel outside the band is untouched, which is what says the
        // rectangle was honoured rather than the whole surface.
        let o = (400 * 1280 + 100) * 4;
        assert_ne!(
            &full.pixels[o..o + 4],
            &[0xff, 0x00, 0xff, 0x00],
            "the client shows the repaint at 100,400, which is outside the 640..704 \
             band that was named -- so the whole surface was applied rather than \
             the rectangle, and the damage comparison would be reporting pixels \
             that never changed"
        );
    });
}

/// A mapped rectangle that names more than the mapping holds is dropped, not
/// clamped, and the client is left showing what it had.
///
/// The message path can check its geometry against the byte count that arrived
/// with it. `UpdateMap` is four integers, so the mapping is the only authority.
///
/// **The assertion is about pixels, not about survival.** The first version of
/// this checked only that the client was still speaking RFB afterwards, and a
/// mutation that removed the handler's bounds check entirely -- clamping
/// instead of dropping -- passed it. Two guards catch that rectangle, the
/// handler's and `set_mapped_rect`'s own, and a test which cannot tell which
/// one fired has measured nothing. So the client is asked what it is showing
/// afterwards: a clamp puts eight columns of the wrong colour at the right edge
/// of the screen, which is a plausible picture, whereas a drop leaves the
/// desktop that was already there. Clamping is the worse of the two failures
/// precisely because it is not visibly one.
#[test]
fn a_mapped_rectangle_that_does_not_fit_is_dropped_and_the_client_is_left_alone() {
    on_a_bus!(|mut mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a read timeout");
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        mock.resize(FIRST, (1280, 800));

        let mut decoders = rfb_client::Decoders::new();
        mock.scanout_map(FIRST, desktop(1280, 800))
            .await
            .expect("the map is offered");

        // 1276 + 8 is four pixels past a 1280-wide mapping. The mock writes the
        // bytes first, the way QEMU would, and then names the rectangle -- so
        // what is being tested is the client's refusal, not the mock's
        // arithmetic.
        // `0xff, 0x00, 0xff` and a junk fourth byte. The junk is deliberate:
        // the mapped path clears x8r8g8b8's padding byte exactly as the message
        // path does, so what reaches the client is `[0xff, 0x00, 0xff, 0x00]`.
        // Filling the buffer with `0xff` instead -- which is what this had at
        // first -- makes the client send *white*, and a test looking for magenta
        // then passes whether or not the rectangle was clamped. It passed the
        // mutation that removed both bounds checks before this was noticed.
        let out_of_bounds = [0xffu8, 0x00, 0xff, 0xff].repeat(8 * 8);
        let _ = mock.update_map(FIRST, (1276, 0, 8, 8), &out_of_bounds).await;

        rfb_client::request_update(&mut client, 0, 0, 1280, 800);
        let rects = rfb_client::try_read_update_rects(&mut client, &mut decoders)
            .expect("a dropped rectangle must not take the client down with it");
        assert!(
            rects.iter().all(|r| r.encoding >= 0),
            "the client is no longer speaking RFB after a rectangle that did not fit: \
             {rects:?}"
        );
        // Whatever was sent, no pixel may be the magenta that was only ever
        // written into a rectangle that does not fit.
        //
        // The positions are worked out from the rectangle's own geometry rather
        // than carried through a map, so the assertion reads as "this pixel is
        // at that place on the screen" and does not need the rectangles to tile
        // the screen without overlapping -- which they do not, in general.
        const MAGENTA: [u8; 4] = [0xff, 0x00, 0xff, 0x00];
        let wrongly_placed: Vec<(u16, u16)> = rects
            .iter()
            .filter(|r| r.encoding >= 0)
            .flat_map(|r| {
                let (w, h) = (r.width as usize, r.height as usize);
                // `as_chunks` rather than `chunks_exact`, so there is no
                // `try_from(...).unwrap()` standing between the bytes and the
                // comparison. A remainder here would mean a rectangle whose
                // length is not a multiple of four, which cannot be decoded --
                // and `try_read_update_rects` would already have said so.
                r.pixels
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .enumerate()
                    .map(move |(i, p)| {
                        (
                            (r.x + (i % w) as u16, r.y + (i / w) as u16),
                            p,
                        )
                    })
                    .take(h * w)
                    .collect::<Vec<_>>()
            })
            .filter(|(_, p)| **p == MAGENTA)
            .map(|(at, _)| at)
            .collect();
        assert!(
            wrongly_placed.is_empty(),
            "the client is showing {MAGENTA:?} at {wrongly_placed:?}, which is \
             inside a rectangle that ran off the mapping. Either the rectangle was \
             clamped -- reading a different part of the surface than the one that \
             was named -- or it was applied before the mapping's own geometry was \
             checked. `desktop` has no magenta, so every one of these came from \
             the rectangle that did not fit."
        );
    });
}

#[test]
fn only_the_pixels_that_changed_are_sent() {
    on_a_bus!(|mut mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a read timeout");
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        mock.resize(FIRST, (1280, 800));
        let mut reader = rfb_client::SyncReader::new(4);
        let mut decoders = rfb_client::Decoders::new();

        mock.scanout(FIRST, desktop(1280, 800))
            .await
            .expect("the first screen");
        rfb_client::request_update(&mut client, 0, 0, 1280, 800);
        let _ = reader.read_update(&mut client);

        // The whole screen again, with one column band repainted in a colour
        // that appears nowhere in `desktop`. The band starts on a 64-pixel
        // boundary because that is what `DIRTY_BLOCK` is: a comparison finds
        // damage in whole blocks, so a band starting mid-block would be
        // reported as the block containing it.
        let mut screen = desktop(1280, 800);
        for y in 0..800usize {
            for x in 640..704usize {
                let o = (y * 1280 + x) * 4;
                screen[o] = 0xff;
                screen[o + 1] = 0x00;
                screen[o + 2] = 0xff;
                screen[o + 3] = 0x00;
            }
        }
        mock.update(FIRST, (0, 0, 1280, 800), screen)
            .await
            .expect("the one-band repaint");

        rfb_client::request_update(&mut client, 0, 0, 1280, 800);
        let rects = rfb_client::try_read_update_rects(&mut client, &mut decoders)
            .expect("the changed band should be answered");
        let drawn: Vec<_> = rects
            .iter()
            .filter(|r| r.encoding >= 0)
            .map(|r| (r.x, r.y, r.width, r.height))
            .collect();

        assert_eq!(
            drawn,
            vec![(640, 0, 64, 800)],
            "a whole-screen update that differed in one 64-pixel column produced \
             {drawn:?} rather than one 64x800 rectangle at x=640. Either the \
             comparison is not happening, or the vertical coalescing is not: 800 \
             rows of one changed column is what a per-row implementation emits, \
             and it is what the client would have to decode as 800 rectangles."
        );

        // The pixels, not just the geometry. A rectangle in the right place with
        // the wrong contents is a rectangle the client draws as noise, and the
        // geometry assertion above would not notice.
        let band = rects
            .iter()
            .find(|r| r.encoding >= 0)
            .expect("the band rectangle");
        assert_eq!(band.pixels.len(), 64 * 800 * 4);
        for y in [0usize, 1, 400, 799] {
            let o = y * 64 * 4;
            assert_eq!(
                &band.pixels[o..o + 4],
                &[0xff, 0x00, 0xff, 0x00],
                "row {y} of the sent band is not the colour the guest drew"
            );
        }
    });
}

/// A resize is reported even when the new screen is identical to a black one.
///
/// The one place where "nothing changed" is a lie, and the branch exists because
/// the alternative is a client that never learns the screen is a different size.
///
/// A resize resets the shadow to black, so a resize to a **black** screen finds
/// no difference anywhere and reports no damage at all. The client would keep
/// the picture it has, at the old size, for ever: its dimensions travel in a
/// message this server only sends on a path that begins with damage, so damage
/// is the only way the news gets out.
#[test]
fn a_resize_to_a_black_screen_is_still_a_full_repaint() {
    on_a_bus!(|mut mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a read timeout");
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        mock.resize(FIRST, (1280, 800));
        let mut reader = rfb_client::SyncReader::new(4);

        mock.scanout(FIRST, desktop(1280, 800))
            .await
            .expect("the first screen");
        rfb_client::request_update(&mut client, 0, 0, 1280, 800);
        let _ = reader.read_update(&mut client);

        // The guest resizes and sends the new surface: 640x400, and **black**.
        mock.resize(FIRST, (640, 400));
        mock.scanout(FIRST, vec![0u8; 640 * 400 * 4])
            .await
            .expect("the black screen at the new size");
        rfb_client::request_update(&mut client, 0, 0, 1280, 800);

        let rects = reader
            .read_update(&mut client)
            .expect("the new size should be announced");
        // The resize itself is a `SetDesktopSize` pseudo-rectangle, and the
        // pixels follow it as a full frame of the new size.
        let drawn: Vec<_> = rects
            .iter()
            .filter(|r| r.encoding >= 0)
            .map(|r| (r.x, r.y, r.width, r.height))
            .collect();
        assert!(
            drawn.contains(&(0, 0, 640, 400)),
            "a resize to a 640x400 black screen produced {drawn:?}. The comparison \
             found no pixel that differed from the fresh black shadow and reported \
             no damage, so the client is left holding the old picture at the old \
             size with no way to learn otherwise."
        );
    });
}

/// Several changed runs in a row arrive as several tall rectangles, not as
/// the whole screen.
///
/// The shape video produces. A decoder that updates some blocks and not others
/// leaves bands all over the output window, and a whole-screen update that
/// differs in ten of them is ten rectangles of 64x800 — not the 8,000
/// single-row rectangles it is found in, and emphatically not the whole screen.
///
/// Note what this test does **not** establish, because believing otherwise was
/// the error that produced it. It does not show that the vertical coalescing is
/// needed: `Damage` merges by adjacency as rectangles arrive, so a stack of
/// rows with the same spans becomes one tall rectangle with or without it, and
/// the list never approaches `MAX_DAMAGE_RECTS`. Deleting the coalescer
/// altogether leaves this test passing. It is here to pin the wire *shape* —
/// the number of rectangles and their geometry — which is worth having whatever
/// produces it. `what_coalescing_the_rows_is_worth` is what measures the
/// coalescing.
#[test]
fn several_changed_bands_in_a_row_arrive_as_several_tall_rectangles() {
    on_a_bus!(|mut mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a read timeout");
        rfb_client::send_set_encodings(&mut client, &[rfb_client::encoding::RAW]);
        mock.resize(FIRST, (1280, 800));
        let mut reader = rfb_client::SyncReader::new(4);

        mock.scanout(FIRST, desktop(1280, 800))
            .await
            .expect("the first screen");
        rfb_client::request_update(&mut client, 0, 0, 1280, 800);
        let _ = reader.read_update(&mut client);

        // Every other 64-pixel band, all 800 rows, in a colour that appears
        // nowhere in `desktop`. `x` counts in 128s, so each changed band is 64
        // wide with 64 unchanged pixels before the next: the gaps are what keep
        // the ten rectangles from being one.
        let bands: Vec<u16> = (0..10u16).map(|i| i * 128).collect();
        let mut screen = desktop(1280, 800);
        for y in 0..800usize {
            for &x in &bands {
                for dx in 0..64usize {
                    let o = (y * 1280 + x as usize + dx) * 4;
                    screen[o] = 0xff;
                    screen[o + 1] = 0xff;
                    screen[o + 2] = 0x00;
                    screen[o + 3] = 0x00;
                }
            }
        }
        mock.update(FIRST, (0, 0, 1280, 800), screen)
            .await
            .expect("the ten-band repaint");

        rfb_client::request_update(&mut client, 0, 0, 1280, 800);
        let rects = reader
            .read_update(&mut client)
            .expect("the ten bands should be answered");
        let mut drawn: Vec<_> = rects
            .iter()
            .filter(|r| r.encoding >= 0)
            .map(|r| (r.x, r.y, r.width, r.height))
            .collect();
        drawn.sort();

        assert_eq!(
            drawn,
            bands
                .iter()
                .map(|&x| (x, 0u16, 64u16, 800u16))
                .collect::<Vec<_>>(),
            "a whole-screen update that differed in ten 64-pixel bands produced \
             {drawn:?} rather than ten 64x800 rectangles. Without the vertical \
             coalescing that is 8000 single-row rectangles, which is past \
             MAX_DAMAGE_RECTS, so the damage degrades to the whole framebuffer \
             and the comparison's work is thrown away."
        );
    });
}

/// A client that connects later is sent the whole screen, not the difference
/// from whoever was here before.
///
/// The one property that makes the shadow copy safe, and the one that a shadow
/// is one bookkeeping slip away from getting wrong.
///
/// `Framebuffer::shadow` is a **single** copy of the surface, compared against to
/// decide what changed — and what it says is "already accounted for", not
/// "already sent to this client". Those are the same thing only while exactly
/// one client has been sent everything. The moment a second client arrives, the
/// first client's history is the wrong reference for it: consult the shadow for
/// the newcomer and it would be told nothing changed, because everything has
/// been accounted for — and the screen it has never seen would stay blank.
///
/// What saves it is that a client starts with `Damage::Full`, so its first frame
/// is the whole screen whatever the shadow holds. This test is here because that
/// is an invariant in `ClientState::new`, three files away from the comparison,
/// and nothing else would notice if it changed.
#[test]
fn a_client_that_connects_later_is_sent_the_whole_screen() {
    // The non-`mut` arm: this test never resizes, and the `mut` binding is
    // what the warning about it was about.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;

        // The first client: the screen, then a change it is told about.
        let (mut first, _a) = listener_for(&server).await;
        handshake(&mut first);
        rfb_client::send_set_encodings(&mut first, &[rfb_client::encoding::RAW]);
        let mut reader = rfb_client::SyncReader::new(4);
        mock.scanout(FIRST, frame())
            .await
            .expect("the screen");
        rfb_client::request_update(&mut first, 0, 0, WIDTH, HEIGHT);
        let _ = reader.read_update(&mut first);

        // The change, which the shadow now accounts for. That it reaches this
        // client is not what is being tested; what is being tested is that the
        // shadow has moved on.
        mock.update(FIRST, (0, 0, WIDTH as i32, HEIGHT as i32), frame_tinted(0x3c))
            .await
            .expect("the change");
        rfb_client::request_update(&mut first, 0, 0, WIDTH, HEIGHT);
        let _ = reader.read_update(&mut first);

        // Now a second client, arriving to a surface whose every pixel the
        // shadow has already accounted for.
        let (mut second, _b) = listener_for(&server).await;
        // The read timeout is not optional here, and the reason is what it is
        // protecting against. `listener_for` hands back a stream that blocks
        // for ever, so a server that sends the newcomer *nothing* — which is
        // exactly the failure this test is for — makes the test hang rather
        // than fail. A hanging test in a suite is worse than a failing one:
        // it reports nothing, so `cargo test` is left to be killed, and the
        // next person to run it sees a timeout rather than a diagnosis.
        second
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a read timeout");
        handshake(&mut second);
        rfb_client::send_set_encodings(&mut second, &[rfb_client::encoding::RAW]);
        let mut reader = rfb_client::SyncReader::new(4);
        rfb_client::request_update(&mut second, 0, 0, WIDTH, HEIGHT);
        let rects = reader
            .read_update(&mut second)
            .expect("the newcomer must be sent something");
        let drawn: Vec<_> = rects
            .iter()
            .filter(|r| r.encoding >= 0)
            .map(|r| (r.x, r.y, r.width, r.height))
            .collect();

        assert!(
            drawn.contains(&(0, 0, WIDTH, HEIGHT)),
            "a client that had never been connected was sent {drawn:?}, which is \
             not the whole {WIDTH}x{HEIGHT} screen. The shadow is compared against \
             to find damage and it says 'already accounted for', not 'already sent \
             to you': a newcomer has to be sent everything on the strength of \
             starting with Damage::Full, and not one pixel of that depends on what \
             the shadow happens to hold."
        );
    });
}

#[test]
fn a_client_that_asks_for_no_compression_gets_raw_pixels() {
    // The -256 pseudo-encoding carries a zlib level, and 0 means none. A client
    // that announces it along with ZRLE, hextile and Tight must be given raw
    // pixels: what it asked for wins over what it can take. It is the one lever
    // a client has for "a compressed rectangle is what I cannot decode", so it
    // is worth having, and it is a gap the -256 range was parsed into a variant
    // nobody read until now.
    //
    // This has to be tested here rather than in `session.rs`, whose `Encoded`
    // harness stands in for the server: it builds its own `Encoders` and calls
    // `choose()` itself, so the per-client policy in `server/client.rs` never
    // runs. Only the mock drives the real `Server`.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        rfb_client::send_set_encodings(
            &mut client,
            &[
                rfb_client::encoding::ZRLE,
                rfb_client::encoding::ZLIB,
                rfb_client::encoding::TIGHT,
                -256, // the compression level pseudo-encoding, at level 0
            ],
        );
        // Now the guest draws, so there is something worth sending.
        mock.scanout(FIRST, frame())
            .await
            .expect("the scanout arrives");

        let mut saw_raw = false;
        for _ in 0..20 {
            rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
            let Ok((rect, _)) = rfb_client::try_read_rect(&mut client) else {
                continue;
            };
            if rect.encoding == rfb_client::encoding::RAW {
                saw_raw = true;
                break;
            }
        }
        assert!(saw_raw, "a client that asked for no compression got something else");
    });
}

#[test]
fn a_client_that_asks_for_no_compression_is_never_given_any() {
    // The wire cannot show the *positive* half of this, and it is worth saying
    // why, because the test that used to sit here asserted it and failed on
    // loaded machines.
    //
    // "A client that asked for compression gets a compressed rectangle" is not
    // a property of the protocol. The level is a request, and the encoder is
    // entitled to decline it: `Policy::record()` drops the level whenever a
    // write takes longer than fifty milliseconds, or the measured bandwidth
    // falls below the floor, which is exactly what a busy machine looks like.
    // So on a slow host every client gets raw pixels, and a test asserting
    // otherwise is asserting the host's load, not the server's behaviour. That
    // the level is *understood* — 0 means none, 1 to 9 mean compress — is
    // covered where it is deterministic, in `encodings.rs`, by
    // `a_client_that_asks_for_no_compression_gets_raw`.
    //
    // What the wire *can* show, on any host at any load, is the negative: a
    // client that says "no compression" must never be given any, however good
    // the link looks and however many encodings it announced. The policy's
    // ceiling is 0, and 0 is the floor, so there is no timing at which the
    // answer can differ. That is the assertion here, and it is the direction
    // that a client on a slow link, or working around a decoder it dislikes,
    // is relying on.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);
        // Every encoding there is, and the -256 pseudo-encoding that says 0.
        rfb_client::send_set_encodings(
            &mut client,
            &[
                rfb_client::encoding::ZRLE,
                rfb_client::encoding::ZLIB,
                rfb_client::encoding::TIGHT,
                rfb_client::encoding::HEXTILE,
                -256,
            ],
        );
        mock.scanout(FIRST, frame())
            .await
            .expect("the scanout arrives");

        let mut rectangles = 0;
        for _ in 0..20 {
            rfb_client::request_full_update(&mut client, 0, 0, WIDTH, HEIGHT);
            let Ok((rect, _)) = rfb_client::try_read_rect(&mut client) else {
                continue;
            };
            if rect.encoding < 0 {
                continue; // a pseudo-encoding: an acknowledgement, not pixels
            }
            rectangles += 1;
            assert_eq!(
                rect.encoding,
                rfb_client::encoding::RAW,
                "a client that asked for no compression was sent encoding {}",
                rect.encoding
            );
        }
        assert!(
            rectangles > 0,
            "the client was sent no pixels at all, so nothing was proved"
        );
    });
}
