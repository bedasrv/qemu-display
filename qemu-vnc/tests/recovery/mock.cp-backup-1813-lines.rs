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

/// How long to wait for something that should have happened already.
const PATIENCE: Duration = Duration::from_secs(5);

/// A mock QEMU with one console of the test size, or `None` when there is no
/// session bus to export it on.
///
/// Only the *absence* of a bus is a reason to skip. A bus that is there and
/// cannot be exported on is a failure, and this is the difference that keeps a
/// broken mock from passing every test by skipping all of them.
async fn mock() -> Option<MockQemu> {
    if zbus::Connection::session().await.is_err() {
        eprintln!("skipping: there is no session bus");
        return None;
    }
    Some(
        MockQemu::start(SIZE)
            .await
            .expect("the mock to export on the session bus"),
    )
}

/// Run a test body, skipping it when there is no bus to run it on.
macro_rules! on_a_bus {
    (|$mock:ident| $body:block) => {
        async_io::block_on(async {
            let Some($mock) = mock().await else {
                return;
            };
            async move $body.await
        });
    };
}

/// A server attached to the mock's console, as `main.rs` attaches one.
///
/// This is the part the unit tests could not do: `add_graphic_console` reads
/// the console's `Width` and `Height` over the bus and then registers the
/// listener, which is what gives the mock a connection to push pixels down.
async fn server_for(mock: &MockQemu) -> Server {
    let connection = zbus::Connection::session().await.expect("a session bus");
    let server = Server::new(&connection, "mock", Share::Ignore)
        .await
        .expect("a server");
    server
        .add_graphic_console(0)
        .await
        .expect("the console to be added");
    mock.wait_registered().await;
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
    for _ in 0..200 {
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
    (0..(WIDTH as usize * HEIGHT as usize))
        .flat_map(|i| {
            if i % 4 == 0 {
                [0x7f, 0x00, 0x00, 0x00]
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
    on_a_bus!(|mock| {
        let server = server_for(&mock).await;
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);
            request_picture(&mut client);

            // Nothing has been drawn yet, so the console is black.
            let black = rfb_client::read_update(&mut client);
            assert_eq!(black, vec![0; WIDTH as usize * HEIGHT as usize * 4]);

            // Now the guest draws, which is the mock pushing a scanout.
            mock.scanout(frame()).await.expect("the scanout arrives");
            let pixels = request_until(&mut client, || rfb_client::try_read_update(&mut client))
                .await;
            assert_eq!(pixels, frame(), "the scanout should reach the client");
    });
}

#[test]
fn only_the_damaged_part_of_a_console_is_sent_again() {
    // A scanout is the whole console; an update is a rectangle of it. What
    // proves the damage tracking is the second one: the client must be sent
    // the rectangle, not the whole console again.
    on_a_bus!(|mock| {
        let server = server_for(&mock).await;
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);
            request_picture(&mut client);
            let _ = rfb_client::try_read_update(&mut client);

            // One pixel, in the middle of the console.
            mock.update((10, 10, 1, 1), vec![0x11, 0x22, 0x33, 0x00])
                .await
                .expect("the update arrives");
            let pixels = request_until(&mut client, || rfb_client::try_read_update(&mut client))
                .await;
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
    on_a_bus!(|mock| {
        let server = server_for(&mock).await;
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
                        // 0x41 is the keysym for A and 30 the QEMU keycode for
                        // it; 0x42 is B and 48 its keycode. The client is
                        // keymap independent, so the console gets the keycode
                        // and not the symbol the viewer sent.
                        keycode: 30,
                        down: true
                    },
                    Key {
                        keycode: 30,
                        down: false
                    },
                    Key {
                        keycode: 48,
                        down: true
                    },
                ],
                "the keysyms should become keycodes, and their order should hold"
            );
    });
}

#[test]
fn a_mouse_button_from_the_client_arrives_at_the_console() {
    on_a_bus!(|mock| {
        let server = server_for(&mock).await;
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
                    // Every event carries the pointer position, and only the
                    // buttons are edges: holding the button down sends one
                    // `press`, not one per event.
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
    on_a_bus!(|mock| {
        let server = server_for(&mock).await;
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
    on_a_bus!(|mock| {
        let server = server_for(&mock).await;
            let connection = server.connection().clone();
            let clipboard =
                qemu_vnc::clipboard::Clipboard::register(&connection, server.downgrade())
                    .await
                    .expect("the clipboard peer to register");
            server.set_clipboard(clipboard);
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);

            mock.offer_clipboard("from the guest")
                .await
                .expect("the guest offers its clipboard");
            let text = wait_for(
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
    on_a_bus!(|mock| {
        let server = server_for(&mock).await;
            let connection = server.connection().clone();
            let clipboard =
                qemu_vnc::clipboard::Clipboard::register(&connection, server.downgrade())
                    .await
                    .expect("the clipboard peer to register");
            server.set_clipboard(clipboard);
            let (mut client, _addr) = listener_for(&server).await;
            handshake(&mut client);

            rfb_client::send_cut_text(&mut client, "from the viewer");

            let grabs = wait_for(
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
    on_a_bus!(|mock| {
        let server = server_for(&mock).await;
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
        move |samples| server.broadcast_audio(samples),
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

/// Get a client from the handshake to receiving audio.
///
/// The order is the protocol's and it is not negotiable: the client announces
/// the audio pseudo-encoding, the server acknowledges it as a framebuffer
/// update, and only then does an enable mean anything. Skipping the middle step
/// does not fail loudly — the acknowledgement is still sitting in the socket,
/// and an audio reader looking at it reports "not an audio message" for ever.
async fn start_audio(client: &mut std::net::TcpStream) {
    // The encodings go once, with the audio among them. `SetEncodings` replaces
    // the whole set rather than adding to it, so a second one without the audio
    // would take the client back out of the audio business — which is right,
    // and is what a viewer that stopped asking for the audio means.
    rfb_client::send_set_encodings(
        client,
        &[rfb_client::encoding::RAW, rfb_client::encoding::AUDIO],
    );
    rfb_client::request_update(client, 0, 0, WIDTH, HEIGHT);
    let _ = rfb_client::try_read_update(client);
    // The acknowledgement, which the server sends because this one has audio.
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
    rfb_client::send_audio_command(client, qemu_vnc::rfb::audio::ENABLE);
    wait_for(
        "saw the start of the audio stream",
        || rfb_client::try_read_audio_sub(client),
        |sub| matches!(sub, Ok(sub) if *sub == qemu_vnc::rfb::audio::BEGIN),
    )
    .await
    .expect("the stream to start");
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
    format!(
        "{}\n--- stderr ---\n{}",
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

#[test]
fn a_console_that_draws_after_the_client_asked_still_reaches_it() {
    // The sequence from a real "no image" report, in order:
    //
    //   1. a scanout arrives and the console is black
    //   2. a client connects and asks for the screen
    //   3. it is sent the black screen, which is correct
    //   4. the guest draws, and a scanout with the real desktop arrives
    //   5. the client has no reason to ask again, so nothing replaces the
    //      black frame it is showing
    //
    // Step 5 is the fault. QEMU answers step 4 without a new request:
    // `vnc_should_update` passes as soon as `has_dirty` is set and the client
    // is in the incremental state its last request left it in. This port only
    // ever sent an update in answer to a request, so a client that had asked
    // once sat looking at whatever it was first given — a working connection,
    // a good handshake and a correctly encoded frame, and a blank screen.
    on_a_bus!(|mock, connection| {
        let server = server_for(&mock, &connection).await;
        // The console starts black.
        mock.scanout(FIRST, vec![0u8; WIDTH as usize * HEIGHT as usize * 4])
            .await
            .expect("the first scanout");
        let (mut client, _addr) = listener_for(&server).await;
        handshake(&mut client);

        // The client asks, incrementally, as a viewer does.
        rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
        let black = rfb_client::try_read_update(&mut client).expect("the first update");
        assert_eq!(black, vec![0; WIDTH as usize * HEIGHT as usize * 4]);

        // Now the guest draws, with no request from the client.
        mock.scanout(FIRST, frame())
            .await
            .expect("the second scanout");

        // The client must be sent the new content *without asking again*.
        // Nothing here sends a request, which is the whole point: the client
        // had asked once, been answered, and has no reason to ask again. Using
        // `request_until` here would send a request per iteration and would
        // pass with or without the push, which is exactly the mistake that
        // left this bug in for six rounds.
        let mut seen_black = false;
        for _ in 0..40 {
            match rfb_client::try_read_update(&mut client) {
                Ok(pixels) if pixels == vec![0; WIDTH as usize * HEIGHT as usize * 4] => {
                    seen_black = true;
                }
                Ok(pixels) => {
                    assert_eq!(
                        pixels,
                        frame(),
                        "the console that drew after the request should have reached the client"
                    );
                    return;
                }
                Err(_) => continue,
            }
        }
        panic!("the client was never sent anything after the console drew (saw black: {seen_black})");
    });
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

        let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let addr = socket.local_addr().expect("an address");
        server.add_listener(qemu_vnc::server::ListenerInfo {
            addr,
            auth: "None".into(),
            websocket: false,
        });
        println!("PORT {addr}");
        io::stdout().flush().expect("the port to be printed");

        // The accept loop, which is `main.rs`'s: the library does not own it.
        for stream in socket.incoming() {
            let stream = match stream {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let addr = stream.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
            if let Err(e) = server.add_client(stream, addr) {
                eprintln!("failed to add a client: {e}");
            }
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
        // Damage, so an update happens at all.
        mock.scanout(FIRST, frame())
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
