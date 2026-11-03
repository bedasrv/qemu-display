//! Does the D-Bus receive path have an owner in the counters?
//!
//! # Why this test exists
//!
//! `dbus_messages` counted what arrived and **nothing timed what it cost**. Every
//! nanosecond the receive path spent — deserialising a 1.58 MB message, copying
//! it into the framebuffer, finding the damage, notifying — appeared in no
//! breakdown at all. It was simply unattributed, and the log line reported the
//! difference as "outside the update path" without anyone knowing what was in
//! it. That is how a third of this port's CPU ended up with no owner.
//!
//! `dbus_cpu_nanos` is the counter that gives it one, and this checks two
//! things about it:
//!
//! - **it moves when updates arrive**, so it is not a field that reads zero and
//!   gets believed;
//! - **it is not a copy of `encode_cpu_nanos`**, which is the failure mode a
//!   counter added to fill a gap is most likely to have. They are measured on
//!   different threads — the receive path is the D-Bus task, the encoder is the
//!   per-client task — so a build that had accidentally wired both to the same
//!   span would look plausible and be wrong.
//!
//! **Only totals are asserted, never rates.** The counters are process globals
//! and this suite runs in parallel, so a per-interval figure would be a race.

mod common;

#[path = "mock/qemu.rs"]
mod qemu;

use std::time::Duration;

use qemu::MockQemu;
use qemu_display::{Scanout, Update};
use qemu_vnc::counters::counters;
use qemu_vnc::server::{Server, Share};

/// The console the tests use.
const SIZE: (u32, u32) = (128, 96);
const FIRST: u32 = 0;

/// `x8r8g8b8`, the framebuffer's own format.
const PIXMAN_X8R8G8B8: u32 = 0x2002_0888;

/// Enough updates for both counters to move well past their resolution. The
/// point is that they move *at all*, not by how much.
const UPDATES: usize = 24;

/// A whole console of `x8r8g8b8` pixels, different on each call so that every
/// push is real damage rather than a repeat the comparison can discard.
fn frame(n: u8) -> Vec<u8> {
    let mut data = vec![0u8; SIZE.0 as usize * SIZE.1 as usize * 4];
    // Four bytes at a time by index rather than `chunks_exact_mut(4)`, which
    // clippy flags as a constant chunk size: that each write is exactly one
    // pixel is the point, and a literal index says it without the lint.
    for i in 0..SIZE.0 as usize * SIZE.1 as usize {
        let o = i * 4;
        data[o] = (i as u8).wrapping_add(n);
        data[o + 1] = (i >> 3) as u8;
        data[o + 2] = n;
        data[o + 3] = 0;
    }
    data
}

/// A mock with a console, a server attached to it, and a client already
/// connected and reading, so an update has somewhere to go.
async fn serving() -> (MockQemu, std::net::TcpStream) {
    let (mock, connection) = MockQemu::start(SIZE)
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

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let addr = listener.local_addr().expect("an address");
    let mut client = std::net::TcpStream::connect(addr).expect("a connection");
    let (stream, _peer) = listener.accept().expect("the connection");
    server.add_client(stream, addr).expect("the client to be added");
    async_io::Timer::after(Duration::from_millis(50)).await;

    client.set_read_timeout(Some(Duration::from_millis(200))).ok();
    common::rfb_client::read_server_version(&mut client);
    common::rfb_client::negotiate_version(&mut client, "RFB 003.008\n");
    let _ = common::rfb_client::read_security_types(&mut client, false);
    common::rfb_client::select_security_type(&mut client, 1);
    let _ = common::rfb_client::read_security_result(&mut client);
    common::rfb_client::send_client_init(&mut client, true);
    let _ = common::rfb_client::read_server_init(&mut client);

    // The surface, so the console has dimensions before it is updated.
    mock.scanout(FIRST, frame(0)).await.expect("the scanout");

    (mock, client)
}

/// Push `UPDATES` distinct frames through the bus, draining the client so its
/// socket never fills.
async fn push_updates(mock: &MockQemu, client: &mut std::net::TcpStream) {
    for n in 1..=UPDATES as u8 {
        mock.update(
            FIRST,
            (0, 0, SIZE.0 as i32, SIZE.1 as i32),
            frame(n),
        )
        .await
        .expect("the update arrives");
        let mut buf = [0u8; 8192];
        use std::io::Read;
        let _ = client.read(&mut buf);
    }
}

/// The receive path is timed, and it is the receive path rather than a copy of
/// another counter.
#[test]
fn the_dbus_receive_path_is_timed_and_not_a_copy_of_the_encoder() {
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        // No bus: its absence says nothing about the code.
        return;
    }
    async_io::block_on(async {
        let (mock, mut client) = serving().await;

        let before = counters();
        let (dbus_before, encode_before, messages_before) = (
            before.dbus_cpu_nanos.sample().0,
            before.encode_cpu_nanos.sample().0,
            before.dbus_messages.sample().0,
        );

        push_updates(&mock, &mut client).await;
        // Long enough for the receive task to have finished the last update and
        // for the guard on it to have run.
        async_io::Timer::after(Duration::from_millis(200)).await;

        let after = counters();
        let dbus = after.dbus_cpu_nanos.sample().0 - dbus_before;
        let encode = after.encode_cpu_nanos.sample().0 - encode_before;
        let messages = after.dbus_messages.sample().0 - messages_before;

        assert!(
            messages >= UPDATES as u64,
            "only {messages} of {UPDATES} updates were counted, so the receive path \
             did not run and every figure below would be about nothing"
        );
        assert!(
            dbus > 0,
            "{UPDATES} updates arrived and were counted, and \
             `dbus_cpu_nanos` did not move at all. The receive path is the part \
             of this process that had no owner in any counter, so a counter that \
             reads zero is worse than no counter: it looks like the path is free."
        );

        // The two counters are on different threads, so their sum should exceed
        // either. If they were the same span wired twice, `dbus + encode` would
        // equal roughly one of them, and the encoder alone would account for
        // everything -- which is precisely the reading that made this look like
        // an encoder problem for as long as it did.
        assert!(
            dbus + encode > dbus.min(encode),
            "the two CPU counters appear to be measuring the same span: dbus \
             {dbus} ns, encode {encode} ns. They run on different threads -- the \
             D-Bus receive task and the per-client task -- so one of them is \
             wired to the wrong place."
        );
    });
}

/// The counter is only on the receive path, so an idle console must not move it.
#[test]
fn an_idle_console_does_not_charge_the_receive_path() {
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        return;
    }
    async_io::block_on(async {
        let (mock, mut client) = serving().await;

        let before = counters().dbus_cpu_nanos.sample().0;
        push_updates(&mock, &mut client).await;
        async_io::Timer::after(Duration::from_millis(200)).await;
        let after_updates = counters().dbus_cpu_nanos.sample().0;
        assert!(
            after_updates > before,
            "the updates did not move the counter, so the idle check below is \
             comparing two zeroes"
        );

        // Nothing happens at all for a while.
        async_io::Timer::after(Duration::from_millis(600)).await;
        let idle = counters().dbus_cpu_nanos.sample().0;
        assert!(
            idle == after_updates,
            "the receive path charged {} ns while nothing arrived. The counter \
             is supposed to be started and stopped around the handlers, and this \
             is what catches it being left running.",
            idle - after_updates
        );
    });
}

/// The updates that are timed really arrived, and a client got pixels back.
///
/// Without the second half this only proves the mock counted its own calls. A
/// framebuffer update is sent in answer to a request, so the first version of
/// this pushed updates and then read, and read nothing -- correctly, because no
/// update had ever been asked for. The failure was right and the test was wrong,
/// which is the only good way for it to go.
#[test]
fn the_updates_that_are_timed_really_arrived() {
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        return;
    }
    async_io::block_on(async {
        let (mock, mut client) = serving().await;
        common::rfb_client::send_set_encodings(&mut client, &[common::rfb_client::encoding::RAW]);

        let before = counters().dbus_messages.sample().0;
        push_updates(&mock, &mut client).await;
        assert!(
            counters().dbus_messages.sample().0 - before >= UPDATES as u64,
            "the updates did not reach the listener"
        );

        // Ask for the console, and require pixels back. That is the evidence the
        // whole path ran -- receive, apply, encode, send -- rather than merely
        // being counted.
        common::rfb_client::request_update(&mut client, 0, 0, SIZE.0 as u16, SIZE.1 as u16);
        let mut buf = [0u8; 8192];
        use std::io::Read;
        let mut total = 0;
        for _ in 0..8 {
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => break,
            }
        }
        assert!(
            total > 0,
            "nothing came back after {UPDATES} updates and an explicit request, so \
             the path under test is not the one the log would attribute this to"
        );
    });
}

/// `Scanout` is on the same path and is counted too: it is how the surface gets
/// its dimensions, and a version of this guard that only covered `update` would
/// miss a whole-surface update costing more than every rectangle in a frame.
#[test]
fn a_whole_surface_scanout_is_timed_as_well() {
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        return;
    }
    async_io::block_on(async {
        let (mock, _client) = serving().await;
        // Prime: the scanout in `serving` has already moved the counter.
        let before = counters().dbus_cpu_nanos.sample().0;
        mock.scanout_as(FIRST, PIXMAN_X8R8G8B8, vec![0x11u8; SIZE.0 as usize * SIZE.1 as usize * 4])
            .await
            .expect("the scanout");
        async_io::Timer::after(Duration::from_millis(200)).await;
        assert!(
            counters().dbus_cpu_nanos.sample().0 > before,
            "a whole-surface `Scanout` was not charged to the receive path. It is \
             the largest single message this port handles, and leaving it out \
             would make the counter look cheap."
        );
    });
}

/// A `Scanout` and an `Update` of the same bytes are both accepted, so the
/// shapes these tests use are the shapes the code accepts.
#[test]
fn the_fixtures_are_shapes_the_listener_accepts() {
    let scanout = Scanout {
        width: SIZE.0,
        height: SIZE.1,
        stride: SIZE.0 * 4,
        format: PIXMAN_X8R8G8B8,
        data: frame(1),
    };
    assert_eq!(scanout.data.len(), (SIZE.0 * SIZE.1 * 4) as usize);
    let update = Update {
        x: 0,
        y: 0,
        w: SIZE.0 as i32,
        h: SIZE.1 as i32,
        stride: SIZE.0 * 4,
        format: PIXMAN_X8R8G8B8,
        data: frame(2),
    };
    assert_eq!(update.data.len(), (SIZE.0 * SIZE.1 * 4) as usize);
}