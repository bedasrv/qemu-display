//! Is `idle_nanos` counting time that is not running?
//!
//! # Why this test exists
//!
//! A production heartbeat reported:
//!
//! ```text
//! idle_ms_per_interval=6596   heartbeat_interval_secs=5000ms
//! ```
//!
//! **A count of idle time cannot exceed the interval it is measured over**, so one
//! of those two numbers was wrong. The counter was the one. `Client::run` started
//! an idle clock at the top of each loop iteration and added the span at the top of
//! the next, and the `Wake::Refresh` arm ends in `continue` — straight back to that
//! top. Every deferred update therefore added its own duration to the idle total,
//! on top of the wait that had preceded it.
//!
//! That mattered more than the arithmetic, because `idle_ms` is what the verdict
//! line reads. `verdict="loops are idle; a high CPU here is outside this crate"` is
//! the one sentence in the log that tells a reader not to look at this process, and
//! it was resting on a counter that was counting the update path as rest.
//!
//! # Why three obvious assertions do not work
//!
//! All three were written and all three passed against the unfixed code.
//!
//! | assertion | why it passes anyway |
//! |---|---|
//! | `idle + update <= wall` | the overshoot *is* `update`, which was 18 ms in a 1.5 s window against 236 ms of other work the sum absorbs |
//! | `idle <= wall` | the unfixed clock is still bounded: it is "the loop", which is under the wall |
//! | two runs, ask vs don't ask | the difference came out at 192 ms of task scheduling against 18 ms of update |
//!
//! Raising the update cost does not rescue any of them. The D-Bus push that feeds
//! a frame scales with the frame, so `update`'s share of the window stays put:
//! measured at 256x160, then 640x400, then 1280x800 with every artificial pause
//! removed, and it never passed 1%.
//!
//! # What works
//!
//! **One expensive update, with `idle` read either side of it.** No window, no
//! baseline, no comparison — so none of the noise above can hide in it.
//!
//! Between the two reads the server does one thing: it reads the request, runs the
//! update, and writes the result. The update is made expensive on purpose (hextile
//! at deflate level 6 over a noisy 1280x800 screen, tens of milliseconds), because
//! the bug is that the update's duration lands in `idle` and the size of that
//! duration *is* the signal.
//!
//! - fixed: the clock stops at the `select!`, so `idle` grows by however long the
//!   socket took to deliver the request — microseconds.
//! - unfixed: the clock spans the whole iteration, so `idle` grows by the whole
//!   update, and `idle_delta >= update_delta`.
//!
//! # Why its own binary
//!
//! The counters are process globals and tests inside one binary run in parallel
//! threads, so a second test here would read this one's spans. As in
//! `encode_cpu.rs`, the file gets a binary to itself.

mod common;

#[path = "mock/qemu.rs"]
mod qemu;

use std::io::Read;
use std::time::Duration;

use common::rfb_client;
use qemu::MockQemu;
use qemu_vnc::counters::counters;
use qemu_vnc::server::{Server, Share};

/// 1280x800, so that a level-6 deflate over it is tens of milliseconds.
///
/// **This size is the test's signal.** The bug's size on the counter *is* the cost
/// of the update, so the update has to be expensive enough to stand above the
/// microseconds of scheduling in a loopback fixture. At 64x32 it would be
/// unmeasurable and the test would pass against the bug.
const SIZE: (u32, u32) = (1280, 800);
const FIRST: u32 = 0;

/// hextile, which honours the client's `-254` level, unlike ZRLE and Tight whose
/// levels this port pins at 0.
const HEXTILE: i32 = 6;

/// `-256..=-247` carries a zlib level 0..9 (`Encoding::CompressionLevel`), so
/// level 6 is -250. Level 6 rather than 0 because the point is an *expensive*
/// update: 6 is `Z_DEFAULT_COMPRESSION`, and on a noisy screen it is roughly ten
/// times the work of level 0 on the same pixels.
const LEVEL_6: i32 = -250;

/// The update must cost at least this, or the ratio below is two small numbers.
///
/// A guard rather than a constant to hope for: if the encoding or the frame
/// changes and the update gets cheap, the test says so instead of quietly
/// becoming a test that cannot fail.
const MIN_UPDATE_MS: f64 = 10.0;

/// `idle` may grow by at most this fraction of the update's cost.
///
/// Half, not a small constant: the fixed counter's growth is delivery latency and
/// whatever wait the loop had already entered, and the unfixed one's is the entire
/// update. Half is where the two are unambiguously different.
const MAX_IDLE_FRACTION: f64 = 0.5;

/// Noise: more than 256 colours, so the sub-encoding chosen is not a palette, and
/// nothing that a deflate could turn into a handful of bytes.
fn noisy_frame() -> Vec<u8> {
    let (w, h) = (SIZE.0 as usize, SIZE.1 as usize);
    let mut data = Vec::with_capacity(w * h * 4);
    let mut x = 0x1234_5678u32;
    for _ in 0..w * h {
        // A cheap LCG, so the content is genuinely incompressible and deterministic
        // between runs -- a test whose fixture changes every run cannot be
        // compared with itself.
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        data.extend_from_slice(&[
            (x >> 16) as u8,
            (x >> 8) as u8,
            x as u8,
            0,
        ]);
    }
    data
}

/// `(idle_ms, update_ms)` as monotonic totals.
fn read() -> (f64, f64) {
    let c = counters();
    (
        c.idle_nanos.sample().0 as f64 / 1e6,
        c.update_nanos.sample().0 as f64 / 1e6,
    )
}

fn drain(client: &mut std::net::TcpStream, limit: usize) -> usize {
    let mut buf = [0u8; 65536];
    let mut total = 0;
    for _ in 0..limit {
        match client.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    total
}

#[test]
fn idle_does_not_include_the_update_path() {
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        eprintln!("skipped: no DBUS_SESSION_BUS_ADDRESS, so the mock cannot run");
        return;
    }
    async_io::block_on(async {
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
        server
            .add_client(stream, addr)
            .expect("the client to be added");

        client.set_read_timeout(Some(Duration::from_millis(500))).ok();
        assert_eq!(rfb_client::read_server_version(&mut client), "RFB 003.008");
        rfb_client::negotiate_version(&mut client, "RFB 003.008\n");
        assert_eq!(rfb_client::read_security_types(&mut client, false), vec![1]);
        rfb_client::select_security_type(&mut client, 1);
        assert_eq!(rfb_client::read_security_result(&mut client), 0);
        rfb_client::send_client_init(&mut client, true);
        let (w, h, _) = rfb_client::read_server_init(&mut client);
        assert_eq!((w, h), (SIZE.0 as u16, SIZE.1 as u16), "wrong console size");
        rfb_client::send_set_encodings(&mut client, &[HEXTILE, LEVEL_6]);
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .ok();
        async_io::Timer::after(Duration::from_millis(80)).await;

        // Damage the whole screen, once. One scanout rather than a stream of
        // updates: this test wants a single update to time, and a burst would put
        // several in flight and smear them across the two readings.
        mock.scanout(FIRST, noisy_frame())
            .await
            .expect("the scanout arrives");
        // Let the damage notification land, and drain whatever the server sends so
        // the socket is not already backed up when the measured request goes out.
        async_io::Timer::after(Duration::from_millis(80)).await;
        drain(&mut client, 64);

        // ---- The measurement. Between these two reads the server does one thing.
        let (idle_before, update_before) = read();
        rfb_client::request_update(&mut client, 0, 0, SIZE.0 as u16, SIZE.1 as u16);
        // **Read while it runs, deliberately.** A level-6 hextile of a noisy
        // screen is several megabytes, so the server's write would block on a
        // socket nobody is draining; reading is what lets the update finish, and
        // the blocked write is part of `update_nanos` either way because that
        // counter is wall-clock across `send_framebuffer_update`.
        let mut got = 0usize;
        for _ in 0..512 {
            got += drain(&mut client, 8);
            if got > 0 {
                break;
            }
            async_io::Timer::after(Duration::from_millis(10)).await;
        }
        // Let any late accounting land.
        async_io::Timer::after(Duration::from_millis(120)).await;
        let (idle_after, update_after) = read();
        let idle_delta = idle_after - idle_before;
        let update_delta = update_after - update_before;

        println!("idle grew {idle_delta:.1} ms, update took {update_delta:.1} ms");

        // **Guard: the update has to be expensive, or the ratio is two small
        // numbers.** Three of the four attempts at this test failed exactly here,
        // passing against the bug because the update cost 18 ms of a 1.5 s window.
        assert!(
            update_delta >= MIN_UPDATE_MS,
            "the update cost {update_delta:.1} ms, under the {MIN_UPDATE_MS} ms this \
             test needs. The signal being looked for *is* the cost of the update, so \
             a cheap update cannot show whether it landed in idle. hextile at level \
             6 over a noisy screen should be tens of milliseconds; if this fired, \
             check that the client is really being served hextile."
        );
        assert!(
            idle_delta <= update_delta * MAX_IDLE_FRACTION,
            "an update costing {update_delta:.1} ms was accompanied by {idle_delta:.1} \
             ms of *idle*. Idle is the time the loop spent parked in the `select!`, \
             and an update is not parked: it is the loop running. So the update's \
             duration has been charged to rest, which is what produces \
             `idle_ms_per_interval` larger than the interval and a verdict line \
             that says the CPU here is not ours when it has not been checked."
        );

        drop(client);
    });
}