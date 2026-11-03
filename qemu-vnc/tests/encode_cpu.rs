//! Is `encode_cpu_nanos` measuring something different from `encode_nanos`?
//!
//! # Why this test exists
//!
//! "The encode is 20.4% of a core" was the basis of the entire CPU comparison
//! against QEMU's own VNC server. That figure is `encode_ms_per_interval`,
//! which is timed with `Instant` — wall-clock — around a span that includes
//! writing the framebuffer to a socket. **A blocked write is elapsed time, not
//! processor time**, so a viewer that cannot drain fast enough has its wait
//! charged to the encoder.
//!
//! `encode_cpu_nanos` reads the same span with `CLOCK_THREAD_CPUTIME_ID`. If the
//! two are always equal, the new counter is a second copy of the old mistake and
//! settles nothing. If CPU sits materially below wall, the wait is real and the
//! encoder was never the cost.
//!
//! # What it does
//!
//! Drives a real client against the mock with a 64x32 console, twice: once
//! draining every update, once stalled so the kernel's socket buffer fills and
//! `send` blocks. The assertion is on the *relationship* between the two
//! counters, because absolute costs depend on the machine.
//!
//! **Only totals are asserted, never rates.** The counters are process globals
//! and this suite runs in parallel, so a rate would be a race.

mod common;

#[path = "mock/qemu.rs"]
mod qemu;

use std::io::Read;
use std::time::Duration;

use common::rfb_client;
use qemu::MockQemu;
use qemu_vnc::server::{Server, Share};
use qemu_vnc::counters::counters;

/// The console the tests use.
///
/// **Big enough that a stalled reader actually blocks.** At 64x32 a raw frame is
/// 8 KB and the kernel's socket buffer absorbs hundreds of them, so a write never
/// blocks and the test measured nothing: wall-clock and CPU came out within 2% of
/// each other, which is the signature of a socket that was never full. 256x160 is
/// 160 KB a frame, so a few un-drained frames exceed the default buffer and the
/// write blocks, which is the condition under test.
const SIZE: (u32, u32) = (256, 160);
const FIRST: u32 = 0;

/// How long a run lasts. Long enough for the counters to move well past their
/// resolution, short enough to keep the suite quick.
const RUN: Duration = Duration::from_millis(1500);

/// How long the socket is left undrained after the midpoint, by the ignored test
/// below. Kept because the ignored test reads it and its reasoning depends on the
/// value, not as a constant the suite depends on.
#[allow(dead_code)]
const STALL: Duration = Duration::from_millis(1400);

async fn mock() -> (MockQemu, zbus::Connection) {
    MockQemu::start(SIZE)
        .await
        .expect("the mock to export its interfaces")
}

async fn server_for(connection: &zbus::Connection, mock: &MockQemu) -> Server {
    let server = Server::new(connection, "mock", Share::Ignore)
        .await
        .expect("a server");
    server
        .add_graphic_console(FIRST)
        .await
        .expect("the console to be added");
    mock.wait_registered(FIRST).await;
    server
}

async fn listener_for(server: &Server) -> std::net::TcpStream {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let addr = listener.local_addr().expect("an address");
    let client = std::net::TcpStream::connect(addr).expect("a connection");
    let (stream, _peer) = listener.accept().expect("the connection");
    server
        .add_client(stream, addr)
        .expect("the client to be added");
    async_io::Timer::after(Duration::from_millis(50)).await;
    client
}

/// One full frame of damage, as the guest would.
///
/// **`n` must differ between calls.** Damage is found by comparing the incoming
/// rectangle against a shadow copy, so pushing identical bytes a second time
/// damages nothing and the server correctly encodes nothing. The first version of
/// this test pushed the same gradient four times and the server sent one update
/// in total, which read as "both counters are broken" rather than "there was
/// nothing to encode".
///
/// The frame is a gradient rather than one solid colour so the encoder has real
/// work: a solid screen is four bytes on the wire whatever the CPU cost, and the
/// socket would never fill, so the stall would never block anything.
fn frame(n: u8) -> Vec<u8> {
    let (w, h) = (SIZE.0 as usize, SIZE.1 as usize);
    let mut data = Vec::with_capacity(w * h * 4);
    for y in 0..h {
        for x in 0..w {
            data.extend_from_slice(&[(x * 4) as u8, (y * 8) as u8, n, 0]);
        }
    }
    data
}

/// A raw client, so nothing is compressed and every update is real work on the
/// wire. ZRLE would compress a gradient away to almost nothing and the socket
/// would never fill.
fn handshake(client: &mut std::net::TcpStream) {
    client.set_read_timeout(Some(Duration::from_millis(500))).ok();
    assert_eq!(rfb_client::read_server_version(client), "RFB 003.008");
    rfb_client::negotiate_version(client, "RFB 003.008\n");
    assert_eq!(rfb_client::read_security_types(client, false), vec![1]);
    rfb_client::select_security_type(client, 1);
    assert_eq!(rfb_client::read_security_result(client), 0);
    rfb_client::send_client_init(client, true);
    let (width, height, _) = rfb_client::read_server_init(client);
    assert_eq!(
        (width, height),
        (SIZE.0 as u16, SIZE.1 as u16),
        "the mock's console is not the size this test asked for"
    );
    rfb_client::send_set_encodings(client, &[rfb_client::encoding::RAW]);
}

/// Ask for the whole console, non-incremental.
///
/// **Without this the server encodes nothing at all.** A framebuffer update is
/// sent in answer to a request, so pushing damage into the mock on its own
/// produces no encoding and both counters stay at zero -- which is what the
/// first version of this test measured, and would have read as a pass.
fn request_picture(client: &mut std::net::TcpStream) {
    rfb_client::request_update(client, 0, 0, SIZE.0 as u16, SIZE.1 as u16);
}

/// Read whatever is available, without blocking. Returns false once the socket
/// is quiet.
fn drain(client: &mut std::net::TcpStream) -> bool {
    let mut buf = [0u8; 8192];
    match client.read(&mut buf) {
        Ok(0) => false,
        Ok(_) => true,
        Err(_) => false,
    }
}

/// The two counters as totals, in milliseconds.
///
/// Totals and not rates on purpose: these are process globals and the suite runs
/// in parallel, so a per-interval figure would be a race. A total is monotonic.
///
/// **Microseconds, not milliseconds.** The counters are nanosecond totals, and a
/// 64x32 raw frame encodes in well under a millisecond, so dividing to
/// milliseconds truncated every figure in this test to zero -- which read as
/// "the counters are broken" rather than "the numbers are too small to sum".
type Pair = (u64, u64);

fn read_pair() -> Pair {
    let c = counters();
    (
        c.encode_nanos.sample().0 / 1_000,
        c.encode_cpu_nanos.sample().0 / 1_000,
    )
}

/// Run a client against the mock, provoking damage throughout, and return
/// `(wall_us, cpu_us)` for the updates sent.
///
/// With `stall` set, the client stops reading partway through. The server's
/// writes then block once the kernel buffer fills, and **the run does not end
/// until those writes are released** -- see below, because that detail is the
/// whole test.
async fn run(stall: bool) -> Pair {
    let (mock, connection) = mock().await;
    let server = server_for(&connection, &mock).await;
    let mut client = listener_for(&server).await;
    handshake(&mut client);
    // A distinct frame per push, since identical bytes are not damage.
    let mut frame_n = 0u8;

    // Provoke damage and answer it, well before the measurement, so the
    // handshake and first allocations are not in the window.
    for _ in 0..4 {
        push(&mock, &mut client, &mut frame_n).await;
        while drain(&mut client) {}
    }

    let (wall_before, cpu_before) = read_pair();
    let start = std::time::Instant::now();
    let stall_after = RUN / 2;

    while start.elapsed() < RUN {
        // Push a request per update: an update is sent in answer to a request,
        // so without one the server encodes nothing and both counters stay put.
        push(&mock, &mut client, &mut frame_n).await;
        if stall && start.elapsed() >= stall_after {
            // **Keep going, without reading.** An update is only sent in answer to
            // a request, and the request is a small write the kernel always
            // accepts, so this queues update after update on a socket nobody is
            // draining. That is what fills the buffer and parks the writer. The
            // earlier version of this loop instead slept here, so only one or two
            // updates were ever queued, the buffer never filled, and the run
            // measured 330 us with wall and CPU within 0.6% of each other -- the
            // signature of a socket that never blocked at all.
            continue;
        }
        while drain(&mut client) {}
    }

    // **Release the stall before reading the counters, and this is the point of
    // the test.** The encode counter is added *after* `session.send` returns, so a
    // write that is still blocked has not been counted yet. Ending the run while
    // the writer is parked measures nothing: the first version did that and
    // reported the stalled run as *cheaper* than the draining one, because the
    // blocked update had not been tallied and the run had ended early.
    //
    // Draining here releases the parked writer, and the wait it sat in is then
    // charged to the update that was waiting -- which is the behaviour under test.
    if stall {
        let until = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if !drain(&mut client) {
                break;
            }
            if std::time::Instant::now() > until {
                break;
            }
        }
        // Give the now-unblocked writes time to return and be counted.
        async_io::Timer::after(Duration::from_millis(300)).await;
    }
    let (wall_after, cpu_after) = read_pair();
    (
        wall_after.saturating_sub(wall_before),
        cpu_after.saturating_sub(cpu_before),
    )
}

/// Push one frame of damage and ask for it, as a guest drawing and a viewer
/// asking would.
async fn push(mock: &MockQemu, client: &mut std::net::TcpStream, frame_n: &mut u8) {
    *frame_n = frame_n.wrapping_add(1);
    mock.update(FIRST, (0, 0, SIZE.0 as i32, SIZE.1 as i32), frame(*frame_n))
        .await
        .expect("the update arrives");
    request_picture(client);
}

/// Both clocks must move, or every comparison below is between two zeroes.
#[test]
fn both_clocks_move_when_the_viewer_drains() {
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_ok() {
        async_io::block_on(async {
        let (wall, cpu) = run(false).await;
        assert!(
            wall > 0 && cpu > 0,
            "neither clock moved over a {RUN:?} run: wall {wall} us, cpu {cpu} us. \
             No updates were encoded, so the other test here would compare two \
             zeroes and pass."
        );
        assert!(
            cpu <= wall,
            "CPU time ({cpu} us) exceeds wall-clock ({wall} us) for the same span. \
             Either `thread_cpu_nanos` is not `CLOCK_THREAD_CPUTIME_ID`, or the two \
             counters do not span the same code, and nothing here can be read."
        );
        });
    }
}

/// The point of the counter: a blocked write is elapsed time, not CPU.
///
/// **Ignored, and I could not make it pass.** A client is a loopback socket with
/// a 64 KB send buffer, and the write is dispatched by `async_io::Async` onto a
/// reactor thread rather than performed on the client thread. Two consequences,
/// both found by running it:
///
/// - the buffer never filled. Frames were raised from 8 KB to 160 KB and the
///   stall lengthened, and wall-clock stayed within 1% of CPU -- the signature of
///   a socket that was never full. The writer was never parked.
/// - the run has to *end* with the stall still in place, or the blocked write
///   completes and the wait is charged after the counters are read. Ending it with
///   the writer parked instead measures almost nothing, because the encode counter
///   is added after `send` returns and a write that has not returned has not been
///   counted: the stalled run read 267 us against the draining run's 322 us, which
///   looks like the stall making the server *faster*.
///
/// What this test wants to prove is real and the guard in it is right -- a socket
/// that never blocks leaves the two clocks within about a percent of each other,
/// and that is the check worth keeping. Proving the converse needs a client that
/// genuinely stops reading, on a socket with a small send buffer, driven by a
/// second thread. That is a bigger fixture than this file should grow into, and
/// the number that settles the production question comes from the server's own log
/// on the real viewer rather than from a loopback pair.
///
/// Run with `--ignored` to see the current behaviour.
#[test]
#[ignore = "a loopback client never fills the send buffer; see above"]
fn a_stalled_reader_costs_wall_clock_and_not_cpu() {
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_ok() {
        async_io::block_on(async {
        let (wall_drain, cpu_drain) = run(false).await;
        let (wall_stall, cpu_stall) = run(true).await;

        // Separate runs, so the deltas are not directly comparable -- but the
        // stalled run must have spent *some* wall-clock blocked, and the
        // question is whether it also spent CPU doing it.
        let cpu_share = if wall_stall == 0 {
            1.0
        } else {
            cpu_stall as f64 / wall_stall as f64
        };
        let drain_share = if wall_drain == 0 {
            1.0
        } else {
            cpu_drain as f64 / wall_drain as f64
        };

        assert!(
            wall_stall > 0 && cpu_stall > 0,
            "the stalled run moved neither clock: wall {wall_stall} us, cpu \
             {cpu_stall} us. The stall is not reaching the write path, so this \
             test is not testing what it claims."
        );

        // **First, prove the stall actually blocked.** If the socket never
        // filled, the two clocks stay within about a percent of each other and
        // the assertion below would pass for entirely the wrong reason -- which
        // is what a test that cannot fail looks like. A blocked write shows up as
        // wall-clock ahead of CPU in the *stalled* run.
        //
        // The margin is 1.5x, not 5x, because the kernel is copying the queued
        // frames while the writer waits and that copying is real CPU: the wait is
        // proportional, not absolute. 50% is well clear of the ~1% a socket that
        // never blocked produces, without demanding a ratio that a busy machine
        // would fail.
        assert!(
            wall_stall as f64 > cpu_stall as f64 * 1.5,
            "in the stalled run wall-clock ({wall_stall} us) is not ahead of CPU \
             ({cpu_stall} us), so the socket never blocked and this test is not \
             measuring what it claims. A socket that never blocks leaves the two \
             within about a percent of each other, which is what this looks for."
        );

        // And the stalled run should show *less* CPU per unit of wall-clock,
        // because part of its span was spent asleep in the kernel.

        assert!(
            cpu_share < drain_share,
            "a stalled reader did not lower the CPU share of the update path. \
             Draining: {cpu_drain} us CPU of {wall_drain} us wall ({:.0}%). \
             Stalled: {cpu_stall} us CPU of {wall_stall} us wall ({:.0}%). \
             If those are the same, then either the socket never blocked, or \
             `encode_cpu_nanos` is not reading a processor clock -- and the \
             figure it is meant to correct is not corrected.",
            drain_share * 100.0,
            cpu_share * 100.0
        );
        });
    }
}
