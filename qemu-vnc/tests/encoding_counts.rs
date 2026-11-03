//! Does the log say which encoding was sent?
//!
//! # Why this test exists
//!
//! A run against the real viewer was started with `-T info` to check that Tight
//! works after the compact-length fix. Eleven seconds of it were kept, along with
//! a `top -H` showing where the CPU had gone: `dbus_cpu_ms_per_interval=211`,
//! `bytes_per_interval=85359455`, `damage_per_interval=28537792`, one client, no
//! errors, no disconnection.
//!
//! **None of that says which encoding a single byte went out as**, because the
//! chosen encoding was logged at `debug` and the run used `info`. So the one
//! question the run existed to answer — *is the viewer now reading our Tight?* —
//! could not be answered from it, and "no error for ninety seconds" is not an
//! answer: a viewer being sent something it cannot read is exactly the shape of a
//! run that does not error.
//!
//! The fix is not a louder log line. It is a counter, at `info`, counting what
//! went **on the wire** — not the preference, which the policy is free to
//! override at any time.
//!
//! # Why one test and not two
//!
//! The counters are process globals. Two `#[test]`s in one binary run in parallel
//! threads and would read each other's rectangles, so both halves are sequential
//! inside a single test. This file also gets a binary to itself, as
//! `encode_cpu.rs` does, so no other test target shares the process.

mod common;

#[path = "mock/qemu.rs"]
mod qemu;

use std::io::Read;
use std::time::Duration;

use common::rfb_client;
use qemu::MockQemu;
use qemu_vnc::counters::counters;
use qemu_vnc::server::{Server, Share};

/// Small, and deliberately not the 256x160 of `encode_cpu.rs`: nothing here stalls
/// a socket, and a big frame would only make the run slower.
const SIZE: (u32, u32) = (64, 32);
const FIRST: u32 = 0;

/// How many rounds of damage each half pushes.
///
/// Enough that the counters clearly move. The assertions are on a *delta* and on
/// the other encodings staying flat, so one frame would do; several makes a
/// partial delivery show up as a failure rather than a pass.
const ROUNDS: usize = 5;

/// The per-encoding rectangle counts, as totals, in [`NAMES`] order.
///
/// An array rather than a five-tuple: a tuple is not `IntoIterator`, so the
/// comparison below wanted `.iter()` on something that does not have it.
type Counts = [u64; 5];

/// Totals, not rates. The counters are process globals and this suite runs in
/// parallel, so a per-interval figure would be a race; a total is monotonic.
fn read_counts() -> Counts {
    let c = counters();
    [
        c.rects_raw.sample().0,
        c.rects_zlib.sample().0,
        c.rects_zrle.sample().0,
        c.rects_tight.sample().0,
        c.rects_jpeg.sample().0,
    ]
}

const NAMES: [&str; 5] = ["raw", "zlib", "zrle", "tight", "jpeg"];

/// Which counters moved between two readings, as `name -> delta`.
///
/// Only the ones that moved: a failure that printed all five numbers makes the
/// reader work out which one is the point.
fn describe(before: Counts, after: Counts) -> Vec<(String, i64)> {
    NAMES
        .iter()
        .zip(before.iter().zip(after.iter()))
        .filter(|(_, (b, a))| a != b)
        .map(|(name, (b, a))| (name.to_string(), *a as i64 - *b as i64))
        .collect()
}

fn report(before: Counts, after: Counts) -> String {
    let d = describe(before, after);
    if d.is_empty() {
        return "no counter moved at all".to_string();
    }
    d.iter()
        .map(|(n, v)| format!("{n} {v:+}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A distinct frame per push.
///
/// Damage is found by comparing against a shadow copy, so identical bytes are not
/// damage and the server correctly encodes nothing: push one frame twice and the
/// second push sends no rectangle at all. That failure reads as "the counter is
/// broken" rather than "there was nothing to send", and `encode_cpu.rs` carries
/// the same note for the same reason.
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

async fn setup() -> (MockQemu, Server) {
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
    (mock, server)
}

/// Connect a client that offers exactly `encodings`, in that order, and complete
/// the handshake.
fn client_offering(server: &Server, encodings: &[i32]) -> std::net::TcpStream {
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
    let (width, height, _) = rfb_client::read_server_init(&mut client);
    assert_eq!(
        (width, height),
        (SIZE.0 as u16, SIZE.1 as u16),
        "the mock's console is not the size this test asked for"
    );
    rfb_client::send_set_encodings(&mut client, encodings);
    client
}

/// Read whatever is there without blocking. Returns false once the socket is quiet.
fn drain(client: &mut std::net::TcpStream) -> bool {
    let mut buf = [0u8; 8192];
    match client.read(&mut buf) {
        Ok(0) | Err(_) => false,
        Ok(_) => true,
    }
}

/// Push `ROUNDS` distinct frames, requesting a picture after each.
///
/// **Both halves are needed.** A framebuffer update is sent in answer to a
/// *request*, so damage on its own produces no encoding and no rectangle: an
/// earlier version of the sibling test measured a run that provably sent nothing
/// and read it as a pass.
async fn provoke(mock: &MockQemu, client: &mut std::net::TcpStream, first: u8) {
    for i in 0..ROUNDS {
        mock.update(
            FIRST,
            (0, 0, SIZE.0 as i32, SIZE.1 as i32),
            frame(first.wrapping_add(i as u8)),
        )
        .await
        .expect("the update arrives");
        rfb_client::request_update(client, 0, 0, SIZE.0 as u16, SIZE.1 as u16);
        // Give the client's loop a turn to encode and write, then take the bytes
        // so the socket never backs up.
        async_io::Timer::after(Duration::from_millis(40)).await;
        while drain(client) {}
    }
    async_io::Timer::after(Duration::from_millis(60)).await;
}

/// The counters name the encoding that went out, at the level production runs at.
#[test]
fn the_counters_name_the_encoding_that_went_out() {
    // No session bus means no mock, and the test would be checking nothing.
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        eprintln!("skipped: no DBUS_SESSION_BUS_ADDRESS, so the mock cannot run");
        return;
    }
    async_io::block_on(async {
        // ---- Half one: the client asks for Tight first, as the production
        // viewer does, and Tight is what should be counted.
        let (mock, server) = setup().await;
        let mut tight_client = client_offering(
            &server,
            &[rfb_client::encoding::TIGHT, rfb_client::encoding::ZRLE],
        );
        // Let SetEncodings land before the first damage, or the preference is not
        // set yet and the first rectangles go out under the default ladder.
        async_io::Timer::after(Duration::from_millis(50)).await;

        let before_tight = read_counts();
        provoke(&mock, &mut tight_client, 0).await;
        let after_tight = read_counts();
        let tight_delta = describe(before_tight, after_tight);

        assert!(
            tight_delta.iter().any(|(n, v)| n == "tight" && *v > 0),
            "a client offering Tight first had no Tight rectangle counted. \
             Counters moved: {}. If this fails, the log cannot say which \
             encoding was sent and the production question stays unanswerable.",
            report(before_tight, after_tight)
        );
        assert!(
            !tight_delta.iter().any(|(n, v)| n == "zrle" && *v > 0),
            "Tight was counted *and* ZRLE was, so the preference was ignored or the \
             counters are counting something other than what went out. \
             Counters moved: {}",
            report(before_tight, after_tight)
        );
        assert!(
            tight_delta.iter().any(|(n, _)| n == "tight"),
            "a Tight rectangle was not counted, but {}. Tight may have been sent \
             under raw -- every encoder can decline -- and then the log is honest \
             and this test's premise was wrong.",
            report(before_tight, after_tight)
        );

        // ---- Half two: raw only, and the raw counter has to move.
        //
        // The point is not that raw works. It is that the counter is keyed on the
        // encoding rather than on "something was sent", which half one alone
        // cannot show: a counter that always incremented `rects_tight` would pass
        // half one and only be caught here.
        let (mock2, server2) = setup().await;
        let mut raw_client = client_offering(&server2, &[rfb_client::encoding::RAW]);
        async_io::Timer::after(Duration::from_millis(50)).await;

        let before_raw = read_counts();
        provoke(&mock2, &mut raw_client, 100).await;
        let after_raw = read_counts();

        assert!(
            describe(before_raw, after_raw)
                .iter()
                .any(|(n, v)| n == "raw" && *v > 0),
            "a raw client had no raw rectangle counted, so the per-encoding \
             counters are not keyed on the encoding. Counters moved: {}",
            report(before_raw, after_raw)
        );
        assert!(
            !describe(before_raw, after_raw)
                .iter()
                .any(|(n, v)| n == "tight" && *v > 0),
            "a raw-only client had Tight rectangles counted, so the counter is not \
             tracking what went out. Counters moved: {}",
            report(before_raw, after_raw)
        );

        // Leaving the sockets dropped closes the clients, so the server threads
        // stop rather than outliving the test binary.
        drop(tight_client);
        drop(raw_client);
    });
}