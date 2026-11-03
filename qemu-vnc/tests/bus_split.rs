//! How much of the D-Bus receive cost is ours, and how much is the transport's?
//!
//! # The question
//!
//! Production says `dbus_cpu_ms_per_interval=207` against
//! `damage_per_interval=30477632` pixels -- 121.9 MB per 5 s.
//! An earlier estimate put our own work in `set_update` at about 43 ms of
//! that, leaving ~164 ms attributed to zbus and the kernel. **That 43 ms is an
//! estimate, assembled from three separate measurements**, and the 164 ms has
//! never been decomposed at all.
//!
//! This measures the split directly, with the counter that already exists.
//!
//! # Two things it deliberately does not do
//!
//! **It does not add a "skip the handler" mode to the crate.** That would be the
//! obvious way to get the number -- make `update` return immediately, and whatever
//! CPU the thread still spends is zbus's -- but it puts a switch in production
//! code that silently stops the server receiving pixels. `dbus_cpu_nanos` already
//! times the handler, so the split is available without it.
//!
//! **It does not attribute the residue to zbus alone.** The mock is in the same
//! process, so process CPU includes the *sender* serialising the same bytes. That
//! is why the sweep below is over payload size at a fixed message count: the
//! question it answers -- is this cost per byte or per message -- does not care
//! which side pays, and that is the question that says whether a copy is worth
//! removing.
//!
//! # What to read out of it
//!
//! `dbus_cpu / total` is the share that is ours. A flat intercept with a slope in
//! ns a pixel means the cost is copies, and the copies are two of zbus's plus one
//! of ours. A large intercept means framing, which is per message and does not
//! shrink with a smaller payload.

mod common;

#[path = "mock/qemu.rs"]
mod qemu;

use std::time::{Duration, Instant};

use qemu::MockQemu;
use qemu_vnc::counters::counters;

/// The console size. 1280x800 is production's, and the largest payload here is a
/// whole screen, which is what `Scanout` sends.
const SIZE: (u32, u32) = (1280, 800);
const FIRST: u32 = 0;

/// Heights, in rows, of the rectangle each `Update` carries.
///
/// **A geometric ladder, deliberately.** Equal steps in payload size would bunch
/// every point at the large end and make the slope a function of two or three
/// samples. These span three orders of magnitude, which is what separates a
/// per-byte term from a per-message one.
const ROWS: [u32; 5] = [4, 16, 64, 256, 800];

/// Messages pushed per point.
///
/// Held **constant** across points, which is the whole design: with the message
/// count fixed, anything that changes with payload size is a per-byte cost and
/// anything that does not is a per-message cost. Varying the count as well would
/// confound them.
const MESSAGES: usize = 120;

/// Long enough for the CPU clock to resolve, short enough to run five times.
const SETTLE: Duration = Duration::from_millis(150);

/// The whole process's CPU in nanoseconds, from `CLOCK_PROCESS_CPUTIME_ID`.
///
/// **Not `/proc/self/task/*/stat`, and not `schedstat`.** `stat` ticks at
/// `CLK_TCK`, which is 100 on this machine, so the whole measurement is
/// quantised to 10 ms -- the first version of this test read the 0.02 MB point as
/// `0` ms and the next as `10`, and produced a least-squares fit with a *negative*
/// intercept. `schedstat` is nanoseconds and would be ideal, and on this machine
/// it reads `0 0 1` because the kernel was built without `CONFIG_SCHEDSTATS`.
///
/// `CLOCK_PROCESS_CPUTIME_ID` is nanoseconds, needs no new dependency (`libc` is
/// already one), and -- importantly -- is a *processor* clock, so it excludes the
/// time this test spends blocked in the D-Bus round trip. Wall-clock would have
/// charged the sleep to the measurement.
///
/// It is process-wide, so it includes the mock's own sending cost. That is
/// deliberate and is why the sweep varies payload size at a fixed message count:
/// see the header.
fn process_cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable `timespec`, and this cannot fail for
    // CLOCK_PROCESS_CPUTIME_ID on any platform this crate builds for.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime failed");
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn frame(rows: u32, n: u8) -> Vec<u8> {
    let w = SIZE.0 as usize;
    let h = rows as usize;
    let mut v = Vec::with_capacity(w * h * 4);
    for _ in 0..w * h {
        // Varies with `n` so every push is new damage: identical bytes are not
        // damage, the server correctly encodes nothing, and the handler would be
        // measuring the early return instead of the conversion. That mistake was
        // made once already, in `encode_cpu.rs`, and it reads as a broken counter.
        v.extend_from_slice(&[n, n.wrapping_mul(3), n.wrapping_mul(7), 0]);
    }
    v
}

#[test]
fn the_receive_cost_is_reported_against_its_shape() {
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        eprintln!("skipped: no DBUS_SESSION_BUS_ADDRESS, so the mock cannot run");
        return;
    }
    async_io::block_on(async {
        let (mock, connection) = MockQemu::start(SIZE)
            .await
            .expect("the mock to export its interfaces");
        let server = qemu_vnc::server::Server::new(&connection, "mock", qemu_vnc::server::Share::Ignore)
            .await
            .expect("a server");
        server
            .add_graphic_console(FIRST)
            .await
            .expect("the console to be added");
        mock.wait_registered(FIRST).await;

        println!(
            "\n{:<7} {:>10} {:>10} {:>12} {:>12} {:>10}",
            "rows", "MB", "msgs", "proc ms", "ours ms", "ours %"
        );
        println!("{}", "-".repeat(68));

        let mut points: Vec<(f64, f64, f64)> = Vec::new(); // (bytes, total_ms, ours_ms)

        // `enumerate` rather than a lookup: the index is only used to vary the
        // payload so every push is new damage, and the lookup needed a comparison
        // that `rows` is a `&u32`.
        for (i, rows) in ROWS.iter().enumerate() {
            let payload = frame(*rows, 0);
            let mb = payload.len() as f64 / 1e6;

            let cpu_before = process_cpu_ns();
            let ours_before = counters().dbus_cpu_nanos.sample().0;

            let start = Instant::now();
            for m in 0..MESSAGES {
                // A distinct frame each time, and a rectangle whose height is the
                // point under test.
                mock.update(
                    FIRST,
                    (0, 0, SIZE.0 as i32, *rows as i32),
                    frame(*rows, (m + 1 + i) as u8),
                )
                .await
                .expect("the update arrives");
            }
            // The handler is timed inside the call, so every message has been
            // dispatched by the time the last `update` returns -- but let the
            // accounting settle anyway.
            let _ = start;
            async_io::Timer::after(SETTLE).await;

            let cpu_after = process_cpu_ns();
            let ours_after = counters().dbus_cpu_nanos.sample().0;

            let total_ms = (cpu_after - cpu_before) as f64 / 1e6;
            let ours_ms = (ours_after - ours_before) as f64 / 1e6;
            let share = if total_ms > 0.0 { ours_ms / total_ms * 100.0 } else { 0.0 };

            println!(
                "{:<7} {:>10.2} {:>10} {:>12.0} {:>12.0} {:>9.0}%",
                rows, mb, MESSAGES, total_ms, ours_ms, share
            );
            points.push((mb * 1e6 * MESSAGES as f64, total_ms, ours_ms));
        }

        // The shape: with the message count fixed, bytes vs milliseconds. A least
        // squares line through the points, printed rather than asserted -- this
        // test's job is to produce the number, and what counts as an acceptable
        // intercept depends on the machine.
        let n = points.len() as f64;
        let sum_x: f64 = points.iter().map(|p| p.0).sum();
        let sum_y: f64 = points.iter().map(|p| p.1).sum();
        let sum_xx: f64 = points.iter().map(|p| p.0 * p.0).sum();
        let sum_xy: f64 = points.iter().map(|p| p.0 * p.1).sum();
        let denom = n * sum_xx - sum_x * sum_x;
        if denom.abs() > f64::EPSILON {
            // `slope` is ms per **byte**, because x is in bytes. Two of the three
            // scale factors below were wrong in the first version, which printed
            // "0.00 ms per MB" for a line that is really 1.33 ms/MB.
            let slope = (n * sum_xy - sum_x * sum_y) / denom;
            let intercept = (sum_y - slope * sum_x) / n;
            println!(
                "\ntotal CPU: {:.3} ms per MB, {:.1} ms fixed",
                slope * 1e6,
                intercept
            );
            // 4 bytes a pixel; ms -> ns is 1e6.
            println!(
                "  per-byte term {:.2} ns/pixel; a per-message framing cost would \
                 show up as the {:.1} ms intercept",
                slope * 4.0 * 1e6,
                intercept
            );
        }

        // And ours alone, which is the number that 43 ms was an estimate of.
        let ours_total: f64 = points.iter().map(|p| p.2).sum();
        let bytes_total: f64 = points.iter().map(|p| p.0).sum();
        // `bytes_total` is bytes. A pixel is 4, and ms -> ns is 1e6.
        println!(
            "ours, summed over all points: {:.0} ms for {:.1} MB -> {:.1} ns/pixel",
            ours_total,
            bytes_total / 1e6,
            ours_total * 1e6 / (bytes_total / 4.0)
        );
        let total_sum: f64 = points.iter().map(|p| p.1).sum();
        println!(
            "the whole process, same points: {:.0} ms -> {:.1} ns/pixel, and ours is \
             {:.0}% of it",
            total_sum,
            total_sum * 1e6 / (bytes_total / 4.0),
            ours_total / total_sum * 100.0
        );
    });
}