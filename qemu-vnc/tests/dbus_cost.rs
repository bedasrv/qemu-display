//! What the D-Bus transport costs, per update, on each of the two paths.
//!
//! # Why this is a measurement and not a test
//!
//! The map path was wired up because a message path was costing something —
//! about 10% of a core, attributed to `zbus::Connection` serialising and
//! deserialising pixels. That attribution came from a production profile, but
//! **the saving was arithmetic**: nobody had run the map path, so there was no
//! before-and-after and the number was an extrapolation from a cost model.
//! This file exists because that number turned out to be wrong, and the only
//! way to know it was wrong was to measure it.
//!
//! # What it measures
//!
//! The round trip through the bus, for the two message shapes, with both ends
//! being real code: the real `ConsoleListener` and `ConsoleListenerMap`
//! interfaces as `zbus` exports them, driven by the mock's proxies, at the two
//! shapes the production logs were made of —
//!
//! - **the band**: 1280x308, the video surface, 1.5 MB, 135 of roughly 200
//!   updates a second;
//! - **the average**: the mean damaged pixels per update in the last production
//!   run, 245,325, about 981 KB.
//!
//! Two shapes rather than one because the *average* is what an average-case
//! claim has to be made of, and one shape plus arithmetic is how the first
//! version of that claim went wrong. Both are measured.
//!
//! # What it is not
//!
//! The mock runs in this process, so a round trip includes *both* ends: the
//! peer's construction of the message as well as this client's reading of it.
//! QEMU's half is a real cost of the message path and this port does not pay
//! it, so what is measured here is an upper bound on what the map saves on our
//! side and a lower bound on the total. There is also no guest, no GPU and no
//! compositor in the figure, and nothing here says what QEMU decides to offer.
//!
//! **Run this in release.** ```sh
//! cargo test -p qemu-vnc --release --test dbus_cost -- --nocapture --ignored
//! ```

mod common;
/// The mock lives in `tests/mock/` beside `mock.rs`, and `mock.rs` says why it
/// is not a shared module: that file is the only test that builds a stand-in
/// for QEMU. This one does too — it needs a real peer to push two different
/// message shapes at — so it declares the module the same way and for the same
/// reason, and pays the same compilation cost, which is the trade `mock.rs`
/// made once already.
#[path = "mock/qemu.rs"]
mod qemu;

use std::io::{Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use qemu::MockQemu;
use qemu_vnc::server::{Server, Share};

/// The video band: 1280x308, the shape 135 of roughly 200 updates a second
/// were. 394,240 pixels, 1,576,960 bytes of `x8r8g8b8`.
const BAND: (u32, u32) = (1280, 308);

/// The mean damaged pixels per update in the last measured production run,
/// which is the shape an average-case claim has to be made of.
const AVERAGE_PIXELS: u32 = 245_325;

/// Updates per second in the last measured production run. This is what turns a
/// per-update cost into a share of a core, and it is itself a production
/// measurement rather than a constant of nature.
const UPDATES_PER_SECOND: f64 = 18.0;

/// Rounds per path per shape. The message path moves ~1.5 MB a round, so the
/// band alone is 225 MB through one socket; with fewer rounds the per-call
/// figure is whatever the machine happened to be doing.
const ROUNDS: u32 = 150;

/// One update's measured encode budget from the production log, in
/// microseconds: 12.32 ms an update. The bus cost is not part of that, so the
/// two are reported side by side rather than summed — summing a CPU figure
/// with a wall-clock one is how this port once concluded it used 136% of a
/// core.
const ENCODE_MICROS: f64 = 12_320.0;

/// The figure the map path was wired up on, before anything was measured.
///
/// Kept in the output so the measurement can be read against it rather than
/// taken on trust. It was an extrapolation from a cost model, from a profile
/// that attributed about 10% of a core to `zbus::Connection`; at 18 updates a
/// second that is 5.6 ms an update. The saving turned out to be five times smaller
/// than that extrapolation, which is why this file exists rather than the number.
const PREDICTED_MICROS: f64 = 5_600.0;

const CONSOLE: u32 = 0;

async fn server_for(connection: &zbus::Connection, mock: &MockQemu) -> Server {
    let server = Server::new(connection, "mock", Share::Ignore)
        .await
        .expect("a server");
    server
        .add_graphic_console(CONSOLE)
        .await
        .expect("the console to be added");
    mock.wait_registered(CONSOLE).await;
    server
}

/// What one shape costs on each path.
struct Measured {
    message: Duration,
    mapped: Duration,
}

async fn measure(mock: &mut MockQemu, (width, height): (u32, u32)) -> Measured {
    let band = vec![0x40u8; (width * height * 4) as usize];
    let rect = (0, 0, width as i32, height as i32);
    // The console is resized to the shape first: the mock refuses a surface
    // that is not the size of the console it is offering, which is right, and
    // which means a second shape needs a second console size rather than a
    // payload of a different length.
    mock.resize(CONSOLE, (width, height));

    // **The message path**: the whole rectangle, as `ay`, on every update.
    mock.scanout(CONSOLE, vec![0u8; band.len()])
        .await
        .expect("the surface");
    let message = timed(|| async {
        for _ in 0..ROUNDS {
            mock.update(CONSOLE, rect, band.clone())
                .await
                .expect("a message update");
        }
    })
    .await;

    // **The map path**: `ScanoutMap` once, then the same rectangle named by
    // four integers, with the pixels written into the mapping rather than
    // sent.
    //
    // The write is inside the measurement, because it is what QEMU does — it
    // draws, then names what it drew — and the message path pays for the same
    // drawing. Excluding a copy from the measurement of a change that removes a
    // copy is how a copy gets called free.
    let mut file = mock
        .scanout_map(CONSOLE, band.clone())
        .await
        .expect("the map to be offered");
    let mapped = timed(|| async {
        for _ in 0..ROUNDS {
            file.seek(SeekFrom::Start(0)).expect("a seekable mapping");
            file.write_all(&band).expect("the band fits the mapping");
            mock.update_map(CONSOLE, rect, &band)
                .await
                .expect("a mapped update");
        }
    })
    .await;

    Measured { message, mapped }
}

#[test]
#[ignore = "a measurement, not a check: needs an optimised build and a reader"]
fn what_an_update_costs_on_the_bus_by_which_path_it_takes() {
    async_io::block_on(async {
        let (mut mock, connection) = MockQemu::start(BAND).await.expect("the mock to start");
        let _server = server_for(&connection, &mock).await;

        // The average shape is a rectangle of the production mean, rounded to a
        // whole row band: 245,325 pixels is not a rectangle, and inventing one
        // would be a third thing measured by arithmetic.
        let average_side = (AVERAGE_PIXELS as f64).sqrt().round() as u32;
        let average = (average_side, AVERAGE_PIXELS / average_side);

        println!(
            "\n{} rounds per path per shape, both ends of every call in this process.\n",
            ROUNDS
        );
        for (name, shape) in [("the band", BAND), ("the average", average)] {
            let measured = measure(&mut mock, shape).await;
            report(name, shape, &measured);
        }
        println!(
            "\nBOTH ends of every call are in this process, so these are whole-bus \
             costs and not this client's share of them. No guest, no GPU, no \
             compositor, and nothing here says what QEMU offers. These are not the \
             production numbers, and the production claim needs one run against \
             live QEMU before and after to be closed.\n"
        );
    });
}

fn report(name: &str, (width, height): (u32, u32), measured: &Measured) {
    let rounds = f64::from(ROUNDS);
    let per = |d: Duration| d.as_secs_f64() * 1e6 / rounds;
    let saved = (measured.message.as_secs_f64() - measured.mapped.as_secs_f64()) * 1e6 / rounds;
    let megabytes = f64::from(width * height * 4) / 1e6;
    println!(
        "{name}, {width}x{height} ({megabytes:.2} MB a pixel payload)\n  \
         as a message, with its pixels   {:>8.0} us an update\n  \
         as four integers over a mapping {:>8.0} us an update\n  \
         difference                      {:>8.0} us an update\n    \
         which is {:.2}% of one core at {UPDATES_PER_SECOND:.0} updates/s, \
         and {:.1}% of the measured {ENCODE_MICROS:.0} us of encode per update\n",
        per(measured.message),
        per(measured.mapped),
        saved,
        (saved / 1e6) * UPDATES_PER_SECOND * 100.0,
        saved / ENCODE_MICROS * 100.0,
    );
}

async fn timed<F, Fut>(f: F) -> Duration
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let started = Instant::now();
    f().await;
    started.elapsed()
}

/// The figure this file exists to check, printed once so it cannot be read
/// past.
#[test]
#[ignore = "a measurement, not a check"]
fn the_prediction_this_file_checks() {
    println!(
        "\nthe map path was wired up on an extrapolation of {PREDICTED_MICROS:.0} us \
         an update, from a profile attributing about 10% of a core to \
         zbus::Connection at {UPDATES_PER_SECOND:.0} updates a second.\n\
         the measurement above is what it is actually worth.\n"
    );
}