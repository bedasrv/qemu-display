//! What does `Framebuffer::set_update` cost per changed pixel?
//!
//! # Why this measurement
//!
//! The production log's encode is 972 ms of **processor** time per 5-second
//! interval — 19.4% of a core, at 41.5 ns a pixel over 23.4 Mpx of damage. Both
//! clocks were compared on the real viewer and came out equal, so this is real CPU
//! and not a blocked socket write.
//!
//! 41.5 ns a pixel is a lot for a ZRLE encode. The parts already measured on this
//! shape add up to well under it:
//!
//! - deflate on the three-bytes-a-pixel stream ZRLE feeds it: **19.1 ns/px**
//! - the raw tiling that produces that stream: **4.8 ns/px**
//!
//! which is about 24. The remaining ~17 ns/px is not in `encodings.rs` at all, and
//! `encode_ms` covers it, because the timer starts before the framebuffer lock and
//! `set_update` runs inside it. That is the conversion, the `memcmp` against the
//! shadow, and `changed_runs`.
//!
//! # What it measures
//!
//! `set_update` on production's real shape — the video band, 1280x308 — for two
//! cases that differ only in how much of the band actually changed:
//!
//! - **all changed**: every pixel differs from the shadow, so every block is
//!   reported dirty. This is the video case.
//! - **none changed**: the same bytes again. The comparison must find nothing, and
//!   the conversion still runs.
//!
//! The difference between the two is what the comparison and `changed_runs` cost,
//! and the second figure is the floor: it is paid on every update whether anything
//! changed or not.
//!
//! **Release only.** `pixel_to_xrgb` measured 40 ns a pixel on a debug build, so a
//! debug number here is not a small version of the truth, it is a different one.

use qemu_display::{Scanout, Update};

/// `x8r8g8b8`, the framebuffer's own format. Spelled correctly this time: the
/// first version used `0x34325258`, which is the same digits as ASCII "XRGB", and
/// nothing caught it because the only assertion was on a message the failure
/// produced.
const PIXMAN_X8R8G8B8: u32 = 0x2002_0888;
use qemu_vnc::display::Framebuffer;
use qemu_vnc::rfb::Rect;

/// The production video band: 1280 wide, 308 tall, inside a 1280x800 console.
const SCREEN: (u16, u16) = (1280, 800);
const BAND: (u16, u16) = (1280, 308);

/// Rounds per case. Enough that the per-pixel figure is stable to a few percent
/// and the whole thing still runs in a second or two.
const ROUNDS: u32 = 40;

/// A band of `x8r8g8b8` pixels, with `seed` mixed in so two calls differ.
fn band(seed: u8) -> Vec<u8> {
    let (w, h) = (BAND.0 as usize, BAND.1 as usize);
    let mut data = vec![0u8; w * h * 4];
    // Four bytes at a time by index rather than `chunks_exact_mut(4)`, which
    // clippy flags as a constant chunk size: the point is that each write is
    // exactly one pixel, and a literal index says that without the lint.
    for i in 0..w * h {
        let o = i * 4;
        data[o] = (i as u8).wrapping_add(seed);
        data[o + 1] = (i >> 3) as u8;
        data[o + 2] = seed;
        data[o + 3] = 0;
    }
    data
}

fn measure(changed: bool) -> f64 {
    let px = (BAND.0 as f64) * (BAND.1 as f64);
    let mut fb = Framebuffer::new(SCREEN.0 as u32, SCREEN.1 as u32);
    fb.set_scanout(&Scanout {
        width: SCREEN.0 as u32,
        height: SCREEN.1 as u32,
        stride: SCREEN.0 as u32 * 4,
        format: PIXMAN_X8R8G8B8,
        data: vec![0u8; SCREEN.0 as usize * SCREEN.1 as usize * 4],
    })
    .expect("the scanout is accepted");

    // Prime the shadow, so the "none changed" case really is unchanged.
    let initial = band(0);
    let update = |data: &[u8]| Update {
        x: 0,
        y: 0,
        w: BAND.0 as i32,
        h: BAND.1 as i32,
        stride: BAND.0 as u32 * 4,
        format: PIXMAN_X8R8G8B8,
        data: data.to_vec(),
    };
    fb.set_update(&update(&initial)).expect("the priming update");

    let started = std::time::Instant::now();
    let mut seed = 1u8;
    for _ in 0..ROUNDS {
        let data = if changed {
            seed = seed.wrapping_add(1);
            band(seed)
        } else {
            initial.clone()
        };
        fb.set_update(&update(&data)).expect("the update is inside the surface");
    }
    started.elapsed().as_secs_f64() / f64::from(ROUNDS) / px * 1e9
}

#[test]
#[ignore = "a measurement, not a gate; run with --release"]
fn what_the_update_path_costs_a_pixel() {
    let all = measure(true);
    let none = measure(false);

    println!(
        "\n  set_update on the {BAND:?} band, nanoseconds a changed pixel\n\n  \
         every pixel changed   {all:>6.1} ns/px   <- the video case\n  \
         nothing changed       {none:>6.1} ns/px   <- the floor, paid either way\n  \
         the difference        {:>6.1} ns/px   <- finding the damage\n\n  \
         against the encode's own parts, measured on this shape:\n    \
         deflate on the byte stream ZRLE feeds it   19.1 ns/px\n    \
         the raw tiling that produces that stream     4.8 ns/px\n    \
         ------------------------------------------------------\n    \
         deflate plus tiling                         23.9 ns/px\n\n  \
         the log's whole encode is 41.5 ns/px, so the parts of it that are not\n  \
         the encoder account for {:.1} ns/px. If `all` is most of that, the cost \
         is in\n  applying the update rather than in encoding it, and no encoder \
         change can touch it.\n",
        all - none,
        41.5 - 23.9
    );

    // The floor is real work: the conversion runs whether or not anything changed,
    // because the pixels have to land in the framebuffer either way. A run that
    // changed nothing must still cost something, and if it costs nothing at all
    // then the whole measurement is not measuring `set_update`.
    //
    // **The threshold was 1.0 ns/pixel and this test was failing.** The guard was
    // calibrated when `set_update` converted per pixel, and then the conversion
    // was hoisted to once per row (`display.rs`, the same change that took
    // `set_scanout` from 3.4 to 0.7). The optimisation made the floor it was
    // watching faster than the floor it was watching for, and nothing noticed for
    // as long as the optimisation had been in the tree -- because this test is
    // `#[ignore]`d and only runs under `--release`, so the ordinary suite never
    // executes it and reported `ok` throughout.
    //
    // The replacement is derived rather than picked. A no-change update still has
    // to copy the band's 1.18 MB into the framebuffer and `memcmp` the same
    // 1.18 MB against the shadow, so 2.36 MB of traffic over 394,240 pixels. At
    // about 8 GB/s that is 0.75 ns/pixel, and the run measures 0.7 -- which is
    // what a bulk row copy should cost, and is the evidence that the fixture is
    // reaching `set_update`. Half that is a floor low enough to survive a faster
    // machine and a thousandfold above a fixture that does not run at all.
    const FLOOR_NS_PER_PX: f64 = 0.35;
    assert!(
        none > FLOOR_NS_PER_PX,
        "an update that changed nothing cost {none:.2} ns a pixel, which is below \
         the {FLOOR_NS_PER_PX} that copying and comparing a {BAND:?} band has to \
         cost, and so the fixture is probably not reaching `set_update` at all. \
         Every figure here would be wrong."
    );
    assert!(
        all >= none,
        "changing every pixel ({all:.1} ns/px) cost less than changing none \
         ({none:.1} ns/px). The comparison cannot be cheaper than skipping it, so \
         one of the two runs is not doing what this says."
    );
    // The shape is asserted rather than assumed: a band of the wrong size would
    // still produce two plausible numbers and a plausible ns/px.
    assert_eq!(
        Rect::new(0, 0, BAND.0, BAND.1).width as usize * BAND.1 as usize,
        band(0).len() / 4,
        "the band rectangle and the band of pixels disagree, so the per-pixel \
         figure below would be divided by the wrong area"
    );
}
