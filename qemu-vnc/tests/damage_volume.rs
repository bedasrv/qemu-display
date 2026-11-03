//! How many rectangles does the damage tracking produce, and how much of each?
//!
//! # Why this measurement
//!
//! The message volume on the bus is a median 1.58 MB body, 183 times in a
//! 12-second window. That is what feeds the `zbus::Connectio` transport thread,
//! which a `top` snapshot put at 8.0% while the client thread was at 29.2% — and
//! which no counter in this crate covers, because it is neither the encoder nor
//! the receive handler.
//!
//! "Deal with the message volume" is only worth doing if the volume is reducible.
//! It might not be: QEMU sends whole rectangles, and if this port's own damage
//! tracking already produces the minimum number of tight rectangles then the
//! bytes are what QEMU asked for and there is nothing here to win.
//!
//! So this measures, on production's shapes:
//!
//! - **how many rectangles** one `Update` turns into;
//! - **how many pixels they cover** against how many actually changed.
//!
//! That ratio is the whole question. At 1.0 the tracking is already minimal and
//! the message volume is QEMU's. At 3 or 10 there are pixels on the bus that did
//! not change, and that is worth fixing.
//!
//! **It measures the rects, not the wire.** The bytes follow from the rects plus
//! the pixel format, and guessing at a wire figure would be a measurement of
//! nothing.

use qemu_display::{Scanout, Update};
use qemu_vnc::display::Framebuffer;

/// The production console, and the video band inside it.
const SCREEN: (u32, u32) = (1280, 800);
const BAND_TOP: u32 = 0;
const BAND_ROWS: u32 = 308;

/// `x8r8g8B8`, the framebuffer's own format.
const PIXMAN_X8R8G8B8: u32 = 0x2002_0888;

fn framebuffer() -> Framebuffer {
    let mut fb = Framebuffer::new(SCREEN.0, SCREEN.1);
    fb.set_scanout(&Scanout {
        width: SCREEN.0,
        height: SCREEN.1,
        stride: SCREEN.0 * 4,
        format: PIXMAN_X8R8G8B8,
        data: vec![0u8; (SCREEN.0 * SCREEN.1 * 4) as usize],
    })
    .expect("the scanout");
    fb
}

/// A frame with `changed` marked out of `total` horizontal cells of 64 pixels.
///
/// The band is the content that matters: 1280x308 is what the production log
/// shows being redrawn, and it is the shape the message volume comes from.
fn band_frame(changed_cells: usize, total_cells: usize, seed: u8) -> Vec<u8> {
    let mut data = vec![0u8; (SCREEN.0 * SCREEN.1 * 4) as usize];
    for y in 0..BAND_ROWS as usize {
        for cell in 0..total_cells {
            // Offset each row by a different amount, so the changed spans do not
            // all start at the same left edge. Without this every row produces an
            // identical run and the coalescer's best case is measured instead of
            // a realistic one.
            let cell = (cell + y / 37) % total_cells;
            if cell >= changed_cells {
                continue;
            }
            let end = ((cell + 1) * 64).min(SCREEN.0 as usize);
            for x in (cell * 64)..end {
                let o = (y * SCREEN.0 as usize + x) * 4;
                // Content that changes every frame, so the shadow comparison has
                // something to find and cannot collapse the rect to a solid tile.
                let n = (x as u32).wrapping_mul(2654435761) >> 13
                    ^ (y as u32 * 40503) >> 7;
                data[o] = (n as u8).wrapping_add(seed);
                data[o + 1] = (n >> 3) as u8;
                data[o + 2] = seed;
            }
        }
    }
    data
}

/// Push an update and return `(rect count, pixels covered)`.
fn push(fb: &mut Framebuffer, data: Vec<u8>) -> (usize, usize) {
    let rects = fb
        .set_update(&Update {
            x: 0,
            y: BAND_TOP as i32,
            w: SCREEN.0 as i32,
            h: BAND_ROWS as i32,
            stride: SCREEN.0 * 4,
            format: PIXMAN_X8R8G8B8,
            data,
        })
        .expect("the update is inside the surface");
    let covered = rects
        .iter()
        .map(|r| usize::from(r.width) * usize::from(r.height))
        .sum();
    (rects.len(), covered)
}

/// One figure per shape: `(changed_cells, rects, pixels covered, pixels changed)`.
struct Shape {
    changed: usize,
    rects: usize,
    covered: usize,
}

fn shape(changed_cells: usize, total_cells: usize) -> Shape {
    let mut fb = framebuffer();
    // Prime the shadow, so what follows is a real change and not a first draw.
    let _ = push(&mut fb, band_frame(0, total_cells, 0));
    let (rects, covered) = push(&mut fb, band_frame(changed_cells, total_cells, 7));
    Shape {
        // Per *row* is not per update: the fixture changes the cell on every row
        // of the band, so the area that really changed is this many pixels.
        // Dividing by `changed_cells * 64` alone reported a ratio of 308 for a
        // perfectly tight rectangle, which is a measurement being wrong about
        // what it was measuring rather than the tracking over-sending.
        changed: changed_cells * 64 * BAND_ROWS as usize,
        rects,
        covered,
    }
}

#[test]
#[ignore = "a measurement, not a gate; run with --release"]
fn how_much_damage_tracking_over_sends() {
    let cells = (SCREEN.0 / 64) as usize;
    println!(
        "\n  one {BAND_ROWS}-row update of a {}x{} console, in 64-pixel cells\n",
        SCREEN.0, SCREEN.1
    );
    println!(
        "  {:>9}  {:>6}  {:>12}  {:>7}",
        "changed px", "rects", "pixels sent", "ratio"
    );
    println!(
        "  {:>9}  {:>6}  {:>12}  {:>7}",
        "---------", "------", "------------", "-------"
    );

    for changed in [1usize, 2, 5, 10, 20] {
        let s = shape(changed, cells);
        let ratio = if s.changed == 0 {
            0.0
        } else {
            s.covered as f64 / s.changed as f64
        };
        println!(
            "  {:>9}  {:>6}  {:>12}  {:>6.2}x",
            s.changed, s.rects, s.covered, ratio
        );
    }
    println!(
        "\n  A ratio near 1 means the tracking sends what changed and nothing \
         else.\n  A ratio far above it means pixels are crossing the bus that \
         did not change, and\n  that is the only way 'deal with the message \
         volume' has anything to do."
    );
}