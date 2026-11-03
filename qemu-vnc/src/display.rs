//! D-Bus display listener — scanout, update and cursor handling.
//!
//! Port of `display.c`: it keeps a local framebuffer in sync with a QEMU
//! console, and forwards the input to the D-Bus keyboard & mouse interfaces
//! (see [`crate::input`]).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use image::RgbaImage;
use qemu_display::{
    Console as QemuConsole, ConsoleListenerHandler, ConsoleListenerMapHandler, Cursor as QemuCursor,
    Error, MouseSet, Result, Scanout, ScanoutMap, ScanoutMmap, Update, UpdateMap,
};
use tracing::{debug, error, info, trace, warn};

use crate::console::TextConsole;
use crate::input::Input;
use crate::rfb::Rect;
use crate::server::ServerInner;

/// 32bpp, 8 bits of unused padding, 8 bits each of red, green and blue.
///
/// This is the format QEMU uses for the scanout, and it matches the
/// [`PixelFormat`](crate::rfb::PixelFormat) the VNC clients are served with,
/// which means updates
/// can be sent to the clients without any pixel conversion.
pub const PIXMAN_X8R8G8B8: u32 = 0x2002_0888;
/// 32bpp, 8 bits each of alpha, red, green and blue.
pub const PIXMAN_A8R8G8B8: u32 = 0x2003_8888;
/// 16bpp, 5 bits of red, 6 of green and 5 of blue.
pub const PIXMAN_R5G6B5: u32 = 0x1001_0615;

/// Bytes per pixel of a pixman format we know how to handle.
fn bytes_per_pixel(format: u32) -> Option<usize> {
    match format {
        PIXMAN_X8R8G8B8 | PIXMAN_A8R8G8B8 => Some(4),
        PIXMAN_R5G6B5 => Some(2),
        _ => None,
    }
}

/// Convert a single `format` pixel to the internal x8r8g8b8 layout.
fn pixel_to_xrgb(format: u32, src: &[u8], dst: &mut [u8]) -> Result<()> {
    let bpp = bytes_per_pixel(format)
        .ok_or_else(|| Error::Failed(format!("Unhandled pixman format: {format:#x}")))?;
    if src.len() < bpp || dst.len() < 4 {
        return Err(Error::Failed("Truncated pixel data".into()));
    }
    match format {
        PIXMAN_X8R8G8B8 => dst[..3].copy_from_slice(&src[..3]),
        PIXMAN_A8R8G8B8 => dst.copy_from_slice(&src[..4]),
        PIXMAN_R5G6B5 => {
            let v = u16::from_le_bytes([src[0], src[1]]);
            let r = ((v >> 11) & 0x1f) as u8;
            let g = ((v >> 5) & 0x3f) as u8;
            let b = (v & 0x1f) as u8;
            // Expand to 8 bits per channel.
            dst[..3].copy_from_slice(&[
                (b << 3) | (b >> 2),
                (g << 2) | (g >> 4),
                (r << 3) | (r >> 2),
            ]);
        }
        _ => unreachable!("the format was checked above"),
    }
    // The last byte of x8r8g8b8 is unused padding.
    dst[3] = 0;
    Ok(())
}

/// Return the row `y` of a pixel buffer, or an error if it is truncated.
fn row(data: &[u8], stride: u32, y: u32, len: usize) -> Result<&[u8]> {
    let start = y as usize * stride as usize;
    data.get(start..start + len)
        .ok_or_else(|| Error::Failed("Truncated pixel data".into()))
}

/// The width of a damage comparison run, in pixels.
///
/// QEMU's `VNC_DIRTY_PIXELS_PER_BIT`, and the same 64 because a smaller block
/// finds finer damage and costs a comparison per block, and a larger one is
/// cheaper and rounds the damage up. 64 is where a video codec's macroblock and
/// a typical tile both sit, so it is a sensible place for the two to meet.
const DIRTY_BLOCK: u16 = 64;

/// A run of changed pixels that has been open for more than one row.
#[derive(Debug, Clone)]
struct OpenRun {
    left: u16,
    width: u16,
    top: u32,
    rows: u32,
}

/// Coalesces the changed runs of successive rows into rectangles.
///
/// **This is `find_and_clear_dirty_height`, and it is a cost measure rather than
/// a correctness one.** The obvious alternative is to hand the per-row runs to
/// the client and let [`crate::server::client::Damage`] merge them, and that
/// produces the same rectangles — `Damage` merges by adjacency and restarts its
/// scan on every contact, so a stack of rows with the same spans ends up as one
/// tall rectangle either way.
///
/// It was justified here at first by a claim about `MAX_DAMAGE_RECTS`: that
/// 800 rows of ten runs is 8,000 rectangles, that the client would give up and
/// degrade to the whole framebuffer, and that the coalescing was the only thing
/// standing between the comparison and its own result. **That is wrong**, and a
/// mutation that deletes this struct entirely survives every wire test in the
/// suite, which is how it was found. `Damage` merges each rectangle into the
/// list *as it arrives*, so the list holds ten entries however many rows go by;
/// it never approaches the cap.
///
/// So what this is actually for is the merge itself. Sixteen thousand calls to
/// `Damage::part`, each restarting an O(n) scan and shifting a `Vec` on contact,
/// on the client's own task, every update, for a frame that is ten rectangles.
/// `what_coalescing_the_rows_is_worth` measures it on a 1280x800 frame with ten
/// changed bands every row: 8000 calls take 119-144 us, ten coalesced rectangles
/// take 39-41 us. **About 0.08 ms, against the 19.7 ms the same update spends
/// encoding — so this is three tenths of one per cent, and it is kept because
/// it is free and it grows with the number of runs, not because it is the
/// answer.** The answer is the comparison above; the numbers on that come from
/// `compare_nanos` in the heartbeat, not from this paragraph.
///
/// Runs match by exact span, and **both lists are walked in one ascending
/// pass** rather than searched. `changed_runs` emits its spans in ascending
/// order — it walks blocks left to right — so a row's spans and the open runs
/// can be zipped like two sorted lists, which is O(runs) rather than the
/// O(runs²) a `position()` search per open run gives. That search is not a
/// detail: measured at 1.79 ms for a 1280x800 frame of twenty runs, against
/// 0.22 ms for the merging it was supposed to be cheaper than. The assert below
/// is the precondition, and it is a debug assert because the alternative to
/// getting it wrong is silently quadratic.
///
/// A run whose width changes from one row to the next is a different shape, and
/// stitching the two would give a rectangle covering pixels that did not
/// change. Nothing on the wire can tell the difference — `Damage` would merge
/// the two either way — so this is a reason to keep the rule, not a tested one.
#[derive(Debug, Default)]
pub(crate) struct Coalescer {
    open: Vec<OpenRun>,
    done: Vec<Rect>,
}

impl Coalescer {
    /// Record the changed spans of row `y`, which must be in ascending order of
    /// left edge.
    pub(crate) fn row(&mut self, y: u32, runs: Vec<(u16, u16)>) {
        debug_assert!(
            runs.is_sorted_by_key(|run| run.0),
            "changed_runs walks blocks left to right, so its spans come out in \\
             ascending order and the merge below depends on it"
        );
        let mut next = Vec::with_capacity(self.open.len() + runs.len());
        // Two cursors into two ascending lists: the runs still open from an
        // earlier row, and this row's spans. `oi` walks the first, the `for`
        // walks the second, and both only ever move right.
        let mut oi = 0;
        for span in runs {
            // Close every open run strictly left of this span: no later span in
            // this row can have its left edge, so it is finished.
            while oi < self.open.len() && self.open[oi].left < span.0 {
                let open = self.open[oi].clone();
                self.done
                    .push(Rect::new(open.left, open.top as u16, open.width, open.rows as u16));
                oi += 1;
            }
            // An open run of exactly this shape continues; anything else at
            // this left edge is a different shape and starts over.
            if oi < self.open.len()
                && self.open[oi].left == span.0
                && self.open[oi].width == span.1
            {
                let mut open = self.open[oi].clone();
                open.rows += 1;
                next.push(open);
                oi += 1;
            } else {
                next.push(OpenRun {
                    left: span.0,
                    width: span.1,
                    top: y,
                    rows: 1,
                });
            }
        }
        // Open runs to the right of every span in this row never matched: this
        // row is unchanged there.
        for open in &self.open[oi..] {
            self.done
                .push(Rect::new(open.left, open.top as u16, open.width, open.rows as u16));
        }
        self.open = next;
    }

    /// The rectangles, in any order.
    pub(crate) fn finish(mut self) -> Vec<Rect> {
        for open in self.open.drain(..) {
            self.done
                .push(Rect::new(open.left, open.top as u16, open.width, open.rows as u16));
        }
        self.done
    }
}

/// A framebuffer, in the x8r8g8b8 layout the VNC clients expect.
#[derive(Debug)]
pub struct Framebuffer {
    data: Vec<u8>,
    width: u32,
    height: u32,
    /// A copy of `data` as it was last *reported* to the clients, used to find
    /// the parts of a guest update that actually changed.
    shadow: Vec<u8>,
}

impl Framebuffer {
    /// Allocate a black framebuffer.
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            data: vec![0; (width * height * 4) as usize],
            // A fresh surface is black and every client is told it is, so the
            // shadow starts as the same black: nothing is "new" until the guest
            // draws something different.
            shadow: vec![0; (width * height * 4) as usize],
            width,
            height,
        }
    }

    /// Width, in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Height, in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Width and height, in pixels.
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// The raw x8r8g8b8 pixels.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Draw an RGBA image, at (x, y), clipping it to the framebuffer.
    pub fn draw_image(&mut self, img: &RgbaImage, x: i64, y: i64) {
        for (sy, sy_pixels) in img.rows().enumerate() {
            let y = y + sy as i64;
            if y < 0 || y >= self.height as i64 {
                continue;
            }
            for (sx, pixel) in sy_pixels.enumerate() {
                let x = x + sx as i64;
                if x < 0 || x >= self.width as i64 {
                    continue;
                }
                let o = ((y as u32 * self.width + x as u32) * 4) as usize;
                self.data[o] = pixel[2];
                self.data[o + 1] = pixel[1];
                self.data[o + 2] = pixel[0];
                self.data[o + 3] = 0;
            }
        }
    }
    /// Replace the whole content with `scanout`, resizing if needed, and
    /// report the parts that actually changed.
    pub fn set_scanout(&mut self, scanout: &Scanout) -> Result<Vec<Rect>> {
        let bpp = bytes_per_pixel(scanout.format).ok_or_else(|| {
            Error::Failed(format!("Unhandled pixman format: {:#x}", scanout.format))
        })?;
        let resized = self.dimensions() != (scanout.width, scanout.height);
        if resized {
            *self = Self::new(scanout.width, scanout.height);
        }
        let mut changed = Coalescer::default();
        let width = scanout.width as usize;
        let row_bytes = width * 4;
        for y in 0..scanout.height {
            let src = row(&scanout.data, scanout.stride, y, width * bpp)?;
            let row_start = (y as usize * self.width as usize) * 4;
            // **The format is dispatched once per row, not once per pixel, which is
            // the same change `set_update` got three rounds ago and for the same
            // reason.**
            //
            // `set_scanout` is `set_update` over the whole surface: the same
            // formats, the same transform, the same zeroed padding byte, and the
            // same `pixel_to_xrgb` call per pixel -- which re-enters a `match` on
            // the format, re-checks two lengths and returns a `Result` for every
            // single pixel, none of it hoistable out of a call that must also
            // propagate an error. So it cost what `set_update` cost, 2.9 ns a
            // pixel against 0.6 once hoisted.
            //
            // **It went unfixed for a reason worth recording: this function runs
            // once, when the console is first scanned out, and then not again for
            // the life of the connection.** So it never appeared in a profile of a
            // running server, and the argument that had protected it -- "it is not
            // in the profile" -- was true and beside the point. A profile of a
            // steady state cannot see a startup cost, and this one had been
            // sitting in the code the whole time next to the function that had
            // already been fixed.
            //
            // The destination row is the whole row, which is one thing this
            // function has and `set_update` does not: the resize above has already
            // made `self.width` equal `scanout.width` on both paths, so there is no
            // x offset to compute and no strided write to get wrong.
            let dst = &mut self.data[row_start..row_start + row_bytes];
            match scanout.format {
                PIXMAN_X8R8G8B8 | PIXMAN_A8R8G8B8 => {
                    dst.copy_from_slice(&src[..row_bytes]);
                    // The padding byte, for the reason spelled out in `set_update`:
                    // the damage comparison reads it and no encoder does, so left
                    // as it arrived it reports pixels no client can see as changed.
                    for i in (3..row_bytes).step_by(4) {
                        dst[i] = 0;
                    }
                }
                _ => {
                    for x in 0..width {
                        let o = x * 4;
                        pixel_to_xrgb(
                            scanout.format,
                            &src[x * bpp..x * bpp + bpp],
                            &mut dst[o..o + 4],
                        )?;
                    }
                }
            }
            let comparing = std::time::Instant::now();
            changed.row(
                y,
                Self::changed_runs(&self.data, &self.shadow, row_start, width),
            );
            self.shadow[row_start..row_start + row_bytes]
                .copy_from_slice(&self.data[row_start..row_start + row_bytes]);
            crate::counters::counters()
                .compare_nanos
                .add(comparing.elapsed().as_nanos() as u64);
        }
        let mut changed = changed.finish();
        if resized {
            // **A resize is always a full repaint, whatever the pixels say.**
            //
            // The runs above are measured against a shadow that was reset to
            // black by the resize, so a *black* screen reports no damage at all
            // — and a client told nothing keeps the picture it has, at the old
            // size, indefinitely. The dimensions travel in the client's own
            // `desktop_resize`, which only runs on a path that begins with
            // damage, so damage is the only way the news gets out. Reporting
            // zero runs here is the one case where "nothing changed" is a lie.
            changed.clear();
            changed.push(Rect::new(0, 0, self.width as u16, self.height as u16));
        }
        Ok(changed)
    }

    /// Composite an update rectangle into the framebuffer, and report the parts
    /// of it that actually changed.
    ///
    /// **The guest's rectangle is a claim, not a fact.** A guest that repaints a
    /// whole window repaints the unchanged parts of it too, and QEMU does not
    /// send those: `vnc_refresh_server_surface` `memcmp`s each block of the
    /// guest's damage against its own copy of the surface and marks the client
    /// dirty only where the bytes differ.
    ///
    /// ```c
    /// if (memcmp(server_ptr, guest_ptr, _cmp_bytes) == 0) {
    ///     continue;                       // the guest said dirty; nothing changed
    /// }
    /// memcpy(server_ptr, guest_ptr, _cmp_bytes);
    /// QTAILQ_FOREACH(vs, &vd->clients) { set_bit(x, vs->dirty[y]); }
    /// ```
    ///
    /// Trusting the rectangle instead means encoding pixels the client already
    /// has, at full cost: a 388,000-pixel update that differs in 4,000 of them
    /// is 97 times the work for a tenth of the picture. Video is the worst case,
    /// because a decoder-driven guest repaints its output window in full every
    /// frame while most of it is inter-frame repetition.
    ///
    /// The comparison is in `DIRTY_BLOCK`-pixel runs, which is QEMU's
    /// `VNC_DIRTY_PIXELS_PER_BIT`, and the runs are returned **per row**: rows
    /// that stack merge themselves in the client's `Damage`, which is the same
    /// coalescing `find_and_clear_dirty_height` does, reached by a different
    /// road.
    ///
    /// The cost is a `memcmp` and a `memcpy` over the update — about 0.2 ms for
    /// 388,000 pixels — against 19.7 ms of encoding, so the trade is one per
    /// cent.
    pub fn set_update(&mut self, update: &Update) -> Result<Vec<Rect>> {
        let bpp = bytes_per_pixel(update.format).ok_or_else(|| {
            Error::Failed(format!("Unhandled pixman format: {:#x}", update.format))
        })?;
        if update.x < 0
            || update.y < 0
            || update.w <= 0
            || update.h <= 0
            || update.x as u32 + update.w as u32 > self.width
            || update.y as u32 + update.h as u32 > self.height
        {
            // The update does not fit the current surface, ask for a new scanout.
            return Err(Error::Failed("Update is out of the surface bounds".into()));
        }
        let mut changed = Coalescer::default();
        let x0 = update.x as u16;
        let row_len = update.w as usize;
        let row_bytes = row_len * 4;
        for y in 0..update.h as u32 {
            let src = row(&update.data, update.stride, y, row_len * bpp)?;
            let row_start = ((y + update.y as u32) * self.width + update.x as u32) as usize * 4;
            let dst = &mut self.data[row_start..row_start + row_bytes];
            // **The format is dispatched once per row, not once per pixel, and that
            // is the whole cost of receiving an update.**
            //
            // Measured by timers placed inside this function, over 300 updates of
            // 1280x308 at production's shape:
            //
            // ```text
            //   convert       2.945 ns/pixel    <- 90 to 95 per cent of the lot
            //   changed_runs  0.081
            //   collect       0.018
            //   shadow        0.056
            //   row()         0.016
            //   coalescer     0.027
            // ```
            //
            // Three separate arguments had named the damage comparison as the
            // thing to attack. It is three per cent of it. The two per-row
            // allocations that looked like the obvious suspect are under three per
            // cent between them.
            //
            // And the conversion had been measured at **0.73 ns a pixel** in
            // isolation, which is why nobody looked at it. In the loop it is 2.9 --
            // four times worse -- because `pixel_to_xrgb` re-enters a `match` on
            // the format, re-checks two lengths and returns a `Result` for every
            // pixel, and none of that is hoisted out of a call that must also
            // propagate an error.
            //
            // `set_mapped_rect` has had this shape since it was written: same
            // formats, same transform, same zeroed padding byte. The message path
            // did not, and there was nothing to connect the two but the profile.
            match update.format {
                PIXMAN_X8R8G8B8 | PIXMAN_A8R8G8B8 => {
                    dst.copy_from_slice(&src[..row_bytes]);
                    // The padding byte. The damage comparison reads it and no
                    // encoder does, so left alone it reports pixels no client can
                    // see as changed; see `set_mapped_rect` for the long version of
                    // that argument, which applies here unchanged.
                    for i in (3..row_bytes).step_by(4) {
                        dst[i] = 0;
                    }
                }
                _ => {
                    for x in 0..row_len {
                        let o = x * 4;
                        pixel_to_xrgb(
                            update.format,
                            &src[x * bpp..x * bpp + bpp],
                            &mut dst[o..o + 4],
                        )?;
                    }
                }
            }
            // Now the row is in the framebuffer; find the runs of it that the
            // shadow disagrees with. A `memcmp` over the whole row would be one
            // answer, "changed" or "not", and a video frame is neither: it is a
            // few thousand changed pixels in the middle of 388,000.
            //
            // The timer starts here, not at the top of the loop, because
            // `compare_nanos` is meant to be the price of *finding the damage*
            // and not the price of applying the update. Wrapping the whole loop
            // timed `pixel_to_xrgb` as well and reported 270 us for a 16 KB strip
            // of 4,160 pixels -- 65 ns a pixel, which is the conversion's cost
            // wearing the comparison's name. A counter whose number is 100x the
            // thing it claims to measure is worse than no counter, because it
            // will be believed.
            let row_start = ((y + update.y as u32) * self.width + update.x as u32) as usize * 4;
            let comparing = std::time::Instant::now();
            changed.row(
                update.y as u32 + y,
                Self::changed_runs(&self.data, &self.shadow, row_start, update.w as usize)
                    .into_iter()
                    .map(|(left, width)| (x0 + left, width))
                    .collect(),
            );
            let row_bytes = update.w as usize * 4;
            self.shadow[row_start..row_start + row_bytes]
                .copy_from_slice(&self.data[row_start..row_start + row_bytes]);
            crate::counters::counters()
                .compare_nanos
                .add(comparing.elapsed().as_nanos() as u64);
        }
        Ok(changed.finish())
    }

    /// Take QEMU's mapping as the console's surface, and report what the client
    /// must be sent.
    ///
    /// **This is `set_scanout` for a surface we do not own the memory of**, and
    /// it exists because `ScanoutMap` is not merely a cheaper way to deliver
    /// the same pixels: it is a *resize* as well.
    ///
    /// `c/display.c`'s `on_scanout_map` does not just map and remember. It
    /// builds a `DisplaySurface` and calls `qemu_console_set_surface()` on it,
    /// which is what makes the console the new size — and the frame follows the
    /// surface, so a mapping whose geometry differs from the framebuffer's has
    /// to be applied to a framebuffer of that geometry. The first version of
    /// this stored the mapping and nothing else, and the mock caught it: the
    /// framebuffer was still the console's old 64x32, so every subsequent
    /// `UpdateMap` was refused by its own bounds check and the client was sent
    /// the *pre-mapping* picture. Nothing errored, because every individual
    /// step had behaved correctly.
    ///
    /// **No pixels are copied here, either.** The surface is not read at all:
    /// `UpdateMap` names rectangles of it as the guest draws them, and QEMU
    /// sends a full-surface `UpdateMap` for a new surface, which is where the
    /// pixels come from. Copying them now as well would be the very copy this
    /// interface exists to avoid, and it would be a copy of a buffer QEMU is
    /// still writing.
    ///
    /// What comes back is a full repaint whenever the geometry changed, for
    /// the same reason `set_scanout` does it: the dimensions reach the client
    /// only inside a `desktop_resize`, which only travels with damage.
    pub fn set_mapped_scanout(&mut self, width: u32, height: u32) -> Vec<Rect> {
        if self.dimensions() == (width, height) {
            return Vec::new();
        }
        *self = Self::new(width, height);
        vec![Rect::new(0, 0, width as u16, height as u16)]
    }

    /// Apply a rectangle of a mapped surface, and report what changed.
    ///
    /// **The same apply as [`Framebuffer::set_update`], from a different place.**
    /// The damage comparison, the shadow copy and the vertical coalescing are
    /// the code `set_update` runs, called here with a slice of QEMU's mapping
    /// instead of with the bytes out of a D-Bus message. That is deliberate: a
    /// parallel implementation would be a second place for the bugs this file has
    /// already found in the first one, and it would be a second one nobody was
    /// measuring.
    ///
    /// `bytes` is the rectangle's rows from the mapping, **row by row and
    /// `stride` apart**, so it is not necessarily contiguous with the mapping
    /// and its length is `height * stride`, not `width * bpp * height`. The
    /// screen stride and the rectangle's own left edge are both in play, which is
    /// exactly the arithmetic that `set_update`'s `row()` helper gets wrong if it
    /// is handed the wrong thing -- so the row bounds are computed here rather
    /// than inferred.
    ///
    /// The rectangle is `UpdateMap` rather than four loose numbers, because that
    /// is the shape the message arrives in and the four of them are never
    /// separated from it anywhere else. Passing them separately is how `x` and
    /// `y` end up the right way round.
    pub fn set_mapped_rect(&mut self, format: u32, bytes: &[u8], rect: UpdateMap) -> Result<Vec<Rect>> {
        let bpp = bytes_per_pixel(format)
            .ok_or_else(|| Error::Failed(format!("Unhandled pixman format: {format:#x}")))?;
        // **Every one of these is its own condition, and the bounds check cannot
        // see any of them.** `x + 0 > width` is false for every `x` that fits,
        // so a zero-width rectangle walks through a check that looks like it is
        // doing the work and then does nothing at all: no damage, no
        // notification, no error. The negative case is the same shape of
        // mistake and worse, because `as u32` turns `-1` into `4294967295`
        // rather than refusing it, and `x + w` then overflows -- a panic in a
        // debug build and a wrapped, meaningless comparison in a release one.
        // The version with only the bounds check was caught by its own test,
        // which is the only reason to have written one.
        let (Ok(x), Ok(y), Ok(w), Ok(h)) = (
            u32::try_from(rect.x),
            u32::try_from(rect.y),
            u32::try_from(rect.w),
            u32::try_from(rect.h),
        ) else {
            return Err(Error::Failed("mapped rectangle is negative".into()));
        };
        if w == 0 || h == 0 {
            return Err(Error::Failed("mapped rectangle is empty".into()));
        }
        if x.checked_add(w).is_none_or(|end| end > self.width)
            || y.checked_add(h).is_none_or(|end| end > self.height)
        {
            return Err(Error::Failed("mapped rectangle is outside the surface".into()));
        }
        // **The rows are `w * bpp` apart, because `bytes` is the rectangle's
        // rows cropped to the rectangle.** This took two attempts: the first
        // version indexed them at the mapping's `stride` and took a
        // `stride`-spaced slice, and the end-to-end mock test failed with
        // "mapped rectangle is short" -- the handler passed a compacted slice
        // and the callee read it as a strided one. Two places each holding half
        // of one arithmetic, disagreeing, is the arrangement most likely to
        // survive review: neither is wrong on its own.
        //
        // Collapsing it is the fix. The pitch is now derived from `w` and the
        // format, so there is nothing to disagree about, and `stride` -- which
        // only the caller needs, to find the rectangle in the mapping at all --
        // is not a parameter here.
        let row_bytes = w as usize * bpp;
        if bytes.len() < h as usize * row_bytes {
            return Err(Error::Failed("mapped rectangle is short".into()));
        }
        let mut changed = Coalescer::default();
        for row in 0..h as usize {
            let src = &bytes[row * row_bytes..row * row_bytes + row_bytes];
            let dst_start = ((y as usize + row) * self.width as usize + x as usize) * 4;
            let dst = &mut self.data[dst_start..dst_start + w as usize * 4];
            if format == PIXMAN_X8R8G8B8 || format == PIXMAN_A8R8G8B8 {
                // The common case, and the one that matters: the mapping is
                // already the framebuffer's own layout, so the row is a copy
                // rather than a per-pixel conversion.
                dst.copy_from_slice(&src[..w as usize * 4]);
                // ...and then the padding byte is cleared, which is what
                // `pixel_to_xrgb` does on every pixel of the message path.
                //
                // **It is not the same thing to leave it alone.** The encoder
                // never reads that byte, but the damage comparison does -- it
                // compares four bytes per pixel against the shadow -- so a
                // padding byte that varies between frames would be reported as
                // changed pixels that no client can see and no encoder will
                // ever send. That is pure encode cost bought by nothing, and it
                // would only appear once QEMU started offering us a mapping,
                // which makes it exactly the kind of fault that is invisible
                // until the fast path is switched on. Zeroing costs one store
                // in four on a row that is a `memcpy` beside it.
                //
                // **This used to be guarded by `if format == PIXMAN_X8R8G8B8`,
                // and that was wrong, and the reason it was wrong is that
                // "padding byte" is the wrong name for byte 3.**
                //
                // On A8R8G8B8 the fourth byte is the alpha, and it is real data
                // rather than padding -- which is true of the *source*. It is not
                // true of the destination: the framebuffer is x8r8g8b8, byte 3 is
                // unused there, and `pixel_to_xrgb` discards the alpha for every
                // format including this one. So the two paths disagreed about what
                // the framebuffer holds, and because the damage comparison reads
                // four bytes and the shadow is written from the framebuffer, they
                // did not merely differ -- they took it in turns:
                //
                // ```text
                //   frame 1, mapped,  first time   2048 px damaged   correct
                //   frame 2, message, SAME bytes    2048 px damaged   WRONG
                //   frame 3, message, SAME bytes       0 px damaged
                //   frame 4, mapped,  SAME bytes    2048 px damaged   WRONG
                // ```
                //
                // A mapped update put the alpha in byte 3; the next message-path
                // update of the *same pixels* zeroed it, so every pixel differed
                // from the shadow, and the client was sent a full rectangle that
                // had not changed. Then the mapped path did it again. On a guest
                // that alternates between the two -- which is what happens as soon
                // as QEMU offers a mapping for some rectangles and a message for
                // others -- that is a full-screen re-encode every frame, forever,
                // for pixels that are identical.
                //
                // The test that claims to pin the message path against this one,
                // `the_mapped_path_finds_the_same_damage_as_the_message_path`, runs
                // on `PIXMAN_X8R8G8B8`, where all three paths agree by
                // construction. It could not see this, and neither could any test
                // written against the guard's own comment, because the comment
                // states the requirement correctly and the code under it did not
                // meet it. `a_mapped_update_and_a_message_update_agree_about_the
                // fourth_byte` is the test that can.
                for i in (3..w as usize * 4).step_by(4) {
                    dst[i] = 0;
                }
            } else {
                for i in 0..w as usize {
                    pixel_to_xrgb(format, &src[i * bpp..], &mut dst[i * 4..i * 4 + 4])?;
                }
            }
            // Compare and record the damage for this row, exactly as
            // `set_update` does.
            let comparing = std::time::Instant::now();
            let row_start = dst_start;
            changed.row(
                y + row as u32,
                // `changed_runs` reports positions from the start of the range it
                // was given, which is the rectangle's left edge, not the screen's.
                // The damage is a screen rectangle, so `x` has to be added --
                // exactly as `set_update` does with its `x0`. Without it every
                // rect came back at the wrong horizontal position, which is the
                // kind of wrong that shows a client a plausible picture: the
                // right pixels, a few hundred columns to the left of where they
                // were drawn.
                Self::changed_runs(&self.data, &self.shadow, row_start, w as usize)
                    .into_iter()
                    .map(|(left, width)| (x as u16 + left, width))
                    .collect(),
            );
            self.shadow[row_start..row_start + w as usize * 4]
                .copy_from_slice(&self.data[row_start..row_start + w as usize * 4]);
            crate::counters::counters()
                .compare_nanos
                .add(comparing.elapsed().as_nanos() as u64);
        }
        Ok(changed.finish())
    }

    /// The runs of `row_len` pixels at `offset` where `now` differs from
    /// `shadow`, in `DIRTY_BLOCK`-pixel blocks, as `(left, width)` in pixels
    /// from `offset`.
    fn changed_runs(now: &[u8], shadow: &[u8], offset: usize, row_len: usize) -> Vec<(u16, u16)> {
        let mut runs = Vec::new();
        let mut run: Option<usize> = None;
        let mut block = 0;
        while block < row_len {
            let start = block * 4;
            let end = (block + DIRTY_BLOCK as usize).min(row_len) * 4;
            let differs = now[offset + start..offset + end] != shadow[offset + start..offset + end];
            if differs {
                if run.is_none() {
                    run = Some(block);
                }
            } else if let Some(from) = run.take() {
                runs.push((from as u16, (block - from) as u16));
            }
            block += DIRTY_BLOCK as usize;
        }
        if let Some(from) = run {
            runs.push((from as u16, (row_len - from) as u16));
        }
        runs
    }
}

/// Adds processor time to `dbus_cpu_nanos` when it goes out of scope.
///
/// A guard rather than a pair of calls at the ends of three functions, because
/// these handlers have early returns — a read-only console, a rectangle that
/// does not fit — and a timer that only fires on the fall-through path would
/// report the cost of exactly the updates that were cheap to reject.
///
/// The clock is per thread (`CLOCK_THREAD_CPUTIME_ID`), which is the point:
/// these run on the D-Bus task, so their time is in neither `encode_cpu_nanos`
/// nor any counter on the client thread.
struct CpuTimer(u64);

impl CpuTimer {
    fn new(started: u64) -> Self {
        Self(started)
    }
}

impl Drop for CpuTimer {
    fn drop(&mut self) {
        let spent = crate::server::thread_cpu_nanos().saturating_sub(self.0);
        crate::counters::counters().dbus_cpu_nanos.add(spent);
    }
}

/// A cheap, clonable handle to a shared framebuffer.
#[derive(Clone, Debug)]
pub struct FramebufferHandle(Arc<Mutex<Framebuffer>>);

impl Default for FramebufferHandle {
    fn default() -> Self {
        Self::new(Framebuffer::new(0, 0))
    }
}

impl FramebufferHandle {
    /// Share an existing framebuffer.
    pub fn new(framebuffer: Framebuffer) -> Self {
        Self(Arc::new(Mutex::new(framebuffer)))
    }

    /// Run `f` with a read lock on the framebuffer.
    pub fn with<R>(&self, f: impl FnOnce(&Framebuffer) -> R) -> R {
        f(&self.0.lock().unwrap())
    }

    /// Run `f` with a write lock on the framebuffer.
    pub fn update<R>(&self, f: impl FnOnce(&mut Framebuffer) -> R) -> R {
        f(&mut self.0.lock().unwrap())
    }
}

/// A software cursor, ready to be sent to the VNC clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// Cursor width, in pixels.
    pub width: u16,
    /// Cursor height, in pixels.
    pub height: u16,
    /// Horizontal hotspot.
    pub hot_x: u16,
    /// Vertical hotspot.
    pub hot_y: u16,
    /// x8r8g8b8 pixels.
    pub pixels: Vec<u8>,
    /// The RFB cursor mask: one bit per pixel, the rows byte aligned.
    pub mask: Vec<u8>,
}

impl Cursor {
    fn from_qemu(cursor: &QemuCursor) -> Option<Self> {
        if cursor.width <= 0 || cursor.height <= 0 {
            return None;
        }
        let (width, height) = (cursor.width as usize, cursor.height as usize);
        let len = width * height;
        let mut pixels = Vec::with_capacity(len * 4);
        // The RFB mask is a bitmap, one bit per pixel, most significant bit
        // first, with each row starting on a byte boundary.
        let stride = width.div_ceil(8);
        let mut mask = vec![0u8; stride * height];
        let (chunks, _) = cursor.data.as_chunks::<4>();
        for (i, chunk) in chunks.iter().take(len).enumerate() {
            // QEMU cursors are a8r8g8b8, we hand out x8r8g8b8.
            pixels.extend_from_slice(&[chunk[0], chunk[1], chunk[2], 0]);
            if chunk[3] != 0 {
                let (row, col) = (i / width, i % width);
                mask[row * stride + col / 8] |= 0x80 >> (col % 8);
            }
        }
        if pixels.len() != len * 4 {
            // Not enough data for the announced size.
            return None;
        }
        Some(Self {
            width: width as u16,
            height: height as u16,
            hot_x: cursor.hot_x.max(0) as u16,
            hot_y: cursor.hot_y.max(0) as u16,
            pixels,
            mask,
        })
    }
}

/// A graphic console, exposed by QEMU over the D-Bus display interface.
///
/// Port of the `ConsoleData` structure of `display.c`.
#[derive(Clone, Debug)]
pub struct GraphicConsole {
    index: u32,
    console: Arc<QemuConsole>,
    input: Input,
    framebuffer: FramebufferHandle,
    cursor: Arc<Mutex<Option<Cursor>>>,
    /// Set when the surface is backed by a read-only memory map, in which
    /// case `Update` messages can not be composited into it.
    read_only: Arc<AtomicBool>,
}

impl GraphicConsole {
    /// Create a console for the D-Bus console object `index`.
    pub async fn new(conn: &zbus::Connection, index: u32) -> Result<Self> {
        let console = QemuConsole::new(conn, index).await?;
        let width = console.width().await?;
        let height = console.height().await?;
        let input = Input::new(&console);
        Ok(Self {
            index,
            console: Arc::new(console),
            input,
            framebuffer: FramebufferHandle::new(Framebuffer::new(width, height)),
            cursor: Arc::new(Mutex::new(None)),
            read_only: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The console index, as exposed by QEMU.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The console label, as reported by QEMU.
    pub async fn label(&self) -> String {
        self.console.label().await.unwrap_or_default()
    }

    /// The shared framebuffer of this console.
    pub fn framebuffer(&self) -> FramebufferHandle {
        self.framebuffer.clone()
    }

    /// The input handler of this console.
    pub fn input(&self) -> &Input {
        &self.input
    }

    /// The current software cursor, if any.
    pub fn cursor(&self) -> Option<Cursor> {
        self.cursor.lock().unwrap().clone()
    }

    /// Register the display listener, which will push the console content to
    /// `server` and notify the VNC clients of the changes.
    pub async fn register_listener(&self, server: Weak<ServerInner>) -> Result<()> {
        #[cfg(unix)]
        let map = Arc::new(Mutex::new(None));
        // Whether we ended up offering the map, which the message path needs to
        // know before it can say that QEMU declined one.
        let declined = map_not_yet_offered();
        let index = self.index;
        let notifier = server.clone();
        self.console
            .register_listener(ConsoleListener {
                index: self.index,
                framebuffer: self.framebuffer.clone(),
                cursor: self.cursor.clone(),
                read_only: self.read_only.clone(),
                server,
                declined_map: declined.clone(),
            })
            .await?;

        // **Now ask for the mapped surface.**
        //
        // QEMU does not push pixels at us unless we ask. `Console.RegisterListener`
        // takes a socket FD, QEMU dials back on it, and on that connection we
        // export `org.qemu.Display1.Listener` -- and then, if we serve
        // `Listener.Unix.Map` as well, QEMU switches to calling `ScanoutMap`
        // once and `UpdateMap(x, y, w, h)` per frame instead of shipping 1.5 MB
        // of `ay` every time.
        //
        // **This line was missing for the whole life of the port.** The
        // interface, the handler trait, `ScanoutMap::mmap()` and the RDP client's
        // `set_map_listener` call were all written and ported; qemu-vnc never
        // made the call, so it received the message form forever. Milestone 1
        // concluded from `ui/vnc.c`'s `dcl_ops` that no mapped path existed -- which is a file that cannot answer the question, and the
        // question was about *us*, not about QEMU.
        //
        // **What the `bool` means, which took a while to establish and is not
        // what it looks like.** `Console::set_map_listener` returns
        // `Result<bool>` straight out of zbus's `ObjectServer::at()`, whose
        // documented contract is "If the interface already exists at this path,
        // returns false." So `false` means *we had already put
        // `Listener.Unix.Map` at `/org/qemu/Display1/Listener`* -- it says
        // nothing about whether QEMU will map, and nothing at all about the FD
        // passing, which happens later and reports through `ScanoutMap`'s own
        // error. The two candidates this was assumed to be between are not
        // cases of it at all.
        //
        // It is logged rather than discarded anyway, because `false` is the one
        // thing that *would* explain a map that is served and never used, and a
        // port that had logged it would have had the answer in the first
        // heartbeat instead of a day later. RDP discards it.
        #[cfg(unix)]
        let listener = ConsoleListenerMap {
            index,
            framebuffer: self.framebuffer.clone(),
            map: map.clone(),
            read_only: self.read_only.clone(),
            notify: Arc::new(move |rects| {
                if let Some(server) = notifier.upgrade() {
                    server.console_updated(index, Some(rects));
                }
            }),
        };
        match self.console.set_map_listener(listener).await {
            Ok(true) => {
                declined.store(false, Ordering::Relaxed);
                info!(
                    console = self.index,
                    "the listener offers the shared-map interface. Updates will carry \
                     four integers instead of pixels *if QEMU uses it*; if they still \
                     carry pixels, the first update will say so and name the reason."
                );
            }
            Ok(false) => info!(
                console = self.index,
                "the shared-map interface was already at the listener's path, so this \
                 handler replaced one that was there rather than adding beside it. \
                 Only the newest handler will be called."
            ),
            Err(e) => warn!(
                console = self.index,
                error = %e,
                "could not serve the shared-map interface, so updates carry pixels over \
                 D-Bus. This is not fatal: the message path still works, and it is \
                 the path that ran for this port's whole life until now."
            ),
        }
        Ok(())
    }

    /// Stop listening to console updates.
    pub fn unregister_listener(&self) {
        self.console.unregister_listener();
    }

    /// Report a new display size to the guest, as `vnc_hw_ops.ui_info` does
    /// in `display.c`.
    pub async fn set_ui_info(&self, width: u32, height: u32) -> Result<()> {
        self.console
            .proxy
            .set_ui_info(0, 0, 0, 0, width, height)
            .await?;
        Ok(())
    }
}

/// A console a VNC client can attach to: either a graphic console provided
/// by QEMU, or a text console backed by a chardev.
#[derive(Clone, Debug)]
pub enum Display {
    /// A console of the QEMU display.
    Graphic(GraphicConsole),
    /// A VT100 console backed by a chardev.
    Text(TextConsole),
}

impl Display {
    /// The display index, as used to select the console with Ctrl+Alt-N.
    pub fn index(&self) -> u32 {
        match self {
            Display::Graphic(console) => console.index,
            Display::Text(console) => console.index(),
        }
    }

    /// A human readable name for this display.
    pub fn label(&self) -> String {
        match self {
            Display::Graphic(console) => format!("console {}", console.index),
            Display::Text(console) => console.name().to_string(),
        }
    }

    /// The shared framebuffer of this console.
    pub fn framebuffer(&self) -> FramebufferHandle {
        match self {
            Display::Graphic(console) => console.framebuffer(),
            Display::Text(console) => console.framebuffer(),
        }
    }

    /// The size of the console surface, in pixels.
    pub fn dimensions(&self) -> (u32, u32) {
        self.framebuffer().with(|fb| fb.dimensions())
    }

    /// The software cursor of this console, if any.
    pub fn cursor(&self) -> Option<Cursor> {
        match self {
            Display::Graphic(console) => console.cursor(),
            // The text console draws its cursor in its framebuffer.
            Display::Text(_) => None,
        }
    }
}

/// The D-Bus display listener, i.e. the `on_scanout()`, `on_update()`,
/// `on_cursor_define()` and `on_scanout_map()` handlers of `display.c`.
struct ConsoleListener {
    index: u32,
    framebuffer: FramebufferHandle,
    cursor: Arc<Mutex<Option<Cursor>>>,
    read_only: Arc<AtomicBool>,
    server: Weak<ServerInner>,
    /// Said once already that QEMU declined the shared map.
    ///
    /// Set from `register_listener`, which knows whether the map interface was
    /// offered; read by the message path, which is where the answer arrives.
    /// Shared rather than one flag per object because the two live on the same
    /// connection but are separate objects.
    declined_map: Arc<AtomicBool>,
}

/// The flag as `register_listener` leaves it before the map is offered: **set**,
/// so an update that somehow arrives first says nothing -- a map we have not
/// asked for is not one QEMU declined.
///
/// This is a function and not a literal at the call site because two places
/// need the same value, and a test that hardcodes it checks its own copy rather
/// than this code: mutating the initial state in `register_listener` left such a
/// test green, which is the same mistake as asserting against a number the test
/// worked out for itself.
fn map_not_yet_offered() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(true))
}

/// Serves `org.qemu.Display1.Listener.Unix.Map` on the connection QEMU dials
/// back to us on.
///
/// The handler is `Clone`-shaped rather than `Clone` itself: the mapping has to
/// be reachable from the `ConsoleListener` that registered, which already owns
/// it, and the two are separate objects on the same connection.
struct ConsoleListenerMap {
    index: u32,
    framebuffer: FramebufferHandle,
    map: Arc<Mutex<Option<ScanoutMmap>>>,
    read_only: Arc<AtomicBool>,
    notify: Arc<dyn Fn(Vec<Rect>) + Send + Sync>,
}

#[async_trait::async_trait]
impl ConsoleListenerMapHandler for ConsoleListenerMap {
    async fn scanout_map(&mut self, scanout: ScanoutMap) {
        // **A mapped surface is not ours to write into.**
        //
        // `c/display.c` says so in a comment on its own `read_only` flag and
        // enforces it in `on_update`: "When true the surface is backed by a
        // read-only mmap (ScanoutMap path) and Update messages must be rejected
        // because compositing into the surface is not possible." Composing an
        // `Update` message into a mapping we merely borrowed would write into
        // QEMU's buffer behind its back. The flag is shared with the message
        // listener so that a `Update` arriving on this connection is refused
        // rather than silently corrupting the guest's scanout.
        self.read_only.store(true, Ordering::Relaxed);
        let width = scanout.width;
        let height = scanout.height;
        let stride = scanout.stride;
        let format = scanout.format;
        match scanout.mmap() {
            Ok(mmap) => {
                info!(
                    console = self.index,
                    console_height = height,
                    console_width = width,
                    stride,
                    format = format!("{format:#x}"),
                    bytes = mmap.as_ref().len(),
                    "QEMU offered a shared map; updates now name a rectangle of it \
                     instead of carrying pixels"
                );
                // The console is this size now, whatever it was before. See
                // `set_mapped_scanout` for why this is not optional.
                let changed = self
                    .framebuffer
                    .update(|fb| fb.set_mapped_scanout(width, height));
                *self.map.lock().unwrap() = Some(mmap);
                if !changed.is_empty() {
                    (self.notify)(changed);
                }
            }
            Err(e) => {
                // Nothing is registered, so `UpdateMap` will arrive with nothing
                // to read. It has to say so and drop the update rather than read
                // a stale or absent mapping: see `update_map`.
                error!(console = self.index, "could not map the surface QEMU offered: {e}");
                *self.map.lock().unwrap() = None;
            }
        }
    }

    async fn update_map(&mut self, update: UpdateMap) {
        let cpu_started = crate::server::thread_cpu_nanos();
        // Counted on exit by the guard below, so every `return` in this function
        // is accounted for rather than only the paths that fall through it.
        let _cpu = CpuTimer::new(cpu_started);
        crate::counters::counters().dbus_messages.bump();
        trace!(?update, "mapped update");
        // **Every bound here comes from the mapping, not from the message.**
        //
        // The message is four integers and nothing else, so there is no length
        // to check it against -- no byte count that could contradict the
        // geometry, which is the check that has caught every malformed-frame
        // fault in this file. The mapping's own `stride * height` is the only
        // authority, and QEMU writes into it concurrently, so the rectangle is
        // validated against *that* before a single byte is read. A rectangle
        // that does not fit is dropped and logged, never clamped: clamping would
        // read a different part of the surface than QEMU said it had drawn, and
        // the client would show pixels from the wrong place as though they were
        // current.
        let (x, y, w, h) = (
            update.x as i64,
            update.y as i64,
            update.w as i64,
            update.h as i64,
        );
        if x < 0 || y < 0 || w <= 0 || h <= 0 {
            warn!(
                x = update.x,
                y = update.y,
                w = update.w,
                h = update.h,
                "UpdateMap with a non-positive or negative rectangle, ignoring"
            );
            return;
        }
        let map = self.map.lock().unwrap();
        let Some(map) = map.as_ref() else {
            // An update naming a map we do not have. QEMU has called
            // `UpdateMap` without a successful `ScanoutMap`, which is a QEMU
            // fault or a `ScanoutMap` we failed to map; either way the only
            // safe answer is to drop it and say so once, because the console
            // then stops updating and a silent drop looks like a frozen screen.
            error!(
                x = update.x,
                y = update.y,
                w = update.w,
                h = update.h,
                "UpdateMap with no mapped surface; the console will not update until QEMU \
                 offers one again"
            );
            return;
        };
        // **Bytes per pixel has to be known before the rectangle can be checked
        // against the stride**, and the first version of this checked `x + w
        // > stride / 4` -- hardcoding the answer. That is right for the only
        // format QEMU offers today and silently wrong for every other one: a
        // 16bpp surface would have had its right half treated as out of bounds
        // and dropped, or a 64bpp one treated as in bounds and read past.
        let Some(bpp) = bytes_per_pixel(map.format()) else {
            error!(
                console = self.index,
                format = format!("{:#x}", map.format()),
                "QEMU mapped a surface in a format we cannot read, and did not say so in \
                 any way we can use. Updates on it will be dropped."
            );
            return;
        };
        let stride = i64::from(map.stride());
        let height = map.as_ref().len() as i64 / stride.max(1);
        if x + w > stride / bpp as i64 || y + h > height {
            warn!(
                x = update.x,
                y = update.y,
                w = update.w,
                h = update.h,
                stride,
                mapped_height = height,
                "UpdateMap rectangle is outside the mapped surface, ignoring rather than \
                 clamping: clamping would send the client pixels from somewhere other \
                 than where QEMU drew"
            );
            return;
        }

        // Read the rectangle out of the mapping, row by row, straight into the
        // framebuffer -- **no `to_vec()`**, unlike the RDP client.
        //
        // This is the whole point of offering the map. `to_vec()` would copy the
        // rectangle out and hand `set_update` an owned buffer, which is one copy
        // instead of the two the message path makes (zbus writes it, we read
        // it) -- so it would keep a cost this change exists to remove, and the
        // remaining saving would be only the D-Bus framing.
        //
        // It has to be a read and a write either way, because the framebuffer is
        // ours and the mapping is QEMU's, and QEMU may write into it again the
        // moment this returns. What is saved is the *copy into a message-sized
        // buffer first*, which for a 1280x308 band is 1.5 MB allocated and
        // filled per update at 18 a second.
        let stride = map.stride() as usize;
        let format = map.format();
        let offset = y as usize * stride + x as usize * bpp;
        let row_bytes = w as usize * bpp;
        // **The rows are cropped here, where the mapping's stride is known.**
        // That is one copy per update of only the rectangle -- 4,160 pixels'
        // worth for a 1280x308 band, not the 1.5 MB a D-Bus message would have
        // carried -- and it is a copy, not a fix: the framebuffer is ours and
        // the mapping is QEMU's, so a read and a write happen either way. What
        // the map removes is the *serialisation* of the pixels, not the
        // application of them.
        let mut rows = Vec::with_capacity(h as usize * row_bytes);
        for row in 0..h as usize {
            let start = offset + row * stride;
            let Some(row_bytes_of_mapping) = map.as_ref().get(start..start + row_bytes) else {
                warn!(
                    console = self.index,
                    start,
                    mapped_bytes = map.as_ref().len(),
                    "the mapping is shorter than row {row} of the rectangle we were \
                     told to read"
                );
                return;
            };
            rows.extend_from_slice(row_bytes_of_mapping);
        }

        // Applied like any other update, so the damage comparison, the shadow
        // copy and the notification all happen exactly as they do on the message
        // path. This is not a parallel implementation of the update: it is the
        // same one, fed from a different place -- which is why a bug in the
        // comparison, the conversion or the coalescing cannot be fixed in one
        // path and missed in the other.
        let claimed = (w as u32) * (h as u32);
        let applied = self.framebuffer.update(|fb| {
            fb.set_mapped_rect(format, &rows, update)
        });
        match applied {
            Ok(changed) => {
                // The same line the message path logs, with the same fields,
                // because the whole reason it exists was that a heartbeat could
                // not tell "the guest drew nothing" from "the guest drew
                // something we judged unchanged", and a run over one path must
                // not be the only run that could answer that. `claimed_pixels`
                // against `found_pixels` is the question, and it is the question
                // for both paths.
                let found: u32 = changed.iter().map(|r| u32::from(r.width) * u32::from(r.height)).sum();
                info!(
                    console = self.index,
                    x = update.x,
                    y = update.y,
                    w = update.w,
                    h = update.h,
                    stride,
                    format = format!("{format:#x}"),
                    claimed_pixels = claimed,
                    found_rects = changed.len(),
                    found_pixels = found,
                    "mapped update received"
                );
                // No damage, no notification -- the same rule as `update`.
                // Notifying on an empty list would wake the clients up to send
                // nothing, which costs a round trip per frame on a desktop that
                // repaints identically.
                if !changed.is_empty() {
                    (self.notify)(changed);
                }
            }
            Err(e) => error!("could not apply a mapped rectangle: {e}"),
        }
    }
}

impl ConsoleListener {
    /// Say, once, that we offered a shared map and pixels arrived anyway.
    ///
    /// **The fact is knowable here and nowhere else.** We offer the map at
    /// registration; QEMU's answer is a `ScanoutMap` that never comes. Until
    /// this line existed, that was only visible by reading the registration
    /// line and then counting the updates — two things far apart in the log,
    /// and the kind of inference that produced this port's other three wrong
    /// turns.
    ///
    /// The reason is QEMU's, and it is in QEMU's source rather than in anything
    /// this port can change. `ui/dbus-listener.c`'s `dbus_scanout_map()`:
    ///
    /// ```c
    /// if (!ddl->can_share_map || ddl->ds->share_handle == SHAREABLE_NONE) {
    ///     return false;
    /// }
    /// ```
    ///
    /// `can_share_map` is ours to set and is: it becomes true when QEMU reads
    /// `Interfaces` and finds `org.qemu.Display1.Listener.Unix.Map` in it, via
    /// `dbus_display_listener_implements()`. **The other half is not.** A
    /// `DisplaySurface` only has a `share_handle` when the console's display
    /// was set up to be shareable, which is a property of the QEMU command
    /// line and the display backend, and on this VM it clearly is not — the
    /// first scanout arrived as pixels, which is what a non-shareable surface
    /// produces.
    ///
    /// There is a second thing QEMU would rather do on Linux, and did not do
    /// either: under `CONFIG_GBM`, `dbus_scanout_texture()` exports the
    /// surface as DMA-BUF through `dbus_call_scanout_dmabuf()` instead. No
    /// DMA-BUF was offered on this host either, so the guest's surface is
    /// neither shareable nor GBM-exportable — a plain pixman buffer in QEMU's
    /// own RAM.
    ///
    /// So the cost model behind the original estimate of the map's worth is not
    /// wrong about the map; it is answering a question about a configuration
    /// this VM is not in. That is worth one line in the log, once, instead of
    /// a day's worth of arithmetic.
    ///
    /// Returns whether *this* call was the one that said it. Nothing in the
    /// server needs to know that, and it is here so that "once" is something a
    /// test can read instead of something a test has to take on trust: the only
    /// other observable is a log line, and counting log lines is how this port
    /// once ended up hashing every pixel of a surface on the task that applies
    /// the frame.
    fn note_map_declined(&self) -> bool {
        // `swap` is the whole point: the first caller says it, everyone after
        // finds the flag set and returns. `Ordering::Relaxed` is enough because
        // this carries no data for anyone else to see.
        if self.declined_map.swap(true, Ordering::Relaxed) {
            return false;
        }
        info!(
            console = self.index,
            "pixels are arriving as messages, so QEMU is not using the shared map we \
             offered. Nothing is wrong with this port: QEMU only maps a console whose \
             DisplaySurface is shareable -- ui/dbus-listener.c's dbus_scanout_map() \
             returns false when ds->share_handle == SHAREABLE_NONE, and that is a \
             property of how the VM's display is configured, not of the listener. \
             Every update costs its pixels on the bus, which is what it always did."
        );
        true
    }

    /// Notify the VNC clients that the console content changed, everywhere.
    fn notify(&self) {
        if let Some(server) = self.server.upgrade() {
            server.console_updated(self.index, None);
        }
    }

    /// Tell the clients what actually changed, as a list of rectangles.
    ///
    /// Separate from [`ConsoleListener::notify`] because one rectangle and a
    /// list are different things to a client, and because the list is the whole
    /// point: QEMU's `vnc_job_add_rect` is called once per run of changed
    /// pixels, so its job — and so its single `FramebufferUpdate` — carries
    /// several rectangles. Handing the client one rectangle per run is the same
    /// shape on the wire.
    fn notify_rects(&self, rects: Vec<Rect>) {
        if let Some(server) = self.server.upgrade() {
            server.console_updated(self.index, Some(rects));
        }
    }

    /// The damaged area of an `Update` message, as a VNC rectangle.
    ///
    /// The coordinates are negative when the guest clips a rectangle at the
    /// edge of the surface, and are not bounded by the surface at all when
    /// the update is out of bounds: both cases end up covering everything,
    /// because we can not tell what part of the framebuffer they touched.
    fn damage_of(update: &Update, (width, height): (u32, u32)) -> Option<Rect> {
        if update.x < 0
            || update.y < 0
            || update.w <= 0
            || update.h <= 0
            || update.x as u32 + update.w as u32 > width
            || update.y as u32 + update.h as u32 > height
        {
            return None;
        }
        // The `set_update` bounds check rejects the same rectangles, so this
        // one always fits.
        Some(Rect::new(
            update.x as u16,
            update.y as u16,
            update.w as u16,
            update.h as u16,
        ))
    }
}

#[async_trait::async_trait]
impl ConsoleListenerHandler for ConsoleListener {
    async fn scanout(&mut self, scanout: Scanout) {
        let cpu_started = crate::server::thread_cpu_nanos();
        // Counted on exit by the guard below, so every `return` in this function
        // is accounted for rather than only the paths that fall through it.
        let _cpu = CpuTimer::new(cpu_started);
        crate::counters::counters().dbus_messages.bump();
        trace!(?scanout, "scanout");
        let _ = self.note_map_declined();
        // The plain Scanout path provides a writable copy of the surface.
        self.read_only.store(false, Ordering::Relaxed);
        match self.framebuffer.update(|fb| {
            let result = fb.set_scanout(&scanout);
            // The dimensions, the pixman format and the byte count, and
            // nothing else. Everything here is free, because it is a field
            // read.
            //
            // This line used to also report what the surface *looks like* — how
            // many distinct colours it holds, how much of it the commonest one
            // covers, a coarse grid of bands. That was the measurement that
            // found the blank screen, and it is gone because it cost 35 ms and
            // 20 ms respectively on a 1280x800 console: two million `HashSet`
            // inserts per D-Bus message, on the task that applies the frame,
            // whether or not anything was logging. A guest updating twenty times
            // a second pinned a core and delayed the very updates the log was
            // describing, which is a diagnostic that costs more than the thing
            // it diagnoses.
            //
            // The question it answered — is the client being sent a picture or
            // noise — is now answered by an outside decoder, which is where it
            // belongs: a measurement inside the server can only say what arrived,
            // and everything that has been wrong here was never what arrived.
            info!(
                width = scanout.width,
                height = scanout.height,
                stride = scanout.stride,
                format = format!("{:#x}", scanout.format),
                bytes = scanout.data.len(),
                "scanout applied"
            );
            result
        }) {
            // What the *server's own comparison* found changed, not the
            // rectangle the guest named. A scanout is the whole surface either
            // way, and a full-screen one that differs in a corner is a corner.
            Ok(changed) if changed.is_empty() => {}
            Ok(changed) => self.notify_rects(changed),
            Err(e) => error!("failed to apply scanout: {e}"),
        }
    }

    async fn update(&mut self, update: Update) {
        let cpu_started = crate::server::thread_cpu_nanos();
        // Counted on exit by the guard below, so every `return` in this function
        // is accounted for rather than only the paths that fall through it.
        let _cpu = CpuTimer::new(cpu_started);
        crate::counters::counters().dbus_messages.bump();
        trace!(?update, "update");
        let _ = self.note_map_declined();
        if self.read_only.load(Ordering::Relaxed) {
            warn!("update on a read-only console surface, ignoring");
            return;
        }
        let damage = Self::damage_of(&update, self.framebuffer.with(|fb| fb.dimensions()));
        match self.framebuffer.update(|fb| {
            let result = fb.set_update(&update);
            // **What the comparison found, next to what the guest said.** Two
            // numbers that are the same on a well-behaved guest and wildly
            // different on a decoder-driven one, and until this line existed the
            // only record of a guest's damage was the rectangle it named — which
            // is the number the whole shadow copy exists to disbelieve.
            //
            // It was added because a reference client sat asking 147 times for
            // fifteen seconds, the server logged 70 strip updates arriving, and
            // nothing in the log said whether those strips were judged damaged.
            // `updates=1` in the heartbeat said the answer was no; this line
            // says which, and a heartbeat interval cannot.
            let found = result
                .as_ref()
                .map(|rects| {
                    (
                        rects.len(),
                        rects
                            .iter()
                            .map(|r| u32::from(r.width) * u32::from(r.height))
                            .sum::<u32>(),
                    )
                })
                .unwrap_or((0, 0));
            // Free fields only, for the reason on the scanout path above: the
            // content measurement that used to be here cost 55 ms of `HashSet`
            // inserts per message, on the task that composites the frame.
            //
            // "received" rather than "applied", and only on success. The line
            // used to be logged before the result was known, so a truncated or
            // out-of-bounds update produced an INFO line saying it had been
            // applied and an ERROR line a moment later saying it had not — and
            // the INFO one is the one that reads as fact. It cost a round of
            // debugging to work out which was lying, because a log that
            // contradicts itself is worse than one that is merely quiet.
            if result.is_ok() {
                info!(
                    x = update.x,
                    y = update.y,
                    w = update.w,
                    h = update.h,
                    stride = update.stride,
                    format = format!("{:#x}", update.format),
                    bytes = update.data.len(),
                    damage = ?damage,
                    claimed_pixels = update.w as u32 * update.h as u32,
                    found_rects = found.0,
                    found_pixels = found.1,
                    "update received"
                );
            }
            result
        }) {
            // **What changed, not what the guest said changed.** This is where
            // QEMU's `memcmp` in `vnc_refresh_server_surface` earns its keep,
            // and it is the one change here that is not a micro-optimisation: a
            // guest that repaints a window repaints the unchanged parts of it
            // too, and sending those costs full price. The log line above still
            // reports `damage`, the rectangle the guest *named*, because what it
            // said is worth having next to what we did about it.
            Ok(changed) if changed.is_empty() => {}
            Ok(changed) => self.notify_rects(changed),
            Err(e) => {
                // The guest resized the display under our feet, it will send
                // us a new scanout.
                error!("failed to apply update: {e}");
            }
        }
    }

    async fn cursor_define(&mut self, cursor: QemuCursor) {
        trace!(?cursor, "cursor define");
        *self.cursor.lock().unwrap() = Cursor::from_qemu(&cursor);
        // The cursor is not drawn in the framebuffer: the clients draw it
        // themselves, from the pseudo-encoding sent along the next update.
        self.notify();
    }

    async fn mouse_set(&mut self, set: MouseSet) {
        trace!(?set, "mouse set");
    }

    async fn disable(&mut self) {
        debug!(index = self.index, "console disabled");
    }

    #[cfg(unix)]
    /// **Refused, and the reference does not use it either.**
    ///
    /// The reason matters, because the wrong version of this reason is what
    /// closed the *map* half of this milestone for the port's whole life. That
    /// one said "QEMU's VNC server has no DMA-BUF path", on the evidence of
    /// `ui/vnc.c` -- which is QEMU's VNC *client-facing* server, a different
    /// program, and cannot say anything about what a display *consumer* may
    /// offer.
    ///
    /// This one is read off `c/`, which is the thing being ported:
    ///
    /// - `setup_display_listener` adds exactly two interfaces to the skeleton --
    ///   `org.qemu.Display1.Listener` and `org.qemu.Display1.Listener.Unix.Map`
    ///   -- and sets the `interfaces` property to the second of those alone.
    /// - `grep -ri dma c/` finds nothing at all. Not a handler, not a
    ///   `warn`, not a mention in a comment.
    ///
    /// So the reference never offers a DMA-BUF, and a consumer that
    /// implemented one would be *adding* a capability `tools/qemu-vnc` does not
    /// have. That is the one thing a port must not do, and it is a much better
    /// reason than "we cannot": the DMA-BUF scanout is a guest-GPU handle whose
    /// pixels live in the guest's address space, so consuming one would need
    /// access this client does not have and that no VNC client has ever wanted.
    ///
    /// It stays `warn!` rather than `error!` and rather than being folded away:
    /// QEMU offering one when the reference would not is a real possibility
    /// worth a line in the log, and a line that says "the reference does not do
    /// this either" is more useful to whoever reads it next.
    async fn scanout_dmabuf(&mut self, scanout: qemu_display::ScanoutDMABUF) {
        trace!(?scanout, "scanout dmabuf");
        warn!(
            width = scanout.width,
            height = scanout.height,
            fourcc = format!("{:#x}", scanout.fourcc),
            num_planes = scanout.num_planes,
            "a DMA-BUF scanout was offered and is refused. tools/qemu-vnc does not \
             use one either -- its listener serves Listener and Listener.Unix.Map and \
             nothing else -- so this is a QEMU offering a capability the reference \
             does not have, and the console will keep using the map or the scanout \
             messages."
        );
    }

    #[cfg(unix)]
    async fn update_dmabuf(&mut self, update: qemu_display::UpdateDMABUF) {
        trace!(?update, "update dmabuf");
        warn!(
            x = update.x,
            y = update.y,
            w = update.w,
            h = update.h,
            "a DMA-BUF update was offered and is refused; see scanout_dmabuf for why \
             tools/qemu-vnc has no such path either"
        );
    }

    fn disconnected(&mut self) {
        debug!(index = self.index, "display listener disconnected");
    }

    fn interfaces(&self) -> Vec<String> {
        // **This property is what makes QEMU offer the map at all.**
        //
        // It is the second half of the wiring, and the half that is easy to
        // leave behind: `set_map_listener` puts
        // `org.qemu.Display1.Listener.Unix.Map` on the object server, and
        // QEMU reads this property to decide whether it *should* use it. An
        // empty list here means the interface is served and never called, which
        // looks exactly like the interface not existing.
        //
        // It said "we do not support the shared memory map interfaces, the
        // scanout messages are good enough for a VNC server" for the whole life
        // of this port. `c/display.c`'s `setup_display_listener` sets this very
        // property to `org.qemu.Display1.Listener.Unix.Map` and adds the map
        // interface to the skeleton unconditionally -- so the reference server
        // does not treat the map as optional either, and the comment was a
        // decision this file had never actually made.
        //
        // The Windows branch is left empty: the Win32 map needs
        // `Listener.Win32.Map` and a handle, and nothing here can serve it, so
        // claiming it would be worse than admitting it.
        if cfg!(unix) {
            vec!["org.qemu.Display1.Listener.Unix.Map".to_string()]
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The row-at-a-time conversion must agree with the per-pixel one it replaced.
    ///
    /// **`set_update` stopped calling `pixel_to_xrgb` per pixel** and now copies
    /// the row and clears the padding byte in one go, which is what took the
    /// receive path from 3.2 ns a pixel to 0.9. That is measured and the
    /// measurement is recorded where the code is; this is the part that says the
    /// speed-up did not change what comes out.
    ///
    /// **It goes through `set_update`, because the first version of this test did
    /// not and could not have caught anything.** It re-implemented the bulk path
    /// inline and compared that against `pixel_to_xrgb` -- and a mutation that
    /// deleted the padding-byte clear from `set_update` passed it, because the
    /// test was comparing a copy of the code with a copy of the code, and the
    /// copy was still correct. A test that reimplements what it is testing checks
    /// that its own two copies agree.
    ///
    /// So this drives the real `set_update` and compares the framebuffer it
    /// produces against one built pixel by pixel with `pixel_to_xrgb`, which is the
    /// function the bulk path replaced and which is still in the crate and still
    /// called for 16-bit formats.
    ///
    /// The padding byte is the thing worth checking. It is invisible to the encoder
    /// and to the client and **is** read by the damage comparison, so a version
    /// that disagreed would report the whole screen as changed on every update
    /// while showing, on screen, nothing at all.
    #[test]
    fn the_bulk_row_conversion_agrees_with_the_per_pixel_one() {
        for format in [PIXMAN_X8R8G8B8, PIXMAN_A8R8G8B8, PIXMAN_R5G6B5] {
            let bpp = bytes_per_pixel(format).expect("a known format");
            // A rectangle that starts off-screen-left and stops short of the right
            // edge, so the row offset and the length are both wrong if they are
            // wrong, and a height past `DIRTY_BLOCK`.
            let (w, h, rx, ry, rw, rh) = (200u32, 70u32, 7i32, 5i32, 150i32, 40i32);
            // Byte 3 of every pixel deliberately non-zero, so a padding byte that
            // is copied rather than cleared is visible in the comparison.
            let data: Vec<u8> = (0..(rw as usize * rh as usize * bpp))
                .map(|i| ((i * 37 + i / 5) % 251 + 1) as u8)
                .collect();
            let update = Update {
                x: rx, y: ry, w: rw, h: rh,
                stride: rw as u32 * bpp as u32,
                format,
                data,
            };

            // What `set_update` produces.
            let mut fb = Framebuffer::new(w, h);
            fb.set_update(&update).expect("the update applies");

            // What the per-pixel function produces, over the same rectangle of a
            // framebuffer that started at zero -- which is where both of them start.
            let mut expected = vec![0u8; (w * h * 4) as usize];
            for y in 0..rh as u32 {
                let src = row(&update.data, update.stride, y, rw as usize * bpp)
                    .expect("the row is there");
                for x in 0..rw as usize {
                    let o = ((y + ry as u32) * w + x as u32 + rx as u32) as usize * 4;
                    pixel_to_xrgb(format, &src[x * bpp..x * bpp + bpp], &mut expected[o..o + 4])
                        .expect("a known format");
                }
            }

            assert_eq!(
                fb.data, expected,
                "format {format:#x}: `set_update` and `pixel_to_xrgb` produced \
                 different framebuffers. The first byte of each pixel that differs \
                 is reported below."
            );
        }
    }

    /// `set_scanout`'s bulk row conversion is the same transform as the per-pixel
    /// one.
    ///
    /// **The twin of the test above, written when `set_scanout` was given the same
    /// hoisted dispatch `set_update` has had for three rounds.**
    ///
    /// It is a separate test rather than a fourth format added to that one because
    /// the two functions are reached by different messages and can be fixed
    /// separately -- and they were, which is exactly how the asymmetry survived so
    /// long. `set_update` runs on every update; `set_scanout` runs once, at
    /// startup. Both were per-pixel. The first was in every profile and was fixed;
    /// the second was in none and was not, and "it is not in the profile" was both
    /// true and no reason to leave it.
    ///
    /// Two things are pinned, and they are not the same thing. The first is that
    /// the transform is unchanged, across the two 32-bit formats that take the bulk
    /// path and the 16-bit one that falls back to `pixel_to_xrgb`. The second is
    /// the padding byte, and it is the one a plain `copy_from_slice` gets wrong:
    /// the damage comparison reads byte 3 and no encoder does, so a padding byte
    /// copied through instead of cleared reports damage that is not there.
    ///
    /// **The payload is built so that byte 3 of every 32-bit pixel is non-zero, on
    /// purpose, and that is what stops the test being vacuous.** Every byte in it is
    /// non-zero, so a bulk path that forgot the padding would copy a non-zero into
    /// byte 3 where `pixel_to_xrgb` writes a zero -- and with a payload of zeros
    /// there it would have agreed perfectly and passed while being wrong. The
    /// mutation below is that deletion, and it is caught.
    ///
    /// The width is 203 and the height 61: neither is round, so a row length or a
    /// destination offset off by one lands in the comparison, and the height is past
    /// `DIRTY_BLOCK` so the coalescer is doing more than one block.
    #[test]
    fn the_scanout_bulk_row_conversion_agrees_with_the_per_pixel_one() {
        for format in [PIXMAN_X8R8G8B8, PIXMAN_A8R8G8B8, PIXMAN_R5G6B5] {
            let bpp = bytes_per_pixel(format).expect("a known format");
            let (w, h) = (203u32, 61u32);
            let data: Vec<u8> = (0..(w as usize * h as usize * bpp))
                .map(|i| ((i * 37 + i / 5) % 251 + 1) as u8)
                .collect();
            let scanout = Scanout {
                width: w,
                height: h,
                stride: w * bpp as u32,
                format,
                data,
            };

            // What `set_scanout` produces. The surface starts at the scanout's own
            // dimensions, so the resize inside it does not fire and this is a plain
            // conversion over a framebuffer that began black -- which is where both
            // sides of the comparison start.
            let mut fb = Framebuffer::new(w, h);
            fb.set_scanout(&scanout).expect("the scanout applies");

            // What the per-pixel function produces, over the same payload.
            let mut expected = vec![0u8; (w * h * 4) as usize];
            for y in 0..h {
                let src = row(&scanout.data, scanout.stride, y, w as usize * bpp)
                    .expect("the row is there");
                for x in 0..w as usize {
                    let o = (y as usize * w as usize + x) * 4;
                    pixel_to_xrgb(format, &src[x * bpp..x * bpp + bpp], &mut expected[o..o + 4])
                        .expect("a known format");
                }
            }

            assert_eq!(
                fb.data, expected,
                "format {format:#x}: `set_scanout` and `pixel_to_xrgb` produced \
                 different framebuffers. The first byte of each pixel that differs \
                 is reported below."
            );
        }
    }

    /// A repeated scanout is not damage.
    ///
    /// **Written alongside the bulk conversion above, and for a reason it does not
    /// share.** The conversion decides what the framebuffer contains; this decides
    /// what the client is told, and the two are wired differently: the damage
    /// comparison reads `self.data` and `self.shadow`, and the shadow is updated
    /// *after* the comparison, from the same row. So a conversion that is right and
    /// a shadow update that is wrong produce a server that encodes the correct
    /// pixels and reports them as damaged on every scanout, forever -- and the
    /// differential test above cannot see it, because it compares `fb.data`, which
    /// is correct either way.
    ///
    /// **This test was written with an all-black payload and the mutation check
    /// proved it was worth nothing.** Black compares equal to black whether or not
    /// the shadow was ever written, so deleting the shadow update outright -- the
    /// single most damaging thing that could happen to this code -- left the test
    /// green. The differential test caught a deleted padding byte; this one caught
    /// nothing at all, and it was sitting here named after the property it did not
    /// check.
    ///
    /// So the payload is **non-black**, which is what makes the shadow load-bearing:
    /// the first scanout has to report damage, and the second must not. Both halves
    /// are asserted, because a test that only checked the second would also pass
    /// against a `set_scanout` that reported nothing ever, and that is a server
    /// which never sends a pixel.
    #[test]
    fn a_scanout_that_changes_nothing_is_not_damage() {
        for format in [PIXMAN_X8R8G8B8, PIXMAN_A8R8G8B8, PIXMAN_R5G6B5] {
            let bpp = bytes_per_pixel(format).expect("a known format");
            let (w, h) = (64u32, 48u32);
            // Non-black everywhere, and byte 3 non-zero for the 32-bit formats for
            // the reason the differential test gives.
            let data: Vec<u8> = (0..(w as usize * h as usize * bpp))
                .map(|i| ((i * 61 + i / 3) % 251 + 1) as u8)
                .collect();
            let scanout = Scanout {
                width: w,
                height: h,
                stride: w * bpp as u32,
                format,
                data,
            };
            let mut fb = Framebuffer::new(w, h);

            let first = fb.set_scanout(&scanout).expect("the first scanout applies");
            assert!(
                !first.is_empty(),
                "format {format:#x}: the first scanout of a non-black screen \\
                 reported no damage, so nothing would be sent to the client at all"
            );

            let again = fb.set_scanout(&scanout).expect("the second scanout applies");
            assert!(
                again.is_empty(),
                "format {format:#x}: the same scanout twice reported {again:?} as \\
                 damage the second time. Nothing changed, so the shadow already \\
                 holds it. The shadow is not being written from the row, so every \\
                 pixel of every scanout is reported as changed."
            );
        }
    }

    /// A repeated update is not damage.
    ///
    /// **Written while `set_update` was being rewritten to compare the incoming
    /// pixels against the shadow before writing anything**, and kept after that
    /// rewrite was measured and reverted, because the property is worth having
    /// whether or not the shortcut exists.
    ///
    /// It is the only check in this file that can see the one fault the format
    /// handling is prone to. A differential test against the previous algorithm
    /// was tried first and **could not**: it applies payloads that differ, so the
    /// right answer is "the whole rectangle changed", and a comparison that is
    /// wrong also says the whole rectangle changed. Giving a 16-bit format the
    /// three-byte prefix that suits X8R8G8B8 passed against it, and would have
    /// shipped a console reporting a full screen of damage on every update,
    /// forever, on any guest with a 16-bit framebuffer.
    ///
    /// It caught the same class of fault in its own author: the prefix length for
    /// A8R8G8B8 was written as four, when `pixel_to_xrgb` zeroes the fourth byte
    /// of every format, so comparing four source bytes finds QEMU's alpha against
    /// our zero.
    ///
    /// The case that separates them is an update that changes nothing: the source
    /// is identical to what the shadow already holds, so the right answer is no
    /// damage at all. The shortcut compares two bytes against three and finds a
    /// difference on every pixel, and reports a full screen of damage for a screen
    /// that did not move -- every update, for the life of the connection, on any
    /// 16-bit-per-pixel console.
    ///
    /// It is also worth having on its own terms: a viewer that re-requests an
    /// update it has already been sent is ordinary, and the third time this port
    /// got a plausible-looking wrong answer it was because encoder and decoder
    /// agreed and nobody asked what the *other* reading would have said.
    #[test]
    fn an_update_that_changes_nothing_is_not_damage() {
        for format in [PIXMAN_X8R8G8B8, PIXMAN_A8R8G8B8, PIXMAN_R5G6B5] {
            let bpp = bytes_per_pixel(format).expect("a known format");
            // A width past `DIRTY_BLOCK`, so more than one block is involved.
            let (w, h, rw, rh) = (1280u32, 800u32, 200i32, 3i32);
            let payload: Vec<u8> = (0..(rw as usize * rh as usize * bpp))
                .map(|i| ((i * 17 + i / 3) % 256) as u8)
                .collect();
            let update = Update {
                x: 5,
                y: 7,
                w: rw,
                h: rh,
                stride: rw as u32 * bpp as u32,
                format,
                data: payload,
            };

            let mut fb = Framebuffer::new(w, h);
            let first = fb.set_update(&update).expect("the first applies");
            assert!(
                !first.is_empty(),
                "format {format:#x}: the first update reported no damage, so the \\
                 shadow was never established and the second cannot be tested"
            );

            for round in 2..=3 {
                let again = fb.set_update(&update).expect("the repeat applies");
                assert!(
                    again.is_empty(),
                    "format {format:#x}: applying the same update again reported \
                     {again:?} as damage. Nothing changed, so the shadow already \
                     holds it. On X8R8G8B8 and A8R8G8B8 this is the comparison \\
                     being wrong; on R5G6B5 it is the two-byte prefix shortcut \
                     being taken for a format that expands two bytes into three, \
                     which finds a difference on every pixel of every frame."
                );
                let _ = round;
            }
        }
    }

    /// The "QEMU declined the map" line is said once, not once per update.
    ///
    /// **The line is a diagnostic, and a diagnostic that fires on every update
    /// is not one.** It would be a log line at INFO, on the message path, on a
    /// console doing sixteen updates a second -- which is what the `scanout
    /// applied` line used to be, and the reason that line had to be taken out
    /// of the hot path in the first place. So the count matters, and a count
    /// derived from what the code *intends* to do proves nothing; this counts
    /// calls.
    ///
    /// It also has to fire **at all**. A flag that is initialised to "already
    /// declined" would satisfy a test that only checked the count, and would
    /// silence the one line that says the answer to this question.
    #[test]
    fn declining_the_map_is_said_once_and_not_before_it_is_known() {
        // Not `mut`: `AtomicBool::store` takes `&self`, so the flag is shared
        // rather than owned and nothing here writes through it.
        let listener = ConsoleListener {
            index: 0,
            framebuffer: FramebufferHandle::new(Framebuffer::new(64, 32)),
            cursor: Arc::new(Mutex::new(None)),
            read_only: Arc::new(AtomicBool::new(false)),
            server: Weak::new(),
            // As `register_listener` leaves it, not a literal of its own.
            declined_map: map_not_yet_offered(),
        };

        // Before the map is offered, pixels say nothing: an un-offered map
        // going unused is not news, and `register_listener` leaves the flag set
        // for exactly that.
        assert!(
            !listener.note_map_declined(),
            "an update arrived before the map was even offered, and the diagnostic \
             claimed QEMU declined something we had not asked for"
        );

        // Now offer it, as `Ok(true)` from `set_map_listener` does.
        listener.declined_map.store(false, Ordering::Relaxed);
        let said: Vec<bool> = (0..3).map(|_| listener.note_map_declined()).collect();
        assert_eq!(
            said,
            vec![true, false, false],
            "the first update after the offer has to be the one that says so, and \
             the sixteen a second after it must not be. [true, true, true] means \
             the line is now an INFO line on the message path of a busy console, \
             which is what the scanout line used to be."
        );
    }

    /// The mapped path finds the same damage as the message path.
    ///
    /// **This is the assertion the whole change rests on.** `set_mapped_rect`
    /// applies a rectangle of QEMU's mapping; `set_update` applies the same
    /// rectangle as it arrived in a D-Bus message. If they disagree about what
    /// changed, a client is either sent pixels from the wrong place or loses
    /// damage -- and the two paths being separate code is precisely why.
    ///
    /// So the test does not check the mapped path in isolation. It puts the same
    /// pixels through both and asserts the **framebuffer and the reported damage
    /// are identical**, on a rectangle chosen to be awkward: not at the origin,
    /// covering part of a row, and read out of a mapping whose stride is four
    /// times the rectangle's own row -- the case a stride mistake produces
    /// silently, because the framebuffer still ends up with plausible pixels in
    /// it and nothing anywhere complains.
    ///
    /// It also has to be a *pair* of framebuffers that start equal, brought
    /// there by the same update. The first version of this test handed the
    /// message path the whole surface and the mapped path only the band, and it
    /// failed -- for a reason that had nothing to do with either path, which is
    /// how a test gets to be green for the wrong reasons.
    #[test]
    fn the_mapped_path_finds_the_same_damage_as_the_message_path() {
        const W: u32 = 1280;
        const H: u32 = 400;
        const STRIDE: usize = W as usize * 4;

        // A gradient, which no two rows and no two columns share, so that a
        // pixel read from the wrong place cannot come out the same.
        let gradient = {
            let mut g = vec![0u8; STRIDE * H as usize];
            for y in 0..H as usize {
                for x in 0..W as usize {
                    let o = y * STRIDE + x * 4;
                    g[o] = (x as u8).wrapping_add(y as u8);
                    g[o + 1] = (x as u8).wrapping_add(y as u8).rotate_left(3);
                    g[o + 2] = (y as u8).wrapping_mul(3).wrapping_add(x as u8);
                    // The padding byte is **not** left at zero -- see below.
                    g[o + 3] = (x as u8).wrapping_add(y as u8);
                }
            }
            g
        };

        // The same surface with a band drawn into it, the way a video surface
        // differs from the desktop one around it.
        let (x, y, w, h) = (640u32, 162u32, 320u32, 13u32);
        let mut surface = gradient.clone();
        for row in 0..h as usize {
            for col in 0..w as usize {
                let o = (y as usize + row) * STRIDE + (x as usize + col) * 4;
                surface[o] = 0xff;
                surface[o + 1] = 0x00;
                surface[o + 2] = 0xff;
                // **The padding byte is filled with junk, deliberately.**
                // x8r8g8b8 calls it unused, but QEMU owns the mapping and its
                // fourth byte is whatever its scanout buffer happened to hold.
                // The message path throws it away on every pixel
                // (`pixel_to_xrgb` ends with `dst[3] = 0`) and the mapped path
                // has to throw it away the same way, or the shadow comparison
                // reads junk as changed pixels that no client can see and no
                // encoder will ever send. With a zero here the test cannot tell
                // the two behaviours apart, and the difference is worth encode
                // time on every frame.
                surface[o + 3] = 0x5a;
            }
        }

        // Both framebuffers start from the same state, reached the same way.
        let background = Update {
            x: 0,
            y: 0,
            w: W as i32,
            h: H as i32,
            stride: STRIDE as u32,
            format: PIXMAN_X8R8G8B8,
            data: gradient,
        };
        let mut via_message = Framebuffer::new(W, H);
        via_message
            .set_update(&background)
            .expect("the background applies");
        let mut via_map = Framebuffer::new(W, H);
        via_map
            .set_update(&background)
            .expect("the background applies");
        assert_ne!(
            via_message.data[(y as usize * W as usize + x as usize) * 4],
            0xff,
            "the band is already in the background, so applying it changes nothing and \
             both paths would agree on an empty answer"
        );

        // **Through the message path, in the shape QEMU sends it.**
        //
        // The data is the *rectangle*, not the surface. That is read off the C
        // rather than assumed: `c/display.c`'s `on_update` passes the array to
        // `pixman_image_create_bits(pixman_format, w, h, pixels, stride)`, so
        // row `n` is `data[n * stride ..]` of a `w`-wide image, which is what
        // `set_update`'s `row()` reads. Feeding it a whole surface instead --
        // which the first version of this test did -- makes the message path
        // take column 0 of every row, and it fails.
        let mut packed = Vec::with_capacity(w as usize * 4 * h as usize);
        for row in 0..h as usize {
            let o = (y as usize + row) * STRIDE + x as usize * 4;
            packed.extend_from_slice(&surface[o..o + w as usize * 4]);
        }
        let message_damage = via_message
            .set_update(&Update {
                x: x as i32,
                y: y as i32,
                w: w as i32,
                h: h as i32,
                stride: w * 4,
                format: PIXMAN_X8R8G8B8,
                data: packed,
            })
            .expect("the message update applies");

        // **Through the mapped path**, from the same pixels as QEMU's mapping
        // presents them: whole rows of the surface at the surface's own stride,
        // of which only `w` pixels of each row are the rectangle. **No
        // `to_vec()`** -- the map *is* that surface, and offering it is only
        // worth anything if the pixels never get copied into a message.
        let rect = UpdateMap {
            x: x as i32,
            y: y as i32,
            w: w as i32,
            h: h as i32,
        };
        // Cropped to the rectangle, row by row, which is what the handler hands
        // over and therefore what this has to compare against.
        let mut cropped = Vec::with_capacity(w as usize * 4 * h as usize);
        for row in 0..h as usize {
            let from = (y as usize + row) * STRIDE + x as usize * 4;
            cropped.extend_from_slice(&surface[from..from + w as usize * 4]);
        }
        let map_damage = via_map
            .set_mapped_rect(PIXMAN_X8R8G8B8, &cropped, rect)
            .expect("the mapped rectangle applies");

        // Report the first differing byte as a pixel. `assert_eq!` on two
        // two-megabyte buffers prints a wall of numbers in which the one number
        // that matters cannot be found.
        if let Some(at) = via_map
            .data
            .iter()
            .zip(via_message.data.iter())
            .position(|(a, b)| a != b)
        {
            panic!(
                "the mapped path left a different framebuffer than the message path. \
                 First difference at byte {at}, pixel ({}, {y}): mapped {:?}, message {:?}. \
                 Both applied the same {w}x{h} at {x},{y}, so one of them read the wrong bytes.",
                (at / 4) % W as usize,
                &via_map.data[at..at + 4],
                &via_message.data[at..at + 4],
            );
        }

        // Same damage, same place. The comparison is what the damage *is*, so
        // equal framebuffers with different damage rectangles is a real fault
        // and not a cosmetic one: a client would be sent the right pixels for
        // the wrong region, or none of them.
        let (mut a, mut b) = (map_damage.clone(), message_damage.clone());
        a.sort_by_key(|r| (r.top, r.left));
        b.sort_by_key(|r| (r.top, r.left));
        assert_eq!(
            a, b,
            "the two paths found the same pixels at different places: mapped \
             {map_damage:?}, message {message_damage:?}"
        );
        assert!(
            !b.is_empty(),
            "a band drawn onto a gradient reported no damage, so every comparison \
             above was between two wrong answers"
        );
        // And the damage covers the band, rather than being merely non-empty.
        for rect in &b {
            assert_eq!(u32::from(rect.top), y, "damage reported outside the band");
            assert_eq!(u32::from(rect.left), x, "damage reported outside the band");
        }
    }

    /// The mapped path and the message path agree about what byte 3 holds.
    ///
    /// **Written after finding that they did not, on `PIXMAN_A8R8G8B8`, and after
    /// the test above was found not to be able to see it.**
    ///
    /// That test is the right test for its question and it passes. It runs on
    /// `PIXMAN_X8R8G8B8`, and on that format all three apply paths zero byte 3, so
    /// they agree by construction and a disagreement anywhere else is outside
    /// anything it looks at. Widening it to a second format would have been the
    /// obvious repair and would have been wrong: its payload fills the fourth byte
    /// with junk on purpose, to pin the padding rule, and A8R8G8B8's fourth byte
    /// is the alpha -- so the same payload is a *legitimate* difference on that
    /// format and widening the test would have made it fail for a reason that has
    /// nothing to do with the fault. Two different questions, two different tests.
    ///
    /// This one asks the question that actually bites, which is not "do the two
    /// produce the same bytes" but **"do they take turns disagreeing"**. The fault
    /// was not that the paths differed; it was that the damage comparison reads
    /// four bytes while the encoder reads three, and the shadow is written from
    /// whatever the last path put there. So each path invalidated the other's
    /// shadow, and a guest alternating between them reported a full rectangle of
    /// damage on every frame for pixels that never changed:
    ///
    /// ```text
    ///   frame 1, mapped,  first time   2048 px damaged   correct
    ///   frame 2, message, SAME bytes    2048 px damaged   WRONG
    ///   frame 3, message, SAME bytes       0 px damaged
    ///   frame 4, mapped,  SAME bytes    2048 px damaged   WRONG
    /// ```
    ///
    /// **The payload's RGB is constant and only the alpha varies**, and that is
    /// what makes the test able to fail. With a constant fourth byte the two rules
    /// agree on the answer and every assertion below passes against the bug; with
    /// a varying one, a path that keeps the alpha is caught on the very next
    /// frame. Asserting that frames 2 and 3 are both silent is the whole property:
    /// frame 2 is silent only if the mapped path did not leave the alpha behind,
    /// and frame 3 is silent only if the shadow was written at all.
    ///
    /// The first frame is asserted too, and not as busywork. A "fix" that made the
    /// comparison ignore byte 3 entirely would pass frames 2 through 4 and produce
    /// a server that reports no damage the first time anything is drawn.
    #[test]
    fn a_mapped_update_and_a_message_update_agree_about_the_fourth_byte() {
        for format in [PIXMAN_X8R8G8B8, PIXMAN_A8R8G8B8] {
            const W: u32 = 64;
            const H: u32 = 32;
            let area = (W * H) as usize;

            // RGB constant; only the fourth byte differs between pixels, and for
            // A8R8G8B8 that byte is the alpha, which is a colour no client of ours
            // will ever be sent.
            let data: Vec<u8> = (0..area)
                .flat_map(|i| [0x20u8, 0x40, 0x60, if i % 2 == 0 { 0x00 } else { 0xff }])
                .collect();
            let rect = UpdateMap { x: 0, y: 0, w: W as i32, h: H as i32 };
            let as_update = |data: &[u8]| Update {
                x: 0,
                y: 0,
                w: W as i32,
                h: H as i32,
                stride: W * 4,
                format,
                data: data.to_vec(),
            };
            let damaged = |rects: &[Rect]| -> usize {
                rects.iter().map(|r| r.width as usize * r.height as usize).sum()
            };

            let mut fb = Framebuffer::new(W, H);
            let first = fb
                .set_mapped_rect(format, &data, rect)
                .expect("the first mapped rectangle applies");
            let second = fb
                .set_update(&as_update(&data))
                .expect("the message update applies");
            let third = fb
                .set_update(&as_update(&data))
                .expect("the second message update applies");
            let fourth = fb
                .set_mapped_rect(format, &data, rect)
                .expect("the second mapped rectangle applies");

            assert_eq!(
                damaged(&first),
                area,
                "format {format:#x}: the first draw of a {area}-pixel rectangle \
                 reported no damage, so nothing would be sent to the client at all"
            );
            for (n, rects) in [("the message update right after it", &second), ("a repeat", &third)] {
                assert_eq!(
                    damaged(rects),
                    0,
                    "format {format:#x}: {n} reported {} pixels as damaged, out of \
                     {area}, having been sent the identical bytes to identical \
                     positions. One apply path is leaving something in the fourth \
                     byte that the other clears, so each invalidates the other's \
                     shadow and every frame re-encodes a rectangle that did not \
                     change.",
                    damaged(rects)
                );
            }
            assert_eq!(
                damaged(&fourth),
                0,
                "format {format:#x}: a mapped rectangle reapplied with identical \
                 bytes reported {} pixels as damaged. Byte 3 of the framebuffer \
                 disagrees with the shadow after an update that changed nothing.",
                damaged(&fourth)
            );
        }
    }

    /// A mapped rectangle that does not fit the surface is refused, not clamped.
    ///
    /// The message path validates its geometry against the message's own length,
    /// and there is a test for that. **The mapped path has no length to check
    /// against**: `UpdateMap` is four integers, and the only authority on how far
    /// the rectangle reaches is the mapping's `stride` and its length. A
    /// rectangle that does not fit is dropped rather than clamped, because
    /// clamping reads a different part of the surface than QEMU said it had
    /// drawn and hands it to the client as though it were current.
    #[test]
    fn a_mapped_rectangle_outside_the_surface_is_refused() {
        let mut fb = Framebuffer::new(64, 32);
        let stride = 64 * 4;
        let map = vec![0u8; stride * 32];

        let rect = |x: i32, y: i32, w: i32, h: i32| UpdateMap { x, y, w, h };
        for (x, y, w, h) in [(60i32, 0, 8, 8), (0, 28, 8, 8)] {
            assert!(
                fb.set_mapped_rect(PIXMAN_X8R8G8B8, &map, rect(x, y, w, h)).is_err(),
                "a {w}x{h} rectangle at {x},{y} runs off a 64x32 surface and was accepted"
            );
        }
        // A rectangle exactly filling the surface is not "outside" it. The
        // whole surface is its own rows, so no cropping is needed.
        assert!(
            fb.set_mapped_rect(PIXMAN_X8R8G8B8, &map, rect(0, 0, 64, 32)).is_ok(),
            "a rectangle exactly filling the surface was refused"
        );
        // **An empty rectangle is refused, and this one is here because the
        // bounds check does not catch it.** `x + 0 > width` is false for every
        // `x` that fits, so a zero-width rectangle walks through a check that
        // looks like it is doing the work and then does nothing at all: no
        // damage, no notification, no error. Found by this test, not by reading
        // the code.
        assert!(
            fb.set_mapped_rect(PIXMAN_X8R8G8B8, &map, rect(0, 0, 0, 8)).is_err(),
            "a zero-width mapped rectangle was accepted"
        );
        assert!(
            fb.set_mapped_rect(PIXMAN_X8R8G8B8, &map, rect(0, 0, 8, 0)).is_err(),
            "a zero-height mapped rectangle was accepted"
        );
        // And rows that are not there are refused rather than read past.
        assert!(
            fb.set_mapped_rect(PIXMAN_X8R8G8B8, &map[..stride], rect(0, 0, 64, 8)).is_err(),
            "one row of bytes was accepted as an eight-row rectangle"
        );
        // **Negative coordinates are refused, not wrapped.** `as u32` turns
        // `-1` into `4294967295`; `x + w` then either overflows -- a panic under
        // `debug_assertions` and a silently meaningless comparison without
        // them, so the test would pass in one build and fail in the other for a
        // reason that has nothing to do with the code. This is the case that
        // makes a bounds check look like it is working while doing nothing.
        for bad in [rect(-1, 0, 8, 8), rect(0, -1, 8, 8), rect(-1, -1, -8, -8)] {
            assert!(
                fb.set_mapped_rect(PIXMAN_X8R8G8B8, &map, bad).is_err(),
                "a rectangle at {},{} of {}x{} was accepted",
                bad.x,
                bad.y,
                bad.w,
                bad.h
            );
        }
    }

    /// A console the size of a real one, applied through the listener, stays
    /// cheap — and cheap *whether or not anything is logging*.
    ///
    /// This is a test about cost, and it exists because of a bug that no
    /// functional test could see. The `scanout applied` and `update applied` log
    /// lines used to report what the surface *looked like*: how many distinct
    /// colours it held, how much of it the commonest colour covered, a coarse
    /// grid of bands. Those were the measurements that found the blank screen,
    /// and they were computed on every D-Bus message — two million `HashSet`
    /// inserts across a 1280x800 console, measured at 35 ms and 20 ms, on the
    /// task that applies the frame. And they were computed whether or not
    /// anything was logging, because a function call used as a tracing argument
    /// is evaluated *before* the macro checks the level. `tracing` only defers
    /// formatting, not the argument.
    ///
    /// So the console-listener task was saturated, the apply was queued behind
    /// it, and the client was shown a stale picture — while the log line that
    /// should have explained it was itself the cause. The symptom was a viewer
    /// that could see the desktop and could not make it move, the server at
    /// 100% CPU, and nothing in the log to account for it.
    ///
    /// The handler is called directly rather than through a bus, a client or a
    /// socket, because the point is the handler and everything else is noise:
    /// an earlier version of this test drove a real client and timed whole
    /// frames, and the 55 ms of the bug sat inside 100 ms of legitimate work,
    /// so it passed with the instrumentation in place. Measuring the thing the
    /// bug was in is the only way to see it.
    ///
    /// **Run this in release.** It is `#[ignore]`d because the measurement is
    /// only meaningful optimised, and that is a property of the bug rather than
    /// an inconvenience: both the legitimate work and the work that was added
    /// are proportional to the pixel count, at one operation per pixel each. In
    /// a debug build `pixel_to_xrgb` costs about 40 ns and a `HashSet` insert
    /// about 27, so the bug is 2.4x the real work and no console size or bound
    /// can tell them apart without flaking. In release the same two cost 1 ns
    /// and 27 ns, and the bug is 56x — which is why the assertion below is
    /// calibrated against the copy this build actually performs.
    ///
    /// ```sh
    /// cargo test -p qemu-vnc --release --lib applying_a_full_size
    /// ```
    #[test]
    #[ignore = "needs an optimised build to separate the two costs; see above"]
    fn applying_a_full_size_console_does_not_inspect_it() {
        /// The large console, and the small one the marginal cost is taken
        /// between. Sixteen times fewer pixels, so the fixed costs — allocating
        /// a surface, the format check, the log statement — cancel out and what
        /// is left is the cost of a pixel.
        const W: u16 = 1280;
        const H: u16 = 800;
        const W0: u16 = 320;
        const H0: u16 = 200;
        const ROUNDS: u32 = 5;
        /// The most a single pixel may cost, in nanoseconds.
        ///
        /// The apply calls `pixel_to_xrgb` once per pixel, which is a bounds
        /// check and four stores: about a nanosecond optimised. The content
        /// measurement hashed every pixel twice, once into a colour set and once
        /// into the per-band sets, at roughly fifty nanoseconds a hash. So the
        /// measurement is a pixel costing *fifty times* what it should, and any
        /// bound between the two finds it.
        ///
        /// Total cost cannot make this argument and an earlier version of the
        /// test tried: both are one operation per pixel, so they are the same
        /// order and a bound that separates them in a release build is a bound
        /// that flakes in a debug one, where `pixel_to_xrgb` alone costs forty.
        /// The *marginal* cost per pixel is a different quantity, and this is it.
        const MAX_NANOS_PER_PIXEL: f64 = 8.0;

        /// Time `rounds` applications of a `w` by `h` console, through the
        /// listener, with a dangling server so `notify` does nothing.
        fn time(listener: &mut ConsoleListener, w: u16, h: u16, rounds: u32) -> std::time::Duration {
            let mut data = Vec::with_capacity(usize::from(w) * usize::from(h) * 4);
            for i in 0..(usize::from(w) * usize::from(h)) {
                data.extend_from_slice(&[(i & 0xff) as u8, 0, 0, 0]);
            }
            let started = std::time::Instant::now();
            for _ in 0..rounds {
                let scanout = Scanout {
                    width: u32::from(w),
                    height: u32::from(h),
                    stride: u32::from(w) * 4,
                    format: PIXMAN_X8R8G8B8,
                    data: data.clone(),
                };
                async_io::block_on(listener.scanout(scanout));
            }
            started.elapsed()
        }

        let mut listener = ConsoleListener {
            index: 0,
            framebuffer: FramebufferHandle::new(Framebuffer::new(u32::from(W), u32::from(H))),
            cursor: Arc::new(Mutex::new(None)),
            read_only: Arc::new(AtomicBool::new(false)),
            server: Weak::new(),
            declined_map: map_not_yet_offered(),
        };
        // Small first, so the large one resizes rather than being allocated at
        // full size each time.
        time(&mut listener, W0, H0, ROUNDS);
        let small = time(&mut listener, W0, H0, ROUNDS);
        let large = time(&mut listener, W, H, ROUNDS);

        let pixels = |w: u16, h: u16| f64::from(u32::from(w) * u32::from(h)) * f64::from(ROUNDS);
        let per_pixel = (large.as_secs_f64() - small.as_secs_f64())
            / (pixels(W, H) - pixels(W0, H0));
        let nanos = per_pixel * 1e9;
        assert!(
            nanos < MAX_NANOS_PER_PIXEL,
            "a pixel costs {nanos:.1} ns to apply, over the {MAX_NANOS_PER_PIXEL} ns \
             a conversion and four stores should take. Anything proportional to \
             the pixel count a *second* time is inspecting the surface, and \
             because it would be written as a tracing argument it would run \
             whether or not anyone is logging. ({small:.2?} for {W0}x{H0}, \
             {large:.2?} for {W}x{H}, {ROUNDS} rounds each)"
        );
    }
}
