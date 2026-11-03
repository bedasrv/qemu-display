//! The RFB pixel encodings we can send, and the policy that picks between
//! them.
//!
//! The vendored server can only write a raw rectangle (and the copy
//! rectangle, cursor and desktop size pseudo-encodings): everything else is
//! compressed data it does not produce. This module is the other half of that
//! contract, it turns a rectangle of the frame buffer into the payload of a
//! `FramebufferUpdate`.
//!
//! The encoders are the ones QEMU's VNC server offers, minus the obsolete
//! RRE/CoRRE (TinyVNC only):
//!
//! * [`Codec::Raw`]: no compression, the baseline every client understands.
//! * [`Codec::Zrle`]: the modern default, palette or solid tiles compressed
//!   with zlib. This is what most clients ask for first.
//! * [`Codec::Zlib`]: the older hextile encoding, cheap to produce and still
//!   understood by everything.
//! * [`Codec::Tight`]: solid fill and palettes, and — with the `lossy`
//!   feature — JPEG. Tight also has a gradient filter, which is *not*
//!   implemented yet, so the policy only picks Tight for the big rectangles,
//!   and prefers ZRLE when a client supports both.
//!
//! Each encoder keeps its own persistent zlib stream, like QEMU does, so the
//! compression of a connection is not restarted for every rectangle.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use flate2::{Compress, Compression, FlushCompress};

use super::{Encoding, PixelFormat, Rect};

/// The size of a ZRLE tile.
const ZRLE_TILE: u16 = 64;
/// The size of a hextile tile.
const HEXTILE_TILE: u16 = 16;
/// The largest palette a ZRLE tile can have.
const MAX_ZRLE_PALETTE: usize = 16;
/// Slots in the tile builder's colour lookup. Four times the palette, so the
/// load factor is a quarter and a probe almost always lands on the first slot.
const ZRLE_LOOKUP_SLOTS: usize = MAX_ZRLE_PALETTE * 4;
/// A slot holding no palette entry.
const ZRLE_LOOKUP_EMPTY: u8 = u8::MAX;
/// Below this many pixels, the zlib header of a rectangle costs more than the
/// compression saves.
const MIN_COMPRESSED_PIXELS: u32 = 16;
/// A rectangle has to be at least this big for Tight to be worth it.
const MIN_TIGHT_RECT: u16 = 64;

/// The deflate level used until a client says otherwise with the -254
/// `CompressionLevel` pseudo-encoding.
///
/// **A deliberate divergence from QEMU, and the reason for it.** QEMU's
/// `set_encodings` defaults `worker->tight.compression` to 9, and
/// `vnc_zlib_stop` passes it straight to `deflateInit2`, so QEMU compresses at
/// level 9 until told otherwise. Level 9 is a defensible default for the
/// content QEMU mostly serves — a desktop is mostly flat colour, so the
/// expensive search over nine passes finds very little and costs little — and
/// it is a poor one for content that is not, where it is several times the
/// time for a few percent of size.
///
/// 6 is flate2's default, so it is what this crate used before the -254 level
/// was honoured at all. Matching QEMU's 9 here would make every client that
/// does not send the pseudo-encoding *slower* than it is today, which is not
/// what a parity argument should be for. The mechanism is QEMU's; the default
/// is ours, and a client that cares has a way to say so.
const DEFAULT_DEFLATE_LEVEL: u32 = 6;

/// The level the **ZRLE** stream uses, which is 0 and is not `DEFAULT_DEFLATE_LEVEL`.
///
/// **This is a deliberate divergence from QEMU's behaviour, and it is the
/// opposite direction to the one just fixed.** QEMU's ZRLE is hardcoded to
/// `Z_DEFAULT_COMPRESSION` at `vnc-enc-zrle.c:339`, which zlib reads as level 6;
/// a client's `-254` does not reach it. Matching that was right for correctness
/// and wrong for the thing this port is for, and the trade is measured.
///
/// On the production video band, 1280x308, at every level
/// (`what_deflate_costs_and_what_it_buys`):
///
/// ```text
/// level   ns/px   bytes/px   vs level 6
///     0     5.4     3.001       2.24x
///     2    30.1     1.407       1.05x
///     6    37.8     1.342       1.00x   <- what QEMU serves
///     9    57.2     1.284       0.96x
/// ```
///
/// Level 0 is **seven times cheaper** than 6 and costs 2.24x the bytes. The
/// production log runs at 18 updates a second, which is 9.0 MB/s at the level
/// this crate was serving and 14.0 MB/s at level 0 — both carried by any LAN,
/// and the log's viewer is at 10.10.20.150 on one.
///
/// Against the encode's 41.5 ns/px on that log: deflate is 19.6 of it and at
/// level 0 is about 1.5, so the encode goes to roughly 23 ns/px, **19.4% of a
/// core to about 11%, and the process from 34.4% to about 26%.**
///
/// **What this does not do is close the gap.** 26% against a reference measured
/// at 6.32% is still 4.1x. It is the largest single lever found and it is not
/// sufficient, and saying so here is the point: the remaining cost is an
/// out-of-process listener's, not the compressor's.
///
/// **Why 0 rather than 1 or 2.** Level 1 is 18.5 ns/px for 1.587 bytes/px, which
/// is 3.4x the CPU of level 0 for a 1.9x bandwidth saving — a much worse trade
/// than 0's. Level 2 is what this crate was serving and is 5.6x level 0's cost.
/// The curve is flat in bytes from 4 to 9 and steep in time, so the bottom of
/// it is the only place worth sitting.
///
/// **The stream is still a zlib stream.** Level 0 is deflate's store mode, not
/// no deflate: the output is a valid deflate stream with stored blocks, and
/// every client inflates it exactly as it inflates level 6. Nothing about the
/// protocol changes, and a client's `-254` still reaches Tight and hextile.
const ZRLE_DEFLATE_LEVEL: u32 = 0;

/// The level Tight's **raw pixel data** is compressed at, which is 0.
///
/// **The same deliberate divergence as [`ZRLE_DEFLATE_LEVEL`], for the same
/// reason and with the same caveat: this is not what QEMU does.** QEMU reads
/// this number out of `tight_conf[tight.compression].raw_zlib_level`, so a
/// client asking for Tight level 2 gets its full-colour rectangles deflated at 2
/// and one asking for 9 gets 9.
///
/// The measurement is on the production band, and it is the same one that chose
/// level 0 for ZRLE: at 2 this costs **30.1 ns a pixel against 3.4**, which is
/// about 16 points of a core, to buy 3.0 bytes a pixel instead of 3.0. The bytes
/// are the same number because deflate's store mode is three bytes a pixel either
/// way -- only the *search* is what level 2 adds.
///
/// So the split is deliberate and it is the one the protocol actually makes:
/// **the encoding comes from the client, because that is what the protocol says
/// `SetEncodings` means; the compression level is ours, because that is a
/// CPU-for-bandwidth trade nobody obliged us to make QEMU's way.**
const TIGHT_BASIC_DEFLATE_LEVEL: u32 = 0;

/// The lossy JPEG encoder, which is only compiled with the `lossy` feature.
#[cfg(feature = "lossy")]
type Lossy = Option<Jpeg>;
#[cfg(not(feature = "lossy"))]
type Lossy = Option<()>;

/// The lossy JPEG encoder, which is only compiled with the `lossy` feature.
#[cfg(feature = "lossy")]
#[derive(Debug)]
struct Jpeg {
    /// The quality of the JPEG image, as QEMU's `-vnc jpeg=<quality>`.
    quality: u8,
}

/// A rectangle of a frame buffer, in the pixel format of a client.
///
/// The coordinates are **relative to the rectangle**, not to the frame
/// buffer: a rectangle of a strided frame buffer is not a sub-slice, and
/// keeping the two apart is what stops the encoders from reading the wrong
/// row.
#[derive(Clone, Copy)]
pub struct RectPixels<'a> {
    data: &'a [u8],
    format: &'a PixelFormat,
    /// The offset of the first byte of the rectangle, in the frame buffer.
    offset: usize,
    /// The distance between two rows of the frame buffer.
    stride: usize,
}

impl<'a> RectPixels<'a> {
    /// Extract a rectangle of a frame buffer.
    pub fn new(data: &'a [u8], format: &'a PixelFormat, stride: usize, rect: Rect) -> Self {
        Self {
            data,
            format,
            offset: rect.top as usize * stride + rect.left as usize * bpp(format),
            stride,
        }
    }

    /// The size of a pixel, in bytes.
    fn bpp(&self) -> usize {
        bpp(self.format)
    }

    /// The byte offset of one pixel, relative to the frame buffer.
    ///
    /// Exposed because a row of a ZRLE raw tile is addressed once and walked,
    /// rather than four thousand times through `raw`. Both compute the same
    /// thing: `raw` is `&data[offset_of(x, y)..][..bpp]`.
    fn offset_of(&self, x: u16, y: u16) -> usize {
        self.offset + usize::from(y) * self.stride + usize::from(x) * self.bpp()
    }

    /// The raw bytes of a pixel, in the client pixel format. `x` and `y` are
    /// relative to the rectangle.
    fn raw(&self, x: u16, y: u16) -> &'a [u8] {
        let o = self.offset_of(x, y);
        &self.data[o..o + self.bpp()]
    }

    /// The colour of a pixel, as the 3 bytes RGB the Tight and ZRLE
    /// encodings use, or `None` for a format we can not read.
    fn rgb(&self, x: u16, y: u16) -> Option<[u8; 3]> {
        if !self.format.true_colour || !matches!(self.format.bits_per_pixel, 16 | 32) {
            return None;
        }
        let raw = self.raw(x, y);
        let format = self.format;
        let mut value = 0u32;
        for (i, byte) in raw.iter().enumerate() {
            if format.big_endian {
                value = (value << 8) | *byte as u32;
            } else {
                value |= (*byte as u32) << (8 * i);
            }
        }
        let scale = |value: u32, max: u16| -> u8 {
            if max == 255 || max == 0 {
                value as u8
            } else {
                (value * 255 / max as u32) as u8
            }
        };
        Some([
            scale(
                (value >> format.red_shift) & format.red_max as u32,
                format.red_max,
            ),
            scale(
                (value >> format.green_shift) & format.green_max as u32,
                format.green_max,
            ),
            scale(
                (value >> format.blue_shift) & format.blue_max as u32,
                format.blue_max,
            ),
        ])
    }

    /// Whether every pixel of the given area, relative to the rectangle, has
    /// the same colour, and what it is.
    fn is_uniform(&self, x0: u16, y0: u16, width: u16, height: u16) -> Option<[u8; 3]> {
        let first = self.rgb(x0, y0)?;
        for y in y0..y0 + height {
            for x in x0..x0 + width {
                if (x, y) != (x0, y0) && self.rgb(x, y) != Some(first) {
                    return None;
                }
            }
        }
        Some(first)
    }
}

/// The size of a pixel, in bytes.
fn bpp(format: &PixelFormat) -> usize {
    (format.bits_per_pixel as usize).div_ceil(8)
}

/// How many bits one palette index takes in a packed ZRLE tile.
///
/// QEMU's table, indexed by `palette size - 1`:
/// `{ 0, 1, 2, 2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 }` — one bit for two
/// colours, two for three or four, four for five to sixteen. Enough to address
/// every colour in the palette, and no more.
/// A slot for `pixel` in a [`ZRLE_LOOKUP_SLOTS`]-entry table.
///
/// Multiply-shift, because a tile's colours are usually *close together* — a
/// gradient, a shaded panel, a run of near-identical antialiased text — and a
/// plain `value ^ (value >> 16)` maps neighbours to neighbouring slots only
/// when the difference is in the high half, which for little-endian 32-bit
/// pixels means the red channel. Fibonacci hashing scatters them whatever the
/// layout, and costs one multiply.
fn zrle_slot(pixel: &[u8]) -> usize {
    // Two to four bytes, little- or big-endian, padded to a word. Loading them
    // one at a time would be four bounds checks; this is one.
    let mut word = [0u8; 4];
    word[..pixel.len()].copy_from_slice(pixel);
    let value = u32::from_le_bytes(word);
    (value.wrapping_mul(2_654_435_761) >> (32 - ZRLE_LOOKUP_SLOTS.trailing_zeros())) as usize
        & (ZRLE_LOOKUP_SLOTS - 1)
}

fn packed_bits(palette_size: usize) -> u8 {
    match palette_size {
        0 | 1 => 0,
        2 => 1,
        3..=4 => 2,
        _ => 4,
    }
}

/// The bytes of a ZRLE palette entry for one pixel in `format`.
///
/// A palette entry is a pixel in the client's format, with the two exceptions
/// the format allows: 16 bits per pixel is two bytes rather than three, and 32
/// bits per pixel at depth 24 is three, taken from the end that holds the
/// colour rather than the end that is padding.
fn palette_entry<'a>(pixel: &'a [u8], format: &PixelFormat) -> &'a [u8] {
    let n = zrle_pixel_len(format);
    // Which three of the four is the padding depends on the byte order: the
    // colour sits in the low three bytes of a little-endian pixel and the high
    // three of a big-endian one.
    if n < bpp(format) && format.big_endian {
        &pixel[bpp(format) - n..]
    } else {
        &pixel[..n]
    }
}

/// How many bytes one pixel takes in a ZRLE rectangle.
///
/// This is note 1 of the RFB specification, and QEMU implements it as four
/// separate encoders rather than one width: for a client whose format fits in
/// three bytes it includes `ZRLE_COMPACT_PIXEL`, which redefines
/// `ZRLE_WRITE_PIXEL` as `zrle_write_u24a` and `ZRLE_BPP_OUT` as 24. Every
/// pixel it writes is therefore three bytes — the palette entries, the solid
/// tile's colour, and the raw tile's pixels alike.
///
/// Getting this wrong for a 32-bit client at depth 24 writes a byte too many
/// per pixel, which puts every following field out of step, and a client that
/// cannot follow the tile stream shows nothing at all.
fn zrle_pixel_len(format: &PixelFormat) -> usize {
    let compact = format.depth == 24
        && format.red_max == 255
        && format.green_max == 255
        && format.blue_max == 255;
    match (bpp(format), format.depth) {
        // 16 bits per pixel is two bytes whatever the depth.
        (2, _) => 2,
        // Three bytes wherever the three components are eight bits wide, which
        // covers 8bpp true colour, 24bpp, and 32bpp at depth 24.
        (_, _) if compact => 3,
        // Anything else: the whole pixel.
        _ => bpp(format),
    }
}

/// The Tight constants, from QEMU's `ui/vnc-enc-tight.h`, which is the file
/// that documents the whole encoding.
mod tight {
    /// One pixel fills the rectangle, and nothing is compressed.
    pub const FILL: u8 = 0x08;
    /// A filter byte follows the control byte.
    pub const EXPLICIT_FILTER: u8 = 0x04;
    /// The filter that indexes a palette.
    pub const FILTER_PALETTE: u8 = 0x01;
    /// Which of the four zlib streams the indexes are compressed on. QEMU
    /// uses 2, and the decoder reads it out of the control byte, so it has to
    /// be 2.
    pub const STREAM_INDEX: u8 = 0x02;
    /// Filtered data below this many bytes is sent uncompressed and without a
    /// size in front of it.
    pub const MIN_TO_COMPRESS: usize = 12;

    /// QEMU's `tight_conf[]`, verbatim from `ui/vnc-enc-tight.c:62`.
    ///
    /// **A client's `-254` level is an index into this, not a deflate level.**
    /// `set_encodings` writes the number to `vc->worker.tight.compression`
    /// (`vnc.c:2195`) and every zlib level Tight uses is read out of the row it
    /// indexes — `raw_zlib_level` for raw pixel data, `idx_zlib_level` for the
    /// palette's indexes, `mono_zlib_level` for the two-colour case,
    /// `gradient_zlib_level` for a filtered rectangle.
    ///
    /// This port treated the client's number as *the* deflate level, which is
    /// right at Tight level 2 (`raw_zlib_level` is 2 there, by coincidence) and
    /// wrong at eight of the other nine. At level 9 the indexes should go out at
    /// 9 and were going out at the number the client sent; at level 0 everything
    /// is stored and this port compressed anyway.
    ///
    /// Only the columns this port's Tight can use are transcribed — it
    /// implements the fill and palette sub-encodings and not the gradient or
    /// full-colour ones, so `gradient_*` and `jpeg_*` have nothing to configure.
    /// The rest of the row is left out rather than filled with zeros, because a
    /// zero there would read as "never" when QEMU means "always" for several of
    /// them and the difference is not obvious from the number.
    pub struct Conf {
        /// Largest rectangle QEMU will put in one Tight rectangle, in pixels,
        /// before splitting. `tight_send_framebuffer_update` splits by this
        /// divided by `max_rect_width`.
        ///
        /// **Transcribed but not yet used.** This port sends one Tight rectangle
        /// for one rectangle of damage and declines anything wider than 2048,
        /// rather than splitting as `tight_send_framebuffer_update` does. At
        /// Tight level 2 QEMU would cut a 1280x308 band into 65 rectangles of
        /// 256x24. Recorded rather than dropped so the table is complete against
        /// the C and the gap is visible, instead of the row quietly disagreeing
        /// with QEMU where nobody could see it.
        #[allow(dead_code)]
        pub max_rect_size: u32,
        /// The width it splits to. See `max_rect_size`.
        #[allow(dead_code)]
        pub max_rect_width: u32,
        /// A rectangle smaller than this is not worth the sub-encoding's header.
        /// See `max_rect_size`.
        #[allow(dead_code)]
        pub mono_min_rect_size: u32,
        /// Deflate level for the palette's indexes.
        pub idx_zlib_level: u32,
        /// Deflate level for a two-colour rectangle's bits.
        ///
        /// **Equal to `idx_zlib_level` in all ten rows**, which is why the index
        /// stream is built once at that level and serves both. Checked by
        /// `tight_levels_come_from_qemus_table_and_not_from_the_clients_number`.
        #[allow(dead_code)]
        pub mono_zlib_level: u32,
        /// Deflate level for raw pixel data.
        ///
        /// **Transcribed but not used**: this port's Tight implements the fill and
        /// palette sub-encodings, and `send_full_color_rect` -- the one that reads
        /// this column -- is not implemented. See `max_rect_size` for the other
        /// columns of the same kind.
        #[allow(dead_code)]
        pub raw_zlib_level: u32,
    }

    pub const CONF: [Conf; 10] = [
        Conf { max_rect_size: 512,    max_rect_width: 32,   mono_min_rect_size: 6,  idx_zlib_level: 0, mono_zlib_level: 0, raw_zlib_level: 0 },
        Conf { max_rect_size: 2048,   max_rect_width: 128,  mono_min_rect_size: 6,  idx_zlib_level: 1, mono_zlib_level: 1, raw_zlib_level: 1 },
        Conf { max_rect_size: 6144,   max_rect_width: 256,  mono_min_rect_size: 8,  idx_zlib_level: 3, mono_zlib_level: 3, raw_zlib_level: 2 },
        Conf { max_rect_size: 10240,  max_rect_width: 1024, mono_min_rect_size: 12, idx_zlib_level: 5, mono_zlib_level: 5, raw_zlib_level: 3 },
        Conf { max_rect_size: 16384,  max_rect_width: 2048, mono_min_rect_size: 12, idx_zlib_level: 6, mono_zlib_level: 6, raw_zlib_level: 4 },
        Conf { max_rect_size: 32768,  max_rect_width: 2048, mono_min_rect_size: 12, idx_zlib_level: 7, mono_zlib_level: 7, raw_zlib_level: 5 },
        Conf { max_rect_size: 65536,  max_rect_width: 2048, mono_min_rect_size: 16, idx_zlib_level: 7, mono_zlib_level: 7, raw_zlib_level: 6 },
        Conf { max_rect_size: 65536,  max_rect_width: 2048, mono_min_rect_size: 16, idx_zlib_level: 8, mono_zlib_level: 8, raw_zlib_level: 7 },
        Conf { max_rect_size: 65536,  max_rect_width: 2048, mono_min_rect_size: 32, idx_zlib_level: 9, mono_zlib_level: 9, raw_zlib_level: 8 },
        Conf { max_rect_size: 65536,  max_rect_width: 2048, mono_min_rect_size: 32, idx_zlib_level: 9, mono_zlib_level: 9, raw_zlib_level: 9 },
    ];

    /// The row a client's `-254` selects, clamped to the table.
    pub fn conf(level: u32) -> &'static Conf {
        &CONF[(level as usize).min(CONF.len() - 1)]
    }
    /// Note 4: no Tight rectangle may be wider than this, and a wider one has
    /// to be split before it is encoded.
    pub const MAX_WIDTH: u16 = 2048;
}

/// How wide one pixel is in the Tight encoding.
///
/// The header's note 1: at depth 24 with all three components eight bits wide
/// a pixel is three bytes in red, green, blue order whatever the client's own
/// byte order is, and that applies to palette entries as well. Everywhere else
/// it is the client's own pixel.
fn tight_pixel_len(format: &PixelFormat) -> usize {
    // QEMU's condition, which is on the *maxima* and not on the depth: a
    // 32-bit client whose three components are all eight bits wide gets three
    // bytes whatever its depth field says.
    let eight_bit_components =
        format.red_max == 255 && format.green_max == 255 && format.blue_max == 255;
    if bpp(format) == 4 && eight_bit_components {
        3
    } else {
        bpp(format)
    }
}

/// Append one Tight pixel of `len` bytes: the red, green, blue triple when the
/// format gets the compact form, and otherwise the client's own pixel.
fn tight_pixel(out: &mut Vec<u8>, rgb: &[u8; 3], pixel: &[u8], len: usize) {
    if len == 3 {
        out.extend_from_slice(rgb);
    } else {
        out.extend_from_slice(&pixel[..len]);
    }
}

/// Append a length in the "compact" form Tight uses: one, two or three bytes,
/// seven bits each with a continuation bit, the first byte least significant.
/// Read back what [`compact_size`] wrote: the value and how many bytes it took.
///
/// The inverse of `compact_size`, and used by a test that checks the framing from
/// the other end -- writing a length and then never reading it is how a rectangle
/// ends up describing the wrong number of bytes without anything noticing.
#[cfg(test)]
fn read_compact(bytes: &[u8]) -> (usize, usize) {
    // The inverse of `compact_size`, and so bounded by the same three bytes: the
    // last one is a whole byte with no continuation bit, which is what stops the
    // loop. Reading a fourth would be reading past the field, which is exactly
    // the mistake the four-byte writer made from the other direction.
    // **The width is decided by the first two bytes, and the third is read
    // regardless.** Not a "read while the top bit is clear" loop, which is the
    // mistake the writer made and which the reader inherited: at the very top of
    // the field, 0x3F_FFFF, QEMU's third byte is `(len >> 14) & 0xFF` = 0xFF, whose
    // top bit is set, so a loop keyed on that bit asks for a fourth byte that
    // belongs to the payload.
    //
    // A real decoder does not loop. It reads one byte, and if the top bit is set
    // reads a second, and if *that* top bit is set reads a third and stops
    // there. That is what `at` below decides, and it is why the third byte
    // carries all eight of its bits.
    let at = if bytes[0] & 0x80 == 0 {
        1
    } else if bytes[1] & 0x80 == 0 {
        2
    } else {
        3
    };
    let mut value = 0usize;
    for (i, byte) in bytes[..at].iter().enumerate() {
        // The last byte is a whole byte; the others are seven bits and a marker.
        let (mask, shift) = if i == 2 { (0xff, 14) } else { (0x7f, 7 * i) };
        value |= usize::from(byte & mask) << shift;
    }
    (value, at)
}

fn compact_size(len: usize, out: &mut Vec<u8>) {
    // QEMU's `tight_send_compact_size`, transcribed. `ui/vnc-enc-tight.c:824`.
    //
    // **Three bytes, and the third one is a whole byte.** That is the point, and
    // getting it wrong is invisible at every size a test would naturally use.
    // The layout is 7 bits, then 7 bits, then a *full* 8, with the top bit of
    // each of the first two saying another follows. So the width is 22 bits and
    // the ceiling is 0x3F_FFFF = 4,194,303 bytes of payload.
    //
    // This used to be a "seven bits to a byte with a continuation bit" loop,
    // which describes 7 + 7 + 7 + 8 = 29 bits and emits a *fourth* byte for
    // anything above 0x1F_FFFF = 2,097,151. A decoder that reads the three-byte
    // form -- which is every decoder, because three bytes is the form -- stopped
    // at the third byte, whose top bit QEMU never sets and this loop did set.
    // It therefore read a smaller number than was written, handed that many
    // bytes to its inflater, and got a stream cut off mid-block.
    //
    // Which is what happened, twice, to two independent decoders that agreed
    // with each other and disagreed with us: vnc-rs reported `deflate
    // decompression error` and a real viewer reported `zlib inflate failed`.
    // Our own decoder agreed with our own encoder, because both are the same
    // flate2 build reading its own length back. Neither the in-tree tests nor the
    // 64x32 witness could see it, because a 64x32 rectangle compresses to about
    // six kilobytes and both forms agree below the threshold.
    //
    // So the boundary is real traffic, not a synthetic length: at Tight's level 0
    // a 1280x800 full-colour rectangle is 3,072,000 bytes raw and 3,072,247
    // deflated, which is the first production shape to cross it.
    let mut bytes = [0u8; 3];
    bytes[0] = (len & 0x7f) as u8;
    if len > 0x7f {
        bytes[0] |= 0x80;
        bytes[1] = ((len >> 7) & 0x7f) as u8;
        if len > 0x3fff {
            bytes[1] |= 0x80;
            // All eight of this one, and no continuation bit: this is the last
            // byte, and a decoder stops here because the bit is clear.
            bytes[2] = ((len >> 14) & 0xff) as u8;
        }
    }
    let used = if len > 0x3fff {
        3
    } else if len > 0x7f {
        2
    } else {
        1
    };
    out.extend_from_slice(&bytes[..used]);
}

/// A persistent zlib stream, the state every encoder keeps between
/// rectangles.
#[derive(Debug)]
pub(crate) struct Zlib {
    compress: Compress,
    /// The deflate level, kept beside the compressor because a `Compress` is
    /// built with one and there is no `set_level` to change it afterwards.
    level: u32,
    /// Whether this stream has produced anything yet, which is what decides
    /// whether a requested level can still be taken. See [`Zlib::set_level`].
    used: bool,
    /// How many times a level was asked for and could not be taken.
    declined: u32,
}

impl Zlib {
    fn new() -> Self {
        Self::with_level(DEFAULT_DEFLATE_LEVEL)
    }

    pub(crate) fn with_level(level: u32) -> Self {
        Self {
            // `true`: a zlib stream, with a header, as the RFB encodings
            // expect (a raw deflate stream would not).
            compress: Compress::new(Compression::new(level), true),
            level,
            used: false,
            declined: 0,
        }
    }

    /// Change the deflate level, if the stream can afford it.
    ///
    /// **It usually cannot, and the reason is a gap in flate2 rather than a
    /// choice.** There is no `Compress::set_level`: a deflate compressor's level
    /// is fixed when it is built, and the only way to change one is to throw it
    /// away and build another. That ends the stream. The next rectangle would
    /// begin a new zlib stream, with a new header, in the middle of a connection
    /// — and every persistent client inflates once for the life of the
    /// connection (`libvncclient`'s `decompStreamInited`, noVNC's single
    /// `inflator`, TigerVNC's one `Inflater`), so it would meet a header where it
    /// expected deflate data. That is the fault this port spent a day removing.
    ///
    /// QEMU does not have the gap: `vnc_zlib_stop` changes level with
    /// `deflateParams`, which re-tunes a live stream and leaves the state alone,
    /// and the comment there is the reason — the compressor and decompressor
    /// states have to stay in step, so a level change is not a place to discard
    /// anything.
    ///
    /// So the rule here is: a level is taken while the stream is still unused,
    /// and declined afterwards with a count of how many times that has happened.
    /// In practice the request arrives with `SetEncodings`, before the client
    /// has been sent a single pixel of this connection, so it is honoured every
    /// time it occurs; the decline is for the case where a client changes its
    /// mind mid-session, where the two available answers are "break the stream"
    /// and "ignore the request", and breaking the stream is worse.
    fn set_level(&mut self, level: u32) {
        if level == self.level {
            return;
        }
        if self.used {
            self.declined += 1;
            return;
        }
        self.level = level;
        self.compress = Compress::new(Compression::new(level), true);
    }

    /// Compress `data`, and return the bytes that belong to this rectangle.
    pub(crate) fn compress(&mut self, data: &[u8]) -> Vec<u8> {
        self.used = true;
        // A sync flush, not none, and so the stream this produces has no
        // trailer: it is deliberately left open, one per connection, and the
        // client keeps its inflater across rectangles.
        //
        // The old comment here said the client was told how much to expect —
        // "ZRLE by a length, hextile and Tight by the rectangle being complete".
        // The second half of that was the belief behind a real bug. Hextile does
        // have a 32-bit length on the wire, and it has to: a client reads that
        // length, then hands exactly that many bytes to its inflater, and there
        // is nothing else that says how much of an unterminated stream belongs
        // to this rectangle. Reasoning from "the rectangle is complete" is how
        // the length came to be left out, and how the test client came to leave
        // it out too, so that the two agreed and every zlib test passed.
        //
        // QEMU flushes the same way, and writes the length.
        self.compress_prefixed(0, data)
    }

    /// Compress `data`, leaving `prefix` zero bytes in front of the stream.
    ///
    /// **This exists so a caller can put a header in front of a payload without
    /// copying the payload to do it.** `compress` writes into a `Vec`'s spare
    /// capacity, which begins at its length -- so starting that length at `prefix`
    /// puts the deflate output after `prefix` bytes, and the caller writes the
    /// header into them afterwards, once it knows how long the stream came out.
    ///
    /// Which is the whole difficulty with Tight's compact length: it *is* the
    /// compressed length, so it cannot be written before the compression. The
    /// usual answer is to build the header separately and copy the payload in
    /// behind it, and for a 1280x800 rectangle at level 0 that is 3,072,247 bytes
    /// copied to save two.
    ///
    /// The caller must then be able to write a *fixed-width* header. For Tight
    /// that works because the compact length may be written in three bytes for any
    /// value below 2^22 -- and QEMU writes three bytes for anything over 16 KB
    /// anyway, so a viewer meets the three-byte form on nearly every rectangle.
    pub(crate) fn compress_prefixed(&mut self, prefix: usize, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() / 2 + 64 + prefix);
        out.resize(prefix, 0);
        let mut rest = data;
        loop {
            // `compress_vec` writes into the spare capacity of the vector and
            // never grows it, so room has to be reserved up front.
            if out.len() == out.capacity() {
                out.reserve(out.capacity().max(1024));
            }
            let room = out.capacity() - out.len();
            let (before_in, before_out) = (self.compress.total_in(), self.compress.total_out());
            self.compress
                .compress_vec(rest, &mut out, FlushCompress::Sync)
                .expect("zlib compression failed");
            let consumed = (self.compress.total_in() - before_in) as usize;
            let produced = (self.compress.total_out() - before_out) as usize;
            rest = &rest[consumed.min(rest.len())..];
            // Everything was taken in and the output was not filled, so there
            // is nothing left in the deflate window. (A call with no input
            // left would otherwise emit a new empty block on every turn.)
            if rest.is_empty() && produced < room {
                break;
            }
        }
        out
    }
}

/// The encodings we can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    /// No compression.
    Raw,
    /// The `zlib` hextile encoding.
    Zlib,
    /// The ZRLE encoding.
    Zrle,
    /// The Tight encoding.
    Tight,
    /// A Tight rectangle holding a JPEG image, i.e. the lossy encoding. It
    /// only exists with the `lossy` cargo feature, and is sent under the Tight
    /// encoding number with the JPEG bit of the control byte set.
    Jpeg,
}

impl Codec {
    /// The RFB encoding number the rectangle header carries.
    pub fn encoding(&self) -> i32 {
        match self {
            Codec::Raw => 0,
            Codec::Zlib => 6,
            Codec::Tight | Codec::Jpeg => 7,
            Codec::Zrle => 16,
        }
    }

    /// Whether we can produce this encoding for a client using `format`.
    fn supports(&self, format: &PixelFormat) -> bool {
        match self {
            // Raw works with any format.
            Codec::Raw => true,
            // ZRLE and Tight only need to read the colours of a pixel.
            Codec::Zrle | Codec::Tight | Codec::Jpeg => {
                format.true_colour && matches!(format.bits_per_pixel, 16 | 32)
            }
            // Hextile is defined for 32 bits per pixel, and clients
            // occasionally get a 16 bits one wrong.
            Codec::Zlib => format.bits_per_pixel == 32,
        }
    }

    /// The next encoding to try when this one can not handle the content.
    ///
    /// The encoders are not equally capable: the Tight palette holds 256
    /// colours and the ZRLE ones 16, so a rectangle with a photograph in it is
    /// better served by the encoding below than by raw pixels.
    fn fallback(&self) -> Option<Codec> {
        match self {
            Codec::Jpeg => Some(Codec::Zrle),
            Codec::Tight => Some(Codec::Zrle),
            Codec::Zrle => Some(Codec::Zlib),
            Codec::Zlib | Codec::Raw => None,
        }
    }

    /// Whether the client can be sent this encoding, i.e. it asked for it.
    fn offered_by(&self, offered: &HashSet<Encoding>) -> bool {
        let pseudo = match self {
            Codec::Jpeg => Encoding::Jpeg(0),
            Codec::Tight => Encoding::Tight,
            Codec::Zrle => Encoding::Zrle,
            Codec::Zlib => Encoding::Zlib,
            Codec::Raw => return true,
        };
        offered.contains(&pseudo)
    }
}

/// The encoders of one client, and the state they need between rectangles.
#[derive(Debug)]
pub struct Encoders {
    /// The policy, which picks an encoding per rectangle.
    policy: Policy,
    /// The persistent zlib stream of the hextile encoding.
    hextile: Zlib,
    /// The persistent zlib stream of the ZRLE encoding.
    zrle: Zlib,
    /// The persistent zlib stream of the Tight encoding, shared with the
    /// lossy JPEG one, which is a Tight rectangle.
    tight: Zlib,
    /// zlib stream 0, which is where Tight's raw pixel data goes.
    ///
    /// **Separate from `tight` because Tight has four streams and QEMU uses more
    /// than one of them**: the palette's indexes go out on stream 2
    /// (`tight::STREAM_INDEX`) and raw pixel data on stream 0. One `Zlib` for
    /// both would produce a stream the decoder reads as the wrong one, and it
    /// would do so by returning plausible pictures.
    tight_basic: Zlib,
    /// The JPEG encoder of the lossy rectangles, if enabled.
    lossy: Lossy,
    /// The scratch buffer of the rectangle header.
    scratch: Vec<u8>,
    /// A row of a ZRLE raw tile, repacked into the client's pixel layout.
    ///
    /// Separate from `scratch` because that one holds the rectangle header, and
    /// reusing it would mean reasoning about which of the two is live at the
    /// point a tile is written.
    row_scratch: Vec<u8>,
}

impl Encoders {
    /// Create the encoders of a client.
    ///
    /// `jpeg_quality` enables the lossy encoding, with the given quality from
    /// 0 (smallest) to 100 (best), as QEMU's `-vnc jpeg=<quality>`.
    pub fn new(jpeg_quality: Option<u8>) -> Self {
        Self {
            row_scratch: Vec::new(),
            policy: Policy::new(),
            hextile: Zlib::new(),
            // Level 0, on purpose and against QEMU's 6: see `ZRLE_DEFLATE_LEVEL`.
            zrle: Zlib::with_level(ZRLE_DEFLATE_LEVEL),
            tight: Zlib::new(),
            tight_basic: Zlib::with_level(TIGHT_BASIC_DEFLATE_LEVEL),
            #[cfg(feature = "lossy")]
            lossy: jpeg_quality.map(|quality| Jpeg { quality }),
            #[cfg(not(feature = "lossy"))]
            lossy: {
                if jpeg_quality.is_some() {
                    tracing::warn!("built without the lossy feature, ignoring the JPEG quality");
                }
                None
            },
            scratch: Vec::new(),
        }
    }

    /// The encoding to use for `rect`, given what the client supports.
    pub fn choose(
        &mut self,
        offered: &HashSet<Encoding>,
        format: &PixelFormat,
        rect: Rect,
    ) -> Codec {
        let lossy = self.lossy.is_some();
        self.policy.choose(offered, format, rect, lossy)
    }

    /// Note the compression level the client asked for, from the -254
    /// pseudo-encoding. See [`Policy::want_compression`].
    pub fn want_compression(&mut self, level: u8) {
        self.policy.want_compression(level);
    }

    /// Note which encoding the client listed first, in its own order.
    ///
    /// QEMU takes the client's first encoding it recognises rather than the one
    /// this port would have chosen; see [`Policy::preferred_encoding`] and
    /// [`Policy::choose`].
    ///
    /// **Tight used to be barred here, and the bar has a story worth keeping.**
    ///
    /// The rule is QEMU's and it is right: the client's first encoding is the
    /// encoding. But a real viewer answered it with `Failed while connected:
    /// Error decoding rect: Error: zlib inflate failed`, and this port's Tight
    /// had never been read by anything except the decoder written alongside it.
    ///
    /// Three things were known about the evidence and one was not:
    ///
    /// - **libvncclient cannot check Tight at all.** Its build contains
    ///   `rfbtightserver.o` and no client-side `tight.o`, so it silently ignores
    ///   a Tight rectangle and reports an all-black screen. Three sub-encodings
    ///   all "failed" against it, including the fill path that predates any of
    ///   this work, which is what gave the game away.
    /// - **vnc-rs read our Tight correctly at 64x32**, which looked like the same
    ///   exoneration and was not: the viewer's screen is 1280x800, and nothing had
    ///   asked the witness about that size.
    /// - **the viewer's report was a real signal**, and it was about our bytes.
    ///
    /// The cause was the compact length, one byte too wide, which put the payload
    /// a byte late. See `compact_size`. It is the fourth time in this port that
    /// the encoder and its own decoder agreed, and were both wrong together;
    /// `tests/common/rfb_client.rs::compact_size` had the identical four-byte
    /// mistake, so no test using the pair could have seen it. What finally broke
    /// the tie was a decoder that had never seen this code, asked about the size
    /// production uses: `a_reference_client_can_read_our_tight_at_productions_size`.
    pub fn prefer_encoding(&mut self, encodings: &[Encoding]) {
        // **No environment variable forces this back on, and that is on
        // purpose.** There was one -- `QEMU_VNC_PREFER_TIGHT` -- and it leaked:
        // `set_var` is process-global, so a test that set it changed the
        // preference for every other test running in parallel in the same
        // binary, and the suite hung rather than failing.
        //
        // It is also unnecessary. A client offering **Tight and nothing else**
        // makes the ladder pick Tight by itself, because there is nothing to
        // fall back to -- which is what the witness does, sending a one-element
        // `SetEncodings`. Reaching the path needs no override.
        //
        // The arm below used to hold `Some(Codec::Tight) | Some(Codec::Jpeg) =>
        // None`, keeping Tight out of production because a real viewer had
        // reported `zlib inflate failed` against it and nothing could explain
        // why. It can be explained: the compact length was a byte too wide, so
        // the payload began one byte late and every third-party inflater was fed
        // the wrong first byte. See `compact_size`. The bar for putting an
        // encoding back is not "it works here" -- it worked here the whole time,
        // because our reader shared the writer's mistake -- but "an independent
        // decoder reads it at the size production uses".
        let codec = match Policy::preferred_encoding(encodings) {
            // JPEG stays out: it is lossy, and nothing has witnessed it.
            Some(Codec::Jpeg) => None,
            other => other,
        };
        self.policy.prefer_encoding(codec);
    }

    /// Tell the policy how an update went, so it can adapt.
    pub fn record(&mut self, bytes: usize, written: Duration, since_last: Duration) {
        self.policy.record(bytes, written, since_last);
    }

    /// Note the deflate level a client asked for, from the -254
    /// `CompressionLevel` pseudo-encoding.
    ///
    /// **It goes to Tight and to nothing else, because that is what QEMU does
    /// with it, and this port had it exactly backwards.**
    ///
    /// In QEMU's `set_encodings` the pseudo-encoding lands in exactly one place,
    /// `vnc.c:2195`:
    ///
    /// ```c
    /// case VNC_ENCODING_COMPRESSLEVEL0 ... VNC_ENCODING_COMPRESSLEVEL0 + 9:
    ///     vc->worker.tight.compression = (enc & 0x0F);
    /// ```
    ///
    /// `tight.compression`, and nothing else. It is an index into `tight_conf[]`
    /// rather than a deflate level directly, which is why Tight's zlib levels
    /// come from that table: at Tight level 2 the row is
    /// `{ 6144, 256, 8, 65536, 3, 3, 2, 0, ... }`, so raw data is deflated at
    /// level 2 and a gradient at level 0.
    ///
    /// ZRLE is not in that path at all. `vnc_zlib_init` is never called for it
    /// with a client level; `vnc-enc-zrle.c:339` passes
    /// `Z_DEFAULT_COMPRESSION`, which zlib reads as level 6. **So a QEMU serving
    /// ZRLE always deflates at 6, whatever the client asked.**
    ///
    /// This port applied the client's number to ZRLE, so a viewer announcing
    /// `CompressionLevel(2)` was served 2 where QEMU would have served 6, and
    /// An earlier revision of this port recorded that as "matching QEMU" — the exact
    /// inversion of what QEMU does. Fixing it makes the comparison honest rather than
    /// flattering: our encode was already the cheaper of the two.
    ///
    /// **Hextile is left alone deliberately.** The same mechanism appears to
    /// apply — QEMU's hextile is also a persistent zlib stream — but the
    /// `vnc.c` available to this port predates `compress_level` and does not
    /// contain the call that would settle it. Changing it on a guess is how a
    /// parity argument becomes a coincidence, so hextile keeps the client's
    /// level and this says so rather than implying it was checked.
    pub fn set_deflate_level(&mut self, level: u32) {
        let level = level.min(9);
        self.hextile.set_level(level);
        // **Through `tight_conf[]`, not straight through.** QEMU stores the
        // client's number in `tight.compression` and reads the deflate level out
        // of the row it indexes, so at Tight level 3 the indexes go out at 5 and
        // at level 9 at 9. This port passed the number to `deflateInit2` as if it
        // were the level, which agrees with QEMU at Tight level 2 -- where
        // `raw_zlib_level` happens to be 2 -- and disagrees at eight of the other
        // nine.
        //
        // `idx_zlib_level` rather than `mono_zlib_level`, and that is not a
        // choice between them: the two columns are identical in all ten rows of
        // QEMU's table, so one stream serves both the palette and the two-colour
        // case. Checked rather than assumed, because a `deflateParams` re-tune per
        // call -- which is what QEMU does -- is not available here, and if the
        // columns ever diverged one stream could not serve both.
        self.tight.set_level(tight::conf(level).idx_zlib_level);
        // **Not the ZRLE stream.** QEMU never puts a client's level there, so
        // setting it would be this port's own invention. The stream keeps
        // `ZRLE_DEFLATE_LEVEL`.
    }

    /// Build encoders whose **ZRLE** stream is at `level`, whatever a client asks.
    ///
    /// **This exists for one measurement, and it is deliberately not reachable
    /// from `set_deflate_level`.** That function no longer touches ZRLE, because
    /// QEMU's does not: `vnc-enc-zrle.c:339` passes `Z_DEFAULT_COMPRESSION` and
    /// the client's `-254` reaches only `tight.compression`. So the level curve
    /// for ZRLE cannot be walked through the public path any more, and
    /// `what_deflate_costs_and_what_it_buys` needs to walk it.
    ///
    /// Without this the measurement reports one number ten times and its own
    /// guard catches it — which it did, on the first run, after item 1 landed.
    /// A guard that fires because the instrument is wrong rather than the code is
    /// worth having: the alternative was a table that looked fine and measured
    /// nothing.
    #[cfg(test)]
    pub(crate) fn with_zrle_level_for_measurement(level: u32) -> Self {
        let mut encoders = Self::new(None);
        encoders.zrle = Zlib::with_level(level.min(9));
        encoders
    }

    /// How many requested levels could not be taken because the stream was
    /// already in use. Non-zero means a client changed its mind mid-session and
    /// was ignored, which is a thing to know rather than to guess at.
    pub fn declined_levels(&self) -> u32 {
        self.hextile.declined + self.zrle.declined + self.tight.declined
    }

    /// The current quality level, from 0 (raw) to 3 (the best encoding).
    pub fn level(&self) -> u8 {
        self.policy.level()
    }

    /// Compress `rect` of the frame buffer into a `FramebufferUpdate`
    /// payload, i.e. the bytes that follow the rectangle header and the
    /// encoding number, and return it with the encoding actually used.
    ///
    /// A `codec` that can not represent the content falls back to the next
    /// one the client asked for, down to raw pixels, rather than sending
    /// something wrong. `None` means no encoding applied and the caller has to
    /// send the raw rectangle.
    pub fn encode(
        &mut self,
        codec: Codec,
        offered: &HashSet<Encoding>,
        data: &[u8],
        format: &PixelFormat,
        stride: usize,
        rect: Rect,
    ) -> Option<(Codec, Vec<u8>)> {
        let mut codec = codec;
        loop {
            if codec.supports(format) {
                let pixels = RectPixels::new(data, format, stride, rect);
                let encoded = match codec {
                    Codec::Raw => None,
                    Codec::Zrle => self.encode_zrle(&pixels, rect),
                    Codec::Zlib => self.encode_hextile(&pixels, rect),
                    Codec::Tight => self.encode_tight(&pixels, rect),
                    #[cfg(feature = "lossy")]
                    Codec::Jpeg => self.encode_jpeg(data, format, stride, rect),
                    #[cfg(not(feature = "lossy"))]
                    Codec::Jpeg => None,
                };
                if let Some(data) = encoded {
                    return Some((codec, data));
                }
                // This encoder can not represent the content, so stop
                // offering it to this client.
                self.policy.refuse(codec);
            } else {
                self.policy.refuse(codec);
            }
            // The next one has to be one the client asked for too.
            let next = codec.fallback()?;
            if !next.offered_by(offered) {
                return None;
            }
            codec = next;
        }
    }

    /// The ZRLE encoding: a zlib stream of solid, palette and raw 64x64
    /// tiles.
    ///
    /// The stream is the tiles and nothing else. There is no header in front of
    /// them: `ZRLE_ENCODE` in `vnc-enc-zrle.c.inc` loops over the tiles calling
    /// `ZRLE_ENCODE_TILE`, which writes each tile's sub-encoding byte and its
    /// data, and the rectangle's width and height are in the framebuffer update
    /// message the generic layer has already written. A client agrees: the only
    /// thing it reads before the compressed data is a four byte length, and
    /// `HandleZRLE` then loops over the same 64x64 grid taking its width and
    /// height from the rectangle.
    ///
    /// A five byte header of "the first tile's sub-encoding, then width - 1,
    /// then height - 1" was here first, on the strength of a
    /// `vnc_zrle_send_header` that does not exist in QEMU's tree. Its first byte
    /// is the first tile's sub-encoding either way, so the first tile decodes
    /// and then every one after it is four bytes out of step.
    fn encode_zrle(&mut self, pixels: &RectPixels<'_>, rect: Rect) -> Option<Vec<u8>> {
        let mut stream = std::mem::take(&mut self.scratch);
        stream.clear();

        for tile_y in (0..rect.height).step_by(ZRLE_TILE as usize) {
            for tile_x in (0..rect.width).step_by(ZRLE_TILE as usize) {
                let w = (rect.width - tile_x).min(ZRLE_TILE);
                let h = (rect.height - tile_y).min(ZRLE_TILE);
                if self.zrle_tile(pixels, tile_x, tile_y, w, h, &mut stream).is_none() {
                    self.scratch = stream;
                    return None;
                }
            }
        }

        self.scratch = stream;
        Some(self.zrle.compress(&self.scratch))
    }

    /// One ZRLE tile, appended to `out`, and its sub-encoding.
    ///
    /// This is the hottest loop in the crate. It was written the obvious way and
    /// measured at **45.3 ms for a 1280x800 frame** on content that takes the
    /// palette path, against 4.8 ms for content that does not and 3.9 ms for a
    /// solid one — ten times the cost of the raw path for six times fewer bytes,
    /// and on its own more than the whole budget for sixty frames a second. The
    /// obvious way was:
    ///
    /// ```ignore
    /// // counting: a linear search per pixel
    /// palette.iter_mut().find(|(colour, _)| *colour == pixel)
    /// // packing: a HashMap built per tile, looked up per pixel
    /// let indices: HashMap<&[u8], u8> = palette.iter().enumerate()...collect();
    /// indices[pixels.raw(x, y)]
    /// ```
    ///
    /// A thousand pixels a tile and a hundred and sixty-five thousand per
    /// frame, so that is a million linear searches over up to sixteen entries
    /// comparing byte slices, and a million SipHashes. The palette never has
    /// more than sixteen entries and the whole thing is being done sixteen times
    /// over per tile.
    ///
    /// What is here now is a fixed open-addressed table of sixty-four slots, so
    /// a quarter full, with Fibonacci hashing to scatter the near-identical
    /// colours a tile tends to hold. No allocation, no hashing function, one
    /// probe in the common case. It is used twice: once while counting, mapping
    /// a pixel to the entry that holds it, and again after the sort, mapping a
    /// pixel to its *packed index* — because the sort moves the entries and the
    /// counting table's indices no longer mean what they did.
    ///
    /// The output is byte for byte what the straightforward version produced,
    /// and `a_zrle_tile_is_what_a_naive_encoder_would_produce` is how that is
    /// known: it checks this against a deliberately simple reference encoder
    /// written from the format, over a corpus built to hit every branch. A test
    /// comparing this against the *old* implementation would have been worth
    /// less — it would have pinned the code to itself and said nothing about
    /// the format.
    fn zrle_tile(
        &mut self,
        pixels: &RectPixels<'_>,
        x0: u16,
        y0: u16,
        w: u16,
        h: u16,
        out: &mut Vec<u8>,
    ) -> Option<u8> {
        // Count the colours of the tile, keeping at most 16 of them: a tile
        // with more is sent raw.
        //
        // The palette is keyed on the *pixel bytes*, not on an RGB triple,
        // because a palette entry goes out in the client's pixel format and
        // there is no conversion from RGB back to one. QEMU keys on the pixel
        // value for the same reason.
        //
        // `palette` is an array rather than a `Vec` because sixteen entries is
        // every tile ever needs and a `Vec` means a branch and a possible
        // allocation per tile to hold them.
        let mut palette: [(&[u8], u16); MAX_ZRLE_PALETTE] = [(&[], 0); MAX_ZRLE_PALETTE];
        let mut used = 0usize;
        let mut slots = [ZRLE_LOOKUP_EMPTY; ZRLE_LOOKUP_SLOTS];
        let mut too_many = false;
        'tile: for y in y0..y0 + h {
            for x in x0..x0 + w {
                let pixel = pixels.raw(x, y);
                // The first colour, checked before hashing. On a mostly-uniform
                // tile — a toolbar, a panel, a background, which is most of a
                // desktop — that is the colour nearly every pixel is, and the
                // hash is then pure overhead: without this the solid path went
                // from 3.9 ms to 5.4 ms for a full frame, which is the price of
                // making the sixteen-colour path five times cheaper and worth
                // paying, but not a price worth paying twice.
                if used > 0 && used <= 2 && palette[0].0 == pixel {
                    palette[0].1 += 1;
                    continue;
                }
                let mut slot = zrle_slot(pixel);
                loop {
                    let entry = slots[slot];
                    if entry == ZRLE_LOOKUP_EMPTY {
                        if used == MAX_ZRLE_PALETTE {
                            too_many = true;
                            break 'tile;
                        }
                        palette[used] = (pixel, 1);
                        slots[slot] = used as u8;
                        used += 1;
                        break;
                    }
                    let found = &mut palette[entry as usize].1;
                    if palette[entry as usize].0 == pixel {
                        *found += 1;
                        break;
                    }
                    // A different colour that hashed here. Sixty-four slots for
                    // sixteen entries means this is rare, but it is not
                    // impossible and skipping it would be a rare wrong answer.
                    slot = (slot + 1) & (ZRLE_LOOKUP_SLOTS - 1);
                }
            }
        }

        if too_many {
            // More than sixteen colours: the pixels as they are, at the ZRLE
            // pixel width rather than the client's, which is three bytes rather
            // than four for a 32-bit client at depth 24.
            //
            // **QEMU does not do this, and the difference is measured.** It
            // picks between this and sub-encoding 128's plain run-length
            // encoding by estimating both in `zrle_choose_palette_rle()`, and on
            // desktop-shaped content it picks plain RLE where this sends raw. On
            // a 1280x800 desktop that is 125 KB against 186 KB — **33% fewer
            // bytes on the wire** — and it costs 9.9 ms against 8.0, so **24% more
            // CPU**. On noisy content it is worse on both: 30.7 ms against 21.4,
            // and 1,530,242 bytes against 1,384,293, because deflate already
            // finds the runs that the RLE pass would have written.
            //
            // QEMU is buying bandwidth with CPU. The complaint this port exists
            // to answer is CPU, so the trade runs the wrong way, and the rule
            // stays. `where_the_tile_rule_and_qemus_would_differ` is the
            // measurement, and the round trip in `tests/mock.rs` that checks the
            // alternative decodes is what caught three errors in an
            // implementation of it — which is why the answer here is a number
            // and not a shrug.
            out.push(0);
            // **A row at a time, not a pixel at a time.** The obvious loop is
            //
            // ```text
            // for y in y0..y0+h { for x in x0..x0+w {
            //     out.extend_from_slice(palette_entry(pixels.raw(x, y), format)); } }
            // ```
            //
            // and on a 64x64 tile that is 4,096 of each of three things: a
            // bounds-checked slice to address the pixel, a branch in
            // `palette_entry` to choose which end of it the colour sits at, and a
            // three-byte `extend_from_slice` whose length the compiler cannot see,
            // so it is a `memcpy` call rather than three stores. Measured at
            // **4.3 ns a pixel**, which at the deflate level this port now serves
            // is 84% of the whole encode -- the compressor is gone and this is
            // what is left.
            //
            // So: pack one row into a scratch buffer with a loop the compiler can
            // unroll, and hand `out` one `extend_from_slice` per row. Sixty-four
            // calls per tile instead of 4,096, and no per-pixel bounds check.
            //
            // The bytes are identical, and `a_zrle_tile_is_what_a_naive_encoder_
            // would_produce` is how that is known: it checks the output against a
            // deliberately simple encoder written from the format, rather than
            // against the loop this replaces.
            let n = zrle_pixel_len(pixels.format);
            let b = pixels.bpp();
            // Which end of the pixel the colour sits at: the low `n` bytes,
            // except on a big-endian client at a width where the colour is the
            // high ones. `palette_entry` says the same thing, per pixel.
            let skip = if n < b && pixels.format.big_endian { b - n } else { 0 };
            let row_bytes = usize::from(w) * n;
            let packed = &mut self.row_scratch;
            for y in y0..y0 + h {
                let start = pixels.offset_of(x0, y);
                let row = &pixels.data[start..start + usize::from(w) * b];
                packed.clear();
                packed.reserve(row_bytes);
                if skip == 0 {
                    // The common case: the colour is the leading `n` bytes, so
                    // this is a strided copy of `n` from every `b`.
                    for px in row.chunks_exact(b) {
                        packed.extend_from_slice(&px[..n]);
                    }
                } else {
                    for px in row.chunks_exact(b) {
                        packed.extend_from_slice(&px[skip..skip + n]);
                    }
                }
                out.extend_from_slice(packed);
            }
            return Some(0);
        }

        if used == 1 {
            // A solid tile: sub-encoding 1, and then the colour as a whole
            // pixel. QEMU writes it with the same `ZRLE_WRITE_PIXEL` as
            // everything else, so it is three bytes for a 32-bit client at
            // depth 24 and not four.
            out.push(1);
            out.extend_from_slice(palette_entry(palette[0].0, pixels.format));
            return Some(1);
        }

        // A palette tile: the colours are sorted by how often they are used,
        // so that index 0 is the most common one, like QEMU does. The sort is
        // stable and the entries are in first-seen order, so colours with equal
        // counts come out in the order they were first met — which is what the
        // straightforward version did too, and what a decoder cannot tell.
        palette[..used].sort_by_key(|(_, count)| std::cmp::Reverse(*count));

        // The sub-encoding is the number of colours, 2 to 16. QEMU writes it as
        // `(use_rle ? 128 : 0) | size`; this encoder does not do run-length
        // tiles, so it is just the count. It is *not* the count plus one, which
        // is the off-by-one that a decoder written from the same reading shares
        // and a real client does not.
        let size = used as u8;
        out.push(size);
        // The palette is in the client's pixel format, with the exceptions the
        // format allows: 16 bits per pixel is two bytes, and 32 bits per pixel
        // at depth 24 is three, taken from the end that holds the colour.
        for (colour, _) in &palette[..used] {
            out.extend_from_slice(palette_entry(colour, pixels.format));
        }

        // The counting table no longer means anything: the sort moved the
        // entries, so slot 7's index of 3 is no longer the third most common
        // colour. A second table maps a pixel to its *packed* index, which is
        // the one the format numbers the colours by. Two tables rather than
        // one reused, because reusing it would mean renumbering sixty-four slots
        // per tile to save sixty-four bytes of stack.
        let mut packed = [ZRLE_LOOKUP_EMPTY; ZRLE_LOOKUP_SLOTS];
        for (i, (colour, _)) in palette[..used].iter().enumerate() {
            let mut slot = zrle_slot(colour);
            while packed[slot] != ZRLE_LOOKUP_EMPTY {
                slot = (slot + 1) & (ZRLE_LOOKUP_SLOTS - 1);
            }
            packed[slot] = i as u8;
        }

        // The indices are *packed*, not one byte each: 1 bit for 2 colours, 2
        // for 3 or 4, 4 for 5 to 16. The packing restarts on every row and the
        // last byte of a row is padded on the right, as QEMU's loop does:
        //
        //     byte = (byte << bppp) | index;  nbits += bppp;
        //     if (nbits >= 8) { write(byte); nbits = 0; }
        //     ...  if (nbits > 0) { byte <<= 8 - nbits; write(byte); }
        let bits = packed_bits(used);
        for y in y0..y0 + h {
            let mut byte = 0u8;
            let mut nbits = 0u8;
            for x in x0..x0 + w {
                let pixel = pixels.raw(x, y);
                let mut slot = zrle_slot(pixel);
                // Every colour in the tile is in the palette by construction, so
                // this terminates at a filled slot; the `while` is on the
                // *empty* marker rather than a bound, because a bound would be
                // a number to keep in step with the table size.
                let index = loop {
                    let entry = packed[slot];
                    if entry != ZRLE_LOOKUP_EMPTY && palette[entry as usize].0 == pixel {
                        break entry;
                    }
                    slot = (slot + 1) & (ZRLE_LOOKUP_SLOTS - 1);
                };
                byte = (byte << bits) | index;
                nbits += bits;
                if nbits >= 8 {
                    out.push(byte);
                    nbits = 0;
                }
            }
            if nbits > 0 {
                out.push(byte << (8 - nbits));
            }
        }
        Some(size)
    }

    /// The hextile encoding: a zlib stream of 16x16 tiles, each one sent raw
    /// or as a solid background.
    fn encode_hextile(&mut self, pixels: &RectPixels<'_>, rect: Rect) -> Option<Vec<u8>> {
        let mut stream = Vec::new();
        let mut subrects = Vec::new();
        for tile_y in (0..rect.height).step_by(HEXTILE_TILE as usize) {
            for tile_x in (0..rect.width).step_by(HEXTILE_TILE as usize) {
                let w = (rect.width - tile_x).min(HEXTILE_TILE);
                let h = (rect.height - tile_y).min(HEXTILE_TILE);
                match pixels.is_uniform(tile_x, tile_y, w, h) {
                    // A uniform tile is sent as a background colour...
                    Some(_) => {
                        subrects.push(1); // BackgroundSpecified
                        subrects.extend_from_slice(pixels.raw(tile_x, tile_y));
                    }
                    // ...and anything else as raw pixels. Hextile also has
                    // foreground and subrectangle sub-encodings, but they
                    // need a scan of the tile we do not need to make.
                    None => {
                        subrects.push(0); // Raw
                        for y in tile_y..tile_y + h {
                            for x in tile_x..tile_x + w {
                                subrects.extend_from_slice(pixels.raw(x, y));
                            }
                        }
                    }
                }
            }
        }
        // No count in front of the tiles: the decoder knows how many there are
        // from the rectangle's dimensions, which is why
        // `vnc_hextile_send_framebuffer_update` can stream them out one
        // `send_tile` at a time and never look ahead. A leading byte here
        // shifts every tile by one and the client reads nonsense from the
        // first one onwards.
        stream.extend_from_slice(&subrects);
        Some(self.hextile.compress(&stream))
    }

    /// The Tight encoding: a solid fill for a uniform rectangle, and a
    /// palette otherwise.
    fn encode_tight(&mut self, pixels: &RectPixels<'_>, rect: Rect) -> Option<Vec<u8>> {
        // Note 4: a Tight rectangle cannot be wider than 2048 pixels, so a
        // wider one has to be split before it is encoded. Splitting it belongs
        // to the caller, which owns the rectangle, so this declines it instead
        // and the policy falls back to an encoding with no such limit. QEMU
        // splits it in `tight_send_split_rect`, which is better for a client
        // and a larger change than declining is.
        if rect.width > tight::MAX_WIDTH {
            return None;
        }
        let len = tight_pixel_len(pixels.format);
        if let Some(rgb) = pixels.is_uniform(0, 0, rect.width, rect.height) {
            // A fill: the control byte and then the one colour that fills the
            // rectangle, and nothing else — no size, no compression. The
            // compression type lives in the top four bits and `VNC_TIGHT_FILL`
            // is 0b1000, so the control byte is 0x80. A 0x10 here would be a
            // *basic* rectangle on zlib stream 1, which is to say raw pixels.
            let mut out = vec![tight::FILL << 4];
            tight_pixel(&mut out, &rgb, pixels.raw(0, 0), len);
            return Some(out);
        }

        // A palette of up to 256 colours, sent as indexes. A rectangle with
        // more colours than that can not be sent this way, and the caller
        // falls back to another encoding. The colours are sorted by how often
        // they are used, so index 0 is the most common one, which is what makes
        // the two colour case worth the single bit it spends per pixel.
        let mut palette: Vec<(&[u8], [u8; 3], u32)> = Vec::new();
        let mut found: HashMap<&[u8], u8> = HashMap::new();
        let mut too_many = false;
        'pixels: for y in 0..rect.height {
            for x in 0..rect.width {
                let rgb = pixels.rgb(x, y)?;
                let pixel = pixels.raw(x, y);
                match found.get(pixel) {
                    Some(&index) => palette[index as usize].2 += 1,
                    None => {
                        if palette.len() == 256 {
                            too_many = true;
                            break 'pixels;
                        }
                        found.insert(pixel, palette.len() as u8);
                        palette.push((pixel, rgb, 1));
                    }
                }
            }
        }
        if too_many {
            // More than 256 colours, so the palette filter cannot represent it.
            // QEMU does not decline here: it sends `send_full_color_rect`, the
            // raw pixel data with no filter, on zlib stream 0.
            //
            // **This port returned `None`, which made Tight unusable for
            // everything that matters** -- a photograph, a video band, anything
            // with more than 256 colours, which is most of a desktop. The
            // encoder then fell back to ZRLE and the client was served an
            // encoding it had not asked for first, having paid a palette scan
            // that found nothing. Declining was not a safe default; it was the
            // absence of the thing Tight is mostly for.
            return self.tight_full_color(pixels, rect, len);
        }
        palette.sort_by_key(|(_, _, count)| std::cmp::Reverse(*count));
        // The sort moves the colours, so the map of pixel to index has to be
        // built again from the palette as it goes out. Reusing the one built
        // while collecting leaves every index pointing at wherever that colour
        // happened to be found, and the picture comes back shuffled — but only
        // where two colours are not equally common, which is why a checkerboard
        // round trips and a gradient does not.
        let indexes: HashMap<&[u8], u8> = palette
            .iter()
            .enumerate()
            .map(|(i, (pixel, _, _))| (*pixel, i as u8))
            .collect();

        // Everything up to and including the palette goes out as it is. Only
        // the indexes are compressed, and they carry a size first, because a
        // decoder cannot otherwise tell a compressed row of indexes from a raw
        // one.
        let mut out = vec![
            // Basic compression, zlib stream 2, and a filter byte follows.
            (tight::STREAM_INDEX | tight::EXPLICIT_FILTER) << 4,
            tight::FILTER_PALETTE,
            // The number of colours *minus one*: 1 means 2 colours and 255
            // means 256. A count of 256 would not fit in a byte.
            (palette.len() - 1) as u8,
        ];
        for (pixel, rgb, _) in &palette {
            tight_pixel(&mut out, rgb, pixel, len);
        }

        // With two colours a pixel is one bit, most significant bit first and
        // every row starting on a byte boundary; otherwise it is a whole byte.
        let mut indexes_data = Vec::new();
        if palette.len() == 2 {
            for y in 0..rect.height {
                let mut byte = 0u8;
                let mut nbits = 0u8;
                for x in 0..rect.width {
                    byte = (byte << 1) | indexes[pixels.raw(x, y)] & 1;
                    nbits += 1;
                    if nbits == 8 {
                        indexes_data.push(byte);
                        byte = 0;
                        nbits = 0;
                    }
                }
                if nbits > 0 {
                    indexes_data.push(byte << (8 - nbits));
                }
            }
        } else {
            for y in 0..rect.height {
                for x in 0..rect.width {
                    indexes_data.push(indexes[pixels.raw(x, y)]);
                }
            }
        }

        // Under twelve bytes of filtered data goes out as it is, with no size
        // in front of it: a decoder can work that out from the rectangle's
        // dimensions, which is the whole reason for the threshold.
        if indexes_data.len() < tight::MIN_TO_COMPRESS {
            out.extend_from_slice(&indexes_data);
        } else {
            let compressed = self.tight.compress(&indexes_data);
            compact_size(compressed.len(), &mut out);
            out.extend_from_slice(&compressed);
        }
        Some(out)
    }

    /// Tight's `send_full_color_rect`: the pixel data with no filter at all.
    ///
    /// From `ui/vnc-enc-tight.c:922`. The wire form is three parts:
    ///
    /// - a control byte of `(stream << 4)` with `stream = 0` and no explicit
    ///   filter, so **0x00**. A filter bit here would send the decoder looking
    ///   for a filter id byte that is not there.
    /// - the pixels, three bytes each when the client is `pixel24` -- 32 bits per
    ///   pixel with all three maxima at 255 -- and four otherwise.
    /// - `tight_compress_data`, which writes under twelve bytes as they are with
    ///   no length in front, and otherwise a compact length and the deflated
    ///   stream.
    ///
    /// The compression level is `TIGHT_BASIC_DEFLATE_LEVEL` rather than QEMU's
    /// `tight_conf[...].raw_zlib_level`, and the constant says why.
    fn tight_full_color(&mut self, pixels: &RectPixels<'_>, rect: Rect, len: usize) -> Option<Vec<u8>> {
        // QEMU returns 0 -- the rectangle is not sent -- when it can not read the
        // client's colours, so declining is right rather than a failure here.
        // **A row at a time, for the reason ZRLE's raw path is.**
        //
        // Written per pixel first, and it cost 10.2 ms a 1280x800 frame against
        // ZRLE's 4.0 for the same content -- because `rgb()` per pixel rebuilds
        // a `u32` from the pixel's bytes, applies a scale closure per component
        // and returns a triple, all to produce a byte permutation that is fixed
        // for the whole rectangle.
        //
        // `tight_pixel_len` already answers when that permutation is trivial: it
        // returns 3 only for a client whose three components are eight bits wide,
        // which is exactly when the colour is the pixel's bytes in a fixed order.
        // So the fast path is a strided copy with no arithmetic per pixel, and
        // the general path is still there for a client with narrower components.
        let mut packed = Vec::with_capacity(usize::from(rect.width) * usize::from(rect.height) * len);
        // Resized per row by the fast path below, and pushed to by the general
        // one, so the capacity is a starting point rather than the final length.
        if len == 3 && pixels.format.true_colour {
            let b = pixels.bpp();
            let (r, g, bl) = (
                (pixels.format.red_shift / 8) as usize,
                (pixels.format.green_shift / 8) as usize,
                (pixels.format.blue_shift / 8) as usize,
            );
            // Two cursors rather than three `push`es a pixel. `Vec::push` checks
            // its capacity every time, so the first version of this -- three
            // pushes per pixel, which is the obvious way to write it -- cost more
            // than the whole of ZRLE's raw path on the same content: 7.5 ms
            // against 3.9 for a 1280x800 frame. Sized once and written through a
            // fixed-size `copy_from_slice`, which inlines and does not.
            let per_row = usize::from(rect.width) * 3;
            packed.resize(per_row * usize::from(rect.height), 0);
            for y in 0..rect.height {
                let start = pixels.offset_of(0, y);
                let src = &pixels.data[start..start + usize::from(rect.width) * b];
                let dst = &mut packed[usize::from(y) * per_row..][..per_row];
                // Threes by index rather than `chunks_exact_mut(3)`, which
                // clippy flags as a constant chunk size. The two are the same
                // shape; this one says so at the call site.
                //
                // **Unless the permutation is the identity, which is production's
                // format and worth its own path.** `red_shift 0, green_shift 8,
                // blue_shift 16` and four bytes a pixel means the three colour
                // bytes are the first three, so the whole transform is "copy three
                // bytes" -- and a `copy_from_slice` of a constant length carries no
                // bounds check, where each of three indexed writes carries its own.
                //
                // Measured on this shape, 1280x800, five ways (`examples/`
                // `pack_speed.rs` and a standalone bench):
                //
                // ```text
                //   chunks_exact + three indexed writes   0.687 ns/px  10.2 GB/s
                //   chunks_exact + copy_from_slice(3)      0.374 ns/px  18.7 GB/s
                //   two cursors instead of indices         0.691
                //   unrolled x16                            0.721
                // ```
                //
                // 1.84x for a two-word change, and it is the third time in this
                // port that the answer to "this loop looks silly" was a bounds
                // check rather than the arithmetic.
                if len == 3 && b == 4 && (r, g, bl) == (0, 1, 2) {
                    // `as_chunks` rather than `chunks_exact`, which clippy flags
                    // at a constant chunk size. The same loop, and the same
                    // constant-size copy that makes it worth having.
                    let (src4, _) = src.as_chunks::<4>();
                    let (dst3, _) = dst.as_chunks_mut::<3>();
                    for (px, o) in src4.iter().zip(dst3.iter_mut()) {
                        o.copy_from_slice(&px[..3]);
                    }
                } else {
                    for (px, o) in src.chunks_exact(b).zip(dst.chunks_exact_mut(len)) {
                        o[0] = px[r];
                        o[1] = px[g];
                        o[2] = px[bl];
                    }
                }
            }
        } else {
            for y in 0..rect.height {
                for x in 0..rect.width {
                    let rgb = pixels.rgb(x, y)?;
                    tight_pixel(&mut packed, &rgb, pixels.raw(x, y), len);
                }
            }
        }

        // The control byte first: `(stream << 4)` with stream 0 and no explicit
        // filter, so 0x00. Written before the threshold test because it is part of
        // the rectangle either way.
        let mut out = vec![0u8];
        // `tight_compress_data`'s own threshold: under twelve bytes of data go
        // out as they are, because a decoder can work that out from the
        // rectangle's dimensions and a length in front of them would be one byte
        // more than the data it describes.
        if packed.len() < tight::MIN_TO_COMPRESS {
            out.extend_from_slice(&packed);
            return Some(out);
        }
        // **A fixed four-byte header, written after the compression, so the
        // payload is never copied.**
        //
        // `out` above holds the control byte and nothing else, and the length that
        // has to follow it is the compressed length -- which is not known until the
        // compression has happened. So the stream is compressed *after* four
        // reserved bytes, and the header is written into them once the length is.
        //
        // The compact length is then always three bytes rather than one, two or
        // three. That is legal for any value under 2^22 and costs two bytes on the
        // wire, and QEMU writes three bytes for anything over 16 KB anyway -- so
        // every viewer already meets the three-byte form on nearly every rectangle
        // this server sends.
        //
        // 2^22 is QEMU's own ceiling: `tight_send_compact_size` writes
        // `(len >> 14) & 0xFF` with no fourth byte, so it cannot express a larger
        // payload either. This is at parity, not past it -- and anything above the
        // ceiling takes the old shape rather than truncating the length, which
        // would be worse than being long.
        const HEADER: usize = 1 + 3;
        let mut out = self.tight_basic.compress_prefixed(HEADER, &packed);
        let n = out.len() - HEADER;
        if n < 1 << 22 {
            out[0] = 0x00;
            out[1] = (n & 0x7f) as u8 | 0x80;
            out[2] = ((n >> 7) & 0x7f) as u8 | 0x80;
            out[3] = ((n >> 14) & 0xff) as u8;
            return Some(out);
        }
        let mut head = vec![0x00];
        compact_size(n, &mut head);
        head.extend_from_slice(&out[HEADER..]);
        Some(head)
    }

    /// The lossy JPEG encoding, sent as a Tight rectangle with the JPEG bit
    /// set. Only available with the `lossy` cargo feature.
    #[cfg(feature = "lossy")]
    pub fn encode_jpeg(
        &mut self,
        data: &[u8],
        format: &PixelFormat,
        stride: usize,
        rect: Rect,
    ) -> Option<Vec<u8>> {
        let jpeg = self.lossy.as_ref()?;
        let jpeg = jpeg.encode(data, format, stride, rect)?;
        let mut stream = vec![0x28]; // stream reset | JPEG
        let length = jpeg.len().min(0xff_ffff);
        stream.push((length >> 16) as u8);
        stream.push((length >> 8) as u8);
        stream.push(length as u8);
        stream.extend_from_slice(&jpeg);
        Some(self.tight.compress(&stream))
    }
}

#[cfg(feature = "lossy")]
impl Jpeg {
    /// Encode a rectangle as a JPEG image.
    fn encode(
        &self,
        data: &[u8],
        format: &PixelFormat,
        stride: usize,
        rect: Rect,
    ) -> Option<Vec<u8>> {
        use image::ExtendedColorType;
        use image::ImageEncoder;
        use image::codecs::jpeg::JpegEncoder;

        let pixels = RectPixels::new(data, format, stride, rect);
        let mut rgb = Vec::with_capacity(rect.width as usize * rect.height as usize * 3);
        for y in 0..rect.height {
            for x in 0..rect.width {
                rgb.extend_from_slice(&pixels.rgb(x, y)?);
            }
        }
        let mut out = Vec::new();
        JpegEncoder::new_with_quality(&mut out, self.quality)
            .write_image(
                &rgb,
                rect.width as u32,
                rect.height as u32,
                ExtendedColorType::Rgb8,
            )
            .ok()?;
        Some(out)
    }
}

/// How well a client is keeping up, and therefore how much we should try to
/// compress.
///
/// This is the same idea as QEMU's `update_counter`, a running estimate of how
/// many bytes per second the client manages to read: the encodings trade CPU
/// for bandwidth, so a client on a slow link is better served with less
/// compression than with a server that spends all its time in zlib.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// The best level the client supports.
    ceiling: u8,
    /// The current level: 0 is raw, and the highest is the best encoding
    /// the client supports.
    level: u8,
    /// The bytes per second the client read on the last update.
    bandwidth: u64,
    /// How many updates in a row went well, before we try to go back up.
    good: u8,
    /// The level an encoder refused to produce, i.e. the first one that can
    /// not handle the content of this client.
    refused: Option<u8>,
    /// The compression level the client asked for with the -254 pseudo-encoding,
    /// which caps the ceiling however good the link looks. `None` when the
    /// client did not ask, which is most of them.
    wanted: Option<u8>,
    /// The encoding the client listed first, from QEMU's rule in
    /// [`Policy::preferred_encoding`]. `None` when it offered nothing encodable.
    ///
    /// This port used to have no such field and to prefer ZRLE whenever ZRLE was
    /// on offer, which is a decision about compression rather than about what the
    /// client asked for. RFB says the list is in order of preference and QEMU
    /// takes the first entry it recognises; the production viewer lists Tight
    /// before ZRLE and was served ZRLE.
    preferred: Option<Codec>,
}

/// The quality levels, from the cheapest to the best compression.
const LEVEL_RAW: u8 = 0;
const LEVEL_HEXTILE: u8 = 1;
const LEVEL_ZRLE: u8 = 2;
const LEVEL_TIGHT: u8 = 3;

/// A client reading slower than this, in bytes per second, is too slow to be
/// worth compressing for. It is well under any real link, and only a saturated
/// or stalled client falls below it.
const MIN_BANDWIDTH: u64 = 64 * 1024;

/// A client is also considered too slow when writing an update takes longer
/// than this, whatever the byte count: the socket is not draining.
const TOO_SLOW: Duration = Duration::from_millis(50);

impl Policy {
    /// A policy that starts at the best level.
    pub fn new() -> Self {
        Self {
            ceiling: LEVEL_TIGHT,
            level: LEVEL_TIGHT,
            bandwidth: u64::MAX,
            good: 0,
            refused: None,
            wanted: None,
            preferred: None,
        }
    }

    /// The compression level the client asked for, from the -254
    /// pseudo-encoding: 0 is no compression at all, and the client should get
    /// raw pixels for it.
    ///
    /// QEMU takes this as `vs->tight.compression` and clamps it to its own
    /// table. Ignoring it is not merely unhelpful: a client that asks for no
    /// compression because it is on a slow link, or is trying to work around a
    /// decoder it does not like, gets the exact opposite of what it asked for.
    pub fn want_compression(&mut self, level: u8) {
        self.wanted = Some(level);
    }

    /// Note which encoding the client listed first.
    pub fn prefer_encoding(&mut self, codec: Option<Codec>) {
        self.preferred = codec;
    }
    /// The codec to use, given what the client listed first.
    ///
    /// **The client's preference wins, and the ladder is only the fallback.**
    ///
    /// It used to be the other way round: the ladder's top rung, and a comment
    /// recording that Tight used to be the top rung on the assumption that "a
    /// better compression is a better encoding". RFB does not say that. The list
    /// is in order of preference, QEMU takes the first entry it has a case for,
    /// and this port was overriding a client's stated preference with its own
    /// opinion about which codec compresses better.
    ///
    /// The ladder still applies when the preferred encoder **declines** -- which
    /// is what happens on this port's own Tight for anything with more than 256
    /// colours, because the fill and palette sub-encodings are all it implements.
    /// Video, which is most of what a desktop shows, declines, and the update
    /// goes out as ZRLE. So this change is a correctness fix that is invisible on
    /// the production content, and saying otherwise would be selling it.
    pub fn codec_for_preference(
        &self,
        level: u8,
        offered: &HashSet<Encoding>,
        lossy: bool,
    ) -> Codec {
        match self.preferred {
            Some(Codec::Jpeg) | Some(Codec::Tight) if !lossy && offered.contains(&Encoding::Tight) => {
                Codec::Tight
            }
            Some(Codec::Zrle) if offered.contains(&Encoding::Zrle) => Codec::Zrle,
            Some(Codec::Zlib) if offered.contains(&Encoding::Zlib) => Codec::Zlib,
            Some(Codec::Raw) => Codec::Raw,
            _ => Self::codec(level, offered, lossy),
        }
    }


    /// The current quality level, from 0 (raw) to 3 (the best encoding).
    pub fn level(&self) -> u8 {
        self.level
    }

    /// Note that an encoder could not produce what was asked of it, so that
    /// the next rectangles are sent with a cheaper one.
    ///
    /// The Tight palette only holds 256 colours, so a photographic rectangle
    /// is one it has to refuse rather than mangle.
    fn refuse(&mut self, codec: Codec) {
        let level = match codec {
            Codec::Jpeg | Codec::Tight => LEVEL_TIGHT,
            Codec::Zrle => LEVEL_ZRLE,
            Codec::Zlib => LEVEL_HEXTILE,
            Codec::Raw => return,
        };
        self.refused = Some(self.refused.map_or(level, |known: u8| known.min(level)));
        self.level = self.level.min(self.refused.unwrap_or(u8::MAX) - 1);
    }

    /// The last bandwidth estimate, in bytes per second.
    pub fn bandwidth(&self) -> u64 {
        self.bandwidth
    }

    /// Adapt to how fast the client reads.
    ///
    /// `bytes` is the size of the update, `written` how long we spent writing
    /// it, and `since_last` how long the guest waited between the two updates.
    /// Both signals are needed: a client that reads 2 KiB/s needs less
    /// compression even though each write is quick, and a client whose socket
    /// has stopped draining needs less even though the link is fast.
    pub fn record(&mut self, bytes: usize, written: Duration, since_last: Duration) {
        let interval = since_last.max(TOO_SLOW);
        // A write that took less than a millisecond is not something we can
        // measure a rate with, so the previous estimate is kept.
        if written >= Duration::from_millis(1) {
            self.bandwidth = (bytes as u64 * 1000) / written.as_millis() as u64;
        }
        if written > interval || self.bandwidth < MIN_BANDWIDTH {
            // Too slow: fall back, and forget the good runs.
            self.level = self.level.saturating_sub(1);
            self.good = 0;
        } else if written * 2 < interval {
            // Comfortably keeping up: try to go back up after a few updates,
            // so that one slow frame does not degrade a good client.
            self.good += 1;
            if self.good >= 3 && self.level < self.ceiling {
                self.level += 1;
                self.good = 0;
            }
        } else {
            self.good = 0;
        }
        self.level = self.level.min(self.ceiling);
    }

    /// The encoding to use for `rect`.
    pub fn choose(
        &mut self,
        offered: &HashSet<Encoding>,
        format: &PixelFormat,
        rect: Rect,
        lossy: bool,
    ) -> Codec {
        self.ceiling = Self::ceiling_of(offered, format, rect);
        // What the client asked for wins over what it can take: a client that
        // says it wants no compression gets raw pixels even when the link is
        // fast and the encodings are on offer.
        if let Some(wanted) = self.wanted {
            self.ceiling = self.ceiling.min(Self::ceiling_of_level(wanted));
        }
        self.level = self.level.min(self.ceiling);
        if let Some(refused) = self.refused {
            self.level = self.level.min(refused.saturating_sub(1));
        }
        // **A level of 0 is raw pixels, whatever else the client said it would
        // take.** `codec_for_preference` below answers a different question —
        // which of the encodings the client listed it would *rather* have — and
        // its preferred arms never consult `level` at all. So a client that
        // listed Tight first and asked for no compression was given Tight, which
        // is the opposite of the request: `want_compression` says so in as many
        // words, and the comment three lines above this one repeats it.
        //
        // This is a regression and not a trade-off. `codec_for_preference` was
        // introduced to stop the ladder overriding a client's stated *encoding*
        // preference, and in doing so it overrode the one instruction that
        // outranks a preference. Two tests had been passing before that change
        // and failed after it; they are in `tests/mock.rs` as
        // `a_client_that_asks_for_no_compression_gets_raw_pixels` and
        // `a_client_that_asks_for_no_compression_is_never_given_any`.
        if self.wanted == Some(0) {
            return Codec::Raw;
        }
        let lossy = lossy && Self::lossy_offered(offered, rect);
        self.codec_for_preference(self.level, offered, lossy)
    }

    /// The best level the client can be served with.
    fn ceiling_of(offered: &HashSet<Encoding>, format: &PixelFormat, rect: Rect) -> u8 {
        // Tiny rectangles: the zlib header is larger than what it saves.
        if u32::from(rect.width) * u32::from(rect.height) < MIN_COMPRESSED_PIXELS {
            return LEVEL_RAW;
        }
        let mut ceiling = LEVEL_RAW;
        if offered.contains(&Encoding::Zrle) && Codec::Zrle.supports(format) {
            ceiling = LEVEL_ZRLE;
        }
        // Encoding 6, not 5: hextile sub-encodings inside a zlib stream.
        if offered.contains(&Encoding::Zlib) && Codec::Zlib.supports(format) {
            ceiling = ceiling.max(LEVEL_HEXTILE);
        }
        // QEMU refuses encoding 6 to a client that can have ZRLE, and the
        // refusal belongs in `codec`, not here. It was tried here first, on the
        // reasoning that the ladder should not have a rung for an encoding we
        // will not send — and that change was a no-op, which a mutation check
        // found by *not* failing when the change was reverted. `LEVEL_ZRLE` is
        // 2 and `LEVEL_HEXTILE` is 1, so with ZRLE available the ceiling is
        // already above the zlib rung and a `max` cannot lower it. There was
        // never anything to remove.
        // Tight is a rung only when there is nothing better, and on this
        // crate's measurements there is almost never nothing better.
        //
        // It used to be the *top* rung, above ZRLE, on the assumption that a
        // better compression is a better encoding. Measured, on a 1280x800 frame
        // with the level a real viewer asks for:
        //
        // ```text
        //   content                     zrle    tight
        //   hundreds of colours/tile   25.8 ms  25.8 ms   <- Tight declines
        //   sixteen colours/tile        12.8 ms  37.4 ms   <- and is 2.9x slower
        //   bytes, sixteen colours        6845     12167   <- and 1.8x larger
        // ```
        //
        // The first row is the same encode twice: `encode_tight` gives up on a
        // tile with more than 256 colours and `Codec::Tight`'s fallback is
        // `Codec::Zrle`, so the Tight column there is ZRLE's work plus a wasted
        // attempt. The second row is Tight succeeding, and losing on both axes —
        // it is Pareto-dominated by ZRLE on everything measured here.
        //
        // So the ladder now stops at ZRLE for a client that can have it, and
        // Tight is reached only when ZRLE is not on offer. This is the same shape
        // of rule QEMU states for zlib against ZRLE — "prioritise ZRLE, even if
        // the client hints that it prefers ZLIB" — extended to Tight, and here
        // on measurements rather than on a comment.
        //
        // `MIN_TIGHT_RECT` stays, and the reason is a measurement rather than an
        // omission: a 1280x13 strip costs 0.3 ms in *every* codec including
        // JPEG, because thirteen rows is nothing to compress. So excluding Tight
        // from thin rectangles costs nothing, and the threshold was never what
        // was making strips expensive.
        if ceiling < LEVEL_ZRLE
            && offered.contains(&Encoding::Tight)
            && Codec::Tight.supports(format)
            && rect.width >= MIN_TIGHT_RECT
            && rect.height >= MIN_TIGHT_RECT
        {
            ceiling = LEVEL_TIGHT;
        }
        ceiling
    }

    /// The best *codec* a client asking for `level` compression should get.
    ///
    /// **This is not the deflate level, and it is not trying to be.** The -254
    /// pseudo-encoding carries a zlib level from 0 to 9, and
    /// [`Encoders::set_deflate_level`] is where that number goes, because that
    /// is what QEMU does with it. What is left here is the one thing a level
    /// can also mean to a codec ladder, and only one case of it is an answer:
    /// 0, no compression, and the cheapest honest reply to that is the encoding
    /// that is not compression. Everything from 1 to 9 is "please compress",
    /// and all of it means the same thing to a codec, so none of it narrows the
    /// ceiling.
    ///
    /// The distinction is written down because this function used to read as
    /// though the two were the same axis: it mapped a requested 1-to-9 onto
    /// `LEVEL_TIGHT`, a rung of this crate's own ladder, which is a true fact
    /// about a number that means something else entirely.
    fn ceiling_of_level(level: u8) -> u8 {
        if level == 0 { LEVEL_RAW } else { LEVEL_TIGHT }
    }

    /// Whether the client asked for a lossy encoding, and the rectangle is
    /// big enough for it to be worth the artefacts.
    fn lossy_offered(offered: &HashSet<Encoding>, rect: Rect) -> bool {
        let jpeg = offered
            .iter()
            .any(|e| matches!(e, Encoding::Jpeg(_) | Encoding::TightPng));
        jpeg && rect.width >= 128 && rect.height >= 128
    }

    /// The codec of a level.
    ///
    /// Encoding 6 is reachable only when there is no ZRLE to reach for, which
    /// is QEMU's rule again — and it is repeated here rather than left to rest
    /// on `ceiling_of`. That is not redundancy for its own sake: the level
    /// adapts downwards on its own, from how well the last frame compressed, so
    /// a ladder whose *rungs* exclude encoding 6 is still a ladder that can be
    /// standing on a rung which yields it. Putting the rule on the choice as
    /// well means the choice is right whatever the level turns out to be.
    ///
    /// The rung that would have been zlib's goes to ZRLE rather than to raw,
    /// because ZRLE compresses better than zlib — QEMU says so — so sending raw
    /// there would cost ten times the bandwidth to express a disagreement
    /// nobody has.
    /// The encoding QEMU would pick from a client's ordered `SetEncodings`.
    ///
    /// **This is QEMU's rule, exactly, because the rule is the whole of it.**
    /// `set_encodings` walks the list **from the end** and assigns
    /// `vs->vnc_encoding` on every `case` it recognises, so the value that
    /// survives is the one belonging to the **smallest** index that had a case
    /// at all — the client's first real encoding. The comment above QEMU's loop
    /// says so: "the encodings are sent in order of preference".
    ///
    /// The subtlety is the direction. A loop that returned the first match while
    /// walking backwards would give the client's *last* encoding, and on the
    /// production viewer's list that is Raw (index 9), which is the opposite of
    /// what QEMU serves. The check below is written as the assignment list it
    /// produces rather than as "first match", because that is the shape the C
    /// has and the shape that is easy to get backwards.
    ///
    /// The production client sends, in order:
    ///
    /// ```text
    /// [1, 50, 7, -260, 16, 21, 5, 2, 6, 0, -26, -254, -223, -224, ...]
    /// ```
    ///
    /// and the assignments the loop makes, from the end backwards, are
    /// `i=9 Raw`, `i=8 zlib`, `i=6 Hextile`, `i=4 ZRLE`, `i=3 TightPNG`,
    /// `i=2 Tight` — so **Tight** is what survives. Only CopyRect (1) and 50 come
    /// before it, and neither has a case in `set_encodings`.
    ///
    /// `None` when the client offered nothing this port can encode, which is a
    /// real possibility: a client whose whole list is pseudo-encodings has said
    /// nothing about how it wants pixels and falls to raw.
    pub fn preferred_encoding(encodings: &[Encoding]) -> Option<Codec> {
        // The encodings QEMU's `set_encodings` assigns `vnc_encoding` for. CopyRect
        // (1) is absent because it is always available rather than chosen, and
        // RRE (2), Ultra (21) and TRLE (15) are absent because QEMU removed them
        // and this port never had them.
        fn codec_for(encoding: &Encoding) -> Option<Codec> {
            match encoding {
                Encoding::Raw => Some(Codec::Raw),
                Encoding::Zlib => Some(Codec::Zlib),
                Encoding::Zrle => Some(Codec::Zrle),
                // TightPNG maps to Tight: this port has no PNG encoder, so a
                // client that prefers it gets Tight, which is the same
                // sub-encoding family without the PNG sub-encoding.
                //
                // **ZYWRLE (17) is absent and that is a real gap, not an
                // oversight.** QEMU's `set_encodings` has a case for it and would
                // serve it, and this port declined to implement it on a
                // measurement. A client whose list puts 17 first would therefore
                // get Tight here and ZYWRLE from QEMU. The production client's
                // list does not contain 17, so it does not bite there, and the
                // encoder would in any case have to decline content Tight can not
                // represent -- which is most of what ZYWRLE exists for.
                Encoding::Tight | Encoding::TightPng => Some(Codec::Tight),
                _ => None,
            }
        }

        // Walking the list backwards and keeping every assignment is what the C
        // loop does; the last one kept is the client's first real encoding.
        let mut winner = None;
        for encoding in encodings.iter().rev() {
            if let Some(codec) = codec_for(encoding) {
                winner = Some(codec);
            }
        }
        winner
    }

    fn codec(level: u8, offered: &HashSet<Encoding>, lossy: bool) -> Codec {
        match level {
            LEVEL_TIGHT if offered.contains(&Encoding::Tight) && lossy => Codec::Jpeg,
            LEVEL_TIGHT if offered.contains(&Encoding::Tight) => Codec::Tight,
            LEVEL_ZRLE if offered.contains(&Encoding::Zrle) => Codec::Zrle,
            LEVEL_HEXTILE if offered.contains(&Encoding::Zlib) && !offered.contains(&Encoding::Zrle) => {
                Codec::Zlib
            }
            LEVEL_HEXTILE if offered.contains(&Encoding::Zrle) => Codec::Zrle,
            _ => Codec::Raw,
        }
    }

}

/// The encoding QEMU would pick from a client's ordered `SetEncodings`.
///
/// See [`Policy::preferred_encoding`], which is where the reasoning and the
/// worked example are. This is a thin re-export so that a client handler can ask
/// without building a policy first.
pub fn preferred_encoding(encodings: &[Encoding]) -> Option<Codec> {
    Policy::preferred_encoding(encodings)
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offered(encodings: &[Encoding]) -> HashSet<Encoding> {
        encodings.iter().cloned().collect()
    }

    /// The packing fast path must agree with the general path, for every pixel
    /// format.
    ///
    /// **`tight_full_color` has two loops**: a `copy_from_slice` taken when the
    /// client's format is three bytes in the first three of four -- which is what
    /// the production viewer asks for, `red_shift 0, green_shift 8, blue_shift
    /// 16` -- and a general three-indexed-write loop for everything else.
    ///
    /// **And the fast path is what production runs on while every other test runs
    /// the other one.** The server's default format is `red_shift 16, green_shift
    /// 8, blue_shift 0`, which is the *other* byte order, so a client that does not
    /// send a `SetPixelFormat` -- which is every client in this file, and the
    /// witness, which negotiates from `vnc-rs`'s own default -- never reaches the
    /// fast path at all.
    ///
    /// Found by mutation: swapping red and blue in the fast path left every witness
    /// test green. The fast path had no coverage on the day it was written, and a
    /// wrong colour order in it would have reached a real viewer with nothing in
    /// this crate saying so.
    ///
    /// Two fixtures were wrong before this one, and both failed silently:
    ///
    /// - **Too few colours.** A 3x2 rectangle has at most six, so Tight answered
    ///   with fill and a palette and never entered the loop under test. The control
    ///   byte came back `0x60`; that is the only reason it was noticed.
    /// - **Too few pixels to stay uncompressed.** Past `MIN_TO_COMPRESS` the
    ///   payload comes back deflated, so it has to be inflated before it can be
    ///   compared. 32x32 of noise clears both conditions at once.
    #[test]
    fn the_tight_packing_is_the_same_whichever_loop_runs() {
        let (w, h) = (32u16, 32u16);
        let stride = usize::from(w) * 4;
        let n_pixels = usize::from(w) * usize::from(h);
        // Well over 256 colours, and neither a grid nor a gradient.
        let pixels: Vec<u8> = {
            let mut v = Vec::with_capacity(stride * usize::from(h));
            let mut x = 0x1234_5678u32;
            while v.len() < stride * usize::from(h) {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                v.push((x >> 16) as u8);
                v.push((x >> 8) as u8);
                v.push(x as u8);
                v.push(0);
            }
            v
        };
        assert!(
            n_pixels > 256,
            "a {w}x{h} rectangle cannot have more than {n_pixels} colours, so Tight \
             will use fill or a palette instead of the full-colour packing"
        );

        let rect = Rect::new(0, 0, w, h);
        let all = HashSet::new();

        for (r, g, b) in [(0u8, 8u8, 16u8), (16, 8, 0), (0, 16, 8), (8, 0, 16), (16, 0, 8)] {
            let format = PixelFormat {
                bits_per_pixel: 32,
                depth: 24,
                big_endian: false,
                true_colour: true,
                red_max: 255,
                green_max: 255,
                blue_max: 255,
                red_shift: r,
                green_shift: g,
                blue_shift: b,
            };
            let mut encoders = Encoders::new(None);
            let (_codec, out) = encoders
                .encode(Codec::Tight, &all, &pixels, &format, stride, rect)
                .expect("Tight accepts a 32-bit true-colour client");

            // Full colour: stream 0, no fill, no filter, so 0x00 and nothing else.
            assert_eq!(
                out[0], 0x00,
                "red_shift {r} green_shift {g} blue_shift {b}: control byte is \
                 {:#04x}, so Tight chose fill or a filter and never reached the \
                 packing loop this test is about",
                out[0]
            );

            // **Not `read_to_end`.** The zlib stream is persistent, one per
            // connection, flushed with `Z_SYNC_FLUSH` and deliberately left
            // without a trailer -- so a reader that waits for the end of the
            // stream is waiting for something that never comes, and reports
            // "incomplete deflate stream". The expected length is known, so the
            // stream is fed once and truncated to what came out.
            let (declared, at) = read_compact(&out[1..]);
            let body = &out[1 + at..1 + at + declared];
            let mut packed = vec![0u8; n_pixels * 3];
            let mut d = flate2::Decompress::new(true);
            d.decompress(body, &mut packed, flate2::FlushDecompress::None)
                .expect("the payload inflates");
            packed.truncate(d.total_out() as usize);
            assert_eq!(
                packed.len(),
                n_pixels * 3,
                "red_shift {r} green_shift {g} blue_shift {b}: inflated to {} bytes",
                packed.len()
            );

            // Written from the format, not from the code: three bytes a pixel,
            // taken from the source at the client's own shifts.
            let mut expected = Vec::with_capacity(n_pixels * 3);
            for y in 0..h as usize {
                for x in 0..w as usize {
                    let o = y * stride + x * 4;
                    expected.push(pixels[o + r as usize / 8]);
                    expected.push(pixels[o + g as usize / 8]);
                    expected.push(pixels[o + b as usize / 8]);
                }
            }

            assert_eq!(
                packed,
                expected,
                "red_shift {r} green_shift {g} blue_shift {b}: the packed bytes \
                 disagree with the format. If that is the fast path, the condition \
                 admitting it does not describe the transform it performs."
            );
        }
    }

    /// Tight wins the client's preference again.
    ///
    /// **This had no test at all until the gate was removed**, which is worth
    /// noting rather than hiding: `prefer_encoding` was the one place in the
    /// encoder's public surface where nothing checked what came out, so taking the
    /// bar away changed production behaviour and the suite reported `ok` -- which
    /// is indistinguishable from taking the bar away and having done nothing.
    ///
    /// So the gate is pinned from both sides. Tight is chosen when the client
    /// offers it, and JPEG is still not, because JPEG is lossy and no independent
    /// decoder has ever read it.
    #[test]
    fn tight_wins_the_preference_again_and_jpeg_still_does_not() {
        // Ask through the real path -- `choose`, on a screen-sized rectangle --
        // rather than the preference directly, because `choose` is what a client
        // sees and it is what would go on emitting ZRLE behind a closed gate.
        let screen = PixelFormat {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        };
        let rect = Rect::new(0, 0, 1280, 800);
        let chosen = |encoders: &mut Encoders, list: &[Encoding]| {
            encoders.prefer_encoding(list);
            encoders.choose(&offered(list), &screen, rect)
        };

        let mut encoders = Encoders::new(None);
        assert_eq!(
            chosen(&mut encoders, &[Encoding::Tight, Encoding::Zrle]),
            Codec::Tight,
            "Tight was not taken when the client asked for it first, so the gate is \
             still closed and the whole compact-length fix would go unused in \
             production"
        );

        // QEMU's rule is the client's *first* recognised encoding -- `set_encodings`
        // walks its list from the end, so the last assignment wins and that is the
        // earliest entry. Both directions are pinned, because "Tight was not taken"
        // and "Tight always wins" fail the same way and only the pair separates
        // them.
        assert_eq!(
            chosen(&mut encoders, &[Encoding::Zrle, Encoding::Tight]),
            Codec::Zrle,
            "ZRLE first must win over Tight second, or this test would pass with a \
             ladder that always returns Tight"
        );
        assert_eq!(
            chosen(&mut encoders, &[Encoding::Zrle, Encoding::Raw]),
            Codec::Zrle,
            "ZRLE must still win when it comes first"
        );

        // JPEG stays out. It is the same encoding number as Tight with a bit set,
        // so it needs its own bar rather than inheriting Tight's -- and note this
        // is the `lossy` feature off, so `choose` cannot return it anyway. What is
        // pinned here is that a JPEG-only offer does not drag Tight along with it.
        assert_eq!(
            chosen(&mut encoders, &[Encoding::Jpeg(0)]),
            Codec::Raw,
            "a JPEG-only offer fell back to something other than raw, so the bar \
             did not simply decline"
        );
    }

    /// The compact length is three bytes wide and never four.
    ///
    /// **This is the test that was missing while two decoders rejected our Tight
    /// and our own decoder agreed with us.** Everything below the threshold is
    /// identical between the three-byte form and the four-byte form the code used
    /// to write, so every existing test -- and the 64x32 witness, which compresses
    /// to about six kilobytes -- passed. The first shape that distinguishes them is
    /// 2,097,152, which at Tight's level 0 is a 699,050 pixel rectangle: 1024x684.
    ///
    /// QEMU's `tight_send_compact_size` decides the width with `len > 0x7F` and
    /// `len > 0x3FFF`, and the third byte is `(len >> 14) & 0xFF` -- eight bits,
    /// with no continuation bit, because there is no fourth byte to point at. So
    /// the field is 22 bits wide and stops at 0x3F_FFFF.
    #[test]
    fn a_compact_length_is_three_bytes_wide_and_the_third_is_a_whole_byte() {
        // Boundaries, and the real production payload in the middle.
        for len in [
            0usize,
            1,
            0x7f,       // the last one-byte length
            0x80,       // the first two-byte
            0x3fff,     // the last two-byte
            0x4000,     // the first three-byte
            0x1f_ffff,  // what the old four-byte loop treated as its largest three
            0x1f_ffff + 1, // **the first value the two forms disagree about**
            0x3f_ffff,  // the largest length the field can hold
            3_072_247,  // 1280x800 full-colour at level 0: what actually broke
        ] {
            let mut out = Vec::new();
            compact_size(len, &mut out);
            assert!(
                out.len() <= 3,
                "a compact length for {len} took {} bytes: {out:02x?}, and a decoder \\
                 stops at three",
                out.len()
            );
            let (back, at) = read_compact(&out);
            assert_eq!(at, out.len(), "read {len} back using {at} of {} bytes", out.len());
            assert_eq!(back, len, "a compact length for {len} reads back as {back}");
        }

        // The disagreement, spelled out. QEMU writes three bytes here and this
        // test says so independently of `compact_size`, so a regression that
        // changes the width cannot also change the expectation.
        // 2,097,152 is 0x20_0000: bits 21 and up are zero, so the third byte is
        // 0x80 -- whose top bit is set, and which is why the reader has to be
        // keyed on the first two bytes rather than on a clear top bit.
        assert_eq!(qemu_compact_size(0x1f_ffff + 1), vec![0x80, 0x80, 0x80]);
        // The real one, and QEMU's bytes for it: 3,072,247 = 0x2E_E377.
        assert_eq!(qemu_compact_size(3_072_247), vec![0xf7, 0xc1, 0xbb]);
        assert_eq!(qemu_compact_size(0x3f_ffff), vec![0xff, 0xff, 0xff]);
    }

    /// QEMU's `tight_send_compact_size`, line for line, kept beside ours so the
    /// transcription can be compared rather than trusted.
    fn qemu_compact_size(len: usize) -> Vec<u8> {
        let mut buf = [0u8; 3];
        let mut bytes = 0usize;
        buf[bytes] = (len & 0x7F) as u8;
        bytes += 1;
        if len > 0x7F {
            buf[bytes - 1] |= 0x80;
            buf[bytes] = ((len >> 7) & 0x7F) as u8;
            bytes += 1;
            if len > 0x3FFF {
                buf[bytes - 1] |= 0x80;
                buf[bytes] = ((len >> 14) & 0xFF) as u8;
                bytes += 1;
            }
        }
        buf[..bytes].to_vec()
    }

    #[test]
    fn compact_size_matches_qemu_over_its_whole_range() {
        for len in (0usize..0x4_0000).step_by(7) {
            let mut ours = Vec::new();
            compact_size(len, &mut ours);
            assert_eq!(
                ours,
                qemu_compact_size(len),
                "compact_size disagrees with QEMU at {len}"
            );
        }
        for len in [0x3f_ffff, 0x3f_fffe, 1 << 20, 3_072_247, 4_194_303] {
            let mut ours = Vec::new();
            compact_size(len, &mut ours);
            assert_eq!(ours, qemu_compact_size(len), "disagrees at {len}");
        }
    }

    fn xrgb() -> PixelFormat {
        PixelFormat {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        }
    }

    fn rect(width: u16, height: u16) -> Rect {
        Rect::new(0, 0, width, height)
    }

    #[test]
    fn a_client_that_asks_for_no_compression_gets_raw() {
        // The -254 pseudo-encoding carries a zlib level, and 0 means none. A
        // client that says so gets raw pixels however good the link looks and
        // however many encodings it announced, which is the one thing it can
        // ask for when a compressed rectangle is what it cannot decode.
        let all = offered(&[Encoding::Zrle, Encoding::Zlib, Encoding::Tight]);
        let mut policy = Policy::new();
        policy.want_compression(0);
        assert_eq!(policy.choose(&all, &xrgb(), rect(640, 480), false), Codec::Raw);

        // One to nine all mean "please compress", and are left to the policy to
        // interpret. What it picks is ZRLE, not Tight: Tight is the top rung
        // only for a client that cannot have ZRLE, because on the measurements
        // in `ceiling_of` it is slower *and* larger than ZRLE wherever it can
        // represent the content at all. This assertion said Tight, and was
        // asserting the bug the other way round — a test written to match the
        // code rather than to match the format is worth exactly nothing when
        // the code is what is wrong.
        for level in 1..=9u8 {
            let mut policy = Policy::new();
            policy.want_compression(level);
            assert_eq!(
                policy.choose(&all, &xrgb(), rect(640, 480), false),
                Codec::Zrle,
                "level {level} should still compress"
            );
        }
    }

    #[test]
    fn a_client_that_only_wants_raw_gets_raw() {
        let mut policy = Policy::new();
        assert_eq!(
            policy.choose(&offered(&[Encoding::Raw]), &xrgb(), rect(640, 480), false),
            Codec::Raw
        );
    }

    #[test]
    fn the_best_supported_encoding_is_used() {
        let mut policy = Policy::new();
        let all = offered(&[
            Encoding::Raw,
            Encoding::Zlib,
            Encoding::Zrle,
            Encoding::Tight,
        ]);
        // A big rectangle, and ZRLE — not Tight, which used to be the top rung
        // on the assumption that better compression is a better encoding.
        // Measured on 1280x800: where Tight can represent the content it is
        // 2.9x slower than ZRLE and 1.8x larger, and where it cannot it
        // declines and `Codec::Tight`'s fallback hands the work to ZRLE anyway.
        // So the ladder stops at ZRLE for a client that can have it.
        assert_eq!(
            policy.choose(&all, &xrgb(), rect(640, 480), false),
            Codec::Zrle
        );
        // Without Tight on offer, the same answer, for a different reason.
        let no_tight = offered(&[Encoding::Raw, Encoding::Zlib, Encoding::Zrle]);
        assert_eq!(
            policy.choose(&no_tight, &xrgb(), rect(640, 480), false),
            Codec::Zrle
        );
        // And without ZRLE, hextile — unless the client can do ZRLE, which by
        // now it cannot, since ZRLE is not on offer.
        let hextile = offered(&[Encoding::Raw, Encoding::Zlib]);
        assert_eq!(
            policy.choose(&hextile, &xrgb(), rect(640, 480), false),
            Codec::Zlib
        );
        // A client that can only have Tight still gets it, so capping the ladder
        // does not cost the codec: it moves the rung rather than removing it.
        //
        // A *fresh* policy, because a `Policy` is per-client — it holds one
        // client's adaptation state — and the level left by the previous case
        // was 1, which is below Tight's rung, so the shared policy answered
        // `Raw`. Four hypothetical clients want four policies; the earlier
        // assertions happened to agree only because the level had been
        // clamping downwards the whole way.
        let only_tight = offered(&[Encoding::Raw, Encoding::Tight]);
        let mut policy = Policy::new();
        assert_eq!(
            policy.choose(&only_tight, &xrgb(), rect(640, 480), false),
            Codec::Tight,
            "a client that offers Tight and nothing else compressed must still get \
             something compressed"
        );
    }

    #[test]
    fn a_small_rectangle_stays_raw() {
        let mut policy = Policy::new();
        let all = offered(&[Encoding::Raw, Encoding::Zrle]);
        // 9 pixels: the zlib header alone would be longer than the update.
        assert_eq!(policy.choose(&all, &xrgb(), rect(3, 3), false), Codec::Raw);
    }

    #[test]
    fn a_slow_client_makes_us_compress_less() {
        let mut policy = Policy::new();
        let all = offered(&[Encoding::Raw, Encoding::Zrle]);
        // The first rectangle tells the policy what the client supports, so
        // the ceiling is 2 rather than the best level we could reach.
        assert_eq!(
            policy.choose(&all, &xrgb(), rect(640, 480), false),
            Codec::Zrle
        );
        assert_eq!(policy.level(), 2);
        // The guest updates every 200ms, and writing takes 300ms: give up a
        // level and send hextile instead.
        policy.record(1024, Duration::from_millis(300), Duration::from_millis(200));
        assert_eq!(policy.level(), 1);
        // Comfortably keeping up: after a few updates, try again.
        for _ in 0..3 {
            policy.record(1024, Duration::from_millis(1), Duration::from_millis(100));
        }
        assert_eq!(policy.level(), 2);
    }

    #[test]
    fn the_level_never_goes_above_what_the_client_supports() {
        let mut policy = Policy::new();
        let hextile = offered(&[Encoding::Raw, Encoding::Zlib]);
        // A client that only understands hextile is never sent ZRLE, whatever
        // the adaptation thinks, as long as it is keeping up.
        for _ in 0..20 {
            policy.record(16_384, Duration::from_millis(5), Duration::from_millis(100));
            assert_eq!(
                policy.choose(&hextile, &xrgb(), rect(640, 480), false),
                Codec::Zlib
            );
        }
    }

    #[test]
    fn a_slow_link_degrades_even_when_the_updates_are_small() {
        // A narrow link, where a small update is written in a millisecond:
        // the timing says we have time to spare, but the byte rate is far
        // below anything worth compressing for.
        let mut policy = Policy::new();
        // A client that cannot do ZRLE, so the rung below the top is encoding 6
        // and the ladder has somewhere to go. This is the case the degradation
        // is *for*, and it is why the level ladder exists at all.
        let no_zrle = offered(&[Encoding::Raw, Encoding::Zlib]);
        assert_eq!(
            policy.choose(&no_zrle, &xrgb(), rect(640, 480), false),
            Codec::Zlib
        );
        policy.record(32, Duration::from_millis(1), Duration::from_millis(100));
        assert!(policy.bandwidth() < MIN_BANDWIDTH);
        assert_eq!(
            policy.choose(&no_zrle, &xrgb(), rect(640, 480), false),
            Codec::Raw,
            "a client that can only have encoding 6 should be served raw on a link too \
             narrow to compress for"
        );
    }

    #[test]
    fn a_slow_link_cannot_degrade_a_zrle_client_below_zrle() {
        // The other half, and the reason `a_slow_link_degrades_even_when_the \
        // updates_are_small` had to be rewritten.
        //
        // A client that can do ZRLE has nothing between raw and ZRLE except
        // encoding 6, which QEMU refuses to send it. So on a narrow link the
        // level still drops, and the encoding does not follow: the rung the
        // policy lands on means "cheaper than ZRLE", and there is no such
        // encoding to have. Raw is the alternative, and raw for a thin strip is
        // ten times the bytes of ZRLE — trading a real cost for a distinction
        // no client can act on.
        //
        // Backpressure on a slow link is the update *interval*'s job, not the
        // encoding's, and there is a ladder for that in `REFRESH_BASE` and
        // `REFRESH_INC`. This used to degrade to encoding 6 here, and that is
        // what a production viewer rejected.
        let mut policy = Policy::new();
        let zrle = offered(&[Encoding::Raw, Encoding::Zrle, Encoding::Zlib]);
        assert_eq!(
            policy.choose(&zrle, &xrgb(), rect(640, 480), false),
            Codec::Zrle
        );
        policy.record(32, Duration::from_millis(1), Duration::from_millis(100));
        assert!(policy.bandwidth() < MIN_BANDWIDTH, "the link is narrow");
        assert!(
            policy.level() < 2,
            "the level should have dropped, or this test is not testing a slow link"
        );
        assert_eq!(
            policy.choose(&zrle, &xrgb(), rect(640, 480), false),
            Codec::Zrle,
            "a client that can have ZRLE was served something else on a slow link"
        );
    }

    #[test]
    fn a_slow_client_is_never_served_worse_than_raw() {
        let mut policy = Policy::new();
        let all = offered(&[Encoding::Raw, Encoding::Zrle, Encoding::Tight]);
        for _ in 0..10 {
            policy.record(4096, Duration::from_secs(1), Duration::from_millis(10));
        }
        assert_eq!(policy.level(), 0);
        assert_eq!(
            policy.choose(&all, &xrgb(), rect(640, 480), false),
            Codec::Raw
        );
    }

    #[test]
    fn an_8_bits_client_stays_raw() {
        let mut policy = Policy::new();
        let mut format = xrgb();
        format.bits_per_pixel = 8;
        format.depth = 8;
        let all = offered(&[Encoding::Raw, Encoding::Zrle, Encoding::Zlib]);
        assert_eq!(
            policy.choose(&all, &format, rect(640, 480), false),
            Codec::Raw
        );
    }
}

// The ZRLE wire format, pinned against QEMU's encoder rather than against this
// crate's own decoder, which is how the palette layout got wrong in the first
// place: an encoder and a decoder written from the same reading agree with each
// other and disagree with every real client.
#[cfg(test)]
mod zrle_layout {
    use super::*;

    /// Inflate a zlib stream that has no trailer.
    ///
    /// The encoders flush rather than finishing, as QEMU's
    /// `deflate(zstream, Z_SYNC_FLUSH)` does, so whatever comes out before the
    /// input runs out is the whole of it and the missing checksum is not an
    /// error to complain about.
    fn inflate(data: &[u8]) -> Vec<u8> {
        let mut decompress = flate2::Decompress::new(true);
        let mut out = Vec::with_capacity(64 * 1024);
        loop {
            if out.len() == out.capacity() {
                out.reserve(out.capacity().max(4096));
            }
            let before = out.len();
            // `decompress_vec` never grows the vector, so the spare capacity is
            // what limits it, and a stream with no trailer needs a second call
            // to drain whatever is left.
            let _ = decompress.decompress_vec(data, &mut out, flate2::FlushDecompress::Sync);
            if out.len() == before {
                break;
            }
        }
        out
    }

    fn format() -> PixelFormat {
        PixelFormat {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: false,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        }
    }

    /// The *uncompressed* bytes of a ZRLE rectangle, for a frame of `pixels`:
    /// the tiles, and nothing else. There is no header, so these tests read
    /// from byte zero — which is what makes a spurious one impossible to miss.
    fn encoded(pixels: &[u8], width: u16, height: u16) -> Vec<u8> {
        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width,
            height,
        };
        let mut encoders = Encoders::new(None);
        let (_codec, data) = encoders
            .encode(
                Codec::Zrle,
                &HashSet::from([Encoding::Zrle]),
                pixels,
                &format,
                width as usize * 4,
                rect,
            )
            .expect("the ZRLE encoder");
        inflate(&data)
    }

    /// The bytes of a Tight rectangle, uncompressed where they are sent
    /// uncompressed: only the indexes are ever compressed, and the header in
    /// front of them is not.
    fn tight(pixels: &[u8], width: u16, height: u16) -> Vec<u8> {
        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width,
            height,
        };
        let mut encoders = Encoders::new(None);
        let (_codec, data) = encoders
            .encode(
                Codec::Tight,
                &HashSet::from([Encoding::Tight]),
                pixels,
                &format,
                width as usize * 4,
                rect,
            )
            .expect("the Tight encoder");
        data
    }

    /// A row of `w` pixels alternating between `a` and `b`, x8r8g8b8, so the
    /// colour of a pixel is `[b, g, r, unused]` for the byte triple given.
    fn alternate(width: u16, height: u16, a: [u8; 3], b: [u8; 3]) -> Vec<u8> {
        let mut data = Vec::new();
        for y in 0..height {
            for x in 0..width {
                let rgb = if (x + y) % 2 == 0 { a } else { b };
                data.extend_from_slice(&[rgb[2], rgb[1], rgb[0], 0]);
            }
        }
        data
    }

    /// The *uncompressed* bytes of a hextile rectangle.
    fn hextile(pixels: &[u8], width: u16, height: u16) -> Vec<u8> {
        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width,
            height,
        };
        let mut encoders = Encoders::new(None);
        let (_codec, data) = encoders
            .encode(
                Codec::Zlib,
                &HashSet::from([Encoding::Zlib]),
                pixels,
                &format,
                width as usize * 4,
                rect,
            )
            .expect("the hextile encoder");
        inflate(&data)
    }

    /// Whether the Tight encoder will take a rectangle of this width.
    fn tight_takes(width: u16) -> bool {
        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width,
            height: 1,
        };
        let pixels = vec![0u8; width as usize * 4];
        let mut encoders = Encoders::new(None);
        encoders
            .encode(
                Codec::Tight,
                &HashSet::from([Encoding::Tight]),
                &pixels,
                &format,
                width as usize * 4,
                rect,
            )
            .is_some()
    }

    #[test]
    fn a_tight_palette_counts_a_whole_rectangle() {
        // A flat rectangle the size of a console: the commonest colour is most
        // of a million pixels, which does not fit a `u16` and panicked the
        // client task on a full screen. A count is only ever compared against
        // the palette size, so a wider type costs nothing.
        let (w, h) = (512u16, 300u16);
        // x8r8g8b8 is B, G, R, X in memory, while a Tight pixel is R, G, B —
        // which is note 1 of the header and worth spelling out in a test about
        // a rectangle big enough to overflow a counter.
        let flat = [0x33u8, 0x22, 0x11, 0];
        let other = [0x66u8, 0x55, 0x44, 0];
        let pixels: Vec<u8> = flat.repeat(w as usize * h as usize);
        let bytes = tight(&pixels, w, h);
        // Uniform, so it is a fill rather than a palette at all — the point is
        // that encoding it must not overflow on the way there.
        assert_eq!(bytes, [0x80, 0x11, 0x22, 0x33], "{bytes:02x?}");

        // And a rectangle that is *almost* flat, so it does take the palette
        // path, with one pixel of a second colour in the far corner.
        let mut pixels: Vec<u8> = flat.repeat(w as usize * h as usize);
        let last = (w as usize * h as usize - 1) * 4;
        pixels[last..last + 4].copy_from_slice(&other);
        let bytes = tight(&pixels, w, h);
        assert_eq!(bytes[0], 0x60, "two colours, so a palette");
        assert_eq!(bytes[2], 1, "the colour count, minus one");
    }

    #[test]
    fn a_tight_rectangle_wider_than_2048_pixels_is_declined() {
        // Note 4 of the header: a Tight rectangle may not be wider than 2048
        // pixels and a wider one must be split. Declining it is not what QEMU
        // does — QEMU splits it — but the policy falls back to an encoding
        // with no limit, which is right rather than fast. A guest at 2560 or
        // 3840 across is what reaches this.
        assert!(tight_takes(2048), "2048 is the limit, not over it");
        assert!(!tight_takes(2049));
        assert!(!tight_takes(4096), "a 4K-wide console is declined too");
    }

    #[test]
    fn a_hextile_rectangle_has_no_count_in_front_of_its_tiles() {
        // `vnc_hextile_send_framebuffer_update` writes one `send_tile` after
        // another and each writes a sub-encoding byte and its data. Nothing
        // counts the tiles, because a decoder works that out from the
        // rectangle's dimensions — so the first byte of the stream is the first
        // *tile*, not a count. Sixteen by sixteen is one tile, here solid, so
        // the whole rectangle is a sub-encoding 1 and the pixel that fills it.
        let mut pixels = Vec::new();
        for _ in 0..16 * 16 {
            pixels.extend_from_slice(&[0x56, 0x34, 0x12, 0]);
        }
        let bytes = hextile(&pixels, 16, 16);
        assert_eq!(bytes, [1, 0x56, 0x34, 0x12, 0], "{bytes:02x?}");
    }

    #[test]
    fn a_hextile_raw_tile_is_the_pixels_themselves() {
        // A tile that is not uniform is sent as sub-encoding 0 and the pixels
        // of the whole tile, in rows, in the client's own format.
        let mut pixels = Vec::new();
        for i in 0..16 * 16u32 {
            pixels.extend_from_slice(&[(i % 251) as u8, 0, 0, 0]);
        }
        let bytes = hextile(&pixels, 16, 16);
        assert_eq!(bytes[0], 0, "a raw tile");
        assert_eq!(bytes.len(), 1 + 16 * 16 * 4);
        assert_eq!(&bytes[1..5], &pixels[..4]);
    }

    #[test]
    fn a_hextile_screen_of_four_tiles_is_four_sub_encodings() {
        // A screen one tile wider and taller than one tile, which is the case a
        // count in front would get wrong: the stream is just the four tiles.
        let mut pixels = Vec::new();
        for _ in 0..17 * 17 {
            pixels.extend_from_slice(&[1, 2, 3, 0]);
        }
        let bytes = hextile(&pixels, 17, 17);
        // 2x2 tiles, each 16x16 or clipped, all the same colour.
        assert_eq!(bytes, [1, 1, 2, 3, 0, 1, 1, 2, 3, 0, 1, 1, 2, 3, 0, 1, 1, 2, 3, 0], "{bytes:02x?}");
    }

    #[test]
    fn a_tight_fill_is_a_control_byte_and_one_pixel() {
        // `VNC_TIGHT_FILL` is 0b1000 and the compression type is the top four
        // bits, so the control byte is 0x80 and *nothing* follows but the
        // colour: no size, no compression. A 0x10 control byte is a basic
        // rectangle on zlib stream 1, which is to say raw pixels, and a client
        // that reads it that way is out of step from the first byte.
        let pixels = alternate(8, 8, [0x11, 0x22, 0x33], [0x11, 0x22, 0x33]);
        let bytes = tight(&pixels, 8, 8);
        assert_eq!(bytes, [0x80, 0x11, 0x22, 0x33], "{bytes:02x?}");
    }

    #[test]
    fn a_tight_palette_is_basic_on_stream_two_with_the_count_less_one() {
        // `send_palette_rect` writes `(stream | VNC_TIGHT_EXPLICIT_FILTER) << 4`
        // with stream 2, then `VNC_TIGHT_FILTER_PALETTE`, then `colors - 1`.
        // So: 0x60, 0x01, and one for two colours — not two, which would be a
        // palette of three.
        let pixels = alternate(8, 1, [0xff, 0, 0], [0, 0, 0xff]);
        let bytes = tight(&pixels, 8, 1);
        assert_eq!(bytes[0], 0x60, "basic, zlib stream 2, filter byte follows");
        assert_eq!(bytes[1], 0x01, "the palette filter");
        assert_eq!(bytes[2], 1, "the number of colours *minus one*");
        // The two colours, as red, green, blue — note 1 of the header: at depth
        // 24 with three eight bit components a pixel is always three bytes in
        // that order, whatever the client's own byte order is.
        assert_eq!(&bytes[3..6], &[0xff, 0, 0], "red first");
        assert_eq!(&bytes[6..9], &[0, 0, 0xff], "then blue");
        // Eight pixels of two colours is one byte of indexes, which is below
        // the twelve byte threshold, so it goes out as it is with no size in
        // front of it. The first pixel is the commonest colour, so it is index
        // 0, and the byte is 0b0101_0101.
        assert_eq!(&bytes[9..], &[0b0101_0101], "one bit a pixel, uncompressed");
    }

    #[test]
    fn a_tight_two_colour_row_starts_on_a_byte_of_its_own() {
        // Every row of a two colour rectangle starts on a byte boundary, so a
        // width that is not a multiple of eight pads each row rather than
        // running the rows together. Twelve pixels over two rows is two bytes a
        // row, so four in all; a packing that ran from row to row would spend
        // three and a half and round up, and every row after the first would be
        // a bit out.
        let pixels = alternate(12, 2, [0xff, 0, 0], [0, 0, 0xff]);
        let bytes = tight(&pixels, 12, 2);
        assert_eq!(bytes.len(), 3 + 2 * 3 + 2 * 2, "{bytes:02x?}");
        assert_eq!(
            &bytes[9..13],
            &[0b0101_0101, 0b0101_0000, 0b1010_1010, 0b1010_0000],
            "two bytes a row, each padded on the right"
        );
    }

    #[test]
    fn a_tight_palette_of_more_than_two_colours_is_a_byte_per_pixel() {
        // Three colours, so the count is 2 and every pixel takes a whole byte.
        let mut data = Vec::new();
        for x in 0..16u16 {
            let rgb = [[0x11, 0, 0], [0x22, 0, 0], [0x33, 0, 0]][x as usize % 3];
            data.extend_from_slice(&[rgb[2], rgb[1], rgb[0], 0]);
        }
        let bytes = tight(&data, 16, 1);
        assert_eq!(bytes[2], 2, "three colours, announced as two");
        // 3 + 9 for the palette, then a compact size, then 16 indexes. Sixteen
        // is over the threshold, so the indexes are compressed and the size
        // says how many bytes they took — 0x0e, fourteen, at index 12.
        assert_eq!(bytes[12] & 0x80, 0, "fourteen bytes fits in one size byte");
        assert_eq!(bytes[12] as usize, bytes.len() - 13, "the size is right");
        let indexes = inflate(&bytes[13..]);
        assert_eq!(indexes.len(), 16, "one byte a pixel");
        // The palette is sorted by how often each colour is used, so 0x11 — six
        // of the sixteen pixels — is index 0, and the two five-pixel colours
        // keep the order they were found in. The indexes are then a plain
        // 0, 1, 2 cycle, one byte per pixel rather than a bit.
        assert_eq!(indexes, (0..16).map(|i: u8| i % 3).collect::<Vec<u8>>());
    }

    #[test]
    fn tight_short_index_data_is_not_compressed_and_carries_no_size() {
        // Under twelve bytes of indexes there is nothing to gain from
        // compressing, and a decoder can tell from the rectangle's dimensions
        // that the data is raw — which is why no size is written in front of
        // it. Writing one anyway desynchronises the next rectangle.
        let pixels = alternate(4, 1, [0xff, 0, 0], [0, 0, 0xff]);
        let bytes = tight(&pixels, 4, 1);
        assert_eq!(bytes.len(), 3 + 2 * 3 + 1, "{bytes:02x?}");
        // Four pixels at one bit each, most significant first, padded on the
        // right: the first pixel is the commonest colour and so index 0.
        assert_eq!(&bytes[9..], &[0b0101_0000]);
    }

    #[test]
    fn a_zrle_stream_is_the_tiles_and_nothing_else() {
        // A rectangle of two 64x64 solid tiles is exactly eight bytes: a
        // sub-encoding and a three byte pixel for each. A header of "the first
        // tile's sub-encoding, then width - 1, then height - 1" in front of
        // them would make it thirteen, and because the header's first byte is
        // the first tile's sub-encoding either way, the first tile would still
        // decode and the second would not. That is the shape of the bug: it
        // looks right for one tile.
        let mut pixels = Vec::new();
        for _ in 0..64u16 {
            for x in 0..128u16 {
                let rgb = if x < 64 { [0x11, 0x22, 0x33] } else { [0x44, 0x55, 0x66] };
                // x8r8g8b8 is B, G, R, unused.
                pixels.extend_from_slice(&[rgb[2], rgb[1], rgb[0], 0]);
            }
        }
        let bytes = encoded(&pixels, 128, 64);
        assert_eq!(
            bytes,
            [
                1, 0x33, 0x22, 0x11, // first tile: solid, then three bytes
                1, 0x66, 0x55, 0x44, // second tile, and no header between
            ],
            "{bytes:02x?}"
        );
    }

    /// The pixel format the real viewer asked for, in the log.
    fn viewer_format() -> PixelFormat {
        PixelFormat {
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
            ..format()
        }
    }

    /// The framebuffer in the server's own x8r8g8b8, converted to the format
    /// the viewer asked for, exactly as `convert_pixels` does it.
    fn converted_viewer_frame(width: u16, height: u16) -> (Vec<u8>, PixelFormat) {
        let format = viewer_format();
        let mut fb: Vec<u8> = Vec::new();
        for y in 0..height {
            for x in 0..width {
                let rgb = if (x / 8 + y / 8) % 2 == 0 {
                    [0x11, 0x22, 0x33]
                } else {
                    [0x44, 0x55, 0x66]
                };
                // x8r8g8b8: blue, green, red.
                fb.extend_from_slice(&[rgb[2], rgb[1], rgb[0], 0]);
            }
        }
        let mut out = Vec::with_capacity(fb.len());
        for pixel in fb.as_chunks::<4>().0 {
            let (red, green, blue) = (pixel[2], pixel[1], pixel[0]);
            let value = (red as u32) << format.red_shift
                | (green as u32) << format.green_shift
                | (blue as u32) << format.blue_shift;
            out.extend_from_slice(&value.to_le_bytes()[..4]);
        }
        (out, format)
    }

    #[test]
    fn a_grey_windows_desktop_compresses_like_one() {
        // The screen that arrived from QEMU: a large area of near-neutral grey
        // with a slight blue tint, a 4.7% commonest colour and 4096 distinct
        // ones, which is what the log reports. The size of the update that
        // followed was 44.9% of raw, and a desktop has to be a few percent, so
        // this is the case that said the encoder was not the problem — or that
        // it was.
        let width = 320u16;
        let height = 200u16;
        let format = format();
        let mut data = Vec::new();
        for y in 0..height {
            for x in 0..width {
                // Grey with a slight blue tint, as the log's first pixels are.
                let tint = ((x / 4 + y / 4) % 8) as u8;
                let rgb = [156 + tint / 4, 156 + tint / 4, 162 + tint / 4];
                data.extend_from_slice(&[rgb[2], rgb[1], rgb[0], 0]);
            }
        }
        let rect = Rect { left: 0, top: 0, width, height };
        let mut encoders = Encoders::new(None);
        let (_codec, out) = encoders
            .encode(
                Codec::Zrle,
                &HashSet::from([Encoding::Zrle]),
                &data,
                &format,
                width as usize * 4,
                rect,
            )
            .expect("the ZRLE encoder");
        let raw = width as usize * height as usize * 4;
        let share = out.len() as f32 / raw as f32;
        // A desktop has to be a few percent of raw. This one is a near-flat
        // grey with a tint, the case the log's numbers describe, and it comes
        // out at a fraction of a percent — against the 44.9% of raw a real
        // console produced. So a framebuffer that compresses at 45% is not
        // holding a desktop, whatever it holds.
        assert!(
            share < 0.10,
            "a grey desktop compressed to {:.1}% of raw, which is not a picture",
            share * 100.0
        );
    }

    #[test]
    fn the_real_pipeline_does_not_say_a_desktop_is_uniform() {
        // Encode a converted desktop through the real Tight encoder and check
        // the size of what comes out. A four byte rectangle is a fill, and a
        // fill of a desktop is what a client shows as one flat colour.
        let (data, format) = converted_viewer_frame(1280, 800);
        let rect = Rect { left: 0, top: 0, width: 1280, height: 800 };
        let mut encoders = Encoders::new(None);
        let (_codec, out) = encoders
            .encode(
                Codec::Tight,
                &HashSet::from([Encoding::Tight]),
                &data,
                &format,
                1280 * 4,
                rect,
            )
            .expect("the Tight encoder");
        assert!(
            out.len() > 4,
            "a desktop encoded as {} bytes, which is a fill",
            out.len()
        );
    }

    #[test]
    fn a_converted_desktop_is_not_uniform() {
        // The whole pipeline: a framebuffer in x8r8g8b8, converted to the
        // format the viewer asked for, and then asked whether it is one
        // colour. This is the path the real update takes, and the answer has
        // to be "no" — a "yes" is a four byte fill of the whole screen, which
        // is what a client sees as a single flat colour.
        let (data, format) = converted_viewer_frame(64, 64);
        let rect = Rect { left: 0, top: 0, width: 64, height: 64 };
        let view = RectPixels::new(&data, &format, 64 * 4, rect);
        // The two squares must decode apart, and the whole must not read as
        // one colour.
        assert_ne!(view.rgb(0, 0), view.rgb(8, 0), "the squares decode alike");
        assert_eq!(view.is_uniform(0, 0, 64, 64), None, "not one colour");
    }

    #[test]
    fn a_desktop_is_not_uniform_in_the_viewers_format() {
        // The framebuffer arrives in the server's own x8r8g8b8 and is converted
        // to the client's format before it reaches an encoder. With the viewer
        // asking for red in the *first* byte, a conversion that is subtly wrong
        // can make every pixel look the same, and `is_uniform` then says the
        // whole screen is one colour and the encoder sends a four byte fill.
        let format = viewer_format();
        let mut data = Vec::new();
        for y in 0..64u16 {
            for x in 0..64u16 {
                let rgb = if (x / 8 + y / 8) % 2 == 0 { [0x11, 0x22, 0x33] } else { [0x44, 0x55, 0x66] };
                // The client's byte order: red first.
                data.extend_from_slice(&[rgb[0], rgb[1], rgb[2], 0]);
            }
        }
        let rect = Rect { left: 0, top: 0, width: 64, height: 64 };
        let view = RectPixels::new(&data, &format, 64 * 4, rect);
        assert_eq!(
            view.is_uniform(0, 0, 64, 64),
            None,
            "a checkerboard is one colour only if every pixel decodes the same"
        );
        // And the two colours must really decode apart.
        let a = view.rgb(0, 0).expect("a colour");
        let b = view.rgb(8, 0).expect("a colour");
        assert_ne!(a, b, "the two squares decode to the same colour");
    }

    #[test]
    fn a_desktop_is_not_uniform() {
        // The screen is a picture; if `is_uniform` says otherwise the encoder
        // sends a four byte fill and the client sees one flat colour. This is
        // the frame the mock pushes, and it is not one colour.
        let mut data = Vec::new();
        for y in 0..64u16 {
            for x in 0..64u16 {
                let rgb = if (x / 8 + y / 8) % 2 == 0 { [0x11, 0x22, 0x33] } else { [0x44, 0x55, 0x66] };
                data.extend_from_slice(&[rgb[2], rgb[1], rgb[0], 0]);
            }
        }
        let format = format();
        let rect = Rect { left: 0, top: 0, width: 64, height: 64 };
        let view = RectPixels::new(&data, &format, 64 * 4, rect);
        assert_eq!(
            view.is_uniform(0, 0, 64, 64),
            None,
            "a checkerboard is not one colour"
        );
    }

    #[test]
    fn a_flat_area_is_uniform() {
        let data = [0x33u8, 0x22, 0x11, 0].repeat(64 * 64);
        let format = format();
        let rect = Rect { left: 0, top: 0, width: 64, height: 64 };
        let view = RectPixels::new(&data, &format, 64 * 4, rect);
        assert_eq!(
            view.is_uniform(0, 0, 64, 64),
            Some([0x11, 0x22, 0x33]),
            "a flat area is one colour"
        );
    }

    #[test]
    fn a_palette_tile_is_the_colour_count_and_packed_indices() {
        // A 64x1 tile of two colours, alternating. QEMU writes the sub-encoding
        // as `(use_rle ? 128 : 0) | size`, so 2 — the count, not the count plus
        // one — then the palette, then the indices at one bit each, packed most
        // significant bit first, which for 64 pixels is exactly eight bytes.
        // x8r8g8b8 with red_shift 16, so red is the third byte: white is
        // [B, G, R, unused] = [0, 0, 0xff, 0].
        let mut pixels = Vec::new();
        for x in 0..64u16 {
            let colour: [u8; 4] = if x % 2 == 0 {
                [0, 0, 0xff, 0] // white
            } else {
                [0, 0, 0, 0] // black
            };
            pixels.extend_from_slice(&colour);
        }
        let bytes = encoded(&pixels, 64, 1);
        let tile = &bytes[..];
        assert_eq!(tile[0], 2, "the sub-encoding is the number of colours: {tile:02x?}");
        // Two entries of three bytes each: 32 bits per pixel at depth 24 is a
        // three byte palette entry, not a four byte pixel.
        assert_eq!(tile.len(), 1 + 2 * 3 + 8, "the tile is 15 bytes: {tile:02x?}");
        // The palette is sorted by use, and both colours are used 32 times, so
        // the order is the order they were found: white, then black. Each entry
        // is the client's own pixel with the padding byte dropped — three bytes
        // for a 32 bit pixel at depth 24 — and *not* rearranged, which is the
        // whole point of the compact form: a decoder copies them straight into
        // its own pixels.
        assert_eq!(&tile[1..4], &[0, 0, 0xff], "white, as the pixel's own bytes");
        assert_eq!(&tile[4..7], &[0, 0, 0], "then black");
        // 64 pixels, one bit each, packed most significant bit first. The
        // first pixel is white, which is index 0, so the first bit is 0 and a
        // byte of eight pixels is 0b0101_0101.
        for byte in &tile[7..15] {
            assert_eq!(*byte, 0b0101_0101, "one bit per pixel, MSB first");
        }
    }

    #[test]
    fn a_four_colour_tile_uses_two_bits_per_index() {
        // Four colours in a repeating pattern. QEMU's table maps a palette of
        // three or four to two bits per index, so 64 pixels take sixteen bytes
        // rather than eight.
        let palette: [[u8; 4]; 4] = [
            [1, 0, 0, 0],
            [2, 0, 0, 0],
            [3, 0, 0, 0],
            [4, 0, 0, 0],
        ];
        let mut pixels = Vec::new();
        for x in 0..64u16 {
            pixels.extend_from_slice(&palette[(x % 4) as usize]);
        }
        let bytes = encoded(&pixels, 64, 1);
        let tile = &bytes[..];
        assert_eq!(tile[0], 4, "the sub-encoding is the colour count");
        // 1 + 4*3 + 64*2/8
        assert_eq!(tile.len(), 1 + 4 * 3 + 16, "16 bytes of indices: {tile:02x?}");
        // Indices 0,1,2,3 repeating, two bits each, MSB first: 00 01 10 11
        // repeated is the byte 0b00011011.
        for byte in &tile[1 + 4 * 3..] {
            assert_eq!(*byte, 0b0001_1011, "two bits per index, MSB first");
        }
    }

    #[test]
    fn a_narrow_row_is_padded_onto_its_own_byte() {
        // The packing restarts on every row and the last byte of a row is
        // padded on the right, so a tile twelve pixels wide is two bytes to a
        // row and not a run-on of twenty four bits in three bytes. Nothing else
        // here can tell the two apart: a tile a multiple of eight pixels wide
        // fills its bytes exactly, and every tile of a 64 or 32 wide rectangle
        // does, which is why it takes a deliberately awkward width to pin.
        let mut pixels = Vec::new();
        for y in 0..2u16 {
            for x in 0..12u16 {
                let white = (x + y) % 2 == 0;
                // x8r8g8b8 is B, G, R, unused.
                pixels.extend_from_slice(&[0, 0, if white { 0xff } else { 0 }, 0]);
            }
        }
        let bytes = encoded(&pixels, 12, 2);
        let tile = &bytes[..];
        assert_eq!(tile[0], 2, "two colours, so the sub-encoding is 2");
        // 1 for the sub-encoding, 2 colours of 3 bytes, and two rows of 2.
        assert_eq!(tile.len(), 1 + 2 * 3 + 2 * 2, "{tile:02x?}");
        // Row 0 is 0,1,0,1... for twelve pixels. The first eight fill a byte;
        // the last four are 0,1,0,1, which the row's final shift leaves as
        // 0b0101_0000 — the four indices in the top of the byte and the four
        // padding bits below them, zero.
        assert_eq!(&tile[7..9], &[0b0101_0101, 0b0101_0000], "row 0, padded");
        // Row 1 is the other way round, because the checkerboard turns over.
        assert_eq!(&tile[9..11], &[0b1010_1010, 0b1010_0000], "row 1, padded");
    }

    #[test]
    fn a_solid_tile_is_three_bytes_for_a_thirty_two_bit_client() {
        // Note 1 of the RFB specification: a 32 bit pixel at depth 24 is three
        // bytes, and that is the width of *every* pixel a ZRLE rectangle
        // writes. QEMU comes at it through `ZRLE_COMPACT_PIXEL`, which
        // redefines `ZRLE_WRITE_PIXEL` as `zrle_write_u24a`, so the solid
        // tile's colour is three bytes and not four.
        //
        // This is the case that showed as a blank screen, because the palette
        // entries were right and everything else was a byte too wide: a client
        // reads the first tile and then every field after it is out of step.
        let pixels = [0x11u8, 0x22, 0x33, 0x44].repeat(64);
        let bytes = encoded(&pixels, 64, 1);
        let tile = &bytes[..];
        assert_eq!(tile[0], 1, "sub-encoding 1 is a solid tile");
        assert_eq!(tile.len(), 1 + 3, "and the colour is three bytes: {tile:02x?}");
        // The three that hold the colour, in the client's own order, with the
        // padding byte dropped.
        assert_eq!(&tile[1..4], &[0x11, 0x22, 0x33]);
    }


    #[test]
    fn a_tile_of_more_than_sixteen_colours_is_sent_raw() {
        // Sub-encoding 0, and then the pixels as they are — at the ZRLE width
        // of three bytes for this client, not the four the framebuffer holds.
        // A raw tile is most of a photographic screen, so getting this wrong
        // costs a byte a pixel over the largest part of the frame.
        let mut pixels = Vec::new();
        for x in 0..64u16 {
            pixels.extend_from_slice(&[x as u8, (x / 2) as u8, 0, 0]);
        }
        let bytes = encoded(&pixels, 64, 1);
        let tile = &bytes[..];
        assert_eq!(tile[0], 0, "sub-encoding 0 is raw");
        assert_eq!(tile.len(), 1 + 64 * 3, "and 64 three byte pixels: {}", tile.len());
    }

    #[test]
    fn a_sixteen_bit_client_gets_two_bytes_a_pixel() {
        // The other end of the same rule: a 16 bit pixel is two bytes, whether
        // it is a palette entry, a solid tile's colour or a raw tile's pixel.
        let format = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
            ..self::format()
        };
        assert_eq!(zrle_pixel_len(&format), 2);

        // And a 32 bit client at depth 32 — four components, no padding to
        // drop — keeps all four.
        let thirty_two = PixelFormat {
            depth: 32,
            ..self::format()
        };
        assert_eq!(zrle_pixel_len(&thirty_two), 4);
    }
    /// A hextile stream is a sub-encoding byte per tile and the tile's pixels,
    /// and both halves of that sentence are load-bearing.
    ///
    /// A hextile rectangle is not `width * height * 4` bytes. It is
    /// `tiles * (1 + tile_width * tile_height * 4)`, where the tile dimensions
    /// are the *clipped* ones, so a 320x13 rectangle is twenty tiles of one
    /// row-block of sixteen rows — clipped to thirteen — and not 16640 bytes but
    /// 20 * (1 + 13 * 16 * 4) = 16660.
    ///
    /// This is written down because getting it wrong is easy and was: a test
    /// that asserted a hextile rectangle inflates to `width * height * 4` failed
    /// by exactly the number of tiles, and the twenty bytes it was short by
    /// looked for a while like a compressor emitting rubbish.
    #[test]
    fn a_hextile_stream_is_a_sub_encoding_byte_per_tile() {
        for (w, h) in [
            (320u16, 13u16),
            (1280, 13),
            (320, 1),
            (64, 32),
            (320, 16),
            (320, 200),
            (1, 1),
        ] {
            let pixels = alternate(w, h, [1, 2, 3], [4, 5, 6]);
            let out = hextile_exactly(&pixels, w, h);
            let tiles_x = (w as usize).div_ceil(16);
            let tiles_y = (h as usize).div_ceil(16);
            let want: usize = (0..tiles_y)
                .flat_map(|ty| (0..tiles_x).map(move |tx| (tx, ty)))
                .map(|(tx, ty)| {
                    let tw = (w as usize - tx * 16).min(16);
                    let th = (h as usize - ty * 16).min(16);
                    1 + tw * th * 4
                })
                .sum();
            assert_eq!(
                out.len(),
                want,
                "a {w}x{h} hextile rectangle inflated to {} bytes",
                out.len()
            );
        }
    }

    /// The *uncompressed* bytes of a hextile rectangle.
    ///
    /// Measured the way a client measures it, because the two other ways both
    /// give the wrong answer and one of them is how the missing length field
    /// survived. A complete-stream decoder (`ZlibDecoder::read_to_end`) reports
    /// "incomplete deflate stream", because `Compress` is used with a sync
    /// flush and never finished — the stream is deliberately left open, one
    /// per connection, and the rectangle's length on the wire is what says how
    /// much of it to read. And a `Sync`-flush loop over `decompress_vec`, which
    /// is what `inflate` above does, reports 523616 bytes for a 320x200
    /// rectangle that is 256260 bytes long.
    ///
    /// So: one inflater, fed once, measured by `total_out`. That is
    /// libvncclient's loop, and it is the only one of the three that agrees
    /// with a real client.
    fn hextile_exactly(pixels: &[u8], width: u16, height: u16) -> Vec<u8> {
        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width,
            height,
        };
        let mut encoders = Encoders::new(None);
        let (_codec, data) = encoders
            .encode(
                Codec::Zlib,
                &HashSet::from([Encoding::Zlib]),
                pixels,
                &format,
                width as usize * 4,
                rect,
            )
            .expect("the hextile encoder");
        // Room for the tiles and a sub-encoding byte each, and then some: a
        // uniform tile costs five bytes where a raw one costs a thousand, so
        // the smallest possible stream and the largest differ by a factor of
        // two hundred.
        let mut out = vec![0u8; width as usize * height as usize * 4 + 4096];
        let mut decompress = flate2::Decompress::new(true);
        decompress
            .decompress(&data, &mut out, flate2::FlushDecompress::None)
            .expect("the body is a zlib stream");
        out.truncate(decompress.total_out() as usize);
        out
    }

    /// A zlib rectangle is headed once, and never ends.
    ///
    /// The stream is continuous. That is what QEMU does and what
    /// `libvncclient` is built for: one `deflateInit2` per *session*,
    /// `Z_SYNC_FLUSH` per rectangle, no finish and no reset — see
    /// `ui/vnc-enc-zlib.c`, where `if (zstream->opaque != vs)` guards the only
    /// `deflateInit2` and `deflate(zstream, Z_SYNC_FLUSH)` is the only call —
    /// and `libvncserver/src/libvncserver/zlib.c` before it. So rectangle one
    /// carries the zlib header, every rectangle after it is a mid-stream
    /// fragment, and a client is expected to keep one inflater for the life of
    /// the connection.
    ///
    /// What that obliges is the whole of the convention, and it is worth
    /// writing down because the alternative is not a variant of it:
    ///
    /// * The **first** rectangle must carry the header. Nothing has inflated
    ///   this stream yet, so the first rectangle is the one that has to be
    ///   readable from the top.
    /// * **No** rectangle may end the stream. There is no final block and no
    ///   adler32, only the empty stored block a sync flush leaves, so a decoder
    ///   waiting for `Z_STREAM_END` never gets it and reports "incomplete zlib
    ///   block". A real viewer did exactly that, having decoded our ZRLE
    ///   rectangles without complaint — so its ZRLE path tolerates a stream
    ///   that runs on and its zlib path does not.
    /// * The **data** is complete all the same. Every tile byte is inside the
    ///   rectangle; only the framing continues into the next one. A client that
    ///   inflates the declared length and takes what comes out draws the right
    ///   picture, and that is what this asserts.
    ///
    /// A self-contained stream per rectangle — `Z_FINISH` and a reset — would
    /// satisfy a decoder that treats a rectangle as a unit and break a decoder
    /// that keeps its inflater, because a deflate stream cannot both continue
    /// and restart. The two are mutually exclusive, only one can be right, and
    /// this is QEMU's.
    #[test]
    fn a_zlib_rectangle_is_headed_once_and_never_ends() {
        let pixels = alternate(1280, 13, [1, 2, 3], [4, 5, 6]);
        let format = format();
        // `top: 0`, not the 762 the production strip sits at: `RectPixels`
        // indexes from the screen origin, so a rectangle at 762 wants a buffer
        // that has 762 rows above it. Where the rectangle is has no bearing on
        // whether the stream is headed or terminated, and giving it a position
        // it cannot have is a way of testing nothing.
        let rect = Rect {
            left: 0,
            top: 0,
            width: 1280,
            height: 13,
        };
        let mut encoders = Encoders::new(None);
        let rect_body = |encoders: &mut Encoders| -> Vec<u8> {
            encoders
                .encode(
                    Codec::Zlib,
                    &HashSet::from([Encoding::Zlib]),
                    &pixels,
                    &format,
                    1280 * 4,
                    rect,
                )
                .expect("the hextile encoder")
                .1
        };
        let first = rect_body(&mut encoders);
        let second = rect_body(&mut encoders);

        assert_eq!(
            first[0],
            0x78,
            "the first zlib rectangle must start with a zlib header (0x78) and not with \
             mid-stream deflate data ({:#04x}). Nothing has inflated this stream yet, so \
             the first rectangle is the one that has to be readable from the top",
            first[0]
        );

        // No rectangle ends the stream: a sync flush closes with an empty
        // stored block, 00 00 ff ff. A finished stream closes with a final
        // block and an adler32 instead.
        for (name, body) in [("first", &first), ("second", &second)] {
            assert_eq!(
                &body[body.len() - 4..],
                b"\x00\x00\xff\xff",
                "the {name} rectangle does not close with a sync-flush marker, so the \
                 compressor is ending the stream. It must not: a client that keeps one \
                 inflater for the connection would meet the next rectangle's header in the \
                 middle of a stream it was never told to restart"
            );
        }

        // And the data is complete, which is what says a lenient client draws
        // the right picture and that "unterminated" is a framing fact rather
        // than a data fault. One inflater for the connection, fed the declared
        // length of each rectangle, has to produce every tile byte of both.
        let want = hextile_tiles(1280, 13);
        let mut inflate = flate2::Decompress::new(true);
        let mut out = vec![0u8; want * 2 + 64];
        let mut produced = 0usize;
        for body in [&first, &second] {
            let before = inflate.total_out();
            inflate
                .decompress(body, &mut out[produced..], flate2::FlushDecompress::None)
                .expect("the body is a zlib stream");
            produced += (inflate.total_out() - before) as usize;
        }
        assert_eq!(
            produced,
            want * 2,
            "two rectangles of this shape should inflate to {want} bytes each and produced \
             {produced} between them, so the data is incomplete rather than merely \
             unterminated — a different fault, and one that would be ours"
        );
    }

    /// The byte count of a hextile stream of `w` by `h`: one sub-encoding byte
    /// per tile, and then that tile's pixels, clipped at the right and bottom.
    fn hextile_tiles(w: u16, h: u16) -> usize {
        let tiles_x = (w as usize).div_ceil(16);
        let tiles_y = (h as usize).div_ceil(16);
        (0..tiles_y)
            .flat_map(|ty| (0..tiles_x).map(move |tx| (tx, ty)))
            .map(|(tx, ty)| {
                let tw = (w as usize - tx * 16).min(16);
                let th = (h as usize - ty * 16).min(16);
                1 + tw * th * 4
            })
            .sum()
    }

    /// A client that can have ZRLE is never sent encoding 6.
    ///
    /// QEMU's rule, unconditional and at every size: `vnc_set_encodings` only
    /// takes `VNC_ENCODING_ZLIB` when the client has no ZRLE feature, with the
    /// comment "VNC_ENCODING_ZRLE compresses better than VNC_ENCODING_ZLIB. So
    /// prioritize ZRLE, even if the client hints that it prefers ZLIB."
    ///
    /// This exists because a viewer that works against QEMU rejected ours. Not
    /// the pixels and not the framing: its zlib path inflates a rectangle on
    /// its own and its ZRLE path does not, and QEMU had never given it a zlib
    /// rectangle to have an opinion about. This port offered it both and chose
    /// per rectangle, so a thin strip came out as encoding 6 and the viewer
    /// said "Incomplete zlib block" and stopped. The fix is to make the same
    /// choice QEMU makes, not to change the format — the two conventions are
    /// mutually exclusive, and QEMU's is the one that has to be matched.
    #[test]
    fn a_client_that_can_have_zrle_is_never_sent_zlib() {
        let format = format();
        // The shape that caused it, and a few others: the rule is not about
        // size, so a large rectangle has to be ZRLE as well.
        for (w, h) in [(1280u16, 13u16), (320, 13), (1280, 800), (64, 64), (16, 16)] {
            let rect = Rect {
                left: 0,
                top: 0,
                width: w,
                height: h,
            };
            let both = HashSet::from([Encoding::Zrle, Encoding::Zlib]);
            let ceiling = Policy::ceiling_of(&both, &format, rect);
            // The rule is structural rather than a special case: the zlib level
            // is not on the ladder at all when ZRLE is available, so the policy
            // cannot wander onto it however the level adapts. Tight may still be
            // above it, and Tight is a different encoding, not encoding 6.
            let lowest_reachable = if ceiling == LEVEL_TIGHT {
                LEVEL_ZRLE
            } else {
                LEVEL_RAW
            };
            assert_eq!(
                lowest_reachable,
                LEVEL_RAW,
                "a {w}x{h} rectangle to a client offering both ZRLE and zlib has a floor of \
                 {lowest_reachable}, but the zlib level should be unreachable entirely"
            );
            assert!(
                ceiling == LEVEL_ZRLE || ceiling == LEVEL_TIGHT,
                "unexpected ceiling {ceiling} for a {w}x{h} rectangle"
            );
            for level in 0..=ceiling {
                assert_ne!(
                    Policy::codec(level, &both, false),
                    Codec::Zlib,
                    "a {w}x{h} rectangle at level {level} chose zlib for a client that can \
                     have ZRLE"
                );
            }
            // And the other half of the rule, so the change cannot be "never
            // send zlib": a client that offers only zlib still gets it.
            let zlib_only = HashSet::from([Encoding::Zlib]);
            let ceiling = Policy::ceiling_of(&zlib_only, &format, rect);
            assert_eq!(
                Policy::codec(ceiling, &zlib_only, false),
                Codec::Zlib,
                "a client that offers zlib and nothing else was not sent zlib for a {w}x{h} \
                 rectangle, so the ZRLE rule has become a blanket refusal"
            );
        }
    }

    /// What one frame costs to encode, per codec, on content that behaves like
    /// video rather than like a desktop.
    ///
    /// This exists because "the CPU is at 100%" is not a diagnosis. It is
    /// equally consistent with a spin, with encoding flat out, and with
    /// encoding something the policy should never have chosen — and the three
    /// have nothing in common as fixes. The measurement that separates them is
    /// the cost of one encode, because that is also the floor on the frame rate:
    /// the client task encodes inline, so a frame that takes *n* milliseconds
    /// caps the server at 1000/*n* frames a second no matter what the update
    /// interval says, and a core at 100% is the *expected* consequence of
    /// sitting at that cap.
    ///
    /// The content matters as much as the codecs. A desktop is mostly flat
    /// colour, which every codec compresses to nothing, so a desktop will never
    /// show the cost. Video is the opposite: smooth gradients and noise, many
    /// distinct colours per tile, and a palette that does not help. The frame
    /// below is a photograph's statistics rather than a photograph — a smooth
    /// two-axis gradient, which compresses the way a gradient compresses, with a
    /// band of noise over part of it, which does not compress at all.
    ///
    /// **Run this in release.** A debug build's bounds checks and lack of
    /// inlining put every codec in the same order of magnitude and the
    /// comparison between them is meaningless; the absolute numbers are roughly
    /// an order of magnitude worse than the ones that matter.
    ///
    /// ```sh
    /// cargo test -p qemu-vnc --release --lib what_a_frame_costs -- --nocapture
    /// ```
    #[test]
    #[ignore = "a measurement, not a check: needs an optimised build and a reader"]
    fn what_a_frame_costs() {
        const W: u16 = 1280;
        const H: u16 = 800;
        const ROUNDS: u32 = 5;

        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width: W,
            height: H,
        };
        let raw = usize::from(W) * usize::from(H) * 4;
        let pixels = photographic(W, H);
        let all = HashSet::from([Encoding::Raw, Encoding::Zlib, Encoding::Zrle, Encoding::Tight]);

        println!(
            "\n  one {W}x{H} frame, {raw} raw bytes, x{ROUNDS} rounds, release build\n"
        );
        println!("  {:<8} {:>10} {:>10} {:>8} {:>10}", "codec", "ms/frame", "fps", "bytes", "of raw");
        for (name, codec) in [
            ("raw", Codec::Raw),
            ("zlib", Codec::Zlib),
            ("zrle", Codec::Zrle),
            ("tight", Codec::Tight),
        ] {
            let mut encoders = Encoders::new(None);
            // One untimed round, so the first call's allocation is not in the
            // measurement. It is the same cost the server pays once per client.
            let _ = encoders.encode(codec, &all, &pixels, &format, usize::from(W) * 4, rect);
            let started = std::time::Instant::now();
            // `None` means the data goes out as it is, so raw is not `encode`d at
            // all — the caller hands the rectangle's own pixels to the frame
            // update. Timing the `encode` call and reporting zero bytes, which
            // is what a first version of this table did, reads as though raw
            // were free *and* empty. It is free because it is a copy.
            let mut bytes = 0usize;
            let mut samples = 0u32;
            for _ in 0..ROUNDS {
                match encoders.encode(codec, &all, &pixels, &format, usize::from(W) * 4, rect) {
                    Some((_codec, data)) => {
                        bytes = data.len();
                        samples += 1;
                    }
                    None => {
                        bytes = raw;
                        samples += 1;
                    }
                }
            }
            let each = started.elapsed().as_secs_f64() / f64::from(ROUNDS);
            assert_eq!(samples, ROUNDS, "a codec produced nothing at all");
            let fps = if each > 0.0 { 1.0 / each } else { f64::INFINITY };
            println!(
                "  {name:<8} {:>10.2} {:>10.1} {:>8} {:>9.1}%",
                each * 1000.0,
                fps,
                bytes,
                bytes as f64 * 100.0 / raw as f64
            );
        }
        println!(
            "\n  the fps column is the ceiling the client task imposes, because the \
             encode is inline:\nthe interval cannot buy anything above it, and a core at \
             100% is what\nsitting at that ceiling looks like.\n"
        );
    }
    /// A frame with video's statistics: every pixel a different colour, so
    /// every tile goes out raw, which is what 100% of the production band's
    /// 64x64 tiles did.
    fn video_frame(width: u16, height: u16) -> Vec<u8> {
        let mut data = vec![0u8; usize::from(width) * usize::from(height) * 4];
        for y in 0..usize::from(height) {
            for x in 0..usize::from(width) {
                let o = (y * usize::from(width) + x) * 4;
                data[o] = (x * 31 + y * 17) as u8;
                data[o + 1] = ((x * 13 + y * 29 + x * y) % 251) as u8;
                data[o + 2] = x as u8 ^ ((y * 11) as u8);
            }
        }
        data
    }

    /// A desktop: broad areas of few colours, so most tiles are palette, with a
    /// band in the middle third that has *more* than sixteen colours and long
    /// runs. That band is the whole point of this fixture -- it is the only
    /// shape in this file on which this port's rule and QEMU's could differ.
    fn desktop_with_a_many_colour_band(width: u16, height: u16) -> Vec<u8> {
        let mut data = vec![0u8; usize::from(width) * usize::from(height) * 4];
        for y in 0..usize::from(height) {
            for x in 0..usize::from(width) {
                let in_band = y > usize::from(height) / 3 && y < 2 * usize::from(height) / 3;
                let (r, g, b) = if in_band {
                    // Twenty-four colours, in runs of sixteen: too many for a
                    // sixteen-entry palette, and very compressible.
                    //
                    // **The row has to be in there.** A 64-wide tile holds four
                    // strips of sixteen, so varying only with the column gives
                    // *four* colours -- a palette tile, and the shape this
                    // fixture exists to rule out. The first version varied with
                    // x alone and the measurement cheerfully reported a tile
                    // rule disagreement that was really nothing of the kind.
                    let band = (((x / 16) + y) % 24) as u8;
                    (band * 10, band * 7, band * 3)
                } else if y < 40 {
                    (0x20, 0x40, 0x60)
                } else {
                    let t = (x * 255 / usize::from(width)) as u8;
                    (t, (y * 255 / usize::from(height)) as u8, 0x40)
                };
                let o = (y * usize::from(width) + x) * 4;
                data[o] = b;
                data[o + 1] = g;
                data[o + 2] = r;
            }
        }
        data
    }

    /// How often this port's tile rule and QEMU's would choose differently.
    ///
    /// **This is the measurement that decides whether ZYWRLE is worth
    /// implementing at all**, and it exists because ZYWRLE turned out to be
    /// blocked on something nobody had noticed.
    ///
    /// ZYWRLE's entire effect in QEMU is one line in
    /// `zrle_choose_palette_rle()`:
    ///
    /// ```c
    /// estimated_bytes = w * h * (bpp_out / 8); /\* start assuming raw \*/
    /// if (zywrle_level > 0)
    ///     estimated_bytes >>= zywrle_level;
    /// ```
    ///
    /// It shifts the *raw* estimate, which is then compared against the plain-
    /// RLE and palette estimates. So ZYWRLE cannot be implemented without an
    /// estimator -- and this port has none. `zrle_tile` here asks a different
    /// question: "are there more than sixteen colours?", and answers raw if so.
    /// There is nothing to shift.
    ///
    /// So the question is whether the two rules actually differ on content that
    /// matters. They cannot differ on video: a tile with more than sixteen
    /// colours out of a noisy frame has about as many runs as pixels, so plain
    /// RLE costs more than raw and both rules say raw. They can differ only on a
    /// tile that has **more than sixteen colours and few, long runs** -- a
    /// toolbar, a gradient with dithering, a text area -- where QEMU's estimate
    /// picks RLE and this port picks raw and sends three bytes a pixel.
    ///
    /// That is the shape counted here. If the count is zero across the shapes
    /// this port is measured on, matching QEMU's estimator buys nothing and
    /// ZYWRLE stays blocked for a reason that is worth knowing. If it is not
    /// zero, the estimator is a performance change worth measuring in its own
    /// right, and it is the thing to do before ZYWRLE.
    ///
    /// ```sh
    /// cargo test -p qemu-vnc --release --all-features --lib where_the_tile_rule_and_qemus_would_differ -- --nocapture
    /// ```
    #[test]
    #[ignore = "a measurement, not a check: needs an optimised build and a reader"]
    fn where_the_tile_rule_and_qemus_would_differ() {
        const W: u16 = 1280;
        const H: u16 = 800;
        const TILE: usize = 64;
        println!();
        for (name, frame) in [
            ("video, every tile raw", video_frame(W, H)),
            (
                "a desktop with a 24-colour band in runs of 16",
                desktop_with_a_many_colour_band(W, H),
            ),
            (
                "the frame the codec measurement calls 'noisy'",
                photographic(W, H),
            ),
        ] {
            let mut tiles = 0usize;
            let mut over_sixteen = 0usize;
            let mut qemu_says_rle = 0usize;
            let mut bytes_raw = 0usize;
            let mut bytes_rle = 0usize;
            for ty in (0..usize::from(H)).step_by(TILE) {
                for tx in (0..usize::from(W)).step_by(TILE) {
                    tiles += 1;
                    let mut colours: Vec<u32> = Vec::new();
                    let mut runs = 0usize;
                    let mut last = u32::MAX;
                    let mut singles = 0usize;
                    let mut run_len = 0usize;
                    for y in ty..(ty + TILE).min(usize::from(H)) {
                        for x in tx..(tx + TILE).min(usize::from(W)) {
                            let o = (y * usize::from(W) + x) * 4;
                            // The pixel value, which is what a palette is keyed
                            // on: the three colour bytes, alpha excluded.
                            let p = u32::from(frame[o])
                                | u32::from(frame[o + 1]) << 8
                                | u32::from(frame[o + 2]) << 16;
                            if p != last {
                                runs += 1;
                                if run_len == 1 {
                                    singles += 1;
                                }
                                run_len = 1;
                                last = p;
                            } else {
                                run_len += 1;
                            }
                            if !colours.contains(&p) {
                                colours.push(p);
                            }
                        }
                    }
                    let raw = TILE * TILE * 3;
                    let plain_rle = 4 * (runs + singles);
                    bytes_raw += raw;
                    bytes_rle += plain_rle.min(raw);
                    if colours.len() > 16 {
                        over_sixteen += 1;
                        if plain_rle < raw {
                            qemu_says_rle += 1;
                        }
                    }
                }
            }
            let differ = qemu_says_rle;
            println!(
                "  {name}\n    {tiles} tiles, {over_sixteen} over sixteen colours, \
                 **{differ} of them where QEMU would pick plain RLE and this port \
                 picks raw**\n    bytes before deflate: raw {} KB, as QEMU would \
                 choose {} KB ({:+.0}%)\n",
                bytes_raw / 1024,
                bytes_rle / 1024,
                100.0 * (bytes_rle as f64 - bytes_raw as f64) / bytes_raw as f64,
            );
        }
        println!(
            "  A zero in the middle row means the two rules never disagree on that \
             content,
  and ZYWRLE is blocked for a reason worth having rather than a \
             missing feature.\n  A non-zero means matching QEMU's estimator is worth \
             doing on its own merits,\n  and it is the prerequisite, not ZYWRLE, \
             that is the work.\n"
        );
    }

    /// A thin strip with video's statistics, which is the shape every taskbar
    /// redraw in the production logs had: `1280x13`, and never `1280x800`.
    fn photographic_strip(width: u16, height: u16) -> Vec<u8> {
        photographic(width, height)
    }

    /// A frame with a desktop's statistics and then some: a smooth gradient
    /// across the whole surface, with a noisy band down the middle third.
    /// The band is there so the number is not flattered by content that
    /// every codec would have thrown away.
    fn photographic(width: u16, height: u16) -> Vec<u8> {
        let mut data = vec![0u8; usize::from(width) * usize::from(height) * 4];
        for y in 0..usize::from(height) {
            for x in 0..usize::from(width) {
                let noisy = y > usize::from(height) / 3 && y < 2 * usize::from(height) / 3;
                let (r, g, b) = if noisy {
                    (
                        ((x * 7 + y * 13) % 256) as u8,
                        ((x * 29 + y * 3) % 256) as u8,
                        ((x * 11 + y * 41) % 256) as u8,
                    )
                } else {
                    (
                        (x * 255 / usize::from(width)) as u8,
                        (y * 255 / usize::from(height)) as u8,
                        ((x + y) * 255 / usize::from(width + height)) as u8,
                    )
                };
                let o = (y * usize::from(width) + x) * 4;
                data[o] = b;
                data[o + 1] = g;
                data[o + 2] = r;
            }
        }
        data
    }


    /// What the client's requested deflate level is worth.
    ///
    /// The -254 `CompressionLevel` pseudo-encoding carries a zlib level from 0
    /// to 9 and is the only mechanism in the protocol for a client to say how it
    /// wants the trade-off made. QEMU honours it: `set_encodings` defaults
    /// `worker->tight.compression` to 9, `VNC_ENCODING_COMPRESSLEVEL0 + n` sets
    /// it to `n`, and `vnc_zlib_stop` hands it to `deflateInit2`.
    ///
    /// This port accepted the pseudo-encoding, logged it, and then used it for
    /// something else: `ceiling_of_level` mapped a requested 1-to-9 onto
    /// *`LEVEL_TIGHT`*, a rung of this crate's own codec ladder, while the
    /// deflate level stayed at `Compression::default()` — 6 — whatever was
    /// asked for. A client that asks for 2, which is a common way of saying
    /// "fast, I would rather have the frames", got 6.
    ///
    /// So this is worth measuring before anything is built on it, because it is
    /// the one lever here that does not trade latency against size or size
    /// against CPU. It moves along a curve the client has already said where on
    /// it to sit.
    ///
    /// **Run this in release**, and read the sizes as well as the times: a lower
    /// level buys its speed with bytes, and which side of that a given client
    /// wants is not this crate's decision.
    ///
    /// ```sh
    /// cargo test -p qemu-vnc --release --lib what_the_deflate_level_is_worth -- --nocapture
    /// ```
    #[test]
    #[ignore = "a measurement, not a check: needs an optimised build and a reader"]
    fn what_the_deflate_level_is_worth() {
        const W: u16 = 1280;
        const H: u16 = 800;
        const ROUNDS: u32 = 5;

        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width: W,
            height: H,
        };
        let raw = usize::from(W) * usize::from(H) * 4;
        let pixels = photographic(W, H);
        let all = HashSet::from([Encoding::Raw, Encoding::Zlib, Encoding::Zrle, Encoding::Tight]);

        println!("\n  one {W}x{H} frame, {raw} raw bytes, x{ROUNDS} rounds, release build\n");
        println!(
            "  {:<6} {:<7} {:>9} {:>7} {:>8} {:>9}",
            "level", "codec", "ms/frame", "fps", "bytes", "of raw"
        );
        for level in [1u32, 2, 3, 6, 9] {
            for (name, codec) in [("zrle", Codec::Zrle), ("zlib", Codec::Zlib)] {
                // A fresh `Encoders` per level: the compressor is built with a
                // level, and whether it can be re-levelled without a reset is
                // part of what this has to decide.
                let mut encoders = Encoders::new(None);
                encoders.set_deflate_level(level);
                let _ = encoders.encode(codec, &all, &pixels, &format, usize::from(W) * 4, rect);
                let started = std::time::Instant::now();
                let mut bytes = 0usize;
                for _ in 0..ROUNDS {
                    if let Some((_c, data)) =
                        encoders.encode(codec, &all, &pixels, &format, usize::from(W) * 4, rect)
                    {
                        bytes = data.len();
                    }
                }
                let each = started.elapsed().as_secs_f64() / f64::from(ROUNDS);
                let fps = if each > 0.0 { 1.0 / each } else { f64::INFINITY };
                println!(
                    "  {level:<6} {name:<7} {:>9.2} {:>7.1} {:>8} {:>8.1}%",
                    each * 1000.0,
                    fps,
                    bytes,
                    bytes as f64 * 100.0 / raw as f64
                );
            }
        }
    }


    /// A client's requested zlib level reaches the compressor.
    ///
    /// The -254 `CompressionLevel` pseudo-encoding is the only mechanism in RFB
    /// for a client to say where on the size-versus-speed curve it wants to sit,
    /// and QEMU hands the number straight to `deflateInit2`
    /// (`VNC_ENCODING_COMPRESSLEVEL0 + n` sets `worker->tight.compression`,
    /// and `vnc_zlib_stop` passes it on).
    ///
    /// This port accepted the pseudo-encoding, logged it, and compressed at
    /// flate2's default of 6 regardless. A production viewer announces
    /// `CompressionLevel(2)` and was served 6, which on a 1280x800 frame is
    /// 40.9 ms instead of 31.8 — a fifth of the frame rate, to a client that
    /// had already asked not to spend it.
    ///
    /// The assertion is on the *bytes*, not on a timing. A timing would be a
    /// measurement pretending to be a check, and it would be the flakiest thing
    /// in the file. What has to be true is that the compressor was built with
    /// the level the client asked for, and the size of its output is the
    /// observable consequence: level 1 keeps 64 bytes of window and level 9
    /// keeps 32K, so on content with any redundancy the two cannot produce the
    /// same length. The test says which it expects, and a compressor built at
    /// the wrong level produces the other one.
    #[test]
    fn a_clients_zlib_level_reaches_the_compressor() {
        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width: 320,
            height: 200,
        };
        let pixels = photographic(320, 200);
        let offered = HashSet::from([Encoding::Zlib]);

        let at = |level: u32| -> usize {
            let mut encoders = Encoders::new(None);
            encoders.set_deflate_level(level);
            let (_codec, data) = encoders
                .encode(Codec::Zlib, &offered, &pixels, &format, 320 * 4, rect)
                .expect("the hextile encoder");
            data.len()
        };

        let one = at(1);
        let nine = at(9);
        assert_ne!(
            one, nine,
            "level 1 and level 9 produced the same {one} bytes, so the level is not \
             reaching the compressor at all and this test is measuring nothing"
        );
        assert!(
            one > nine,
            "level 1 produced {one} bytes and level 9 produced {nine}, which is backwards: \
             the lower level has the smaller window and the weaker match search, so it must \
             produce at least as many bytes"
        );

        // And the level the production viewer asked for is not the one that was
        // being used, which is the whole reason this function exists. Spelled out
        // as a ratio so the claim cannot be quietly satisfied by a change that
        // makes the two the same size by accident.
        let two = at(2);
        let six = at(6);
        assert_ne!(
            two, six,
            "level 2 and level 6 agree at {two} bytes, so the difference between them is \
             too small on this content to tell them apart and the test proves nothing"
        );
    }

    /// A level outside 0-to-9 is clamped rather than trusted.
    ///
    /// The number arrives off the wire, in a pseudo-encoding, from a client.
    /// `Compression::new` takes a `u32` and a level above 9 is not a level
    /// zlib defines, so passing one through would be asking the C library to
    /// do something unspecified with it.
    #[test]
    fn a_zlib_level_from_the_wire_is_clamped() {
        let mut encoders = Encoders::new(None);
        encoders.set_deflate_level(9);
        encoders.set_deflate_level(4_000_000_000);
        // And the encoder still works, which a level zlib rejected would not.
        let rect = Rect {
            left: 0,
            top: 0,
            width: 64,
            height: 64,
        };
        let pixels = photographic(64, 64);
        let (_codec, _data) = encoders
            .encode(
                Codec::Zlib,
                &HashSet::from([Encoding::Zlib]),
                &pixels,
                &format(),
                64 * 4,
                rect,
            )
            .expect("an encoder built at a clamped level still compresses");
    }

    /// A level asked for mid-connection is declined rather than obeyed.
    ///
    /// There is no `Compress::set_level` in flate2, so the only way to change a
    /// deflate level is to build a new compressor, and that ends the stream. The
    /// next rectangle would then start a new zlib stream inside a connection,
    /// and every client that keeps one inflater for the life of the connection
    /// would meet a header where it expected deflate data.
    ///
    /// So the request is refused and counted. This test pins both halves, because
    /// the second is the one that would otherwise be invisible: a level quietly
    /// not being applied looks exactly like a level being applied and ignored
    /// further up, and the log line for it was written for the other fault.
    /// Tight can now encode what it used to decline: more than 256 colours.
    ///
    /// **This is the sub-encoding whose absence made Tight unusable.** Every
    /// photograph and every video band has more than 256 colours in a 1280-wide
    /// rectangle, so `encode_tight` returned `None` for essentially all of a
    /// desktop and the client was served an encoding it had not listed first,
    /// after a palette scan that found nothing.
    ///
    /// The wire form is checked in the shape that matters, because every part of
    /// it can be wrong without anything failing loudly:
    ///
    /// - the control byte must be **0x00** — basic, zlib stream 0, no explicit
    ///   filter. With the filter bit set, a decoder reads a filter-id byte that is
    ///   not there and the *next* rectangle is misread.
    /// - the payload must inflate to **three bytes a pixel** for a client that is
    ///   `pixel24`, which is what note 1 of the Tight header requires.
    #[test]
    fn tight_encodes_more_than_two_hundred_and_fifty_six_colours() {
        let format = format();
        // 64x64 with every pixel a different colour: far past the palette's 256.
        let mut pixels = Vec::new();
        for i in 0..(64u32 * 64) {
            let n = i.wrapping_mul(2_654_435_761) >> 11;
            pixels.extend_from_slice(&[n as u8, (n >> 5) as u8, (n >> 11) as u8, 0]);
        }
        let rect = Rect::new(0, 0, 64, 64);
        let offered = HashSet::from([Encoding::Tight, Encoding::Zrle]);
        let mut encoders = Encoders::new(None);
        let (codec, bytes) = encoders
            .encode(Codec::Tight, &offered, &pixels, &format, 64 * 4, rect)
            .expect("Tight encodes many-coloured content now, or the encoder said \
                     nothing at all rather than falling back");

        assert_eq!(
            codec,
            Codec::Tight,
            "more than 256 colours went to ZRLE. That is what this sub-encoding \
             exists to prevent, and it is the state this test was written against."
        );
        assert_eq!(
            bytes[0],
            0x00,
            "the control byte is {:#04x}. It must be 0x00: basic compression on \
             zlib stream 0 with no explicit filter. A filter bit here would send \
             the decoder looking for a filter id that is not there.",
            bytes[0]
        );

        // The payload is a compact length and then a zlib stream, because 64x64x3
        // is far past the twelve-byte threshold.
        let (len, at) = read_compact(&bytes[1..]);
        assert!(
            len + at < bytes.len(),
            "the compact length says {len} bytes from offset {}, but the rectangle \
             is {} bytes: the framing and the payload disagree",
            at + 1,
            bytes.len()
        );
        let payload = &bytes[1 + at..1 + at + len];
        assert_eq!(
            payload[0],
            0x78,
            "the payload does not open with a zlib header ({:#04x}), so it is not \
             a zlib stream and no client could inflate it",
            payload[0]
        );
    }

    /// The client's first preference is the encoding, as QEMU reads it.
    ///
    /// **The production viewer's own list, from its log, as the test input.**
    ///
    /// ```text
    /// [1, 50, 7, -260, 16, 21, 5, 2, 6, 0, -26, -254, -223, -224,
    ///  -258, -261, -308, -309, -312, -313, -307, ..., -316, ..., -239]
    /// ```
    ///
    /// QEMU's `set_encodings` walks this **from the end** and assigns on every
    /// case it recognises, so what survives is the smallest index that had one.
    /// The assignments in order are `i=9 Raw`, `i=8 zlib`, `i=6 Hextile`,
    /// `i=4 ZRLE`, `i=3 TightPNG`, `i=2 Tight` — so **Tight**. Only CopyRect (1)
    /// and 50 come before it, and neither has a case.
    ///
    /// **The direction is the whole test.** A rule that returned the first match
    /// while walking backwards would give Raw, which is what this port's first
    /// version of the check did and what would have shipped the opposite answer.
    /// So the test states the assignments, not just the winner: a rule that picks
    /// the wrong end fails on Raw, and a rule that skips CopyRect but then
    /// returns Tight by luck still has to agree about ZRLE being at index 4.
    #[test]
    fn the_encoding_is_the_clients_first_and_not_its_last() {
        let wire: [i32; 25] = [
            1, 50, 7, -260, 16, 21, 5, 2, 6, 0, -26, -254, -223, -224, -258, -261, -308, -309,
            -312, -313, -307, -1_063_131_698, -316, 1_464_686_180, -239,
        ];
        let production: Vec<Encoding> = wire
        .into_iter()
        .map(|e| {
            // Parsed through the protocol's own reader rather than written out
            // by hand: the point is that *these* numbers mean these encodings, and
            // a hand-written list would test the list rather than the parser.
            Encoding::from_wire(e).expect("the production viewer's list parses")
        })
        .collect();
        assert_eq!(
            Policy::preferred_encoding(&production),
            Some(Codec::Tight),
            "the production viewer lists Tight at index 2 and ZRLE at index 4, so \
             Tight is its first real encoding and that is what QEMU serves. \
             Returning anything else means the list was walked the wrong way round \
             -- the last entry that has a case is Raw at index 9."
        );

        // Order is the whole rule, so the same set in another order is a
        // different answer. A `HashSet` cannot tell these apart, which is why
        // `ClientState::encodings` is a `Vec`.
        assert_eq!(
            Policy::preferred_encoding(&[Encoding::Zrle, Encoding::Tight]),
            Some(Codec::Zrle),
            "ZRLE first is ZRLE, whatever Tight is also offered"
        );
        assert_eq!(
            Policy::preferred_encoding(&[Encoding::Tight, Encoding::Zrle]),
            Some(Codec::Tight),
            "and Tight first is Tight"
        );

        // A list of nothing encodable has said nothing about pixels, so raw.
        assert_eq!(
            Policy::preferred_encoding(&[Encoding::DesktopSize, Encoding::LastRect]),
            None,
            "a list of pseudo-encodings only should give no preference at all, \
             not a guess"
        );
    }

    /// QEMU's `tight_conf[]`, and the two facts about it that are easy to get
    /// wrong from reading it.
    #[test]
    fn tight_levels_come_from_qemus_table_and_not_from_the_clients_number() {
        use crate::rfb::encodings::tight::conf;

        // At Tight level 2, `raw_zlib_level` is 2 -- which is why passing the
        // client's number straight to `deflateInit2` looked correct, and agrees
        // with QEMU at exactly one of the ten levels.
        assert_eq!(conf(2).raw_zlib_level, 2);

        // Everywhere else it disagrees, and the index stream more so.
        assert_eq!(
            conf(9).raw_zlib_level, 9,
            "QEMU deflates raw Tight data at level 9 when the client asked for 9"
        );
        assert_eq!(
            conf(3).idx_zlib_level, 5,
            "at Tight level 3 the palette's indexes go out at level 5, not at the \
             3 the client asked for"
        );
        assert_eq!(
            conf(0).idx_zlib_level, 0,
            "at Tight level 0 nothing is compressed at all, and this port \
             compressed anyway"
        );
        assert_eq!(
            conf(9).idx_zlib_level, 9,
            "and the client's level is an *index* here, not the level: 9 selects \
             the row whose index level is 9"
        );

        // Out of range is clamped rather than indexed off the end. A client may
        // send any 0..9 and `set_deflate_level` clamps before this is reached,
        // but the table is indexed with a `min` for the same reason zlib clamps.
        assert_eq!(conf(99).raw_zlib_level, conf(9).raw_zlib_level);

        // **The two index columns are identical in all ten rows.** That is why one
        // stream can serve both the palette and the two-colour case: QEMU
        // re-tunes with `deflateParams` per call and this port cannot, so if the
        // columns ever diverged a single stream could not serve both. Checked
        // rather than assumed, because the assumption would be invisible until a
        // client sent a level where they differ.
        for level in 0..=9u32 {
            assert_eq!(
                conf(level).idx_zlib_level,
                conf(level).mono_zlib_level,
                "at Tight level {level} the palette's indexes go out at level {} \
                 and the two-colour bits at level {}, which differ. One stream \
                 cannot serve both, and QEMU's `deflateParams` per call is not \
                 available here.",
                conf(level).idx_zlib_level,
                conf(level).mono_zlib_level
            );
        }
    }

    #[test]
    #[ignore = "a debug dump, not a check"]
    fn what_does_a_tight_full_colour_rectangle_look_like() {
        let format = format();
        // **Genuinely 4096 distinct colours.** The first attempt at this used
        // `(i * 4, i * 2, 0x33, 0)`, which is not injective -- `i` and `i + 128`
        // give the same pixel -- so the fixture had 128 colours, took the
        // *palette* path, and the dump showed a palette control byte (0x60)
        // where a full-colour one (0x00) belonged. A fixture that does not do
        // what it says, in a test whose whole subject is "more than 256
        // colours".
        let mut pixels = Vec::new();
        for i in 0..(64u32 * 64) {
            pixels.extend_from_slice(&[(i / 64) as u8, (i % 64) as u8, 0x33, 0]);
        }
        let rect = Rect::new(0, 0, 64, 64);
        let offered = HashSet::from([Encoding::Tight, Encoding::Zrle]);
        let mut encoders = Encoders::new(None);
        let (codec, bytes) = encoders
            .encode(Codec::Tight, &offered, &pixels, &format, 64 * 4, rect)
            .expect("encoded");
        println!("\n  codec {codec:?}, {} bytes", bytes.len());
        println!("  first 24: {:02x?}", &bytes[..24.min(bytes.len())]);
        let (len, at) = read_compact(&bytes[1..]);
        println!("  control {:02x}, compact len {len} in {at} bytes", bytes[0]);
        let payload = &bytes[1 + at..1 + at + len.min(bytes.len())];
        println!("  payload first 12: {:02x?}", &payload[..12.min(payload.len())]);
        println!("  payload is {} bytes for 64x64x3 = {}", len, 64 * 64 * 3);
    }

    /// ZRLE ignores a client's requested compression level, because QEMU's does.
    ///
    /// **The parity is an inversion, and it was written down backwards for a
    /// long time.** In QEMU's `set_encodings` the -254 pseudo-encoding lands in
    /// one place only — `vnc.c:2195`, `vc->worker.tight.compression`. ZRLE is not
    /// in that path: `vnc-enc-zrle.c:339` passes `Z_DEFAULT_COMPRESSION`, which
    /// zlib reads as **level 6**, so a QEMU serving ZRLE deflates at 6 whatever
    /// the client asked for.
    ///
    /// This port gave the client's number to ZRLE as well, so a viewer announcing
    /// `CompressionLevel(2)` was served 2 where QEMU would have served 6 — and
    /// An earlier revision of this port recorded that as matching QEMU.
    ///
    /// The assertion is on the bytes, not a timing: a timing would be a
    /// measurement pretending to be a check. ZRLE's output must be **identical at
    /// every level the client can ask for**, which is the observable consequence
    /// of the level not reaching that stream. If someone wires the level back in,
    /// level 1 and level 9 diverge and this fails.
    #[test]
    fn zrle_ignores_the_clients_compression_level_as_qemus_does() {
        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width: 320,
            height: 200,
        };
        let pixels = photographic(320, 200);
        let offered = HashSet::from([Encoding::Zrle]);

        let at = |level: u32| -> usize {
            let mut encoders = Encoders::new(None);
            encoders.set_deflate_level(level);
            let (_codec, data) = encoders
                .encode(Codec::Zrle, &offered, &pixels, &format, 320 * 4, rect)
                .expect("the zrle encoder");
            data.len()
        };

        let zero = at(0);
        let two = at(2);
        let six = at(6);
        let nine = at(9);

        assert_eq!(
            zero, nine,
            "ZRLE produced {zero} bytes at level 0 and {nine} at level 9. QEMU \
             passes Z_DEFAULT_COMPRESSION to ZRLE regardless of the client, so \
             every level must give the same length. Differing lengths mean the \
             client's level has reached the ZRLE stream, which is the bug this \
             test was written for."
        );
        assert_eq!(
            two, six,
            "ZRLE gave {two} bytes at the production viewer's level 2 and {six} \
             at 6. Those must be identical for the same reason."
        );
    }

    /// The client's level does reach Tight, and hextile, which is what QEMU
    /// does and what `set_deflate_level` used to get wrong in the other
    /// direction by getting ZRLE wrong at all.
    ///
    /// Without this, "ZRLE ignores the level" is satisfied just as well by a
    /// `set_deflate_level` that does nothing at all -- which is the shape a bad
    /// fix takes, and the shape this took for one build while being written.
    ///
    /// **The content has to be one Tight can represent.** This port implements
    /// Tight's fill and palette sub-encodings and not `send_full_color_rect`, so
    /// a rectangle of more than 256 colours returns `None`, falls back to ZRLE,
    /// and produces byte-identical output at every level -- because it was
    /// measuring ZRLE twice. Three versions of this test got that wrong in
    /// slightly different ways, all reporting the same false conclusion: that
    /// the level was not reaching the compressor. So the pixels here are a
    /// few-colour image, which Tight genuinely encodes, and the codec that comes
    /// back is asserted before its length is compared -- otherwise a fallback
    /// is invisible.
    #[test]
    fn the_clients_level_reaches_tight_and_hextile() {
        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width: 320,
            height: 200,
        };
        // Four colours: enough for a palette, few enough that Tight takes it.
        let pixels = few_colours(320, 200, 4);
        assert!(
            pixels.len() == 320 * 200 * 4,
            "the fixture is not a whole number of pixels, so every length \
             derived from it would be wrong"
        );

        for (codec, offered, name) in [
            (Codec::Tight, Encoding::Tight, "tight"),
            (Codec::Zlib, Encoding::Zlib, "hextile"),
        ] {
            // ZRLE in the set because `Codec::Tight` falls back to it and
            // `encode` only walks a fallback the client also offered -- a set of
            // Tight alone returns `None` even when Tight encodes the content
            // perfectly well. Offering it makes a fallback possible rather than
            // fatal, which is what lets the assertion below notice one.
            let offered_set = HashSet::from([offered, Encoding::Zrle]);
            let at = |level: u32| -> (Codec, usize) {
                let mut encoders = Encoders::new(None);
                encoders.set_deflate_level(level);
                let (used, data) = encoders
                    .encode(codec, &offered_set, &pixels, &format, 320 * 4, rect)
                    .expect("the encoder produced something");
                (used, data.len())
            };

            let (at_one, one) = at(1);
            let (_at_nine, nine) = at(9);
            assert_eq!(
                at_one, codec,
                "{name} fell back to {at_one:?} on content it should have \
                 encoded itself, so the lengths below would be another codec's"
            );
            assert_ne!(
                one, nine,
                "{name} produced {one} bytes at level 1 and {nine} at level 9, so \
                 the client's level is not reaching its compressor. QEMU gives \
                 that number to `tight.compression` and to hextile, and \
                 `set_deflate_level` must reach both -- or a client that asked \
                 for a trade-off is being ignored, and the ZRLE test beside this \
                 one would pass just as well if it reached nothing at all."
            );
        }
    }

    /// `count` distinct colours in a grid pattern, as `x8r8g8b8`.
    ///
    /// Not photographic on purpose: see
    /// `the_clients_level_reaches_tight_and_hextile`, which needs content Tight
    /// will actually encode.
    fn few_colours(width: u16, height: u16, count: usize) -> Vec<u8> {
        let palette: Vec<[u8; 3]> = (0..count)
            .map(|i| [(i * 61) as u8, (i * 97) as u8, (i * 29) as u8])
            .collect();
        let mut out = Vec::with_capacity(usize::from(width) * usize::from(height) * 4);
        for y in 0..usize::from(height) {
            for x in 0..usize::from(width) {
                let rgb = palette[(x / 8 + y / 8) % palette.len()];
                // x8r8g8b8 is B, G, R, unused.
                out.extend_from_slice(&[rgb[2], rgb[1], rgb[0], 0]);
            }
        }
        out
    }

    #[test]
    fn a_level_asked_for_mid_connection_is_declined_and_counted() {
        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width: 320,
            height: 200,
        };
        let pixels = photographic(320, 200);
        let offered = HashSet::from([Encoding::Zlib]);
        let mut encoders = Encoders::new(None);

        // Before anything has been sent: honoured, and this is the case that
        // occurs in practice, because -254 arrives with SetEncodings.
        encoders.set_deflate_level(9);
        assert_eq!(encoders.declined_levels(), 0, "nothing was sent yet");
        let (_codec, first) = encoders
            .encode(Codec::Zlib, &offered, &pixels, &format, 320 * 4, rect)
            .expect("the hextile encoder");

        // After: refused, counted, and the level left alone.
        encoders.set_deflate_level(1);
        assert_eq!(
            encoders.declined_levels(),
            1,
            "a level asked for after the stream was in use was neither applied nor counted"
        );
        let (_codec, second) = encoders
            .encode(Codec::Zlib, &offered, &pixels, &format, 320 * 4, rect)
            .expect("the hextile encoder");

        // The direct evidence, rather than a size comparison: a compressor that
        // had been rebuilt to take the new level would have written a fresh zlib
        // header, and a header is `0x78`. Two rectangles in a row off one stream
        // means the second begins with deflate data, not with a header.
        //
        // Comparing the two lengths instead would have been the obvious thing and
        // it does not work: the second rectangle continues the first one's
        // stream, so its output is a couple of bytes different from an
        // identical first one, which is a difference of *content* and says
        // nothing about the level.
        assert_eq!(
            first[0],
            0x78,
            "the first rectangle should open the stream with a zlib header"
        );
        assert_ne!(
            second[0],
            0x78,
            "the second rectangle opens with a zlib header ({:#04x}), so the compressor was \
             rebuilt when the level was asked for. That ends the stream mid-connection, and \
             every client that keeps one inflater for the life of the connection meets a \
             header where it expected deflate data",
            second[0]
        );
    }

    /// What it would take to hold sixty frames a second.
    ///
    /// The frame rate and the CPU are the same number. The encode is inline, so
    /// `fps = 1/cost`, and `cost x fps = 1 second = one core` — which means
    /// "sixty frames a second" and "not at a hundred per cent" are one
    /// requirement and not two: the encode has to fit in 16.7 milliseconds.
    ///
    /// Everything else follows from that budget, and this table is the budget
    /// spent in the ways available. It is here to answer a strategy question
    /// with arithmetic rather than with a list of plausible ideas, because three
    /// of the ideas that sound best do not move this number at all:
    ///
    /// * **A worker thread** is QEMU parity and it is worth doing, but it moves
    ///   the cost to another core. It does not make it smaller, so a hundred per
    ///   cent of *a* core becomes a hundred per cent of *this* core plus a
    ///   hundred per cent of that one. It fixes latency, not CPU.
    /// * **Encoding rectangles in parallel** is the obvious way to use several
    ///   cores and it is not available. Deflate is serial within a stream, so
    ///   parallel rectangles would need parallel streams, and a client keeps one
    ///   inflater per *connection* — it has no way to know there were four. The
    ///   single-stream convention is what forecloses this, which is a real cost
    ///   of that decision and worth saying out loud.
    /// * **Dropping frames** trades CPU for latency, and the latency is the
    ///   thing being complained about. It is a dial between two complaints, not
    ///   an improvement on either.
    ///
    /// What does move the number is on the table: the deflate level, which is the
    /// client's to choose, JPEG, which is cheaper and lossy, and the area of the
    /// rectangle, which is the guest's to decide and the one that matters most,
    /// because real video does not change every pixel of every frame.
    ///
    /// **Run this in release.** ```sh
    /// cargo test -p qemu-vnc --release --all-features --lib what_it_would_take_to_hold_sixty -- --nocapture
    /// ```
    #[test]
    #[ignore = "a measurement, not a check: needs an optimised build and a reader"]
    #[cfg(feature = "lossy")]
    fn what_it_would_take_to_hold_sixty() {
        const W: u16 = 1280;
        const H: u16 = 800;
        const ROUNDS: u32 = 5;
        /// Sixty frames a second, and the budget one frame gets.
        const BUDGET_MS: f64 = 1000.0 / 60.0;

        let format = format();
        let all = HashSet::from([
            Encoding::Raw,
            Encoding::Zlib,
            Encoding::Zrle,
            Encoding::Tight,
            Encoding::Jpeg(80),
        ]);
        let pixels = photographic(W, H);
        let _full = Rect {
            left: 0,
            top: 0,
            width: W,
            height: H,
        };

        let time = |codec: Codec, level: u32, w: u16, h: u16| -> (f64, usize) {
            let mut encoders = Encoders::new(Some(80));
            encoders.set_deflate_level(level);
            let rect = Rect {
                left: 0,
                top: 0,
                width: w,
                height: h,
            };
            // The damage is taken from the top-left, which is what a growing
            // dirty region looks like.
            let sub = &pixels[..usize::from(w) * usize::from(h) * 4];
            let _ = encoders.encode(codec, &all, sub, &format, usize::from(w) * 4, rect);
            let started = std::time::Instant::now();
            let mut bytes = 0usize;
            for _ in 0..ROUNDS {
                if let Some((_c, data)) =
                    encoders.encode(codec, &all, sub, &format, usize::from(w) * 4, rect)
                {
                    bytes = data.len();
                }
            }
            (started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0, bytes)
        };

        println!(
            "\n  the budget is {BUDGET_MS:.1} ms per frame, and a frame that costs more \
             than that\n  is a frame rate below sixty no matter what the interval says\n"
        );
        println!(
            "  {:<22} {:>8} {:>7} {:>9} {:>10}",
            "how", "ms/frame", "fps", "bytes", "in budget"
        );

        // The full screen, at the level a real viewer asks for, and at the level
        // below it that it did not.
        for (label, level) in [("full screen, level 2", 2u32), ("full screen, level 1", 1)] {
            let (ms, bytes) = time(Codec::Zrle, level, W, H);
            println!(
                "  {label:<22} {ms:>8.1} {:>7.1} {bytes:>9} {:>10}",
                1.0 / (ms / 1000.0),
                if ms <= BUDGET_MS { "yes" } else { "NO" }
            );
        }

        // Lossy. Cheaper by a wide margin, and the picture is worse, which is
        // why the feature is off by default and why QEMU needs `-vnc lossy`.
        let (ms, bytes) = time(Codec::Jpeg, 6, W, H);
        println!(
            "  {:<22} {ms:>8.1} {:>7.1} {bytes:>9} {:>10}",
            "full screen, jpeg 80",
            1.0 / (ms / 1000.0),
            if ms <= BUDGET_MS { "yes" } else { "NO" }
        );

        // And the one that matters most: how much of the screen has to change
        // before sixty frames a second stops being affordable.
        println!();
        for (w, h) in [
            (1280u16, 800u16),
            (960, 600),
            (640, 400),
            (512, 320),
            (320, 200),
            (160, 100),
        ] {
            let (ms, bytes) = time(Codec::Zrle, 2, w, h);
            println!(
                "  {:<22} {ms:>8.1} {:>7.1} {bytes:>9} {:>10}",
                format!("zrle level 2, {w}x{h}"),
                1.0 / (ms / 1000.0),
                if ms <= BUDGET_MS { "yes" } else { "NO" }
            );
        }
        println!(
            "\n  the last table is the useful one: it says the cost tracks the area of the \
             damage,\n  so whether sixty frames a second is affordable is mostly a question \
             about the\n  guest and not about this crate. A guest that repaints a quarter of \
             the screen\n  per frame is inside budget at level 2. One that repaints all of \
             it is not.\n"
        );
    }

    /// How much of a ZRLE frame is deflate and how much is everything else.
    ///
    /// Two backends disagree about this frame by a factor of two, and the
    /// disagreement is the measurement. `miniz_oxide` at deflate level 1 encodes
    /// a 1280x800 frame in 13.4 ms; the system zlib backend takes about 29 ms at
    /// *every* level from 1 to 3, which is not how a cost that is mostly deflate
    /// behaves. A cost that barely moves with the deflate level is a cost that is
    /// mostly *not* deflate, and 29 ms of ZRLE that is not deflate would be a
    /// 2x win sitting in our own palette code rather than out of reach in a
    /// compression library.
    ///
    /// But 13.4 ms of total is *less* than a supposed 29 ms of palette work, so
    /// one of those two numbers cannot be right, and guessing between them is how
    /// a week goes. So: compress a buffer of the same size and shape on its own
    /// and subtract. The remainder is everything the encoder does before deflate
    /// sees anything — building a palette per 64x64 tile, counting occurrences,
    /// sorting them by frequency, and writing the indexes out.
    ///
    /// This reaches into the encoder's private half deliberately. The whole
    /// point is to time the two halves separately, and there is no other way to
    /// do that without putting a clock inside production code.
    ///
/// What a faster deflate is worth, measured rather than assumed.
///
/// The obvious idea for a server that will not hit sixty frames a second is to
/// compress faster, and `flate2` will use `zlib-ng` instead of the default
/// `miniz_oxide` for the price of a line in `Cargo.toml` and a C toolchain:
///
/// ```toml
/// flate2 = { version = "1.0", features = ["zlib-ng"] }
/// ```
///
/// Measured on a 1280x800 frame, three runs each, release build — and the
/// level-to-level comparison is not like for like, because `zlib-ng`'s level
/// *n* is not `zlib`'s level *n*: it produces slightly larger output for the
/// same number, so part of what follows is a different point on the curve
/// rather than a better implementation.
///
/// ```text
///                   level 1   level 2   level 6
///   ZRLE  miniz_oxide   13.4      30.6      40.4     ms
///   ZRLE  zlib-ng       14.7      22.3      26.4
///   hextile miniz       15.8      23.2      48.0
///   hextile zlib-ng     10.7      15.2      18.3
/// ```
///
/// Two things follow, and the second is the interesting one.
///
/// At deflate level 2 — the level a real viewer asks for — a 1280x800 frame
/// goes from 30.6 ms to 22.3 ms, which is 45 frames a second. **Not enough.**
/// The budget for sixty is 16.7 ms.
///
/// **And the reason it is not enough is not the frame this section measured.**
/// The remainder here was called "palette work" and valued at 11.8 ms, and both
/// the number and the name were artefacts: it came from subtracting a deflate
/// timed on raw pixels from a total timed on the tile stream the builder
/// actually produces — 3.07 MB against 4.10 MB, which are not the same
/// compressibility and so are not the same quantity. Measured properly, each
/// half on the same data, the tile builder costs 4.8 ms for content with more
/// than sixteen colours per tile and **45.3 ms** for content with between two
/// and sixteen, which is the palette path proper. `what_the_tile_builder_costs`
/// is that measurement and it supersedes the subtraction.
///
/// What a faster deflate does change is the builder's *share*. Under
/// `miniz_oxide` at level 2 the frame is 30.6 ms with the same builder in it;
/// under `zlib-ng` it is 22.3 ms, so the same builder is a much larger fraction.
/// And how large the builder is depends entirely on the content — 4.8 ms for a
/// photographic frame, 45.3 ms for a tiled one — so the sixty-frame question has
/// a different answer for a desktop full of icons and text than it has for
/// video, and no single figure describes both.
///
/// **The backend that answers it without a C toolchain is `zlib-rs`, and that
/// is the whole of the update.** The first version of this note concluded the
/// speed-up was unavailable, because the cargo cache held only `libz-sys`. That
/// was an inference from a directory listing rather than a test, and it was
/// wrong: `cargo fetch` resolved and downloaded `libz-ng-sys` on the first
/// attempt. The `curl` probe that seemed to confirm the opposite was asking for
/// `index.crates.io/{len}/{first-two}/{name}`, which this network's CDN answers
/// `NoSuchKey` — and it answered the same way for `flate2`, a crate certainly in
/// the cache. A probe that fails for something known to exist is measuring the
/// probe.
///
/// Every backend flate2 1.1.10 offers, one 1280x800 frame, release, ms:
///
/// ```text
///   backend            ZRLE L1  L2    L6     hextile L1  L2    C toolchain
///   miniz_oxide (dflt)  14.3  29.1  40.4       14.9  22.6    no
///   zlib-rs             15.6  22.5  28.8       10.8  14.8    no
///   zlib-ng             14.7  22.3  26.4       10.7  15.2    yes, cmake
///   zlib-default        30.9  29.6  35.5       22.7  24.4    yes
///   cloudflare_zlib     28.1  30.0  32.8       22.6  26.2    yes
/// ```
///
/// `libdeflate` is not on that list at all: flate2 1.1.10 has no such backend,
/// and reaching one means pinning to an older flate2.
///
/// So `zlib-rs` gives the same 1.4-1.5x as `zlib-ng` — the two agree to within
/// a millisecond at every level that matters — **and needs no C, no cmake and
/// no system library**, which dissolves the objection that made this look like
/// a non-starter. `zlib-default` and `cloudflare_zlib` are both *slower* than
/// the default at level 1 and no better at level 2, so they go on the
/// measurement rather than on principle.
///
/// Verified rather than assumed: 171 tests green on it, and a strip sent
/// through the server decoded by a client sharing no code with it — 0 wrong
/// pixels of 4160 — plus libvncclient reading the first frame. A round trip
/// through this crate's own decoder would have proved nothing, which is the
/// whole of §8.
///
/// Two costs, both stated rather than buried. `zlib-rs`'s level *n* is not
/// `miniz_oxide`'s level *n*: at level 2 it emits about five per cent more and
/// at level 1 about nine, so a client asking for a level is asking for a point
/// on a curve that moved under it — not a correctness problem, but not the same
/// promise either. And it is *slower* for ZRLE at level 1, 15.6 against 14.3,
/// so the change is a trade at that one point and a win everywhere else.
///
/// There is a tension in the table worth naming. The cheapest in-budget row
/// is hextile at 15.2 ms, and hextile is encoding 6 — the encoding this port
/// deliberately stopped sending to a client that can do ZRLE, because a real
/// viewer rejects it. So the fastest option available is one we have ruled
/// out, and that is a cost of the ruling-out which nobody had the numbers to
/// see when it was made.
    ///
    /// **Run this in release.** ```sh
    /// cargo test -p qemu-vnc --release --lib how_much_of_a_zrle_frame_is_deflate -- --nocapture
    /// ```
    #[test]
    #[ignore = "a measurement, not a check: needs an optimised build and a reader"]
    fn how_much_of_a_zrle_frame_is_deflate() {
        use super::Zlib;

        const W: u16 = 1280;
        const H: u16 = 800;
        const ROUNDS: u32 = 5;
        /// Tiles across and down: ZRLE's tile is 64x64.
        const TILE: u16 = 64;

        let format = format();
        let rect = Rect {
            left: 0,
            top: 0,
            width: W,
            height: H,
        };
        let pixels = photographic(W, H);
        let all = HashSet::from([Encoding::Zrle]);

        // The whole encode, per level.
        let mut total_ms = Vec::new();
        for level in [1u32, 2, 6] {
            let mut encoders = Encoders::new(None);
            encoders.set_deflate_level(level);
            let _ = encoders.encode(Codec::Zrle, &all, &pixels, &format, W as usize * 4, rect);
            let started = std::time::Instant::now();
            for _ in 0..ROUNDS {
                let _ = encoders.encode(Codec::Zrle, &all, &pixels, &format, W as usize * 4, rect);
            }
            total_ms.push(started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0);
        }

        // Deflate alone, on the same photographic bytes ZRLE is fed.
        //
        // The first version of this used a buffer built from repeated 16 KB tiles
        // "of the same shape", and the result was nonsense that looked like a
        // finding: the non-deflate remainder came out *growing* with the deflate
        // level, 4.6 ms at 1 and 31.2 ms at 6, and palette-building cannot depend
        // on the deflate level. A repeated tile is almost free to compress, so
        // that column measured deflate on a holiday and the difference between
        // it and the total absorbed everything else. Same bytes, same
        // incompressibility, same bytes-per-second.
        //
        // This is still an approximation and the doc comment above says so: what
        // ZRLE actually hands deflate is tile-structured with a palette per tile,
        // so it is more compressible than the raw pixels and this over-charges
        // the deflate half. Over-charging is the safe direction here, because the
        // question is whether a 2x is available in *our* code, and over-charging
        // deflate makes that look less likely.
        let stream = pixels.clone();
        let _ = (W / TILE, H / TILE);
        let mut deflate_ms = Vec::new();
        for level in [1u32, 2, 6] {
            let mut zlib = Zlib::with_level(level);
            let _ = zlib.compress(&stream);
            let started = std::time::Instant::now();
            for _ in 0..ROUNDS {
                let _ = zlib.compress(&stream);
            }
            deflate_ms.push(started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0);
        }

        println!(
            "\n  a {W}x{H} ZRLE frame, {ROUNDS} rounds, release build\n"
        );
        println!(
            "  {:<7} {:>12} {:>12} {:>14} {:>8}",
            "level", "total ms", "deflate ms", "the rest ms", "rest %"
        );
        for (i, level) in [1u32, 2, 6].iter().enumerate() {
            let total = total_ms[i];
            let defl = deflate_ms[i];
            let rest = total - defl;
            println!(
                "  {level:<7} {total:>12.1} {defl:>12.1} {rest:>14.1} {:>7.0}%",
                rest / total * 100.0
            );
        }
        println!(
            "\n  the deflate column is measured on a {}-byte buffer of photographic pixels, not\n  \
             on ZRLE's own pre-compression stream. ZRLE hands deflate a tile-and-palette\n  \
             stream, which compresses better than raw pixels, so this over-charges deflate and\n  \
             under-charges the palette half. Over-charging is the safe direction for the\n  \
             question being asked, which is whether a speed-up is available in our own code.\n",
            stream.len()
        );
    }



    /// What the ZRLE tile builder costs, measured rather than inferred.
    ///
    /// Earlier versions of this section subtracted an independently measured
    /// deflate from a total and called the remainder "the palette work". That is
    /// arithmetic on two different buffers — the deflate was timed on raw
    /// photographic pixels while ZRLE hands deflate a tile-and-palette stream —
    /// so the remainder absorbed the difference between them, and a number that
    /// grew with the deflate level came out of it before the proxy was fixed.
    ///
    /// This measures the two halves on the *same* data instead. The tile builder
    /// is `zrle_tile`, called once per tile into a scratch buffer with no
    /// compression involved at all; `Zlib::compress` is then timed on the exact
    /// bytes the builder produced. Nothing is subtracted across buffers, so the
    /// two numbers can be added and the sum compared against a whole-frame
    /// encode as a check that nothing else is hiding in there.
    ///
    /// It is worth knowing which half is which, because the answer decides
    /// whether there is anything to optimise in this crate at all. Per 64x64
    /// tile the builder does:
    ///
    /// * a full pass counting colours, and for **each pixel** a linear search
    ///   over up to sixteen entries comparing byte slices — 4096 x 16 in the
    ///   worst case, 260 tiles at 1280x800;
    /// * over sixteen colours, a raw fallback at three bytes a pixel;
    /// * otherwise a sort, and a `HashMap<&[u8], u8>` built from scratch;
    /// * a second full pass packing indices, with a **hash lookup per pixel**.
    ///
    /// The hash map is the obvious suspect: an allocation per tile and a SipHash
    /// per pixel, something like a million of them. But "obvious suspect" is not
    /// a measurement, which is the entire reason this test exists.
    ///
    /// **Run this in release.** ```sh
    /// cargo test -p qemu-vnc --release --lib what_the_tile_builder_costs -- --nocapture
    /// ```
    #[test]
    #[ignore = "a measurement, not a check: needs an optimised build and a reader"]
    fn what_the_tile_builder_costs() {
        use super::{Zlib, ZRLE_TILE};

        const W: u16 = 1280;
        const H: u16 = 800;
        const ROUNDS: u32 = 5;

        let format = format();
        let pixels = photographic(W, H);
        let stride = usize::from(W) * 4;
        let full_frame = crate::rfb::Rect {
            left: 0,
            top: 0,
            width: W,
            height: H,
        };

        // The two content shapes that decide everything, because a tile is
        // either palette-able or not and the two take different paths.
        let mut shapes: Vec<(&str, Vec<u8>)> = vec![
            ("many colours per tile", pixels.clone()),
            (
                "few colours per tile",
                (0..stride * usize::from(H))
                    .map(|i| if i % 4 == 0 { 0x20 } else if i % 4 == 1 { 0x40 } else { 0x60 })
                    .collect(),
            ),
        ];
        // And one that genuinely takes the palette path, which the other two do
        // not. A 64x64 ZRLE tile holds at most sixteen colours; anything with
        // more is sent raw, and both of the shapes above have hundreds per
        // tile, so both were measuring the raw fallback and neither touched the
        // sort, the index map, or the packed-index pass at all. Calling a
        // gradient "the palette path" was wrong twice over: a smooth gradient
        // across 1280 pixels has more than sixteen distinct values in every
        // tile, so it is raw too.
        //
        // Sixteen-pixel blocks, each one colour drawn from a set of sixteen, so
        // every tile holds exactly sixteen and the palette path is the one
        // taken. This is the shape a desktop icon grid or a tiled UI has, and
        // it is the only one of the three that exercises the code the
        // optimisation would be aimed at.
        let blocky: Vec<u8> = (0..stride * usize::from(H))
            .map(|i| {
                let (x, y) = (i % stride / 4, i / stride);
                let which = ((x / 16) + (y / 16) * 4) % 16;
                match i % 4 {
                    0 => (which * 16) as u8,
                    1 => (which * 8) as u8,
                    2 => (which * 4) as u8,
                    _ => 0,
                }
            })
            .collect();
        shapes.push(("16 colours, palette path", blocky));

        println!("\n  a {W}x{H} frame, {ROUNDS} rounds, release build\n");
        println!(
            "  {:<24} {:>10} {:>10} {:>9} {:>8}",
            "content", "build ms", "deflate ms", "sum ms", "build %"
        );
        for (name, data) in &shapes {
            let mut scratch = Vec::with_capacity(data.len());
            let mut zlib = Zlib::with_level(2);

            // The builder, on the same frame `encode_zrle` walks: one
            // `RectPixels` over the whole frame, then every tile in it. No
            // compression is involved, so this is the palette path and nothing
            // else.
            let mut encoders = Encoders::new(None);
            let frame = RectPixels::new(data, &format, stride, full_frame);
            let mut build_all = |scratch: &mut Vec<u8>| {
                for ty in (0..usize::from(H)).step_by(ZRLE_TILE as usize) {
                    for tx in (0..usize::from(W)).step_by(ZRLE_TILE as usize) {
                        let tw = (usize::from(W) - tx).min(ZRLE_TILE as usize) as u16;
                        let th = (usize::from(H) - ty).min(ZRLE_TILE as usize) as u16;
                        let _ = encoders.zrle_tile(&frame, tx as u16, ty as u16, tw, th, scratch);
                    }
                }
            };

            // Warm both, so the first call's allocation is not in either number.
            build_all(&mut scratch);
            let _ = zlib.compress(&scratch);

            let started = std::time::Instant::now();
            for _ in 0..ROUNDS {
                scratch.clear();
                build_all(&mut scratch);
            }
            let build = started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0;
            let bytes = scratch.len();

            let started = std::time::Instant::now();
            for _ in 0..ROUNDS {
                let _ = zlib.compress(&scratch);
            }
            let deflate = started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0;

            println!(
                "  {name:<24} {build:>10.1} {deflate:>10.1} {:>9.1} {:>7.0}%",
                build + deflate,
                build / (build + deflate) * 100.0
            );
            println!(
                "  {:<24} the builder wrote {bytes} bytes for {} pixels",
                "",
                usize::from(W) * usize::from(H)
            );
        }
    }



    /// A ZRLE tile is what a naive encoder reading the format would produce.
    ///
    /// The tile builder is a fixed open-addressed table with Fibonacci hashing,
    /// which is fast because the straightforward version it replaced was not:
    /// 45.3 ms for a 1280x800 frame against 4.8 ms for content on the raw path.
    /// Fast and correct are separate claims, and this is the one about correct.
    ///
    /// The obvious way to test that rewrite is to compare the new code against
    /// the old, and it is worth nothing: the old code *was* the definition, so
    /// the test would pin the new code to a bug if the old code had one, and to
    /// a quirk if it did not. It would also have stopped existing the moment
    /// the old code was deleted, which is to say it would not have outlasted
    /// the change it was written for.
    ///
    /// So the reference here is written from the *format* and is deliberately
    /// as slow and as obvious as possible: a linear scan for every pixel's
    /// colour, a `Vec` for the palette, a `BTreeMap` for the packed indices, and
    /// no hashing of any kind. It is the kind of code that is correct by
    /// inspection, which is the property a reference needs and speed does not.
    ///
    /// The corpus is built to reach every branch, because a corpus that misses
    /// one is a test that passes for the wrong reason:
    ///
    /// * one colour, which takes the solid sub-encoding;
    /// * two, three, four and five colours, which take packed widths of 1, 2 and
    ///   4 bits and so exercise the row padding at three different rates;
    /// * sixteen, the largest a palette may be;
    /// * seventeen, one over, which must fall back to raw — the boundary is
    ///   where an off-by-one hides, and `>=` versus `>` matters here;
    /// * every colour in the *last* pixel, so the first-seen order and the
    ///   count order disagree and the sort has to do real work;
    /// * a gradient, whose colours are numerically adjacent and which therefore
    ///   collides in the hash table, so the probe path runs;
    /// * a tile narrower and shorter than 64, since the edge tiles are clipped
    ///   and a table sized for the interior is wrong for them.
    #[test]
    fn a_zrle_tile_is_what_a_naive_encoder_would_produce() {
        let format = format();
        let rect = crate::rfb::Rect {
            left: 0,
            top: 0,
            width: 64,
            height: 64,
        };

        // A deterministic little generator, so a failure is reproducible and the
        // corpus does not change from run to run.
        let mut state = 0x1234_5678u32;
        let mut next = move || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state >> 24
        };

        let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
        for colours in [1usize, 2, 3, 4, 5, 15, 16, 17, 40] {
            // Each colour is four bytes, x8r8g8b8, so a distinct u32 is a
            // distinct pixel.
            let mut data = vec![0u8; 64 * 64 * 4];
            for i in 0..64 * 64 {
                let which = next() as usize % colours;
                data[i * 4] = which as u8;
                data[i * 4 + 1] = (which * 3) as u8;
                data[i * 4 + 2] = (which * 7) as u8;
            }
            cases.push((format!("{colours} random colours"), data));
        }
        // Solid.
        cases.push((
            "solid".into(),
            (0..64 * 64 * 4).map(|i| if i % 4 == 3 { 0 } else { 0x5a }).collect(),
        ));
        // Every colour first seen in the very last pixel, so discovery order and
        // frequency order disagree completely.
        let mut data = vec![0x11u8; 64 * 64 * 4];
        for n in 0..5usize {
            let o = (64 * 64 - 1 - n) * 4;
            data[o] = 0x20 + n as u8;
            data[o + 1] = 0x30 + n as u8;
            data[o + 2] = 0x40 + n as u8;
        }
        cases.push(("colours discovered last".into(), data));
        // A gradient: numerically adjacent colours, so the hash collides.
        let data = (0..64 * 64 * 4)
            .map(|i| match i % 4 {
                0 => ((i / 4) % 256) as u8,
                1 => ((i / 256) % 256) as u8,
                2 => 0,
                _ => 0,
            })
            .collect();
        cases.push(("gradient, adjacent colours".into(), data));

        // Colours built to collide, because the others do not and the probe is
        // the branch most likely to be quietly untested. Sixty-four slots for
        // sixteen entries should collide by the birthday bound about four times
        // in five, and yet a corpus of scattered colours produced none across
        // every case above — so a mutation that removed the probe entirely, and
        // so silently dropped any colour that landed on an occupied slot, passed
        // this test. That is the test's corpus failing rather than the code, and
        // it is the same shape as the twenty-byte tile error in §8: a plausible
        // number nobody checked.
        //
        // So: find colours that provably hash to one slot, by asking the same
        // function the encoder asks.
        let mut colliding: Vec<u32> = Vec::new();
        let mut candidate = 0u32;
        while colliding.len() < 6 && candidate < 1 << 20 {
            let value = candidate;
            // The first candidate is a colour whatever its slot — it is what the
            // others have to agree with — and after that only a candidate in the
            // same slot is taken.
            let wanted = colliding
                .first()
                .is_none_or(|first| zrle_slot(&value.to_le_bytes()) == zrle_slot(&first.to_le_bytes()));
            if wanted {
                colliding.push(value);
            }
            candidate += 1;
        }
        assert!(
            colliding.len() >= 4,
            "could not find four colours that collide, so the probe is untested"
        );
        let mut data = vec![0u8; 64 * 64 * 4];
        for i in 0..64 * 64 {
            // The bytes written are the bytes that were searched, which is the
            // whole point and the first version got it wrong: it wrote
            // `[which, which * 3, which * 7, 0]` while the search had hashed
            // `value.to_le_bytes()`. Different words, so a different slot, so a
            // corpus labelled "all one slot" in which no two colours collided
            // at all — and a mutation that deleted the probe passed it, twice,
            // and so did a `panic!()` planted on the collision branch, which is
            // how it was found. A corpus that does not reach the branch it names
            // is worse than no corpus, because it is counted as coverage.
            let value = colliding[next() as usize % colliding.len()];
            data[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        cases.push((
            format!("{} colours, all one slot", colliding.len()),
            data,
        ));

        for (name, data) in &cases {
            let pixels = RectPixels::new(data, &format, 64 * 4, rect);
            let mut fast = Vec::new();
            let sub = Encoders::new(None)
                .zrle_tile(&pixels, 0, 0, 64, 64, &mut fast)
                .expect("the tile builder");

            let (want_sub, want) = naive_zrle_tile(data, &format, 64, 64);

            assert_eq!(
                sub, want_sub,
                "{name}: sub-encoding {sub} where a naive encoder says {want_sub}"
            );
            assert_eq!(
                fast, want,
                "{name}: {} bytes where a naive encoder says {}",
                fast.len(),
                want.len()
            );
        }

        // And the clipped edge tiles, which are a different shape entirely and
        // where a table or a bit count sized for 64x64 would be wrong.
        for (w, h) in [(64u16, 64u16), (64, 17), (17, 64), (1, 1), (13, 3)] {
            let data: Vec<u8> = (0..usize::from(w) * usize::from(h) * 4)
                .map(|i| if i % 4 == 3 { 0 } else { (i / 4) as u8 % 7 })
                .collect();
            let rect = crate::rfb::Rect {
                left: 0,
                top: 0,
                width: w,
                height: h,
            };
            let pixels = RectPixels::new(&data, &format, usize::from(w) * 4, rect);
            let mut fast = Vec::new();
            let sub = Encoders::new(None)
                .zrle_tile(&pixels, 0, 0, w, h, &mut fast)
                .expect("the tile builder");
            let (want_sub, want) = naive_zrle_tile(&data, &format, w, h);
            assert_eq!(sub, want_sub, "{w}x{h}: sub-encoding");
            assert_eq!(fast, want, "{w}x{h}: tile bytes");
        }
    }

    /// A ZRLE tile written the slow, obvious way: a linear scan per pixel, a
    /// `Vec` for the palette, a `BTreeMap` for the packed indices, and no
    /// hashing anywhere. Slow on purpose, and correct by inspection.
    fn naive_zrle_tile(
        data: &[u8],
        format: &PixelFormat,
        w: u16,
        h: u16,
    ) -> (u8, Vec<u8>) {
        let pixel = |x: u16, y: u16| -> &[u8] {
            let o = (usize::from(y) * usize::from(w) + usize::from(x)) * bpp(format);
            &data[o..o + bpp(format)]
        };
        let mut palette: Vec<(&[u8], u16)> = Vec::new();
        let mut too_many = false;
        'outer: for y in 0..h {
            for x in 0..w {
                let p = pixel(x, y);
                let mut found = None;
                for (n, (colour, _)) in palette.iter().enumerate() {
                    if *colour == p {
                        found = Some(n);
                        break;
                    }
                }
                match found {
                    Some(n) => palette[n].1 += 1,
                    None => {
                        if palette.len() == MAX_ZRLE_PALETTE {
                            too_many = true;
                            break 'outer;
                        }
                        palette.push((p, 1));
                    }
                }
            }
        }
        let mut out = Vec::new();
        if too_many {
            out.push(0);
            for y in 0..h {
                for x in 0..w {
                    out.extend_from_slice(palette_entry(pixel(x, y), format));
                }
            }
            return (0, out);
        }
        if palette.len() == 1 {
            out.push(1);
            out.extend_from_slice(palette_entry(palette[0].0, format));
            return (1, out);
        }
        palette.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        let size = palette.len() as u8;
        out.push(size);
        for (colour, _) in &palette {
            out.extend_from_slice(palette_entry(colour, format));
        }
        let indices: std::collections::BTreeMap<&[u8], u8> = palette
            .iter()
            .enumerate()
            .map(|(i, (colour, _))| (*colour, i as u8))
            .collect();
        let bits = packed_bits(palette.len());
        for y in 0..h {
            let mut byte = 0u8;
            let mut nbits = 0u8;
            for x in 0..w {
                byte = (byte << bits) | indices[pixel(x, y)];
                nbits += bits;
                if nbits >= 8 {
                    out.push(byte);
                    nbits = 0;
                }
            }
            if nbits > 0 {
                out.push(byte << (8 - nbits));
            }
        }
        (size, out)
    }


    /// What each codec costs on each shape, so the encoding choice can be made
    /// on numbers instead of on the order someone wrote the constants in.
    ///
    /// `MIN_TIGHT_RECT` is 64, so Tight is offered only for a rectangle at least
    /// 64 wide *and* 64 tall. That is this crate's rule and QEMU has no
    /// equivalent: `set_encodings` picks one encoding for the whole connection
    /// from the client's preference order and never looks at a rectangle's
    /// size. So a 1280x13 strip — the shape every taskbar redraw in the
    /// production logs had — cannot be Tight here, and could be under QEMU.
    ///
    /// Whether lifting that is worth anything is a measurement, because Tight
    /// is not automatically cheaper: it has its own palette machinery, and
    /// §8's tile builder was this crate's ZRLE one turning out to be ten times
    /// the cost of its raw path. The question is whether Tight's is better than
    /// ZRLE's *after* the rewrite, on both content shapes, and whether a thin
    /// strip is a shape Tight can represent at all — the RFB format has no
    /// minimum height, but a palette built from one row of pixels is a
    /// different trade from one built from a whole screen.
    ///
    /// **Run this in release.** ```sh
    /// cargo test -p qemu-vnc --release --all-features --lib what_each_codec_costs_on_which_shape -- --nocapture
    /// ```
    #[test]
    #[ignore = "a measurement, not a check: needs an optimised build and a reader"]
    fn what_each_codec_costs_on_which_shape() {
        const ROUNDS: u32 = 5;
        /// Sixty frames a second for a full screen, the budget to compare with.
        const BUDGET_MS: f64 = 16.7;

        let format = format();
        let offered = HashSet::from([
            Encoding::Raw,
            Encoding::Zlib,
            Encoding::Zrle,
            Encoding::Tight,
            Encoding::Jpeg(80),
        ]);

        // Two content shapes, because the last measurement showed they differ by
        // an order of magnitude: one with hundreds of colours per tile, which
        // takes every palette path's raw fallback, and one with exactly sixteen
        // per tile, which takes ZRLE's palette path and is what a desktop full
        // of text and icons looks like.
        let shapes: Vec<(&str, u16, u16, Vec<u8>)> = vec![
            ("noisy, raw palette path", 1280, 800, photographic(1280, 800)),
            (
                "desktop with a 24-colour band",
                1280,
                800,
                desktop_with_a_many_colour_band(1280, 800),
            ),
            (
                "16 colours, ZRLE palette path",
                1280,
                800,
                (0..1280 * 800 * 4)
                    .map(|i| {
                        let (x, y) = (i % 5120 / 4, i / 5120);
                        let which = ((x / 16) + (y / 16) * 4) % 16;
                        match i % 4 {
                            0 => (which * 16) as u8,
                            1 => (which * 8) as u8,
                            2 => (which * 4) as u8,
                            _ => 0,
                        }
                    })
                    .collect(),
            ),
            ("a taskbar strip", 1280, 13, photographic_strip(1280, 13)),
        ];

        println!("\n  ms per frame, release, zlib-rs, level 2, x{ROUNDS} rounds");
        println!("  a full 1280x800 frame has a {:.1} ms budget at sixty frames a second\n", BUDGET_MS);
        for (name, w, h, data) in &shapes {
            println!("  {name}, {w}x{h}");
            println!(
                "    {:<7} {:>9} {:>7} {:>9} {:>9}",
                "codec", "ms", "fps", "bytes", "budget"
            );
            for (label, codec) in [
                ("zrle", Codec::Zrle),
                ("tight", Codec::Tight),
                ("zlib", Codec::Zlib),
                ("jpeg80", Codec::Jpeg),
            ] {
                let rect = crate::rfb::Rect {
                    left: 0,
                    top: 0,
                    width: *w,
                    height: *h,
                };
                let mut encoders = Encoders::new(Some(80));
                encoders.set_deflate_level(2);
                let _ = encoders.encode(codec, &offered, data, &format, usize::from(*w) * 4, rect);
                let started = std::time::Instant::now();
                let mut bytes = 0usize;
                let mut ok = false;
                for _ in 0..ROUNDS {
                    if let Some((_c, d)) =
                        encoders.encode(codec, &offered, data, &format, usize::from(*w) * 4, rect)
                    {
                        bytes = d.len();
                        ok = true;
                    }
                }
                let ms = started.elapsed().as_secs_f64() / f64::from(ROUNDS) * 1000.0;
                let note = if !ok {
                    "declined"
                } else if ms <= BUDGET_MS {
                    "yes"
                } else {
                    "NO"
                };
                println!(
                    "    {label:<7} {ms:>9.1} {:>7.1} {bytes:>9} {note:>9}",
                    1.0 / (ms / 1000.0)
                );
            }
            println!();
        }
    }



}
