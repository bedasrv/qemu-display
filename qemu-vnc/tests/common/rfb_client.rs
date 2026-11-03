//! A scripted RFB client, to exercise the server handshake without a real
//! VNC viewer.
//!
//! The `vnc` crate we used to depend on shipped a `Client`, but it is
//! `TcpStream`-only and plaintext: it could not have driven the security
//! handshake, TLS or WebSocket anyway. Talking the protocol by hand also
//! gives us the negative cases (a security type we do not offer, a wrong
//! password, a truncated response) that a well-behaved client never produces.
//!
//! It also decodes the pixel encodings, which is the only way to know that
//! the ZRLE, hextile and Tight encoders produce something a real viewer can
//! display rather than something that merely compiles.

#![allow(dead_code)]

use std::io::{Read, Write};

use flate2::{Decompress, FlushDecompress};
use qemu_vnc::rfb::{des, PixelFormat};

/// The size of a pixel, in bytes: the tests all use the x8r8g8b8 format the
/// server announces, and the decoders write that back.
pub const BPP: usize = 4;

/// The width of a ZRLE pixel, which is *not* [`BPP`].
///
/// Note 1 of the RFB specification: at depth 24 with all three components
/// eight bits wide, one pixel is three bytes — and that is every pixel a
/// ZRLE rectangle writes, not only the palette entries. QEMU gets it from
/// `ZRLE_COMPACT_PIXEL` redefining `ZRLE_WRITE_PIXEL` to `zrle_write_u24a`, so
/// the solid tile's colour and the raw tile's pixels are three bytes as well.
///
/// A decoder that reads four bytes per pixel here follows the whole tile
/// stream correctly for a few tiles and then not at all.
const ZRLE_ENTRY: usize = 3;

/// The RFB encoding numbers the tests use.
pub mod encoding {
    /// Raw pixels.
    pub const RAW: i32 = 0;
    /// Hextile.
    pub const HEXTILE: i32 = 5;
    /// zlib.
    pub const ZLIB: i32 = 6;
    /// Tight.
    pub const TIGHT: i32 = 7;
    /// ZRLE.
    pub const ZRLE: i32 = 16;
    /// The audio pseudo-encoding, as `VNC_ENCODING_AUDIO`.
    pub const AUDIO: i32 = -259;
    /// `RichCursor`, whose rectangle carries a hotspot and a mask.
    pub const RICH_CURSOR: i32 = -239;
    /// `CursorWithAlpha`, the same with an alpha channel in the shape.
    pub const CURSOR_WITH_ALPHA: i32 = -314;
    /// `CopyRect`, the one encoding that is not pixels but is not empty either.
    pub const COPY_RECT: i32 = 1;
    /// `DesktopSize`, a pseudo-encoding with no payload: the server
    /// acknowledges it with a rectangle and nothing else.
    pub const DESKTOP_SIZE: i32 = -223;
    /// `ExtendedKeyEvent`, the other payload-free acknowledgement, and the one
    /// QEMU sends in `send_ext_key_event_ack()`.
    pub const EXTENDED_KEY_EVENT: i32 = -258;
    /// `ExtendedDesktopSize`, which carries a screen count and a screen. A bare
    /// rectangle for it desynchronises the client's stream.
    pub const EXTENDED_DESKTOP_SIZE: i32 = -308;
    /// `Led`, which carries one byte of LED state.
    pub const LED: i32 = -261;
}

/// The DES key of a password, as the RFB scheme derives it.
fn password_key(password: &str) -> des::Key {
    let mut key = [0u8; 8];
    for (dst, src) in key.iter_mut().zip(password.as_bytes().iter().take(8)) {
        *dst = src.reverse_bits();
    }
    key
}

pub fn read_exact<R: Read>(stream: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    stream.read_exact(buf)
}

/// Read the 12 bytes of the RFB protocol version the server speaks.
pub fn read_server_version<R: Read>(stream: &mut R) -> String {
    let mut buf = [0u8; 12];
    read_exact(stream, &mut buf).expect("version");
    String::from_utf8_lossy(&buf).trim().to_string()
}

/// Send our version, and read the security types the server offers.
pub fn negotiate_version<W: Write>(stream: &mut W, version: &str) {
    write!(stream, "{version:>12}").expect("version");
    stream.flush().expect("flush");
}

/// The security handshake, returning the security types on offer.
pub fn read_security_types<R: Read>(stream: &mut R, rfb33: bool) -> Vec<u8> {
    if rfb33 {
        // RFB 3.3 sends the chosen security type directly, which we already
        // read as the offer.
        return Vec::new();
    }
    let mut count = [0u8];
    read_exact(stream, &mut count).expect("security count");
    let mut types = vec![0u8; count[0] as usize];
    read_exact(stream, &mut types).expect("security types");
    types
}

/// Pick a security type among the ones the server offered.
pub fn select_security_type<W: Write>(stream: &mut W, security_type: u8) {
    stream.write_all(&[security_type]).expect("security type");
    stream.flush().expect("flush");
}

/// Read the `SecurityResult` of a handshake that needs no challenge.
pub fn read_security_result<R: Read>(stream: &mut R) -> u32 {
    let mut result = [0u8; 4];
    read_exact(stream, &mut result).expect("security result");
    u32::from_be_bytes(result)
}

/// Answer the VNC authentication challenge, and read the security result.
pub fn authenticate<RW: Read + Write>(stream: &mut RW, password: &str) -> u32 {
    let mut challenge = [0u8; 16];
    read_exact(stream, &mut challenge).expect("challenge");
    let response = des::encrypt(&challenge, &password_key(password));
    stream.write_all(&response).expect("response");
    stream.flush().expect("flush");
    let mut result = [0u8; 4];
    read_exact(stream, &mut result).expect("security result");
    u32::from_be_bytes(result)
}

/// Read an RFB string: a length and that many bytes of UTF-8.
pub fn read_utf8<R: Read>(stream: &mut R) -> String {
    let mut len = [0u8; 4];
    read_exact(stream, &mut len).expect("string length");
    let mut text = vec![0u8; u32::from_be_bytes(len) as usize];
    read_exact(stream, &mut text).expect("string");
    String::from_utf8(text).expect("the string is UTF-8")
}

/// The RFB SASL security type, as QEMU's `VNC_AUTH_SASL`.
pub const SASL: u8 = 20;

/// Read the mechanism list a SASL server offers, as its comma separated names.
pub fn read_sasl_mechanisms<R: Read>(stream: &mut R) -> Vec<String> {
    let mut len = [0u8; 4];
    read_exact(stream, &mut len).expect("mechanism list length");
    let mut list = vec![0u8; u32::from_be_bytes(len) as usize];
    read_exact(stream, &mut list).expect("mechanism list");
    String::from_utf8(list)
        .expect("the list is UTF-8")
        .split(',')
        .map(str::to_owned)
        .collect()
}

/// Choose a SASL mechanism, by name.
pub fn select_sasl_mechanism<W: Write>(stream: &mut W, mechanism: &str) {
    stream
        .write_all(&(mechanism.len() as u32).to_be_bytes())
        .expect("mechanism length");
    stream.write_all(mechanism.as_bytes()).expect("mechanism");
    stream.flush().expect("flush");
}

/// Send one round of a SASL exchange.
///
/// The protocol pads the data with a NUL, and a length of zero means the
/// client sent nothing at all rather than an empty string, so both are here
/// rather than left to the caller to spell out.
pub fn send_sasl_data<W: Write>(stream: &mut W, data: Option<&[u8]>) {
    match data {
        None => stream.write_all(&0u32.to_be_bytes()).expect("no data"),
        Some(data) => {
            stream
                .write_all(&((data.len() + 1) as u32).to_be_bytes())
                .expect("data length");
            stream.write_all(data).expect("data");
            stream.write_all(&[0]).expect("padding");
        }
    }
    stream.flush().expect("flush");
}

/// Read one round of a SASL exchange.
///
/// Returns what the server said, and whether it said the exchange is over. A
/// length of zero is the server sending nothing, which is not the same as
/// sending an empty string.
pub fn read_sasl_data<R: Read>(stream: &mut R) -> (Option<Vec<u8>>, bool) {
    let mut len = [0u8; 4];
    read_exact(stream, &mut len).expect("data length");
    let length = u32::from_be_bytes(len);
    let data = if length == 0 {
        None
    } else {
        let mut data = vec![0u8; length as usize];
        read_exact(stream, &mut data).expect("data");
        // The last byte is the padding the protocol adds.
        assert_eq!(
            *data.last().expect("a non-empty block has a last byte"),
            0,
            "the SASL data must end in its NUL padding"
        );
        data.pop();
        Some(data)
    };
    let mut complete = [0u8; 1];
    read_exact(stream, &mut complete).expect("the completion byte");
    (data, complete[0] != 0)
}

/// The `ClientInit` message: the only bit is the "shared" flag.
pub fn send_client_init<W: Write>(stream: &mut W, shared: bool) {
    stream.write_all(&[u8::from(shared)]).expect("client init");
    stream.flush().expect("flush");
}

/// The `ServerInit` message: dimensions, pixel format and desktop name.
pub fn read_server_init<R: Read>(stream: &mut R) -> (u16, u16, String) {
    // width (2) + height (2) + pixel format (16)
    let mut buf = [0u8; 20];
    read_exact(stream, &mut buf).expect("server init");
    let width = u16::from_be_bytes([buf[0], buf[1]]);
    let height = u16::from_be_bytes([buf[2], buf[3]]);
    let mut len = [0u8; 4];
    read_exact(stream, &mut len).expect("name length");
    let mut name = vec![0u8; u32::from_be_bytes(len) as usize];
    read_exact(stream, &mut name).expect("name");
    (width, height, String::from_utf8_lossy(&name).to_string())
}

/// Tell the server which encodings we understand, as a real client does.
pub fn send_set_encodings<W: Write>(stream: &mut W, encodings: &[i32]) {
    // type (1) + padding (1) + count (2)
    let mut msg = vec![2u8, 0];
    msg.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
    for encoding in encodings {
        msg.extend_from_slice(&encoding.to_be_bytes());
    }
    stream.write_all(&msg).expect("set encodings");
    stream.flush().expect("flush");
}

/// Ask for a rectangle *whatever* the server thinks changed.
///
/// The `incremental` flag clear is what makes the answer unconditional: an
/// incremental request is only answered if the server believes something is
/// dirty, so a test that retries one can starve on a machine where the damage
/// was consumed before the retry arrived. That is a legitimate protocol
/// behaviour and a useless thing for a test to depend on.
pub fn request_full_update<W: Write>(stream: &mut W, x: u16, y: u16, width: u16, height: u16) {
    let mut msg = vec![3u8, 0 /* not incremental */];
    msg.extend_from_slice(&x.to_be_bytes());
    msg.extend_from_slice(&y.to_be_bytes());
    msg.extend_from_slice(&width.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    stream.write_all(&msg).expect("framebuffer update request");
    stream.flush().expect("flush");
}

/// Tell the server we want an incremental update of a rectangle.
/// Ask the server for pixels in a different format than the one it announced.
///
/// Every other test in this file decodes x8r8g8b8, because that is what the
/// server announces and every test client has been content with it. A client
/// is free to ask for something else, and the byte order it picks is its own
/// business — which is exactly the thing a server has to get right and cannot
/// check against its own idea of the format.
pub fn send_set_pixel_format<W: Write>(stream: &mut W, format: &PixelFormat) {
    // type (0) + padding (3)
    let mut msg = vec![0u8, 0, 0, 0];
    msg.push(format.bits_per_pixel);
    msg.push(format.depth);
    msg.push(u8::from(format.big_endian));
    msg.push(u8::from(format.true_colour));
    msg.extend_from_slice(&format.red_max.to_be_bytes());
    msg.extend_from_slice(&format.green_max.to_be_bytes());
    msg.extend_from_slice(&format.blue_max.to_be_bytes());
    msg.push(format.red_shift);
    msg.push(format.green_shift);
    msg.push(format.blue_shift);
    msg.extend_from_slice(&[0u8; 3]);
    stream.write_all(&msg).expect("set pixel format");
    stream.flush().expect("flush");
}

/// Decode pixels the way a real client does: read each one as a number in the
/// client's byte order and pull the channels out of it with its shifts.
///
/// The other decoders in this file all assume x8r8g8b8, which is fine for them
/// and useless here — the question is what the bytes mean to *the client*, and
/// only the client's own format says that.
pub fn decode_pixels(data: &[u8], format: &PixelFormat) -> Vec<[u8; 3]> {
    let width = format.bits_per_pixel as usize / 8;
    data.as_chunks::<4>()
        .0
        .iter()
        .map(|bytes| {
            let value = match (width, format.big_endian) {
                (2, false) => u32::from(u16::from_le_bytes([bytes[0], bytes[1]])),
                (2, true) => u32::from(u16::from_be_bytes([bytes[0], bytes[1]])),
                (4, false) => u32::from_le_bytes(*bytes),
                (4, true) => u32::from_be_bytes(*bytes),
                (1, _) => bytes[0] as u32,
                other => panic!("no decoding for {other:?}"),
            };
            let channel = |shift: u8, max: u16| {
                let raw = (value >> shift) & max as u32;
                (raw * 255 / max as u32) as u8
            };
            [
                channel(format.red_shift, format.red_max),
                channel(format.green_shift, format.green_max),
                channel(format.blue_shift, format.blue_max),
            ]
        })
        .collect()
}

pub fn request_update<W: Write>(stream: &mut W, x: u16, y: u16, width: u16, height: u16) {
    let mut msg = vec![3u8, 1 /* incremental */];
    msg.extend_from_slice(&x.to_be_bytes());
    msg.extend_from_slice(&y.to_be_bytes());
    msg.extend_from_slice(&width.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    stream.write_all(&msg).expect("framebuffer update request");
    stream.flush().expect("flush");
}

/// Read a whole `FramebufferUpdate` message, and return the pixel data of
/// its first rectangle.
pub fn read_update<R: Read>(stream: &mut R) -> Vec<u8> {
    let mut header = [0u8; 4];
    read_exact(stream, &mut header).expect("update header");
    assert_eq!(
        header[0], 0,
        "expected a FramebufferUpdate, got {}",
        header[0]
    );
    let rects = u16::from_be_bytes([header[2], header[3]]);
    assert!(rects > 0, "no rectangle in the update");

    // left (2) + top (2) + width (2) + height (2)
    let mut rect = [0u8; 8];
    read_exact(stream, &mut rect).expect("rectangle header");
    let width = u16::from_be_bytes([rect[4], rect[5]]);
    let height = u16::from_be_bytes([rect[6], rect[7]]);
    let mut encoding = [0u8; 4];
    read_exact(stream, &mut encoding).expect("encoding");
    assert_eq!(
        i32::from_be_bytes(encoding),
        encoding::RAW,
        "expected the Raw encoding, got {}",
        i32::from_be_bytes(encoding)
    );
    let mut pixels = vec![0u8; width as usize * height as usize * 4];
    read_exact(stream, &mut pixels).expect("pixels");
    pixels
}

/// A rectangle read from the wire, with its pixels decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    /// The RFB encoding number the server used.
    pub encoding: i32,
    /// The pixels, in x8r8g8b8, row by row.
    pub pixels: Vec<u8>,
    /// How many bytes the pixel data took on the wire, which is what the
    /// encoders are there to reduce.
    pub bytes: usize,
}

/// Read the rectangles of the next `FramebufferUpdate`, decoding them.
pub fn read_update_rects<R: Read>(stream: &mut R, decoders: &mut Decoders) -> Vec<Rect> {
    let mut header = [0u8; 4];
    read_exact(stream, &mut header).expect("update header");
    assert_eq!(
        header[0], 0,
        "expected a FramebufferUpdate, got {}",
        header[0]
    );
    let count = u16::from_be_bytes([header[2], header[3]]);
    (0..count).map(|_| read_rect(stream, decoders)).collect()
}

/// Read one rectangle of a `FramebufferUpdate`, and decode its pixels.
pub fn read_rect<R: Read>(stream: &mut R, decoders: &mut Decoders) -> Rect {
    // left (2) + top (2) + width (2) + height (2)
    let mut header = [0u8; 8];
    read_exact(stream, &mut header).expect("rectangle header");
    let x = u16::from_be_bytes([header[0], header[1]]);
    let y = u16::from_be_bytes([header[2], header[3]]);
    let width = u16::from_be_bytes([header[4], header[5]]);
    let height = u16::from_be_bytes([header[6], header[7]]);
    let mut encoding = [0u8; 4];
    read_exact(stream, &mut encoding).expect("encoding");
    let encoding = i32::from_be_bytes(encoding);
    let mut pixels = vec![0u8; width as usize * height as usize * BPP];
    let bytes = match encoding {
        encoding::RAW => {
            read_exact(stream, &mut pixels).expect("raw pixels");
            pixels.len()
        }
        encoding::ZRLE => {
            // ZRLE announces the size of its compressed data.
            let mut length = [0u8; 4];
            read_exact(stream, &mut length).expect("zrle length");
            let length = u32::from_be_bytes(length) as usize;
            let mut data = vec![0u8; length];
            read_exact(stream, &mut data).expect("zrle data");
            decoders.decode_zrle(stream, &data, width, height, &mut pixels);
            length
        }
        encoding::ZLIB => {
            // A 32-bit length, then that many bytes of stream — the same
            // layout the ZRLE arm above uses and the same one
            // libvncclient's `zlib.c` reads (`rfbZlibHeader`, then `nBytes`).
            //
            // This arm used to skip the length and let the hextile decoder
            // pull bytes off the socket until it had enough. That agreed with
            // the server, which was also skipping it, so every zlib test in
            // the suite passed against a wire format no client can read. A
            // decoder written from the same wrong idea as the encoder is not
            // a check on the encoder; the two are one function split in two.
            let mut length = [0u8; 4];
            read_exact(stream, &mut length).expect("zlib length");
            let length = u32::from_be_bytes(length) as usize;
            let mut data = vec![0u8; length];
            read_exact(stream, &mut data).expect("zlib data");
            decoders.decode_hextile(&mut &data[..], width, height, &mut pixels);
            length + 4
        }
        encoding::TIGHT => {
            let before = decoders.tight.total_in();
            decoders.decode_tight(stream, width, height, &mut pixels);
            (decoders.tight.total_in() - before) as usize
        }
        // A pseudo-encoding carries no payload, so it is a rectangle with the
        // framebuffer's size and no pixels. A decoder that treats one as raw
        // reads the next message's bytes as if they were its own, and the test
        // fails somewhere unrelated — which is what a test that only ever used
        // one pixel format and one set of encodings would never notice.
        other if other < 0 => 0,
        other => panic!("unexpected encoding {other}"),
    };
    Rect {
        x,
        y,
        width,
        height,
        encoding,
        pixels,
        bytes,
    }
}

/// The persistent inflate streams of a client, one per encoding, as a real
/// viewer keeps them across the whole connection.
pub struct Decoders {
    zrle: Inflate,
    hextile: Inflate,
    tight: Inflate,
}

impl Default for Decoders {
    fn default() -> Self {
        Self {
            zrle: Inflate::new(),
            hextile: Inflate::new(),
            tight: Inflate::new(),
        }
    }
}

/// One zlib stream, fed from the socket as the decoding needs more data.
struct Inflate {
    decompress: Decompress,
    /// The compressed data that was read from the socket but not consumed
    /// yet.
    input: Vec<u8>,
    /// The decompressed data, of which the first `cursor` bytes were used.
    output: Vec<u8>,
    cursor: usize,
}

impl Inflate {
    /// A fresh, empty stream.
    fn new() -> Self {
        Self {
            // `true`: a zlib stream, with a header, as the RFB encodings
            // expect (not a raw deflate stream).
            decompress: Decompress::new(true),
            input: Vec::new(),
            output: Vec::new(),
            cursor: 0,
        }
    }

    /// Make sure the output holds at least `n` unconsumed bytes, reading from
    /// the socket as needed.
    fn need<R: Read>(&mut self, reader: &mut R, n: usize) {
        while self.output.len() - self.cursor < n {
            self.step(reader);
        }
    }

    /// Feed the decompressor until it has produced something, reading from
    /// the socket when the data it has is not enough.
    fn step<R: Read>(&mut self, reader: &mut R) {
        loop {
            // `decompress_vec` writes into the spare capacity of the vector
            // and never grows it, so room has to be reserved up front. The
            // inflate holds output back when it runs out of room, and a
            // later call with the same input drains it, which is why the
            // room is topped up rather than the whole rectangle reserved.
            if self.output.len() == self.output.capacity() {
                self.output.reserve(self.output.capacity().max(4096));
            }
            // The totals are for the whole stream, so the difference is what
            // this call consumed.
            let (before_in, before_out) = (self.decompress.total_in(), self.decompress.total_out());
            let status = self
                .decompress
                .decompress_vec(&self.input, &mut self.output, FlushDecompress::None)
                .expect("inflate");
            let consumed = (self.decompress.total_in() - before_in) as usize;
            self.input.drain(..consumed);
            if self.decompress.total_out() != before_out {
                return;
            }
            // Nothing came out: either the input is exhausted, and the socket
            // has to be read, or the inflate is stuck on data it can not use.
            if self.input.is_empty() {
                let mut chunk = [0u8; 4096];
                let read = reader.read(&mut chunk).expect("compressed data");
                assert!(read > 0, "the compressed stream ended too early");
                self.input.extend_from_slice(&chunk[..read]);
                continue;
            }
            panic!("the decompressor made no progress: {status:?}");
        }
    }

    /// The next `n` bytes *straight off the socket*, with no decompressing.
    ///
    /// Tight only compresses the indexes of a paletted rectangle: the control
    /// byte, the filter, the colour count and the palette itself are sent as
    /// they are, and reading them through the inflater is how a decoder ends
    /// up a few bytes out of step and then blaming the pixel format.
    fn raw_take<R: Read>(&mut self, reader: &mut R, n: usize) -> Vec<u8> {
        let mut out = vec![0u8; n];
        reader.read_exact(&mut out).expect("uncompressed data");
        out
    }

    /// A length in Tight's "compact" form: one, two or three bytes of seven
    /// bits, least significant first, each with the top bit set while another
    /// byte follows.
    /// Read Tight's compact length: three bytes, the last of which is a *whole*
    /// byte.
    ///
    /// **This had the same four-byte bug the writer had, which is why nothing
    /// noticed.** It looped three times over seven-bit bytes and then read a
    /// fourth at bit 21, so it agreed with the writer about every length by
    /// construction: the two could not have disagreed, so no test using both
    /// could ever see the fault. A client is a witness only if it was written
    /// from something other than the code it is checking.
    ///
    /// QEMU's `tight_send_compact_size` (`ui/vnc-enc-tight.c:824`) decides the
    /// width from the first two bytes and writes `(len >> 14) & 0xFF` as the
    /// third, all eight bits, with no continuation bit -- there is no fourth byte
    /// to point at. So the field is 22 bits wide.
    ///
    /// The tell that this matters: a 1280x800 full-colour rectangle at level 0 is
    /// 3,072,247 bytes deflated, and masking the third byte to seven turns that
    /// into 614,647. The reader then waits for bytes the server never sends, and
    /// the test hangs rather than failing.
    fn compact_size<R: Read>(&mut self, reader: &mut R) -> usize {
        let mut value = 0usize;
        for shift in 0..3 {
            let byte = self.raw_take(reader, 1)[0];
            if shift == 2 {
                // The last byte is a whole byte; the marker bit is data here.
                return value | ((byte as usize) << 14);
            }
            value |= ((byte & 0x7f) as usize) << (7 * shift);
            if byte & 0x80 == 0 {
                return value;
            }
        }
        value
    }

    /// Decompress a whole buffer through the stream, which is where the
    /// indexes of a Tight rectangle come out.
    fn inflate(&mut self, data: &[u8]) -> Vec<u8> {
        self.input.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if out.len() == out.capacity() {
                out.reserve(out.capacity().max(4096));
            }
            let (before_in, before_out) = (self.decompress.total_in(), out.len());
            self.decompress
                .decompress_vec(&self.input, &mut out, FlushDecompress::None)
                .expect("inflate");
            let consumed = (self.decompress.total_in() - before_in) as usize;
            self.input.drain(..consumed);
            if out.len() == before_out {
                // Nothing more can come out of what is left.
                return out;
            }
        }
    }

    /// The next `n` decompressed bytes.
    fn take(&mut self, n: usize) -> Vec<u8> {
        let end = self.cursor + n;
        let out = self.output[self.cursor..end].to_vec();
        self.cursor = end;
        if self.cursor == self.output.len() && self.output.len() > 1 << 16 {
            self.output.clear();
            self.cursor = 0;
        }
        out
    }

    /// The next decompressed byte.
    fn byte(&mut self) -> u8 {
        self.take(1)[0]
    }

    /// The next decompressed 16 bits integer.
    fn u16(&mut self) -> u16 {
        let b = self.take(2);
        u16::from_be_bytes([b[0], b[1]])
    }

    /// How many compressed bytes the stream has taken in, which is what a
    /// rectangle cost on the wire.
    fn total_in(&self) -> u64 {
        self.decompress.total_in()
    }
}

impl Decoders {
    /// A client that has not decoded anything yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode a ZRLE rectangle, whose compressed data we already read.
    fn decode_zrle<R: Read>(
        &mut self,
        stream: &mut R,
        data: &[u8],
        width: u16,
        height: u16,
        out: &mut [u8],
    ) {
        self.zrle.input.extend_from_slice(data);
        // No header: the stream is the tiles, and the rectangle's width and
        // height are in the framebuffer update message rather than in here.
        for tile_y in (0..height).step_by(64) {
            for tile_x in (0..width).step_by(64) {
                let w = (width - tile_x).min(64) as usize;
                let h = (height - tile_y).min(64) as usize;
                let sub_encoding = {
                    self.zrle.need(stream, 1);
                    self.zrle.byte()
                };
                match sub_encoding {
                    0 => {
                        // Raw pixels, at the ZRLE width rather than the
                        // framebuffer's four bytes: three, for a 32 bit client
                        // at depth 24.
                        self.zrle.need(stream, w * h * ZRLE_ENTRY);
                        let pixels = self.zrle.take(w * h * ZRLE_ENTRY);
                        for y in 0..h {
                            let dst = (tile_y as usize + y) * width as usize * BPP
                                + tile_x as usize * BPP;
                            for x in 0..w {
                                let src = (y * w + x) * ZRLE_ENTRY;
                                out[dst + x * BPP] = pixels[src];
                                out[dst + x * BPP + 1] = pixels[src + 1];
                                out[dst + x * BPP + 2] = pixels[src + 2];
                                out[dst + x * BPP + 3] = 0;
                            }
                        }
                    }
                    1 => {
                        // A solid tile: one whole pixel, at the ZRLE width.
                        self.zrle.need(stream, ZRLE_ENTRY);
                        let colour = self.zrle.take(ZRLE_ENTRY);
                        let area = Area {
                            x: tile_x,
                            y: tile_y,
                            width: w as u16,
                            height: h as u16,
                        };
                        // Three bytes of x8r8g8b8 is B, G, R with the fourth
                        // byte padding, which has to be zeroed rather than left
                        // as whatever was in the buffer.
                        let mut pixel = [0u8; BPP];
                        pixel[..ZRLE_ENTRY].copy_from_slice(&colour);
                        fill_pixel(out, width, area, &pixel);
                    }
                    2..=16 => {
                        // A palette tile. The sub-encoding *is* the number of
                        // colours, and the entries are the client's own pixels
                        // with the padding byte dropped: `ZRLE_ENTRY` bytes
                        // rather than `BPP`. A decoder written to read `BPP`
                        // bytes per entry agrees with an encoder written that
                        // way and with no real client, which is how the palette
                        // layout was wrong in the first place.
                        let colours = sub_encoding as usize;
                        self.zrle.need(stream, colours * ZRLE_ENTRY);
                        let palette = self.zrle.take(colours * ZRLE_ENTRY);
                        // The indices are packed, `packed_bits(colours)` to a
                        // pixel, most significant bit first, restarting on
                        // every row and padded at the end of each row.
                        let bits = match colours {
                            2 => 1,
                            3 | 4 => 2,
                            _ => 4,
                        };
                        let per_row = (w * bits).div_ceil(8);
                        for y in 0..h {
                            self.zrle.need(stream, per_row);
                            let row = self.zrle.take(per_row);
                            for x in 0..w {
                                let bit = x * bits;
                                let index = (row[bit / 8] >> (7 - bit % 8)) as usize
                                    & ((1 << bits) - 1);
                                assert!(index < colours, "palette index out of range");
                                // The entry is the pixel without its padding
                                // byte, so it goes straight into the low bytes
                                // of the pixel.
                                let colour = &palette[index * ZRLE_ENTRY..(index + 1) * ZRLE_ENTRY];
                                let dst = (tile_y as usize + y) * width as usize * BPP
                                    + (tile_x as usize + x) * BPP;
                                out[dst..dst + ZRLE_ENTRY]
                                    .copy_from_slice(colour);
                                out[dst + ZRLE_ENTRY] = 0;
                            }
                        }
                    }
                    other => panic!("unexpected ZRLE sub-encoding {other}"),
                }
            }
        }
    }

    /// Decode a hextile rectangle.
    ///
    /// Note the width is the client's whole pixel, [`BPP`], and *not*
    /// [`ZRLE_ENTRY`] as it is in [`Inflate::decode_zrle`]. QEMU's hextile
    /// encoder writes pixels with `vnc_write_pixels_generic()`, which emits
    /// `client_pf.bytes_per_pixel` bytes each; only ZRLE has the compact
    /// three-byte form, from `ZRLE_COMPACT_PIXEL`.
    fn decode_hextile<R: Read>(&mut self, stream: &mut R, width: u16, height: u16, out: &mut [u8]) {
        // No count in front of the tiles: the number of them is the rectangle's
        // dimensions in blocks of sixteen.
        let mut background = [0u8; BPP];
        for tile_y in (0..height).step_by(16) {
            for tile_x in (0..width).step_by(16) {
                let w = (width - tile_x).min(16);
                let h = (height - tile_y).min(16);
                self.hextile.need(stream, 1);
                let sub_encoding = self.hextile.byte();
                match sub_encoding {
                    0 => {
                        self.hextile.need(stream, w as usize * h as usize * BPP);
                        let pixels = self.hextile.take(w as usize * h as usize * BPP);
                        for y in 0..h as usize {
                            let dst = (tile_y as usize + y) * width as usize * BPP
                                + tile_x as usize * BPP;
                            out[dst..dst + w as usize * BPP].copy_from_slice(
                                &pixels[y * w as usize * BPP..(y + 1) * w as usize * BPP],
                            );
                        }
                    }
                    1 => {
                        // The whole tile takes the new background colour.
                        self.hextile.need(stream, BPP);
                        background.copy_from_slice(&self.hextile.take(BPP));
                        let area = Area {
                            x: tile_x,
                            y: tile_y,
                            width: w,
                            height: h,
                        };
                        fill_pixel(out, width, area, &background);
                    }
                    2 => {
                        // Only the first pixel changes.
                        self.hextile.need(stream, BPP);
                        let foreground = self.hextile.take(BPP);
                        let dst = tile_y as usize * width as usize * BPP + tile_x as usize * BPP;
                        out[dst..dst + BPP].copy_from_slice(&foreground);
                    }
                    3 | 4 => {
                        // Subrectangles drawn with the foreground colour.
                        if sub_encoding == 3 {
                            self.hextile.need(stream, BPP);
                            background.copy_from_slice(&self.hextile.take(BPP));
                        }
                        self.hextile.need(stream, 2);
                        let bitmap = self.hextile.u16();
                        for y in 0..h as usize {
                            for x in 0..w as usize {
                                // The bitmap is most significant bit first.
                                if bitmap & (0x8000 >> (y * w as usize + x)) != 0 {
                                    let dst = (tile_y as usize + y) * width as usize * BPP
                                        + (tile_x as usize + x) * BPP;
                                    out[dst..dst + BPP].copy_from_slice(&background);
                                }
                            }
                        }
                        self.hextile.need(stream, 2);
                        let subrect = self.hextile.u16();
                        let x = (subrect >> 12) & 0xf;
                        let y = (subrect >> 8) & 0xf;
                        let w = (subrect >> 4) & 0xf;
                        let h = subrect & 0xf;
                        for row in y..y + h {
                            for col in x..x + w {
                                let dst = (tile_y as usize + row as usize) * width as usize * BPP
                                    + (tile_x as usize + col as usize) * BPP;
                                out[dst..dst + BPP].copy_from_slice(&background);
                            }
                        }
                    }
                    other => panic!("unexpected hextile sub-encoding {other}"),
                }
            }
        }
    }

    /// Decode a Tight rectangle.
    ///
    /// The control byte is `compression type << 4 | flags`: bits 7-4 are the
    /// type (0 to 7 basic, 8 fill, 9 JPEG, 10 PNG), bits 5-4 of a basic
    /// rectangle say which zlib stream the data is on, bit 6 says a filter
    /// byte follows, and bits 3-0 reset that many zlib streams. A decoder that
    /// tests the wrong bit here reads a *basic raw* rectangle where a fill or
    /// a palette was sent, and every later field falls out of step.
    fn decode_tight<R: Read>(&mut self, stream: &mut R, width: u16, height: u16, out: &mut [u8]) {
        let control = self.tight.raw_take(stream, 1)[0];
        match control >> 4 {
            8 => {
                // A fill: one pixel and nothing else, uncompressed.
                let colour: [u8; 3] = self
                    .tight
                    .raw_take(stream, 3)
                    .try_into()
                    .expect("a colour");
                fill(
                    out,
                    width,
                    Area {
                        x: 0,
                        y: 0,
                        width,
                        height,
                    },
                    &colour,
                );
                return;
            }
            9 => {
                // A JPEG image, which we only check the size of: the lossy
                // encoding can not be compared pixel by pixel.
                let length = self.tight.compact_size(stream);
                self.tight.need(stream, length);
                let data = self.tight.take(length);
                let image = image::load_from_memory_with_format(&data, image::ImageFormat::Jpeg)
                    .expect("a JPEG image");
                assert_eq!(image.width(), u32::from(width));
                assert_eq!(image.height(), u32::from(height));
                let rgb = image.to_rgb8();
                for (i, pixel) in rgb.pixels().enumerate() {
                    out[i * BPP] = pixel[2];
                    out[i * BPP + 1] = pixel[1];
                    out[i * BPP + 2] = pixel[0];
                }
                return;
            }
            0..=7 => {}
            other => panic!("unexpected Tight compression type {other:x}"),
        }

        // A basic rectangle, so the data was filtered and then compressed on
        // the zlib stream the control byte names.
        let zlib_stream = (control >> 4) & 0x03;
        // **Stream 0 with no filter is `send_full_color_rect`**: the raw pixel
        // data of a rectangle with more than 256 colours. It used to be rejected
        // here as well as in the encoder, because the encoder never sent it.
        if control & 0x40 == 0 && zlib_stream == 0 {
            // Three bytes a pixel for a pixel24 client, which is what the frame
            // buffer here is. Anything else and the count below would be wrong.
            let want = width as usize * height as usize * 3;
            let data = if want < 12 {
                self.tight.raw_take(stream, want)
            } else {
                let length = self.tight.compact_size(stream);
                let data = self.tight.raw_take(stream, length);
                self.tight.inflate(&data)
            };
            assert_eq!(
                data.len(),
                want,
                "a full-colour rectangle should hold {} bytes and held {}",
                want,
                data.len()
            );
            for i in 0..(width as usize * height as usize) {
                out[i * BPP] = data[i * 3 + 2];
                out[i * BPP + 1] = data[i * 3 + 1];
                out[i * BPP + 2] = data[i * 3];
            }
            return;
        }
        assert_eq!(zlib_stream, 2, "the indexes go on zlib stream 2");

        let mut palette: Vec<[u8; 3]> = Vec::new();
        if control & 0x40 != 0 {
            let filter = self.tight.raw_take(stream, 1)[0];
            assert_eq!(filter, 1, "only the palette filter is expected");
            // The palette is preceded by its size *minus one*, so 255 is 256
            // colours rather than 255, and a count of zero is not a palette of
            // one colour.
            let colours = self.tight.raw_take(stream, 1)[0] as usize + 1;
            palette = self
                .tight
                .raw_take(stream, colours * 3)
                .as_chunks::<3>()
                .0
                .iter()
                .map(|c| [c[0], c[1], c[2]])
                .collect();
        }

        let count = width as usize * height as usize;
        // Two colours are worth a bit each, every other count a byte. Both are
        // raw when the data is too short to be worth compressing, which is why
        // the size is not in front of them.
        let per_row = (width as usize).div_ceil(8);
        let bytes = if palette.len() == 2 {
            per_row * height as usize
        } else {
            count
        };
        let indexes = if bytes < 12 {
            self.tight.raw_take(stream, bytes)
        } else {
            let length = self.tight.compact_size(stream);
            let data = self.tight.raw_take(stream, length);
            self.tight.inflate(&data)
        };

        if palette.len() == 2 {
            for i in 0..count {
                // Every row starts on a byte boundary of its own.
                let bit = (i / width as usize) * per_row * 8 + i % width as usize;
                let index = (indexes[bit / 8] >> (7 - bit % 8)) as usize & 1;
                let colour = palette[index];
                out[i * BPP] = colour[2];
                out[i * BPP + 1] = colour[1];
                out[i * BPP + 2] = colour[0];
            }
        } else {
            for i in 0..count {
                let index = indexes[i] as usize;
                assert!(index < palette.len(), "palette index out of range");
                let colour = palette[index];
                out[i * BPP] = colour[2];
                out[i * BPP + 1] = colour[1];
                out[i * BPP + 2] = colour[0];
            }
        }
    }
}

/// An area of a decoded rectangle, in rectangle coordinates./// An area of a decoded rectangle, in rectangle coordinates.
#[derive(Clone, Copy)]
struct Area {
    x: u16,
    y: u16,
    width: u16,
    height: u16,
}

/// Fill an area of a decoded rectangle with an RGB colour.
fn fill(out: &mut [u8], width: u16, area: Area, rgb: &[u8; 3]) {
    for y in area.y..area.y + area.height {
        for x in area.x..area.x + area.width {
            let dst = y as usize * width as usize * BPP + x as usize * BPP;
            // x8r8g8b8 is B, G, R, X in memory.
            out[dst] = rgb[2];
            out[dst + 1] = rgb[1];
            out[dst + 2] = rgb[0];
        }
    }
}

/// Fill an area of a decoded rectangle with a pixel already in the client
/// format.
fn fill_pixel(out: &mut [u8], width: u16, area: Area, pixel: &[u8]) {
    for y in area.y..area.y + area.height {
        for x in area.x..area.x + area.width {
            let dst = y as usize * width as usize * BPP + x as usize * BPP;
            out[dst..dst + BPP].copy_from_slice(pixel);
        }
    }
}

/// Tell the server we are still there, with an empty cut text, which is the
/// usual way to keep an idle connection open.
/// A key event: the keysym, and whether it went down.
pub fn send_key<W: Write>(stream: &mut W, keysym: u32, down: bool) {
    let mut msg = vec![4u8, u8::from(down)];
    msg.extend_from_slice(&[0, 0]);
    msg.extend_from_slice(&keysym.to_be_bytes());
    stream.write_all(&msg).expect("key event");
    stream.flush().expect("flush");
}

/// An extended key event: the QEMU message with a keysym and a key number.
///
/// The `keycode` field is already a QEMU key number (`0x80 | scancode` for the
/// `0xe0`-prefixed keys), which is what noVNC's `QEMUExtendedKeyEvent` sends.
pub fn send_extended_key<W: Write>(stream: &mut W, keysym: u32, keycode: u32, down: bool) {
    let mut msg = vec![255u8, 0u8];
    msg.extend_from_slice(&u16::from(down).to_be_bytes());
    msg.extend_from_slice(&keysym.to_be_bytes());
    msg.extend_from_slice(&keycode.to_be_bytes());
    stream.write_all(&msg).expect("extended key event");
    stream.flush().expect("flush");
}

/// A pointer event: the button mask and the position.
pub fn send_pointer<W: Write>(stream: &mut W, button_mask: u8, x: u16, y: u16) {
    let mut msg = vec![5u8, button_mask];
    msg.extend_from_slice(&x.to_be_bytes());
    msg.extend_from_slice(&y.to_be_bytes());
    stream.write_all(&msg).expect("pointer event");
    stream.flush().expect("flush");
}

/// The client sets the clipboard, which is a cut text from the client.
pub fn send_cut_text<W: Write>(stream: &mut W, text: &str) {
    // type (1) + padding (3) + length (4) + the Latin-1 text
    let bytes: Vec<u8> = text.chars().map(|c| c as u32 as u8).collect();
    let mut msg = vec![6u8, 0, 0, 0];
    msg.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    msg.extend_from_slice(&bytes);
    stream.write_all(&msg).expect("cut text");
    stream.flush().expect("flush");
}

/// The client asks for a desktop of another size.
pub fn send_set_desktop_size<W: Write>(stream: &mut W, width: u16, height: u16) {
    // type (1) + padding (1) + width (2) + height (2) + 1 screen
    let mut msg = vec![251u8, 0];
    msg.extend_from_slice(&width.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    msg.push(1);
    msg.push(0);
    msg.extend_from_slice(&[0, 0, 0, 0]); // id
    msg.extend_from_slice(&[0, 0, 0, 0]); // x, y
    msg.extend_from_slice(&width.to_be_bytes());
    msg.extend_from_slice(&height.to_be_bytes());
    // The screen's flags, which the RFB spec calls "flags" and QEMU sets to
    // zero for a plain primary screen.
    msg.extend_from_slice(&[0, 0, 0, 0]);
    stream.write_all(&msg).expect("set desktop size");
    stream.flush().expect("flush");
}

/// A read of one update that gives up when nothing arrives, for a test that
/// polls for one.
///
/// The scripted client blocks everywhere else, which is what makes its
/// assertions simple; a test waiting on something asynchronous needs to come
/// back empty-handed instead. The timeout is what does that, and it is set
/// well above the time a loopback write takes, so the one case it does not
/// cover — a message split across two reads with the gap between them longer
/// than the timeout — cannot happen for messages this small.
pub fn try_read_update(stream: &mut std::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let previous = stream.read_timeout().ok().flatten();
    stream.set_read_timeout(Some(POLL_TIMEOUT))?;
    let result = poll_read_update(stream);
    stream.set_read_timeout(previous)?;
    result
}

/// How long [`try_read_update`] and [`try_read_cut_text`] wait.
const POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

fn poll_read_update(stream: &mut std::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    read_exact(stream, &mut header)?;
    let mut bytes = header.to_vec();
    let rects = u16::from_be_bytes([header[2], header[3]]);
    for _ in 0..rects {
        let mut rect = [0u8; 12];
        read_exact(stream, &mut rect)?;
        bytes.extend_from_slice(&rect);
        let (w, h) = (
            u16::from_be_bytes([rect[4], rect[5]]),
            u16::from_be_bytes([rect[6], rect[7]]),
        );
        let encoding = i32::from_be_bytes(rect[8..12].try_into().unwrap());
        // Whatever the encoding, the raw length is what a test checks, and
        // only the raw one is decoded here.
        let length = match encoding {
            encoding::RAW => (w as usize) * (h as usize) * 4,
            _ => (w as usize) * (h as usize) * 4,
        };
        let mut data = vec![0u8; length];
        read_exact(stream, &mut data)?;
        bytes.extend_from_slice(&data);
    }
    // The pixels of the first rectangle, which is what every test wants.
    Ok(bytes[4 + (rects as usize) * 12..].to_vec())
}

/// A read of one rectangle that gives up when nothing arrives.
///
/// Unlike [`try_read_update`] this knows about the cursor pseudo-encodings,
/// whose rectangle is a hotspot, a size, a bit mask and a shape, and not a
/// block of pixels. A cursor is the one thing the server sends that is not
/// part of the console, so a test that reads one needs to read it differently.
/// The second value is the cursor's mask, and is empty for a rectangle that is
/// not a cursor.
/// [`read_update_rects`] for a socket, giving up when nothing arrives.
///
/// The blocking version panics on a read timeout, which is right for a test
/// that expects to be answered and wrong for one that is polling a console
/// that may not have anything new to say.
pub fn try_read_update_rects(
    stream: &mut std::net::TcpStream,
    decoders: &mut Decoders,
) -> std::io::Result<Vec<Rect>> {
    let previous = stream.read_timeout().ok().flatten();
    stream.set_read_timeout(Some(POLL_TIMEOUT))?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        read_update_rects(stream, decoders)
    }));
    stream.set_read_timeout(previous)?;
    match result {
        Ok(rects) => Ok(rects),
        Err(_) => Err(std::io::Error::other("no update arrived")),
    }
}

pub fn try_read_rect(stream: &mut std::net::TcpStream) -> std::io::Result<(Rect, Vec<u8>)> {
    let previous = stream.read_timeout().ok().flatten();
    stream.set_read_timeout(Some(POLL_TIMEOUT))?;
    let result = (|| {
        // type (0) + padding (1) + rectangles (2)
        let mut header = [0u8; 4];
        read_exact(stream, &mut header)?;
        if header[0] != 0 {
            return Err(std::io::Error::other("not a framebuffer update"));
        }
        if u16::from_be_bytes([header[2], header[3]]) == 0 {
            return Err(std::io::Error::other("an update with no rectangles"));
        }
        let mut rect = [0u8; 12];
        read_exact(stream, &mut rect)?;
        let width = u16::from_be_bytes([rect[4], rect[5]]);
        let height = u16::from_be_bytes([rect[6], rect[7]]);
        let encoding = i32::from_be_bytes(rect[8..12].try_into().unwrap());
        // What a rectangle carries depends on its encoding, and getting this
        // wrong does not fail loudly: it reads the next message's bytes as if
        // they were this one's, and the test fails somewhere else.
        //
        // A cursor is a shape and then a bit mask, in that order: the RFB
        // specification's own wording puts the mask first, but QEMU writes the
        // pixels with `vnc_write_pixels_generic()` and the mask with
        // `vnc_write()` after it, and parity with QEMU is the point of the
        // port. `CopyRect` names another rectangle and nothing else. A
        // pseudo-encoding — an acknowledgement, a desktop size, a key event —
        // carries no payload at all, which is the case that looks like a bug
        // when it is handled as raw.
        let mut mask = Vec::new();
        let bytes = match encoding {
            encoding::RICH_CURSOR | encoding::CURSOR_WITH_ALPHA => {
                let mut shape = vec![0u8; width as usize * height as usize * 4];
                read_exact(stream, &mut shape)?;
                mask = vec![0u8; (width as usize).div_ceil(8) * height as usize];
                read_exact(stream, &mut mask)?;
                shape
            }
            encoding::COPY_RECT => {
                let mut source = vec![0u8; 8];
                read_exact(stream, &mut source)?;
                source
            }
            encoding::RAW => {
                let mut data = vec![0u8; width as usize * height as usize * 4];
                read_exact(stream, &mut data)?;
                data
            }
            // **A compressed rectangle has to be consumed, not ignored.**
            //
            // This arm used to be `_ => Vec::new()`, which is right only if every
            // caller asked for Raw -- and they all did, because the policy
            // preferred ZRLE only when nothing else was on offer and the tests
            // that reached this helper offered Raw. The moment a client listed
            // ZRLE first, QEMU's rule sent it ZRLE, and this read the *next*
            // rectangle header out of the middle of the compressed payload: a
            // plausible width, a plausible height, and an encoding of 127.
            //
            // Silently reading the wrong bytes is the failure this helper's own
            // comment warns about, and it was the helper doing it. Every
            // compressed encoding carries either a length in front of the data
            // (ZRLE) or nothing at all because the rectangle's dimensions already
            // say how long it is (hextile and Tight), and all three have to be
            // consumed or the next read is garbage.
            encoding::ZRLE => {
                // Four big-endian bytes: the compressed length. Then the data.
                let mut length = [0u8; 4];
                read_exact(stream, &mut length)?;
                let mut data = vec![0u8; u32::from_be_bytes(length) as usize];
                read_exact(stream, &mut data)?;
                data
            }
            encoding::ZLIB => {
                // Hextile carries no length: the rectangle's dimensions say how
                // much data there is once it is inflated. So the only way to know
                // how many bytes went past is to inflate it.
                let mut out = vec![0u8; width as usize * height as usize * 4];
                Decoders::new().decode_hextile(stream, width, height, &mut out);
                out
            }
            encoding::TIGHT => {
                // Same, for Tight's fill, palette and basic sub-encodings.
                let mut out = vec![0u8; width as usize * height as usize * 4];
                Decoders::new().decode_tight(stream, width, height, &mut out);
                out
            }
            _ => Vec::new(),
        };
        let rect = Rect {
            x: u16::from_be_bytes([rect[0], rect[1]]),
            y: u16::from_be_bytes([rect[2], rect[3]]),
            width,
            height,
            encoding,
            bytes: bytes.len(),
            pixels: bytes,
        };
        Ok((rect, mask))
    })();
    stream.set_read_timeout(previous)?;
    result
}

/// One of the client's audio commands, which are `255, 1, 0, command`.
///
/// A viewer sends these to turn the audio on and off; `SetFormat` is a different
/// sub-command and has its own message, because it carries a format.
pub fn send_audio_command<W: Write>(stream: &mut W, command: u16) {
    let mut msg = vec![255u8, 1, 0];
    msg.extend_from_slice(&command.to_be_bytes());
    stream.write_all(&msg).expect("audio command");
    stream.flush().expect("flush");
}

/// A read of one of the server's audio messages, which is `255, 1, sub` and
/// nothing else. A block of samples carries a length and is not what this
/// reads; a test that wants samples should ask for a length first.
pub fn try_read_audio_sub(stream: &mut std::net::TcpStream) -> std::io::Result<u16> {
    let previous = stream.read_timeout().ok().flatten();
    stream.set_read_timeout(Some(POLL_TIMEOUT))?;
    let result = (|| {
        let mut header = [0u8; 4];
        read_exact(stream, &mut header)?;
        if header[0] != 255 || header[1] != 1 {
            return Err(std::io::Error::other("not an audio message"));
        }
        Ok(u16::from_be_bytes([header[2], header[3]]))
    })();
    stream.set_read_timeout(previous)?;
    result
}

/// A read of one block of samples, which is `255, 1, 2` and then a length and
/// the samples.
///
/// The counterpart of [`send_audio_format`]: a test that wants to know what a
/// client is actually being sent has to read the data, and reading the audio
/// message header alone would only say that a message arrived.
pub fn try_read_audio_data(stream: &mut std::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let previous = stream.read_timeout().ok().flatten();
    stream.set_read_timeout(Some(POLL_TIMEOUT))?;
    let result = (|| {
        let mut header = [0u8; 4];
        read_exact(stream, &mut header)?;
        if header[0] != 255 || header[1] != 1 {
            return Err(std::io::Error::other("not an audio message"));
        }
        if u16::from_be_bytes([header[2], header[3]]) != 2 {
            return Err(std::io::Error::other("not a block of samples"));
        }
        let mut length = [0u8; 4];
        read_exact(stream, &mut length)?;
        let mut samples = vec![0u8; u32::from_be_bytes(length) as usize];
        read_exact(stream, &mut samples)?;
        Ok(samples)
    })();
    stream.set_read_timeout(previous)?;
    result
}

/// The format a client asks for, which is `255, 1, 0, 2` and then the format:
/// a byte of sample format, a byte of channels, and a frequency.
pub fn send_audio_format<W: Write>(stream: &mut W, format: u8, channels: u8, frequency: u32) {
    let mut msg = vec![255u8, 1, 0, 2];
    msg.push(format);
    msg.push(channels);
    msg.extend_from_slice(&frequency.to_be_bytes());
    stream.write_all(&msg).expect("audio format");
    stream.flush().expect("flush");
}

/// A read of a cut text from the server that gives up when nothing arrives.
///
/// The timeout is [`POLL_TIMEOUT`], and the assumption it rests on is the same
/// one [`try_read_update`] documents.
pub fn try_read_cut_text(stream: &mut std::net::TcpStream) -> std::io::Result<String> {
    let previous = stream.read_timeout().ok().flatten();
    stream.set_read_timeout(Some(POLL_TIMEOUT))?;
    let result = (|| {
        let mut header = [0u8; 4];
        read_exact(stream, &mut header)?;
        if header[0] != 3 {
            return Err(std::io::Error::other("not a cut text"));
        }
        // A cut text is a length and then Latin-1 text.
        let mut len = [0u8; 4];
        read_exact(stream, &mut len)?;
        let mut text = vec![0u8; u32::from_be_bytes(len) as usize];
        read_exact(stream, &mut text)?;
        Ok(String::from_utf8_lossy(&text).into_owned())
    })();
    stream.set_read_timeout(previous)?;
    result
}

/// One rectangle as it came off the wire, with the payload bytes left unread.
///
/// The distinction this type exists to make is between a rectangle the client
/// can *skip* and one it cannot. A rectangle carrying pixels is followed by a
/// body whose length comes from its encoding, so a reader that wants to reach
/// the next rectangle has to know that length. A pseudo-encoding rectangle is
/// supposed to be followed by nothing at all — and that "supposed to" is the
/// whole difficulty, because several of them are followed by a payload, and a
/// reader cannot tell which without a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    pub encoding: i32,
}

/// A `FramebufferUpdate` read with a table of what each encoding carries.
///
/// Deliberately *not* a decoder. It reads no pixels and interprets no
/// compression; it walks the message structure and checks that the byte count
/// adds up, which is the only property at issue when a server emits a
/// pseudo-encoding it should not have. `SKIPPABLE` is the table from QEMU's
/// `vnc.c` and the RFB specification: the encodings whose rectangles a client
/// can step over knowing nothing else.
pub struct SyncReader {
    /// The pixel format's bytes per pixel, for the encodings that send pixels.
    bytes_per_pixel: usize,
}

impl SyncReader {
    /// A reader for a client that asked for `bytes_per_pixel` per pixel.
    pub fn new(bytes_per_pixel: usize) -> Self {
        Self { bytes_per_pixel }
    }

    /// Name an I/O failure, keeping "nothing more is coming" distinct.
    ///
    /// The distinction matters because the two are opposites. A truncated read
    /// means the stream is malformed; a read that ran out of time means the
    /// server had nothing more to say, which is allowed and expected. Guessing
    /// from the message text is not possible — a socket read timeout on Linux
    /// arrives as `EAGAIN`, whose `Display` is "Resource temporarily
    /// unavailable" and whose text contains no word for a timeout at all, so a
    /// caller matching on the string calls a loaded machine a broken stream.
    /// The `ErrorKind` is the only honest signal, and it is what this keeps.
    fn describe(e: std::io::Error) -> String {
        match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                format!("no more messages: {e}")
            }
            _ => format!("the stream is malformed: {e}"),
        }
    }

    /// Whether a failure from [`SyncReader::read_update`] is the server running
    /// out of things to say, as against the stream not adding up.
    pub fn is_idle(error: &str) -> bool {
        error.starts_with("no more messages")
    }

    /// The body length of a rectangle with `encoding`.
    ///
    /// Only for the encodings whose length the geometry determines. The
    /// length-prefixed ones are read rather than computed, and the ones a
    /// reader cannot skip at all are an error, because guessing a length is
    /// what this whole reader exists to catch.
    fn body_len(&self, encoding: i32, width: u16, height: u16) -> Result<usize, String> {
        Ok(match encoding {
            // Raw carries no length prefix; the geometry is the length. QEMU's
            // `vnc_raw_send_framebuffer_update()` writes the rows and stops.
            0 => width as usize * height as usize * self.bytes_per_pixel,
            // CopyRect: eight bytes of source rectangle.
            1 => 8,
            // RRE: a background pixel and a 32-bit count, then the rectangles.
            2 => self.bytes_per_pixel + 4,
            // The pseudo-encodings with a payload. A rectangle for any of them
            // is legal; a reader has to know the length, which is the whole
            // reason this table is here.
            -239 | -314 => 4 * 4 + 4, // RichCursor / CursorWithAlpha
            -261 => 1,               // Led
            // The payload-free ones: nothing to skip.
            -223 | -258 | -259 => 0,
            _ => {
                return Err(format!(
                    "encoding {encoding} is not in the table, so this reader cannot \
                     say how long its rectangle is"
                ))
            }
        })
    }

    /// Read one `FramebufferUpdate`, and leave the stream on the next message.
    ///
    /// The returned rectangles are the message's. Any error means the stream
    /// did not add up: a rectangle whose length cannot be determined, or a
    /// message that ran off the end of what was there.
    ///
    /// Generic over `Read` rather than a socket, so that the same walk can be
    /// pointed at a buffer. That is what lets a test show the walk *failing*
    /// on a known-bad stream, which is the only way to know that a walk
    /// succeeding on a good one means anything.
    pub fn read_update<R: Read>(&mut self, stream: &mut R) -> Result<Vec<WireRect>, String> {
        let mut header = [0u8; 4];
        read_exact(stream, &mut header).map_err(Self::describe)?;
        if header[0] != 0 {
            return Err(format!("message type {} is not a FramebufferUpdate", header[0]));
        }
        if header[1] != 0 {
            return Err(format!("the padding byte is {}, not 0", header[1]));
        }
        let count = u16::from_be_bytes([header[2], header[3]]);
        let mut rects = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut raw = [0u8; 12];
            read_exact(stream, &mut raw).map_err(Self::describe)?;
            let rect = WireRect {
                x: u16::from_be_bytes([raw[0], raw[1]]),
                y: u16::from_be_bytes([raw[2], raw[3]]),
                width: u16::from_be_bytes([raw[4], raw[5]]),
                height: u16::from_be_bytes([raw[6], raw[7]]),
                encoding: i32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]),
            };
            // How much is there to skip? For the length-prefixed encodings the
            // length is in the stream, so it has to be read, not guessed.
            let body = match rect.encoding {
                5 | 6 | 7 | 16 | 8 | 248 | 250 => {
                    let mut len = [0u8; 4];
                    read_exact(stream, &mut len).map_err(Self::describe)?;
                    let n = u32::from_be_bytes(len) as usize;
                    let mut skip = vec![0u8; n];
                    read_exact(stream, &mut skip).map_err(Self::describe)?;
                    n
                }
                -308 => {
                    // ExtendedDesktopSize: a screen count, three padding bytes,
                    // then sixteen per screen. QEMU's
                    // `vnc_desktop_resize_ext()` writes all of it.
                    let mut head = [0u8; 4];
                    read_exact(stream, &mut head).map_err(Self::describe)?;
                    let screens = head[0] as usize;
                    let mut skip = vec![0u8; screens * 16];
                    read_exact(stream, &mut skip).map_err(Self::describe)?;
                    4 + screens * 16
                }
                other => {
                    let n = self.body_len(other, rect.width, rect.height)?;
                    if n > 0 {
                        let mut skip = vec![0u8; n];
                        read_exact(stream, &mut skip).map_err(Self::describe)?;
                    }
                    n
                }
            };
            let _ = body;
            rects.push(rect);
        }
        Ok(rects)
    }
}

/// A `FramebufferUpdate` carrying `rects`, as literal bytes.
///
/// Written by hand rather than through the server's own writer, because the
/// point of using it is to produce a stream the server would refuse to produce.
pub fn update_bytes(rects: &[(u16, u16, u16, u16, i32)], bodies: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![0u8, 0u8];
    out.extend_from_slice(&(rects.len() as u16).to_be_bytes());
    for ((x, y, w, h, encoding), body) in rects.iter().zip(bodies) {
        out.extend_from_slice(&x.to_be_bytes());
        out.extend_from_slice(&y.to_be_bytes());
        out.extend_from_slice(&w.to_be_bytes());
        out.extend_from_slice(&h.to_be_bytes());
        out.extend_from_slice(&encoding.to_be_bytes());
        out.extend_from_slice(body);
    }
    out
}

/// A zlib rectangle, read as bytes and decoded by nothing.
///
/// Deliberately narrow: it walks a `FramebufferUpdate` assuming every rectangle
/// in it is a zlib rectangle, and says so by panicking on anything else. That
/// restriction is what makes it a check rather than a reader. A reader that
/// knows how to step over every encoding is a reader that will accept whatever
/// it is given and hand back a plausible answer, which is how the missing zlib
/// length survived: the general decoder consumed four bytes of compressed
/// stream as a length, and nobody compared the result against the format.
pub struct RawZlibRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
    /// The 32-bit length the rectangle claims, as it appeared on the wire.
    pub declared: u32,
    /// Exactly `declared` bytes read after it.
    pub body: Vec<u8>,
}

/// Reads the next message, and if it is a zlib rectangle, returns it.
///
/// Returns `None` for a message that is not a zlib rectangle rather than
/// failing, so a caller can keep asking. The one thing it will not do is guess:
/// a rectangle whose length does not account for the bytes that follow is a
/// stream that has lost its place, and it is reported as an error rather than
/// recovered from.
pub fn read_raw_zlib_rect<R: Read>(stream: &mut R) -> std::io::Result<Option<RawZlibRect>> {
    let mut message = [0u8; 4];
    read_exact(stream, &mut message)?;
    if message[0] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected a FramebufferUpdate, found message type {}", message[0]),
        ));
    }
    let count = u16::from_be_bytes([message[2], message[3]]);
    for index in 0..count {
        let mut header = [0u8; 12];
        read_exact(stream, &mut header)?;
        let x = u16::from_be_bytes([header[0], header[1]]);
        let y = u16::from_be_bytes([header[2], header[3]]);
        let width = u16::from_be_bytes([header[4], header[5]]);
        let height = u16::from_be_bytes([header[6], header[7]]);
        let encoding = i32::from_be_bytes([header[8], header[9], header[10], header[11]]);
        assert_eq!(
            encoding,
            encoding::ZLIB,
            "rectangle {index} of {count} is encoding {encoding}, not zlib. This \
             reader only walks zlib, which is fine as long as the client asked \
             for nothing else — and the test that uses it does"
        );
        let mut length = [0u8; 4];
        read_exact(stream, &mut length)?;
        let declared = u32::from_be_bytes(length);
        let mut body = vec![0u8; declared as usize];
        read_exact(stream, &mut body)?;
        if index == count - 1 {
            return Ok(Some(RawZlibRect {
                x,
                y,
                width,
                height,
                declared,
                body,
            }));
        }
    }
    Ok(None)
}
