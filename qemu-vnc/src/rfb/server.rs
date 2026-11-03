// Vendored from elmarco/rust-vnc, see `mod.rs` for the provenance.
// Upstream is mostly undocumented and carries some client-only code: keep it
// that way, and document the parts we change.
#![allow(missing_docs, dead_code, clippy::all)]

use super::audio;
use super::protocol::{self, Message};
use super::sasl::{self, MAX_MECHNAME};
use super::{Error, Rect, Result, SecurityPolicy, ServerOptions, Transport};
use byteorder::{BigEndian, WriteBytesExt};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use std::io::Write;

/// Definitions of events received by server from client.
#[derive(Debug)]
pub enum Event {
    /// A `SetPixelFormat` message sets the format in which pixel values should be sent in
    /// `FramebufferUpdate` messages. If the client does not send a `SetPixelFormat` message, then
    /// the server sends pixel values in its natural format as specified in the ServerInit message.
    SetPixelFormat(protocol::PixelFormat),

    /// A `SetEncodings` message sets the encoding types in which pixel data can be sent by the
    /// server. The order of the encoding types given in this message is a hint by the client as to
    /// its preference (the first encoding specified being most preferred). The server may or may
    /// not choose to make use of this hint. Pixel data may always be sent in raw encoding even if
    /// not specified explicitly here.
    ///
    /// In addition to genuine encodings, a client can request "pseudo-encodings" to declare to the
    /// server that it supports certain extensions to the protocol. A server that does not support
    /// the extension will simply ignore the pseudo-encoding. Note that this means the client must
    /// assume that the server does not support the extension until it gets some extension-specific
    /// confirmation from the server.
    SetEncodings(Vec<protocol::Encoding>),

    /// A `FramebufferUpdateRequest` message notifies the server that the client is interested in
    /// the area of the framebuffer specified by `x_position`, `y_position`, `width` and `height`.
    /// The server usually responds to a `FramebufferUpdateRequest` by sending a
    /// `FramebufferUpdate`. A single `FramebufferUpdate` may be sent in reply to several
    /// `FramebufferUpdateRequests`.
    ///
    /// The server assumes that the client keeps a copy of all parts of the framebuffer in which it
    /// is interested. This means that normally the server only needs to send incremental updates to
    /// the client.
    ///
    /// If the client has lost the contents of a particular area that it needs, then the client
    /// sends a FramebufferUpdateRequest with incremental set to false. This requests that the
    /// server send the entire contents of the specified area as soon as possible. The area will not
    /// be updated using the `CopyRect` encoding.
    ///
    /// If the client has not lost any contents of the area in which it is interested, then it sends
    /// a `FramebufferUpdateRequest` with incremental set to `true`. If and when there are changes
    /// to the specified area of the framebuffer, the server will send a `FramebufferUpdate`. Note
    /// that there may be an indefinite period between the `FramebufferUpdateRequest` and the
    /// `FramebufferUpdate`.
    FramebufferUpdateRequest {
        incremental: bool,
        x_position: u16,
        y_position: u16,
        width: u16,
        height: u16,
    },

    /// A `KeyEvent` message indicates a key press or release. `down` flag is `true` if the key is
    /// now pressed, and false if it is now released. The key itself is specified using the "keysym"
    /// values defined by the X Window System, even if the client or server is not running the X
    /// Window System.
    KeyEvent { down: bool, key: u32 },

    /// A `PointerEvent` message indicates either pointer movement or a pointer button press or
    /// release. The pointer is now at (`x_position`, `y_position`), and the current state of
    /// buttons 1 to 8 are represented by bits 0 to 7 of button-mask, respectively; 0 means up, 1
    /// means down (pressed).
    ///
    /// On a conventional mouse, buttons 1, 2, and 3 correspond to the left, middle, and right
    /// buttons on the mouse. On a wheel mouse, each step of the wheel upwards is represented by a
    /// press and release of button 4, and each step downwards is represented by a press and release
    /// of button 5.
    PointerEvent {
        button_mask: u8,
        x_position: u16,
        y_position: u16,
    },

    /// RFB provides limited support for synchronizing the "cut buffer" of selected text between
    /// client and server. This message tells the server that the client has new ISO 8859-1
    /// (Latin-1) text in its cut buffer. Ends of lines are represented by the newline character
    /// (hex 0a) alone. No carriage-return (hex 0d) is used. There is no way to transfer text
    /// outside the Latin-1 character set.
    CutText(String),

    /// This encoding allows the client to send an extended key event containing a keycode, in
    /// addition to a keysym. The advantage of providing the keycode is that it enables the server
    /// to interpret the key event independantly of the clients’ locale specific keymap. This can
    /// be important for virtual desktops whose key input device requires scancodes, for example,
    /// virtual machines emulating a PS/2 keycode. Prior to this extension, RFB servers for such
    /// virtualization software would have to be configured with a keymap matching the client. With
    /// this extension it is sufficient for the guest operating system to be configured with the
    /// matching keymap. The VNC server is keymap independant.
    ///
    /// The `keysym` and `down`-flag fields also take the same values as described for the KeyEvent
    /// message. The keycode is the XT keycode that produced the keysym.
    ExtendedKeyEvent {
        down: bool,
        keysym: u32,
        keycode: u32,
    },

    SetDesktopSize {
        width: u16,
        height: u16,
        screens: Vec<protocol::Screen>,
    },

    /// A QEMU extended message about the audio. Ours, not upstream: the
    /// vendored crate had no audio.
    QemuAudio {
        /// What the client asked for.
        command: audio::Command,
    },
}

/// Gathers all data needed to validate framebuffer updates.
struct ValidationData {
    /// Number of bytes per pixel used to check validity of sent data extracted from `PixelFormat`.
    bytes_per_pixel: u16,
}

impl ValidationData {
    /// Constructs new `ValidationData`.
    fn new(pixel_format: Option<&protocol::PixelFormat>) -> Self {
        let bytes_per_pixel = if let Some(pf) = pixel_format {
            (pf.bits_per_pixel as u16 + 7) / 8
        } else {
            0
        };
        Self { bytes_per_pixel }
    }
}

/// Helper data structure containing data to be sent by server in messages containing rectangles.
#[derive(Debug)]
enum Update<'a> {
    Raw {
        rect: Rect,
        pixel_data: &'a [u8],
    },
    CopyRect {
        dst: Rect,
        src_x_position: u16,
        src_y_position: u16,
    },
    Zrle {
        rect: Rect,
        zlib_data: &'a [u8],
    },
    /// The `zlib` hextile encoding.
    Zlib {
        rect: Rect,
        zlib_data: &'a [u8],
    },
    /// The Tight encoding.
    Tight {
        rect: Rect,
        tight_data: &'a [u8],
    },
    SetCursor {
        size: (u16, u16),
        hotspot: (u16, u16),
        pixels: &'a [u8],
        mask_bits: &'a [u8],
    },
    DesktopSize {
        width: u16,
        height: u16,
    },
    ExtendedDesktopSize {
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        screens: &'a [protocol::Screen],
    },
    /// The acknowledgement of a pseudo-encoding: a rectangle with the frame
    /// buffer's size and no pixels at all.
    ///
    /// Ours, not upstream: the vendored `add_pseudo_encoding` wrote an empty
    /// rectangle, and QEMU's acknowledgements carry the dimensions.
    Encoding {
        rect: Rect,
        encoding: protocol::Encoding,
    },
}

impl<'a> Update<'a> {
    /// Checks validity of given `Update`. Panics if it is not valid.
    fn check(&self, validation_data: &ValidationData) {
        match *self {
            Update::Raw {
                ref rect,
                pixel_data,
            } => {
                let expected_num_bytes = rect.width as usize
                    * rect.height as usize
                    * validation_data.bytes_per_pixel as usize;
                if expected_num_bytes != pixel_data.len() {
                    panic!(
                        "Expected data length for rectangle {:?} is {} while given {}",
                        rect,
                        expected_num_bytes,
                        pixel_data.len()
                    );
                }
            }
            Update::CopyRect {
                dst: _,
                src_x_position: _,
                src_y_position: _,
            } => {
                // No check is needed
            }
            Update::Zrle { rect: _, zlib_data } => {
                if zlib_data.len() > u32::max_value() as usize {
                    panic!("Maximal length of compressed data is {}", u32::max_value());
                }
            }
            Update::Zlib { rect: _, zlib_data } => {
                if zlib_data.len() > u32::max_value() as usize {
                    panic!("Maximal length of compressed data is {}", u32::max_value());
                }
            }
            Update::Tight {
                rect: _,
                tight_data,
            } => {
                if tight_data.len() > u32::max_value() as usize {
                    panic!("Maximal length of compressed data is {}", u32::max_value());
                }
            }
            Update::SetCursor {
                size: (width, height),
                hotspot: _,
                pixels,
                mask_bits,
            } => {
                // Check pixel data length
                let expected_num_bytes =
                    width as usize * height as usize * validation_data.bytes_per_pixel as usize;
                if expected_num_bytes != pixels.len() {
                    panic!(
                        "Expected data length is {} while given {}",
                        expected_num_bytes,
                        pixels.len()
                    );
                }

                // Check bit mask length
                let expected_num_bytes = ((width as usize + 7) / 8) * height as usize;
                if expected_num_bytes != mask_bits.len() {
                    panic!(
                        "Expected bit mask length is {} while given {}",
                        expected_num_bytes,
                        mask_bits.len()
                    );
                }
            }
            Update::DesktopSize {
                width: _,
                height: _,
            } => {
                // No check is needed
            }
            Update::ExtendedDesktopSize { .. } => {}
            Update::Encoding { .. } => {
                // No check is needed
            }
        }
    }

    /// Serializes `Update` to given stream.
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match *self {
            Update::Raw {
                ref rect,
                pixel_data,
            } => {
                rect.write_to(writer)?;
                protocol::Encoding::Raw.write_to(writer)?;
                writer.write_all(pixel_data)?;
            }
            Update::CopyRect {
                ref dst,
                src_x_position,
                src_y_position,
            } => {
                dst.write_to(writer)?;
                protocol::Encoding::CopyRect.write_to(writer)?;
                writer.write_u16::<BigEndian>(src_x_position)?;
                writer.write_u16::<BigEndian>(src_y_position)?;
            }
            Update::Zrle {
                ref rect,
                zlib_data,
            } => {
                rect.write_to(writer)?;
                protocol::Encoding::Zrle.write_to(writer)?;
                writer.write_u32::<BigEndian>(zlib_data.len() as u32)?;
                writer.write_all(zlib_data)?;
            }
            Update::Zlib {
                ref rect,
                zlib_data,
            } => {
                rect.write_to(writer)?;
                protocol::Encoding::Zlib.write_to(writer)?;
                // A 32-bit length, then that many bytes of zlib stream. The
                // length is not optional and the client cannot work it out from
                // the rectangle's dimensions: zlib is a stream of indefinite
                // length, and only the sender knows where it ends.
                //
                // This line used to be missing, with a comment claiming the
                // data "has no length of its own". That is true of a Tight
                // rectangle's *filter output*, which does carry a compact
                // length of its own, and false here. Every other compressed
                // encoding in this enum writes the length — Zrle below, and
                // Tight's outer stream — so the omission was also a plain
                // inconsistency within a few lines of itself.
                //
                // It is the bug behind a production viewer showing a perfect
                // first frame and then never changing: the full-screen frame
                // is ZRLE, which always had its length, so it rendered; every
                // update after it was a thin strip encoded as zlib, so the
                // client read four bytes of the stream as a length, waited for
                // bytes that were never coming, and stopped asking. No test
                // caught it because the test client read the same missing field
                // the same wrong way and compared geometry rather than bytes.
                writer.write_u32::<BigEndian>(zlib_data.len() as u32)?;
                writer.write_all(zlib_data)?;
            }
            Update::Tight {
                ref rect,
                tight_data,
            } => {
                rect.write_to(writer)?;
                protocol::Encoding::Tight.write_to(writer)?;
                writer.write_all(tight_data)?;
            }
            Update::SetCursor {
                size,
                hotspot,
                pixels,
                mask_bits,
            } => {
                writer.write_u16::<BigEndian>(hotspot.0)?;
                writer.write_u16::<BigEndian>(hotspot.1)?;
                writer.write_u16::<BigEndian>(size.0)?;
                writer.write_u16::<BigEndian>(size.1)?;
                protocol::Encoding::RichCursor.write_to(writer)?;
                writer.write_all(pixels)?;
                writer.write_all(mask_bits)?;
            }
            Update::DesktopSize { width, height } => {
                writer.write_u16::<BigEndian>(0)?;
                writer.write_u16::<BigEndian>(0)?;
                writer.write_u16::<BigEndian>(width)?;
                writer.write_u16::<BigEndian>(height)?;
                protocol::Encoding::DesktopSize.write_to(writer)?;
            }
            Update::ExtendedDesktopSize {
                x,
                y,
                width,
                height,
                screens,
            } => {
                writer.write_u16::<BigEndian>(x)?;
                writer.write_u16::<BigEndian>(y)?;
                writer.write_u16::<BigEndian>(width)?;
                writer.write_u16::<BigEndian>(height)?;
                protocol::Encoding::ExtendedDesktopSize.write_to(writer)?;
                writer.write_u8(screens.len().try_into().unwrap())?;
                writer.write_all(&[0; 3])?;
                for s in screens {
                    s.write_to(writer)?;
                }
            }
            Update::Encoding { rect, encoding } => {
                rect.write_to(writer)?;
                encoding.write_to(writer)?;
            }
        }
        Ok(())
    }
}

pub trait ServerMessage {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()>;
}

/// `FramebufferUpdate` message.
pub struct FramebufferUpdate<'a> {
    validation_data: ValidationData,
    updates: Vec<Update<'a>>,
}

impl<'a> ServerMessage for FramebufferUpdate<'a> {
    /// Serializes this structure and sends it using given `writer`.
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        for chunk in self.updates.chunks(u16::max_value() as usize) {
            let count = chunk.len() as u16;
            protocol::S2C::FramebufferUpdate { count }.write_to(writer)?;
            for update in chunk {
                update.write_to(writer)?;
            }
        }
        Ok(())
    }
}

impl<'a> FramebufferUpdate<'a> {
    /// Constructs new `FramebufferUpdate`.
    pub fn new(pixel_format: Option<&protocol::PixelFormat>) -> Self {
        FramebufferUpdate {
            validation_data: ValidationData::new(pixel_format),
            updates: Vec::new(),
        }
    }

    /// Adds raw pixel data.
    ///
    /// Panics if length of pixel data does not match rectangle size.
    pub fn add_raw_pixels(&mut self, rect: Rect, pixel_data: &'a [u8]) -> &mut Self {
        let update = Update::Raw { rect, pixel_data };
        update.check(&self.validation_data);
        self.updates.push(update);
        self
    }

    /// Adds `CopyRect` update message instructing client to reuse pixel data it already owns.
    pub fn add_copy_rect(
        &mut self,
        dst: Rect,
        src_x_position: u16,
        src_y_position: u16,
    ) -> &mut Self {
        let update = Update::CopyRect {
            dst,
            src_x_position,
            src_y_position,
        };
        update.check(&self.validation_data);
        self.updates.push(update);
        self
    }

    /// Adds ZRLE compressed pixel data.
    ///
    /// Panics if length of compressed data is bigger than `u32::MAX`.
    ///
    /// The data is the zlib stream of the rectangle, as produced by
    /// [`Encoders`](super::encodings::Encoders).
    pub fn add_compressed_pixels(&mut self, rect: Rect, zlib_data: &'a [u8]) -> &mut Self {
        let update = Update::Zrle { rect, zlib_data };
        update.check(&self.validation_data);
        self.updates.push(update);
        self
    }

    /// Adds hextile (`zlib` encoding) pixel data.
    ///
    /// Panics if length of compressed data is bigger than `u32::MAX`.
    pub fn add_zlib_pixels(&mut self, rect: Rect, zlib_data: &'a [u8]) -> &mut Self {
        let update = Update::Zlib { rect, zlib_data };
        update.check(&self.validation_data);
        self.updates.push(update);
        self
    }

    /// Adds Tight pixel data.
    ///
    /// Panics if length of compressed data is bigger than `u32::MAX`.
    pub fn add_tight_pixels(&mut self, rect: Rect, tight_data: &'a [u8]) -> &mut Self {
        let update = Update::Tight { rect, tight_data };
        update.check(&self.validation_data);
        self.updates.push(update);
        self
    }

    /// Add data for drawing cursor.
    ///
    /// Panics if pixel data or mask bits length does not match size of the cursor.
    pub fn add_cursor(
        &mut self,
        width: u16,
        height: u16,
        hotspot_x: u16,
        hotspot_y: u16,
        pixels: &'a [u8],
        mask_bits: &'a [u8],
    ) -> &mut Self {
        let update = Update::SetCursor {
            size: (width, height),
            hotspot: (hotspot_x, hotspot_y),
            pixels,
            mask_bits,
        };
        update.check(&self.validation_data);
        self.updates.push(update);
        self
    }

    /// Adds notification about framebuffer resize.
    pub fn add_desktop_size(&mut self, width: u16, height: u16) -> &mut Self {
        let update = Update::DesktopSize { width, height };
        update.check(&self.validation_data);
        self.updates.push(update);
        self
    }

    /// Adds notification about framebuffer resize.
    pub fn add_extended_desktop_size(
        &mut self,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
        screens: &'a [protocol::Screen],
    ) -> &mut Self {
        let update = Update::ExtendedDesktopSize {
            x,
            y,
            width,
            height,
            screens,
        };
        update.check(&self.validation_data);
        self.updates.push(update);
        self
    }

    /// Adds confirmation of support of a pseudo-encoding.
    ///
    /// Ours, not upstream: the rectangle carries the frame buffer's size, as
    /// QEMU's acknowledgements do. `vnc_framebuffer_update()` is called with
    /// the dimensions for every one of them — the audio acknowledgement, the
    /// extended key event one, the LED one — so a client reads the same
    /// rectangle whatever extension is being confirmed, and an empty one would
    /// be a difference a viewer could notice.
    ///
    /// The rectangle has to be the *whole* of the message for the encoding.
    /// Most pseudo-encodings are followed by a payload, and a bare rectangle
    /// for one of those desynchronises the client's stream rather than merely
    /// omitting something; see [`protocol::Encoding::is_payload_free`].
    ///
    /// This panics rather than returning an error, and it does so in release
    /// builds too. A missing payload is not a logic fault to be recovered from
    /// at runtime — there is no correct response to "the bytes after this
    /// rectangle are owed to the client and were not sent" other than not
    /// sending the rectangle, and a caller that could reach this at all has a
    /// bug that no test in this tree can catch, since a decoder written by the
    /// same hand as the encoder cannot tell a valid stream from a misaligned
    /// one. Failing at the call site names the bug; sending it anyway produces
    /// a viewer that connects, negotiates, and shows nothing, which is what
    /// this port did and what cost four logs to find.
    pub fn add_pseudo_encoding(
        &mut self,
        encoding: protocol::Encoding,
        width: u16,
        height: u16,
    ) -> &mut Self {
        assert!(
            encoding.is_payload_free(),
            "encoding {encoding:?} is not payload-free, so a bare rectangle for it \
             would desynchronise the client's stream; see Encoding::ACKNOWLEDGED"
        );
        let update = Update::Encoding {
            rect: Rect::new(0, 0, width, height),
            encoding,
        };
        update.check(&self.validation_data);
        self.updates.push(update);
        self
    }
}

/// One served client: the RFB handshake, and the messages exchanged with it.
///
/// The client requests are read with [`Session::read_event`] and the updates
/// sent with [`Session::send`], both from the same task: the stream can not
/// be shared with a reader thread, because a WebSocket or a TLS stream is a
/// single object. A message is only parsed once all of its bytes have been
/// read, so the protocol code keeps the synchronous, `read_exact` based
/// shape of the upstream crate while the transport is polled.
pub struct Session<T: Transport> {
    stream: T,
    /// The bytes read from the client that were not parsed yet.
    input: Vec<u8>,
    /// How much of `input` was already parsed.
    parsed: usize,
    /// The buffer a read from the transport lands in.
    chunk: Vec<u8>,
}

/// What the RFB handshake established about a client.
///
/// The protocol does not end with this: the session is ready, and what the
/// client proved is for the caller to report.
#[derive(Clone, Debug, Default)]
pub struct Handshake {
    /// Whether the client agreed to share the desktop with the others.
    pub shared: bool,
    /// The credentials of the security type the client passed, if it was one
    /// that establishes any.
    pub credentials: Option<sasl::Credentials>,
}

impl Handshake {
    /// Whether the client wanted to share the desktop.
    pub fn shared(&self) -> bool {
        self.shared
    }
}

/// The most bytes one client message may take.
///
/// The largest message of the protocol is a cut text, a 32 bit length
/// followed by that many bytes, and this is the `0xffffff` that caps it in
/// the RFB specification. It is what bounds the cost of the retry loop of
/// [`Session::read`]: an incomplete message is parsed again for every read,
/// and a parser that allocates the declared length charges that length each
/// time, so a peer that declares the maximum and then trickles it out pays a
/// few seconds of CPU for the whole connection. QEMU does not have that cost
/// — it reads a cut text into a buffer it sized once — and avoiding it here
/// would mean duplicating the size of every message next to its parser, so it
/// is bounded and documented rather than designed around.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// The session is printed in the logs, without the stream it holds.
impl<T: Transport> std::fmt::Debug for Session<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("buffered", &self.input.len().saturating_sub(self.parsed))
            .finish_non_exhaustive()
    }
}

/// How many bytes are read from the transport at a time.
///
/// The input is drained as messages are parsed, so this only has to be large
/// enough to keep a read syscall worthwhile.
const READ_CHUNK: usize = 8 * 1024;

/// Append what the transport has to `buffer`.
///
/// There is no `read_buf` in the `futures` asynchronous extensions, so the
/// bytes are read in a fixed chunk and appended.
async fn read_into<T: Transport>(
    stream: &mut T,
    buffer: &mut Vec<u8>,
    chunk: &mut [u8],
) -> Result<()> {
    let read = stream.read(chunk).await?;
    buffer.extend_from_slice(&chunk[..read]);
    Ok(())
}

/// Whether an error means "the message is not all here yet", rather than
/// "the client is gone". `buffered` is how many unparsed bytes were read.
///
/// The parsers report a short read as `UnexpectedEof`. The client to server
/// one is the exception: it reads its first byte with a plain `read`, and
/// reports *no* byte as a disconnection, which on a stream it owns is exactly
/// what it means. Here that is only a disconnection if we have nothing
/// buffered: the transport said how many bytes there were, so an empty buffer
/// means "read more".
fn short_read(error: &Error, buffered: usize) -> bool {
    match error {
        Error::Io(e) => e.kind() == std::io::ErrorKind::UnexpectedEof,
        Error::Disconnected => buffered == 0,
        // Nothing else is a "come back later".
        _ => false,
    }
}

impl<T: Transport> Session<T> {
    /// Read into the buffer, and return how many bytes were added.
    async fn fill(&mut self) -> Result<usize> {
        let before = self.input.len();
        read_into(&mut self.stream, &mut self.input, &mut self.chunk).await?;
        Ok(self.input.len() - before)
    }
    /// Perform the RFB handshake on `stream`, and serve the client.
    ///
    /// Returns the new session, and what the handshake established: whether the
    /// client agreed to share the desktop, and the credentials of the security
    /// type it passed. The protocol does not end with the credentials, and the
    /// caller is what reports them.
    pub async fn from_stream(
        stream: T,
        width: u16,
        height: u16,
        opts: ServerOptions<'_>,
    ) -> Result<(Session<T>, Handshake)> {
        let mut session = Self {
            stream,
            input: Vec::new(),
            parsed: 0,
            chunk: vec![0; READ_CHUNK],
        };

        // Start version handshake - send highest supported version. Client may respond with lower
        // version but never higher.
        session.write(&protocol::Version::Rfb38).await?;
        let version = session.read().await?;
        // What the security type the client picks establishes, if anything.
        let mut credentials = None;

        // Security handshake.
        match version {
            protocol::Version::Rfb33 => {
                // RFB 3.3 has no security type list, and only means "None".
                session.write(&protocol::SecurityType::None).await?;
                // RFB 3.3 has no way to negotiate: a client that only
                // supports 3.3 is served without authentication.
                let _ = opts.security.check_choice(protocol::SecurityType::None);
            }
            _ => {
                let security_types = opts.security.offered();
                session
                    .write(&protocol::SecurityTypes(security_types))
                    .await?;
                let security_type: protocol::SecurityType = session.read().await?;
                let policy = match opts.security.check_choice(security_type) {
                    Ok(policy) => policy,
                    Err(_) => {
                        // RFB 3.8 reports a security type we do not support
                        // with the "Invalid" type, followed by the reason.
                        session.write(&protocol::SecurityType::Invalid).await?;
                        session
                            .write(&String::from("unsupported security type"))
                            .await?;
                        return Err(Error::AuthenticationUnavailable);
                    }
                };
                credentials = Self::authenticate(&mut session, version, &policy, &opts).await?;
            }
        }

        // Wait for client init message
        let client_init: protocol::ClientInit = session.read().await?;

        // Send server init message
        let server_init = protocol::ServerInit {
            framebuffer_width: width,
            framebuffer_height: height,
            pixel_format: opts.pixel_format,
            name: opts.name.to_owned(),
        };
        session.write(&server_init).await?;

        Ok((
            session,
            Handshake {
                shared: client_init.shared,
                credentials,
            },
        ))
    }

    /// Run the security handshake the client chose, and report the result.
    ///
    /// Returns the credentials a SASL exchange produced, if that is what the
    /// client chose: the protocol does not end with them, and the caller is
    /// what reports the user name over D-Bus.
    async fn authenticate(
        session: &mut Session<T>,
        version: protocol::Version,
        policy: &SecurityPolicy<'_>,
        opts: &ServerOptions<'_>,
    ) -> Result<Option<sasl::Credentials>> {
        let password = match policy {
            SecurityPolicy::None => {
                // RFB 3.3 does not send a security result for "None".
                if version == protocol::Version::Rfb33 {
                    return Ok(None);
                }
                session.write(&protocol::SecurityResult::Succeeded).await?;
                return Ok(None);
            }
            SecurityPolicy::Sasl(mechanisms) => {
                return Self::authenticate_sasl(session, version, mechanisms, &opts.endpoints)
                    .await;
            }
            SecurityPolicy::VncAuth(password) => match password.key() {
                Some(password) => password,
                None => {
                    return Err(Self::refuse(session, version, "Authentication disabled").await);
                }
            },
        };

        // The challenge/response exchange. It is a fixed size, so it does not
        // go through the message buffer, but it still has to be flushed: a
        // WebSocket only sends what was pushed to it.
        let challenge = match opts.challenge {
            Some(challenge) => challenge,
            None => super::random_challenge()?,
        };
        session.stream.write_all(&challenge).await?;
        session.stream.flush().await?;
        let mut response = [0u8; 16];
        session.stream.read_exact(&mut response).await?;
        if !password.check(&challenge, &response) {
            return Err(Self::refuse(session, version, "Authentication failure").await);
        }
        session.write(&protocol::SecurityResult::Succeeded).await?;
        Ok(None)
    }

    /// Run a SASL exchange, and report what it established.
    ///
    /// The framing is QEMU's, from `ui/vnc-auth-sasl.c`: a list of mechanism
    /// names, the one the client picked, and then rounds of data. Each round
    /// the server answers ends with a byte saying whether the exchange is
    /// over, which is what makes the loop below terminate on a client that
    /// gives up as well as on one that succeeds.
    async fn authenticate_sasl(
        session: &mut Session<T>,
        version: protocol::Version,
        mechanisms: &sasl::Mechanisms,
        endpoints: &sasl::Endpoints,
    ) -> Result<Option<sasl::Credentials>> {
        // Refuse a client, and report the refusal. The RFB security result,
        // then the reason, as every refusal does: a SASL client that is turned
        // away has to be told why where a VNC one is.
        async fn refuse<T: Transport>(
            session: &mut Session<T>,
            version: protocol::Version,
            reason: &str,
        ) -> Error {
            let _ = session.write(&protocol::SecurityResult::Failed).await;
            if version != protocol::Version::Rfb33 {
                let _ = session.write(&String::from(reason)).await;
            }
            Error::AuthenticationFailure(reason.to_owned())
        }

        // The exchange belongs to this connection; what is offered is shared.
        let mut sasl = sasl::Sasl::new(mechanisms, endpoints);

        // 1. The mechanisms we offer, as a length and a comma separated list.
        let list = mechanisms.mechanism_list();
        if list.is_empty() {
            return Err(refuse(session, version, "no SASL mechanism is available").await);
        }
        session
            .write_raw(&(list.len() as u32).to_be_bytes())
            .await?;
        session.write_raw(list.as_bytes()).await?;

        // 2. The mechanism the client picked: 1 to 100 bytes, and one of ours.
        //    Checked before reading anything else, so a client that names
        //    something else is told so rather than being made to talk for it.
        let name = session.read_sized(MAX_MECHNAME).await?;
        let name = match std::str::from_utf8(&name) {
            Ok(name) if mechanisms.accepts(name) => name.to_owned(),
            _ => return Err(refuse(session, version, "unsupported SASL mechanism").await),
        };

        // 3. Its first message, and then the rounds. `Sasl` owns the state, so
        //    this is a loop around one call.
        let data = session.read_sasl_data().await?;
        let mut step = match sasl.start(name.as_bytes(), data.as_deref()) {
            Ok(step) => step,
            Err(e) => return Err(refuse(session, version, &e.to_string()).await),
        };
        loop {
            if let Some(output) = &step.output
                && output.len() > sasl::MAX_DATA
            {
                return Err(refuse(session, version, "the SASL step is too long").await);
            }
            // The data is sent with a length that includes its NUL padding,
            // so a client can tell an empty string from no data at all.
            match &step.output {
                Some(data) => {
                    session
                        .write_raw(&((data.len() + 1) as u32).to_be_bytes())
                        .await?;
                    session.write_raw(data).await?;
                    session.write_raw(&[0]).await?;
                }
                None => session.write_raw(&0u32.to_be_bytes()).await?,
            }
            session.write_raw(&[u8::from(step.complete)]).await?;
            if step.complete {
                break;
            }
            let data = session.read_sasl_data().await?;
            step = match sasl.step(data.as_deref()) {
                Ok(step) => step,
                Err(e) => return Err(refuse(session, version, &e.to_string()).await),
            };
        }

        session.write(&protocol::SecurityResult::Succeeded).await?;
        Ok(Some(sasl::Credentials {
            // A mechanism that authenticates a user reports it; `ANONYMOUS`
            // does not, and an empty name is what a client sees for it.
            username: sasl.username().unwrap_or_default(),
            ssf: sasl.ssf(),
            mechanism: sasl.mechanism().map(str::to_owned),
            description: sasl.describe(),
        }))
    }

    /// Tell the client its authentication failed, and return the error to
    /// report.
    async fn refuse(session: &mut Session<T>, version: protocol::Version, reason: &str) -> Error {
        let _ = session.write(&protocol::SecurityResult::Failed).await;
        // RFB 3.8 and later tell the client why we refused it.
        if version != protocol::Version::Rfb33 {
            let _ = session.write(&String::from(reason)).await;
        }
        Error::AuthenticationFailure(reason.to_owned())
    }

    /// Read one message from the client, reading more bytes from the transport
    /// until it is complete.
    async fn read<M: Message>(&mut self) -> Result<M> {
        loop {
            // Try to parse what has already been read. A partial message is
            // reported as a short read, which is how we know to read more.
            let mut reader = std::io::Cursor::new(&self.input[self.parsed..]);
            match M::read_from(&mut reader) {
                Ok(message) => {
                    self.parsed += reader.position() as usize;
                    return Ok(message);
                }
                Err(e) if short_read(&e, self.input.len() - self.parsed) => {
                    // Drop what was parsed, so the buffer does not grow for
                    // ever as messages are consumed.
                    if self.parsed > 0 {
                        self.input.drain(..self.parsed);
                        self.parsed = 0;
                    }
                    if self.input.len() > MAX_MESSAGE {
                        return Err(Error::Unexpected("oversized client message"));
                    }
                    if self.fill().await? == 0 {
                        return Err(Error::Disconnected);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Send one message to the client.
    ///
    /// The message is serialised first, so that a single write reaches the
    /// transport: a WebSocket message can not be split, and one RFB message
    /// per WebSocket message is what a viewer expects.
    async fn write<M: Message>(&mut self, message: &M) -> Result<()> {
        let mut buffer = Vec::new();
        message.write_to(&mut buffer)?;
        self.write_raw(&buffer).await
    }

    /// Write bytes that are a message this crate does not model, and get them
    /// out.
    ///
    /// The audio messages are the case: they are QEMU's own, they are not
    /// `Message`s, and serialising them here would be a second copy of the
    /// framing that [`crate::rfb::audio`] already owns.
    pub async fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.write_raw(data).await
    }

    /// Write bytes that are not a message, and get them out.
    ///
    /// The flush is the point: a WebSocket only sends what was pushed to it,
    /// so a write that is not flushed never leaves the process.
    async fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Read a length-prefixed block, refusing one that is too long.
    ///
    /// The length is read before the bytes, which is what lets a peer be
    /// refused before it can make us allocate what it asked for.
    async fn read_sized(&mut self, max: usize) -> Result<Vec<u8>> {
        let length = self.read_u32().await? as usize;
        if length > max {
            return Err(Error::Unexpected("the SASL message is too long"));
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        let mut data = vec![0u8; length];
        self.stream.read_exact(&mut data).await?;
        Ok(data)
    }

    /// Read the data of one SASL round, with the padding taken off.
    async fn read_sasl_data(&mut self) -> Result<Option<Vec<u8>>> {
        let data = self.read_sized(sasl::MAX_DATA).await?;
        Ok(sasl::unpad(&data)?.map(<[u8]>::to_vec))
    }

    /// Read a big endian `u32`, which is how the SASL messages are framed.
    async fn read_u32(&mut self) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.stream.read_exact(&mut bytes).await?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Read the next event sent by the client.
    ///
    /// Waits for the message to be complete: the caller is expected to poll
    /// this together with the events of the server.
    pub async fn read_event(&mut self) -> Result<Event> {
        let package: protocol::C2S = self.read().await?;
        Ok(match package {
            protocol::C2S::SetPixelFormat(pixel_format) => Event::SetPixelFormat(pixel_format),
            protocol::C2S::SetEncodings(encodings) => Event::SetEncodings(encodings),
            protocol::C2S::FramebufferUpdateRequest {
                incremental,
                x_position,
                y_position,
                width,
                height,
            } => Event::FramebufferUpdateRequest {
                incremental,
                x_position,
                y_position,
                width,
                height,
            },
            protocol::C2S::KeyEvent { down, key } => Event::KeyEvent { down, key },
            protocol::C2S::PointerEvent {
                button_mask,
                x_position,
                y_position,
            } => Event::PointerEvent {
                button_mask,
                x_position,
                y_position,
            },
            protocol::C2S::CutText(clipboard) => Event::CutText(clipboard),
            protocol::C2S::ExtendedKeyEvent {
                down,
                keysym,
                keycode,
            } => Event::ExtendedKeyEvent {
                down,
                keysym,
                keycode,
            },
            protocol::C2S::SetDesktopSize {
                width,
                height,
                screens,
            } => Event::SetDesktopSize {
                width,
                height,
                screens,
            },
            protocol::C2S::QemuAudio { command } => Event::QemuAudio { command },
        })
    }

    /// Send a message to the client.
    pub async fn send<M: ServerMessage>(&mut self, msg: &M) -> Result<()> {
        let mut buffer = Vec::new();
        msg.write_to(&mut buffer)?;
        self.stream.write_all(&buffer).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Shut the communication down in both directions, which also unblocks a
    /// pending [`Session::read_event`].
    pub fn disconnect(&self) -> Result<()> {
        Ok(self.stream.shutdown_transport()?)
    }

    /// Whether this client is on a WebSocket, as the `WebSocket` property of
    /// `org.qemu.Vnc1.Client` reports it.
    pub fn is_websocket(&self) -> bool
    where
        T: WebSocketAware,
    {
        self.stream.is_websocket()
    }

    /// A handle on the socket underneath, to shut the connection down from
    /// another thread.
    pub fn shutdown_handle(&self) -> std::sync::Arc<std::net::TcpStream>
    where
        T: ShutdownHandle,
    {
        self.stream.shutdown_handle()
    }
}

/// A transport that knows whether it carries RFB in a WebSocket.
pub trait WebSocketAware {
    /// Whether this is a WebSocket connection.
    fn is_websocket(&self) -> bool;
}

impl WebSocketAware for crate::rfb::ClientTransport {
    fn is_websocket(&self) -> bool {
        crate::rfb::ClientTransport::is_websocket(self)
    }
}

/// A transport whose socket can be shut down from another thread.
pub trait ShutdownHandle {
    /// A handle on the socket underneath.
    fn shutdown_handle(&self) -> std::sync::Arc<std::net::TcpStream>;
}

impl ShutdownHandle for crate::rfb::ClientTransport {
    fn shutdown_handle(&self) -> std::sync::Arc<std::net::TcpStream> {
        crate::rfb::ClientTransport::shutdown_handle(self)
    }
}

#[cfg(test)]
mod test {
    use super::{FramebufferUpdate, Rect, ServerMessage, Update, ValidationData, protocol};
    use std::io::Cursor;

    /// Checks if `ValidationData` correctly converts bits per pixel from `PixelFormat` to bytes
    /// per pixel.
    #[test]
    fn check_if_validation_data_correctly_rounds_bits_to_bytes() {
        let mut format = protocol::PixelFormat::rgb8888();
        let test_data = vec![(8, 1), (23, 3), (24, 3), (25, 4), (31, 4), (32, 4), (33, 5)];
        for (bits, expected_bytes) in test_data {
            format.bits_per_pixel = bits;
            let data = ValidationData::new(Some(&format));
            assert_eq!(data.bytes_per_pixel, expected_bytes);
        }
    }

    /// Checks if `Update::Raw` accepts valid data both in case of very small and big buffer which
    /// could cause `u16` overflow.
    #[test]
    fn check_if_raw_update_accepts_valid_data() {
        let data = vec![0; 4 * 800 * 100];
        let pixel_format = protocol::PixelFormat::rgb8888();
        let validation_data = ValidationData::new(Some(&pixel_format));

        // Small rectangle
        Update::Raw {
            rect: Rect::new(0, 0, 8, 8),
            pixel_data: &data[0..(4 * 8 * 8)],
        }
        .check(&validation_data);

        // Big rectangle (bigger than `u16::MAX`)
        Update::Raw {
            rect: Rect::new(0, 0, 800, 100),
            pixel_data: &data,
        }
        .check(&validation_data);
    }

    /// Checks if `Update::Raw` rejects data with invalid length.
    #[test]
    #[should_panic]
    fn check_if_raw_update_rejects_invalid_data() {
        let data = vec![0; 5];
        let pixel_format = protocol::PixelFormat::rgb8888();
        let validation_data = ValidationData::new(Some(&pixel_format));

        Update::Raw {
            rect: Rect::new(0, 0, 8, 8),
            pixel_data: &data,
        }
        .check(&validation_data);
    }

    /// Checks if `Update::SetCursor` accepts valid data both in case of very small and big buffer
    /// which could cause `u16` overflow.
    #[test]
    fn check_if_set_cursor_update_accepts_valid_data() {
        let data = vec![0; 4 * 800 * 100];
        let pixel_format = protocol::PixelFormat::rgb8888();
        let validation_data = ValidationData::new(Some(&pixel_format));

        // Small rectangle
        Update::SetCursor {
            size: (8, 8),
            hotspot: (0, 0),
            pixels: &data[0..(4 * 8 * 8)],
            mask_bits: &data[0..8],
        }
        .check(&validation_data);

        // Big rectangle (bigger than `u16::MAX`)
        Update::SetCursor {
            size: (800, 100),
            hotspot: (0, 0),
            pixels: &data,
            mask_bits: &data[0..10000],
        }
        .check(&validation_data);
    }

    /// Checks if `Update::SetCursor` rejects data with invalid pixel length.
    #[test]
    #[should_panic]
    fn check_if_set_cursor_update_rejects_invalid_pixel_data() {
        let data = vec![0; 15];
        let pixel_format = protocol::PixelFormat::rgb8888();
        let validation_data = ValidationData::new(Some(&pixel_format));

        Update::SetCursor {
            size: (8, 8),
            hotspot: (0, 0),
            pixels: &data,
            mask_bits: &data[0..8],
        }
        .check(&validation_data);
    }

    /// Checks if `Update::SetCursor` rejects data with invalid bit mask length.
    #[test]
    #[should_panic]
    fn check_if_set_cursor_update_rejects_invalid_bit_mask_data() {
        let data = vec![0; 16];
        let pixel_format = protocol::PixelFormat::rgb8888();
        let validation_data = ValidationData::new(Some(&pixel_format));

        Update::SetCursor {
            size: (8, 8),
            hotspot: (0, 0),
            pixels: &data,
            mask_bits: &data[0..7],
        }
        .check(&validation_data);
    }

    #[test]
    fn framebuffer_update() {
        let mut fbu = FramebufferUpdate::new(Some(&protocol::PixelFormat::rgb8888()));
        let pixel_data = vec![0; 8 * 8 * 4];
        let rect = Rect {
            left: 0,
            top: 0,
            width: 8,
            height: 8,
        };
        fbu.add_raw_pixels(rect, &pixel_data);
        fbu.add_raw_pixels(rect, &pixel_data);
        let mut buff = Cursor::new(Vec::new());
        fbu.write_to(&mut buff).unwrap();
        let buff = buff.into_inner();
        assert_eq!(buff.len(), 540);
    }
}
