// Vendored from elmarco/rust-vnc, see `mod.rs` for the provenance.
// Upstream is mostly undocumented and carries some client-only code: keep it
// that way, and document the parts we change.
#![allow(missing_docs, dead_code, clippy::all)]

use super::audio;
use super::{Error, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::{
    convert::TryInto,
    io::{ErrorKind as IoErrorKind, Read, Write},
};

pub trait Message {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>
    where
        Self: Sized;
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()>;
}

impl Message for Vec<u8> {
    fn read_from<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
        let length = reader.read_u32::<BigEndian>()?;
        let mut buffer = vec![0; length as usize];
        reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let length = self.len() as u32; // TODO: check?
        writer.write_u32::<BigEndian>(length)?;
        writer.write_all(&self)?;
        Ok(())
    }
}

/* All strings in VNC are either ASCII or Latin-1, both of which
are embedded in Unicode. */
impl Message for String {
    fn read_from<R: Read>(reader: &mut R) -> Result<String> {
        let length = reader.read_u32::<BigEndian>()?;
        let mut string = vec![0; length as usize];
        reader.read_exact(&mut string)?;
        Ok(string.iter().map(|c| *c as char).collect())
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let length = self.len() as u32; // TODO: check?
        writer.write_u32::<BigEndian>(length)?;
        writer.write_all(&self.chars().map(|c| c as u8).collect::<Vec<u8>>())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Rfb33,
    Rfb37,
    Rfb38,
}

impl Message for Version {
    fn read_from<R: Read>(reader: &mut R) -> Result<Version> {
        let mut buf = [0; 12];
        reader.read_exact(&mut buf)?;
        match &buf {
            b"RFB 003.003\n" => Ok(Version::Rfb33),
            b"RFB 003.007\n" => Ok(Version::Rfb37),
            b"RFB 003.008\n" => Ok(Version::Rfb38),
            // Apple remote desktop
            b"RFB 003.889\n" => Ok(Version::Rfb38),
            _ => Err(Error::Unexpected("protocol version")),
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Version::Rfb33 => writer.write_all(b"RFB 003.003\n"),
            Version::Rfb37 => writer.write_all(b"RFB 003.007\n"),
            Version::Rfb38 => writer.write_all(b"RFB 003.008\n"),
        }?;
        Ok(())
    }
}

/// The security type a session offers and the client picks.
///
/// Ours, not upstream: the vendored crate only knew `None` and the VNC
/// password, and the numbers come from QEMU's `ui/vnc.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityType {
    Unknown(u8),
    // core spec
    Invalid,
    None,
    VncAuthentication,
    // extensions
    /// SASL, which is a whole sub-protocol rather than a challenge.
    Sasl,
    AppleRemoteDesktop,
}

impl Message for SecurityType {
    fn read_from<R: Read>(reader: &mut R) -> Result<SecurityType> {
        let security_type = reader.read_u8()?;
        match security_type {
            0 => Ok(SecurityType::Invalid),
            1 => Ok(SecurityType::None),
            2 => Ok(SecurityType::VncAuthentication),
            20 => Ok(SecurityType::Sasl),
            30 => Ok(SecurityType::AppleRemoteDesktop),
            n => Ok(SecurityType::Unknown(n)),
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let security_type = match self {
            SecurityType::Invalid => 0,
            SecurityType::None => 1,
            SecurityType::VncAuthentication => 2,
            SecurityType::Sasl => 20,
            SecurityType::AppleRemoteDesktop => 30,
            SecurityType::Unknown(n) => *n,
        };
        writer.write_u8(security_type)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SecurityTypes(pub Vec<SecurityType>);

impl Message for SecurityTypes {
    fn read_from<R: Read>(reader: &mut R) -> Result<SecurityTypes> {
        let count = reader.read_u8()?;
        let mut security_types = Vec::new();
        for _ in 0..count {
            security_types.push(SecurityType::read_from(reader)?)
        }
        Ok(SecurityTypes(security_types))
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let count = self.0.len() as u8; // TODO: check?
        writer.write_u8(count)?;
        for security_type in &self.0 {
            security_type.write_to(writer)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityResult {
    Succeeded,
    Failed,
}

impl Message for SecurityResult {
    fn read_from<R: Read>(reader: &mut R) -> Result<SecurityResult> {
        let result = reader.read_u32::<BigEndian>()?;
        match result {
            0 => Ok(SecurityResult::Succeeded),
            1 => Ok(SecurityResult::Failed),
            _ => Err(Error::Unexpected("security result")),
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let result = match self {
            SecurityResult::Succeeded => 0,
            SecurityResult::Failed => 1,
        };
        writer.write_u32::<BigEndian>(result)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct AppleAuthHandshake {
    pub generator: u16,
    pub prime: Vec<u8>,
    pub peer_key: Vec<u8>,
}

impl Message for AppleAuthHandshake {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let generator = reader.read_u16::<BigEndian>()?;
        let key_length = reader.read_u16::<BigEndian>()?;

        let mut prime = vec![0; key_length as usize];
        reader.read_exact(&mut prime)?;

        let mut peer_key = vec![0; key_length as usize];
        reader.read_exact(&mut peer_key)?;

        Ok(AppleAuthHandshake {
            generator,
            prime,
            peer_key,
        })
    }

    fn write_to<W: Write>(&self, _writer: &mut W) -> Result<()> {
        unreachable!()
    }
}

#[allow(dead_code)]
pub struct AppleAuthResponse {
    pub ciphertext: [u8; 128],
    pub pub_key: Vec<u8>,
}

impl Message for AppleAuthResponse {
    fn read_from<R: Read>(_reader: &mut R) -> Result<Self> {
        unreachable!()
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.ciphertext)?;
        writer.write_all(&self.pub_key)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ClientInit {
    pub shared: bool,
}

impl Message for ClientInit {
    fn read_from<R: Read>(reader: &mut R) -> Result<ClientInit> {
        Ok(ClientInit {
            shared: reader.read_u8()? != 0,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(if self.shared { 1 } else { 0 })?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelFormat {
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl Message for PixelFormat {
    fn read_from<R: Read>(reader: &mut R) -> Result<PixelFormat> {
        let pixel_format = PixelFormat {
            bits_per_pixel: reader.read_u8()?,
            depth: reader.read_u8()?,
            big_endian: reader.read_u8()? != 0,
            true_colour: reader.read_u8()? != 0,
            red_max: reader.read_u16::<BigEndian>()?,
            green_max: reader.read_u16::<BigEndian>()?,
            blue_max: reader.read_u16::<BigEndian>()?,
            red_shift: reader.read_u8()?,
            green_shift: reader.read_u8()?,
            blue_shift: reader.read_u8()?,
        };
        reader.read_exact(&mut [0u8; 3])?;
        Ok(pixel_format)
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(self.bits_per_pixel)?;
        writer.write_u8(self.depth)?;
        writer.write_u8(if self.big_endian { 1 } else { 0 })?;
        writer.write_u8(if self.true_colour { 1 } else { 0 })?;
        writer.write_u16::<BigEndian>(self.red_max)?;
        writer.write_u16::<BigEndian>(self.green_max)?;
        writer.write_u16::<BigEndian>(self.blue_max)?;
        writer.write_u8(self.red_shift)?;
        writer.write_u8(self.green_shift)?;
        writer.write_u8(self.blue_shift)?;
        writer.write_all(&[0u8; 3])?;
        Ok(())
    }
}

impl PixelFormat {
    /// Creates RGB pixel format with 4 bytes per pixel and 3 bytes of depth.
    pub fn rgb8888() -> Self {
        Self {
            bits_per_pixel: 32,
            depth: 24,
            big_endian: true,
            true_colour: true,
            red_max: 255,
            green_max: 255,
            blue_max: 255,
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
        }
    }
}

#[derive(Debug)]
pub struct ServerInit {
    pub framebuffer_width: u16,
    pub framebuffer_height: u16,
    pub pixel_format: PixelFormat,
    pub name: String,
}

impl Message for ServerInit {
    fn read_from<R: Read>(reader: &mut R) -> Result<ServerInit> {
        Ok(ServerInit {
            framebuffer_width: reader.read_u16::<BigEndian>()?,
            framebuffer_height: reader.read_u16::<BigEndian>()?,
            pixel_format: PixelFormat::read_from(reader)?,
            name: String::read_from(reader)?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(self.framebuffer_width)?;
        writer.write_u16::<BigEndian>(self.framebuffer_height)?;
        PixelFormat::write_to(&self.pixel_format, writer)?;
        String::write_to(&self.name, writer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct CopyRect {
    pub src_x_position: u16,
    pub src_y_position: u16,
}

impl Message for CopyRect {
    fn read_from<R: Read>(reader: &mut R) -> Result<CopyRect> {
        Ok(CopyRect {
            src_x_position: reader.read_u16::<BigEndian>()?,
            src_y_position: reader.read_u16::<BigEndian>()?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(self.src_x_position)?;
        writer.write_u16::<BigEndian>(self.src_y_position)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    Unknown(i32),
    // core spec
    Raw,
    CopyRect,
    Rre,
    CoRre,
    Hextile,
    Zlib,
    Tight,
    ZlibHex,
    Zrle,
    Jpeg(i32),
    DesktopSize,
    LastRect,
    PointerPosition,
    RichCursor,
    XCursor,
    /// The -256 pseudo-encoding, carrying a zlib compression level from 0 (no
    /// compression) to 9. The *level* is held, not the encoding number it
    /// arrives as, because the two differ by 256 and reading one as the other
    /// is silent.
    CompressionLevel(u8),
    PointerMotion,
    ExtendedKeyEvent,
    Audio,
    TightPng,
    Led,
    Gii,
    DesktopName,
    ExtendedDesktopSize,
    Xvp,
    Fence,
    ContinuousUpdate,
    CursorWithAlpha,
    JpegFineGrained(i32),
    JpegSubSampling(i32),
    VmwareCursor,
    VmwareCursorState,
    VmwareCursorPosition,
    VmwareKeyRepeat,
    VmwareLed,
    VmwareDisplayMode,
    VmwareVMState,
    ExtendedClipboard,
}

impl Encoding {
    /// The pseudo-encodings a server may acknowledge with a *bare* rectangle.
    ///
    /// A pseudo-rectangle is a rectangle in a `FramebufferUpdate` that reports
    /// a capability rather than carrying pixels, and the tempting reading —
    /// that "pseudo" means "no payload" — is wrong for most of them. Several
    /// are followed by a payload of their own, and a client reads that payload
    /// whether or not the server wrote it. Sending one bare does not merely
    /// lose a rectangle: the client consumes the *next* rectangle's header as
    /// the missing bytes, and from that point on it is decoding a stream that
    /// no longer exists. Meeting an encoding it has no decoder for, it then
    /// drops the connection, having drawn nothing.
    ///
    /// So the set is not "the pseudo-encodings" but the payload-free ones, and
    /// it is short. QEMU's `vnc.c` is the reference, and it acknowledges
    /// exactly two:
    ///
    ///   * `ExtendedKeyEvent` (-258), in `send_ext_key_event_ack()`, which
    ///     writes the rectangle and stops.
    ///   * `Audio` (-259), in `send_ext_audio_ack()`, likewise.
    ///
    /// The ones that are easy to get wrong, and are not here:
    ///
    /// | encoding          | what follows the rectangle                       |
    /// |-------------------|--------------------------------------------------|
    /// | ExtendedDesktopSize (-308) | a screen count and a 16-byte screen description |
    /// | Led (-261)        | one byte of LED state                             |
    /// | Fence (-312)      | a length, a flag, and the fence's bytes            |
    /// | DesktopName (-307)| a length and the name                             |
    ///
    /// `ExtendedDesktopSize` is the one that bites, because a client that
    /// supports desktop resizing announces it routinely, and the reply to
    /// `SetDesktopSize` is the only place it belongs: QEMU's
    /// `vnc_desktop_resize_ext()` writes all twenty of its payload bytes there.
    pub const ACKNOWLEDGED: &'static [Encoding] =
        &[Encoding::ExtendedKeyEvent, Encoding::Audio];

    /// Whether a bare rectangle is a valid acknowledgement of this encoding.
    ///
    /// The one predicate behind [`Encoding::ACKNOWLEDGED`], so that a test can
    /// walk every encoding the server can send and check the property against
    /// the list rather than against a second hand-written copy of it.
    pub fn is_payload_free(&self) -> bool {
        Self::ACKNOWLEDGED.contains(self)
    }

    /// The number this encoding travels as, as `write_to` sends it.
    ///
    /// The specification's numbering, with no wire involved. It is here
    /// because a conformance argument has to be checkable: "encoding -308" is
    /// a claim about the protocol, and a test that wants to assert the claim
    /// against a table of what each number means has to be able to ask what
    /// number a variant is, without writing a message and reading it back.
    pub fn number(self) -> i32 {
        // The same table `write_to` uses, reached by asking it to encode into
        // a buffer and reading the four bytes. One table, not two: a second
        // hand-kept copy of the numbering is a second thing to get wrong.
        let mut buf: Vec<u8> = Vec::new();
        self.write_to(&mut buf).expect("an encoding is four bytes");
        let bytes: [u8; 4] = buf[..4].try_into().expect("an encoding is four bytes");
        i32::from_be_bytes(bytes)
    }
}

impl Encoding {
    /// Parse one encoding number as `SetEncodings` carries it.
    ///
    /// Public because the preference rule is about *which* numbers mean which
    /// encodings, and a test of that rule has to go through this parser rather
    /// than a hand-written list: a hand-written one would test the list.
    pub fn from_wire(encoding: i32) -> Option<Encoding> {
        let mut bytes = encoding.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        Message::read_from(&mut bytes.as_slice()).ok()
    }
}

impl Message for Encoding {
    fn read_from<R: Read>(reader: &mut R) -> Result<Encoding> {
        let encoding = reader.read_i32::<BigEndian>()?;
        match encoding {
            0 => Ok(Encoding::Raw),
            1 => Ok(Encoding::CopyRect),
            2 => Ok(Encoding::Rre),
            4 => Ok(Encoding::CoRre),
            5 => Ok(Encoding::Hextile),
            6 => Ok(Encoding::Zlib),
            7 => Ok(Encoding::Tight),
            8 => Ok(Encoding::ZlibHex),
            16 => Ok(Encoding::Zrle),
            -32..=-23 => Ok(Encoding::Jpeg(encoding)),
            -223 => Ok(Encoding::DesktopSize),
            -224 => Ok(Encoding::LastRect),
            -232 => Ok(Encoding::PointerPosition),
            -239 => Ok(Encoding::RichCursor),
            -240 => Ok(Encoding::XCursor),
            -256..=-247 => Ok(Encoding::CompressionLevel((encoding + 256) as u8)),
            -257 => Ok(Encoding::PointerMotion),
            -258 => Ok(Encoding::ExtendedKeyEvent),
            -259 => Ok(Encoding::Audio),
            -260 => Ok(Encoding::TightPng),
            -261 => Ok(Encoding::Led),
            -305 => Ok(Encoding::Gii),
            -307 => Ok(Encoding::DesktopName),
            -308 => Ok(Encoding::ExtendedDesktopSize),
            -309 => Ok(Encoding::Xvp),
            -312 => Ok(Encoding::Fence),
            -313 => Ok(Encoding::ContinuousUpdate),
            -314 => Ok(Encoding::CursorWithAlpha),
            -512..=-412 => Ok(Encoding::JpegFineGrained(encoding)),
            -768..=-763 => Ok(Encoding::JpegSubSampling(encoding)),
            0x574d5664 => Ok(Encoding::VmwareCursor),
            0x574d5665 => Ok(Encoding::VmwareCursorState),
            0x574d5666 => Ok(Encoding::VmwareCursorPosition),
            0x574d5667 => Ok(Encoding::VmwareKeyRepeat),
            0x574d5668 => Ok(Encoding::VmwareLed),
            0x574d5669 => Ok(Encoding::VmwareDisplayMode),
            0x574d566a => Ok(Encoding::VmwareVMState),
            -1063131698 => Ok(Encoding::ExtendedClipboard), // 0xc0a1e5ce
            n => Ok(Encoding::Unknown(n)),
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let encoding = match self {
            Encoding::Raw => 0,
            Encoding::CopyRect => 1,
            Encoding::Rre => 2,
            Encoding::CoRre => 4,
            Encoding::Hextile => 5,
            Encoding::Zlib => 6,
            Encoding::Tight => 7,
            Encoding::ZlibHex => 8,
            Encoding::Zrle => 16,
            Encoding::Jpeg(n) => *n,
            Encoding::DesktopSize => -223,
            Encoding::LastRect => -224,
            Encoding::PointerPosition => -232,
            Encoding::RichCursor => -239,
            Encoding::PointerMotion => -257,
            Encoding::ExtendedKeyEvent => -258,
            Encoding::Audio => -259,
            Encoding::TightPng => -260,
            Encoding::Led => -261,
            Encoding::XCursor => -240,
            Encoding::CompressionLevel(n) => -256 + i32::from(*n),
            Encoding::Gii => -305,
            Encoding::DesktopName => -307,
            Encoding::ExtendedDesktopSize => -308,
            Encoding::Xvp => -309,
            Encoding::Fence => -312,
            Encoding::ContinuousUpdate => -313,
            Encoding::CursorWithAlpha => -314,
            Encoding::JpegFineGrained(n) => *n,
            Encoding::JpegSubSampling(n) => *n,
            Encoding::VmwareCursor => 0x574d5664,
            Encoding::VmwareCursorState => 0x574d5665,
            Encoding::VmwareCursorPosition => 0x574d5666,
            Encoding::VmwareKeyRepeat => 0x574d5667,
            Encoding::VmwareLed => 0x574d5668,
            Encoding::VmwareDisplayMode => 0x574d5669,
            Encoding::VmwareVMState => 0x574d566a,
            Encoding::ExtendedClipboard => -1063131698, // 0xc0a1e5ce
            Encoding::Unknown(n) => *n,
        };
        writer.write_i32::<BigEndian>(encoding)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum C2S {
    // core spec
    SetPixelFormat(PixelFormat),
    SetEncodings(Vec<Encoding>),
    FramebufferUpdateRequest {
        incremental: bool,
        x_position: u16,
        y_position: u16,
        width: u16,
        height: u16,
    },
    KeyEvent {
        down: bool,
        key: u32,
    },
    PointerEvent {
        button_mask: u8,
        x_position: u16,
        y_position: u16,
    },
    CutText(String),
    SetDesktopSize {
        width: u16,
        height: u16,
        screens: Vec<Screen>,
    },
    // extensions
    /// A QEMU extended message: `255`, a sub-message, and what it carries.
    ///
    /// Ours, not upstream: the vendored parser stopped at the core messages,
    /// and the audio exchange lives in one of these. The length of each is
    /// fixed by the protocol, which is why the payload is read here rather
    /// than left to the consumer: there is no length field to read.
    QemuAudio {
        /// What the client asked for.
        command: audio::Command,
    },
    ExtendedKeyEvent {
        down: bool,
        keysym: u32,
        keycode: u32,
    },
}

impl Message for C2S {
    fn read_from<R: Read>(reader: &mut R) -> Result<C2S> {
        let message_type = match reader.read_u8() {
            Err(ref e) if e.kind() == IoErrorKind::UnexpectedEof => {
                return Err(Error::Disconnected);
            }
            result => result?,
        };
        match message_type {
            0 => {
                reader.read_exact(&mut [0u8; 3])?;
                Ok(C2S::SetPixelFormat(PixelFormat::read_from(reader)?))
            }
            2 => {
                reader.read_exact(&mut [0u8; 1])?;
                let count = reader.read_u16::<BigEndian>()?;
                let mut encodings = Vec::new();
                for _ in 0..count {
                    encodings.push(Encoding::read_from(reader)?);
                }
                // What was read, as read: the count and the numbers, before any
                // filtering and before the policy chooses an encoding.
                //
                // Added because a reference client asked for ZRLE and this log
                // said it had been sent seven pseudo-encodings instead — which
                // reads exactly like a parser off-by-one, and is not one. The
                // client had dropped ZRLE itself: its libvncclient printed
                // `Unknown encoding 'zrle'` and substituted its own defaults,
                // so the message on the wire never contained 16. The server
                // read it correctly and fell back to raw, which is the right
                // answer to a client that offers nothing else.
                //
                // Worth keeping because the two facts — what the client says it
                // asked for, and what actually arrived — are printed by
                // different programs in different places, and having the server
                // state the second one is what turns the first into evidence
                // rather than a rumour.
                tracing::trace!(
                    count,
                    encodings = ?encodings.iter().map(|e| e.number()).collect::<Vec<_>>(),
                    "set encodings"
                );
                Ok(C2S::SetEncodings(encodings))
            }
            3 => Ok(C2S::FramebufferUpdateRequest {
                incremental: reader.read_u8()? != 0,
                x_position: reader.read_u16::<BigEndian>()?,
                y_position: reader.read_u16::<BigEndian>()?,
                width: reader.read_u16::<BigEndian>()?,
                height: reader.read_u16::<BigEndian>()?,
            }),
            4 => {
                let down = reader.read_u8()? != 0;
                reader.read_exact(&mut [0u8; 2])?;
                let key = reader.read_u32::<BigEndian>()?;
                Ok(C2S::KeyEvent { down, key })
            }
            5 => Ok(C2S::PointerEvent {
                button_mask: reader.read_u8()?,
                x_position: reader.read_u16::<BigEndian>()?,
                y_position: reader.read_u16::<BigEndian>()?,
            }),
            6 => {
                reader.read_exact(&mut [0u8; 3])?;
                Ok(C2S::CutText(String::read_from(reader)?))
            }
            251 => {
                reader.read_exact(&mut [0u8; 1])?;
                let width = reader.read_u16::<BigEndian>()?;
                let height = reader.read_u16::<BigEndian>()?;
                let nscreens = reader.read_u8()?;
                reader.read_exact(&mut [0u8; 1])?;
                let mut screens = Vec::new();
                for _ in 0..nscreens {
                    screens.push(Screen::read_from(reader)?);
                }
                Ok(C2S::SetDesktopSize {
                    width,
                    height,
                    screens,
                })
            }
            255 => {
                // `VNC_MSG_CLIENT_QEMU`, then the sub-message. Ours, not
                // upstream: the vendored parser knew only the extended key
                // event, and the audio exchange is the same message with a
                // different one.
                let submessage_type = reader.read_u8()?;
                match submessage_type {
                    0 => {
                        let down = reader.read_u16::<BigEndian>()? != 0;
                        let keysym = reader.read_u32::<BigEndian>()?;
                        let keycode = reader.read_u32::<BigEndian>()?;
                        Ok(C2S::ExtendedKeyEvent {
                            down,
                            keysym,
                            keycode,
                        })
                    }
                    1 => {
                        // `VNC_MSG_CLIENT_QEMU_AUDIO`. There is no length
                        // field, so each sub-message is a fixed size, and one
                        // whose size we do not know is a message we can not
                        // skip over.
                        let sub = reader.read_u16::<BigEndian>()?;
                        // Owned rather than borrowed from a stack array the
                        // borrow checker can not see outlive the call.
                        let payload = match sub {
                            audio::ENABLE | audio::DISABLE => Vec::new(),
                            audio::SET_FORMAT => {
                                let mut payload = vec![0u8; 6];
                                reader.read_exact(&mut payload)?;
                                payload
                            }
                            _ => return Err(Error::Unexpected("an unknown audio sub-message")),
                        };
                        let command = audio::Command::parse(sub, &payload)
                            .map_err(|_| Error::Unexpected("a malformed audio message"))?;
                        Ok(C2S::QemuAudio { command })
                    }
                    _ => Err(Error::Unexpected("client to server QEMU submessage type")),
                }
            }
            _ => Err(Error::Unexpected("client to server message type")),
        }
    }
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            C2S::SetPixelFormat(pixel_format) => {
                writer.write_u8(0)?;
                writer.write_all(&[0u8; 3])?;
                PixelFormat::write_to(pixel_format, writer)?;
            }
            C2S::SetEncodings(encodings) => {
                writer.write_u8(2)?;
                writer.write_all(&[0u8; 1])?;
                writer.write_u16::<BigEndian>(encodings.len() as u16)?; // TODO: check?
                for encoding in encodings {
                    Encoding::write_to(encoding, writer)?;
                }
            }
            C2S::FramebufferUpdateRequest {
                incremental,
                x_position,
                y_position,
                width,
                height,
            } => {
                writer.write_u8(3)?;
                writer.write_u8(if *incremental { 1 } else { 0 })?;
                writer.write_u16::<BigEndian>(*x_position)?;
                writer.write_u16::<BigEndian>(*y_position)?;
                writer.write_u16::<BigEndian>(*width)?;
                writer.write_u16::<BigEndian>(*height)?;
            }
            C2S::KeyEvent { down, key } => {
                writer.write_u8(4)?;
                writer.write_u8(if *down { 1 } else { 0 })?;
                writer.write_all(&[0u8; 2])?;
                writer.write_u32::<BigEndian>(*key)?;
            }
            C2S::PointerEvent {
                button_mask,
                x_position,
                y_position,
            } => {
                writer.write_u8(5)?;
                writer.write_u8(*button_mask)?;
                writer.write_u16::<BigEndian>(*x_position)?;
                writer.write_u16::<BigEndian>(*y_position)?;
            }
            C2S::CutText(text) => {
                String::write_to(text, writer)?;
            }
            C2S::ExtendedKeyEvent {
                down,
                keysym,
                keycode,
            } => {
                writer.write_u8(255)?;
                writer.write_u8(0)?;
                writer.write_u16::<BigEndian>(if *down { 1 } else { 0 })?;
                writer.write_u32::<BigEndian>(*keysym)?;
                writer.write_u32::<BigEndian>(*keycode)?;
            }
            C2S::SetDesktopSize {
                width,
                height,
                screens,
            } => {
                writer.write_u8(251)?;
                writer.write_u8(0)?;
                writer.write_u16::<BigEndian>(*width)?;
                writer.write_u16::<BigEndian>(*height)?;
                writer.write_u8(screens.len().try_into().unwrap())?;
                for s in screens {
                    s.write_to(writer)?;
                }
            }
            C2S::QemuAudio { command } => {
                // A server never sends this, but the parser has to be able to
                // write what it reads so that a test can drive both ends.
                writer.write_u8(255)?;
                writer.write_u8(1)?;
                match command {
                    audio::Command::Enable => writer.write_u16::<BigEndian>(audio::ENABLE)?,
                    audio::Command::Disable => writer.write_u16::<BigEndian>(audio::DISABLE)?,
                    audio::Command::SetFormat(format) => {
                        writer.write_u16::<BigEndian>(audio::SET_FORMAT)?;
                        writer.write_u8(format.sample.code())?;
                        writer.write_u8(format.channels)?;
                        writer.write_u32::<BigEndian>(format.frequency)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Rectangle {
    pub x_position: u16,
    pub y_position: u16,
    pub width: u16,
    pub height: u16,
    pub encoding: Encoding,
}

impl Message for Rectangle {
    fn read_from<R: Read>(reader: &mut R) -> Result<Rectangle> {
        Ok(Rectangle {
            x_position: reader.read_u16::<BigEndian>()?,
            y_position: reader.read_u16::<BigEndian>()?,
            width: reader.read_u16::<BigEndian>()?,
            height: reader.read_u16::<BigEndian>()?,
            encoding: Encoding::read_from(reader)?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(self.x_position)?;
        writer.write_u16::<BigEndian>(self.y_position)?;
        writer.write_u16::<BigEndian>(self.width)?;
        writer.write_u16::<BigEndian>(self.height)?;
        Encoding::write_to(&self.encoding, writer)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Colour {
    pub red: u16,
    pub green: u16,
    pub blue: u16,
}

impl Message for Colour {
    fn read_from<R: Read>(reader: &mut R) -> Result<Colour> {
        Ok(Colour {
            red: reader.read_u16::<BigEndian>()?,
            green: reader.read_u16::<BigEndian>()?,
            blue: reader.read_u16::<BigEndian>()?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(self.red)?;
        writer.write_u16::<BigEndian>(self.green)?;
        writer.write_u16::<BigEndian>(self.blue)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Screen {
    pub id: u32,
    pub rect: Rect,
    pub flags: u32,
}

impl Message for Screen {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            id: reader.read_u32::<BigEndian>()?,
            rect: Rect::read_from(reader)?,
            flags: reader.read_u32::<BigEndian>()?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u32::<BigEndian>(self.id)?;
        self.rect.write_to(writer)?;
        writer.write_u32::<BigEndian>(self.flags)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum S2C {
    // core spec
    FramebufferUpdate {
        count: u16,
        /* Vec<Rectangle> has to be read out manually */
    },
    SetColourMapEntries {
        first_colour: u16,
        colours: Vec<Colour>,
    },
    Bell,
    CutText(String),
    // extensions
}

impl Message for S2C {
    fn read_from<R: Read>(reader: &mut R) -> Result<S2C> {
        let message_type = match reader.read_u8() {
            Err(ref e) if e.kind() == IoErrorKind::UnexpectedEof => {
                return Err(Error::Disconnected);
            }
            result => result?,
        };
        match message_type {
            0 => {
                reader.read_exact(&mut [0u8; 1])?;
                Ok(S2C::FramebufferUpdate {
                    count: reader.read_u16::<BigEndian>()?,
                })
            }
            1 => {
                reader.read_exact(&mut [0u8; 1])?;
                let first_colour = reader.read_u16::<BigEndian>()?;
                let count = reader.read_u16::<BigEndian>()?;
                let mut colours = Vec::new();
                for _ in 0..count {
                    colours.push(Colour::read_from(reader)?);
                }
                Ok(S2C::SetColourMapEntries {
                    first_colour,
                    colours,
                })
            }
            2 => Ok(S2C::Bell),
            3 => {
                reader.read_exact(&mut [0u8; 3])?;
                Ok(S2C::CutText(String::read_from(reader)?))
            }
            _ => Err(Error::Unexpected("server to client message type")),
        }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            S2C::FramebufferUpdate { count } => {
                writer.write_u8(0)?;
                writer.write_all(&[0u8; 1])?;
                writer.write_u16::<BigEndian>(*count)?;
            }
            S2C::SetColourMapEntries {
                first_colour,
                colours,
            } => {
                writer.write_u8(1)?;
                writer.write_all(&[0u8; 1])?;
                writer.write_u16::<BigEndian>(*first_colour)?;
                for colour in colours {
                    Colour::write_to(colour, writer)?;
                }
            }
            S2C::Bell => {
                writer.write_u8(2)?;
            }
            S2C::CutText(text) => {
                writer.write_u8(3)?;
                writer.write_all(&[0u8; 3])?;
                String::write_to(text, writer)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Rect {
    pub left: u16,
    pub top: u16,
    pub width: u16,
    pub height: u16,
}

impl Rect {
    /// Constructs new `Rect`.
    pub fn new(left: u16, top: u16, width: u16, height: u16) -> Self {
        Self {
            left,
            top,
            width,
            height,
        }
    }

    /// Constructs new zero-sized `Rect` placed at (0, 0).
    pub fn empty() -> Self {
        Self::new(0, 0, 0, 0)
    }

    /// Whether `self` and `other` overlap, or sit flush against each other.
    ///
    /// Adjacency counts as touching, not just overlap, and that is deliberate:
    /// a guest that walks a cursor across the screen in sixteen-pixel steps
    /// reports sixteen rectangles that share an edge, and a client that merged
    /// only on overlap would send all sixteen. A dirty bitmap has no such
    /// question — touching bits are one run — so this is the list standing in
    /// for a bitmap and it has to answer it.
    pub fn touches(&self, other: Rect) -> bool {
        let self_right = u32::from(self.left) + u32::from(self.width);
        let self_bottom = u32::from(self.top) + u32::from(self.height);
        let other_right = u32::from(other.left) + u32::from(other.width);
        let other_bottom = u32::from(other.top) + u32::from(other.height);
        u32::from(self.left) <= other_right
            && u32::from(other.left) <= self_right
            && u32::from(self.top) <= other_bottom
            && u32::from(other.top) <= self_bottom
    }

    /// The smallest rectangle holding both `self` and `other`.
    ///
    /// Ours, not upstream: the clients accumulate the damaged areas of the
    /// console updates this way.
    pub fn union(&self, other: Rect) -> Rect {
        let left = self.left.min(other.left);
        let top = self.top.min(other.top);
        let right = (u32::from(self.left) + u32::from(self.width))
            .max(u32::from(other.left) + u32::from(other.width))
            .min(u32::from(u16::MAX));
        let bottom = (u32::from(self.top) + u32::from(self.height))
            .max(u32::from(other.top) + u32::from(other.height))
            .min(u32::from(u16::MAX));
        Rect::new(
            left,
            top,
            (right - u32::from(left)) as u16,
            (bottom - u32::from(top)) as u16,
        )
    }

    /// The part of `self` that fits in a `width` by `height` surface.
    ///
    /// Ours, not upstream: a client that attached while the console was being
    /// resized must not be sent a rectangle it can not store.
    pub fn clipped(&self, width: u16, height: u16) -> Rect {
        let left = self.left.min(width);
        let top = self.top.min(height);
        let right = (u32::from(self.left) + u32::from(self.width)).min(u32::from(width));
        let bottom = (u32::from(self.top) + u32::from(self.height)).min(u32::from(height));
        Rect::new(
            left,
            top,
            (right - u32::from(left)) as u16,
            (bottom - u32::from(top)) as u16,
        )
    }
}

impl Message for Rect {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        Ok(Self {
            left: reader.read_u16::<BigEndian>()?,
            top: reader.read_u16::<BigEndian>()?,
            width: reader.read_u16::<BigEndian>()?,
            height: reader.read_u16::<BigEndian>()?,
        })
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(self.left)?;
        writer.write_u16::<BigEndian>(self.top)?;
        writer.write_u16::<BigEndian>(self.width)?;
        writer.write_u16::<BigEndian>(self.height)?;
        Ok(())
    }
}
