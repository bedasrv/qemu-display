//! RFB audio, the pseudo-encoding QEMU serves it as.
//!
//! Audio is not a frame buffer and not a separate connection: the client asks
//! for the `Audio` pseudo-encoding, the server acknowledges it in a frame
//! buffer update that carries the encoding and no pixels, and the samples then
//! travel as QEMU's own extended messages. The numbers are from `ui/vnc.h` and
//! the exchanges from `ui/vnc.c`.
//!
//! # What the client sends
//!
//! - `SetEncodings` with `VNC_ENCODING_AUDIO`, which is -259.
//! - `255, 1, 0` — enable. `255, 1, 1` — disable.
//! - `255, 1, 2, u8 format, u8 channels, u32 frequency` — the format it wants.
//!   The format is 0 for U8, 1 for S8, 2 for U16, 3 for S16, 4 for U32 and 5
//!   for S32; the channels are 1 or 2; and a frequency above 48 kHz is refused,
//!   as QEMU refuses it, because it is a sane bound rather than a protocol one.
//!
//! # What the server sends
//!
//! - The acknowledgement: one rectangle, the audio encoding, no pixels.
//! - `255, 1, 1` when the capture starts and `255, 1, 0` when it stops.
//! - `255, 1, 2, u32 length`, then that many bytes of samples.

use std::fmt;

/// The `Audio` pseudo-encoding, as `VNC_ENCODING_AUDIO`.
pub const AUDIO_ENCODING: i32 = -259;

/// The QEMU extended message, as `VNC_MSG_CLIENT_QEMU` and
/// `VNC_MSG_SERVER_QEMU`.
const QEMU: u8 = 255;

/// The audio sub-message, as `VNC_MSG_CLIENT_QEMU_AUDIO`.
const AUDIO: u8 = 1;

/// A client asked for the samples to start.
pub const ENABLE: u16 = 0;
/// A client asked for them to stop.
pub const DISABLE: u16 = 1;
/// A client told us the format it wants.
pub const SET_FORMAT: u16 = 2;

/// The capture has stopped, as `VNC_MSG_SERVER_QEMU_AUDIO_END`.
pub const END: u16 = 0;
/// The capture has started, as `VNC_MSG_SERVER_QEMU_AUDIO_BEGIN`.
pub const BEGIN: u16 = 1;
/// A block of samples, as `VNC_MSG_SERVER_QEMU_AUDIO_DATA`.
pub const DATA: u16 = 2;

/// A frequency above this is refused.
///
/// QEMU's comment on its own limit is the one to keep: the protocol has no
/// limit, 48 kHz is a sensible bound for a client worth trusting, and the
/// number is used in arithmetic later, so it has to be bounded.
pub const MAX_FREQUENCY: u32 = 48_000;

/// What one sample is, as the client's format byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sample {
    /// Unsigned 8 bit.
    U8,
    /// Signed 8 bit.
    S8,
    /// Unsigned 16 bit.
    U16,
    /// Signed 16 bit.
    S16,
    /// Unsigned 32 bit.
    U32,
    /// Signed 32 bit.
    S32,
}

impl Sample {
    /// The byte the client uses for this format.
    pub fn code(&self) -> u8 {
        match self {
            Sample::U8 => 0,
            Sample::S8 => 1,
            Sample::U16 => 2,
            Sample::S16 => 3,
            Sample::U32 => 4,
            Sample::S32 => 5,
        }
    }

    /// The format a client asked for, if it is one we know.
    pub fn from_code(code: u8) -> Option<Sample> {
        match code {
            0 => Some(Sample::U8),
            1 => Some(Sample::S8),
            2 => Some(Sample::U16),
            3 => Some(Sample::S16),
            4 => Some(Sample::U32),
            5 => Some(Sample::S32),
            _ => None,
        }
    }

    /// How many bytes one sample of this format is.
    pub fn width(&self) -> usize {
        match self {
            Sample::U8 | Sample::S8 => 1,
            Sample::U16 | Sample::S16 => 2,
            Sample::U32 | Sample::S32 => 4,
        }
    }

    /// Whether the samples are signed, which is what a conversion depends on.
    pub fn is_signed(&self) -> bool {
        matches!(self, Sample::S8 | Sample::S16 | Sample::S32)
    }
}

/// The audio a client wants, or a client has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    /// What one sample is.
    pub sample: Sample,
    /// How many samples make a frame, 1 or 2.
    pub channels: u8,
    /// How many frames a second.
    pub frequency: u32,
    /// Which way round the samples are.
    ///
    /// **RFB's `SetFormat` has no such field, and that is not an oversight in
    /// this port.** QEMU's own VNC server writes the audio backend's native
    /// samples straight out, so a client on a little-endian machine is being sent
    /// little-endian and learns nothing about it -- there is no way to ask. The
    /// byte order is therefore a property of the *stream*, learned from the VM in
    /// `Init`, and it has to travel with the samples: the conversion pipeline
    /// works big-endian, and the integer path round-trips bytes so it was
    /// accidentally right without ever knowing the order. A float stream has to
    /// decode, so it cannot rely on that accident.
    pub be: bool,
}

impl Default for Format {
    /// What QEMU falls back to: signed 16 bit stereo at 44.1 kHz.
    fn default() -> Self {
        Self {
            sample: Sample::S16,
            channels: 2,
            frequency: 44_100,
            be: false,
        }
    }
}

impl Format {
    /// How many bytes one frame of this format is.
    pub fn frame_size(&self) -> usize {
        self.sample.width() * self.channels as usize
    }

    /// Whether `format` is one a client may ask for.
    ///
    /// The channels are 1 or 2, as QEMU insists: more is not something a
    /// viewer plays, and the frequency has the bound above.
    pub fn is_acceptable(&self) -> bool {
        matches!(self.channels, 1 | 2) && self.frequency <= MAX_FREQUENCY && self.frequency > 0
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.sample.is_signed() { 'S' } else { 'U' };
        write!(
            f,
            "{sign}{}Hz/{sign}{}ch",
            self.sample.width() * 8,
            self.channels
        )
    }
}

/// What a client asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// Start the samples.
    Enable,
    /// Stop the samples.
    Disable,
    /// The format the client wants from now on.
    SetFormat(Format),
}

impl Command {
    /// The sub-message a client sent, and the format it carried.
    pub fn parse(sub: u16, payload: &[u8]) -> Result<Command, Error> {
        match sub {
            ENABLE => Ok(Command::Enable),
            DISABLE => Ok(Command::Disable),
            SET_FORMAT => {
                let head = payload
                    .get(..6)
                    .ok_or(Error::Malformed("the audio format is too short"))?;
                let sample =
                    Sample::from_code(head[0]).ok_or(Error::Malformed("unknown audio format"))?;
                let format = Format {
                    sample,
                    channels: head[1],
                    frequency: u32::from_be_bytes([head[2], head[3], head[4], head[5]]),
                be: false,
                };
                if !format.is_acceptable() {
                    return Err(Error::Malformed("an audio format we can not play"));
                }
                Ok(Command::SetFormat(format))
            }
            _ => Err(Error::Malformed("unknown audio sub-message")),
        }
    }
}

/// How far an audio exchange got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A message was not shaped the way the protocol says.
    Malformed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "malformed audio message: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// The bytes of one `255, 1, sub, ...` message, without the first two.
pub fn payload(sub: u16) -> [u8; 2] {
    sub.to_be_bytes()
}

/// A message the server sends, without the `255, 1` that starts every one.
pub fn server_message(sub: u16) -> Vec<u8> {
    let mut bytes = vec![QEMU, AUDIO];
    bytes.extend_from_slice(&sub.to_be_bytes());
    bytes
}

/// A block of samples, as the server sends it.
pub fn data(samples: &[u8]) -> Vec<u8> {
    let mut bytes = server_message(DATA);
    bytes.extend_from_slice(&(samples.len() as u32).to_be_bytes());
    bytes.extend_from_slice(samples);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sample_formats_are_the_ones_qemu_accepts() {
        // The six codes, in the order `ui/vnc.c` lists them.
        let expected = [
            (0, Sample::U8, 1),
            (1, Sample::S8, 1),
            (2, Sample::U16, 2),
            (3, Sample::S16, 2),
            (4, Sample::U32, 4),
            (5, Sample::S32, 4),
        ];
        for (code, sample, width) in expected {
            assert_eq!(Sample::from_code(code), Some(sample));
            assert_eq!(sample.code(), code);
            assert_eq!(sample.width(), width);
        }
        assert_eq!(Sample::from_code(6), None);
    }

    #[test]
    fn the_signedness_is_what_a_conversion_needs() {
        assert!(!Sample::U16.is_signed());
        assert!(Sample::S16.is_signed());
    }

    #[test]
    fn a_format_of_one_and_two_channels_is_acceptable() {
        for channels in [1, 2] {
            let format = Format {
                channels,
                ..Format::default()
            };
            assert!(format.is_acceptable(), "{format} should be acceptable");
            assert_eq!(format.frame_size(), 2 * channels as usize);
        }
    }

    #[test]
    fn a_format_we_can_not_play_is_refused() {
        // Too many channels, and the frequency bound QEMU puts on a client.
        for format in [
            Format {
                channels: 3,
                ..Format::default()
            },
            Format {
                channels: 0,
                ..Format::default()
            },
            Format {
                frequency: MAX_FREQUENCY + 1,
                ..Format::default()
            },
            Format {
                frequency: 0,
                ..Format::default()
            },
        ] {
            assert!(!format.is_acceptable(), "{format} should be refused");
        }
    }

    #[test]
    fn the_commands_are_read_as_qemu_frames_them() {
        assert_eq!(Command::parse(ENABLE, &[]), Ok(Command::Enable));
        assert_eq!(Command::parse(DISABLE, &[]), Ok(Command::Disable));
        // format 3 (S16), 2 channels, 44100 Hz, which is 0x0000AC44.
        let payload = [3u8, 2, 0x00, 0x00, 0xAC, 0x44];
        assert_eq!(
            Command::parse(SET_FORMAT, &payload),
            Ok(Command::SetFormat(Format {
                sample: Sample::S16,
                channels: 2,
                frequency: 44_100,
            be: false,
            }))
        );
    }

    #[test]
    fn a_malformed_audio_message_is_refused() {
        // A format byte we do not know.
        assert!(matches!(
            Command::parse(SET_FORMAT, &[9, 2, 0, 0xAC, 0x44, 0]),
            Err(Error::Malformed(_))
        ));
        // A format that is too short to hold.
        assert!(matches!(
            Command::parse(SET_FORMAT, &[3, 2]),
            Err(Error::Malformed(_))
        ));
        // A sub-message we do not implement.
        assert!(matches!(Command::parse(7, &[]), Err(Error::Malformed(_))));
    }

    #[test]
    fn the_server_messages_are_the_ones_qemu_reads() {
        assert_eq!(server_message(END), vec![255, 1, 0, 0]);
        assert_eq!(server_message(BEGIN), vec![255, 1, 0, 1]);
        assert_eq!(data(&[1, 2, 3]), vec![255, 1, 0, 2, 0, 0, 0, 3, 1, 2, 3]);
        assert_eq!(payload(ENABLE), [0, 0]);
    }

    #[test]
    fn the_encoding_is_the_one_qemu_acks() {
        assert_eq!(AUDIO_ENCODING, -259);
    }
}
