//! A VT100 text console, rendered into a framebuffer.
//!
//! Port of `console.c`: QEMU's `console-vc.c` needs a `Chardev` backend,
//! which the standalone VNC server does not have, so the C code drives the
//! VT100 emulator directly over the chardev file descriptor. The [`vt100`]
//! crate plays the role of `QemuVT100` here, and [`font8x8`] provides the
//! glyphs, which are drawn into a [`Framebuffer`].

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use async_channel::Sender;
use font8x8::UnicodeFonts;
use image::{Rgba, RgbaImage};
use tracing::debug;

use crate::display::{Framebuffer, FramebufferHandle};

/// The number of columns of a text console.
pub const TEXT_COLS: u32 = 80;
/// The number of rows of a text console.
pub const TEXT_ROWS: u32 = 24;
/// The width of a character cell, in pixels.
pub const TEXT_FONT_WIDTH: u32 = 8;
/// The height of a character cell, in pixels.
pub const TEXT_FONT_HEIGHT: u32 = 16;

/// The pixel width of the console surface.
pub const TEXT_WIDTH: u32 = TEXT_COLS * TEXT_FONT_WIDTH;
/// The pixel height of the console surface.
pub const TEXT_HEIGHT: u32 = TEXT_ROWS * TEXT_FONT_HEIGHT;

/// The character encoding of a chardev, as reported by its `VCEncoding`
/// property.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Encoding {
    /// UTF-8, the default.
    #[default]
    Utf8,
    /// ISO-8859-1, also used for the `local` encoding.
    Latin1,
}

impl Encoding {
    /// Parse a `ChardevVCEncoding` enum value.
    pub fn parse(s: &str) -> Self {
        match s {
            "utf8" => Encoding::Utf8,
            "latin1" | "local" => Encoding::Latin1,
            other => {
                debug!(other, "unsupported chardev encoding, using UTF-8");
                Encoding::Utf8
            }
        }
    }

    /// Encode a character for the guest.
    fn encode(self, c: char, out: &mut Vec<u8>) {
        match self {
            Encoding::Utf8 => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            Encoding::Latin1 => out.push(c as u32 as u8),
        }
    }
}

/// The 16 colors of the default xterm palette.
const PALETTE: [(u8, u8, u8); 16] = [
    (0x00, 0x00, 0x00),
    (0xcd, 0x00, 0x00),
    (0x00, 0xcd, 0x00),
    (0xcd, 0xcd, 0x00),
    (0x00, 0x00, 0xee),
    (0xcd, 0x00, 0xcd),
    (0x00, 0xcd, 0xcd),
    (0xe5, 0xe5, 0xe5),
    (0x7f, 0x7f, 0x7f),
    (0xff, 0x00, 0x00),
    (0x00, 0xff, 0x00),
    (0xff, 0xff, 0x00),
    (0x5c, 0x5c, 0xff),
    (0xff, 0x00, 0xff),
    (0x00, 0xff, 0xff),
    (0xff, 0xff, 0xff),
];

const DEFAULT_FG: (u8, u8, u8) = PALETTE[7];
const DEFAULT_BG: (u8, u8, u8) = PALETTE[0];

/// A RGB color.
type Rgb = (u8, u8, u8);

/// The VT100 emulator and its rendering.
struct Inner {
    parser: vt100::Parser,
    image: RgbaImage,
}

/// A VT100 text console, backed by a chardev.
pub struct TextConsole {
    index: AtomicU32,
    name: String,
    /// Whether the chardev echoes the input, in which case we must not do it
    /// ourselves.
    echo: bool,
    encoding: Encoding,
    out: Sender<Vec<u8>>,
    framebuffer: FramebufferHandle,
    inner: Arc<Mutex<Inner>>,
}

impl Clone for TextConsole {
    fn clone(&self) -> Self {
        Self {
            index: AtomicU32::new(self.index()),
            name: self.name.clone(),
            echo: self.echo,
            encoding: self.encoding,
            out: self.out.clone(),
            framebuffer: self.framebuffer.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl std::fmt::Debug for TextConsole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextConsole")
            .field("name", &self.name)
            .field("echo", &self.echo)
            .field("encoding", &self.encoding)
            .finish_non_exhaustive()
    }
}

impl TextConsole {
    /// Create a text console named `name`, sending the typed characters to
    /// the `out` channel.
    pub fn new(name: String, echo: bool, encoding: Encoding, out: Sender<Vec<u8>>) -> Self {
        let console = Self {
            index: AtomicU32::new(0),
            name,
            echo,
            encoding,
            out,
            framebuffer: FramebufferHandle::new(Framebuffer::new(TEXT_WIDTH, TEXT_HEIGHT)),
            inner: Arc::new(Mutex::new(Inner {
                parser: vt100::Parser::new(TEXT_ROWS as u16, TEXT_COLS as u16, 0),
                image: RgbaImage::new(TEXT_WIDTH, TEXT_HEIGHT),
            })),
        };
        console.refresh();
        console
    }

    /// The display index of this console, as assigned by the server.
    pub fn index(&self) -> u32 {
        self.index.load(Ordering::Relaxed)
    }

    /// The chardev name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The shared framebuffer of this console.
    pub fn framebuffer(&self) -> FramebufferHandle {
        self.framebuffer.clone()
    }

    /// Feed data coming from the guest to the VT100 emulator, and refresh the
    /// framebuffer.
    pub fn process(&self, data: &[u8]) {
        self.inner.lock().unwrap().parser.process(data);
        self.refresh();
    }

    /// Queue data for the guest.
    pub fn write(&self, data: &[u8]) {
        if let Err(e) = self.out.try_send(data.to_vec()) {
            debug!(name = %self.name, "failed to write to the chardev: {e}");
        }
    }

    /// Handle a keysym typed by a VNC client: send the bytes the terminal
    /// expects to the guest, and echo them locally if the chardev does not.
    ///
    /// Returns whether the keysym was handled.
    pub fn keysym(&self, keysym: u32, down: bool) -> bool {
        if !down {
            // We do not implement auto-repeat, only handle key presses.
            return false;
        }
        let Some(data) = keysym_to_bytes(keysym, self.encoding) else {
            return false;
        };
        if !self.echo {
            // The guest will not echo the input, do it ourselves.
            self.process(&data);
        }
        self.write(&data);
        true
    }

    /// Redraw the console surface from the emulator state.
    fn refresh(&self) {
        let mut inner = self.inner.lock().unwrap();
        let Inner { parser, image } = &mut *inner;
        render(parser, image);
        self.framebuffer.update(|fb| fb.draw_image(image, 0, 0));
    }
}

/// Redraw `image` from the state of the terminal emulator.
fn render(parser: &vt100::Parser, image: &mut RgbaImage) {
    let screen = parser.screen();
    // The terminal is never resized, but stay on the safe side.
    let (rows, cols) = screen.size();
    let rows = rows.min(TEXT_ROWS as u16);
    let cols = cols.min(TEXT_COLS as u16);
    let default_fg = color(screen.fgcolor(), DEFAULT_FG);
    let default_bg = color(screen.bgcolor(), DEFAULT_BG);
    let cursor = if screen.hide_cursor() {
        None
    } else {
        Some(screen.cursor_position())
    };

    for row in 0..rows {
        for col in 0..cols {
            let (c, mut fg, mut bg) = match screen.cell(row, col) {
                Some(cell) => (
                    cell.contents().chars().next().unwrap_or(' '),
                    color(cell.fgcolor(), default_fg),
                    color(cell.bgcolor(), default_bg),
                ),
                None => (' ', default_fg, default_bg),
            };
            let is_cursor = cursor == Some((row, col));
            if cell_is_inverse(screen, row, col) || is_cursor {
                std::mem::swap(&mut fg, &mut bg);
            }
            draw_cell(image, row, col, c, fg, bg);
        }
    }
}

fn cell_is_inverse(screen: &vt100::Screen, row: u16, col: u16) -> bool {
    screen.cell(row, col).is_some_and(|c| c.inverse())
}

/// Draw a single character cell.
fn draw_cell(image: &mut RgbaImage, row: u16, col: u16, c: char, fg: Rgb, bg: Rgb) {
    let (x, y) = (col as u32 * TEXT_FONT_WIDTH, row as u32 * TEXT_FONT_HEIGHT);
    let glyph = font8x8::BASIC_FONTS
        .get(c)
        .or_else(|| font8x8::BLOCK_FONTS.get(c));

    for line in 0..TEXT_FONT_HEIGHT {
        // The font is 8x8 while a cell is 8x16, draw every line twice.
        let bits = glyph.map(|g| g[(line / 2) as usize]).unwrap_or(0);
        for column in 0..TEXT_FONT_WIDTH {
            let color = if bits & (1 << column) != 0 { fg } else { bg };
            image.put_pixel(
                x + column,
                y + line,
                Rgba([color.0, color.1, color.2, 0xff]),
            );
        }
    }
}

/// Resolve a [`vt100::Color`] to an RGB value.
fn color(c: vt100::Color, default: Rgb) -> Rgb {
    match c {
        vt100::Color::Default => default,
        vt100::Color::Idx(i) => palette(i),
        vt100::Color::Rgb(r, g, b) => (r, g, b),
    }
}

/// Resolve a palette index, with the usual xterm 256 color cube.
fn palette(index: u8) -> Rgb {
    match index {
        0..=15 => PALETTE[index as usize],
        16..=231 => {
            let i = index - 16;
            const STEPS: [u8; 6] = [0, 95, 135, 175, 215, 255];
            (
                STEPS[(i / 36) as usize],
                STEPS[((i % 36) / 6) as usize],
                STEPS[(i % 6) as usize],
            )
        }
        232..=255 => {
            let v = 8 + (index - 232) * 10;
            (v, v, v)
        }
    }
}

/// Translate an X11 keysym into the bytes a terminal expects.
fn keysym_to_bytes(keysym: u32, encoding: Encoding) -> Option<Vec<u8>> {
    let data = match keysym {
        // Control characters, Ctrl-A to Ctrl-Z, Ctrl-Space and Ctrl-\.
        0x00..=0x1f => vec![keysym as u8],
        // Space and printable ASCII.
        0x20..=0x7e => vec![keysym as u8],
        0xff08 => vec![0x7f],          // BackSpace
        0xff09 => vec![0x09],          // Tab
        0xff0d | 0xff8d => vec![0x0d], // Return, KP_Enter
        0xff1b => vec![0x1b],          // Escape
        0xff50 => b"\x1b[H".to_vec(),  // Home
        0xff51 => b"\x1b[D".to_vec(),  // Left
        0xff52 => b"\x1b[A".to_vec(),  // Up
        0xff53 => b"\x1b[C".to_vec(),  // Right
        0xff54 => b"\x1b[B".to_vec(),  // Down
        0xff55 => b"\x1b[5~".to_vec(), // Page Up
        0xff56 => b"\x1b[6~".to_vec(), // Page Down
        0xff57 => b"\x1b[F".to_vec(),  // End
        0xff63 => b"\x1b[2~".to_vec(), // Insert
        0xffff => b"\x1b[3~".to_vec(), // Delete
        0xffbe..=0xffc1 => vec![0x1b, b'O', 0x50 + (keysym - 0xffbe) as u8], // F1-F4
        0xffc2 => b"\x1b[15~".to_vec(), // F5
        0xffc3 => b"\x1b[17~".to_vec(), // F6
        0xffc4 => b"\x1b[18~".to_vec(), // F7
        0xffc5 => b"\x1b[19~".to_vec(), // F8
        0xffc6 => b"\x1b[20~".to_vec(), // F9
        0xffc7 => b"\x1b[21~".to_vec(), // F10
        0xffc8 => b"\x1b[23~".to_vec(), // F11
        0xffc9 => b"\x1b[24~".to_vec(), // F12
        0xff80 => vec![0x20],          // KP_Space
        0xff89 => vec![0x09],          // KP_Tab
        0xffab => vec![0x2b],          // KP_Add
        0xffad => vec![0x2d],          // KP_Subtract
        0xffae => vec![0x2a],          // KP_Multiply
        0xffaf => vec![0x2f],          // KP_Divide
        0xffaa..=0xffb3 => vec![0x30 + (keysym - 0xffaa) as u8], // KP_0 - KP_9
        // Unicode keysyms, either the direct or the 0x01000000 + codepoint
        // form.
        c => {
            let c = if (0x0100_0000..=0x0110_ffff).contains(&c) {
                c - 0x0100_0000
            } else {
                c
            };
            let c = char::from_u32(c)?;
            if !c.is_ascii() {
                let mut data = Vec::new();
                encoding.encode(c, &mut data);
                return Some(data);
            }
            return None;
        }
    };
    Some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_keys() {
        assert_eq!(keysym_to_bytes(0xff52, Encoding::Utf8).unwrap(), b"\x1b[A");
        assert_eq!(keysym_to_bytes(b'a' as u32, Encoding::Utf8).unwrap(), b"a");
        assert_eq!(keysym_to_bytes(0x01, Encoding::Utf8).unwrap(), vec![1]);
        // Lone surrogates are not characters.
        assert!(keysym_to_bytes(0xd800, Encoding::Utf8).is_none());
    }

    #[test]
    fn unicode_keys() {
        let mut expected = Vec::new();
        Encoding::Utf8.encode('€', &mut expected);
        assert_eq!(keysym_to_bytes(0x20ac, Encoding::Utf8).unwrap(), expected);
        assert_eq!(
            keysym_to_bytes(0x0100_20ac, Encoding::Utf8).unwrap(),
            expected
        );
        assert_eq!(
            keysym_to_bytes(0x20ac, Encoding::Latin1).unwrap(),
            vec![0xac]
        );
    }

    #[test]
    fn renders_a_screen() {
        // The number of non-black pixels, i.e. the cursor and the glyphs.
        fn lit(console: &TextConsole) -> usize {
            console.framebuffer().with(|fb| {
                let (pixels, _) = fb.data().as_chunks::<4>();
                pixels.iter().filter(|p| **p != [0, 0, 0, 0]).count()
            })
        }

        let (tx, rx) = async_channel::unbounded();
        let console = TextConsole::new("test".into(), false, Encoding::Utf8, tx);
        assert_eq!(
            console.framebuffer().with(|fb| fb.dimensions()),
            (TEXT_WIDTH, TEXT_HEIGHT)
        );
        // A fresh console only shows the cursor.
        assert_eq!(lit(&console), (TEXT_FONT_WIDTH * TEXT_FONT_HEIGHT) as usize);

        console.process(b"hello");
        assert!(lit(&console) > (TEXT_FONT_WIDTH * TEXT_FONT_HEIGHT) as usize);

        // Without a chardev echo, the typed characters are echoed locally and
        // sent to the guest.
        assert!(console.keysym(b'l' as u32, true));
        assert!(!console.keysym(b'l' as u32, false));
        assert_eq!(rx.recv_blocking().unwrap(), b"l".to_vec());
        assert!(lit(&console) > (TEXT_FONT_WIDTH * TEXT_FONT_HEIGHT) as usize);
    }
}
