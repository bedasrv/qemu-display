//! Keyboard and mouse input dispatch via D-Bus.
//!
//! Port of `input.c`. Where the C code implements the QEMU input backend,
//! and QEMU's VNC server calls into it, the roles are reversed here: the VNC
//! clients produce the events, and this module translates and dispatches
//! them to the QEMU `org.qemu.Display1.Keyboard` and `.Mouse` interfaces.

use keycodemap::KEYMAP_X112QNUM;
use qemu_display::{Console, MouseButton, Result};
use tracing::trace;

/// The largest QEMU key number (`qnum`) QEMU's `qnum -> linux` table covers.
///
/// QEMU generates that table from keycodemapdb's AT set 1 column, and its
/// highest value is `0xfd` (`KEY_EJECTCLOSECD`), so the array is 254 entries
/// long. `qemu_input_key_number_to_linux()` answers `KEY_RESERVED` past the end,
/// which is inert; dropping such a number here has the same effect and keeps a
/// key QEMU would discard from being reported as sent.
const QNUM_MAX: u32 = 0xfd;

/// Keyboard and mouse input for a graphic console.
#[derive(Debug, Clone)]
pub struct Input {
    keyboard: qemu_display::KeyboardProxy<'static>,
    mouse: qemu_display::MouseProxy<'static>,
}

impl Input {
    /// Use the keyboard & mouse interfaces of `console`.
    pub fn new(console: &Console) -> Self {
        Self {
            keyboard: console.keyboard.clone(),
            mouse: console.mouse.clone(),
        }
    }

    /// The QEMU key number (`qnum`) for an X11 keysym, or `None` if the keysym
    /// names no key QEMU knows.
    ///
    /// `KEYMAP_X112QNUM` is keycodemapdb's `x11 -> qnum` table, and the value it
    /// holds is the QEMU key number itself. keymap-gen derives qnum from the AT
    /// set 1 scancode: `atset1 & 0x7f`, with `0x80` set for the extended
    /// (`0xe0`-prefixed) codes. The main block therefore coincides with the
    /// Linux key code -- `1` is 2, `q` is 16, `a` is 30 -- which makes an offset
    /// look plausible and is exactly the trap: `Up` is 200 while its Linux code
    /// is 103, and `KP_Enter` is 156 while its Linux code is 96.
    pub fn qnum_from_keysym(keysym: u32) -> Option<u32> {
        let qnum = KEYMAP_X112QNUM.get(keysym as usize).copied()?;
        (qnum != 0).then_some(qnum.into())
    }

    /// The QEMU key number carried by an RFB `ExtendedKeyEvent`.
    ///
    /// The field is called `keycode` in the message, but it is already a qnum:
    /// QEMU's VNC server feeds it straight to
    /// `qemu_input_key_number_to_linux()` (`ui/vnc.c:ext_key_event` calls
    /// `do_key_event`, which does that), and noVNC sends the AT set 1 scancode
    /// with the `0xe0` prefix re-encoded as `0x80` there. Translating it a
    /// second time is the bug this replaces: the old code looked the number up
    /// in an X11-keycode table whose entries 2..=8 are zero, so digits `1`..`7`
    /// were dropped outright.
    ///
    /// Zero means "unknown" and numbers past `QNUM_MAX` are inert in QEMU, so
    /// both are dropped.
    pub fn qnum_from_extended_keycode(keycode: u32) -> Option<u32> {
        (1..=QNUM_MAX).contains(&keycode).then_some(keycode)
    }

    /// Send a key event, for an already converted key number.
    async fn key(&self, qnum: u32, down: bool) -> Result<()> {
        trace!(qnum, down, "key event");
        if down {
            self.keyboard.press(qnum).await?;
        } else {
            self.keyboard.release(qnum).await?;
        }
        Ok(())
    }

    /// Send a key event, for an X11 keysym.
    pub async fn key_sym(&self, keysym: u32, down: bool) -> Result<()> {
        match Self::qnum_from_keysym(keysym) {
            Some(qnum) => self.key(qnum, down).await,
            None => {
                trace!(keysym, "unhandled keysym");
                Ok(())
            }
        }
    }

    /// Send a key event from an RFB `ExtendedKeyEvent`, whose `keycode` field
    /// is already a QEMU key number.
    pub async fn key_extended(&self, keycode: u32, down: bool) -> Result<()> {
        match Self::qnum_from_extended_keycode(keycode) {
            Some(qnum) => self.key(qnum, down).await,
            None => {
                trace!(keycode, "unhandled extended keycode");
                Ok(())
            }
        }
    }

    /// Send a button press or release.
    pub async fn button(&self, button: MouseButton, down: bool) -> Result<()> {
        trace!(?button, down, "mouse button event");
        if down {
            self.mouse.press(button).await?;
        } else {
            self.mouse.release(button).await?;
        }
        Ok(())
    }

    /// Queue an absolute pointer position.
    pub async fn set_abs_position(&self, x: u32, y: u32) -> Result<()> {
        trace!(x, y, "input abs");
        self.mouse.set_abs_position(x, y).await?;
        Ok(())
    }

    /// Queue a relative pointer motion.
    pub async fn rel_motion(&self, dx: i32, dy: i32) -> Result<()> {
        trace!(dx, dy, "input rel");
        self.mouse.rel_motion(dx, dy).await?;
        Ok(())
    }

    /// Whether the guest console uses an absolute pointing device.
    pub async fn is_absolute(&self) -> bool {
        self.mouse.is_absolute().await.unwrap_or(true)
    }
}

/// The state of the pointer buttons and position of a VNC client.
///
/// This is the equivalent of the `abs_x`/`abs_y`/`rel_dx`/`rel_dy` and
/// pending flags of `input.c`, and converts the absolute coordinates sent by
/// the VNC client into relative motion when the guest expects it.
#[derive(Clone, Copy, Debug, Default)]
pub struct PointerState {
    mask: u8,
    x: u16,
    y: u16,
}

/// The buttons of the D-Bus mouse interface, in RFB button-mask order.
const BUTTONS: [MouseButton; 7] = [
    MouseButton::Left,
    MouseButton::Middle,
    MouseButton::Right,
    MouseButton::WheelUp,
    MouseButton::WheelDown,
    MouseButton::Side,
    MouseButton::Extra,
];

impl PointerState {
    /// Dispatch a pointer event, as `qemu_input_queue_abs()`,
    /// `qemu_input_queue_rel()` and `qemu_input_update_buttons()` do.
    ///
    /// `absolute` is the value of [`Input::is_absolute`], which the caller is
    /// expected to cache.
    pub async fn event(
        &mut self,
        input: &Input,
        absolute: bool,
        mask: u8,
        x: u16,
        y: u16,
    ) -> Result<()> {
        let changed = self.mask ^ mask;
        for (i, button) in BUTTONS.iter().enumerate() {
            if changed & (1 << i) == 0 {
                continue;
            }
            input.button(*button, mask & (1 << i) != 0).await?;
        }

        if absolute {
            input.set_abs_position(x as u32, y as u32).await?;
        } else {
            let (dx, dy) = (x as i32 - self.x as i32, y as i32 - self.y as i32);
            if dx != 0 || dy != 0 {
                input.rel_motion(dx, dy).await?;
            }
        }

        self.mask = mask;
        self.x = x;
        self.y = y;
        Ok(())
    }
}

/// Tracks the modifier keys pressed by a VNC client, to implement the
/// console switching shortcuts.
#[derive(Clone, Debug, Default)]
pub struct ModifierState {
    ctrl: bool,
    alt: bool,
    digits: Vec<u32>,
}

/// A key that matters to the console-switching shortcut.
enum Shortcut {
    Ctrl,
    Alt,
    Digit(u32),
}

impl ModifierState {
    /// Update the state with a key press or release, and return the console
    /// index the client asked to switch to, if any.
    ///
    /// `keysym` is the symbol the client sent, and is authoritative when it is
    /// not zero. `keycode` is the QEMU key number from an `ExtendedKeyEvent`,
    /// used when the client sent no symbol. The two spaces overlap -- `0x38` is
    /// `8` as a keysym and left Alt as a key number -- so they are never matched
    /// together.
    pub fn event(&mut self, keysym: u32, keycode: Option<u32>, down: bool) -> Option<u32> {
        match Self::shortcut(keysym, keycode) {
            Some(Shortcut::Ctrl) => self.ctrl = down,
            Some(Shortcut::Alt) => self.alt = down,
            Some(Shortcut::Digit(digit)) => {
                if down {
                    if !self.digits.contains(&digit) {
                        self.digits.push(digit);
                    }
                } else {
                    self.digits.retain(|d| *d != digit);
                }
                if down && self.ctrl && self.alt && self.digits.len() == 1 {
                    return Some(digit - 1);
                }
            }
            None => {
                if !down {
                    self.digits.clear();
                }
            }
        }
        None
    }

    fn shortcut(keysym: u32, keycode: Option<u32>) -> Option<Shortcut> {
        if keysym != 0 {
            return match keysym {
                0xffe3 | 0xffe4 => Some(Shortcut::Ctrl),
                0xffe9 | 0xffea => Some(Shortcut::Alt),
                c @ 0x31..=0x39 => Some(Shortcut::Digit(c - 0x30)),
                _ => None,
            };
        }
        match keycode? {
            // QEMU key numbers: AT set 1 scancodes, `0x80` for the extended
            // ones. `1`..`9` are `0x02`..`0x0a`.
            0x1d | 0x9d => Some(Shortcut::Ctrl),
            0x38 | 0xb8 => Some(Shortcut::Alt),
            c @ 0x02..=0x0a => Some(Shortcut::Digit(c - 1)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Input, ModifierState};

    /// Every printable key on the main block reaches its own key number, and a
    /// few extended keys reach theirs.
    ///
    /// **This is the regression test for the reported `1`..`7` fault.** These
    /// are keycodemapdb's AT set 1 scancodes, which are the qnum values
    /// (`data/keymaps.csv`, checksum `527727ef...`, the same data the local
    /// `keycodemap` tables were generated from), not expectations derived from
    /// the code under test. The old test computed its expectation from the same
    /// constant as the code, so it could not fail.
    ///
    /// It covers the keys whose qnum is *not* their Linux code as well: `Up` is
    /// 200 (Linux 103), `Left` 203 (105), `KP_Enter` 156 (96).
    #[test]
    fn keys_reach_the_key_number_named_by_their_own_scancode() {
        // (keysym, qnum). Letters and digits share their Linux code only
        // because the main block has no 0xe0 prefix.
        let keys = [
            ('1', 0x02u32),
            ('2', 0x03),
            ('3', 0x04),
            ('4', 0x05),
            ('5', 0x06),
            ('6', 0x07),
            ('7', 0x08),
            ('8', 0x09),
            ('9', 0x0a),
            ('0', 0x0b),
            ('q', 0x10),
            ('w', 0x11),
            ('e', 0x12),
            ('r', 0x13),
            ('t', 0x14),
            ('y', 0x15),
            ('u', 0x16),
            ('i', 0x17),
            ('o', 0x18),
            ('p', 0x19),
            ('a', 0x1e),
            ('s', 0x1f),
            ('d', 0x20),
            ('f', 0x21),
            ('g', 0x22),
            ('h', 0x23),
            ('j', 0x24),
            ('k', 0x25),
            ('l', 0x26),
            ('z', 0x2c),
            ('x', 0x2d),
            ('c', 0x2e),
            ('v', 0x2f),
            ('b', 0x30),
            ('n', 0x31),
            ('m', 0x32),
            (' ', 0x39),
        ];
        let mut wrong = Vec::new();
        for (ch, want) in keys {
            let got = Input::qnum_from_keysym(ch as u32);
            if got != Some(want) {
                wrong.push(format!("{ch:?}: sent {got:?}, want {want}"));
            }
        }
        let extended = [
            (0xff50u32, 0xc7u32, "Home"),
            (0xff52, 0xc8, "Up"),
            (0xff51, 0xcb, "Left"),
            (0xff53, 0xcd, "Right"),
            (0xff54, 0xd0, "Down"),
            (0xffff, 0xd3, "Delete"),
            (0xff8d, 0x9c, "KP_Enter"),
            (0xff13, 0xc6, "Pause"),
            (0xffe1, 0x2a, "Shift_L"),
            (0xffe3, 0x1d, "Control_L"),
            (0xffe9, 0x38, "Alt_L"),
        ];
        for (keysym, want, name) in extended {
            let got = Input::qnum_from_keysym(keysym);
            if got != Some(want) {
                wrong.push(format!("{name}: sent {got:?}, want {want}"));
            }
        }
        assert!(
            wrong.is_empty(),
            "these keys reach the guest as a different key:\n  {}",
            wrong.join("\n  ")
        );
    }

    /// An `ExtendedKeyEvent` keycode is already a qnum and must pass through.
    ///
    /// noVNC sends the AT set 1 scancode with `0xe0` re-encoded as `0x80`, and
    /// QEMU's `ext_key_event()` feeds the field straight to
    /// `qemu_input_key_number_to_linux()`. Re-translating it -- for instance
    /// through an X11 keycode table -- would corrupt every extended key, and the
    /// client prefers this path whenever the server advertises the extension.
    #[test]
    fn an_extended_key_event_keycode_is_already_a_qnum() {
        // The same physical keys as above, in the encoding noVNC sends them.
        let keys = [
            (0x02u32, "1"),
            (0x1e, "a"),
            (0x2c, "z"),
            (0x1d, "Control_L"),
            (0x38, "Alt_L"),
            (0x9c, "KP_Enter"),
            (0xc8, "Up"),
            (0xd3, "Delete"),
            (0xf5, "Help"),
            (0xfd, "EjectCloseCD"),
            (0xb7, "SysRq, the old encoding QEMU still accepts"),
        ];
        for (qnum, name) in keys {
            assert_eq!(
                Input::qnum_from_extended_keycode(qnum),
                Some(qnum),
                "{name} (qnum {qnum}) was translated instead of passed through"
            );
        }
        assert_eq!(
            Input::qnum_from_extended_keycode(0),
            None,
            "0 is the protocol's `unknown keycode`"
        );
        assert_eq!(
            Input::qnum_from_extended_keycode(0xfe),
            None,
            "QEMU's qnum table ends at 0xfd"
        );
        assert_eq!(Input::qnum_from_extended_keycode(u32::MAX), None);
    }

    /// A keysym that names no key is dropped, not sent as `KEY_RESERVED`.
    #[test]
    fn an_unmapped_keysym_is_not_sent() {
        assert_eq!(Input::qnum_from_keysym(0), None, "NoSymbol");
        assert_eq!(Input::qnum_from_keysym(0xffeb), None, "Super_L has no qnum");
        assert_eq!(Input::qnum_from_keysym(0x11_0000), None, "past the table");
        assert_eq!(Input::qnum_from_keysym(u32::MAX), None);
    }

    /// Ctrl+Alt+`N` switches consoles whether the client sends symbols or key
    /// numbers.
    ///
    /// A plain `KeyEvent` always has a symbol; an `ExtendedKeyEvent` may carry
    /// only the QEMU key number (`0x1d` for Ctrl, `0x38` for Alt, `0x02`..`0x0a`
    /// for `1`..`9`). Both are real client behaviour, so both must work.
    #[test]
    fn ctrl_alt_digit_switches_consoles_from_either_encoding() {
        let mut symbols = ModifierState::default();
        assert_eq!(symbols.event(0xffe3, None, true), None, "Ctrl");
        assert_eq!(symbols.event(0xffe9, None, true), None, "Alt");
        assert_eq!(symbols.event('3' as u32, None, true), Some(2));

        let mut numbers = ModifierState::default();
        assert_eq!(numbers.event(0, Some(0x1d), true), None, "Ctrl");
        assert_eq!(numbers.event(0, Some(0x38), true), None, "Alt");
        assert_eq!(numbers.event(0, Some(0x04), true), Some(2));
    }

    /// A symbol is never read as a key number, even where the two coincide.
    ///
    /// `0x38` is `8` as a keysym and left Alt as a key number. Matching both in
    /// one space would arm Alt when the user typed `8`, which is how a
    /// keysym-only client could hijack Ctrl+`1`.
    #[test]
    fn a_keysym_is_not_read_as_a_key_number() {
        let mut state = ModifierState::default();
        state.event(0xffe3, None, true); // Ctrl
        state.event('8' as u32, None, true);
        state.event('8' as u32, None, false);
        assert_eq!(
            state.event('1' as u32, None, true),
            None,
            "Ctrl+8+1 is not Ctrl+Alt+1"
        );
    }
}
