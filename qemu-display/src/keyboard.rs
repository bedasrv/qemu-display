use enumflags2::{bitflags, BitFlags};
use serde::{Deserialize, Serialize};
use zbus::Type;

#[bitflags]
#[repr(u32)]
#[derive(Type, Debug, PartialEq, Copy, Clone, Eq, Serialize, Deserialize)]
pub enum KeyboardModifiers {
    Scroll = 0x1,
    Num = 0x2,
    Caps = 0x4,
}

impl KeyboardModifiers {
    /// Interpret a raw modifier bitmask, as returned by [`KeyboardProxy::modifiers`].
    pub fn from_bits_truncate(bits: u32) -> BitFlags<Self> {
        BitFlags::from_bits_truncate(bits)
    }
}

#[zbus::proxy(default_service = "org.qemu", interface = "org.qemu.Display1.Keyboard")]
pub trait Keyboard {
    /// Press method
    fn press(&self, keycode: u32) -> zbus::Result<()>;

    /// Release method
    fn release(&self, keycode: u32) -> zbus::Result<()>;

    /// Modifiers bitmask, see [`KeyboardModifiers`].
    ///
    /// The D-Bus property is a plain `u32`. zbus 6 no longer provides the
    /// `enumflags2` wire-format impls, and `BitFlags` is a foreign type, so
    /// the raw mask is exposed instead of a `BitFlags<KeyboardModifiers>`.
    #[zbus(property)]
    fn modifiers(&self) -> zbus::Result<u32>;
}
