use serde::{Deserialize, Serialize};
use zbus::Type;

#[repr(u32)]
#[derive(Type, Debug, PartialEq, Copy, Clone, Eq, Serialize, Deserialize)]
pub enum TouchEventKind {
    Begin = 0,
    Update = 1,
    End = 2,
    Cancel = 3,
}

#[zbus::proxy(
    default_service = "org.qemu",
    interface = "org.qemu.Display1.MultiTouch"
)]
pub trait MultiTouch {
    fn send_event(&self, kind: TouchEventKind, num_slot: u64, x: f64, y: f64) -> zbus::Result<()>;

    #[zbus(property)]
    fn max_slots(&self) -> zbus::Result<i32>;
}
