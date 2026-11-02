#[cfg(windows)]
use crate::win32::Fd;
use std::convert::TryFrom;
#[cfg(unix)]
use zbus::Fd;
use zbus::{proxy::CacheProperties, ObjectPath};

use crate::Result;

#[zbus::proxy(default_service = "org.qemu", interface = "org.qemu.Display1.Chardev")]
pub trait Chardev {
    /// Register method
    fn register(&self, stream: Fd<'_>) -> zbus::Result<()>;

    /// SendBreak method
    fn send_break(&self) -> zbus::Result<()>;

    /// Echo property
    #[zbus(property)]
    fn echo(&self) -> zbus::Result<bool>;

    /// FEOpened property
    #[zbus(property, name = "FEOpened")]
    fn fe_opened(&self) -> zbus::Result<bool>;

    /// Name property
    #[zbus(property)]
    fn name(&self) -> zbus::Result<String>;

    /// Owner property
    #[zbus(property)]
    fn owner(&self) -> zbus::Result<String>;
}

#[derive(derive_more::Debug)]
pub struct Chardev {
    pub proxy: ChardevProxy<'static>,
}

impl Chardev {
    pub async fn new(conn: &zbus::Connection, id: &str) -> Result<Self> {
        let obj_path = ObjectPath::try_from(format!("/org/qemu/Display1/Chardev_{id}"))?;
        // Owner changes when streams are registered or closed. QEMU may publish
        // that change after Register returns, so a zbus property cache can
        // briefly report the previous owner and select an occupied chardev.
        let proxy = ChardevProxy::builder(conn)
            .path(&obj_path)
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        Ok(Self { proxy })
    }
}
