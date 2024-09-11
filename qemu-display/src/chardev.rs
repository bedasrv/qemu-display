#[cfg(windows)]
use crate::win32::Fd;
use std::convert::TryFrom;
#[cfg(unix)]
use zbus::zvariant::Fd;
use zbus::zvariant::ObjectPath;

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

#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct Chardev {
    pub proxy: ChardevProxy<'static>,
}

impl Chardev {
    pub async fn new<D>(conn: &zbus::Connection, id: &str, dest: Option<D>) -> Result<Self>
    where
        D: TryInto<zbus::names::BusName<'static>>,
        D::Error: Into<zbus::Error>,
    {
        let obj_path = ObjectPath::try_from(format!("/org/qemu/Display1/Chardev_{}", id))?;
        let mut builder = ChardevProxy::builder(conn).path(&obj_path)?;

        if let Some(dest) = dest {
            builder = builder.destination(dest)?;
        }
        let proxy = builder.build().await?;
        Ok(Self { proxy })
    }
}
