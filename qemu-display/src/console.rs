#[cfg(windows)]
use crate::win32::Fd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{convert::TryFrom, sync::RwLock};
#[cfg(windows)]
use uds_windows::UnixStream;
#[cfg(unix)]
use zbus::zvariant::Fd;
use zbus::{zvariant::ObjectPath, Connection};

use crate::{
    util, ConsoleListener, ConsoleListenerHandler, KeyboardProxy, MouseProxy, MultiTouchProxy,
    Result,
};
#[cfg(windows)]
use crate::{
    ConsoleListenerD3d11, ConsoleListenerD3d11Handler, ConsoleListenerMap,
    ConsoleListenerMapHandler,
};

#[zbus::proxy(default_service = "org.qemu", interface = "org.qemu.Display1.Console")]
pub trait Console {
    /// RegisterListener method
    fn register_listener(&self, listener: Fd<'_>) -> zbus::Result<()>;

    /// SetUIInfo method
    #[zbus(name = "SetUIInfo")]
    fn set_ui_info(
        &self,
        width_mm: u16,
        height_mm: u16,
        xoff: i32,
        yoff: i32,
        width: u32,
        height: u32,
    ) -> zbus::Result<()>;

    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn head(&self) -> zbus::Result<u32>;

    #[zbus(property)]
    fn type_(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn width(&self) -> zbus::Result<u32>;

    #[zbus(property)]
    fn height(&self) -> zbus::Result<u32>;
}

#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct Console {
    #[derivative(Debug = "ignore")]
    pub proxy: ConsoleProxy<'static>,
    #[derivative(Debug = "ignore")]
    pub keyboard: KeyboardProxy<'static>,
    #[derivative(Debug = "ignore")]
    pub mouse: MouseProxy<'static>,
    #[derivative(Debug = "ignore")]
    pub multi_touch: MultiTouchProxy<'static>,
    listener: RwLock<Option<Connection>>,
    #[cfg(windows)]
    peer_pid: u32,
}

impl Console {
    pub async fn with_unique_name(
        conn: &Connection,
        idx: u32,
        unique_name: &str,
        #[cfg(windows)] peer_pid: u32,
    ) -> Result<Self> {
        let obj_path = ObjectPath::try_from(format!("/org/qemu/Display1/Console_{}", idx))?;
        let proxy = ConsoleProxy::builder(conn)
            .path(&obj_path)?
            .destination(unique_name.to_owned())?
            .build()
            .await?;
        let keyboard = KeyboardProxy::builder(conn)
            .path(&obj_path)?
            .destination(unique_name.to_owned())?
            .build()
            .await?;
        let mouse = MouseProxy::builder(conn)
            .path(&obj_path)?
            .destination(unique_name.to_owned())?
            .build()
            .await?;
        let multi_touch = MultiTouchProxy::builder(conn)
            .path(&obj_path)?
            .destination(unique_name.to_owned())?
            .build()
            .await?;
        Ok(Self {
            proxy,
            keyboard,
            mouse,
            multi_touch,
            listener: RwLock::new(None),
            #[cfg(windows)]
            peer_pid,
        })
    }

    pub async fn new(conn: &Connection, idx: u32, #[cfg(windows)] peer_pid: u32) -> Result<Self> {
        Self::with_unique_name(
            conn,
            idx,
            "org.qemu",
            #[cfg(windows)]
            peer_pid,
        )
        .await
    }

    pub async fn label(&self) -> Result<String> {
        Ok(self.proxy.label().await?)
    }

    pub async fn width(&self) -> Result<u32> {
        Ok(self.proxy.width().await?)
    }

    pub async fn height(&self) -> Result<u32> {
        Ok(self.proxy.height().await?)
    }

    #[tracing::instrument(skip(self, handler))]
    pub async fn register_listener<H: ConsoleListenerHandler>(&self, handler: H) -> Result<()> {
        let (p0, p1) = UnixStream::pair()?;
        let p0 = util::prepare_uds_pass(
            #[cfg(windows)]
            self.peer_pid,
            &p0,
        )?;
        self.proxy.register_listener(p0).await?;
        let c = zbus::ConnectionBuilder::unix_stream(p1)
            .p2p()
            .serve_at("/org/qemu/Display1/Listener", ConsoleListener::new(handler))?
            .build()
            .await?;
        *self.listener.write().unwrap() = Some(c);
        Ok(())
    }

    #[cfg(windows)]
    pub async fn set_map_listener<H: ConsoleListenerMapHandler>(&self, handler: H) -> Result<bool> {
        if let Some(l) = &*self.listener.write().unwrap() {
            return l
                .object_server()
                .at(
                    "/org/qemu/Display1/Listener",
                    ConsoleListenerMap::new(handler),
                )
                .await
                .map_err(|e| e.into());
        }

        Err(crate::Error::Failed("Must call register first!".into()))
    }

    #[cfg(windows)]
    pub async fn set_d3d11_listener<H: ConsoleListenerD3d11Handler>(
        &self,
        handler: H,
    ) -> Result<bool> {
        if let Some(l) = &*self.listener.write().unwrap() {
            return l
                .object_server()
                .at(
                    "/org/qemu/Display1/Listener",
                    ConsoleListenerD3d11::new(handler),
                )
                .await
                .map_err(|e| e.into());
        }

        Err(crate::Error::Failed("Must call register first!".into()))
    }

    pub fn unregister_listener(&self) {
        *self.listener.write().unwrap() = None;
    }
}
