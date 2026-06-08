#[cfg(windows)]
use crate::win32::Fd;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::{
    convert::TryFrom,
    sync::{Arc, RwLock},
};
#[cfg(windows)]
use uds_windows::UnixStream;
#[cfg(unix)]
use zbus::zvariant::Fd;
use zbus::{zvariant::ObjectPath, Connection};

use crate::{
    util, ConsoleListener, ConsoleListenerHandler, ConsoleListenerMap, ConsoleListenerMapHandler,
    KeyboardProxy, MouseProxy, MultiTouchProxy, Result,
};
#[cfg(windows)]
use crate::{ConsoleListenerD3d11, ConsoleListenerD3d11Handler};
#[cfg(unix)]
use crate::{ConsoleListenerScanoutDmabuf2, ConsoleListenerScanoutDmabuf2Handler};

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

#[derive(derive_more::Debug, Clone)]
pub struct Console {
    #[debug(skip)]
    pub proxy: ConsoleProxy<'static>,
    #[debug(skip)]
    pub keyboard: KeyboardProxy<'static>,
    #[debug(skip)]
    pub mouse: MouseProxy<'static>,
    #[debug(skip)]
    pub multi_touch: MultiTouchProxy<'static>,
    listener: Arc<RwLock<Option<Connection>>>,
    #[cfg(windows)]
    peer_pid: u32,
}

impl Console {
    pub async fn new(conn: &Connection, idx: u32, #[cfg(windows)] peer_pid: u32) -> Result<Self> {
        let obj_path = ObjectPath::try_from(format!("/org/qemu/Display1/Console_{idx}"))?;
        let proxy = ConsoleProxy::builder(conn).path(&obj_path)?.build().await?;
        let keyboard = KeyboardProxy::builder(conn)
            .path(&obj_path)?
            .build()
            .await?;
        let mouse = MouseProxy::builder(conn).path(&obj_path)?.build().await?;
        let multi_touch = MultiTouchProxy::builder(conn)
            .path(&obj_path)?
            .build()
            .await?;
        Ok(Self {
            proxy,
            keyboard,
            mouse,
            multi_touch,
            listener: Arc::new(RwLock::new(None)),
            #[cfg(windows)]
            peer_pid,
        })
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
        #[cfg(all(unix, feature = "tokio"))]
        let p1 = tokio::net::UnixStream::from_std(p1)?;
        let conn = zbus::connection::Builder::unix_stream(p1)
            .p2p()
            .serve_at("/org/qemu/Display1/Listener", ConsoleListener::new(handler))?;
        #[cfg(windows)]
        let conn = conn.auth_mechanism(zbus::AuthMechanism::Anonymous);
        let conn = conn.build().await?;
        *self.listener.write().unwrap() = Some(conn);
        Ok(())
    }

    #[tracing::instrument(skip(self, handler))]
    pub async fn set_map_listener<H: ConsoleListenerMapHandler>(&self, handler: H) -> Result<bool> {
        let listener = self.listener.write().unwrap().take();
        match listener {
            Some(l) => {
                let res = l
                    .object_server()
                    .at(
                        "/org/qemu/Display1/Listener",
                        ConsoleListenerMap::new(handler),
                    )
                    .await
                    .map_err(|e| e.into());
                *self.listener.write().unwrap() = Some(l);
                res
            }
            _ => Err(crate::Error::Failed("Must call register first!".into())),
        }
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

    #[cfg(unix)]
    pub async fn set_scanout_dmabuf2_listener<H: ConsoleListenerScanoutDmabuf2Handler>(
        &self,
        handler: H,
    ) -> Result<bool> {
        if let Some(l) = &*self.listener.write().unwrap() {
            return l
                .object_server()
                .at(
                    "/org/qemu/Display1/Listener",
                    ConsoleListenerScanoutDmabuf2::new(handler),
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
