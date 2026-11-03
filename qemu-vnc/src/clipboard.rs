//! Clipboard sharing between QEMU and the VNC clients.
//!
//! Port of `clipboard.c`. QEMU's `qemu_clipboard_peer` is a set of callbacks
//! invoked by the display UI; the `qemu_display::ClipboardHandler` trait
//! plays that role here, and the [`ClipboardPeer`] keeps track of which side
//! owns the selection.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use qemu_display::{ClipboardHandler, ClipboardProxy, ClipboardSelection, Error, Result};
use tracing::{debug, info, warn};

use crate::server::ServerInner;

/// The only MIME type we handle, as in `clipboard.c`.
pub const MIME_TEXT_PLAIN_UTF8: &str = "text/plain;charset=utf-8";

/// How long we wait for QEMU to answer a clipboard request, before giving up.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Who currently owns the content of a clipboard selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Owner {
    /// Nobody, the selection is empty.
    #[default]
    None,
    /// The guest, through the `org.qemu.Display1.Clipboard` interface.
    Qemu,
    /// A VNC client, through the RFB cut text messages.
    Vnc,
}

/// The state of a clipboard selection.
#[derive(Clone, Debug, Default)]
struct ClipboardInfo {
    serial: u32,
    owner: Owner,
    /// The `text/plain;charset=utf-8` content, once known.
    text: Option<Vec<u8>>,
}

/// The clipboard peer registered with QEMU.
pub struct ClipboardPeer {
    proxy: ClipboardProxy<'static>,
    server: Weak<ServerInner>,
    infos: Mutex<HashMap<ClipboardSelection, ClipboardInfo>>,
    serial: AtomicU32,
}

impl std::fmt::Debug for ClipboardPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClipboardPeer")
            .field("infos", &self.infos)
            .finish_non_exhaustive()
    }
}

/// A handle on the clipboard shared with QEMU.
#[derive(Clone, Debug)]
pub struct Clipboard {
    peer: Arc<ClipboardPeer>,
}

impl Clipboard {
    /// Register a clipboard peer with QEMU, and export the listener interface
    /// at `/org/qemu/Display1/Clipboard`.
    pub async fn register(conn: &zbus::Connection, server: Weak<ServerInner>) -> Result<Self> {
        let proxy = ClipboardProxy::builder(conn).build().await?;
        let peer = Arc::new(ClipboardPeer {
            proxy,
            server,
            infos: Mutex::new(HashMap::new()),
            serial: AtomicU32::new(0),
        });
        let clipboard = qemu_display::Clipboard::new(conn).await?;
        clipboard
            .register(ClipboardListener {
                peer: Arc::downgrade(&peer),
            })
            .await?;
        info!("clipboard peer registered");
        Ok(Self { peer })
    }

    /// A VNC client took the ownership of a selection.
    pub async fn grab(&self, selection: ClipboardSelection, text: Vec<u8>) -> Result<()> {
        let serial = self.peer.serial.fetch_add(1, Ordering::Relaxed) + 1;
        self.peer.infos.lock().unwrap().insert(
            selection,
            ClipboardInfo {
                serial,
                owner: Owner::Vnc,
                text: Some(text),
            },
        );
        debug!(
            ?selection,
            serial, "grabbing the clipboard for a VNC client"
        );
        self.peer
            .proxy
            .grab(selection, serial, &[MIME_TEXT_PLAIN_UTF8])
            .await?;
        Ok(())
    }

    /// Give a selection back to QEMU, if we own it.
    pub async fn release(&self, selection: ClipboardSelection) -> Result<()> {
        let owned = {
            let infos = self.peer.infos.lock().unwrap();
            infos.get(&selection).is_some_and(|i| i.owner == Owner::Vnc)
        };
        if !owned {
            return Ok(());
        }
        self.peer.proxy.release(selection).await?;
        self.peer.infos.lock().unwrap().remove(&selection);
        Ok(())
    }

    /// The content of a selection, if we already have it.
    pub fn data(&self, selection: ClipboardSelection) -> Option<Vec<u8>> {
        let infos = self.peer.infos.lock().unwrap();
        let info = infos.get(&selection)?;
        match info.owner {
            Owner::Vnc => info.text.clone(),
            _ => None,
        }
    }
}

impl ClipboardPeer {
    fn info(&self, selection: ClipboardSelection) -> ClipboardInfo {
        self.infos
            .lock()
            .unwrap()
            .get(&selection)
            .cloned()
            .unwrap_or_default()
    }

    fn set(&self, selection: ClipboardSelection, info: ClipboardInfo) {
        self.infos.lock().unwrap().insert(selection, info);
    }

    /// Reset the serial counter, as `qemu_clipboard_reset_serial()` does.
    fn reset_serial(&self) {
        self.serial.store(0, Ordering::Relaxed);
        for info in self.infos.lock().unwrap().values_mut() {
            info.serial = 0;
        }
    }

    /// Ask QEMU for the content of a selection, and remember it.
    async fn fetch(&self, selection: ClipboardSelection) -> Option<Vec<u8>> {
        let request = self.proxy.request(selection, &[MIME_TEXT_PLAIN_UTF8]);
        let (mime, data) = match timeout(REQUEST_TIMEOUT, request).await {
            Some(Ok(res)) => res,
            Some(Err(e)) => {
                warn!(?selection, "failed to request the clipboard: {e}");
                return None;
            }
            None => {
                warn!(?selection, "timed out requesting the clipboard");
                return None;
            }
        };
        if mime != MIME_TEXT_PLAIN_UTF8 {
            warn!(?mime, "unsupported clipboard MIME type");
            return None;
        }
        self.set(
            selection,
            ClipboardInfo {
                serial: self.info(selection).serial,
                owner: Owner::Qemu,
                text: Some(data.clone()),
            },
        );
        Some(data)
    }

    /// Send the content of a selection to the VNC clients.
    fn notify_clients(&self, selection: ClipboardSelection) {
        let Some(server) = self.server.upgrade() else {
            debug!(?selection, "the server is gone, not sending the clipboard");
            return;
        };
        let Some(info) = self.infos.lock().unwrap().get(&selection).cloned() else {
            return;
        };
        if info.owner != Owner::Qemu {
            return;
        }
        if let Some(text) = info.text
            && let Ok(text) = String::from_utf8(text)
        {
            server.cut_text(&text);
        }
    }
}

/// The D-Bus interface exported at `/org/qemu/Display1/Clipboard`, i.e. the
/// `on_clipboard_*()` handlers of `clipboard.c`.
struct ClipboardListener {
    peer: Weak<ClipboardPeer>,
}

#[async_trait::async_trait]
impl ClipboardHandler for ClipboardListener {
    async fn register(&mut self) {
        if let Some(peer) = self.peer.upgrade() {
            peer.reset_serial();
        }
    }

    async fn unregister(&mut self) {
        if let Some(peer) = self.peer.upgrade() {
            peer.infos.lock().unwrap().clear();
        }
    }

    async fn grab(&mut self, selection: ClipboardSelection, serial: u32, mimes: Vec<String>) {
        if !mimes.iter().any(|m| m == MIME_TEXT_PLAIN_UTF8) {
            debug!(?selection, ?mimes, "no supported clipboard MIME type");
            return;
        }
        let Some(peer) = self.peer.upgrade() else {
            return;
        };
        debug!(?selection, serial, "guest grabbed the clipboard");
        peer.set(
            selection,
            ClipboardInfo {
                serial,
                owner: Owner::Qemu,
                text: None,
            },
        );
        // The guest does not send the data with the grab, ask for it.
        if peer.fetch(selection).await.is_some() {
            peer.notify_clients(selection);
        }
    }

    async fn release(&mut self, selection: ClipboardSelection) {
        debug!(?selection, "guest released the clipboard");
        if let Some(peer) = self.peer.upgrade() {
            // If we own the data, let the guest know it can grab it again.
            if peer.info(selection).owner == Owner::Vnc
                && let Err(e) = peer.proxy.release(selection).await
            {
                warn!(?selection, "failed to release the clipboard: {e}");
            }
            peer.infos.lock().unwrap().remove(&selection);
        }
    }

    async fn request(
        &mut self,
        selection: ClipboardSelection,
        mimes: Vec<String>,
    ) -> Result<(String, Vec<u8>)> {
        if !mimes.iter().any(|m| m == MIME_TEXT_PLAIN_UTF8) {
            return Err(Error::Failed("Unhandled MIME types requested".into()));
        }
        let Some(peer) = self.peer.upgrade() else {
            return Err(Error::Failed("Clipboard peer is gone".into()));
        };
        let info = peer.info(selection);
        if info.owner == Owner::None {
            return Err(Error::Failed("Empty clipboard".into()));
        }
        if info.owner == Owner::Vnc
            && let Some(data) = info.text
        {
            return Ok((MIME_TEXT_PLAIN_UTF8.into(), data));
        }
        let data = peer
            .fetch(selection)
            .await
            .ok_or_else(|| Error::Failed("Empty clipboard".into()))?;
        Ok((MIME_TEXT_PLAIN_UTF8.into(), data))
    }
}

/// Give up on `future` if it does not complete in `duration`.
async fn timeout<F: Future>(duration: Duration, future: F) -> Option<F::Output> {
    let future = std::pin::pin!(future);
    let timer = std::pin::pin!(async_io::Timer::after(duration));
    match futures::future::select(future, timer).await {
        futures::future::Either::Left((output, _)) => Some(output),
        futures::future::Either::Right(_) => None,
    }
}
