//! The VNC server: listening sockets, clients and the display registry.
//!
//! `qemu-vnc` links against QEMU's `ui/vnc.c` to implement the RFB server
//! itself. Here the vendored [`crate::rfb`] module plays that role, and this
//! module glues it to the QEMU consoles exposed over D-Bus.
//!
//! # The parts
//!
//! - [`Server`] owns the shared state: the D-Bus connection, the consoles,
//!   the connected clients and the listening sockets.
//! - `client` is the per-client half, which is what a `VncState` is in C:
//!   the session, the RFB events, and the input they are dispatched to. It
//!   runs in a task of its own and shares with the server only a handle.
//! - `credentials` is the password and its lifetime, read when a client
//!   connects.
//! - `events` is the seam: what crosses a thread boundary, and nothing else.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use async_channel::{Receiver, Sender, TrySendError};
use qemu_display::{ClipboardSelection, Result};
use tracing::{debug, warn};

use crate::audio::AudioServer;
use crate::clipboard::Clipboard;
use crate::console::TextConsole;
use crate::display::{Display, GraphicConsole};
use crate::rfb::{Authz, ClientTransport, Password, Rect, SaslMechanisms, TcpSession};

mod client;
pub use client::thread_cpu_nanos;
mod credentials;
mod events;

pub use credentials::PasswordStore;
pub use events::ServerEvent;

use client::client_thread;
use events::ClientEvent;

/// The identifier of a VNC client.
pub type ClientId = u32;

/// The display sharing policy, as the `share` VNC option.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Share {
    /// Let the clients decide, as the RFB protocol does.
    #[default]
    Ignore,
    /// Disconnect the other clients when a new one asks for exclusive access.
    AllowExclusive,
    /// Always let the clients share the desktop.
    ForceShared,
}

impl Share {
    /// Parse a sharing policy name.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow-exclusive" => Some(Share::AllowExclusive),
            "force-shared" => Some(Share::ForceShared),
            "ignore" => Some(Share::Ignore),
            _ => None,
        }
    }

    /// The policy name.
    pub fn name(&self) -> &'static str {
        match self {
            Share::Ignore => "ignore",
            Share::AllowExclusive => "allow-exclusive",
            Share::ForceShared => "force-shared",
        }
    }
}

/// Information about a connected VNC client.
#[derive(Debug)]
pub struct ClientInfo {
    /// The client identifier.
    pub id: ClientId,
    /// The client IP address.
    pub host: String,
    /// The client port.
    pub service: String,
    /// The address family, `ipv4`, `ipv6` or `unix`.
    pub family: String,
    /// Whether the client connected through a WebSocket.
    pub websocket: bool,
    /// The name a SASL exchange established, empty when it authenticated with
    /// something that has no name to give, or with no authentication.
    ///
    /// A lock rather than a field: a client is announced as connected before
    /// its handshake, and the name is only known after it.
    pub sasl_username: Arc<RwLock<String>>,
}

impl ClientInfo {
    /// Describe a client that just connected to `listener`.
    ///
    /// A client of the WebSocket listener is a WebSocket client, even before
    /// its HTTP upgrade is answered: a request that is not a valid one is
    /// closed there and never becomes a client at all.
    fn new(id: ClientId, addr: SocketAddr, websocket: bool) -> Self {
        Self {
            id,
            host: addr.ip().to_string(),
            service: addr.port().to_string(),
            family: match addr.ip() {
                IpAddr::V4(_) => "ipv4",
                IpAddr::V6(_) => "ipv6",
            }
            .into(),
            websocket,
            sasl_username: Arc::new(RwLock::new(String::new())),
        }
    }
}

impl Clone for ClientInfo {
    /// The SASL username is shared, not copied: a client has one, and the
    /// clones are the same client seen from different places.
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            host: self.host.clone(),
            service: self.service.clone(),
            family: self.family.clone(),
            websocket: self.websocket,
            sasl_username: self.sasl_username.clone(),
        }
    }
}

impl PartialEq for ClientInfo {
    /// Two clients are the same when they have the same id.
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ClientInfo {}

impl ClientInfo {
    /// The D-Bus object path of this client.
    pub fn path(&self) -> String {
        format!("{}{}", crate::dbus::CLIENT_PATH_PREFIX, self.id)
    }
}

/// Information about a listening socket, for the `Listeners` D-Bus property.
#[derive(Clone, Debug)]
pub struct ListenerInfo {
    /// The address the server was bound to.
    pub addr: SocketAddr,
    /// The primary authentication method. Only `None` is supported.
    pub auth: String,
    /// Whether this listener serves RFB over WebSocket.
    pub websocket: bool,
}

impl ListenerInfo {
    /// The address family, as expected by the D-Bus property.
    pub fn family(&self) -> &'static str {
        match self.addr.ip() {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        }
    }

    /// The service name, i.e. the TCP port.
    pub fn service(&self) -> String {
        self.addr.port().to_string()
    }
}

/// The shared state of a [`Server`].
pub struct ServerInner {
    name: String,
    vm_name: String,
    conn: zbus::Connection,
    share: Share,
    events: Sender<ServerEvent>,
    incoming: Receiver<ServerEvent>,
    /// The consoles this server shares, by index. The client task reads it.
    pub(super) displays: RwLock<BTreeMap<u32, Display>>,
    /// The connected clients, by id. The client task reads it to enforce the
    /// sharing policy.
    pub(super) clients: RwLock<HashMap<ClientId, Arc<events::ClientHandle>>>,
    next_client_id: AtomicU32,
    /// The clipboard peer, if one is serving the clients.
    pub(crate) clipboard: Mutex<Option<Clipboard>>,
    listener: Mutex<Vec<ListenerInfo>>,
    passwords: Arc<PasswordStore>,
    /// The quality of the lossy JPEG encoding, or 0 when it is not allowed.
    jpeg_quality: AtomicU8,
    /// The audio the server plays for its clients, if it is capturing any.
    audio: Mutex<Option<AudioServer>>,
    /// The mechanisms to offer when SASL is enabled, and who may use them.
    sasl: Mutex<Option<SaslConfig>>,
}

/// The SASL configuration of a server: what to offer, and who may connect.
///
/// The mechanisms are shared rather than copied: each is a factory for one
/// client's exchange, and a client gets its own instance out of it.
#[derive(Clone, Debug, Default)]
pub struct SaslConfig {
    /// The mechanisms offered to the clients that connect.
    pub mechanisms: std::sync::Arc<SaslMechanisms>,
    /// Who an authenticated client has to be to be let in.
    pub authz: Authz,
}

impl ServerInner {
    /// Notify the clients that the content of console `index` changed.
    ///
    /// `damage` is the rectangle that changed, or `None` for the whole
    /// console: a client only compresses what changed, so telling it how much
    /// changed is what makes the encodings worthwhile.
    /// The content of a console changed.
    ///
    /// `None` means the whole console; `Some(rects)` means those runs of it,
    /// and an empty list means nothing changed. One event, not one per
    /// rectangle: a guest update that differs in forty runs is one thing that
    /// happened, and forty events would have the client merge them forty times
    /// and wake forty times to do it.
    pub(crate) fn console_updated(&self, index: u32, damage: Option<Vec<Rect>>) {
        crate::counters::counters().damage_notifications.bump();
        self.broadcast(|| ClientEvent::ConsoleUpdate(index, damage.clone()));
    }

    /// Send new clipboard content to all the clients.
    pub(crate) fn cut_text(&self, text: &str) {
        self.broadcast(|| ClientEvent::CutText(text.to_string()));
    }

    /// Send a block of samples to the clients that asked for them.
    pub(crate) fn audio(&self, source: crate::rfb::audio::Format, samples: Vec<u8>) {
        self.broadcast(|| ClientEvent::Audio(source, samples.clone()));
    }

    /// Tell the clients that a stream has started, as QEMU does on
    /// `AUD_CNOTIFY_ENABLE`.
    ///
    /// **Once per stream, not once per session.** A guest that pauses -- between
    /// two tracks of a playlist, say -- stops and restarts its audio, and QEMU
    /// reports each end and each beginning. Without this the client is told the
    /// stream ended once and never that another began, and the audio stops for
    /// good on the second track.
    pub(crate) fn audio_begin(&self) {
        self.broadcast(|| ClientEvent::AudioBegin);
    }

    /// Tell the clients that asked for them that a stream has ended.
    pub(crate) fn audio_end(&self) {
        self.broadcast(|| ClientEvent::AudioEnd);
    }

    /// Send an event to all the connected clients.
    fn broadcast(&self, event: impl Fn() -> ClientEvent) {
        for client in self.clients.read().unwrap().values() {
            if let Err(TrySendError::Closed(_)) = client.events.try_send(event()) {
                debug!(id = client.info.id, "client is gone, dropping event");
            }
        }
    }
}

/// A VNC server, sharing the consoles of a QEMU instance.
#[derive(Clone)]
pub struct Server {
    pub(crate) inner: Arc<ServerInner>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("name", &self.inner.name)
            .field("displays", &self.displays().len())
            .field("clients", &self.clients().len())
            .finish()
    }
}

impl Server {
    /// Create a server for the VM named `vm_name`, connected to QEMU
    /// through `conn`.
    pub async fn new(conn: &zbus::Connection, vm_name: &str, share: Share) -> Result<Self> {
        Self::with_passwords(conn, vm_name, share, PasswordStore::from_environment()?)
    }

    /// Create a server with an already built password store.
    pub fn with_passwords(
        conn: &zbus::Connection,
        vm_name: &str,
        share: Share,
        passwords: PasswordStore,
    ) -> Result<Self> {
        let (events, incoming) = async_channel::unbounded();
        Ok(Self {
            inner: Arc::new(ServerInner {
                name: format!("qemu-vnc ({vm_name})"),
                vm_name: vm_name.into(),
                conn: conn.clone(),
                share,
                events,
                incoming,
                displays: RwLock::new(BTreeMap::new()),
                clients: RwLock::new(HashMap::new()),
                next_client_id: AtomicU32::new(0),
                clipboard: Mutex::new(None),
                listener: Mutex::new(Vec::new()),
                passwords: Arc::new(passwords),
                jpeg_quality: AtomicU8::new(0),
                audio: Mutex::new(None),
                sasl: Mutex::new(None),
            }),
        })
    }

    /// Allow the clients that ask for it to be served lossy JPEG, with the
    /// given quality from 0 (smallest) to 100 (best).
    ///
    /// This is QEMU's `-vnc lossy` and `-vnc jpeg=<quality>`, and it only
    /// applies to the clients connected afterwards. It needs the crate to be
    /// built with the `lossy` feature.
    pub fn set_jpeg_quality(&self, quality: u8) {
        self.inner.jpeg_quality.store(quality, Ordering::Relaxed);
    }

    /// The lossy JPEG quality of a new client, if it is allowed.
    fn jpeg_quality(&self) -> Option<u8> {
        match self.inner.jpeg_quality.load(Ordering::Relaxed) {
            0 => None,
            quality => Some(quality),
        }
    }

    /// The password the clients have to authenticate with, if any.
    pub fn password(&self) -> Option<Password> {
        self.inner.passwords.password()
    }

    /// The store the `SetPassword` and `ExpirePassword` methods write to.
    pub fn passwords(&self) -> Arc<PasswordStore> {
        self.inner.passwords.clone()
    }

    /// The name of the authentication method, for the `Auth` property.
    pub fn auth_method(&self) -> &'static str {
        self.inner.passwords.auth_method()
    }

    /// The name announced to the VNC clients.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// The name of the VM we are serving.
    pub fn vm_name(&self) -> &str {
        &self.inner.vm_name
    }

    /// The connection to QEMU.
    pub fn connection(&self) -> &zbus::Connection {
        &self.inner.conn
    }

    /// A weak reference to the shared state, for the components that must not
    /// keep the server alive.
    pub fn downgrade(&self) -> std::sync::Weak<ServerInner> {
        Arc::downgrade(&self.inner)
    }

    /// The events channel, to be consumed by the main loop.
    pub fn events(&self) -> Receiver<ServerEvent> {
        self.inner.incoming.clone()
    }

    /// The list of displays (consoles) a client can attach to.
    pub fn displays(&self) -> Vec<Display> {
        self.inner
            .displays
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// The display a new client attaches to.
    pub fn default_display(&self) -> Option<Display> {
        self.inner.displays.read().unwrap().values().next().cloned()
    }

    /// The connected clients.
    pub fn clients(&self) -> Vec<ClientInfo> {
        let mut clients: Vec<_> = self
            .inner
            .clients
            .read()
            .unwrap()
            .values()
            .map(|c| c.info.clone())
            .collect();
        clients.sort_by_key(|c| c.id);
        clients
    }

    /// The listening sockets, as the `Listeners` D-Bus property reports them.
    pub fn listeners(&self) -> Vec<ListenerInfo> {
        self.inner.listener.lock().unwrap().clone()
    }

    /// Start serving the audio, or stop with `None`.
    pub fn set_audio(&self, audio: Option<AudioServer>) {
        *self.inner.audio.lock().unwrap() = audio;
    }

    /// Send a block of samples to the clients that are receiving them.
    pub fn broadcast_audio(&self, source: crate::rfb::audio::Format, samples: Vec<u8>) {
        self.inner.audio(source, samples);
    }

    /// Tell the clients that a stream has started.
    ///
    /// **Once per stream, not once per session.** A guest that pauses -- between
    /// two tracks of a playlist, say -- stops and restarts its audio, and QEMU
    /// reports each end and each beginning. Without this the client is told the
    /// stream ended once and never that another began, and the audio stops for
    /// good on the second track.
    pub fn broadcast_audio_begin(&self) {
        self.inner.audio_begin();
    }

    /// Tell the clients that asked for them that a stream has ended.
    ///
    /// Each client flushes what its own converter is holding and is sent
    /// `VNC_MSG_SERVER_QEMU_AUDIO_END`, which is what QEMU does when the guest
    /// stops its audio. **The clients stay enabled**: in QEMU this notification
    /// does not clear `vs->audio_enabled`, which is the client's own setting, and
    /// clearing it here is what made a second stream inaudible.
    pub fn broadcast_audio_end(&self) {
        self.inner.audio_end();
    }

    /// Whether the server has audio to send, which is what a client is told
    /// when it asks for the audio pseudo-encoding.
    pub fn audio_enabled(&self) -> bool {
        self.inner.audio.lock().unwrap().is_some()
    }

    /// The audio server, if the server is capturing any.
    pub fn audio_server(&self) -> Option<AudioServer> {
        self.inner.audio.lock().unwrap().clone()
    }

    /// Require SASL authentication of the clients that connect.
    ///
    /// Nothing is offered until this is called: a client that is told SASL is
    /// available and finds no mechanism behind it is worse off than one that
    /// was never offered it.
    pub fn set_sasl(&self, mechanisms: std::sync::Arc<SaslMechanisms>, authz: Authz) {
        *self.inner.sasl.lock().unwrap() = Some(SaslConfig { mechanisms, authz });
    }

    /// The SASL configuration, if SASL is enabled.
    pub fn sasl(&self) -> Option<SaslConfig> {
        self.inner.sasl.lock().unwrap().clone()
    }

    /// Who a SASL client has to be to be let in.
    ///
    /// With SASL off, nobody is checked: the other security types have no name
    /// to check a list against.
    pub fn sasl_authz(&self) -> Authz {
        self.sasl().map(|sasl| sasl.authz).unwrap_or_default()
    }

    /// Disconnect a client, by shutting its socket down.
    pub fn disconnect_client(&self, id: ClientId) {
        if let Some(handle) = self.inner.clients.read().unwrap().get(&id) {
            handle.disconnect();
        }
    }

    /// Report a listening socket, for the `Listeners` D-Bus property.
    ///
    /// There is more than one when `--websocket` is used: the VNC socket and
    /// the WebSocket one are separate listeners, and a client of either is
    /// reported by its own entry.
    pub fn add_listener(&self, listener: ListenerInfo) {
        self.inner.listener.lock().unwrap().push(listener);
    }

    /// Register a graphic console, and listen to its display updates.
    pub async fn add_graphic_console(&self, index: u32) -> Result<GraphicConsole> {
        let console = GraphicConsole::new(&self.inner.conn, index).await?;
        console
            .register_listener(Arc::downgrade(&self.inner))
            .await?;
        self.inner
            .displays
            .write()
            .unwrap()
            .insert(index, Display::Graphic(console.clone()));
        Ok(console)
    }

    /// Register a text console, and return the display index it was given.
    pub fn add_text_console(&self, console: TextConsole) -> u32 {
        let mut displays = self.inner.displays.write().unwrap();
        let index = displays.keys().copied().max().map_or(0, |i| i + 1);
        displays.insert(index, Display::Text(console));
        index
    }

    /// Notify the clients that the content of console `index` changed.
    pub(crate) fn console_updated(&self, index: u32, damage: Option<Vec<Rect>>) {
        self.inner.console_updated(index, damage);
    }

    /// The clipboard peer, once it has been registered with QEMU.
    pub fn clipboard(&self) -> Option<Clipboard> {
        self.inner.clipboard.lock().unwrap().clone()
    }

    /// Store the clipboard peer.
    pub fn set_clipboard(&self, clipboard: Clipboard) {
        *self.inner.clipboard.lock().unwrap() = Some(clipboard);
    }

    /// Take ownership of an accepted client socket.
    pub fn add_client(&self, stream: TcpStream, addr: SocketAddr) -> Result<ClientId> {
        // Counted here rather than in the accept loop, so it is right however the
        // connection arrived — and so a test that adds a client directly is
        // counted, which is the only way this counter can be tested at all.
        crate::counters::counters().clients.bump();
        self.add_transport(stream, addr, false, Vec::new())
    }

    /// Take ownership of an accepted WebSocket, and serve the RFB stream it
    /// carries.
    #[cfg(feature = "websockets")]
    pub fn add_websocket_client(&self, stream: TcpStream, addr: SocketAddr) -> Result<ClientId> {
        self.add_transport(stream, addr, true, Vec::new())
    }

    /// The same, for a socket whose HTTP request was already read.
    ///
    /// The HTTP server reads the request to tell an upgrade from a page; the
    /// bytes are replayed into the WebSocket handshake.
    #[cfg(feature = "websockets")]
    pub fn add_websocket_client_replaying(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
        replay: Vec<u8>,
    ) -> Result<ClientId> {
        self.add_transport(stream, addr, true, replay)
    }

    /// Take ownership of an accepted connection, and serve it.
    fn add_transport(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
        websocket: bool,
        replay: Vec<u8>,
    ) -> Result<ClientId> {
        let id = self.inner.next_client_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = async_channel::unbounded();
        let handle = Arc::new(events::ClientHandle {
            info: ClientInfo::new(id, addr, websocket),
            events: tx.clone(),
            // **Ready from the first moment**, not once the handshake has
            // finished. A client that connects and then says nothing is the one
            // `disconnect_client` exists for, and it used to be the one case
            // where it could not do anything: the shutdown handle did not exist
            // yet, and the `Terminate` event was queued for a task parked on
            // the handshake rather than on the event loop. The entry then leaked
            // for the life of the process. See `events::Disconnect::from_stream`.
            disconnect: RwLock::new(Some(
                events::Disconnect::from_stream(&stream).map_err(qemu_display::Error::from)?,
            )),
        });
        let info = handle.info.clone();
        self.inner.clients.write().unwrap().insert(id, handle);
        let _ = self
            .inner
            .events
            .try_send(ServerEvent::ClientConnected(info));
        let server = self.clone();
        let jpeg_quality = self.jpeg_quality();
        // The thread is what owns the connection: the handshake and the whole
        // session run in one task, so a transport that can not be duplicated
        // is served as well as one that can.
        thread::Builder::new()
            .name(format!("vnc-client-{id}"))
            .spawn(move || {
                let transport = block_on(async {
                    #[cfg(feature = "websockets")]
                    if websocket {
                        return ClientTransport::websocket_replaying(stream, replay).await;
                    }
                    let _ = websocket;
                    let _ = replay;
                    ClientTransport::socket(stream)
                });
                match transport {
                    Ok(transport) => client_thread(server, id, transport, rx, jpeg_quality),
                    Err(e) => {
                        warn!("failed to take over the socket of {addr}: {e}");
                        server.remove_client(id);
                    }
                }
            })?;
        Ok(id)
    }

    /// Forget a disconnected client.
    fn remove_client(&self, id: ClientId) {
        self.inner.clients.write().unwrap().remove(&id);
        let _ = self
            .inner
            .events
            .try_send(ServerEvent::ClientDisconnected(id));
    }

    /// Ask all the clients to disconnect, and stop the server.
    pub fn terminate_clients(&self) {
        for client in self.inner.clients.read().unwrap().values() {
            let _ = client.events.try_send(ClientEvent::Terminate);
            client.disconnect();
        }
    }

    /// A VNC client took ownership of the clipboard.
    pub(crate) fn client_cut_text(&self, text: &str) {
        let Some(clipboard) = self.clipboard() else {
            warn!("got clipboard data, but no clipboard peer is registered");
            return;
        };
        if let Err(e) =
            block_on(clipboard.grab(ClipboardSelection::Clipboard, text.as_bytes().to_vec()))
        {
            warn!("failed to grab the clipboard: {e}");
        }
    }
}

/// Run an async future from a synchronous context, such as a client thread.
///
/// The zbus connection drives its own I/O in the background, so this only
/// blocks until the remote peer has replied.
pub(super) fn block_on<F: Future>(future: F) -> F::Output {
    async_io::block_on(future)
}
