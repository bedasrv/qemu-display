//! The `org.qemu.Vnc1` D-Bus interfaces, to manage and monitor the server.
//!
//! Port of `dbus.c`, which exports `org.qemu.Vnc1.Server` and
//! `org.qemu.Vnc1.Client` on the D-Bus connection to QEMU.

// The interface macro generates the signal methods, which we do not document.
#![allow(missing_docs)]

use std::collections::HashMap;
use std::net::SocketAddr;

use qemu_display::Error;
use tracing::{debug, info, warn};
use zbus::object_server::SignalEmitter;
use zbus::{Fd, ObjectPath, OwnedObjectPath, Variant};
use zbus::{Connection, fdo};

use crate::server::{ClientId, ClientInfo, Server};

/// The object path of the `org.qemu.Vnc1.Server` interface.
pub const SERVER_PATH: &str = "/org/qemu/Vnc1/Server";
/// The object path prefix of the `org.qemu.Vnc1.Client` interfaces.
pub const CLIENT_PATH_PREFIX: &str = "/org/qemu/Vnc1/Client_";
/// The bus name owned by the VNC server, on a message bus connection.
pub const BUS_NAME: &str = "org.qemu.vnc";

/// The `org.qemu.Vnc1.Server` interface.
pub struct Vnc1Server {
    server: Server,
}

impl Vnc1Server {
    /// Export the server interface, and own `org.qemu.vnc` if we are
    /// connected to a message bus.
    pub async fn setup(conn: &Connection, server: Server) -> Result<(), Error> {
        conn.object_server()
            .at(SERVER_PATH, Vnc1Server { server })
            .await?;
        if conn.is_bus() {
            match conn.request_name(BUS_NAME).await {
                Ok(_) => info!("owned {BUS_NAME}"),
                Err(e) => warn!("failed to own {BUS_NAME}: {e}"),
            }
        }
        Ok(())
    }
}

#[zbus::interface(name = "org.qemu.Vnc1.Server")]
impl Vnc1Server {
    /// The VM name.
    #[zbus(property)]
    fn name(&self) -> String {
        self.server.vm_name().into()
    }

    /// The primary authentication method.
    #[zbus(property)]
    fn auth(&self) -> String {
        self.server.auth_method().into()
    }

    /// The VEncrypt sub-authentication method, empty as we have none.
    #[zbus(property)]
    fn vencrypt_sub_auth(&self) -> String {
        String::new()
    }

    /// The object paths of the connected clients.
    #[zbus(property)]
    fn clients(&self) -> Vec<OwnedObjectPath> {
        self.server
            .clients()
            .iter()
            .filter_map(|c| OwnedObjectPath::try_from(c.path()).ok())
            .collect()
    }

    /// The listening sockets.
    #[zbus(property)]
    fn listeners(&self) -> Vec<HashMap<&'static str, Variant<'static>>> {
        self.server
            .listeners()
            .iter()
            .map(|l| {
                HashMap::from([
                    ("Host", Variant::new(l.addr.ip().to_string())),
                    ("Service", Variant::new(l.service())),
                    ("Family", Variant::new(l.family())),
                    ("WebSocket", Variant::new(l.websocket)),
                    ("Auth", Variant::new(l.auth.clone())),
                    ("VencryptSubAuth", Variant::new("")),
                ])
            })
            .collect()
    }

    /// Change the VNC password.
    ///
    /// The clients that are already connected are not affected.
    async fn set_password(&self, password: &str) -> fdo::Result<()> {
        self.server.passwords().set(password);
        info!("VNC password set");
        Ok(())
    }

    /// Set the password expiry.
    ///
    /// `now` and `never` are understood, as well as a number of seconds from
    /// now (`+N`), or an absolute epoch time (`N`).
    async fn expire_password(&self, time: &str) -> fdo::Result<()> {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let invalid = || fdo::Error::InvalidArgs(format!("Invalid time format: {time}"));
        let now = SystemTime::now();
        let expiry = match time {
            // Expire the password: the clients will not have to authenticate
            // any more.
            "now" => {
                self.server.passwords().set_expiry(Some(now));
                None
            }
            "never" => None,
            t if t.starts_with('+') => {
                let seconds: u64 = t[1..].parse().map_err(|_| invalid())?;
                Some(now + Duration::from_secs(seconds))
            }
            t => {
                let epoch: u64 = t.parse().map_err(|_| invalid())?;
                Some(UNIX_EPOCH + Duration::from_secs(epoch))
            }
        };
        self.server.passwords().set_expiry(expiry);
        info!(%time, "VNC password expiry set");
        Ok(())
    }

    /// Reload the TLS certificates from disk.
    async fn reload_certificates(&self) -> fdo::Result<()> {
        Err(fdo::Error::NotSupported("TLS is not supported".into()))
    }

    /// Add a client from an already connected socket.
    async fn add_client(&self, socket: Fd<'_>, skipauth: bool) -> fdo::Result<()> {
        if skipauth {
            debug!("skipauth is ignored, we do not support authentication");
        }
        add_client_socket(&self.server, socket)
    }

    /// Emitted when a VNC client TCP connection is established.
    #[zbus(signal)]
    async fn client_connected(
        emitter: &SignalEmitter<'_>,
        client: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    /// Emitted when a VNC client has completed authentication.
    #[zbus(signal)]
    async fn client_initialized(
        emitter: &SignalEmitter<'_>,
        client: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    /// Emitted when a VNC client disconnects.
    #[zbus(signal)]
    async fn client_disconnected(
        emitter: &SignalEmitter<'_>,
        client: ObjectPath<'_>,
    ) -> zbus::Result<()>;

    /// Emitted when the VNC server is shutting down cleanly.
    #[zbus(signal)]
    async fn leaving(emitter: &SignalEmitter<'_>, reason: &str) -> zbus::Result<()>;
}

/// The `org.qemu.Vnc1.Client` interface, exported for each client.
///
/// It reads the client state rather than a snapshot of it, because the object
/// is exported when a connection is accepted and one of the properties — the
/// SASL username — is not known until the handshake that follows has finished.
pub struct Vnc1Client {
    server: Server,
    id: ClientId,
}

impl Vnc1Client {
    /// The client as the server knows it, if it is still connected.
    fn info(&self) -> Option<ClientInfo> {
        self.server
            .clients()
            .into_iter()
            .find(|client| client.id == self.id)
    }
}

#[zbus::interface(name = "org.qemu.Vnc1.Client")]
impl Vnc1Client {
    /// The client IP address.
    #[zbus(property)]
    fn host(&self) -> String {
        self.info().map(|info| info.host).unwrap_or_default()
    }

    /// The client port.
    #[zbus(property)]
    fn service(&self) -> String {
        self.info().map(|info| info.service).unwrap_or_default()
    }

    /// The address family.
    #[zbus(property)]
    fn family(&self) -> String {
        self.info().map(|info| info.family).unwrap_or_default()
    }

    /// Whether this is a WebSocket connection.
    #[zbus(property)]
    fn web_socket(&self) -> bool {
        self.info().is_some_and(|info| info.websocket)
    }

    /// The X.509 distinguished name, empty as we have no TLS.
    #[zbus(property)]
    fn x509_dname(&self) -> String {
        String::new()
    }

    /// The name a SASL exchange established, empty as we have no SASL.
    #[zbus(property)]
    fn sasl_username(&self) -> String {
        self.info()
            .map(|info| info.sasl_username.read().unwrap().clone())
            .unwrap_or_default()
    }

    /// Emitted when the VNC client requests a guest shutdown.
    #[zbus(signal)]
    async fn shutdown_request(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    /// Emitted when the VNC client requests a guest reset.
    #[zbus(signal)]
    async fn reset_request(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

/// Export the client object, and emit `ClientConnected`.
pub async fn client_connected(
    conn: &Connection,
    server: &Server,
    info: &ClientInfo,
) -> Result<(), Error> {
    let path = ObjectPath::try_from(info.path())?;
    conn.object_server()
        .at(
            &path,
            Vnc1Client {
                server: server.clone(),
                id: info.id,
            },
        )
        .await?;
    emit(conn, &path, "ClientConnected").await?;
    Ok(())
}

/// Emit `ClientInitialized`.
pub async fn client_initialized(conn: &Connection, id: ClientId) -> Result<(), Error> {
    let path = ObjectPath::try_from(client_path(id))?;
    emit(conn, &path, "ClientInitialized").await?;
    Ok(())
}

/// Emit `ClientDisconnected`, and unexport the client object.
pub async fn client_disconnected(conn: &Connection, id: ClientId) -> Result<(), Error> {
    let path = ObjectPath::try_from(client_path(id))?;
    emit(conn, &path, "ClientDisconnected").await?;
    conn.object_server().remove::<Vnc1Client, _>(&path).await?;
    Ok(())
}

/// Emit `Leaving`, and unexport the server object.
pub async fn leaving(conn: &Connection, reason: &str) -> Result<(), Error> {
    let path = ObjectPath::try_from(SERVER_PATH)?;
    conn.emit_signal(
        None::<&str>,
        &path,
        "org.qemu.Vnc1.Server",
        "Leaving",
        &(reason,),
    )
    .await?;
    conn.object_server().remove::<Vnc1Server, _>(&path).await?;
    Ok(())
}

/// The object path of a client.
fn client_path(id: ClientId) -> String {
    format!("{CLIENT_PATH_PREFIX}{id}")
}

/// Emit a signal of the `org.qemu.Vnc1.Server` interface.
async fn emit(conn: &Connection, path: &ObjectPath<'_>, member: &str) -> Result<(), Error> {
    conn.emit_signal(
        None::<&str>,
        path,
        "org.qemu.Vnc1.Server",
        member,
        &(path.to_owned(),),
    )
    .await?;
    Ok(())
}

/// Take over a socket passed over D-Bus, and use it as a VNC client.
#[cfg(unix)]
fn add_client_socket(server: &Server, socket: Fd<'_>) -> fdo::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::raw::c_int;

    // The message owns the socket, and closes it once the call returns.
    // SAFETY: the D-Bus message holds a valid file descriptor.
    let fd: RawFd = unsafe { libc::dup(socket.as_raw_fd()) };
    if fd < 0 {
        return Err(fdo::Error::Failed(
            std::io::Error::last_os_error().to_string(),
        ));
    }

    // The vnc crate needs a TcpStream, refuse anything else rather than
    // pretending that a Unix socket is a TCP one.
    let mut domain: c_int = 0;
    let mut len = std::mem::size_of::<c_int>() as libc::socklen_t;
    // SAFETY: `fd` is a valid socket, and we only read the option back.
    let res = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            (&raw mut domain).cast(),
            &raw mut len,
        )
    };
    if res != 0 || !matches!(domain, libc::AF_INET | libc::AF_INET6) {
        // SAFETY: we own the duplicated descriptor.
        unsafe { libc::close(fd) };
        return Err(fdo::Error::InvalidArgs(
            "only TCP sockets are supported".into(),
        ));
    }

    // SAFETY: `fd` is a connected TCP socket, and we own it.
    let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    let addr = stream
        .peer_addr()
        .or_else(|_| stream.local_addr())
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    server
        .add_client(stream, addr)
        .map_err(|e| fdo::Error::Failed(format!("Failed to add client: {e}")))?;
    Ok(())
}

/// Sockets can only be passed on unix.
#[cfg(not(unix))]
fn add_client_socket(_server: &Server, _socket: Fd<'_>) -> fdo::Result<()> {
    Err(fdo::Error::NotSupported(
        "Adding a client socket is not supported on this platform".into(),
    ))
}
