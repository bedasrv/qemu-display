//! A minimal RFB (VNC) server, vendored from the [`vnc`] crate.
//!
//! [`vnc`]: https://github.com/elmarco/rust-vnc
//!
//! # Provenance
//!
//! `protocol.rs`, `server.rs` and `des.rs` come from the `server` branch of
//! <https://github.com/elmarco/rust-vnc>, which is `MIT OR Apache-2.0` (the
//! `des.rs` notice is kept verbatim). They are vendored because the server
//! half of that crate is not published on crates.io, and because we need to
//! change the entry point: the transport is generic, and the security
//! handshake is a policy rather than a hard-coded `None`.
//!
//! The crate's `client.rs`, `proxy.rs` and `zrle.rs` are *not* vendored: they
//! are client-side, and a client is a test harness concern, not a server one.
//!
//! # What is left to do here
//!
//! The encoders are not part of the vendored code (the upstream `zrle.rs` is
//! client-side): `FramebufferUpdate::add_compressed_pixels()` takes data that
//! is already compressed, so the Tight/ZRLE/JPEG encoders are ours to write.
//! They are in [`encodings`], together with the policy that chooses one per
//! client.
//!
//! # The transport
//!
//! A [`Session`] is served by a single task, which reads the client requests
//! and writes the updates on the same [`Transport`]: a WebSocket or a TLS
//! stream is one object and can not be shared with a reader thread. The
//! transport is therefore an asynchronous byte stream, and the protocol code
//! keeps its synchronous, `read_exact` based shape — the session buffers what
//! it read and only hands the parser bytes that are all there.
//!
//! A plain socket is [`async_io::Async<TcpStream>`]; a WebSocket is the
//! `websocket` module, which presents the binary messages as the same byte
//! stream.

pub mod audio;
mod auth;
/// The vendored DES implementation, used by the VNC authentication.
///
/// It is public because a client needs it to answer a challenge.
pub mod des;
/// The pixel encodings we can send, and the policy that picks between them.
pub mod encodings;
/// The RFB messages and the pixel formats, as the specification numbers them.
///
/// Public because the specification's numbering is the thing a conformance
/// claim rests on, and a caller checking one — which of the pseudo-encodings
/// may be acknowledged with a bare rectangle, say — cannot check it through a
/// private module.
pub mod protocol;
mod sasl;
#[cfg(feature = "sasl")]
mod sasl_cyrus;
mod server;
#[cfg(feature = "websockets")]
pub mod websocket;

use futures::io::{AsyncRead, AsyncWrite};

pub use audio::{Command as AudioCommand, Format as AudioFormat, Sample as AudioSample};
pub use auth::{Password, SecurityPolicy, VncPassword};
pub use encodings::{Codec, Encoders, Policy};
pub use protocol::{Colour, Encoding, PixelFormat, Rect, Screen, SecurityType, Version};
pub use sasl::{
    Authz, Credentials, Endpoints as SaslEndpoints, Error as SaslError, Mechanism,
    Mechanisms as SaslMechanisms, Offered as SaslMechanism, Sasl, Step as SaslStep,
    default_mechanisms,
};
pub use server::{Event, FramebufferUpdate, Handshake, ServerMessage, Session};

/// A session served over a socket, the usual case.
pub type TcpSession = Session<ClientTransport>;

/// A `Result` alias for this module.
pub type Result<T> = std::result::Result<T, Error>;

/// The errors of the RFB protocol implementation.
#[derive(Debug)]
pub enum Error {
    /// An I/O error occurred.
    Io(std::io::Error),
    /// The peer sent something we did not expect.
    Unexpected(&'static str),
    /// The peer refused the connection, or we could not serve it.
    Server(String),
    /// None of the security types we support was accepted by the peer.
    AuthenticationUnavailable,
    /// The peer failed to authenticate.
    AuthenticationFailure(String),
    /// The peer disconnected.
    Disconnected,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(inner) => inner.fmt(f),
            Error::Unexpected(descr) => write!(f, "unexpected {descr}"),
            Error::Server(descr) => write!(f, "server error: {descr}"),
            Error::AuthenticationFailure(descr) => write!(f, "authentication failure: {descr}"),
            Error::AuthenticationUnavailable => write!(f, "authentication unavailable"),
            Error::Disconnected => write!(f, "disconnected"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::Io(error)
    }
}

impl From<sasl::Error> for Error {
    /// A SASL failure is reported as the failure it is: the mechanism refused
    /// the client, and the detail it gave is what the client is told.
    fn from(error: sasl::Error) -> Error {
        match error {
            sasl::Error::Refused(detail) | sasl::Error::UnsupportedMechanism(detail) => {
                Error::AuthenticationFailure(detail)
            }
            sasl::Error::Malformed(what) => Error::Unexpected(what),
            other => Error::Server(other.to_string()),
        }
    }
}

/// A duplex byte stream a client is served over.
///
/// A session is driven by a single task, which reads the client requests and
/// writes the frame buffer updates on the same stream: a WebSocket or a TLS
/// stream can not be shared between two threads, so there is no reader thread
/// to hide behind. The transport is therefore an asynchronous byte stream, and
/// the client task polls it together with the events of the server.
///
/// A `TcpStream` becomes one with `async_io::Async`, a WebSocket with the
/// `websocket` module, which is behind the `websockets` feature.
pub trait Transport: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    /// Shut both directions down, to unblock a pending read from another
    /// thread, as when a client is disconnected.
    fn shutdown_transport(&self) -> std::io::Result<()>;
}

impl Transport for async_io::Async<std::net::TcpStream> {
    fn shutdown_transport(&self) -> std::io::Result<()> {
        // `TcpStream::shutdown` only needs a shared reference, and waking the
        // reactor is what unblocks the pending read.
        self.get_ref().shutdown(std::net::Shutdown::Both)
    }
}

/// The stream a VNC client is served over: a plain socket, or a WebSocket
/// carrying the same byte stream in binary messages.
#[allow(clippy::large_enum_variant)] // The variants are close in size.
pub enum ClientTransport {
    /// A plain TCP connection.
    Socket {
        /// The connection itself.
        stream: async_io::Async<std::net::TcpStream>,
        /// A second handle on the socket, to shut the connection down from
        /// another thread.
        shutdown: std::sync::Arc<std::net::TcpStream>,
    },
    /// A WebSocket connection, the byte stream carried in binary messages.
    #[cfg(feature = "websockets")]
    WebSocket {
        /// The connection, after the HTTP upgrade.
        stream: websocket::Stream,
        /// A second handle on the socket underneath, to shut the connection
        /// down from another thread.
        shutdown: std::sync::Arc<std::net::TcpStream>,
    },
}

impl ClientTransport {
    /// Take a socket over, and make it usable as a client transport.
    pub fn socket(stream: std::net::TcpStream) -> std::io::Result<Self> {
        let shutdown = std::sync::Arc::new(stream.try_clone()?);
        Ok(Self::Socket {
            stream: async_io::Async::new(stream)?,
            shutdown,
        })
    }

    /// Upgrade a socket to a WebSocket, and serve the RFB stream it carries.
    #[cfg(feature = "websockets")]
    pub async fn websocket(stream: std::net::TcpStream) -> std::io::Result<Self> {
        Self::websocket_replaying(stream, Vec::new()).await
    }

    /// Upgrade a socket whose request bytes were already read.
    ///
    /// The HTTP server reads the request to tell an upgrade from a page, so the
    /// handshake is given those bytes back before the rest of the socket.
    #[cfg(feature = "websockets")]
    pub async fn websocket_replaying(
        stream: std::net::TcpStream,
        replay: Vec<u8>,
    ) -> std::io::Result<Self> {
        let shutdown = std::sync::Arc::new(stream.try_clone()?);
        let stream = async_io::Async::new(stream)?;
        let stream = websocket::accept(websocket::Replay::new(stream, replay)).await?;
        Ok(Self::WebSocket { stream, shutdown })
    }

    /// Whether this is a WebSocket connection, as the `WebSocket` property of
    /// `org.qemu.Vnc1.Client` reports it.
    pub fn is_websocket(&self) -> bool {
        match self {
            ClientTransport::Socket { .. } => false,
            #[cfg(feature = "websockets")]
            ClientTransport::WebSocket { .. } => true,
        }
    }

    /// A handle on the socket underneath, to shut the connection down.
    pub fn shutdown_handle(&self) -> std::sync::Arc<std::net::TcpStream> {
        match self {
            ClientTransport::Socket { shutdown, .. } => shutdown.clone(),
            #[cfg(feature = "websockets")]
            ClientTransport::WebSocket { shutdown, .. } => shutdown.clone(),
        }
    }

    /// The two ends of the connection, which SASL reports a client by.
    pub fn endpoints(&self) -> std::io::Result<sasl::Endpoints> {
        let socket = self.as_socket();
        Ok(sasl::Endpoints::new(
            socket.local_addr()?,
            socket.peer_addr()?,
        ))
    }

    /// The socket underneath, spoken to directly or wrapped in a WebSocket.
    fn as_socket(&self) -> &std::net::TcpStream {
        match self {
            ClientTransport::Socket { shutdown, .. } => shutdown,
            #[cfg(feature = "websockets")]
            ClientTransport::WebSocket { shutdown, .. } => shutdown,
        }
    }
}

impl Transport for ClientTransport {
    fn shutdown_transport(&self) -> std::io::Result<()> {
        self.shutdown_handle().shutdown(std::net::Shutdown::Both)
    }
}

impl AsyncRead for ClientTransport {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ClientTransport::Socket { stream, .. } => std::pin::Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "websockets")]
            ClientTransport::WebSocket { stream, .. } => {
                std::pin::Pin::new(stream).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for ClientTransport {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ClientTransport::Socket { stream, .. } => {
                std::pin::Pin::new(stream).poll_write(cx, buf)
            }
            #[cfg(feature = "websockets")]
            ClientTransport::WebSocket { stream, .. } => {
                std::pin::Pin::new(stream).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientTransport::Socket { stream, .. } => std::pin::Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "websockets")]
            ClientTransport::WebSocket { stream, .. } => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ClientTransport::Socket { stream, .. } => std::pin::Pin::new(stream).poll_close(cx),
            #[cfg(feature = "websockets")]
            ClientTransport::WebSocket { stream, .. } => std::pin::Pin::new(stream).poll_close(cx),
        }
    }
}

/// How a session is created, i.e. what the server offers the client.
#[derive(Debug)]
pub struct ServerOptions<'a> {
    /// The desktop name announced to the client.
    pub name: &'a str,
    /// The pixel format of the frame buffer.
    pub pixel_format: PixelFormat,
    /// The authentication the client has to pass.
    pub security: SecurityPolicy<'a>,
    /// A fixed challenge for the VNC authentication, instead of a random
    /// one. Only useful for tests.
    pub challenge: Option<[u8; 16]>,
    /// The two ends of the connection, which a SASL mechanism is told about.
    pub endpoints: sasl::Endpoints,
}

impl<'a> ServerOptions<'a> {
    /// A server that does not authenticate its clients.
    pub fn anonymous(name: &'a str, pixel_format: PixelFormat) -> Self {
        Self {
            name,
            pixel_format,
            security: SecurityPolicy::None,
            challenge: None,
            endpoints: sasl::Endpoints::default(),
        }
    }

    /// A server that requires its clients to authenticate.
    pub fn authenticated(name: &'a str, pixel_format: PixelFormat, password: &'a Password) -> Self {
        Self {
            name,
            pixel_format,
            security: SecurityPolicy::VncAuth(password),
            challenge: None,
            endpoints: sasl::Endpoints::default(),
        }
    }

    /// A server that requires its clients to authenticate with SASL.
    pub fn with_sasl(
        name: &'a str,
        pixel_format: PixelFormat,
        mechanisms: &'a sasl::Mechanisms,
    ) -> Self {
        Self {
            name,
            pixel_format,
            security: SecurityPolicy::Sasl(mechanisms),
            challenge: None,
            endpoints: sasl::Endpoints::default(),
        }
    }

    /// Tell the handshake where the client connected from, which is what a
    /// SASL mechanism is told about it.
    pub fn at(mut self, endpoints: sasl::Endpoints) -> Self {
        self.endpoints = endpoints;
        self
    }
}

/// Generate the 16 bytes of a VNC authentication challenge.
pub(crate) fn random_challenge() -> Result<[u8; 16]> {
    #[cfg(unix)]
    {
        use std::io::Read;

        let mut challenge = [0u8; 16];
        let mut file = std::fs::File::open("/dev/urandom")?;
        file.read_exact(&mut challenge)?;
        Ok(challenge)
    }
    #[cfg(not(unix))]
    {
        // Refuse rather than use a predictable challenge.
        Err(Error::Server(
            "no random source for the VNC authentication challenge".into(),
        ))
    }
}
