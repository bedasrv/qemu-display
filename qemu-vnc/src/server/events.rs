//! The messages that travel between the server, its clients and the main
//! loop.
//!
//! They are the seam of the threading model: the console listeners and the
//! main loop push [`ServerEvent`]s, a per-client task pushes and receives
//! [`ClientEvent`]s, and nothing else crosses a thread boundary.

use std::net::TcpStream;
use std::sync::{Arc, RwLock};

use async_channel::Sender;

use super::{ClientId, ClientInfo, TcpSession};
use crate::rfb::{Event as VncEvent, Rect};

/// Events sent by the client threads to the main loop.
#[derive(Clone, Debug)]
pub enum ServerEvent {
    /// A TCP connection has been accepted.
    ClientConnected(ClientInfo),
    /// A client completed the RFB handshake.
    ClientInitialized(ClientId),
    /// A client disconnected.
    ClientDisconnected(ClientId),
    /// The server should stop, with the given reason.
    Terminate(String),
}

/// Events sent to a client thread.
#[derive(Debug)]
pub(crate) enum ClientEvent {
    /// An event received from the client.
    Vnc(VncEvent),
    /// The content of a console changed, in the given rectangles. `None` is the
    /// whole console, which is what a new scanout and a cursor change are.
    ///
    /// A **list**, not one rectangle, because the rectangles are the *runs of
    /// changed pixels*, and a guest update is generally several runs: QEMU's
    /// `vnc_job_add_rect` is called once per run, so its job carries several
    /// rectangles and its single `FramebufferUpdate` carries them all.
    ///
    /// `Some` and empty means "nothing changed" — the common case once damage is
    /// found by comparison rather than taken on trust — which is different from
    /// `None` and must not be read as the whole console.
    ConsoleUpdate(u32, Option<Vec<Rect>>),
    /// New clipboard content to send to the client.
    CutText(String),
    /// A block of audio samples, and the format they are in.
    ///
    /// The format is the guest's, and it travels with the samples because a
    /// client is sent them in the format *it* asked for: QEMU's backend
    /// converts to what the client negotiated rather than sending the guest's
    /// format and hoping, and a client that asked for stereo S16 is entitled to
    /// stereo S16.
    Audio(crate::rfb::audio::Format, Vec<u8>),
    /// A stream the guest has started, as `Out::Begin`. Clients are told with
    /// `VNC_MSG_SERVER_QEMU_AUDIO_BEGIN`, once per stream and not once per
    /// session.
    AudioBegin,
    /// A stream the guest has stopped, so that the audio a converter is holding
    /// back can be released and the client told the stream is over.
    AudioEnd,
    /// The client should go away.
    Terminate,
}

/// A handle on a connected client, held by the server.
pub(crate) struct ClientHandle {
    pub(crate) info: ClientInfo,
    pub(crate) events: Sender<ClientEvent>,
    /// A way to shut the connection down, once the client is initialized.
    pub(crate) disconnect: RwLock<Option<Disconnect>>,
}

impl ClientHandle {
    /// Disconnect the client, by shutting down its socket.
    pub(crate) fn disconnect(&self) {
        // A `Terminate` wakes the task even if the socket is not the one it
        // is parked on.
        let _ = self.events.try_send(ClientEvent::Terminate);
        if let Some(disconnect) = self.disconnect.read().unwrap().as_ref() {
            let _ = disconnect.shutdown();
        }
    }
}

/// A handle on the socket of a client, to shut the connection down from
/// another thread.
///
/// A session is owned by the task that reads and writes it, so a disconnect
/// from elsewhere can only go through the socket underneath.
#[derive(Clone)]
pub(crate) struct Disconnect(Arc<TcpStream>);

impl Disconnect {
    /// Take the shutdown handle out of a session.
    pub(crate) fn new(session: &TcpSession) -> Self {
        Self(session.shutdown_handle())
    }

    /// A handle on a socket that has been accepted but not yet spoken to.
    ///
    /// **Installed when the client is added, not when it finishes its
    /// handshake**, and that ordering is the fix rather than a detail.
    ///
    /// A client that connects and then says nothing — hangs in the handshake,
    /// or is a port scanner — is precisely the one an administrator calls
    /// `disconnect_client` about, and it used to be the one case where that call
    /// did nothing at all. Both halves of it failed together: the shutdown
    /// handle did not exist yet, and the `Terminate` event went into a queue
    /// nobody was reading, because the task was parked on the handshake rather
    /// than on the event loop. The entry then stayed in the client table for the
    /// life of the process, still being handed damage for a socket nobody had
    /// answered for.
    ///
    /// Found by `a_client_the_server_hangs_up_on_is_forgotten`, which is the
    /// first test to touch this path at all — it had none, and the untested
    /// path is why this sat unnoticed.
    pub(crate) fn from_stream(stream: &TcpStream) -> std::io::Result<Self> {
        Ok(Self(Arc::new(stream.try_clone()?)))
    }

    /// Shut the connection down, which unblocks a pending read.
    pub(crate) fn shutdown(&self) -> std::io::Result<()> {
        self.0.shutdown(std::net::Shutdown::Both)
    }
}
