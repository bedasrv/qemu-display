use async_broadcast::{broadcast, Receiver, Sender};
use async_lock::RwLock;
use futures::Stream;
use std::{
    collections::HashMap,
    fmt::Debug,
    os::unix::net::UnixStream,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::{Chardev, Error, Result};
#[cfg(windows)]
use uds_windows::UnixStream;

/// Backend trait for a concrete USB redirection implementation.
///
/// `UsbRedir` only allocates a QEMU usbredir chardev and registers one end of a
/// socket pair through D-Bus. The backend owns the other end of the stream and
/// is responsible for the actual usbredir protocol bytes that flow over it.
#[async_trait::async_trait]
pub trait UsbRedirBackend: Send + Sync {
    /// Stable identity used by `UsbRedir` to track the active session.
    type Key: Send + Sync + Eq + std::hash::Hash;
    /// Owned data consumed by the backend when a session starts.
    type SessionInput: Send;
    type Session: Send;

    /// Starts a redirection session using the QEMU-facing stream.
    ///
    /// The stream carries raw usbredir protocol data.
    async fn start_session(
        &self,
        input: Self::SessionInput,
        stream: UnixStream,
    ) -> Result<Self::Session>;
}

#[derive(Debug, Clone, Copy)]
enum Event {
    NFreeChannels(i32),
}

struct Inner<B: UsbRedirBackend> {
    /// QEMU chardev objects.
    chardevs: Vec<Chardev>,
    /// Active device sessions. Keeping the session value alive keeps the
    /// backend-side stream/task alive.
    sessions: HashMap<B::Key, B::Session>,
    channel: (Sender<Event>, Receiver<Event>),
    backend: B,
}

impl<B: UsbRedirBackend> Debug for Inner<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("chardevs", &self.chardevs)
            .field("sessions_len", &self.sessions.len())
            .field("backend_type", &std::any::type_name::<B>())
            .finish_non_exhaustive()
    }
}

impl<B: UsbRedirBackend> Inner<B> {
    // could make use of async combinators..
    async fn first_available_chardev(&self) -> Option<&Chardev> {
        for c in &self.chardevs {
            if c.proxy.owner().await.unwrap_or_default().is_empty() {
                return Some(c);
            }
        }
        None
    }

    async fn n_available_chardev(&self) -> usize {
        let mut n = 0;
        for c in &self.chardevs {
            if c.proxy.owner().await.unwrap_or_default().is_empty() {
                n += 1;
            }
        }
        n
    }
}

/// Small manager for QEMU usbredir chardev slots.
#[derive(Debug, Clone)]
pub struct UsbRedir<B: UsbRedirBackend> {
    inner: Arc<RwLock<Inner<B>>>,
}

impl<B: UsbRedirBackend> UsbRedir<B> {
    /// Creates a manager from already-discovered QEMU usbredir chardevs.
    pub fn new(chardevs: Vec<Chardev>, backend: B) -> Self {
        let mut channel = broadcast(1);
        channel.0.set_overflow(true);
        Self {
            inner: Arc::new(RwLock::new(Inner {
                chardevs,
                channel,
                sessions: Default::default(),
                backend,
            })),
        }
    }

    /// Connects one device to a QEMU usbredir chardev.
    pub async fn connect_device(&self, key: B::Key, input: B::SessionInput) -> Result<bool> {
        let mut inner = self.inner.write().await;
        if inner.sessions.contains_key(&key) {
            return Ok(true);
        }

        // We should do better and watch for owner properties changes, but this would require tasks
        // anticipate result
        let mut nfree = inner.n_available_chardev().await as _;

        let chardev = inner
            .first_available_chardev()
            .await
            .ok_or_else(|| Error::Failed("There are no free USB channels".into()))?;

        let (stream, peer) = UnixStream::pair()?;
        let session = inner.backend.start_session(input, stream).await?;
        chardev.proxy.register((&peer).into()).await?;
        inner.sessions.insert(key, session);
        nfree -= 1;

        let _ = inner.channel.0.broadcast(Event::NFreeChannels(nfree)).await;

        Ok(true)
    }

    /// Disconnects one device from its QEMU usbredir chardev.
    ///
    /// Dropping the stored session lets the backend tear down the stream.
    pub async fn disconnect_device(&self, key: &B::Key) -> Result<bool> {
        let mut inner = self.inner.write().await;
        if inner.sessions.remove(key).is_none() {
            return Ok(false);
        }

        let nfree = inner.n_available_chardev().await as _;
        let _ = inner.channel.0.broadcast(Event::NFreeChannels(nfree)).await;

        Ok(false)
    }

    /// Returns whether this manager has an active session for `key`.
    pub async fn is_device_connected(&self, key: &B::Key) -> bool {
        let inner = self.inner.read().await;

        inner.sessions.contains_key(key)
    }

    /// Returns the number of QEMU usbredir chardevs with no current D-Bus owner.
    pub async fn n_free_channels(&self) -> i32 {
        let inner = self.inner.read().await;

        inner.n_available_chardev().await as _
    }

    /// Receives updates whenever this manager changes the free chardev count.
    pub async fn receive_n_free_channels(&self) -> Pin<Box<dyn Stream<Item = i32>>> {
        let inner = self.inner.read().await;

        Box::pin(NFreeChannelsStream {
            receiver: inner.channel.1.clone(),
        })
    }
}

#[derive(Debug)]
struct NFreeChannelsStream {
    receiver: Receiver<Event>,
}

impl Stream for NFreeChannelsStream {
    type Item = i32;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = Pin::new(self);

        match Stream::poll_next(Pin::new(&mut this.receiver), cx) {
            Poll::Ready(Some(Event::NFreeChannels(n))) => Poll::Ready(Some(n)),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
