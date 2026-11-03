//! RFB over WebSocket, the transport QEMU's `-vnc ...,websocket=<port>`
//! serves.
//!
//! A WebSocket connection is an HTTP upgrade followed by the very same RFB
//! byte stream, carried in *binary* messages: what the session writes goes out
//! as one message per write, and what it reads is the concatenation of the
//! messages it is given. The framing is transparent, which is why only this
//! module knows about it.
//!
//! The client side of an upgrade is a `GET` with `Sec-WebSocket-Protocol:
//! binary`, and the server answers `101 Switching Protocols` before the RFB
//! handshake starts. A request that is not a WebSocket, or that offers a
//! sub-protocol other than `binary`, is refused before a single RFB byte is
//! sent. A client that offers no sub-protocol is accepted *without* one, as
//! websockify accepts it: noVNC 1.7.0 opens its socket with no protocols, and a
//! browser rejects a `101` that names one it did not ask for.

use std::pin::Pin;
use std::task::{Context, Poll};

use async_tungstenite::WebSocketStream;
use async_tungstenite::tungstenite::Message;
use async_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use futures::io::{AsyncRead, AsyncWrite};
use futures::{SinkExt, StreamExt};

/// The RFB sub-protocol of a WebSocket VNC connection.
///
/// The name has no number, unlike the RFB security types: the `binary`
/// sub-protocol *is* the standard. A client that asks for it gets it echoed; a
/// client that asks for nothing is not given it, because the handshake forbids
/// naming a sub-protocol the client did not offer.
const SUBPROTOCOL: &str = "binary";

/// A WebSocket connection over a socket, speaking the RFB byte stream.
pub type Stream = RfbWebSocket<Replay<async_io::Async<std::net::TcpStream>>>;

/// A stream that serves bytes already read from it, then reads its inner.
///
/// The HTTP request is read to find where it ends, so the handshake -- which
/// parses that request itself -- is given the bytes back through this wrapper
/// instead of finding them still in the socket.
pub struct Replay<S> {
    prefix: Vec<u8>,
    /// How much of `prefix` was served already.
    pos: usize,
    inner: S,
}

impl<S> Replay<S> {
    /// Serve `prefix` before anything read from `inner`.
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        if this.pos < this.prefix.len() && !buf.is_empty() {
            let len = (this.prefix.len() - this.pos).min(buf.len());
            buf[..len].copy_from_slice(&this.prefix[this.pos..this.pos + len]);
            this.pos += len;
            return Poll::Ready(Ok(len));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// Perform the HTTP upgrade of a WebSocket client, and check that it does not
/// ask for a sub-protocol other than RFB's.
///
/// On success the returned stream is the RFB byte stream: the request has been
/// consumed, and everything that follows is RFB.
pub async fn accept<S>(stream: S) -> Result<RfbWebSocket<S>, std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // The callback is a plain `FnOnce`, not a future: naming the function
    // rather than writing a lambda is what makes it work for any lifetime of
    // the request.
    let stream = async_tungstenite::accept_hdr_async(stream, select_subprotocol)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(RfbWebSocket {
        stream,
        read_queue: Vec::new(),
        read_pos: 0,
        write_queue: Vec::new(),
    })
}

/// Answer the upgrade with the RFB sub-protocol, or refuse it.
///
/// An offer of no sub-protocol at all is accepted and answered **without** one.
/// That is websockify's behaviour: its `CompatibleWebSocket::select_subprotocol`
/// returns `''` for an empty offer, and the response header is written only when
/// it names a protocol. It is also what noVNC 1.7.0 needs -- it opens its socket
/// with no protocols, and a browser rejects a `101` that names a sub-protocol
/// the request did not offer ("Response must not include 'Sec-WebSocket-Protocol'
/// header if not present in request").
///
/// An offer of protocols that do not include `binary` is refused: the client
/// asked for a stream this server does not speak, and accepting would send RFB
/// bytes to something expecting something else.
#[allow(clippy::result_large_err)] // The type is tungstenite's own.
fn select_subprotocol(
    request: &Request,
    mut response: Response,
) -> Result<Response, ErrorResponse> {
    let offered: Vec<&str> = request
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|protocol| !protocol.is_empty())
        .collect();
    if offered.is_empty() {
        // Nothing was offered, so nothing may be named in the answer.
        return Ok(response);
    }
    if !offered
        .iter()
        .any(|protocol| protocol.eq_ignore_ascii_case(SUBPROTOCOL))
    {
        // Name the sub-protocol we do speak, so a well behaved client can
        // retry with it.
        let mut error =
            ErrorResponse::new(Some(format!("the {SUBPROTOCOL} sub-protocol is required")));
        error.headers_mut().insert(
            "sec-websocket-protocol",
            SUBPROTOCOL.parse().expect("a valid header value"),
        );
        return Err(error);
    }
    response.headers_mut().insert(
        "sec-websocket-protocol",
        SUBPROTOCOL.parse().expect("a valid header"),
    );
    Ok(response)
}

/// A WebSocket, seen as the RFB byte stream it carries.
pub struct RfbWebSocket<S> {
    stream: WebSocketStream<S>,
    /// The RFB bytes that were received but not read yet.
    read_queue: Vec<u8>,
    /// How much of `read_queue` was already read.
    read_pos: usize,
    /// The RFB bytes to send, when a write could not be sent right away.
    write_queue: Vec<u8>,
}

impl<S> RfbWebSocket<S> {
    /// The stream underneath, for a second handle that can shut it down.
    pub fn get_ref(&self) -> &S
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.stream.get_ref()
    }
}

impl<S> AsyncRead for RfbWebSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            // Whatever the messages held is the RFB stream: a message may end
            // in the middle of one, or carry several.
            if self.read_pos < self.read_queue.len() {
                let len = (self.read_queue.len() - self.read_pos).min(buf.len());
                buf[..len].copy_from_slice(&self.read_queue[self.read_pos..self.read_pos + len]);
                self.read_pos += len;
                if self.read_pos == self.read_queue.len() {
                    self.read_queue.clear();
                    self.read_pos = 0;
                }
                return Poll::Ready(Ok(len));
            }

            // Nothing buffered: get the next message.
            match self.stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    self.read_queue.extend_from_slice(&data);
                }
                // A close, or a stream that ended without one, is the end of
                // the RFB stream.
                Poll::Ready(Some(Ok(Message::Close(_)))) => return Poll::Ready(Ok(0)),
                Poll::Ready(Some(Ok(_))) => {
                    // Text, ping, pong and raw frames are not RFB. A ping is
                    // answered by tungstenite itself as it reads.
                    continue;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for RfbWebSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // A WebSocket message can not be split, so the bytes are queued and
        // sent by `poll_flush`, which the session always calls after writing.
        self.write_queue.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.write_queue.is_empty() {
            // One RFB write is one binary message, as a viewer expects.
            let data = std::mem::take(&mut self.write_queue);
            if let Err(e) = self.stream.start_send_unpin(Message::Binary(data.into())) {
                return Poll::Ready(Err(std::io::Error::other(e.to_string())));
            }
        }
        self.stream
            .poll_flush_unpin(cx)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut()
            .stream
            .poll_close_unpin(cx)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::{AsyncReadExt, Cursor};

    #[test]
    fn the_replay_prefix_is_served_before_the_stream() {
        // The bytes the HTTP server read are not in the socket any more, so the
        // handshake has to see them through this wrapper.
        let inner = Cursor::new(b"from the socket".to_vec());
        let mut stream = Replay::new(inner, b"already read: ".to_vec());
        let mut text = String::new();
        async_io::block_on(stream.read_to_string(&mut text)).expect("the replayed stream");
        assert_eq!(text, "already read: from the socket");
    }
}
