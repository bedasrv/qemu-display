//! RFB over WebSocket, the transport the `--websocket` listener serves.
//!
//! The client side is a WebSocket handshake followed by the very same RFB
//! handshake, so the test client is the scripted one of `session.rs` with the
//! bytes carried in binary messages. Running the same assertions over both
//! transports is the point: the framing must be the only difference.

#![cfg(feature = "websockets")]

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

use common::rfb_client;
use qemu_vnc::rfb::{
    ClientTransport, Event, FramebufferUpdate, Password, PixelFormat, Rect, ServerOptions,
    TcpSession,
};

/// The size of the frame buffer the test server serves.
const WIDTH: u16 = 64;
const HEIGHT: u16 = 32;

/// The RFB sub-protocol of a VNC connection.
const SUBPROTOCOL: &str = "binary";

/// Drive a future to completion, in a test.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    async_io::block_on(future)
}

/// A synthetic frame, in the x8r8g8b8 format: a red pixel pattern.
fn frame(width: u16, height: u16) -> Vec<u8> {
    (0..width as usize * height as usize)
        .flat_map(|i| {
            if i % 4 == 0 {
                [0x7f, 0x00, 0x00, 0x00]
            } else {
                [0x00; 4]
            }
        })
        .collect()
}

/// The pixel format the tests use.
fn pixel_format() -> PixelFormat {
    PixelFormat {
        bits_per_pixel: 32,
        depth: 24,
        big_endian: false,
        true_colour: true,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    }
}

/// A WebSocket client, on the blocking side of a socket.
struct WebSocketClient {
    stream: TcpStream,
    /// Bytes of the received messages that were not read yet.
    queue: Vec<u8>,
    /// The HTTP response that answered the upgrade, for the tests that are
    /// about the handshake rather than the stream.
    upgrade: String,
}

impl WebSocketClient {
    /// Perform the upgrade, offering `protocol` when there is one.
    ///
    /// noVNC 1.7.0 offers no sub-protocol at all, so the request has to be
    /// constructible without the header -- and the answer has to come back
    /// without one, or the browser refuses the connection.
    fn connect_offering(mut stream: TcpStream, protocol: Option<&str>) -> Self {
        let offer = match protocol {
            Some(protocol) => format!("Sec-WebSocket-Protocol: {protocol}\r\n"),
            None => String::new(),
        };
        write!(
            stream,
            "GET /websockify HTTP/1.1\r\n\
             Host: localhost\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\
             {offer}\
             \r\n"
        )
        .expect("request");
        stream.flush().expect("flush");
        let mut client = Self {
            stream,
            queue: Vec::new(),
            upgrade: String::new(),
        };
        // Read the response headers, and the first frame that follows them.
        let response = client.read_http_response();
        assert!(
            response.starts_with("HTTP/1.1 101"),
            "unexpected upgrade response: {response}"
        );
        // A browser refuses this answer outright, so the test client does too:
        // the server may not name a sub-protocol the request did not offer.
        if protocol.is_none() {
            assert!(
                !response
                    .to_ascii_lowercase()
                    .contains("sec-websocket-protocol"),
                "a browser would refuse this upgrade: {response}"
            );
        }
        client.upgrade = response;
        client
    }

    /// Read the HTTP response of the upgrade, up to the blank line.
    fn read_http_response(&mut self) -> String {
        let mut response = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            self.stream.read_exact(&mut byte).expect("response");
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
            if response.len() > 4096 {
                panic!("the upgrade response never ended");
            }
        }
        String::from_utf8_lossy(&response).to_string()
    }

    /// Read one WebSocket frame, and return its payload.
    ///
    /// A frame from a server is never masked, and its header is the two
    /// bytes of the opcode and the length, plus an extended length.
    fn read_frame(&mut self) -> Vec<u8> {
        let mut header = [0u8; 2];
        self.stream.read_exact(&mut header).expect("frame header");
        assert_eq!(header[1] & 0x80, 0, "a server frame must not be masked");
        assert_eq!(
            header[0] & 0x0f,
            0x2,
            "expected a binary message, got opcode {}",
            header[0] & 0x0f
        );
        let mut len = usize::from(header[1] & 0x7f);
        if len == 126 {
            let mut extended = [0u8; 2];
            self.stream.read_exact(&mut extended).expect("frame length");
            len = usize::from(u16::from_be_bytes(extended));
        } else if len == 127 {
            let mut extended = [0u8; 8];
            self.stream.read_exact(&mut extended).expect("frame length");
            len = u64::from_be_bytes(extended) as usize;
        }
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).expect("frame payload");
        payload
    }

    /// Send the RFB bytes, as one binary message per write.
    ///
    /// The framing is written out rather than taken from a WebSocket crate:
    /// this is a client to make the server produce the bytes we expect, and a
    /// masked client frame is a handful of lines.
    fn write_bytes(&mut self, data: &[u8]) {
        // A client frame must be masked, with a key of our choosing.
        let mask = [0x12u8, 0x34, 0x56, 0x78];
        let mut frame = vec![0x82]; // FIN, binary
        match data.len() {
            len if len < 126 => frame.push(0x80 | len as u8),
            len if len <= u16::MAX as usize => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            }
            len => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        frame.extend(
            data.iter()
                .enumerate()
                .map(|(i, byte)| byte ^ mask[i % mask.len()]),
        );
        self.stream.write_all(&frame).expect("write");
        self.stream.flush().expect("flush");
    }
}

impl Read for WebSocketClient {
    /// Read the RFB bytes, whatever messages they are in.
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.queue.is_empty() {
            let frame = self.read_frame();
            self.queue.extend_from_slice(&frame);
        }
        let len = self.queue.len().min(out.len());
        out[..len].copy_from_slice(&self.queue[..len]);
        self.queue.drain(..len);
        Ok(len)
    }
}

impl Write for WebSocketClient {
    /// Send the RFB bytes, as one binary message per write.
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.write_bytes(data);
        Ok(data.len())
    }

    /// A WebSocket message goes out as it is written, so there is nothing to
    /// push further.
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

/// The RFB handshake, over the WebSocket.
///
/// This is the scripted client of `session.rs`, unchanged: a WebSocket is a
/// byte stream in binary messages, and nothing above the transport notices.
fn handshake(client: &mut WebSocketClient, password: Option<&str>) {
    assert_eq!(rfb_client::read_server_version(client), "RFB 003.008");
    rfb_client::negotiate_version(client, "RFB 003.008\n");
    // Only the authentication we asked for is offered, as a real viewer needs.
    let expected = if password.is_some() { vec![2] } else { vec![1] };
    assert_eq!(rfb_client::read_security_types(client, false), expected);
    match password {
        Some(password) => {
            rfb_client::select_security_type(client, 2);
            assert_eq!(rfb_client::authenticate(client, password), 0);
        }
        None => {
            rfb_client::select_security_type(client, 1);
            assert_eq!(rfb_client::read_security_result(client), 0);
        }
    }
    rfb_client::send_client_init(client, true);
    let (width, height, name) = rfb_client::read_server_init(client);
    assert_eq!((width, height), (WIDTH, HEIGHT));
    assert_eq!(name, "qemu-vnc test");
}

/// Run the scripted RFB session over an already-opened transport.
///
/// The session answers one frame buffer update, then keeps the connection alive
/// until the test hangs up. Shared by the plain WebSocket and the one that came
/// through the document root, so the two cannot drift apart.
fn serve_session(transport: ClientTransport, options: ServerOptions) {
    block_on(async {
        let Ok((mut session, _)) = TcpSession::from_stream(transport, WIDTH, HEIGHT, options).await
        else {
            return;
        };
        if let Ok(Event::FramebufferUpdateRequest { width, height, .. }) =
            session.read_event().await
        {
            let mut fbu = FramebufferUpdate::new(Some(&pixel_format()));
            let rect = Rect::new(0, 0, width, height);
            let pixels = frame(width, height);
            fbu.add_raw_pixels(rect, &pixels);
            session.send(&fbu).await.unwrap();
        }
        let _ = session.read_event().await;
    });
}

/// Serve one WebSocket client in a background thread, and hand the connection
/// back to the test.
fn serve(password: Option<&str>) -> (WebSocketClient, thread::JoinHandle<()>) {
    serve_offering(password, Some(SUBPROTOCOL))
}

/// Serve one client that offers `protocol`, or nothing at all.
///
/// The second case is noVNC 1.7.0: its socket is opened with no protocols, so
/// the handshake must neither require one nor name one in the answer.
fn serve_offering(
    password: Option<&str>,
    protocol: Option<&str>,
) -> (WebSocketClient, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = TcpStream::connect(addr).unwrap();
    let password = password.map(str::to_owned);

    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let name = "qemu-vnc test".to_string();
        let password = password.map(|password| Password::new(&password));
        let options = match &password {
            Some(password) => ServerOptions::authenticated(&name, pixel_format(), password),
            None => ServerOptions::anonymous(&name, pixel_format()),
        };
        block_on(async {
            let transport = ClientTransport::websocket(stream).await;
            let Ok(transport) = transport else {
                // A client that did not speak WebSocket is refused before the
                // RFB handshake, which is what the test expects.
                return;
            };
            assert!(transport.is_websocket());
            serve_session(transport, options);
        });
    });
    (WebSocketClient::connect_offering(stream, protocol), handle)
}

/// Serve one WebSocket client through a document root, as the program does.
///
/// The request goes to `web::dispatch` first, exactly as the listener does with
/// `--web`: an upgrade is handed on to the WebSocket layer, and anything else is
/// answered as HTTP. This is the composition the binary depends on.
fn serve_web(root: PathBuf, protocol: Option<&str>) -> (WebSocketClient, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = TcpStream::connect(addr).unwrap();

    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        block_on(async {
            let dispatch = qemu_vnc::web::dispatch(stream, &root).await;
            let qemu_vnc::web::Dispatch::Upgrade { stream, replay } =
                dispatch.expect("the request to be classified")
            else {
                panic!("noVNC asked for a WebSocket and was served a page instead");
            };
            let transport = ClientTransport::websocket_replaying(stream, replay)
                .await
                .expect("the upgrade to complete");
            assert!(transport.is_websocket());
            let options = ServerOptions::anonymous("qemu-vnc test", pixel_format());
            serve_session(transport, options);
        });
    });
    (WebSocketClient::connect_offering(stream, protocol), handle)
}

#[test]
fn a_websocket_client_gets_the_rfb_handshake() {
    let (mut client, server) = serve(None);
    handshake(&mut client, None);
    drop(client);
    let _ = server.join();
}

#[test]
fn a_websocket_client_can_authenticate() {
    let (mut client, server) = serve(Some("s3cret"));
    handshake(&mut client, Some("s3cret"));
    drop(client);
    let _ = server.join();
}

#[test]
fn a_websocket_client_can_read_an_update() {
    let (mut client, server) = serve(None);
    handshake(&mut client, None);

    // The very same update, read by the very same helper as over a socket.
    rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
    let pixels = rfb_client::read_update(&mut client);
    assert_eq!(pixels, frame(WIDTH, HEIGHT));

    drop(client);
    let _ = server.join();
}

#[test]
fn a_client_that_offers_no_subprotocol_is_served_without_one() {
    // noVNC 1.7.0 opens its WebSocket with no protocols. The test client applies
    // the browser's rule -- the answer may not name a sub-protocol the request
    // did not offer -- so the unconditional echo that Chrome rejected
    // ("Response must not include 'Sec-WebSocket-Protocol' header if not present
    // in request: binary") fails in `serve_offering`, before this test runs.
    let (mut client, server) = serve_offering(None, None);
    // And it is still a viewer: the RFB handshake and an update run over the
    // connection that was accepted without one.
    handshake(&mut client, None);
    rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
    let pixels = rfb_client::read_update(&mut client);
    assert_eq!(pixels, frame(WIDTH, HEIGHT), "the stream is not RFB");
    drop(client);
    let _ = server.join();
}

#[test]
fn a_client_that_offers_binary_gets_it_echoed() {
    // websockify's `CompatibleWebSocket` selects `binary` when it is offered,
    // and a client that negotiated it is entitled to see it in the answer.
    let (mut client, server) = serve_offering(None, Some(SUBPROTOCOL));
    assert!(
        client
            .upgrade
            .to_ascii_lowercase()
            .contains(&format!("sec-websocket-protocol: {SUBPROTOCOL}")),
        "the offered sub-protocol was not selected: {}",
        client.upgrade
    );
    handshake(&mut client, None);
    drop(client);
    let _ = server.join();
}

#[test]
fn a_request_that_is_not_a_websocket_is_refused() {
    // The upgrade is answered with an HTTP error, and no RFB byte is sent.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        block_on(async {
            let _ = ClientTransport::websocket(stream).await;
        });
    });

    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    client.flush().unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let response = String::from_utf8_lossy(&response).to_string();
    assert!(
        !response.starts_with("HTTP/1.1 101"),
        "a plain HTTP request must not be upgraded, got: {response}"
    );
    assert!(
        !response.contains("RFB"),
        "no RFB byte may be sent to a client that is not a viewer: {response}"
    );
    let _ = server.join();
}

#[test]
fn a_client_that_asks_for_another_subprotocol_is_refused() {
    // A WebSocket that is not VNC: the `binary` sub-protocol is what says the
    // stream is a framebuffer.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        block_on(async {
            let _ = ClientTransport::websocket(stream).await;
        });
    });

    client
        .write_all(
            b"GET / HTTP/1.1\r\n\
              Host: localhost\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Protocol: chat\r\n\
              \r\n",
        )
        .unwrap();
    client.flush().unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let response = String::from_utf8_lossy(&response).to_string();
    assert!(
        !response.starts_with("HTTP/1.1 101"),
        "a client that is not VNC must be refused, got: {response}"
    );
    let _ = server.join();
}

/// A document root under the temporary directory, removed when the test ends.
struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "qemu-vnc-websocket-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a document root");
        Self(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A thread's own CPU time, from `/proc`, so that other tests running in
/// parallel can not be mistaken for it.
#[cfg(target_os = "linux")]
fn thread_cpu_ticks(stat: &std::path::Path) -> u64 {
    let text = std::fs::read_to_string(stat).expect("a thread's stat");
    let rest = &text[text.rfind(')').expect("a command name") + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // Field 3 is index 0, so utime (14) is 11 and stime (15) is 12.
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

#[test]
#[cfg(target_os = "linux")]
fn a_request_head_that_stops_mid_way_does_not_spin() {
    // A client that sends half a head and waits used to pin a core: the head
    // was peeked, so the bytes stayed readable and the wait for the rest
    // returned at once, over and over. A thread that waits must not use CPU.
    let root = TempRoot::new();
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let addr = listener.local_addr().expect("an address");
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let path = root.0.clone();
    let server = thread::spawn(move || {
        // `/proc/thread-self` points at the thread that reads it, so this is
        // the serving thread's id and no other's. The link's target is relative
        // to `/proc`.
        let tid = std::path::Path::new("/proc")
            .join(std::fs::read_link("/proc/thread-self").expect("a thread id"));
        tid_tx.send(tid).expect("the test to wait for the id");
        let (stream, _) = listener.accept().expect("a connection");
        let _ = block_on(qemu_vnc::web::dispatch(stream, &path));
    });

    let mut client = TcpStream::connect(addr).expect("a client");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        .expect("half a head");
    client.flush().expect("flush");

    let stat = tid_rx.recv().expect("the thread id").join("stat");
    // Let the server reach its wait, then sample that thread alone.
    thread::sleep(std::time::Duration::from_millis(100));
    let before = thread_cpu_ticks(&stat);
    thread::sleep(std::time::Duration::from_millis(300));
    let spent = thread_cpu_ticks(&stat) - before;

    assert!(
        spent < 10,
        "the waiting thread used {spent} ticks of CPU in 300 ms; \
         a partial request head must not spin"
    );

    drop(client);
    let _ = server.join();
}

#[test]
fn a_page_is_served_on_the_same_port_the_websocket_upgrades_on() {
    // The two halves of websockify on one listener: a browser fetches the page
    // with a plain `GET`, and noVNC then opens a WebSocket to `/websockify` on
    // the same port and the same directory. Both are driven through
    // `web::dispatch`, which is the dispatch the program's accept path does.
    let root = TempRoot::new();
    std::fs::write(root.0.join("vnc.html"), "<h1>viewer</h1>").expect("the page");

    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let addr = listener.local_addr().expect("an address");
    let mut browser = TcpStream::connect(addr).expect("a browser");
    let served = {
        let root = root.0.clone();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("a connection");
            block_on(qemu_vnc::web::dispatch(stream, &root)).expect("the page");
        })
    };
    browser
        .write_all(b"GET /vnc.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("the request");
    browser.flush().expect("flush");
    let mut response = Vec::new();
    browser.read_to_end(&mut response).expect("the response");
    served.join().expect("the HTTP thread");

    let response = String::from_utf8_lossy(&response).to_string();
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "the page was not served: {response}"
    );
    assert!(
        response.contains("Content-Type: text/html"),
        "the page was served with the wrong type: {response}"
    );
    assert!(
        response.ends_with("<h1>viewer</h1>"),
        "the page body is not the file: {response}"
    );

    // The same port and root, now upgraded: this is what noVNC asks for.
    // noVNC 1.7.0's WebSocket offers no sub-protocol, which is the case the
    // browser hit; the same page and port then have to carry RFB.
    let (mut client, server) = serve_web(root.0.clone(), None);
    handshake(&mut client, None);
    rfb_client::request_update(&mut client, 0, 0, WIDTH, HEIGHT);
    let pixels = rfb_client::read_update(&mut client);
    assert_eq!(
        pixels,
        frame(WIDTH, HEIGHT),
        "the WebSocket served through the document root is not the RFB stream"
    );
    drop(client);
    let _ = server.join();
}
