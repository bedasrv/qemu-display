//! The static file server of the WebSocket listener.
//!
//! websockify serves a directory over HTTP and upgrades WebSockets on the same
//! port, which is how a browser reaches noVNC: the page and its scripts are
//! files, and `vnc.html` opens a WebSocket to `websockify` by default. QEMU's
//! own `-vnc ...,websocket=<port>` does not serve files, so the two halves have
//! to be provided here for a viewer to work without a second process.
//!
//! **An upgrade is accepted on any path**, as websockify does. noVNC asks for
//! `/websockify`, which is what makes a page served from this root work with no
//! configuration, and a client written before this server served anything used
//! `/`: the path of a WebSocket says nothing about what it carries, only the
//! `binary` sub-protocol does, and the WebSocket layer checks that.
//!
//! A request that is not an upgrade is answered here and the connection is
//! closed. The head is *read*, not peeked: the bytes are needed to find where
//! it ends, and an upgrade hands them back with the socket for the WebSocket
//! layer to replay into its handshake. Peeking would leave them in place, but a
//! head that stops mid-way keeps the socket readable, so the wait for the rest
//! would spin on the bytes already seen.

use std::io;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_io::Async;
use futures::future::{Either, select};
use futures::io::{AsyncReadExt, AsyncWriteExt};

/// How much of a request head is read before it is refused.
///
/// A browser sends under two kilobytes; the limit only stops a client from
/// making the server allocate without bound. `431` is the status for a request
/// that exceeds it.
const MAX_HEAD: usize = 16 * 1024;

/// How long a client has to send a request head.
///
/// A browser sends it immediately. The bound exists because the connection is
/// classified on a thread of its own: a client that connects and then says
/// nothing would otherwise hold that thread for the life of the process.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// What became of an HTTP request.
pub enum Dispatch {
    /// The request is a WebSocket upgrade. `replay` is everything read while
    /// looking for the end of the head -- the request itself, and any bytes the
    /// client sent after it -- to be served to the handshake before the socket.
    Upgrade {
        /// The connection, with the request bytes already taken out of it.
        stream: TcpStream,
        /// The bytes the handshake must see first.
        replay: Vec<u8>,
    },
    /// The request was answered here, and the connection is finished.
    Served,
}

/// Read a request head and either answer it as HTTP or hand it to WebSocket.
///
/// `root` is the directory the pages are served from. It is canonicalised here
/// as well as by the caller, because a path is only safe to serve once it has
/// been checked against the directory it is really in: a symlink inside the
/// root that points outside it is not part of the root, whatever it looks like.
pub async fn dispatch(socket: TcpStream, root: &Path) -> io::Result<Dispatch> {
    dispatch_with_timeout(socket, root, HEAD_TIMEOUT).await
}

/// The same, with the wait for a request head bounded by `timeout`.
///
/// The bound is an argument so that a test can use one short enough to wait
/// for; the program always uses [`HEAD_TIMEOUT`].
async fn dispatch_with_timeout(
    socket: TcpStream,
    root: &Path,
    timeout: Duration,
) -> io::Result<Dispatch> {
    let root = std::fs::canonicalize(root)?;
    let mut socket = Async::new(socket)?;

    // The read is raced against the timer here rather than around the whole
    // request: once the head is in, the connection is a viewer and may idle for
    // as long as it likes.
    let read = {
        let head = read_head(&mut socket);
        let timer = async_io::Timer::after(timeout);
        futures::pin_mut!(head, timer);
        match select(head, timer).await {
            Either::Left((result, _)) => Some(result),
            Either::Right((_, _)) => None,
        }
    };

    let (buffered, end) = match read {
        None => {
            // The client never finished asking. Answering is best effort: it
            // may not be listening any more.
            respond(
                &mut socket,
                &Response::status(408, "Request Timeout"),
                false,
            )
            .await?;
            return Ok(Dispatch::Served);
        }
        // The client closed without a request, so there is nothing to answer.
        Some(Err(HeadError::Closed)) => return Ok(Dispatch::Served),
        Some(Err(HeadError::TooLarge)) => {
            respond(
                &mut socket,
                &Response::status(431, "Request Header Fields Too Large"),
                false,
            )
            .await?;
            return Ok(Dispatch::Served);
        }
        Some(Err(HeadError::Io(e))) => return Err(e),
        Some(Ok(head)) => head,
    };

    let Some(request) = Request::parse(&buffered[..end]) else {
        respond(&mut socket, &Response::status(400, "Bad Request"), false).await?;
        return Ok(Dispatch::Served);
    };

    if request.upgrade {
        // The handshake parses the request itself, and these bytes are already
        // out of the socket, so they travel with it to be replayed first.
        return Ok(Dispatch::Upgrade {
            stream: socket.into_inner()?,
            replay: buffered,
        });
    }

    // The head is already read, so closing the connection does not leave the
    // request itself queued: a socket closed with unread bytes sends a reset
    // instead of a FIN, and a reset can destroy a response the client has not
    // read yet.
    if request.method != "GET" && request.method != "HEAD" {
        let mut response = Response::status(405, "Method Not Allowed");
        response.extra = vec![("Allow".into(), "GET, HEAD".into())];
        respond(&mut socket, &response, false).await?;
        return Ok(Dispatch::Served);
    }
    let head_only = request.method == "HEAD";

    let response = match resolve(&root, request.target) {
        Ok(Resolved::File(path)) => file_response(&path),
        Ok(Resolved::Redirect(location)) => {
            let mut response = Response::status(301, "Moved Permanently");
            response.extra = vec![("Location".into(), location)];
            response
        }
        Ok(Resolved::Listing(path)) => match listing(&path, request.target) {
            Ok(body) => Response::new(200, "OK", "text/html; charset=utf-8", body),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Response::not_found(),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                Response::status(403, "Forbidden")
            }
            Err(e) => return Err(e),
        },
        Err(ResolveError::NotFound) => Response::not_found(),
        Err(ResolveError::Forbidden) => Response::status(403, "Forbidden"),
        Err(ResolveError::BadRequest) => Response::status(400, "Bad Request"),
        Err(ResolveError::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
            Response::status(403, "Forbidden")
        }
        // A name the file system cannot represent, such as a component longer
        // than `NAME_MAX`, is the client's mistake rather than ours.
        Err(ResolveError::Io(e))
            if matches!(
                e.kind(),
                io::ErrorKind::InvalidFilename | io::ErrorKind::InvalidInput
            ) =>
        {
            Response::status(400, "Bad Request")
        }
        // Anything else is still answered: a dropped connection leaves the
        // client with no status at all, which is worse than a 500.
        Err(ResolveError::Io(_)) => Response::status(500, "Internal Server Error"),
    };
    respond(&mut socket, &response, head_only).await?;
    Ok(Dispatch::Served)
}

/// Why a request head could not be read.
enum HeadError {
    /// The client closed without sending anything.
    Closed,
    /// The head did not end within [`MAX_HEAD`] bytes.
    TooLarge,
    /// The socket failed.
    Io(io::Error),
}

/// Read the request head, and whatever arrived with it.
///
/// The returned length is where the head ends, including the blank line; the
/// buffer may be longer when the client sent more than the request in one go,
/// and the upgrade path replays all of it.
///
/// Reading rather than peeking is what makes the wait a wait: a partial head
/// left in the socket keeps the socket readable, so a poll on it returns at
/// once and a loop over it never blocks.
async fn read_head(socket: &mut Async<TcpStream>) -> Result<(Vec<u8>, usize), HeadError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = head_end(&buf) {
            return Ok((buf, end));
        }
        if buf.len() == MAX_HEAD {
            return Err(HeadError::TooLarge);
        }
        let want = (MAX_HEAD - buf.len()).min(chunk.len());
        match socket.read(&mut chunk[..want]).await {
            Ok(0) => return Err(HeadError::Closed),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(HeadError::Io(e)),
        }
    }
}

/// The length of the head, including the blank line that ends it.
fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// The parts of a request line and its headers that decide what to do with it.
struct Request<'a> {
    method: &'a str,
    target: &'a str,
    upgrade: bool,
}

impl<'a> Request<'a> {
    fn parse(head: &'a [u8]) -> Option<Self> {
        let head = std::str::from_utf8(head).ok()?;
        let mut lines = head.split("\r\n");
        let request_line = lines.next()?;
        let mut parts = request_line.split(' ');
        let method = parts.next()?;
        let target = parts.next()?;
        let version = parts.next()?;
        if !version.starts_with("HTTP/") || method.is_empty() || target.is_empty() {
            return None;
        }
        let mut upgrade = false;
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':')?;
            // As websockify, the `Upgrade` header alone decides; whether the
            // connection is also marked `Connection: Upgrade` is for the
            // WebSocket layer, which refuses a request that is not a handshake.
            if name.trim().eq_ignore_ascii_case("upgrade")
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("websocket"))
            {
                upgrade = true;
            }
        }
        Some(Self {
            method,
            target,
            upgrade,
        })
    }
}

/// What a request target turns out to be on disk.
enum Resolved {
    /// A file to send.
    File(PathBuf),
    /// A directory named without its trailing slash, and where to send the
    /// client instead.
    Redirect(String),
    /// A directory with no index page, to be listed.
    Listing(PathBuf),
}

/// Why a target could not be resolved.
enum ResolveError {
    /// The target is not a path a client may ask for.
    BadRequest,
    /// The path exists but is outside the root, or is not readable.
    Forbidden,
    /// There is nothing there.
    NotFound,
    /// The file system failed in a way that is not about the request.
    Io(io::Error),
}

/// Map a request target onto a path under `root`.
fn resolve(root: &Path, target: &str) -> Result<Resolved, ResolveError> {
    // A fragment is never sent by a browser, but a query is, and a directory
    // redirect has to carry it over or the browser lands on a different
    // resource.
    let target = target.split('#').next().unwrap_or_default();
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    if !path.starts_with('/') {
        return Err(ResolveError::BadRequest);
    }
    let decoded = percent_decode(path).ok_or(ResolveError::BadRequest)?;
    if decoded.contains('\0') {
        return Err(ResolveError::BadRequest);
    }

    let mut fs_path = root.to_path_buf();
    for component in decoded.split('/') {
        match component {
            "" | "." => {}
            // `..` is refused rather than normalised. No page in a viewer
            // directory needs it, and a rule that only has to be right is
            // better than one that has to be right about symlinks too.
            ".." => return Err(ResolveError::Forbidden),
            component => fs_path.push(component),
        }
    }

    let canonical = match std::fs::canonicalize(&fs_path) {
        Ok(path) => path,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Err(ResolveError::NotFound);
        }
        Err(e) => return Err(ResolveError::Io(e)),
    };
    // Canonicalisation is what makes a symbolic link inside the root visible
    // for what it is. A link to a file outside the root is outside the root.
    if !canonical.starts_with(root) {
        return Err(ResolveError::Forbidden);
    }

    let metadata = match std::fs::metadata(&canonical) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ResolveError::NotFound),
        Err(e) => return Err(ResolveError::Io(e)),
    };
    if metadata.is_file() {
        return Ok(Resolved::File(canonical));
    }
    if !metadata.is_dir() {
        return Err(ResolveError::NotFound);
    }
    if !path.ends_with('/') {
        let mut location = format!("{path}/");
        if let Some(query) = query {
            location.push('?');
            location.push_str(query);
        }
        return Ok(Resolved::Redirect(location));
    }
    for index in ["index.html", "index.htm"] {
        let candidate = match std::fs::canonicalize(canonical.join(index)) {
            Ok(candidate) => candidate,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            Err(e) => return Err(ResolveError::Io(e)),
        };
        // An index is a path like any other. `is_file` on the joined name would
        // follow a symbolic link and serve a file from outside the root.
        if !candidate.starts_with(root) {
            return Err(ResolveError::Forbidden);
        }
        if candidate.is_file() {
            return Ok(Resolved::File(candidate));
        }
    }
    Ok(Resolved::Listing(canonical))
}

/// Read a file and build the response that serves it.
fn file_response(path: &Path) -> Response {
    match std::fs::read(path) {
        Ok(body) => Response::new(200, "OK", content_type(path), body),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Response::not_found(),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Response::status(403, "Forbidden"),
        // A file that vanished between resolving and reading is a 404; any
        // other failure is reported to the caller, which logs it.
        Err(_) => Response::status(500, "Internal Server Error"),
    }
}

/// The content type of a file, from its extension.
///
/// A table rather than a dependency: the files of a browser viewer are a short
/// list, and an unknown extension is `application/octet-stream`, which is what
/// the specification says to send when the type is not known.
fn content_type(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("wasm") => "application/wasm",
        Some("webmanifest") => "application/manifest+json",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// The HTML page that lists a directory, as websockify's does.
///
/// A viewer directory has no `index.html` at its root, so `/` is a listing
/// rather than a 404. Links are relative to the current directory and every
/// name is escaped both as HTML and as a URL component.
fn listing(dir: &Path, target: &str) -> io::Result<Vec<u8>> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        // A name that is not UTF-8 cannot be put in an HTML page or a URL
        // without a lossy conversion. Nothing a viewer needs has one.
        let Some(name) = name.to_str() else {
            continue;
        };
        entries.push((name.to_owned(), entry.file_type()?.is_dir()));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">");
    html.push_str("<title>Index of ");
    html.push_str(&escape_html(target));
    html.push_str("</title></head><body><h1>Index of ");
    html.push_str(&escape_html(target));
    html.push_str("</h1><ul><li><a href=\"../\">../</a></li>");
    for (name, is_dir) in &entries {
        let slash = if *is_dir { "/" } else { "" };
        html.push_str("<li><a href=\"");
        html.push_str(&escape_html(&percent_encode(name)));
        html.push_str(slash);
        html.push_str("\">");
        html.push_str(&escape_html(name));
        html.push_str(slash);
        html.push_str("</a></li>");
    }
    html.push_str("</ul></body></html>\n");
    Ok(html.into_bytes())
}

/// Percent-decode a URL path into the string it names.
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let high = hex(*bytes.get(i + 1)?)?;
                let low = hex(*bytes.get(i + 2)?)?;
                out.push(high << 4 | low);
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-encode a file name for a URL, leaving the unreserved characters.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// An HTTP response, built before any of it is written.
struct Response {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    extra: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn new(status: u16, reason: &'static str, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            reason,
            content_type,
            extra: Vec::new(),
            body,
        }
    }

    fn status(status: u16, reason: &'static str) -> Self {
        Self::new(
            status,
            reason,
            "text/plain; charset=utf-8",
            format!("{status} {reason}\n").into_bytes(),
        )
    }

    fn not_found() -> Self {
        Self::status(404, "Not Found")
    }
}

/// Write a response, and finish the connection.
///
/// `head_only` is the request's method: a `HEAD` is answered with the headers a
/// `GET` would report, including the same `Content-Length`, and no body.
async fn respond(
    socket: &mut Async<TcpStream>,
    response: &Response,
    head_only: bool,
) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n\
         Server: qemu-vnc\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-cache\r\n\
         Connection: close\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len()
    );
    for (name, value) in &response.extra {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    socket.write_all(head.as_bytes()).await?;
    if !head_only {
        socket.write_all(&response.body).await?;
    }
    socket.flush().await?;
    // A FIN, not a reset: the client is told the response is complete even if
    // it reads slowly, and the socket closes when the stream is dropped.
    let _ = socket.get_ref().shutdown(std::net::Shutdown::Write);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A directory under the temporary directory, removed when the test ends.
    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "qemu-vnc-web-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a temporary directory");
            Self { path }
        }

        fn write(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.path.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("a directory");
            }
            std::fs::write(&path, contents).expect("a file");
            path
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// A response, split into its head and its body.
    struct Answer {
        head: String,
        body: Vec<u8>,
    }

    impl Answer {
        fn status(&self) -> &str {
            self.head.lines().next().unwrap_or_default()
        }

        fn header(&self, name: &str) -> Option<&str> {
            self.head.lines().find_map(|line| {
                let (head, value) = line.split_once(':')?;
                head.eq_ignore_ascii_case(name).then(|| value.trim())
            })
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.body).to_string()
        }
    }

    /// Send one request through `dispatch`, and return what came back.
    fn request(root: &Path, request: &str) -> Answer {
        let (mut client, server) = dispatch_once(root);
        client.write_all(request.as_bytes()).expect("write");
        client.flush().expect("flush");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read");
        server.join().expect("the server thread");
        split(response)
    }

    fn split(response: Vec<u8>) -> Answer {
        let end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("the head to end");
        Answer {
            head: String::from_utf8_lossy(&response[..end]).to_string(),
            body: response[end + 4..].to_vec(),
        }
    }

    /// Serve one connection with `dispatch`, on a thread of its own.
    fn dispatch_once(root: &Path) -> (TcpStream, std::thread::JoinHandle<Dispatch>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let addr = listener.local_addr().expect("an address");
        let client = TcpStream::connect(addr).expect("a client");
        let root = root.to_path_buf();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("a connection");
            async_io::block_on(dispatch(stream, &root)).expect("the request to be served")
        });
        (client, server)
    }

    fn get(target: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n")
    }

    #[test]
    fn the_index_is_served_at_the_root() {
        let root = TempRoot::new();
        root.write("index.html", "<h1>came from index.html</h1>");
        let answer = request(&root.path, &get("/"));
        assert_eq!(answer.status(), "HTTP/1.1 200 OK");
        assert_eq!(
            answer.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(answer.text(), "<h1>came from index.html</h1>");
        assert_eq!(
            answer.header("content-length"),
            Some(answer.body.len().to_string().as_str())
        );
    }

    #[test]
    fn a_file_is_served_with_the_type_its_extension_names() {
        let root = TempRoot::new();
        root.write("vnc.html", "a viewer");
        root.write("app/ui.js", "export const viewer = true;");
        root.write("app/ui.css", "body { background: #000; }");

        let page = request(&root.path, &get("/vnc.html"));
        assert_eq!(page.status(), "HTTP/1.1 200 OK");
        assert_eq!(page.text(), "a viewer");
        assert_eq!(
            page.header("content-type"),
            Some("text/html; charset=utf-8")
        );

        let script = request(&root.path, &get("/app/ui.js"));
        assert_eq!(script.text(), "export const viewer = true;");
        assert_eq!(
            script.header("content-type"),
            Some("text/javascript; charset=utf-8")
        );

        let style = request(&root.path, &get("/app/ui.css"));
        assert_eq!(
            style.header("content-type"),
            Some("text/css; charset=utf-8")
        );
    }

    #[test]
    fn a_head_request_reports_the_length_and_sends_no_body() {
        let root = TempRoot::new();
        root.write("vnc.html", "a viewer");
        let answer = request(
            &root.path,
            "HEAD /vnc.html HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert_eq!(answer.status(), "HTTP/1.1 200 OK");
        assert_eq!(answer.header("content-length"), Some("8"));
        assert!(
            answer.body.is_empty(),
            "a HEAD response must carry no body, got {:?}",
            answer.text()
        );
    }

    #[test]
    fn a_missing_file_is_not_found() {
        let root = TempRoot::new();
        let answer = request(&root.path, &get("/vnc.html"));
        assert_eq!(answer.status(), "HTTP/1.1 404 Not Found");
    }

    #[test]
    fn a_directory_named_without_a_slash_redirects_to_one() {
        let root = TempRoot::new();
        root.write("app/ui.js", "");
        let answer = request(&root.path, &get("/app"));
        assert_eq!(answer.status(), "HTTP/1.1 301 Moved Permanently");
        assert_eq!(answer.header("location"), Some("/app/"));
    }

    #[test]
    fn a_directory_without_an_index_is_listed() {
        let root = TempRoot::new();
        root.write("app/ui.js", "");
        root.write("app/a b.html", "");
        let answer = request(&root.path, &get("/app/"));
        assert_eq!(answer.status(), "HTTP/1.1 200 OK");
        assert_eq!(
            answer.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        let body = answer.text();
        assert!(body.contains("href=\"ui.js\""), "no link to ui.js: {body}");
        assert!(
            body.contains("href=\"a%20b.html\""),
            "the name is not URL encoded: {body}"
        );
        assert!(
            body.contains("href=\"../\""),
            "a listing must offer the way back: {body}"
        );
    }

    #[test]
    fn a_percent_encoded_name_is_found() {
        let root = TempRoot::new();
        root.write("a b.html", "spaced");
        let answer = request(&root.path, &get("/a%20b.html"));
        assert_eq!(answer.status(), "HTTP/1.1 200 OK");
        assert_eq!(answer.text(), "spaced");
    }

    #[test]
    fn a_traversal_never_leaves_the_root() {
        let root = TempRoot::new();
        // A sibling of the root, reachable only by leaving it.
        let secret = root.path.parent().unwrap().join(format!(
            "{}-secret.txt",
            root.path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&secret, "not for the browser").expect("a secret");

        for target in [
            "/../secret.txt",
            "/%2e%2e/secret.txt",
            "/app/../../secret.txt",
        ] {
            let answer = request(&root.path, &get(target));
            assert_eq!(
                answer.status(),
                "HTTP/1.1 403 Forbidden",
                "{target} was answered with {}",
                answer.status()
            );
            assert!(
                !answer.text().contains("not for the browser"),
                "{target} leaked a file outside the root"
            );
        }
        let _ = std::fs::remove_file(&secret);
    }

    #[test]
    fn a_symlink_out_of_the_root_is_refused() {
        let root = TempRoot::new();
        let outside = TempRoot::new();
        let secret = outside.write("secret.txt", "not for the browser");
        std::os::unix::fs::symlink(&secret, root.path.join("link.txt")).expect("a symlink");
        let answer = request(&root.path, &get("/link.txt"));
        assert_eq!(answer.status(), "HTTP/1.1 403 Forbidden");
        assert!(!answer.text().contains("not for the browser"));
    }

    #[test]
    fn a_method_other_than_get_or_head_is_refused() {
        let root = TempRoot::new();
        let answer = request(
            &root.path,
            "POST /vnc.html HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(answer.status(), "HTTP/1.1 405 Method Not Allowed");
        assert_eq!(answer.header("allow"), Some("GET, HEAD"));
    }

    #[test]
    fn a_malformed_request_is_refused() {
        let root = TempRoot::new();
        let answer = request(&root.path, "not a request at all\r\n\r\n");
        assert_eq!(answer.status(), "HTTP/1.1 400 Bad Request");
    }

    #[test]
    fn a_head_that_never_ends_is_refused() {
        let root = TempRoot::new();
        let (mut client, server) = dispatch_once(&root.path);
        // A request line and a header that is never terminated.
        client.write_all(b"GET / HTTP/1.1\r\n").expect("write");
        client.write_all(&vec![b'a'; MAX_HEAD]).expect("write");
        client.flush().expect("flush");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read");
        server.join().expect("the server thread");
        let answer = split(response);
        assert_eq!(
            answer.status(),
            "HTTP/1.1 431 Request Header Fields Too Large"
        );
    }

    #[test]
    fn an_upgrade_is_handed_on_with_its_request_to_replay() {
        let root = TempRoot::new();
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let addr = listener.local_addr().expect("an address");
        let mut client = TcpStream::connect(addr).expect("a client");
        let upgrade = "GET /websockify HTTP/1.1\r\n\
                       Host: localhost\r\n\
                       Upgrade: websocket\r\n\
                       Connection: Upgrade\r\n\
                       Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                       Sec-WebSocket-Version: 13\r\n\
                       Sec-WebSocket-Protocol: binary\r\n\
                       \r\n";
        client.write_all(upgrade.as_bytes()).expect("write");
        client.flush().expect("flush");

        let root = root.path.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("a connection");
            let (mut stream, replay) =
                match async_io::block_on(dispatch(stream, &root)).expect("the request") {
                    Dispatch::Upgrade { stream, replay } => (stream, replay),
                    Dispatch::Served => panic!("an upgrade must not be answered as HTTP"),
                };
            assert_eq!(
                String::from_utf8_lossy(&replay),
                upgrade,
                "the handshake needs the request it came in on, so it travels with the socket"
            );
            // And the socket no longer holds it: the client is waiting for the
            // answer, so a read would block rather than return request bytes.
            stream
                .set_nonblocking(true)
                .expect("the socket in non-blocking mode");
            let mut byte = [0u8; 1];
            match stream.read(&mut byte) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("the request was left in the socket: {other:?}"),
            }
        });
        server.join().expect("the server thread");
        drop(client);
    }

    #[test]
    fn a_symlinked_index_out_of_the_root_is_refused() {
        // The index is chosen from a directory that is inside the root, but the
        // index itself is a path like any other: `is_file` would follow the
        // link and serve a file from outside.
        let root = TempRoot::new();
        let outside = TempRoot::new();
        let secret = outside.write("secret.html", "not for the browser");
        std::os::unix::fs::symlink(&secret, root.path.join("index.html")).expect("a symlink");
        let answer = request(&root.path, &get("/"));
        assert_eq!(answer.status(), "HTTP/1.1 403 Forbidden");
        assert!(!answer.text().contains("not for the browser"));
    }

    #[test]
    fn a_redirect_keeps_the_query() {
        let root = TempRoot::new();
        root.write("app/ui.js", "a viewer");
        let answer = request(&root.path, &get("/app?depth=1"));
        assert_eq!(answer.status(), "HTTP/1.1 301 Moved Permanently");
        assert_eq!(answer.header("location"), Some("/app/?depth=1"));
    }

    #[test]
    fn a_name_the_filesystem_can_not_hold_is_answered() {
        // A component longer than `NAME_MAX` makes `canonicalize` fail with
        // `ENAMETOOLONG`. That is the client's mistake, and it has to be
        // answered rather than closing the connection with no status.
        let root = TempRoot::new();
        let answer = request(&root.path, &get(&format!("/{}", "a".repeat(5000))));
        assert_eq!(answer.status(), "HTTP/1.1 400 Bad Request");
    }

    #[test]
    fn a_symlink_loop_is_answered() {
        // `canonicalize` fails with `ELOOP`, which is neither the client's
        // mistake nor a permission problem. It still has to produce a status:
        // a dropped connection tells the client nothing.
        let root = TempRoot::new();
        std::os::unix::fs::symlink("loop", root.path.join("loop")).expect("a symlink");
        let answer = request(&root.path, &get("/loop"));
        assert_eq!(answer.status(), "HTTP/1.1 500 Internal Server Error");
    }

    #[test]
    fn a_client_that_never_asks_is_timed_out() {
        let root = TempRoot::new();
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let addr = listener.local_addr().expect("an address");
        let mut client = TcpStream::connect(addr).expect("a client");
        let path = root.path.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("a connection");
            async_io::block_on(dispatch_with_timeout(
                stream,
                &path,
                std::time::Duration::from_millis(100),
            ))
            .expect("the request")
        });
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read");
        let answer = split(response);
        assert_eq!(answer.status(), "HTTP/1.1 408 Request Timeout");
        assert!(matches!(
            server.join().expect("the server thread"),
            Dispatch::Served
        ));
    }

    #[test]
    fn a_head_split_across_reads_is_served() {
        // The head does not have to arrive in one read, and a client that
        // pauses between the parts must still be served.
        let root = TempRoot::new();
        root.write("vnc.html", "a viewer");
        let (mut client, server) = dispatch_once(&root.path);
        client
            .write_all(b"GET /vnc.html HTTP/1.1\r\n")
            .expect("the request line");
        client.flush().expect("flush");
        std::thread::sleep(std::time::Duration::from_millis(50));
        client
            .write_all(b"Host: localhost\r\n\r\n")
            .expect("the rest of the head");
        client.flush().expect("flush");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read");
        server.join().expect("the server thread");
        assert_eq!(split(response).text(), "a viewer");
    }
}
