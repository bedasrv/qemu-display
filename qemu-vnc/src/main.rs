//! A standalone VNC server, connecting to a QEMU instance through its
//! D-Bus display interface.
//!
//! Port of `qemu-vnc.c`, the `main()` of the standalone VNC server.

use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use futures::FutureExt;
use futures::StreamExt;
use qemu_display::{Display, Error, Result, VMProxy};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use zbus::{Connection, fdo, names::BusName, names::OwnedUniqueName};

use qemu_vnc::chardev;
use qemu_vnc::clipboard::Clipboard;
use qemu_vnc::dbus::{self, Vnc1Server};
use qemu_vnc::rfb::{Authz, SaslMechanisms, default_mechanisms};
use qemu_vnc::server::{ListenerInfo, PasswordStore, ServerEvent, Share};
use qemu_vnc::{Server, utils};

/// The default VNC address, i.e. `localhost:5900`.
const DEFAULT_VNC_ADDR: &str = "localhost:5900";
/// The D-Bus name of a QEMU display.
const DEFAULT_BUS_NAME: &str = "org.qemu";
/// The JPEG quality of `--lossy` when none is given, as in QEMU's VNC
/// options.
const DEFAULT_JPEG_QUALITY: u8 = 30;

/// Standalone VNC server, connecting to a QEMU instance via the
/// D-Bus display interface (`org.qemu.Display1`).
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// D-Bus address to connect to (default: session bus)
    #[arg(short = 'a', long, value_name = "ADDRESS")]
    dbus_address: Option<String>,

    /// D-Bus peer-to-peer socket file descriptor
    #[arg(short = 'p', long, value_name = "FD")]
    dbus_p2p_fd: Option<i32>,

    /// D-Bus bus name (default: org.qemu)
    #[arg(short = 'n', long, value_name = "NAME")]
    bus_name: Option<String>,

    /// Wait for the D-Bus name to appear
    #[arg(short = 'W', long)]
    wait: bool,

    /// VNC display address, as [addr]:port ("none" to disable)
    #[arg(short = 'l', long, value_name = "ADDR", default_value = DEFAULT_VNC_ADDR)]
    vnc_addr: String,

    /// WebSocket address, as [addr]:port ("none" to disable)
    #[cfg(feature = "websockets")]
    #[arg(short = 'w', long = "websocket", value_name = "ADDR")]
    websocket: Option<String>,

    /// Serve this directory over HTTP on the WebSocket listener, as
    /// `websockify --web` does (e.g. a noVNC directory)
    #[cfg(feature = "websockets")]
    #[arg(long, value_name = "DIR", requires = "websocket")]
    web: Option<std::path::PathBuf>,

    /// Display sharing policy (allow-exclusive|force-shared|ignore)
    #[arg(short = 's', long, value_name = "POLICY")]
    share: Option<String>,

    /// Chardev type names to expose as text console (repeatable, default:
    /// serial & hmp)
    #[arg(short = 'C', long, value_name = "NAME")]
    vt_chardev: Vec<String>,

    /// Do not expose any chardevs as text consoles
    #[arg(short = 'N', long)]
    no_vt: bool,

    /// Require password authentication: fail if no password is configured
    /// (see --set-password and the CREDENTIALS_DIRECTORY credential)
    #[arg(long)]
    password: bool,

    /// Set the VNC password and require authentication (visible in the
    /// process list: prefer the credential, or SetPassword over D-Bus)
    #[arg(long, value_name = "PASSWORD")]
    set_password: Option<String>,

    /// Keyboard layout (ignored, the keymap is locale independent)
    #[arg(short = 'k', long, value_name = "LAYOUT")]
    keyboard_layout: Option<String>,

    /// Allow lossy JPEG compression, for the clients that ask for it
    #[arg(long)]
    lossy: bool,

    /// Write the captured audio to this file, instead of playing it
    #[arg(long, value_name = "PATH")]
    audio_dump: Option<std::path::PathBuf>,

    /// Require SASL authentication of the clients that connect
    #[arg(long)]
    sasl: bool,

    /// Comma separated SASL usernames allowed to connect (requires --sasl)
    #[arg(long, value_name = "USERS", requires = "sasl")]
    sasl_authz: Option<String>,

    /// Lossy JPEG quality, from 0 (smallest) to 100 (best), default 30
    #[arg(long, value_name = "QUALITY")]
    jpeg_quality: Option<u8>,

    /// Trace options, e.g. "qemu_vnc=debug" (default: $RUST_LOG)
    #[arg(short = 'T', long, value_name = "PATTERN")]
    trace: Option<String>,
}

/// Parse a VNC address, `none` meaning "no VNC server".
fn parse_addr(addr: &str) -> Result<Option<SocketAddr>> {
    if addr == "none" {
        return Ok(None);
    }
    if let Ok(addr) = addr.parse::<SocketAddr>() {
        return Ok(Some(addr));
    }
    // Accept a bare port number, as QEMU's VNC address syntax does.
    let (host, port) = match addr.rsplit_once(':') {
        Some(("", port)) => ("localhost", port),
        Some((host, port)) => (host, port),
        None => ("localhost", addr),
    };
    let port: u16 = port
        .parse()
        .map_err(|_| Error::Failed(format!("Invalid VNC address: {addr}")))?;
    Ok(Some(
        ToSocketAddrs::to_socket_addrs(&(host, port))
            .map_err(|e| Error::Failed(format!("Invalid VNC address {addr}: {e}")))?
            .next()
            .ok_or_else(|| Error::Failed(format!("Invalid VNC address: {addr}")))?,
    ))
}

/// Set up the D-Bus connection to QEMU, as `setup_dbus_connection()` does.
///
/// The returned name is the well-known name of the VM, if any: a peer-to-peer
/// connection does not go through a bus, and the proxies then use the default
/// `org.qemu` destination.
async fn connect(args: &Cli) -> Result<(Connection, Option<String>)> {
    if let Some(fd) = args.dbus_p2p_fd {
        if args.bus_name.is_some() {
            return Err(Error::Failed(
                "--bus-name is not supported with --dbus-p2p-fd".into(),
            ));
        }
        return Ok((utils::p2p_from_fd(fd).await?, None));
    }
    if let Some(address) = &args.dbus_address {
        let conn = zbus::connection::Builder::address(address.as_str())
            .build()
            .await?;
        return Ok((conn, args.bus_name.clone()));
    }
    // On a message bus, the VM is expected to own a well-known name.
    Ok((
        Connection::session().await?,
        Some(
            args.bus_name
                .clone()
                .unwrap_or_else(|| DEFAULT_BUS_NAME.into()),
        ),
    ))
}

/// Watch a well-known name, as `g_bus_watch_name_on_connection()` does, and
/// return the unique name of its current owner.
///
/// A watch can end without the connection ending — the peer's name is no longer
/// the one being watched, or the match rule behind the watch is gone — and that
/// is why there is a separate [`name_watch`] for putting one back.
async fn name_watch(conn: &Connection) -> Result<zbus::fdo::NameOwnerChangedStream> {
    let dbus = fdo::DBusProxy::new(conn).await?;
    Ok(dbus.receive_name_owner_changed().await?)
}

/// Watch a well-known name, as `g_bus_watch_name_on_connection()` does, and
/// return the unique name of its current owner.
async fn watch_name(
    conn: &Connection,
    name: &str,
    wait: bool,
) -> Result<(OwnedUniqueName, zbus::fdo::NameOwnerChangedStream)> {
    let dbus = fdo::DBusProxy::new(conn).await?;
    let mut changed = dbus.receive_name_owner_changed().await?;
    loop {
        match dbus.get_name_owner(name.to_owned().try_into()?).await {
            Ok(owner) => return Ok((owner, changed)),
            Err(fdo::Error::NameHasNoOwner(_)) if wait => {
                info!("waiting for the D-Bus name {name} to appear");
                if changed.next().await.is_none() {
                    return Err(Error::Failed("D-Bus connection closed".into()));
                }
            }
            Err(_) => {
                return Err(Error::Failed(format!(
                    "D-Bus name {name} not found. Is QEMU running? \
                     Use --wait to wait for it to appear."
                )));
            }
        }
    }
}

async fn run() -> Result<()> {
    let args = Cli::parse();
    init_tracing(args.trace.as_deref());

    if args.dbus_p2p_fd.is_some() && args.dbus_address.is_some() {
        return Err(Error::Failed(
            "--dbus-p2p-fd and --dbus-address are mutually exclusive".into(),
        ));
    }
    if let Some(keyboard_layout) = &args.keyboard_layout {
        warn!("ignoring --keyboard-layout {keyboard_layout}: the keymap is locale independent");
    }
    let share = match &args.share {
        Some(policy) => Share::parse(policy)
            .ok_or_else(|| Error::Failed(format!("Invalid share policy: {policy}")))?,
        None => Share::default(),
    };
    let vnc_addr = parse_addr(&args.vnc_addr)?;

    let (conn, bus_name) = connect(&args).await?;
    if args.wait && bus_name.is_none() {
        return Err(Error::Failed(
            "--wait requires a D-Bus bus name (--bus-name)".into(),
        ));
    }
    // Resolve the bus name to the unique name of the VM, and keep watching it
    // to notice when the peer goes away.
    let (dest, mut name_changed) = match &bus_name {
        Some(name) => {
            let (owner, changed) = watch_name(&conn, name, args.wait).await?;
            (Some(BusName::from(owner)), Some(changed))
        }
        None => (None, None),
    };

    let mut vm_builder = VMProxy::builder(&conn);
    if let Some(dest) = &dest {
        vm_builder = vm_builder.destination(dest.clone());
    }
    let vm = vm_builder.build().await?;
    let vm_name = vm.name().await?;
    // The build marker. Every line of every log says which build produced it,
    // because "did they rebuild" is a question that has now cost two rounds of
    // a symptom being diagnosed against a binary that might not have had the
    // last change in it — and neither the log nor the symptom can answer it.
    //
    // **And whether it was optimised**, which cost rather more than that. A
    // report of "100% CPU" was chased through four rounds of real bugs — a
    // missing length field, a wrong encoding choice, a whole-framebuffer
    // conversion on every update — each of which was a genuine fault and none of
    // which was *this* machine's hundred per cent, because the binary was a
    // debug build. Every measurement in `PORTING.md` is a release measurement,
    // and a debug build of the same code is 25x slower on this path: the
    // heartbeat that finally said so reported 240 ms to encode 518,000 pixels
    // where the release benchmark says 4.6 ms for 256,000.
    //
    // So the marker says which profile it is, and it is the difference between
    // "this is a bug" and "this is a debug build" in one field. A version string
    // cannot tell them apart: both builds are `0.1.0`.
    info!(
        vm = %vm_name,
        build = env!("CARGO_PKG_VERSION"),
        profile = if cfg!(debug_assertions) { "debug" } else { "release" },
        heartbeat = "armed: two counters lines per interval, plus one at startup",
        "serving {vm_name}"
    );

    // Set up the credentials, as `setup_credentials()` does. A systemd
    // `vnc-password` credential is enough to require authentication, and so
    // is a password set later with `SetPassword` over D-Bus.
    let passwords = PasswordStore::from_environment()?;
    if let Some(password) = &args.set_password {
        warn!("--set-password is visible in the process list");
        passwords.set(password);
    }
    if args.password && passwords.password().is_none() {
        return Err(Error::Failed(
            "--password needs a password: use --set-password, the \
             CREDENTIALS_DIRECTORY/vnc-password systemd credential, or the \
             SetPassword method of org.qemu.Vnc1.Server"
                .into(),
        ));
    }
    if passwords.password().is_some() {
        info!("the clients have to authenticate with a VNC password");
    }
    let server = Server::with_passwords(&conn, &vm_name, share, passwords)?;
    // SASL authentication, as `-vnc sasl=on` does. The mechanisms are the
    // ones the build has: with the `sasl` feature that is Cyrus's and
    // ANONYMOUS, and without it only ANONYMOUS, which needs no library.
    if args.sasl {
        let mechanisms = Arc::new(SaslMechanisms::new(default_mechanisms()));
        let authz = match &args.sasl_authz {
            Some(users) => Authz::allow(
                users
                    .split(',')
                    .map(str::trim)
                    .filter(|user| !user.is_empty())
                    .map(str::to_owned),
            ),
            None => Authz::allow_all(),
        };
        server.set_sasl(mechanisms, authz);
        info!("SASL authentication enabled");
    }

    // The lossy JPEG encoding, as `-vnc lossy` and `-vnc jpeg=<quality>` do.
    if args.lossy || args.jpeg_quality.is_some() {
        let quality = args.jpeg_quality.unwrap_or(DEFAULT_JPEG_QUALITY);
        if quality > 100 {
            return Err(Error::Failed(format!(
                "Invalid JPEG quality: {quality} (0 to 100)"
            )));
        }
        server.set_jpeg_quality(quality);
        info!(quality, "allowing the lossy JPEG encoding");
    }
    // The audio of the guest, for the clients that ask for it. Without the
    // `audio` feature there is no output device to open, so the samples go to
    // a file or nowhere: the audio path is the same either way, which is what
    // makes it testable on a machine with no sound card.
    let audio_listener: Option<qemu_vnc::audio::AudioServer> = {
        let sink: Box<dyn qemu_vnc::audio::Sink> = match &args.audio_dump {
            Some(path) => Box::new(
                qemu_vnc::audio::FileSink::create(path, qemu_vnc::audio::DEFAULT_FORMAT)
                    .map_err(|e| Error::Failed(format!("{e}")))?,
            ),
            #[cfg(feature = "audio")]
            None => match qemu_vnc::audio::CpalSink::open(qemu_vnc::audio::DEFAULT_FORMAT) {
                Ok(sink) => Box::new(sink),
                Err(e) => {
                    // A machine with no output device is not a machine without
                    // audio: the samples are captured either way.
                    warn!("playing no audio: {e}");
                    Box::new(qemu_vnc::audio::NullSink::new())
                }
            },
            #[cfg(not(feature = "audio"))]
            None => {
                if !args.audio_dump.is_some() {
                    info!("built without the audio feature: capturing audio, playing none");
                }
                Box::new(qemu_vnc::audio::NullSink::new())
            }
        };
        let target = server.clone();
        let audio = qemu_vnc::audio::AudioServer::new(sink, move |out| match out {
            qemu_vnc::audio::Out::Samples(source, samples) => {
                target.broadcast_audio(source, samples)
            }
            // Once per stream. This used to be dropped, because the start of a
            // stream arrived as an empty block and an empty block is not audio:
            // so a client was told `BEGIN` exactly once, when it asked, and never
            // again. A guest that pauses between tracks then went silent for good
            // after the first one.
            qemu_vnc::audio::Out::Begin => target.broadcast_audio_begin(),
            qemu_vnc::audio::Out::End => target.broadcast_audio_end(),
        });
        // **Not** `set_audio` here, and the position of the call below is the
        // whole reason. The gate a client is answered by is `audio_enabled()`,
        // so setting it before the listener is registered promises audio to
        // every client that connects in the window -- and then withdraws it
        // with nothing to tell them, because `set_audio` only swaps a slot.
        // That client sits with `audio.enabled` set, waiting for samples that
        // can never arrive. It is decided once, below, after the peer's objects
        // are known and the registration has either worked or not.
        Some(audio)
    };

    let display = Display::new(&conn, dest).await?;

    // The audio listener, once the peer's objects are known. An owned name: the
    // proxy keeps it, and a peer-to-peer connection has no well-known name to
    // keep.
    //
    // **Before any client can connect**, which is the only reason it is here and
    // not further down. `RegisterOutListener` carries a file descriptor, so the
    // peer's object manager does have to be read first -- but nothing about that
    // needs `Vnc1Server::setup`, and until the registration has succeeded the
    // gate must stay shut.
    // `Audio` is **kept, not dropped**, and that is the whole point of the
    // binding. It owns the peer-to-peer connection to QEMU's
    // `AudioOutListener` -- the only reference to it there is -- so dropping it
    // closes the socket and every sample QEMU pushes afterwards goes into a
    // broken pipe. This was a real fault, not a theoretical one: scoped to the
    // `match` arm it used to be, the registration succeeded, the client was
    // told to expect audio, and then the connection died with no warning and an
    // empty capture.
    //
    // A test cannot see this from the other side, because a test that holds the
    // handle is the arrangement that works. `dropping_the_audio_handle_closes_
    // the_listener` in `tests/mock.rs` pins the behaviour itself.
    let _audio_handle = if let Some(audio) = audio_listener {
        if !display.has_audio() {
            info!("the VM has no audio device: capturing audio, playing none");
            None
        } else {
            let audio_dest = match &bus_name {
                Some(name) => Some(
                    BusName::try_from(name.clone())
                        .map_err(|e| Error::Failed(format!("Invalid bus name {name}: {e}")))?,
                ),
                None => None,
            };
            match qemu_display::Audio::new(&conn, audio_dest).await {
                Ok(mut iface) => match iface.register_out_listener(audio.clone()).await {
                    Ok(()) => {
                        server.set_audio(Some(audio));
                        Some(iface)
                    }
                    Err(e) => {
                        warn!("failed to register the audio listener: {e}");
                        None
                    }
                },
                Err(e) => {
                    info!("no audio interface on the VM: {e}");
                    None
                }
            }
        }
    } else {
        None
    };

    Vnc1Server::setup(&conn, server.clone()).await?;

    let mut listener: Option<async_io::Async<TcpListener>> = None;
    // Only the WebSocket listener ever fills this one.
    #[cfg_attr(not(feature = "websockets"), allow(unused_mut))]
    let mut websocket: Option<async_io::Async<TcpListener>> = None;
    if let Some(addr) = vnc_addr {
        let socket = TcpListener::bind(addr)?;
        let addr = socket.local_addr()?;
        info!(%addr, "VNC server listening");
        server.add_listener(ListenerInfo {
            addr,
            auth: "None".into(),
            websocket: false,
        });
        listener = Some(async_io::Async::new(socket)?);
    } else {
        warn!("the VNC server is disabled");
    }
    #[cfg(feature = "websockets")]
    let web_root: Option<Arc<std::path::PathBuf>> = match &args.web {
        Some(dir) => {
            let root = std::fs::canonicalize(dir).map_err(|e| {
                Error::Failed(format!("Invalid --web directory {}: {e}", dir.display()))
            })?;
            if !root.is_dir() {
                return Err(Error::Failed(format!(
                    "--web {} is not a directory",
                    root.display()
                )));
            }
            Some(Arc::new(root))
        }
        None => None,
    };
    #[cfg(not(feature = "websockets"))]
    let web_root: Option<Arc<std::path::PathBuf>> = None;

    #[cfg(feature = "websockets")]
    if let Some(addr) = &args.websocket {
        match parse_addr(addr)? {
            Some(addr) => {
                let socket = TcpListener::bind(addr)?;
                let addr = socket.local_addr()?;
                info!(%addr, "VNC WebSocket server listening");
                if let Some(root) = &web_root {
                    info!(
                        root = %root.display(),
                        "serving {} over HTTP on http://{addr}/; the VNC WebSocket is at ws://{addr}/websockify",
                        root.display()
                    );
                }
                server.add_listener(ListenerInfo {
                    addr,
                    auth: "None".into(),
                    websocket: true,
                });
                websocket = Some(async_io::Async::new(socket)?);
            }
            None => {
                if web_root.is_some() {
                    return Err(Error::Failed(
                        "--web needs a WebSocket listener to serve on".into(),
                    ));
                }
                warn!("the VNC WebSocket server is disabled");
            }
        }
    }

    let mut consoles = 0;
    for id in vm.console_ids().await? {
        match server.add_graphic_console(id).await {
            Ok(console) => {
                info!(id, label = %console.label().await, "console registered");
                consoles += 1;
            }
            Err(e) => error!("failed to setup console {id}: {e}"),
        }
    }
    if consoles == 0 {
        return Err(Error::Failed("No consoles found".into()));
    }

    if display.clipboard().await?.is_some() {
        let peer = Clipboard::register(&conn, server.downgrade()).await?;
        server.set_clipboard(peer);
    }
    if !args.no_vt {
        let names = (!args.vt_chardev.is_empty()).then_some(args.vt_chardev.as_slice());
        if let Err(e) = chardev::setup(&server, &display, names).await {
            error!("failed to setup the chardevs: {e}");
        }
    }

    // The heartbeat reports what the server has actually been doing, every five
    // seconds, for as long as it runs. It exists because a loop that spins
    // produces no log output at all: a quiet log is indistinguishable from a
    // correctly idle server, and that is how two rounds of logs failed to
    // account for a saturated core.
    //
    // **Spawned, not selected, and that is the whole of it.** The first version
    // raced it against `main_loop` with `select`, on the reasoning that a task
    // would do. A task is not enough: `select` polls both futures from *one*
    // poll of the enclosing task, so a `main_loop` that spins — which is exactly
    // what this heartbeat exists to detect — never yields, never gets to the
    // second branch, and the timer inside the heartbeat is never woken. The
    // diagnostic could not report the fault it was built for. It printed once at
    // startup, before the loop, and then never again for the twenty-nine seconds
    // a real run lasted: a heartbeat that is silent precisely when it is needed.
    //
    // `async_io::spawn` gives it a thread of its own. It costs one thread and one
    // timer wake-up per interval, and it cannot be starved by anything in this
    // process, which is the property that makes it worth anything.
    // A thread of its own rather than a task on the same executor, so that
    // nothing in this process can starve it. It has no shutdown to do and must
    // not have one: a heartbeat that could be stopped is a heartbeat that stops
    // exactly when it is wanted.
    std::thread::Builder::new()
        .name("heartbeat".into())
        .spawn(|| {
            async_io::block_on(qemu_vnc::counters::heartbeat(async {
                futures::future::pending::<()>().await;
            }))
        })
        .map_err(|e| Error::Failed(format!("failed to start the heartbeat: {e}")))?;
    let reason = main_loop(
        &conn,
        &server,
        listener,
        websocket,
        &mut name_changed,
        bus_name.as_deref(),
        web_root,
    )
    .await;
    info!("shutting down: {reason}");
    if let Err(e) = dbus::leaving(&conn, &reason).await {
        error!("failed to emit Leaving: {e}");
    }
    server.terminate_clients();
    Ok(())
}

/// How many times a lost name watch may be put back before it is treated as
/// the connection being gone after all.
const MAX_WATCH_RESTARTS: u32 = 3;

/// A connection accepted on one of the listeners.
type Accepted = std::io::Result<(async_io::Async<std::net::TcpStream>, SocketAddr)>;

/// Hand an accepted connection over to the server.
#[cfg_attr(not(feature = "websockets"), allow(unused_variables))]
fn accept_client(
    server: &Server,
    accepted: Accepted,
    websocket: bool,
    web_root: Option<&Arc<std::path::PathBuf>>,
) {
    let (stream, addr) = match accepted {
        Ok(accepted) => accepted,
        Err(e) => {
            error!("failed to accept a connection: {e}");
            return;
        }
    };
    let stream = match stream.into_inner() {
        Ok(stream) => stream,
        Err(e) => {
            error!("failed to take over the socket of {addr}: {e}");
            return;
        }
    };
    // A WebSocket listener with a document root answers HTTP first: the request
    // says whether the connection is a viewer or a browser fetching a page.
    #[cfg(feature = "websockets")]
    if websocket && let Some(root) = web_root {
        dispatch_web(server, stream, addr, Arc::clone(root));
        return;
    }
    let result = if websocket {
        #[cfg(feature = "websockets")]
        {
            server.add_websocket_client(stream, addr)
        }
        // Without the feature the second listener is never armed, so this is
        // unreachable; the branch keeps the two builds the same.
        #[cfg(not(feature = "websockets"))]
        {
            let _ = (stream, addr);
            Err(Error::Failed("built without WebSocket support".into()))
        }
    } else {
        server.add_client(stream, addr)
    };
    if let Err(e) = result {
        error!("failed to add client {addr}: {e}");
    }
}

/// Tell a WebSocket upgrade from a page, and serve the page if that is what it
/// is.
///
/// **On a thread of its own**, because the request head has to arrive before it
/// can be classified and the main loop serves every other connection while it
/// waits; and **before the connection is registered**, so that fetching
/// `vnc.html` does not appear as a VNC client in the `Clients` D-Bus property
/// and then vanish.
#[cfg(feature = "websockets")]
fn dispatch_web(
    server: &Server,
    stream: std::net::TcpStream,
    addr: SocketAddr,
    root: Arc<std::path::PathBuf>,
) {
    let server = server.clone();
    let result = std::thread::Builder::new()
        .name(format!("vnc-http-{addr}"))
        .spawn(
            move || match async_io::block_on(qemu_vnc::web::dispatch(stream, &root)) {
                Ok(qemu_vnc::web::Dispatch::Upgrade { stream, replay }) => {
                    if let Err(e) = server.add_websocket_client_replaying(stream, addr, replay) {
                        error!("failed to add client {addr}: {e}");
                    }
                }
                Ok(qemu_vnc::web::Dispatch::Served) => {}
                Err(e) => warn!("failed to answer an HTTP request from {addr}: {e}"),
            },
        );
    if let Err(e) = result {
        error!("failed to start the HTTP thread for {addr}: {e}");
    }
}

/// The main loop: accept clients, and watch the D-Bus name owner.
///
/// A client arrives either on the VNC socket or on the WebSocket one, and
/// both are served the same RFB stream.
/// Wait for one connection on `listener`, or for ever if there is no listener.
///
/// The `None` case is the whole difficulty, and it is one where the obvious
/// spelling is a spin. The type has to stay `Accepted` so that both arms of the
/// match produce it, so the absent listener has to *wait* rather than report:
///
/// ```ignore
/// None => Either::Right(pending::<Accepted>())   // what it used to say
/// ```
///
/// That returns a future as a **payload**. Nothing awaits it, so the enclosing
/// `async` block finishes on its first poll, the `select!` branch is `Ready`
/// immediately, the handler finds `Either::Right` and does nothing, and the
/// event loop turns over — 330,000 times a second, forever, on a machine with
/// no WebSocket listener and no intention of having one. It is not a hang and it
/// is not a crash: it is a loop that waits for nothing, which is why it produced
/// no output of any kind and looked identical to a correctly idle server.
///
/// `pending().await` is the way to wait for ever, and it is the only thing in
/// this function that can be hard to get right, so it is why the function
/// exists at all.
async fn accept_one(listener: &mut Option<async_io::Async<TcpListener>>) -> Accepted {
    match listener.as_mut() {
        Some(listener) => listener.accept().await,
        None => futures::future::pending().await,
    }
}

/// Wait for the next `NameOwnerChanged`, or for ever if there is no watch.
///
/// The same trap as [`accept_one`], and the same fix: the absent watch has to
/// wait rather than hand back a future nobody awaits.
async fn next_name_owner_change(
    name_changed: &mut Option<zbus::fdo::NameOwnerChangedStream>,
) -> Option<zbus::fdo::NameOwnerChanged> {
    match name_changed.as_mut() {
        Some(stream) => stream.next().await,
        None => futures::future::pending().await,
    }
}

async fn main_loop(
    conn: &zbus::Connection,
    server: &Server,
    mut listener: Option<async_io::Async<TcpListener>>,
    mut websocket: Option<async_io::Async<TcpListener>>,
    name_changed: &mut Option<zbus::fdo::NameOwnerChangedStream>,
    bus_name: Option<&str>,
    web_root: Option<Arc<std::path::PathBuf>>,
) -> String {
    let events = server.events();
    let mut watch_restarts = 0;

    loop {
        qemu_vnc::counters::counters().main_loop.bump();
        let mut event = Box::pin(events.recv()).fuse();
        let mut accept = Box::pin(accept_one(&mut listener)).fuse();
        let mut accept_ws = Box::pin(accept_one(&mut websocket)).fuse();
        // The watch is taken for the duration of the wait rather than borrowed,
        // so that the arm which has to *replace* it is not fighting the borrow
        // of the branch that is reading it. The replacement is then a local
        // assignment, and the stream is put back when the wait is over. The
        // paths that `return` from inside the `select!` are the shutdown ones,
        // where losing it costs nothing.
        let mut watch = name_changed.take();
        let mut owner_changed = Box::pin(next_name_owner_change(&mut watch)).fuse();
        // **The connection dying, which on a peer-to-peer link is the only way
        // to learn it.** The name watch compares against `org.qemu`, and a
        // peer-to-peer connection owns no well-known name, so no
        // `NameOwnerChanged` for it is ever delivered and that arm cannot fire --
        // which is how a server whose QEMU had gone was found still running,
        // still holding its client's socket, with `main_loop` parked on a select
        // nothing would ever wake.
        //
        // `Connection::closed` is the one primitive that covers both shapes: it
        // resolves on a remote disconnect, on an I/O error, and on a close we
        // asked for, and it resolves immediately if the connection is already
        // gone. The watch is not redundant with it -- a bus connection can lose
        // the peer's name and stay perfectly usable -- but it cannot replace it.
        let mut conn_closed = Box::pin(conn.closed()).fuse();

        let outcome = futures::select! {
            event = event => {
                qemu_vnc::counters::counters().main_loop_event.bump();
                match event {
                    Ok(event) => {
                        handle_event(server, event).await;
                        (None, false)
                    }
                    Err(_) => (Some("D-Bus connection closed".into()), true),
                }
            }
            accepted = accept => {
                qemu_vnc::counters::counters().main_loop_accept.bump();
                accept_client(server, accepted, false, None);
                (None, false)
            },
                        accepted = accept_ws => {
                qemu_vnc::counters::counters().main_loop_accept_ws.bump();
                accept_client(server, accepted, true, web_root.as_ref());
                (None, false)
            },
                        signal = owner_changed => {
                qemu_vnc::counters::counters().main_loop_owner.bump();
                match signal {
                    Some(signal) => {
                        let vanished = match signal.args() {
                            Ok(args) => {
                                args.name == bus_name.unwrap_or(DEFAULT_BUS_NAME)
                                    && args.new_owner.is_none()
                            }
                            Err(e) => {
                                warn!("failed to parse the name owner signal: {e}");
                                false
                            }
                        };
                        if vanished {
                            (Some(format!("D-Bus peer {} vanished",
                                bus_name.unwrap_or(DEFAULT_BUS_NAME))), true)
                        } else {
                            (None, false)
                        }
                    }
                    // The watch ended. That is the symptom of a lost
                    // connection and it is also the symptom of a lost *watch*,
                    // and the two call for opposite responses: the first means
                    // stop, the second means the server is fine and only our
                    // view of the peer's name is gone. The connection says
                    // which, so ask it rather than reporting one message for
                    // both.
                    _ if conn.is_closed() => {
                        (Some("D-Bus connection closed".into()), true)
                    }
                    _ => {
                        // The connection is fine, so the server can go on
                        // serving: what was lost is our view of the peer's
                        // name, and that is worth putting back rather than
                        // shutting a working server down over. Bounded, because
                        // a watch that ends the moment it is made would
                        // otherwise turn into a loop.
                        watch_restarts += 1;
                        if watch_restarts > MAX_WATCH_RESTARTS {
                            return "the D-Bus name watch kept ending".to_owned();
                        }
                        match name_watch(conn).await {
                            Ok(watch) => {
                                warn!(
                                    restarts = watch_restarts,
                                    "the name owner watch ended with the connection \\
                                     still open; watching again"
                                );
                                *name_changed = Some(watch);
                                (None, false)
                            }
                            Err(e) => {
                                (Some(format!("failed to watch the D-Bus name again: {e}")), true)
                            }
                        }
                    }
                }
            },
            _closed = conn_closed => {
                qemu_vnc::counters::counters().main_loop_conn_closed.bump();
                (Some("D-Bus connection closed".into()), true)
            },
        };
        // The wait is over, so the borrow it held is released and the watch can
        // go back. A server that has been serving for hours still has one to
        // lose and put back again.
        drop(owner_changed);
        drop(conn_closed);
        *name_changed = watch;
        let (reason, done) = outcome;
        if done {
            return reason.unwrap_or_else(|| "Shutting down".into());
        }
    }
}

/// React to the events of the client threads.
async fn handle_event(server: &Server, event: ServerEvent) {
    let conn = server.connection();
    match event {
        ServerEvent::ClientConnected(info) => {
            info!(id = info.id, host = %info.host, "client connected");
            if let Err(e) = dbus::client_connected(conn, server, &info).await {
                error!("failed to export the client object: {e}");
            }
        }
        ServerEvent::ClientInitialized(id) => {
            if let Err(e) = dbus::client_initialized(conn, id).await {
                error!("failed to emit ClientInitialized: {e}");
            }
        }
        ServerEvent::ClientDisconnected(id) => {
            info!(id, "client disconnected");
            if let Err(e) = dbus::client_disconnected(conn, id).await {
                error!("failed to emit ClientDisconnected: {e}");
            }
        }
        ServerEvent::Terminate(reason) => {
            error!("terminating: {reason}");
        }
    }
}

/// Set up the tracing subscriber, from the `--trace` option.
fn init_tracing(trace: Option<&str>) {
    let filter = match trace {
        Some(trace) => EnvFilter::new(trace),
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    };
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .try_init();
}

fn main() -> ExitCode {
    match async_io::block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("qemu-vnc: {e}");
            let mut source = std::error::Error::source(&e);
            while let Some(e) = source {
                eprintln!("qemu-vnc:   caused by: {e}");
                source = e.source();
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An absent listener must leave the loop waiting, not turning over.
    ///
    /// This is the whole of the fault, and it is a fault about a type. The
    /// branch has to produce an `Accepted` whichever way the option goes, and
    /// the tempting way to say "no listener" is to hand back a future that never
    /// completes:
    ///
    /// ```ignore
    /// None => Either::Right(pending::<Accepted>())
    /// ```
    ///
    /// That compiles, it type-checks, and the `select!` arm is written to
    /// ignore `Either::Right` — so nothing looks wrong. But nothing *awaits* the
    /// `pending()`: it is returned as a payload, the enclosing `async` block
    /// finishes on its first poll, the branch is `Ready` immediately, the arm
    /// does nothing, and the event loop turns over. Measured at 330,000
    /// iterations a second on a machine with no WebSocket listener and no
    /// intention of having one.
    ///
    /// What it looked like from outside: 100% CPU with nothing in the log. Not a
    /// hang, not a crash, not a warning — a loop waiting for nothing, which is
    /// indistinguishable from a correctly idle server by any observation short of
    /// counting the iterations. It is why three rounds of logs failed, and why
    /// the per-branch counters were the thing that found it.
    #[test]
    fn an_absent_listener_leaves_the_branch_pending() {
        let mut none: Option<async_io::Async<TcpListener>> = None;
        // Poll it properly: a future that is `Pending` once and then `Ready` is
        // the bug, and only the second poll can tell.
        let mut branch = Box::pin(accept_one(&mut none));
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(
            branch.as_mut().poll(&mut cx).is_pending(),
            "a branch with no listener must never be ready"
        );
        assert!(
            branch.as_mut().poll(&mut cx).is_pending(),
            "and must still not be ready on the second poll, which is where a \\
             payload of \\`pending()\\` gives itself away"
        );
        std::hint::black_box(&mut branch);
    }

    /// The same, for the name-owner watch.
    ///
    /// A separate test because it is a separate arm, and because the production
    /// case has the watch *present* while the WebSocket listener is absent —
    /// which is exactly why the first three rounds of evidence pointed the wrong
    /// way. The watch arm looked exercised; the branch next to it never was.
    #[test]
    fn an_absent_watch_leaves_the_branch_pending() {
        let mut none: Option<zbus::fdo::NameOwnerChangedStream> = None;
        let mut branch = Box::pin(next_name_owner_change(&mut none));
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        assert!(branch.as_mut().poll(&mut cx).is_pending());
        assert!(branch.as_mut().poll(&mut cx).is_pending());
        std::hint::black_box(&mut branch);
    }

    /// The document root is served on the WebSocket listener, so a `--web` with
    /// no `--websocket` has nowhere to serve and must be refused rather than
    /// silently ignored.
    #[cfg(feature = "websockets")]
    #[test]
    fn the_document_root_needs_the_websocket_listener() {
        let error = Cli::try_parse_from(["qemu-vnc", "--web", "/tmp"]).unwrap_err();
        assert!(
            error.to_string().contains("--websocket"),
            "the error should name the listener that is missing: {error}"
        );
        let cli = Cli::try_parse_from(["qemu-vnc", "--websocket", "6080", "--web", "/tmp"])
            .expect("a document root and a listener");
        assert_eq!(
            cli.web.as_deref(),
            Some(std::path::Path::new("/tmp")),
            "the directory must survive parsing unchanged"
        );
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;

    /// **The loop must notice a connection that dies, on a peer-to-peer link.**
    ///
    /// This is the fault that left a server running, holding a client's socket,
    /// after its QEMU had gone: the loop learned of the peer's departure from a
    /// `NameOwnerChanged` signal for `org.qemu`, which a peer-to-peer connection
    /// never receives because it owns no such name. With no listeners and no
    /// watch there is then nothing in the `select!` that can ever be ready, so
    /// the loop parks -- which a heartbeat renders as every wake counter reading
    /// zero, and which looked from the outside like a correctly idle server.
    ///
    /// `Connection::closed` is what covers it: it resolves on a remote
    /// disconnect, on an I/O error, and on a close asked for here.
    #[test]
    fn the_loop_notices_a_connection_that_dies() {
        async_io::block_on(async {
            let (_server_end, client_end) = p2p_pair().await;
            let server = Server::new(&client_end, "mock", Share::Ignore)
                .await
                .expect("a server");

            // A thread of its own, because the assertion is about a future that
            // does *not* resolve: awaiting it on this thread would hang the test
            // rather than fail it, and a hanging test is the bug being looked for.
            let conn = client_end.clone();
            let handle = std::thread::Builder::new()
                .name("main-loop-under-test".to_string())
                .spawn(move || {
                    async_io::block_on(async move {
                        let mut no_watch: Option<zbus::fdo::NameOwnerChangedStream> = None;
                        // No listener and no name watch on either kind of
                        // connection: the connection dying is the only thing
                        // that can end this, which is the point.
                        main_loop(&conn, &server, None, None, &mut no_watch, None, None).await
                    })
                })
                .expect("a thread for the loop");

            // Let it reach the select before the connection goes, or the test
            // would pass on a loop that had not started.
            async_io::Timer::after(std::time::Duration::from_millis(50)).await;
            client_end.close().await.expect("the connection to close");

            let reason = handle.join().expect("the loop thread");
            assert!(
                reason.contains("closed"),
                "the loop ended for the wrong reason: {reason}"
            );
        });
    }
}

/// Two ends of a peer-to-peer socket pair, which is what `--dbus-p2p-fd` hands
/// the real program.
///
/// The full mock is not available here -- it belongs to `tests/mock.rs`, a
/// different binary -- and it is not needed: these tests want a live `Server`
/// whose D-Bus peer can be closed, not a VM behind it.
#[cfg(test)]
async fn p2p_pair() -> (zbus::Connection, zbus::Connection) {
    use std::os::fd::IntoRawFd;
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().expect("a socket pair");
    let ours = zbus::connection::Builder::unix_stream(ours)
        .server(zbus::Guid::generate())
        .p2p()
        .build();
    let theirs = qemu_vnc::utils::p2p_from_fd(theirs.into_raw_fd());
    let (a, b) = futures::future::join(ours, theirs).await;
    (a.expect("the server end"), b.expect("the client end"))
}

/// The WebSocket listener when it is also the document server.
#[cfg(all(test, feature = "websockets"))]
mod web_listener_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    /// A request for a file on the WebSocket listener's port must be answered
    /// with the file, and must not register a VNC client.
    ///
    /// The accept path is the part the library tests cannot reach: `dispatch`
    /// being right is not enough if the program hands every accepted socket to
    /// the WebSocket layer before looking at it. A browser fetching `vnc.html`
    /// would then be refused the upgrade and the page would never load -- and
    /// if the order were the other way round, the page would be announced to
    /// D-Bus as a client and immediately disconnected.
    #[test]
    fn a_page_fetched_on_the_websocket_listener_is_not_a_vnc_client() {
        async_io::block_on(async {
            let (_server_end, client_end) = p2p_pair().await;
            let server = Server::new(&client_end, "mock", Share::Ignore)
                .await
                .expect("a server");
            let events = server.events();

            let root =
                std::env::temp_dir().join(format!("qemu-vnc-listener-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("a document root");
            std::fs::write(root.join("vnc.html"), "<h1>viewer</h1>").expect("a page");
            let root = Arc::new(std::fs::canonicalize(&root).expect("the root"));

            let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
            let addr = listener.local_addr().expect("an address");
            let mut browser = TcpStream::connect(addr).expect("a browser");
            browser
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("a timeout");
            let (stream, peer) = listener.accept().expect("a connection");
            accept_client(
                &server,
                Ok((async_io::Async::new(stream).expect("an async socket"), peer)),
                true,
                Some(&root),
            );

            browser
                .write_all(b"GET /vnc.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .expect("the request");
            browser.flush().expect("flush");
            let mut response = Vec::new();
            browser.read_to_end(&mut response).expect("the response");
            let response = String::from_utf8_lossy(&response).to_string();
            assert!(
                response.starts_with("HTTP/1.1 200 OK"),
                "the page was not served on the WebSocket listener's port: {response}"
            );
            assert!(
                response.ends_with("<h1>viewer</h1>"),
                "the response is not the file: {response}"
            );
            assert!(
                events.try_recv().is_err(),
                "an HTTP GET must not be announced as a VNC client"
            );

            let _ = std::fs::remove_dir_all(&*root);
        });
    }

    /// An upgrade on the listener must be replayed into the handshake.
    ///
    /// Classifying the request reads it, so the bytes are out of the socket by
    /// the time the WebSocket layer gets it. Without the replay the handshake
    /// waits for a request that already arrived, and the client never gets its
    /// `101`.
    #[test]
    fn an_upgrade_on_the_websocket_listener_is_replayed_into_the_handshake() {
        async_io::block_on(async {
            let (_server_end, client_end) = p2p_pair().await;
            let server = Server::new(&client_end, "mock", Share::Ignore)
                .await
                .expect("a server");
            let events = server.events();

            let root = std::env::temp_dir()
                .join(format!("qemu-vnc-listener-upgrade-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("a document root");
            let root = Arc::new(std::fs::canonicalize(&root).expect("the root"));

            let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
            let addr = listener.local_addr().expect("an address");
            let mut client = TcpStream::connect(addr).expect("a client");
            client
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("a timeout");
            let (stream, peer) = listener.accept().expect("a connection");
            accept_client(
                &server,
                Ok((async_io::Async::new(stream).expect("an async socket"), peer)),
                true,
                Some(&root),
            );

            client
                .write_all(
                    b"GET /websockify HTTP/1.1\r\n\
                      Host: localhost\r\n\
                      Upgrade: websocket\r\n\
                      Connection: Upgrade\r\n\
                      Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                      Sec-WebSocket-Version: 13\r\n\
                      \r\n",
                )
                .expect("the upgrade");
            client.flush().expect("flush");

            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                client.read_exact(&mut byte).expect("the upgrade response");
                head.push(byte[0]);
            }
            let head = String::from_utf8_lossy(&head).to_string();
            assert!(
                head.starts_with("HTTP/1.1 101"),
                "the upgrade was not accepted: {head}"
            );

            // The RFB greeting, in the first binary frame the server sends.
            let mut frame = [0u8; 14];
            client.read_exact(&mut frame).expect("the RFB greeting");
            assert_eq!(frame[0], 0x82, "the greeting is not a binary frame");
            assert_eq!(
                frame[1] as usize,
                "RFB 003.008\n".len(),
                "the greeting frame length"
            );
            assert_eq!(&frame[2..], b"RFB 003.008\n");

            match events.try_recv() {
                Ok(ServerEvent::ClientConnected(info)) => {
                    assert!(
                        info.websocket,
                        "the upgrade was not announced as a WebSocket client"
                    );
                }
                other => panic!("the upgrade was not announced as a client: {other:?}"),
            }

            let _ = std::fs::remove_dir_all(&*root);
        });
    }
}
