//! Chardev registration, to expose serial and monitor consoles to the VNC
//! clients as text consoles.
//!
//! Port of `chardev.c`.

use std::io::{Read, Write};
use std::thread;

use qemu_display::{Chardev, Display, Result};
use tracing::{debug, info, warn};

use crate::console::{Encoding, TextConsole};
use crate::server::Server;

/// The chardevs exposed as text consoles, unless `--vt-chardev` is used.
pub const DEFAULT_CHARDEV_NAMES: &[&str] = &["org.qemu.console.serial.0", "org.qemu.monitor.hmp.0"];

/// The `org.qemu.Display1.Chardev.VCEncoding` interface.
#[zbus::proxy(interface = "org.qemu.Display1.Chardev.VCEncoding")]
trait ChardevVCEncoding {
    /// Encoding property
    #[zbus(property)]
    fn encoding(&self) -> zbus::Result<String>;
}

/// Expose the chardevs of `display` as text consoles of `server`.
///
/// `names` is the list of chardev names to expose, or
/// [`DEFAULT_CHARDEV_NAMES`] when `None`.
#[cfg(unix)]
pub async fn setup(server: &Server, display: &Display<'_>, names: Option<&[String]>) -> Result<()> {
    let names: Vec<&str> = match names {
        Some(names) => names.iter().map(String::as_str).collect(),
        None => DEFAULT_CHARDEV_NAMES.to_vec(),
    };

    for chardev in display.chardevs().await {
        let Ok(name) = chardev.proxy.name().await else {
            continue;
        };
        if !names.contains(&name.as_str()) {
            continue;
        }
        match register(server, chardev, name).await {
            Ok(index) => info!(index, "chardev registered as a text console"),
            Err(e) => warn!("failed to register chardev: {e}"),
        }
    }
    Ok(())
}

/// Chardevs need a Unix socket to be passed over D-Bus.
#[cfg(not(unix))]
pub async fn setup(
    _server: &Server,
    _display: &Display<'_>,
    _names: Option<&[String]>,
) -> Result<()> {
    warn!("text consoles are only supported on unix");
    Ok(())
}

/// Register a single chardev, and start pumping its data through a
/// [`TextConsole`].
#[cfg(unix)]
async fn register(server: &Server, chardev: Chardev, name: String) -> Result<u32> {
    use std::os::unix::net::UnixStream;

    let echo = chardev.proxy.echo().await.unwrap_or(false);
    let encoding = encoding(&chardev).await.unwrap_or_default();

    // QEMU keeps one end of the socket, we keep the other one.
    let (local, remote) = UnixStream::pair()?;
    chardev.proxy.register((&remote).into()).await?;
    drop(remote);

    let (tx, rx) = async_channel::unbounded();
    let console = TextConsole::new(name.clone(), echo, encoding, tx);
    let index = server.add_text_console(console.clone());

    // Read the guest output, and feed the VT100 emulator.
    let mut reader = local.try_clone()?;
    let server = server.clone();
    let reader_name = name.clone();
    thread::Builder::new()
        .name(format!("chardev-{name}"))
        .spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        debug!(name = %reader_name, "chardev closed");
                        break;
                    }
                    Ok(n) => {
                        console.process(&buf[..n]);
                        // A text console is redrawn whole: the terminal
                        // emulator has no notion of partial damage.
                        server.console_updated(index, None);
                    }
                    Err(e) => {
                        debug!(name = %reader_name, "chardev read error: {e}");
                        break;
                    }
                }
            }
        })?;

    // Write the keys typed by the VNC clients.
    thread::Builder::new()
        .name(format!("chardev-{name}-out"))
        .spawn(move || {
            let mut writer = local;
            while let Ok(data) = rx.recv_blocking() {
                if let Err(e) = writer.write_all(&data) {
                    debug!(%name, "chardev write error: {e}");
                    break;
                }
            }
        })?;

    Ok(index)
}

/// Read the `VCEncoding` property of a chardev.
#[cfg(unix)]
async fn encoding(chardev: &Chardev) -> Option<Encoding> {
    let inner = chardev.proxy.inner();
    let proxy = ChardevVCEncodingProxy::builder(inner.connection())
        .destination(inner.destination().to_owned())
        .path(inner.path().to_owned())
        .build()
        .await
        .ok()?;
    proxy.encoding().await.ok().map(|e| Encoding::parse(&e))
}
