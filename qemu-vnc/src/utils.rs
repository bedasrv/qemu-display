//! Helpers for the peer-to-peer D-Bus connections used to pass sockets
//! around.
//!
//! Port of `utils.c`.

#[cfg(not(unix))]
use qemu_display::Error;
use qemu_display::Result;

#[cfg(not(unix))]
use qemu_display::Error;
#[cfg(unix)]
use std::os::fd::FromRawFd;

/// Create a peer-to-peer D-Bus connection from an inherited socket.
///
/// This implements the `--dbus-p2p-fd` option, where the parent process
/// passes one end of an `AF_UNIX` socket pair.
#[cfg(unix)]
pub async fn p2p_from_fd(fd: std::os::fd::RawFd) -> Result<zbus::Connection> {
    use std::os::unix::net::UnixStream;

    // SAFETY: the caller gives up the ownership of the file descriptor.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    Ok(zbus::connection::Builder::unix_stream(stream)
        .p2p()
        .build()
        .await?)
}

/// Peer-to-peer sockets are only supported on unix.
#[cfg(not(unix))]
pub async fn p2p_from_fd(_fd: i32) -> Result<zbus::Connection> {
    Err(Error::Failed(
        "Peer-to-peer connections are not supported on this platform".into(),
    ))
}
