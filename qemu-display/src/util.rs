use crate::Result;

#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use win32::Fd;
#[cfg(unix)]
use zbus::Fd;

#[cfg(windows)]
use crate::win32;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
#[cfg(windows)]
use uds_windows::UnixStream;
#[cfg(windows)]
use windows::Win32::Networking::WinSock::SOCKET;
#[cfg(windows)]
use windows::Win32::System::Threading::PROCESS_DUP_HANDLE;

pub fn prepare_uds_pass(#[cfg(windows)] peer_pid: u32, us: &UnixStream) -> Result<Fd<'_>> {
    #[cfg(unix)]
    {
        Ok(us.into())
    }

    #[cfg(windows)]
    {
        let p = win32::ProcessHandle::open(Some(peer_pid as _), PROCESS_DUP_HANDLE)?;
        p.duplicate_socket(SOCKET(us.as_raw_socket() as _))
    }
}
