#[cfg(windows)]
use crate::win32::{Fd, Mmap};

#[cfg(unix)]
use memmap2::Mmap;
use std::ops::Drop;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
#[cfg(unix)]
use std::os::{
    fd::{AsFd, OwnedFd},
    unix::io::{AsRawFd, RawFd},
};
#[cfg(unix)]
use zbus::Fd;

#[derive(derive_more::Debug)]
pub struct Scanout {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
    #[debug(skip)]
    pub data: Vec<u8>,
}

#[derive(derive_more::Debug)]
pub struct Update {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub stride: u32,
    pub format: u32,
    #[debug(skip)]
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct ScanoutMap {
    #[cfg(unix)]
    pub fd: OwnedFd,
    #[cfg(windows)]
    pub handle: OwnedHandle,
    pub offset: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
}

#[derive(Debug)]
pub struct ScanoutMmap {
    scanout: ScanoutMap,
    mmap: Mmap,
}

impl ScanoutMap {
    /// Map the surface QEMU offered, **read-only and private**.
    ///
    /// `map_copy_read_only()` is `MAP_PRIVATE` with `PROT_READ`, which is what
    /// `c/display.c`'s `on_scanout_map` uses, with its reason in the comment
    /// above the call: *"MAP_PRIVATE: we only read; avoid propagating writes
    /// back to QEMU."*
    ///
    /// This used to be `MmapOptions::map()`, whose defaults are `MAP_SHARED`
    /// and writable. Nothing wrote through it, and nothing *could*:
    /// `ScanoutMmap` holds its `Mmap` privately and implements only
    /// `AsRef<[u8]>`, so a writable mapping was not reachable through this API
    /// in the first place. The default was an accident of an omitted argument
    /// standing in for an invariant, and the fix is to say the invariant rather
    /// than to add a mode parameter with one user and one branch.
    ///
    /// The practical difference is nil today and the parity difference is not:
    /// a port should not be more permissive with QEMU's memory than the program
    /// it is a port of.
    pub fn mmap(self) -> std::io::Result<ScanoutMmap> {
        let len = self.height as usize * self.stride as usize;
        let offset = self.offset;

        #[cfg(unix)]
        let desc = self.fd.as_raw_fd();
        #[cfg(windows)]
        let desc = self.handle.as_raw_handle();

        #[cfg(unix)]
        let mmap = unsafe {
            memmap2::MmapOptions::new()
                .len(len)
                .offset(offset.into())
                // `unsafe` because the length and offset come from QEMU, which
                // is the peer: both are checked against the descriptor's actual
                // size by `mmap` itself, and a mapping past the end of the file
                // fails rather than succeeding.
                .map_copy_read_only(desc)?
        };

        #[cfg(windows)]
        let mmap = {
            use windows::Win32::Foundation::HANDLE;
            let handle = HANDLE(desc as _);
            Mmap::new(handle, offset.try_into().unwrap(), len)?
        };

        Ok(ScanoutMmap {
            scanout: self,
            mmap,
        })
    }
}

impl ScanoutMmap {
    pub fn stride(&self) -> u32 {
        self.scanout.stride
    }

    pub fn format(&self) -> u32 {
        self.scanout.format
    }
}

impl AsRef<[u8]> for ScanoutMmap {
    fn as_ref(&self) -> &[u8] {
        self.mmap.as_ref()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct UpdateMap {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

#[cfg(windows)]
#[derive(Debug)]
pub struct ScanoutD3dTexture2d {
    pub handle: u64,
    pub tex_width: u32,
    pub tex_height: u32,
    pub y0_top: bool,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

#[cfg(windows)]
#[derive(Debug, Copy, Clone)]
pub struct UpdateD3dTexture2d {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

#[cfg(unix)]
#[derive(Debug)]
pub struct ScanoutDMABUF {
    pub fd: [RawFd; 4],
    pub width: u32,
    pub height: u32,
    pub offset: [u32; 4],
    pub stride: [u32; 4],
    pub fourcc: u32,
    pub modifier: u64,
    pub y0_top: bool,
    pub num_planes: u32,
}

#[cfg(windows)]
#[derive(Debug)]
pub struct ScanoutDMABUF {}

#[derive(derive_more::Debug)]
pub struct Cursor {
    pub width: i32,
    pub height: i32,
    pub hot_x: i32,
    pub hot_y: i32,
    #[debug(skip)]
    pub data: Vec<u8>,
}

#[cfg(unix)]
impl Drop for ScanoutDMABUF {
    fn drop(&mut self) {
        for &fd in &self.fd {
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

#[cfg(unix)]
impl ScanoutDMABUF {
    pub fn into_raw_fds(mut self) -> [RawFd; 4] {
        std::mem::replace(&mut self.fd, [-1; 4])
    }
}

#[derive(Debug, Copy, Clone)]
pub struct MouseSet {
    pub x: i32,
    pub y: i32,
    pub on: i32,
}

#[derive(Debug, Copy, Clone)]
pub struct UpdateDMABUF {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

#[async_trait::async_trait]
pub trait ConsoleListenerHandler: 'static + Send + Sync {
    async fn scanout(&mut self, scanout: Scanout);

    async fn update(&mut self, update: Update);

    #[cfg(unix)]
    async fn scanout_dmabuf(&mut self, scanout: ScanoutDMABUF);

    #[cfg(unix)]
    async fn update_dmabuf(&mut self, update: UpdateDMABUF);

    async fn disable(&mut self);

    async fn mouse_set(&mut self, set: MouseSet);

    async fn cursor_define(&mut self, cursor: Cursor);

    fn disconnected(&mut self);

    fn interfaces(&self) -> Vec<String>;
}

#[derive(Debug)]
pub(crate) struct ConsoleListener<H: ConsoleListenerHandler> {
    handler: H,
}

#[zbus::interface(name = "org.qemu.Display1.Listener", spawn = false)]
impl<H: ConsoleListenerHandler> ConsoleListener<H> {
    async fn scanout(
        &mut self,
        width: u32,
        height: u32,
        stride: u32,
        format: u32,
        data: serde_bytes::ByteBuf,
    ) {
        self.handler
            .scanout(Scanout {
                width,
                height,
                stride,
                format,
                data: data.into_vec(),
            })
            .await;
    }

    async fn update(
        &mut self,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        stride: u32,
        format: u32,
        data: serde_bytes::ByteBuf,
    ) {
        self.handler
            .update(Update {
                x,
                y,
                w,
                h,
                stride,
                format,
                data: data.into_vec(),
            })
            .await;
    }

    #[cfg(not(unix))]
    #[zbus(name = "ScanoutDMABUF")]
    async fn scanout_dmabuf(
        &mut self,
        _fd: Fd<'_>,
        _width: u32,
        _height: u32,
        _stride: u32,
        _fourcc: u32,
        _modifier: u64,
        _y0_top: bool,
    ) -> zbus::fdo::Result<()> {
        Err(zbus::fdo::Error::NotSupported(
            "DMABUF is not support on !unix".into(),
        ))
    }

    #[cfg(unix)]
    #[zbus(name = "ScanoutDMABUF")]
    async fn scanout_dmabuf(
        &mut self,
        fd: Fd<'_>,
        width: u32,
        height: u32,
        stride: u32,
        fourcc: u32,
        modifier: u64,
        y0_top: bool,
    ) -> zbus::fdo::Result<()> {
        let fd = unsafe { libc::dup(fd.as_raw_fd()) };
        self.handler
            .scanout_dmabuf(ScanoutDMABUF {
                fd: [fd, -1, -1, -1],
                width,
                height,
                offset: [0; 4],
                stride: [stride, 0, 0, 0],
                fourcc,
                modifier,
                y0_top,
                num_planes: 1,
            })
            .await;
        Ok(())
    }

    #[cfg(not(unix))]
    #[zbus(name = "UpdateDMABUF")]
    async fn update_dmabuf(&mut self, _x: i32, _y: i32, _w: i32, _h: i32) -> zbus::fdo::Result<()> {
        Err(zbus::fdo::Error::NotSupported(
            "DMABUF is not support on !unix".into(),
        ))
    }

    #[cfg(unix)]
    #[zbus(name = "UpdateDMABUF")]
    async fn update_dmabuf(&mut self, x: i32, y: i32, w: i32, h: i32) -> zbus::fdo::Result<()> {
        self.handler
            .update_dmabuf(UpdateDMABUF { x, y, w, h })
            .await;
        Ok(())
    }

    async fn disable(&mut self) {
        self.handler.disable().await;
    }

    async fn mouse_set(&mut self, x: i32, y: i32, on: i32) {
        self.handler.mouse_set(MouseSet { x, y, on }).await;
    }

    async fn cursor_define(
        &mut self,
        width: i32,
        height: i32,
        hot_x: i32,
        hot_y: i32,
        data: Vec<u8>,
    ) {
        self.handler
            .cursor_define(Cursor {
                width,
                height,
                hot_x,
                hot_y,
                data,
            })
            .await;
    }

    #[zbus(property)]
    fn interfaces(&self) -> Vec<String> {
        self.handler.interfaces()
    }
}

impl<H: ConsoleListenerHandler> ConsoleListener<H> {
    pub(crate) fn new(handler: H) -> Self {
        Self { handler }
    }
}

impl<H: ConsoleListenerHandler> Drop for ConsoleListener<H> {
    fn drop(&mut self) {
        self.handler.disconnected();
    }
}

#[async_trait::async_trait]
pub trait ConsoleListenerMapHandler: 'static + Send + Sync {
    async fn scanout_map(&mut self, scanout: ScanoutMap);

    async fn update_map(&mut self, update: UpdateMap);
}

#[derive(Debug)]
pub(crate) struct ConsoleListenerMap<H: ConsoleListenerMapHandler> {
    handler: H,
}

#[cfg(unix)]
#[zbus::interface(name = "org.qemu.Display1.Listener.Unix.Map")]
impl<H: ConsoleListenerMapHandler> ConsoleListenerMap<H> {
    async fn scanout_map(
        &mut self,
        fd: Fd<'_>,
        offset: u32,
        width: u32,
        height: u32,
        stride: u32,
        format: u32,
    ) -> zbus::fdo::Result<()> {
        let map = ScanoutMap {
            fd: fd.as_fd().try_clone_to_owned().unwrap(),
            offset,
            width,
            height,
            stride,
            format,
        };
        self.handler.scanout_map(map).await;
        Ok(())
    }

    async fn update_map(&mut self, x: i32, y: i32, w: i32, h: i32) -> zbus::fdo::Result<()> {
        let up = UpdateMap { x, y, w, h };
        self.handler.update_map(up).await;
        Ok(())
    }
}

#[cfg(windows)]
#[zbus::interface(name = "org.qemu.Display1.Listener.Win32.Map")]
impl<H: ConsoleListenerMapHandler> ConsoleListenerMap<H> {
    async fn scanout_map(
        &mut self,
        handle: u64,
        offset: u32,
        width: u32,
        height: u32,
        stride: u32,
        format: u32,
    ) -> zbus::fdo::Result<()> {
        let handle = unsafe { OwnedHandle::from_raw_handle(handle as _) };
        let map = ScanoutMap {
            handle,
            offset,
            width,
            height,
            stride,
            format,
        };
        self.handler.scanout_map(map).await;
        Ok(())
    }

    async fn update_map(&mut self, x: i32, y: i32, w: i32, h: i32) -> zbus::fdo::Result<()> {
        let up = UpdateMap { x, y, w, h };
        self.handler.update_map(up).await;
        Ok(())
    }
}

impl<H: ConsoleListenerMapHandler> ConsoleListenerMap<H> {
    pub(crate) fn new(handler: H) -> Self {
        Self { handler }
    }
}

#[cfg(windows)]
#[async_trait::async_trait]
pub trait ConsoleListenerD3d11Handler: 'static + Send + Sync {
    async fn scanout_texture2d(&mut self, scanout: ScanoutD3dTexture2d);

    async fn update_texture2d(&mut self, update: UpdateD3dTexture2d);
}

#[cfg(windows)]
#[derive(Debug)]
pub(crate) struct ConsoleListenerD3d11<H: ConsoleListenerD3d11Handler> {
    handler: H,
}

#[cfg(windows)]
#[zbus::interface(name = "org.qemu.Display1.Listener.Win32.D3d11")]
impl<H: ConsoleListenerD3d11Handler> ConsoleListenerD3d11<H> {
    async fn scanout_texture2d(
        &mut self,
        handle: u64,
        tex_width: u32,
        tex_height: u32,
        y0_top: bool,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
    ) -> zbus::fdo::Result<()> {
        let texture = ScanoutD3dTexture2d {
            handle,
            tex_width,
            tex_height,
            y0_top,
            x,
            y,
            w,
            h,
        };
        self.handler.scanout_texture2d(texture).await;
        Ok(())
    }

    async fn update_texture2d(&mut self, x: i32, y: i32, w: i32, h: i32) -> zbus::fdo::Result<()> {
        let up = UpdateD3dTexture2d { x, y, w, h };
        self.handler.update_texture2d(up).await;
        Ok(())
    }
}

#[cfg(windows)]
impl<H: ConsoleListenerD3d11Handler> ConsoleListenerD3d11<H> {
    pub(crate) fn new(handler: H) -> Self {
        Self { handler }
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
pub trait ConsoleListenerScanoutDmabuf2Handler: 'static + Send + Sync {
    async fn scanout_dmabuf(&mut self, scanout: ScanoutDMABUF);
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct ConsoleListenerScanoutDmabuf2<H: ConsoleListenerScanoutDmabuf2Handler> {
    handler: H,
}

#[cfg(unix)]
#[zbus::interface(name = "org.qemu.Display1.Listener.Unix.ScanoutDMABUF2")]
impl<H: ConsoleListenerScanoutDmabuf2Handler> ConsoleListenerScanoutDmabuf2<H> {
    #[zbus(name = "ScanoutDMABUF2")]
    async fn scanout_dmabuf(
        &mut self,
        fd: Vec<Fd<'_>>,
        _x: u32,
        _y: u32,
        width: u32,
        height: u32,
        offset: Vec<u32>,
        stride: Vec<u32>,
        num_planes: u32,
        fourcc: u32,
        _backing_width: u32,
        _backing_height: u32,
        modifier: u64,
        y0_top: bool,
    ) -> zbus::fdo::Result<()> {
        let mut fds: [RawFd; 4] = [-1; 4];
        for (i, f) in fd.iter().take(4).enumerate() {
            fds[i] = unsafe { libc::dup(f.as_raw_fd()) };
        }

        let mut offsets: [u32; 4] = [0; 4];
        for (i, &o) in offset.iter().take(4).enumerate() {
            offsets[i] = o;
        }

        let mut strides: [u32; 4] = [0; 4];
        for (i, &s) in stride.iter().take(4).enumerate() {
            strides[i] = s;
        }

        self.handler
            .scanout_dmabuf(ScanoutDMABUF {
                fd: fds,
                width,
                height,
                offset: offsets,
                stride: strides,
                fourcc,
                modifier,
                y0_top,
                num_planes,
            })
            .await;
        Ok(())
    }
}

#[cfg(unix)]
impl<H: ConsoleListenerScanoutDmabuf2Handler> ConsoleListenerScanoutDmabuf2<H> {
    pub(crate) fn new(handler: H) -> Self {
        Self { handler }
    }
}
