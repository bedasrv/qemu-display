use glib::{clone, MainContext};
use gtk::{glib, prelude::*};
use rdw::gtk;

#[cfg(unix)]
use std::os::unix::{
    io::{AsRawFd, RawFd},
    net::UnixStream,
};
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
    thread::JoinHandle,
};
#[cfg(windows)]
use uds_windows::UnixStream;
use usbredirhost::{
    rusb::{self, UsbContext},
    Device, DeviceHandler, LogLevel,
};

use qemu_display::{UsbRedir, UsbRedirBackend};

#[derive(Debug, Clone)]
pub struct RusbBackend;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key(u8, u8);

impl From<&rusb::Device<rusb::Context>> for Key {
    fn from(device: &rusb::Device<rusb::Context>) -> Self {
        Self(device.bus_number(), device.address())
    }
}

#[async_trait::async_trait]
impl UsbRedirBackend for RusbBackend {
    type Key = Key;
    type SessionInput = rusb::Device<rusb::Context>;
    type Session = RusbSession;

    async fn start_session(
        &self,
        device: Self::SessionInput,
        stream: UnixStream,
    ) -> qemu_display::Result<Self::Session> {
        RusbSession::new(&device, stream).await
    }
}

#[derive(Debug)]
struct SessionInner {
    #[allow(unused)] // keep the device opened, as rusb doesn't take it
    #[cfg(unix)]
    device_fd: Option<zbus::zvariant::OwnedFd>,
    stream: UnixStream,
    ctxt: rusb::Context,
    ctxt_thread: Option<JoinHandle<()>>,
    event: (UnixStream, UnixStream),
    quit: bool,
}

#[derive(Clone, Debug)]
struct StreamHandler {
    inner: Arc<Mutex<SessionInner>>,
}

impl DeviceHandler for StreamHandler {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        let read = match fd_poll_readable(inner.stream.as_raw_fd(), None) {
            Ok(true) => {
                let read = inner.stream.read(buf);
                if let Ok(0) = read {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "disconnected",
                    ))
                } else {
                    read
                }
            }
            Ok(false) => Ok(0),
            Err(e) => Err(e),
        };

        inner.quit = read.is_err();
        read
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();
        let write = inner.stream.write_all(buf);
        inner.quit = write.is_err();
        write?;
        Ok(buf.len())
    }

    fn log(&mut self, _level: LogLevel, _msg: &str) {}

    fn flush_writes(&mut self) {}
}

#[cfg(unix)]
#[zbus::proxy(
    interface = "org.freedesktop.usbredir1",
    default_service = "org.freedesktop.usbredir1",
    default_path = "/org/freedesktop/usbredir1"
)]
trait SystemHelper {
    fn open_bus_dev(&self, bus: u8, dev: u8) -> zbus::fdo::Result<zbus::zvariant::OwnedFd>;
}

#[derive(Debug)]
pub struct RusbSession {
    inner: Arc<Mutex<SessionInner>>,
}

impl RusbSession {
    async fn new(
        device: &rusb::Device<rusb::Context>,
        stream: UnixStream,
    ) -> qemu_display::Result<Self> {
        let ctxt = device.context().clone();

        let (dev, device_fd) = match device.open() {
            Ok(it) => (it, None),
            #[cfg(unix)]
            Err(rusb::Error::Access) => {
                let (bus, dev) = (device.bus_number(), device.address());
                let sysbus = zbus::Connection::system().await?;
                let fd = SystemHelperProxy::new(&sysbus)
                    .await?
                    .open_bus_dev(bus, dev)
                    .await?;
                unsafe {
                    (
                        ctxt.open_device_with_fd(fd.as_raw_fd())
                            .map_err(|e| qemu_display::Error::Failed(format!("rusb error: {e}")))?,
                        Some(fd),
                    )
                }
            }
            Err(e) => {
                return Err(qemu_display::Error::Failed(format!("rusb error: {e}")));
            }
        };

        let c = ctxt.clone();
        let stream_fd = stream.as_raw_fd();
        // really annoying libusb/usbredir APIs...
        let event = UnixStream::pair()?;
        let event_fd = event.1.as_raw_fd();
        std::thread::spawn(move || loop {
            let ret = fd_poll_readable(stream_fd, Some(event_fd));
            c.interrupt_handle_events();
            if ret.is_err() {
                break;
            }
        });

        let handler = StreamHandler {
            inner: Arc::new(Mutex::new(SessionInner {
                #[cfg(unix)]
                device_fd,
                stream,
                event,
                quit: false,
                ctxt: ctxt.clone(),
                ctxt_thread: Default::default(),
            })),
        };

        let redirdev = Device::new(&ctxt, Some(dev), handler.clone(), LogLevel::None as _)
            .map_err(|e| qemu_display::Error::Failed(format!("usbredir error: {e}")))?;
        let c = ctxt.clone();
        let inner = handler.inner.clone();
        let ctxt_thread = std::thread::spawn(move || loop {
            if inner.lock().unwrap().quit {
                break;
            }
            if let Ok(true) = fd_poll_readable(stream_fd, None) {
                redirdev.read_peer().unwrap();
            }
            if redirdev.has_data_to_write() > 0 {
                redirdev.write_peer().unwrap();
            }
            c.handle_events(None).unwrap();
        });
        handler
            .inner
            .lock()
            .unwrap()
            .ctxt_thread
            .replace(ctxt_thread);

        Ok(RusbSession {
            inner: handler.inner,
        })
    }
}

impl Drop for RusbSession {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        inner.quit = true;
        inner.ctxt.interrupt_handle_events();
        // stream will be dropped and stream_thread will kick context_thread
        inner.event.0.write_all(&[0]).unwrap();
    }
}

#[cfg(unix)]
fn fd_poll_readable(fd: RawFd, wait: Option<RawFd>) -> std::io::Result<bool> {
    let mut fds = vec![libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    }];
    if let Some(wait) = wait {
        fds.push(libc::pollfd {
            fd: wait,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        });
    }
    let ret = unsafe {
        libc::poll(
            fds.as_mut_ptr(),
            fds.len() as _,
            if wait.is_some() { -1 } else { 0 },
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else if ret == 0 {
        Ok(false)
    } else if fds[0].revents & libc::POLLHUP != 0
        || (wait.is_some() && fds[1].revents & libc::POLLIN != 0)
    {
        Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "hup"))
    } else {
        Ok(fds[0].revents & libc::POLLIN != 0)
    }
}

#[derive(Clone, Debug)]
pub struct Handler {
    usbredir: UsbRedir<RusbBackend>,
}

impl Handler {
    pub fn new(usbredir: UsbRedir<RusbBackend>) -> Self {
        Self { usbredir }
    }

    pub fn widget(&self) -> rdw::UsbRedir {
        let widget = rdw::UsbRedir::new();

        let usbredir = self.usbredir.clone();
        widget
            .model()
            .connect_items_changed(clone!(move |model, pos, _rm, add| {
                let usbredir = usbredir.clone();
                MainContext::default().spawn_local(clone!(
                    #[weak]
                    model,
                    async move {
                        for pos in pos..pos + add {
                            let item = model.item(pos).unwrap();
                            if let Some(dev) =
                                item.downcast_ref::<rdw::UsbDevice>().unwrap().device()
                            {
                                let key = Key::from(&dev);
                                item.set_property(
                                    "active",
                                    usbredir.is_device_connected(&key).await,
                                );
                            }
                        }
                    }
                ));
            }));

        let usbredir = self.usbredir.clone();
        widget.connect_device_state_set(move |widget, item, state| {
            let device = match item.device() {
                Some(it) => it,
                _ => return,
            };
            let key = Key::from(&device);

            let usbredir = usbredir.clone();
            MainContext::default().spawn_local(clone!(
                #[weak]
                item,
                #[weak]
                widget,
                async move {
                    let result = if state {
                        usbredir.connect_device(key, device).await
                    } else {
                        usbredir.disconnect_device(&key).await
                    };
                    match result {
                        Ok(active) => item.set_property("active", active),
                        Err(e) => {
                            if state {
                                item.set_property("active", false);
                            }
                            widget.emit_by_name::<bool>("show-error", &[&e.to_string()]);
                        }
                    }
                }
            ));
        });

        let usbredir = self.usbredir.clone();
        MainContext::default().spawn_local(clone!(
            #[weak]
            widget,
            async move {
                use futures::stream::StreamExt; // for `next`
                widget.set_property("free-channels", usbredir.n_free_channels().await);
                let mut n = usbredir.receive_n_free_channels().await;
                while let Some(n) = n.next().await {
                    widget.set_property("free-channels", n);
                }
            }
        ));

        widget
    }
}
