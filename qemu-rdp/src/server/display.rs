use anyhow::Result;
use ironrdp::connector::DesktopSize;
use qemu_display::{zbus, Console, ConsoleListenerHandler, Cursor, MouseSet, Scanout, Update};

use ironrdp::server::{BitmapUpdate, DisplayUpdate, PixelFormat, PixelOrder, RdpServerDisplay};

pub struct DisplayHandler {
    console: Console,
    receiver: tokio::sync::mpsc::Receiver<DisplayUpdate>,
}

impl DisplayHandler {
    pub async fn connect(dbus: zbus::Connection) -> Result<Self> {
        let (sender, receiver) = tokio::sync::mpsc::channel::<DisplayUpdate>(32);
        let listener = Listener::new(sender);

        let console = Console::new(&dbus, 0).await?;
        console.register_listener(listener).await?;

        Ok(Self { console, receiver })
    }
}

#[async_trait::async_trait]
impl RdpServerDisplay for DisplayHandler {
    async fn size(&mut self) -> DesktopSize {
        let width = self.console.proxy.width().await.unwrap() as u16;
        let height = self.console.proxy.height().await.unwrap() as u16;
        DesktopSize { height, width }
    }

    async fn get_update(&mut self) -> Option<DisplayUpdate> {
        self.receiver.recv().await
    }
}

struct Listener {
    sender: tokio::sync::mpsc::Sender<DisplayUpdate>,
}

impl Listener {
    fn new(sender: tokio::sync::mpsc::Sender<DisplayUpdate>) -> Self {
        Self { sender }
    }

    async fn send(&mut self, update: DisplayUpdate) {
        if let Err(e) = self.sender.send(update).await {
            println!("{:?}", e);
        };
    }
}

#[async_trait::async_trait]
impl ConsoleListenerHandler for Listener {
    async fn scanout(&mut self, scanout: Scanout) {
        let format = match scanout.format {
            537_004_168 => PixelFormat::BgrA32,
            _ => PixelFormat::RgbA32,
        };

        let bitmap = DisplayUpdate::Bitmap(BitmapUpdate {
            top: 0,
            left: 0,
            width: scanout.width,
            height: scanout.height,
            format,
            order: PixelOrder::TopToBottom,
            data: scanout.data,
        });

        self.send(bitmap).await;
    }

    async fn update(&mut self, update: Update) {
        let format = match update.format {
            537_004_168 => PixelFormat::BgrA32,
            _ => PixelFormat::RgbA32,
        };

        let bitmap = DisplayUpdate::Bitmap(BitmapUpdate {
            // TODO: fix scary conversion
            top: update.y as u32,
            left: update.x as u32,
            width: update.w as u32,
            height: update.h as u32,
            format,
            order: PixelOrder::TopToBottom,
            data: update.data,
        });

        self.send(bitmap).await;
    }

    #[cfg(unix)]
    async fn scanout_dmabuf(&mut self, _scanout: qemu_display::ScanoutDMABUF) {}

    #[cfg(unix)]
    async fn update_dmabuf(&mut self, _update: qemu_display::UpdateDMABUF) {}

    async fn disable(&mut self) {}
    async fn mouse_set(&mut self, _set: MouseSet) {}
    async fn cursor_define(&mut self, _cursor: Cursor) {}
    fn disconnected(&mut self) {}
    fn interfaces(&self) -> Vec<String> {
        vec![]
    }
}
