use std::{
    cmp,
    os::{fd::AsFd, unix::net::UnixStream},
};

use serde_bytes::ByteBuf;
use zbus::connection;

const WIDTH: u32 = 1024;
const HEIGHT: u32 = 768;

struct VM;

#[zbus::interface(name = "org.qemu.Display1.VM")]
impl VM {
    #[zbus(property, name = "ConsoleIDs")]
    async fn console_ids(&self) -> Vec<u8> {
        vec![0]
    }

    #[zbus(property)]
    async fn interfaces(&self) -> Vec<String> {
        vec![]
    }

    #[zbus(property, name = "UUID")]
    async fn uuid(&self) -> String {
        "00000000-0000-0000-0000-000000000000".into()
    }

    #[zbus(property)]
    async fn name(&self) -> &str {
        "VM Name"
    }
}

#[zbus::proxy(
    interface = "org.qemu.Display1.Listener",
    default_path = "/org/qemu/Display1/Listener",
    default_service = "org.qemu"
)]
trait Listener {
    fn scanout(
        &self,
        width: u32,
        height: u32,
        stride: u32,
        format: u32,
        data: serde_bytes::ByteBuf,
    ) -> zbus::Result<()>;

    #[allow(clippy::too_many_arguments)]
    fn update(
        &self,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        stride: u32,
        format: u32,
        data: serde_bytes::ByteBuf,
    ) -> zbus::Result<()>;
}

struct Console {
    task: Option<async_std::task::JoinHandle<()>>,
}

#[zbus::interface(name = "org.qemu.Display1.Console")]
impl Console {
    async fn register_listener(
        &mut self,
        #[zbus(connection)] conn: &zbus::Connection,
        listener: zbus::Fd<'_>,
    ) {
        let fd = listener.as_fd().try_clone_to_owned().unwrap();
        let task = async_std::task::spawn(async move {
            let stream = UnixStream::from(fd);
            let conn = connection::Builder::unix_stream(stream)
                .server(zbus::Guid::generate())
                .p2p()
                .build()
                .await
                .unwrap();
            let listener = ListenerProxy::new(&conn).await.unwrap();
            let format = pixman_sys::pixman_format_code_t_PIXMAN_x8r8g8b8;
            let data = vec![0u8; WIDTH as usize * HEIGHT as usize * 4];
            listener
                .scanout(WIDTH, HEIGHT, WIDTH * 4, format, ByteBuf::from(data))
                .await
                .unwrap();
            let mut x = 0i32;
            let mut y = 0i32;
            loop {
                let w = cmp::min(256, WIDTH - x as u32) as _;
                let h = cmp::min(256, HEIGHT - y as u32) as _;
                let data: Vec<u8> = (0..w * h * 4).map(|_| rand::random()).collect();
                listener
                    .update(x, y, w, h, w as u32 * 4, format, ByteBuf::from(data))
                    .await
                    .unwrap();
                x += 1;
                if x >= WIDTH as _ {
                    x = 0;
                    y += 1;
                }
                // async_std::task::sleep(core::time::Duration::from_millis(1)).await;
            }
        });
        self.task = Some(task);
    }

    #[zbus(name = "SetUIInfo")]
    fn set_ui_info(
        &self,
        _width_mm: u16,
        _height_mm: u16,
        _xoff: i32,
        _yoff: i32,
        width: u32,
        height: u32,
    ) {
        tracing::warn!(%width, %height, "set-ui");
    }

    #[zbus(property)]
    fn label(&self) -> String {
        "label".into()
    }

    #[zbus(property)]
    fn head(&self) -> u32 {
        0
    }

    #[zbus(property)]
    fn type_(&self) -> String {
        "Graphic".into()
    }

    #[zbus(property)]
    fn width(&self) -> u32 {
        1024
    }

    #[zbus(property)]
    fn height(&self) -> u32 {
        768
    }
}

#[async_std::main]
async fn main() -> zbus::Result<()> {
    tracing_subscriber::fmt::init();

    let _connection = connection::Builder::session()
        .name("org.qemu")
        .serve_at("/org/qemu/Display1/VM", VM)
        .serve_at("/org/qemu/Display1/Console_0", Console { task: None })
        .build()
        .await?;

    loop {
        std::future::pending::<()>().await;
    }
}
