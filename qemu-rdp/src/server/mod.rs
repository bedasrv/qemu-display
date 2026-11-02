use anyhow::{bail, Error};
use ironrdp_server::{Credentials, ServerEvent, TlsIdentityCtx};
use std::path::PathBuf;
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use tracing::{debug, error};
use zbus::object_server::SignalEmitter;

use ironrdp_server::RdpServer;
use qemu_display::{zbus, Display};

mod clipboard;
mod display;
mod input;
mod sound;
mod usbredir;

use crate::{args::ServerArgs, server::usbredir::QemuUsbFactory};
use clipboard::ClipboardHandler;
use display::DisplayHandler;
use input::InputHandler;
use sound::SoundHandler;

pub struct Server {
    dbus: zbus::Connection,
    args: ServerArgs,
}

struct DBusCtrl {
    ev: UnboundedSender<ServerEvent>,
}

impl Server {
    pub fn new(dbus: zbus::Connection, args: ServerArgs) -> Self {
        Self { dbus, args }
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        let (cert, key) = match (&self.args.cert, &self.args.key) {
            (Some(cert), Some(key)) => (cert.as_path().to_owned(), key.as_path().to_owned()),
            (None, None) => {
                let mut config_dir = dirs::config_dir().expect("configuration directory");
                config_dir.push("qemu-rdp");
                let cert: PathBuf = [config_dir.clone(), PathBuf::from("server-cert.pem")]
                    .iter()
                    .collect();
                let key: PathBuf = [config_dir, PathBuf::from("server-key.pem")]
                    .iter()
                    .collect();
                (cert, key)
            }
            _ => {
                bail!("Provide both --cert and --key")
            }
        };

        println!("Waiting for org.qemu...");
        Display::lookup(&self.dbus, true, None).await?;

        let dbus_display = Display::new::<()>(&self.dbus, None).await?;

        let handler = InputHandler::connect(&dbus_display).await?;
        let display = DisplayHandler::connect(&dbus_display).await?;
        let clipboard = ClipboardHandler::connect(&dbus_display).await?;
        let usbredir = QemuUsbFactory::connect(&dbus_display).await?;
        let sound = match SoundHandler::connect(&dbus_display).await {
            Ok(h) => Some(h),
            Err(e) => {
                debug!("Can't connect audio: {}", e);
                None
            }
        };

        let tls = TlsIdentityCtx::init_from_paths(&cert, &key)?;
        let mut server = RdpServer::builder()
            .with_addr(self.args.bind_address)
            .with_hybrid(tls.make_acceptor()?, tls.pub_key)
            .with_input_handler(handler)
            .with_display_handler(display)
            .with_cliprdr_factory(Some(Box::new(clipboard)))
            .with_sound_factory(sound.map(|h| Box::new(h) as _))
            .with_usb_factory(Some(Box::new(usbredir)))
            .build();

        let ev = server.event_sender().clone();
        let dbus_ctrl = DBusCtrl { ev };
        let dbus_path = "/org/qemu_display/rdp";
        self.dbus.object_server().at(dbus_path, dbus_ctrl).await?;

        let dbus_iface_ref = self
            .dbus
            .object_server()
            .interface::<_, DBusCtrl>(dbus_path)
            .await?;
        let server_ev = server.event_sender().clone();
        let proxy = dbus_display.inner_proxy().clone();
        tokio::spawn(async move {
            use futures_util::StreamExt;

            let mut owner_changed = proxy.receive_owner_changed().await.unwrap();
            let _ = owner_changed.next().await;
            let dbus_emitter = dbus_iface_ref.signal_emitter();
            let _ = DBusCtrl::leaving(dbus_emitter, "org.qemu is gone").await;
            server_ev
                .send(ServerEvent::Quit("org.qemu is gone".to_owned()))
                .unwrap();
        });

        self.dbus
            .request_name_with_flags("org.QemuDisplay.RDP", zbus::fdo::RequestNameFlags::empty())
            .await?;

        println!("Starting RDP server, args: {:?}", self.args);
        println!("Cert: {cert:?}, Key: {key:?}");
        server.run().await?;
        println!("RDP server ended");
        Ok(())
    }
}

#[zbus::interface(name = "org.QemuDisplay.RDP")]
impl DBusCtrl {
    async fn set_credentials(&self, username: &str, password: &str, domain: &str) {
        if let Err(error) = self.ev.send(ServerEvent::SetCredentials(Credentials {
            username: username.into(),
            password: password.into(),
            domain: if domain.is_empty() {
                None
            } else {
                Some(domain.into())
            },
        })) {
            error!(?error, "Failed to send SetCredentials")
        }
    }

    #[zbus(property)]
    async fn listen_address(&self) -> zbus::fdo::Result<String> {
        let (tx, rx) = oneshot::channel();
        if let Err(error) = self.ev.send(ServerEvent::GetLocalAddr(tx)) {
            error!(?error, "Failed to send GetLocalAddr")
        }
        if let Some(addr) = rx
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?
        {
            Ok(addr.to_string())
        } else {
            Err(zbus::fdo::Error::Failed("Not yet available".into()))
        }
    }

    #[zbus(signal)]
    async fn leaving(emitter: &SignalEmitter<'_>, reason: &str) -> zbus::Result<()>;
}
