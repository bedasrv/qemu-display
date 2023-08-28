mod display;
mod input;

use anyhow::Error;
use qemu_display::zbus;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{fs::File, io::BufReader, sync::Arc};
use tokio_rustls::TlsAcceptor;

use ironrdp::server::RdpServer;

use crate::args::ServerArgs;

use display::DisplayHandler;
use input::InputHandler;

pub struct Server {
    dbus: zbus::Connection,
    args: ServerArgs,
}

impl Server {
    pub fn new(dbus: zbus::Connection, args: ServerArgs) -> Self {
        Self { dbus, args }
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        let tls = self
            .args
            .cert
            .as_ref()
            .zip(self.args.key.as_ref())
            .map(|(cert, key)| acceptor(cert, key).unwrap());

        let handler = InputHandler::connect(self.dbus.clone()).await?;
        let display = DisplayHandler::connect(self.dbus.clone()).await?;

        let mut server = RdpServer::builder()
            .with_addr((self.args.address, self.args.port))
            .with_tls(tls.unwrap())
            .with_input_handler(handler)
            .with_display_handler(display)
            .build();

        server.run().await
    }
}

fn acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, Error> {
    let cert = certs(&mut BufReader::new(File::open(cert_path)?))?[0].clone();
    let key = pkcs8_private_keys(&mut BufReader::new(File::open(key_path)?))?[0].clone();

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![rustls::Certificate(cert)], rustls::PrivateKey(key))
        .expect("bad certificate/key");

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}
