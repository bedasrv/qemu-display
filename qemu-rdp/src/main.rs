mod args;
mod server;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut args = args::parse();

    let dbus = match args.dbus_address.take() {
        None => zbus::Connection::session().await,
        Some(addr) => zbus::ConnectionBuilder::address(addr.as_str())?
            .build()
            .await
    }
    .expect("Failed to connect to DBus");

    server::Server::new(dbus, args.server).run().await?;

    Ok(())
}
