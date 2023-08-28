use anyhow::Context;
use qemu_display::zbus;

mod args;
mod server;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut args = args::parse();

    setup_logging(args.log_file.as_str()).context("unable to initialize logging")?;

    let dbus = match args.dbus_address.take() {
        None => zbus::Connection::session().await,
        Some(addr) => {
            zbus::ConnectionBuilder::address(addr.as_str())?
                .build()
                .await
        }
    }
    .expect("Failed to connect to DBus");

    server::Server::new(dbus, args.server).run().await?;

    Ok(())
}

fn setup_logging(log_file: &str) -> anyhow::Result<()> {
    use std::fs::OpenOptions;

    use tracing::metadata::LevelFilter;
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::EnvFilter;

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .with_context(|| format!("couldn’t open {log_file}"))?;

    let fmt_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_ansi(false)
        .with_writer(file);

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into())
        .with_env_var("QEMURDP_LOG_LEVEL")
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(env_filter)
        .try_init()
        .context("failed to set tracing global subscriber")?;

    Ok(())
}
