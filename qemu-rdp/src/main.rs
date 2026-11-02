use std::io::Write;

use anyhow::Context;
use clap::{CommandFactory, Parser};
use qemu_display::zbus;

mod args;
mod server;
mod utils;

use args::Args;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut args = Args::parse();

    if args.print_capabilities {
        return print_capabilities();
    }

    setup_logging().context("unable to initialize logging")?;

    let dbus = match args.dbus_address.take() {
        None => zbus::Connection::session().await,
        Some(addr) => {
            zbus::connection::Builder::address(addr.as_str())
                .build()
                .await
        }
    }
    .expect("Failed to connect to DBus");

    match args.command {
        Some(args::Commands::Serve(args)) => server::Server::new(dbus, args).run().await?,
        _ => {
            Args::command().print_help().unwrap();
        }
    }

    Ok(())
}

fn print_capabilities() -> Result<(), anyhow::Error> {
    std::io::stdout().write_all(
        r#"{
  "type": "qemu-rdp",
  "features": [
    "dbus-address",
    "remotefx"
  ]
}
"#
        .as_bytes(),
    )?;

    Ok(())
}

fn setup_logging() -> anyhow::Result<()> {
    use tracing::metadata::LevelFilter;
    use tracing_subscriber::{prelude::*, EnvFilter};

    let fmt_layer = tracing_subscriber::fmt::layer().compact();

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into())
        .with_env_var("QEMURDP_LOG")
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(env_filter)
        .try_init()
        .context("failed to set tracing global subscriber")?;

    Ok(())
}
