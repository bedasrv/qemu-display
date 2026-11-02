use std::path::PathBuf;

use clap::{Parser, Subcommand};

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\nGit commit: ",
    env!("GIT_HASH"),
);

/// QEMU "-display dbus" RDP server
#[derive(Parser, Debug)]
#[command(version = VERSION, about, long_about = None)]
pub struct Args {
    /// Print program capabilities in JSON.
    #[arg(long)]
    pub print_capabilities: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,

    /// D-Bus bus address (default to session)
    #[arg(short, long)]
    pub dbus_address: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start a RDP server
    #[command()]
    Serve(ServerArgs),
}

#[derive(Debug, clap::Args)]
#[command(flatten_help = true)]
pub struct ServerArgs {
    /// IP address
    #[clap(short, long, default_value = "0.0.0.0:3389")]
    pub bind_address: std::net::SocketAddr,

    /// Path to tls certificate
    #[clap(short, long, value_parser)]
    pub cert: Option<PathBuf>,

    /// Path to private key
    #[clap(short, long, value_parser)]
    pub key: Option<PathBuf>,

    /// Codecs configuration
    #[clap(long)]
    pub codecs: Vec<String>,
}
