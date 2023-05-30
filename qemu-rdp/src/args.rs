use clap::clap_derive::ValueEnum;
use clap::Parser;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum SecurityProtocol {
    Ssl,
    Hybrid,
    HybridEx,
}

impl From<SecurityProtocol> for ironrdp::pdu::nego::SecurityProtocol {
    fn from(value: SecurityProtocol) -> Self {
        match value {
            SecurityProtocol::Ssl => ironrdp::pdu::nego::SecurityProtocol::SSL,
            SecurityProtocol::Hybrid => ironrdp::pdu::nego::SecurityProtocol::HYBRID,
            SecurityProtocol::HybridEx => ironrdp::pdu::nego::SecurityProtocol::HYBRID_EX,
        }
    }
}

#[derive(Parser, Debug)]
pub struct ServerArgs {
    /// IP address
    #[clap(short, long, default_value = "127.0.0.1")]
    pub address: std::net::IpAddr,

    /// IP port
    #[clap(short, long, default_value = "3389")]
    pub port: u16,

    /// Specify the security protocols to use
    #[clap(long, value_enum, value_parser, default_value_t = SecurityProtocol::Ssl)]
    pub security_protocol: SecurityProtocol,

    /// Path to tls certificate
    #[clap(short, long, value_parser)]
    pub cert: Option<String>,

    /// Path to private key
    #[clap(short, long, value_parser)]
    pub key: Option<String>,
}

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(flatten)]
    pub server: ServerArgs,

    /// DBUS address
    #[clap(short, long)]
    pub dbus_address: Option<String>,
}

pub fn parse() -> Args {
    Args::parse()
}
