use clap::Parser;

mod connection;
#[allow(unused_imports)]
use crate::connection::Connection;

#[derive(Parser)]
#[command(version, about, long_about = "A modern Port-Knocking Client")]
struct Cli {
    /// The host/IP to send the knock to OR the name of a preset
    #[arg(value_names = ["host | preset"])]
    host: String,

    /// The Sequence of ports, seperated by spaces. Example: 1234 5678:udp 9101:tcp
    #[arg(value_names = ["port<:proto>"])]
    ports: Vec<String>,

    /// Make all ports hits use UDP (default is TCP)
    #[arg(short, long)]
    udp: bool,

    /// Wait <t> milliseconds between Port hits
    #[arg(short, long, value_names = ["t"], default_value_t = 0)]
    delay: u64,

    /// Force usage of IPv4
    #[arg(short = '4', long)]
    ipv4: bool,

    /// Force usage of IPv6
    #[arg(short = '6', long)]
    ipv6: bool,

    /// Be verbose
    #[arg(short, long)]
    verbose: bool,

    /// List all presets
    #[arg(short, long, help_heading = Some("Presets"))]
    list: bool,

    /// Run the Wizard to create a new preset
    #[arg(long, help_heading = Some("Presets"))]
    new: bool,

    /// Run the wizard to change a preset
    #[arg(long, value_names = ["name"], help_heading = Some("Presets"))]
    reconfigure: Option<String>,

    /// Delete a preset
    #[arg(long, value_names = ["name"], help_heading = Some("Presets"))]
    delete: Option<String>,

    /// Delete all presets
    #[arg(long, help_heading = Some("Presets"))]
    delete_all: bool,
}

fn main() {
    let cli = Cli::parse();

    let connection = Connection::new(cli);
    connection.execute_knock();
}
