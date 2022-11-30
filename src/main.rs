use dns_lookup::getaddrinfo;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;

use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about = "A modern Port-Knocking Client")]
struct Cli {
    /// The host/IP to send the knock to OR the name of a preset
    #[arg(value_names = ["host | preset"])]
    host: Option<String>,

    /// The Sequence of ports, seperated by spaces. Example: 1234 5678:udp 9101:tcp
    #[arg(value_names = ["port<:proto>"])]
    ports: Vec<String>,

    /// Make all ports hits use UDP (default is TCP)
    #[arg(short, long)]
    udp: bool,

    /// Wait <t> milliseconds between Port hits
    #[arg(short, long, value_names = ["t"])]
    delay: Option<u64>,

    /// Force usage of IPv4
    #[arg(short = '4', long)]
    ipv4: bool,

    /// Force usage of IPv6
    #[arg(short = '6', long)]
    ipv6: bool,

    /// List all presets
    #[arg(short, long)]
    list: bool,

    /// Run the Wizard to create a new preset
    #[arg(long)]
    new: bool,

    /// Run the wizard to change a preset
    #[arg(long, value_names = ["name"])]
    reconfigure: Option<String>,

    /// Delete a preset
    #[arg(long, value_names = ["name"])]
    delete: Option<String>,

    /// Delete all presets
    #[arg(long)]
    delete_all: bool,

    /// Be verbose
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();

    // TODO: Parse properly and implement protocols
    let ports_u16: Vec<u16> = cli
        .ports
        .iter()
        .map(|p| p.parse::<u16>().unwrap())
        .collect();

    run_portknock(&cli.host.unwrap(), &ports_u16);
}

#[allow(dead_code)]
fn run_portknock(host: &str, ports: &[u16]) {
    let gai = getaddrinfo(Some(host), None, None).unwrap();
    let gai_result = gai.collect::<std::io::Result<Vec<_>>>().unwrap();
    let sa = &gai_result[0].sockaddr;
    let ip = sa.ip();

    for port in ports {
        let socket = if ip.is_ipv4() {
            Socket::new(Domain::IPV4, Type::STREAM, None).unwrap()
        } else {
            Socket::new(Domain::IPV6, Type::STREAM, None).unwrap()
        };
        socket.set_nonblocking(true).unwrap();

        let address = SocketAddr::new(ip, *port);
        let address = address.into();

        // let _ = socket.connect(&address);
        println!("Connecting to {}:{}", ip, port);
        match socket.connect(&address) {
            Ok(_) => {}
            Err(_) => {
                // We expect this to fail, the port is probably closed after all
            }
        }

        drop(socket);
        std::thread::sleep(std::time::Duration::from_micros(1000 * 100));
    }
}
