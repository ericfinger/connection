use crate::Cli;

use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::time::Duration;

use dns_lookup::lookup_host;
use socket2::{Domain, Protocol, Socket, Type};

#[allow(dead_code)]
pub(crate) struct Connection {
    ip: IpAddr,
    port_sequence: Vec<(u16, bool)>, // false = tcp
    cli: Cli,
}

impl Connection {
    pub fn new(cli: Cli) -> Self {
        let host = cli.host.as_ref().unwrap();

        let mut port_sequence = Vec::new();
        for entry in &cli.ports {
            match entry.split_once(':') {
                Some(split) => {
                    if split.1 == "tcp" || split.1 == "udp" {
                        port_sequence.push((
                            split
                                .0
                                .parse::<u16>()
                                .unwrap_or_else(|_| panic!("Given port '{entry}' is not valid")),
                            split.1 == "udp",
                        ));
                    } else {
                        panic!("Given port '{}' has invalid protocol '{}'", entry, split.1);
                        // TODO: Better Error-handling
                    }
                }
                None => {
                    // No protocol specified, assuming default (tcp unless -u is passed)
                    port_sequence.push((
                        entry
                            .parse::<u16>()
                            .unwrap_or_else(|_| panic!("Given port '{entry}' is not valid")),
                        cli.udp,
                    ));
                }
            }
        }

        Connection {
            ip: Connection::get_ip(host, cli.ipv4, cli.ipv6),
            port_sequence,
            cli,
        }
    }

    pub fn execute_knock(&self) {
        let udp_socket = Socket::new(
            if self.ip.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            },
            Type::DGRAM,
            Some(Protocol::UDP),
        )
        .unwrap();

        for port in &self.port_sequence {
            let address = SocketAddr::new(self.ip, port.0).into();

            if self.cli.verbose {
                println!(
                    "hitting {} {}:{}",
                    if port.1 { "udp" } else { "tcp" },
                    self.ip,
                    port.0
                );
            }

            if port.1 {
                udp_socket.send_to(&[], &address).unwrap();
            } else {
                // Sadly, we have to build this socket every time because dropping the refence is the
                // only way to force-close the connection without relying on connect-timeout jank
                let tcp_socket = Socket::new(
                    if self.ip.is_ipv4() {
                        Domain::IPV4
                    } else {
                        Domain::IPV6
                    },
                    Type::STREAM,
                    Some(Protocol::TCP),
                )
                .unwrap();
                tcp_socket.set_nonblocking(true).unwrap();
                tcp_socket.set_nodelay(true).unwrap();

                // We expect this to fail, the port is probably closed after all:
                if tcp_socket.connect(&address).is_ok() {}
                drop(tcp_socket);
            }

            std::thread::sleep(Duration::from_micros(1000 * self.cli.delay));
        }
    }

    pub fn exec_cmd(self) {
        if let Some(cmd) = self.cli.command {
            let mut split = cmd.split(' ');
            let mut command = Command::new(split.next().unwrap());
            for arg in split {
                command.arg(arg);
            }

            if self.cli.verbose {
                println!("Executing '{cmd}'");
            }

            let mut handle = command.spawn().unwrap();
            handle.wait().unwrap();
        }
    }

    fn get_ip(host: &str, ipv4: bool, ipv6: bool) -> IpAddr {
        let ips = match lookup_host(host) {
            Ok(ips) => ips,
            Err(err) => {
                panic!("Error looking up host '{host}': {:#?}", err);
            }
        };

        for ip in ips {
            if !ipv4 && !ipv6 {
                // If not specified just return the first entry
                return ip;
            }

            if ipv4 && ip.is_ipv4() {
                return ip;
            }

            if ipv6 && ip.is_ipv6() {
                return ip;
            }
        }

        panic!(
            "Could not find suitable IP Address for type '{}' and host {host}",
            if ipv4 { "ipv4" } else { "ipv6" }
        );
    }
}
