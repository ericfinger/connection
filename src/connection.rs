use crate::Cli;

use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use dns_lookup::lookup_host;
use socket2::{Domain, Protocol, Socket, Type};

pub(crate) struct Connection {
    target_ip: IpAddr,
    port_sequence: Vec<SequenceEntry>,
    cli: Cli,
}

struct SequenceEntry {
    port: u16,
    protocol: PortProtocol,
    payload: Vec<u8>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(strum_macros::Display)]
enum PortProtocol {
    TCP,
    UDP,
}

impl Connection {
    pub fn new(cli: Cli) -> Result<Self> {
        let host = cli.host.as_ref().unwrap();

        let mut port_sequence = Vec::new();
        for entry in &cli.ports {
            match entry.split_once(':') {
                Some(split) => {
                    let port = split
                        .0
                        .parse::<u16>()
                        .context(format!("Given Port '{}' is not valid", split.0))?;
                    let protocol = match split.1 {
                        "tcp" => PortProtocol::TCP,
                        "udp" => PortProtocol::UDP,
                        _ => bail!("Given port '{}' has invalid protocol '{}'", entry, split.1),
                    };
                    let entry = SequenceEntry {
                        port,
                        protocol,
                        payload: Vec::new(),
                    };
                    port_sequence.push(entry);
                }
                None => {
                    // No protocol specified, assuming default (tcp unless -u is passed)
                    let port = entry
                        .parse::<u16>()
                        .context(format!("Given Port '{}' is not valid", entry))?;

                    let protocol = if cli.udp {
                        PortProtocol::UDP
                    } else {
                        PortProtocol::TCP
                    };
                    let entry = SequenceEntry {
                        port,
                        protocol,
                        payload: Vec::new(),
                    };
                    port_sequence.push(entry);
                }
            }
        }

        Ok(Connection {
            target_ip: Connection::get_ip(host, cli.ipv4, cli.ipv6)?,
            port_sequence,
            cli,
        })
    }

    pub fn execute_knock(&self) -> Result<()> {
        let udp_socket = Socket::new(
            if self.target_ip.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            },
            Type::DGRAM,
            Some(Protocol::UDP),
        )
        .context("Could not create UDP Socket")?;

        for entry in &self.port_sequence {
            let address = SocketAddr::new(self.target_ip, entry.port).into();

            if self.cli.verbose {
                println!(
                    "hitting {} {}:{}",
                    entry.protocol, self.target_ip, entry.port
                );
            }

            match entry.protocol {
                PortProtocol::TCP => {
                    // Sadly, we have to build this socket every time because dropping the refence is the
                    // only way to force-close the connection without relying on connect-timeout jank
                    let tcp_socket = Socket::new(
                        if self.target_ip.is_ipv4() {
                            Domain::IPV4
                        } else {
                            Domain::IPV6
                        },
                        Type::STREAM,
                        Some(Protocol::TCP),
                    )
                    .context("Could not create TCP Socket")?;

                    tcp_socket
                        .set_nonblocking(true)
                        .context("Could not set TCP Socket to non-blocking")?;
                    tcp_socket
                        .set_nodelay(true)
                        .context("Could not set TCP Socket to no-delay")?;

                    // We expect this to fail, the port is probably closed after all:
                    tcp_socket.connect(&address).ok();
                    drop(tcp_socket);
                }

                PortProtocol::UDP => {
                    udp_socket
                        .send_to(&entry.payload, &address)
                        .context(format!("Could not send data to '{:?}' via UDP", address))?;
                }
            }

            std::thread::sleep(Duration::from_micros(1000 * self.cli.delay));
        }

        Ok(())
    }

    pub fn exec_cmd(self) -> Result<()> {
        if self.cli.no_command {
            return Ok(());
        }

        if let Some(cmd) = self.cli.command {
            let mut split = cmd.split(' ');
            let mut command = Command::new(split.next().unwrap());
            for arg in split {
                command.arg(arg);
            }

            if self.cli.verbose {
                println!("Executing '{cmd}'");
            }

            let mut handle = command
                .spawn()
                .context(format!("Could not spawn process for command '{cmd}'"))?;
            handle.wait().context(format!(
                "Could not wait for process for command '{cmd}' to finish"
            ))?;
        }

        Ok(())
    }

    fn get_ip(host: &str, ipv4: bool, ipv6: bool) -> Result<IpAddr> {
        let ips = lookup_host(host).context(format!("Error looking up host '{host}'"))?;

        for ip in ips {
            if !ipv4 && !ipv6 {
                // If not specified just return the first entry
                return Ok(ip);
            }

            if ipv4 && ip.is_ipv4() {
                return Ok(ip);
            }

            if ipv6 && ip.is_ipv6() {
                return Ok(ip);
            }
        }

        bail!(
            "Could not find suitable IP Address for type '{}' and host {host}",
            if ipv4 { "ipv4" } else { "ipv6" }
        )
    }
}
