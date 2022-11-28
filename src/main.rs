use std::net::SocketAddr;
use socket2::{Socket, Domain, Type};
use dns_lookup::getaddrinfo;

fn main() {
    let ports = [1234, 5678, 910, 1112, 1314];
    let host = "example.com";
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

        let address = SocketAddr::new(ip, port);
        let address = address.into();

        // let _ = socket.connect(&address);
        println!("Connecting to {}:{}", ip, port);
        match socket.connect(&address) {
            Ok(_) => {},
            Err(_) => {
                // We expect this to fail, the port is probably closed after all
            }
        }

        drop(socket);
        std::thread::sleep(std::time::Duration::from_micros(1000 * 100));
    }
}

