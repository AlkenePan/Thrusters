pub mod icmp;
pub mod tcp;
pub mod udp;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};

pub fn handle_transport_protocol(interface_name: &str,
                             source: IpAddr,
                             destination: IpAddr,
                             protocol: IpNextHeaderProtocol,
                             packet: &[u8]) {
    match protocol {

        IpNextHeaderProtocols::Udp => {
            udp::handle_udp_packet(interface_name, source, destination, packet)
        }

        IpNextHeaderProtocols::Tcp => {
            tcp::handle_tcp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            icmp::handle_icmp_packet(interface_name, source, destination, packet)
        }
        _ => {
            println!("[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                     interface_name,
                     match source {
                         IpAddr::V4(..) => "IPv4",
                         _ => "IPv6",
                     },
                     source,
                     destination,
                     protocol,
                     packet.len())
        }
    }
}
