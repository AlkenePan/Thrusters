use std::net::IpAddr;

use pnet::packet::udp::UdpPacket;

pub fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!("[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                 interface_name,
                 source,
                 udp.get_source(),
                 destination,
                 udp.get_destination(),
                 udp.get_length());
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}