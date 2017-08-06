extern crate hexdump;

use std::net::IpAddr;


use pnet::packet::tcp::TcpPacket;

// same IP
// same port

struct tcp_frag {
    seq,
    len,
    data_len,
    data,
}


pub fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!("[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                 interface_name,
                 source,
                 tcp.get_source(),
                 destination,
                 tcp.get_destination(),
                 packet.len());
        hexdump::hexdump(packet);
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}
