
use std::net::IpAddr;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, echo_reply, echo_request};

pub fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!("[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                         interface_name,
                         source,
                         destination,
                         echo_reply_packet.get_sequence_number(),
                         echo_reply_packet.get_identifier());
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!("[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                         interface_name,
                         source,
                         destination,
                         echo_request_packet.get_sequence_number(),
                         echo_request_packet.get_identifier());
            }
            _ => {
                println!("[{}]: ICMP packet {} -> {} (type={:?})",
                         interface_name,
                         source,
                         destination,
                         icmp_packet.get_icmp_type())
            }
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}


