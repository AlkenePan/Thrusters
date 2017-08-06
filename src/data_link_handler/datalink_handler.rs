use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ethernet::EtherType;


pub fn handler(interface_name: &str, ethernet: &EthernetPacket) -> EtherType {
    let ether_type: EtherType = match ethernet.get_ethertype() {
        //EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet, ip_defrag_hash_map),
        EtherTypes::Ipv4 => EtherTypes::Ipv4,
        _ => {
            println!("[{}]: DataLink!: {} > {}; ethertype: {:?} length: {}",
                     interface_name,
                     ethernet.get_source(),
                     ethernet.get_destination(),
                     ethernet.get_ethertype(),
                     ethernet.packet().len());
            let a: EtherType = EtherType(0x0000);
            a
        }
    };
    ether_type
}


