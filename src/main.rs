use std::env;
use std::io::{self, Write};
use std::process;
use std::collections::VecDeque;
use std::collections::HashMap;

extern crate pnet;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;


pub mod data_link_handler;
pub mod internet_handler;
pub mod transport_handler;


fn main() {
    use pnet::datalink::Channel::Ethernet;

    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "USAGE: packetdump <NETWORK INTERFACE>").unwrap();
            process::exit(1);
        }
    };
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().filter(interface_names_match).next().unwrap();

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };
    let mut iter = rx.iter();

    // IP 重组所需的 HashMap
    let mut ip_defrag_hash_map: HashMap<u64, VecDeque<internet_handler::internet_handler::IpInfo>> = HashMap::new();

    loop {
        match iter.next() {
            // 捕获数据
            Ok(packet) => {
                // datalink
                /*
                识别 使用的 ip 层协议
                // TODO track&dump src_mac dst_mac
                */
                let ether_type = data_link_handler::datalink_handler::handler(&interface.name[..], &packet);
                // Internet
                match ether_type {
                    EtherTypes::Ipv4 => {
                        println!("IPV4");
                        let ip_packet: internet_handler::internet_handler::NextLayer = internet_handler::internet_handler::handle_ipv4_packet(&interface.name[..], &packet, &mut ip_defrag_hash_map);
                        if ip_packet.hash == 1 {
                            println!("error ip");
                        } else {
                            // transport
                            transport_handler::handle_transport_protocol(&interface.name[..], ip_packet.src_ip, ip_packet.dst_ip, ip_packet.next_layer_proto_type, &ip_packet.payload)
                        }
                    }
                    _ => {
                        println!("error ethertype");
                    }
                };

            }

            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}