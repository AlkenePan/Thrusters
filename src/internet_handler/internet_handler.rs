use pnet::packet::Packet;

use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocol;

use std::env;
use std::io::{self, Write};
use std::process;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use std::collections::VecDeque;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};


#[derive(Hash)]
struct IpFragId {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
}

pub struct IpInfo {
    offset: u16,
    total: u16,
    frag_id: IpFragId,
    payload: Vec<u8>,
}

pub struct NextLayer {
    pub hash: u64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub payload: Vec<u8>,
    pub next_layer_proto_type: IpNextHeaderProtocol
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

fn check_flag(flags: u8) -> bool {
    let ret = if flags == 2 {
        false
    } else {
        true
    };
    ret
}


pub fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket, ip_defrag_hash_map: &mut HashMap<u64, VecDeque<IpInfo>>) -> NextLayer {
    let header = Ipv4Packet::new(ethernet.payload());
    let res: NextLayer;
    if let Some(header) = header {
        /*
        println!("IPv4: {:?} -> {:?}", header.get_source(), header.get_destination());
        println!("\t ip header length: {:?}", header.get_header_length());
        println!("\t ip total length: {:?}", header.get_total_length());
        println!("\t ip identification: {:?}", header.get_identification());
        // 000 fragment done
        // 010 don't fragment
        // 001 need fragment
        println!("\t ip flag: {:b}", header.get_flags());
        println!("\t ip fragment offset: {:?}", header.get_fragment_offset());
        println!("\t packet: ");
        //println!("\t {:?}", header.packet());
        println!("\t payload: ");
        println!("\t {:?}", header.payload());
        */
        // 检查是否需要分片
        if !check_flag(header.get_flags()) {
            /*
            handle_transport_protocol(interface_name,
                                      IpAddr::V4(header.get_source()),
                                      IpAddr::V4(header.get_destination()),
                                      header.get_next_level_protocol(),
                                      header.payload());
            */
            // println!("not need defrag");
            let next_layer = NextLayer {
                hash: 0,
                src_ip: IpAddr::V4(header.get_source()),
                dst_ip: IpAddr::V4(header.get_destination()),
                next_layer_proto_type: header.get_next_level_protocol(),
                payload: header.payload().to_vec()
            };
            next_layer
        } else {
            // 注册 src dest id
            let ip_id = IpFragId {
                src: header.get_source(),
                dst: header.get_destination(),
                id: header.get_identification(),
            };
            // 计算 hash
            let hash = calculate_hash(&ip_id);
            // println!("hash: {}", hash);
            let ip_info = IpInfo {
                offset: header.get_fragment_offset(),
                total: header.get_total_length(),
                frag_id: ip_id,
                payload: {
                    let len = header.payload().len();
                    //println!("len: {}", len);
                    // TODO SLOW WAY need check len()
                    let mut payloads: Vec<_> = vec![0; len];
                    payloads.clone_from_slice(header.payload());
                    payloads
                }
            };

            // 在 hashmap 中 查找是否有存在过
            let mut temp_defrag_queue: VecDeque<IpInfo>;
            if ip_defrag_hash_map.contains_key(&hash) {
                // 如果 存在 追加数据
                let mut defrag_queue: &mut VecDeque<IpInfo> = ip_defrag_hash_map.get_mut(&hash).unwrap();
                // 存入队列
                defrag_queue.push_back(ip_info);
                // println!("add frag");
            } else {
                // 如果 不存在 新建队列
                let mut defrag_queue: VecDeque<IpInfo> = VecDeque::new();
                // 存入队列
                defrag_queue.push_back(ip_info);
                // 存入 hashmap
                ip_defrag_hash_map.insert(hash, defrag_queue);
                // println!("new frag");
            };
            let mut payloads: Vec<u8> = Vec::new();
            if header.get_flags() == 0 {
                // println!("frag done!");
                if ip_defrag_hash_map.contains_key(&hash) {
                    let mut defrag_queue: &mut VecDeque<IpInfo> = ip_defrag_hash_map.get_mut(&hash).unwrap();

                    for ip_info in defrag_queue.iter() {
                        // println!("offset: {} ", ip_info.offset);
                        // println!("payload {:?} ", ip_info.payload);
                        payloads.extend(ip_info.payload.iter());
                    }
                    // println!("payloads: {:?}", payloads);
                    /*
                    handle_transport_protocol(interface_name,
                                              IpAddr::V4(header.get_source()),
                                              IpAddr::V4(header.get_destination()),
                                              header.get_next_level_protocol(),
                                              &payloads);
                    */
                    // println!("defrag done");

                };
                // 回收 hashmap 销毁 队列
                ip_defrag_hash_map.remove(&hash);
            }
            let next_layer = NextLayer {
                hash: 0,
                src_ip: IpAddr::V4(header.get_source()),
                dst_ip: IpAddr::V4(header.get_destination()),
                next_layer_proto_type: header.get_next_level_protocol(),
                payload: payloads
            };
            next_layer
        }
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
        let next_layer = NextLayer {
            hash: 1,
            src_ip: IpAddr::V4(Ipv4Addr::new(999,999,999,999)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(999,999,999,999)),
            next_layer_proto_type: IpNextHeaderProtocol(57),
            payload: Vec::new(),
        };
        next_layer
    }
}
