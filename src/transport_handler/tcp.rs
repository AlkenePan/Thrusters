extern crate hexdump;

use std::collections::HashMap;
use std::collections::LinkedList;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};


use std::net::IpAddr;

use pnet::packet::Packet;
use pnet::packet::tcp::TcpPacket;


// TCP 4 元组
#[derive(Hash)]
struct tcp_tuple {
    sip: IpAddr,
    dip: IpAddr,
    sport: u16,
    dport: u16,
}

// TCP 头的各个部分

struct tcp_header {
    seq: u32,
    ack: u32,
    offset: u8,
    flag: u16,
    //len: u8,
    window: u16,
    //data_len: u8,
    //padding: u8,

    // collect
    // if collect >0
    // save this payload to steam.data
    collect: u8,
}

// 定义 一致方向的 TCP 重组数据结构
pub struct tcp_stream {
    //start_ts: u16,
    //end_ts: u16,
    // tcp 4 元组 从 header 中剥离，解决内存，方便对比
    tuple: tcp_tuple,
    header: tcp_header,
    data: Vec<u8>,

}

// 定义 TCP 重组过程中的状态
enum tcp_reassemble_state {
    ESTABLISHED,
    SYN_SENT,
    SYN_RECV,
    FIN_WAIT,
    TIME_WAIT,
    CLOSE,
    CLOSE_WAIT,
    LAST_ACK,
    LISTEN,
    CLOSING,

}

// 定义 tcp flow 状态
enum tcp_flow_state {
    // 准备重组
    EST,
    // 正在重组
    REASSEMBLY,
    // 重组完毕 正常结束
    CLOSE,
    // 重组完毕 RST
    RESET,
    // 重组结束 超时
    TIMEOUT,
    // 重组结束 异常（不停止重组）
    WARNING,
    // 重组结束 错误（可忽视重组 停止重组）
    ERROR
}

// TODO 异常处理 数据结构

// 定义 重组 TCP FLOW 的数据结构
pub struct tcp_flow {
    // 收到第一个 SYN 的时间
    SYN_ts: u16,
    // 开始 重组数据 的时间
    EST_ts: u16,
    // 结束 重组数据 的时间
    end_ts: u16,
    // 异常时间 TODO 由于没有异常处理 暂时不使用
    except_ts: u16,
    client_to_server_steam: LinkedList<tcp_stream>,
    server_to_client_steam: LinkedList<tcp_stream>,
    state: tcp_flow_state,
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

pub fn handle_tcp_packet(interface_name: &str,
                         source: IpAddr,
                         destination: IpAddr,
                         packet: &[u8],
                         stream_hash_map: &mut HashMap<u64, tcp_stream>) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!("[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
                 interface_name,
                 source,
                 tcp.get_source(),
                 destination,
                 tcp.get_destination(),
                 packet.len());
        println!("\tseq:{} ack:{} offset:{}",
                 tcp.get_sequence(),
                 tcp.get_acknowledgement(),
                 tcp.get_data_offset());
        /*
        FLAGS:
        00000000 8 bit
        00000001 FIN
        00000010 SYN
        00000100 RST
        00001000 PSH
        00010000 ACK
        00100000 URG
        01000000 ECE
        10000000 CER
        */
        println!("\tflags:{:b} window:{} checksum:{}",
                 tcp.get_flags(),
                 tcp.get_window(),
                 tcp.get_checksum());
        println!("\toptions:{:?}", tcp.get_options_raw());
        // full packet
        println!("\tpacket:{:?}", tcp.packet());
        // full payload
        println!("\tpayload:{:?}", tcp.payload());
        hexdump::hexdump(packet);

        // create TCP tuple
        let new_tcp_tuple = tcp_tuple {
            sip: source,
            sport: tcp.get_source(),
            dip: destination,
            dport: tcp.get_destination()
        };
        let reverse_new_tcp_tuple = tcp_tuple {
            sip: destination,
            sport: tcp.get_destination(),
            dip: source,
            dport: tcp.get_source()
        };
        // 计算当前方向 Hash
        let hash = calculate_hash(&new_tcp_tuple);
        let reverse_hash = calculate_hash(&reverse_new_tcp_tuple);
        // 检查 是否在已跟踪 stream 中
        if stream_hash_map.contains_key(&hash) {
            // 检查 是否存在 反方向 tuple hash 也就是 另一条 stream
            if stream_hash_map.contains_key(&reverse_hash) {
                // 存在 创建 flow
            };
            // 检查状态 packet 中的 flag
        } else {
            // 判断是否处于 00000010 SYN 时
            if tcp.get_flags() == 2 {
                // 创建新的 stream
                let new_tcp_stream = tcp_stream {
                    tuple: new_tcp_tuple,
                    header: {
                        let new_header = tcp_header {
                            seq: tcp.get_sequence(),
                            ack: tcp.get_acknowledgement(),
                            offset: tcp.get_data_offset(),
                            flag: tcp.get_flags(),
                            window: tcp.get_window(),
                            collect: 1,
                        };
                        new_header
                    },
                    data: {
                        let len = tcp.payload().len();
                        //println!("len: {}", len);
                        // TODO SLOW WAY need check len()
                        let mut payloads: Vec<_> = vec![0; len];
                        payloads.clone_from_slice(tcp.payload());
                        payloads
                    }
                };
                stream_hash_map.insert(hash, new_tcp_stream);
            } else {
                println!("没有从 SYN 开始重组的 TCP 数据，忽略。");
            };
        };
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn check_steam() {
    println!("233")
}