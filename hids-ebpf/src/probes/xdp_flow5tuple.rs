use aya_ebpf::{
    macros::xdp,
    programs::XdpContext,
};

use hids_common::FlowEvent;

use crate::maps::{CAPTURE_ALL_PORTS, FLOW_EVENTS, LOCAL_IPS, SENSITIVE_PORTS, SKIP_IPS};

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const XDP_PASS: u32 = 2;

// tcp flags bits (low 8 bits of 13-bit flags field)
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

const DIR_UNKNOWN: u8 = 0;
const DIR_INBOUND: u8 = 1;
const DIR_OUTBOUND: u8 = 2;

#[inline(always)]
fn read_u16_be(ptr: *const u8) -> u16 {
    let b0 = unsafe { *ptr };
    let b1 = unsafe { *ptr.add(1) };
    ((b0 as u16) << 8) | (b1 as u16)
}

#[inline(always)]
fn read_u32_be(ptr: *const u8) -> u32 {
    let b0 = unsafe { *ptr };
    let b1 = unsafe { *ptr.add(1) };
    let b2 = unsafe { *ptr.add(2) };
    let b3 = unsafe { *ptr.add(3) };
    ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32)
}

#[inline(always)]
fn ip_in_skip(ip_be: u32) -> bool {
    // ip stored in network byte order as big-endian u32.
    let key = ip_be;
    match unsafe { SKIP_IPS.get_ptr(&key) } {
        Some(_) => true,
        None => false,
    }
}

#[inline(always)]
fn ip_is_local(ip_be: u32) -> bool {
    let key = ip_be;
    match unsafe { LOCAL_IPS.get_ptr(&key) } {
        Some(_) => true,
        None => false,
    }
}

#[inline(always)]
fn is_sensitive_port(dst_port: u16) -> bool {
    let all_key: u8 = 0;
    if unsafe { CAPTURE_ALL_PORTS.get_ptr(&all_key) }.is_some() {
        return true;
    }

    unsafe { SENSITIVE_PORTS.get_ptr(&dst_port) }.is_some()
}

#[xdp]
pub fn xdp_flow5tuple(ctx: XdpContext) -> u32 {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;

    // Ethernet header
    if unsafe { data.add(14) } > data_end {
        return XDP_PASS;
    }
    let eth_proto = read_u16_be(unsafe { data.add(12) });
    if eth_proto != ETH_P_IP {
        return XDP_PASS;
    }

    // IPv4 header
    let ip_ptr = unsafe { data.add(14) };
    if unsafe { ip_ptr.add(20) } > data_end {
        return XDP_PASS;
    }

    let ver_ihl = unsafe { *ip_ptr };
    let ihl_words = (ver_ihl & 0x0f) as usize;
    if ihl_words < 5 {
        return XDP_PASS;
    }
    let ip_hdr_len = ihl_words * 4;
    if unsafe { ip_ptr.add(ip_hdr_len) } > data_end {
        return XDP_PASS;
    }

    let proto = unsafe { *ip_ptr.add(9) };
    if proto != IPPROTO_TCP {
        return XDP_PASS;
    }

    let src_ip = read_u32_be(unsafe { ip_ptr.add(12) });
    let dst_ip = read_u32_be(unsafe { ip_ptr.add(16) });

    // Whitelist/skip filtering
    //
    // 语义：只要“本机<->外网”这种典型通信中有一端是非白名单 IP，
    // 就保留它们；只有当 src/dst 同时都在白名单里时才跳过。
    //
    // 否则如果把本机 IP 也放进白名单，同时又用 OR 逻辑跳过，就会把
    // 本机对外的所有流量都排除掉，导致抓不到包。
    if ip_in_skip(src_ip) && ip_in_skip(dst_ip) {
        return XDP_PASS;
    }

    // direction determination: only report inbound (dst is local) for now
    let direction = if ip_is_local(dst_ip) {
        DIR_INBOUND
    } else if ip_is_local(src_ip) {
        DIR_OUTBOUND
    } else {
        DIR_UNKNOWN
    };
    if direction != DIR_INBOUND {
        return XDP_PASS;
    }

    // Transport header offset
    let l4_ptr = unsafe { ip_ptr.add(ip_hdr_len) };
    if unsafe { l4_ptr.add(20) } > data_end {
        return XDP_PASS;
    }
    let src_port = read_u16_be(l4_ptr);
    let dst_port = read_u16_be(unsafe { l4_ptr.add(2) });

    // Exclude DNS response traffic (src_port=53)
    if src_port == 53 {
        return XDP_PASS;
    }

    let sensitive = is_sensitive_port(dst_port);
    if !sensitive {
        return XDP_PASS;
    }

    // TCP flags are at offset 13 in TCP header
    if unsafe { l4_ptr.add(14) } > data_end {
        return XDP_PASS;
    }
    let tcp_flags = unsafe { *l4_ptr.add(13) } & 0x3f;

    // TCP data offset (header length)
    let doff_words = (unsafe { *l4_ptr.add(12) } >> 4) as usize;
    if doff_words < 5 {
        return XDP_PASS;
    }
    let tcp_hdr_len = doff_words * 4;
    if unsafe { l4_ptr.add(tcp_hdr_len) } > data_end {
        return XDP_PASS;
    }
    let total_len = read_u16_be(unsafe { ip_ptr.add(2) }) as u32;
    let l4_payload_len = total_len.saturating_sub((ip_hdr_len + tcp_hdr_len) as u32);

    // demo.md flow: only report TCP SYN (initial) packets as flow events.
    if (tcp_flags & TCP_SYN) != 0 && (tcp_flags & TCP_ACK) == 0 {
        let mut entry = match unsafe { FLOW_EVENTS.reserve::<FlowEvent>(0) } {
            Some(e) => e,
            None => return XDP_PASS,
        };
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).ts = 0;
            (*ev).src_ip = src_ip;
            (*ev).dst_ip = dst_ip;
            (*ev).src_port = src_port;
            (*ev).dst_port = dst_port;
            (*ev).proto = proto;
            (*ev).tcp_flags = tcp_flags;
            (*ev).direction = direction;
            (*ev).is_sensitive_port = if sensitive { 1 } else { 0 };
            (*ev).payload_len = l4_payload_len;
        }
        entry.submit(0);
    }

    XDP_PASS
}

