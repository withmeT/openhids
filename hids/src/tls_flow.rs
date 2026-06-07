//! TLS 事件五元组解析：eBPF fd 表 + 会话缓存 + /proc 扫描，尽量填满 src/dst 端口。

use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::{Duration, Instant};

use crate::events::AgentEvent;

/// 与 eBPF `TlsFdKey` 布局一致（`#[repr(C)]` tgid + ssl_ptr）。
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TlsFdKeyPod {
    pub tgid: u32,
    pub ssl_ptr: u64,
}

unsafe impl aya::Pod for TlsFdKeyPod {}

#[derive(Debug, Clone)]
pub struct TcpSocketTuple {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
}

struct CachedTuple {
    tuple: TcpSocketTuple,
    last_seen: Instant,
}

/// 按 `(tgid, ssl_ptr)` 缓存已解析五元组。
pub struct TlsFlowResolver {
    cache: HashMap<(u32, u64), CachedTuple>,
    monitor_ports: HashSet<u16>,
}

impl TlsFlowResolver {
    pub fn new(monitor_ports: HashSet<u16>) -> Self {
        Self {
            cache: HashMap::new(),
            monitor_ports,
        }
    }

    pub fn prune(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.cache
            .retain(|_, v| now.duration_since(v.last_seen) < max_age);
    }

    /// 解析并写入 `AgentEvent` 的 flow_* / `flow_correlation_key`。
    pub fn apply_to_event(
        &mut self,
        ae: &mut AgentEvent,
        tgid: u32,
        pid: u32,
        ssl_ptr: u64,
        fd: i32,
        tls_direction: u8,
        hint_local_port: Option<u16>,
    ) {
        let Some(tuple) = self.resolve(tgid, pid, ssl_ptr, fd, hint_local_port) else {
            ae.flow_correlation_key = Some(format!("ssl:{ssl_ptr:x}"));
            return;
        };
        fill_flow_fields(ae, &tuple, tls_direction);
    }

    fn resolve(
        &mut self,
        tgid: u32,
        pid: u32,
        ssl_ptr: u64,
        fd: i32,
        hint_local_port: Option<u16>,
    ) -> Option<TcpSocketTuple> {
        let key = (tgid, ssl_ptr);
        if let Some(c) = self.cache.get(&key) {
            return Some(c.tuple.clone());
        }

        for probe_tgid in [tgid, pid] {
            if fd >= 0 {
                if let Some(t) = resolve_tls_socket_tuple(probe_tgid, fd) {
                    if self.accept_tuple(key, t) {
                        return self.cache.get(&key).map(|c| c.tuple.clone());
                    }
                }
            }
            if let Some(t) =
                resolve_via_socket_scan(probe_tgid, &self.monitor_ports, hint_local_port)
            {
                if self.accept_tuple(key, t) {
                    return self.cache.get(&key).map(|c| c.tuple.clone());
                }
            }
        }

        None
    }

    fn accept_tuple(&mut self, key: (u32, u64), tuple: TcpSocketTuple) -> bool {
        if tuple.remote_ip == "0.0.0.0" && tuple.remote_port == 0 {
            return false;
        }
        self.cache.insert(
            key,
            CachedTuple {
                tuple,
                last_seen: Instant::now(),
            },
        );
        true
    }
}

pub fn tcp_flow_correlation_key(
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> String {
    format!("tcp:{src_ip}:{src_port}->{dst_ip}:{dst_port}")
}

pub fn fill_flow_fields(ae: &mut AgentEvent, tuple: &TcpSocketTuple, tls_direction: u8) {
    ae.flow_src_ip = Some(tuple.remote_ip.clone());
    ae.flow_src_port = Some(tuple.remote_port);
    ae.flow_dst_ip = Some(tuple.local_ip.clone());
    ae.flow_dst_port = Some(tuple.local_port);
    ae.flow_proto = Some(6);
    ae.flow_direction = Some(if tls_direction == 1 { 1 } else { 2 });
    ae.flow_is_sensitive_port = Some(true);
    ae.flow_correlation_key = Some(tcp_flow_correlation_key(
        &tuple.remote_ip,
        tuple.remote_port,
        &tuple.local_ip,
        tuple.local_port,
    ));
}

/// 从 HTTP Host / URL 推断本机监听端口（用于多连接歧义）。
pub fn hint_local_port_from_http(payload: &str) -> Option<u16> {
    if let Some(host) = parse_host_header(payload) {
        if let Some((_, port_str)) = host.rsplit_once(':') {
            return port_str.trim().parse().ok();
        }
    }
    None
}

fn parse_host_header(payload: &str) -> Option<String> {
    let header_end = payload.find("\r\n\r\n")?;
    let headers = &payload[..header_end];
    for line in headers.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("host") {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

fn parse_socket_inode_from_fd(tgid: u32, fd: i32) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    let path = format!("/proc/{tgid}/fd/{fd}");
    let link = fs::read_link(path).ok()?;
    let text = link.to_string_lossy();
    let start = text.find("socket:[")?;
    let rem = &text[start + "socket:[".len()..];
    let end = rem.find(']')?;
    rem[..end].parse::<u64>().ok()
}

fn parse_ipv4_hex_le(hex8: &str) -> Option<String> {
    if hex8.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex8, 16).ok()?;
    let b1 = (raw & 0xff) as u8;
    let b2 = ((raw >> 8) & 0xff) as u8;
    let b3 = ((raw >> 16) & 0xff) as u8;
    let b4 = ((raw >> 24) & 0xff) as u8;
    Some(format!("{b1}.{b2}.{b3}.{b4}"))
}

fn resolve_tcp_tuple_by_inode(tgid: u32, inode: u64) -> Option<TcpSocketTuple> {
    let candidates = [format!("/proc/{tgid}/net/tcp"), "/proc/net/tcp".to_string()];
    for p in candidates {
        let text = fs::read_to_string(&p).ok()?;
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 || cols[3] != "01" {
                continue;
            }
            let row_inode = cols[9].parse::<u64>().ok()?;
            if row_inode != inode {
                continue;
            }
            let (lip_hex, lport_hex) = cols[1].split_once(':')?;
            let (rip_hex, rport_hex) = cols[2].split_once(':')?;
            return Some(TcpSocketTuple {
                local_ip: parse_ipv4_hex_le(lip_hex)?,
                local_port: u16::from_str_radix(lport_hex, 16).ok()?,
                remote_ip: parse_ipv4_hex_le(rip_hex)?,
                remote_port: u16::from_str_radix(rport_hex, 16).ok()?,
            });
        }
    }
    None
}

fn resolve_tls_socket_tuple(tgid: u32, fd: i32) -> Option<TcpSocketTuple> {
    let inode = parse_socket_inode_from_fd(tgid, fd)?;
    resolve_tcp_tuple_by_inode(tgid, inode)
}

fn list_socket_fds(tgid: u32) -> Vec<i32> {
    let mut fds = Vec::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{tgid}/fd")) else {
        return fds;
    };
    for entry in entries.flatten() {
        let Ok(link) = fs::read_link(entry.path()) else {
            continue;
        };
        if link.to_string_lossy().contains("socket:[") {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(fd) = name.parse::<i32>() {
                    fds.push(fd);
                }
            }
        }
    }
    fds
}

fn resolve_via_socket_scan(
    tgid: u32,
    monitor_ports: &HashSet<u16>,
    hint_local_port: Option<u16>,
) -> Option<TcpSocketTuple> {
    let mut matches = Vec::new();
    for fd in list_socket_fds(tgid) {
        let Some(inode) = parse_socket_inode_from_fd(tgid, fd) else {
            continue;
        };
        let Some(t) = resolve_tcp_tuple_by_inode(tgid, inode) else {
            continue;
        };
        if t.remote_ip == "0.0.0.0" && t.remote_port == 0 {
            continue;
        }
        if monitor_ports.is_empty() || monitor_ports.contains(&t.local_port) {
            if let Some(hint) = hint_local_port {
                if t.local_port != hint {
                    continue;
                }
            }
            matches.push(t);
        }
    }

    matches.sort_by(|a, b| {
        a.remote_ip
            .cmp(&b.remote_ip)
            .then(a.remote_port.cmp(&b.remote_port))
    });
    matches.dedup_by(|a, b| {
        a.local_ip == b.local_ip
            && a.local_port == b.local_port
            && a.remote_ip == b.remote_ip
            && a.remote_port == b.remote_port
    });

    if matches.len() == 1 {
        return matches.into_iter().next();
    }

    if let Some(hint) = hint_local_port {
        let filtered: Vec<_> = matches.into_iter().filter(|t| t.local_port == hint).collect();
        if filtered.len() == 1 {
            return filtered.into_iter().next();
        }
    }

    None
}
