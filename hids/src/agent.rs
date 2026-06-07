use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::PathBuf,
    sync::{mpsc, Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::RingBuf;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{TracePoint, UProbe, Xdp, XdpFlags};
use pnet_datalink::{self, Channel, Config as DatalinkConfig};
use pnet_packet::Packet;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;

use crate::{
    batcher::Batcher,
    collect_policy,
    config::Config,
    events::{AgentEvent, AgentStats, IngestEnvelope},
    features::file_change,
    http_client::drain_spool,
    spool::Spool,
    tls_flow::{self, TlsFlowResolver},
    utils::cstr_from_fixed,
};

use hids_common::{CommandEvent, ExecEvent, ExitEvent, FlowEvent, TlsEvent, MAX_EXEC_PATH};

fn ipv4_str_to_be_u32(s: &str) -> Option<u32> {
    let mut it = s.split('.');
    let a: u32 = it.next()?.trim().parse().ok()?;
    let b: u32 = it.next()?.trim().parse().ok()?;
    let c: u32 = it.next()?.trim().parse().ok()?;
    let d: u32 = it.next()?.trim().parse().ok()?;
    if [a, b, c, d].iter().any(|x| *x > 255) {
        return None;
    }
    Some((a << 24) | (b << 16) | (c << 8) | d)
}

/// 生成除 `event_kind` / 身份字段外均为空的 `AgentEvent`，减少重复字段。
fn base_event(
    event_kind: u8,
    ts_ms: u64,
    local_ip: Option<&str>,
    uid: u32,
    tgid: u32,
    pid: u32,
    comm: impl Into<String>,
) -> AgentEvent {
    AgentEvent {
        event_kind,
        ts_ms,
        local_ip: local_ip.map(ToOwned::to_owned),
        uid,
        tgid,
        pid,
        comm: comm.into(),
        line: None,
        ssh_client_ip: None,
        exit_code: None,
        success: None,
        flow_correlation_key: None,
        flow_src_ip: None,
        flow_dst_ip: None,
        flow_src_port: None,
        flow_dst_port: None,
        flow_proto: None,
        flow_tcp_flags: None,
        flow_direction: None,
        flow_is_sensitive_port: None,
        flow_payload_len: None,
        http_payload_trunc: None,
        http_trunc_len: None,
        http_method: None,
        http_url: None,
        http_body_trunc: None,
        http_host: None,
        http_cookie_trunc: None,
        http_status: None,
        exec_path: None,
        file_path: None,
        file_op: None,
        tls_direction: None,
        tls_payload_trunc: None,
        tls_threat: None,
    }
}

fn exec_filename_to_string(buf: &[u8], reported_len: u32) -> String {
    if reported_len == 0 {
        return String::new();
    }
    let n = (reported_len as usize).min(buf.len()).min(MAX_EXEC_PATH);
    let slice = &buf[..n];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let mut out = String::with_capacity(end.min(512));
    for ch in String::from_utf8_lossy(&slice[..end]).chars().take(512) {
        if ch.is_ascii_graphic() || ch == ' ' || ch == '/' {
            out.push(ch);
        } else {
            out.push(' ');
        }
    }
    out.trim().to_string()
}

fn detect_libssl_path(cfg_path: &str) -> Option<String> {
    if !cfg_path.trim().is_empty() && cfg_path != "auto" && std::path::Path::new(cfg_path).exists()
    {
        return Some(cfg_path.to_string());
    }

    let out = std::process::Command::new("ldconfig").args(["-p"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if !line.contains("libssl.so") {
            continue;
        }
        if let Some((_, p)) = line.split_once("=>") {
            let path = p.trim();
            if std::path::Path::new(path).exists() {
                return Some(path.to_string());
            }
        }
    }
    None
}

fn parse_host_header(payload: &str) -> Option<&str> {
    for line in payload.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("host") {
                return Some(value.trim());
            }
        }
    }
    None
}

fn payload_hits_target_port(payload: &str, port: u16) -> bool {
    // 0 = disable port filter.
    if port == 0 {
        return true;
    }

    // Fast-path: explicit `:port` exists in plaintext headers.
    let token = format!(":{port}");
    if payload.contains(&token) {
        return true;
    }

    // HTTP response usually has no Host header. For common HTTPS target port 443,
    // allow responses once TLS monitor has already passed process-level filter.
    if payload.starts_with("HTTP/") && port == 443 {
        return true;
    }

    // Handle default-port host without explicit ":443"/":80", e.g.:
    // `Host: 192.168.4.169` while request is actually to 443.
    let Some(host) = parse_host_header(payload) else {
        return false;
    };
    if let Some((_, p)) = host.rsplit_once(':') {
        return p.trim().parse::<u16>().ok() == Some(port);
    }
    matches!(port, 80 | 443)
}

fn detect_sqli_keyword(payload_lc: &str) -> Option<String> {
    const SQLI_PATS: &[&str] = &[
        "union select",
        " or 1=1",
        "' or '1'='1",
        "sleep(",
        "benchmark(",
        "information_schema",
        "select ",
    ];
    for p in SQLI_PATS {
        if payload_lc.contains(p) {
            return Some("sqli_keyword".to_string());
        }
    }
    None
}

fn be_u32_to_ipv4_str(ip_be: u32) -> String {
    let a = (ip_be >> 24) & 0xff;
    let b = (ip_be >> 16) & 0xff;
    let c = (ip_be >> 8) & 0xff;
    let d = ip_be & 0xff;
    format!("{a}.{b}.{c}.{d}")
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

/// `/proc/net/tcp` 状态列（十六进制），`01` = TCP_ESTABLISHED。
const PROC_TCP_ESTABLISHED: &str = "01";

fn read_proc_ppid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if line.starts_with("PPid:") {
            return line.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

fn read_proc_comm(pid: u32) -> Option<String> {
    let s = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(s.trim_end_matches('\n').to_string())
}

fn find_sshd_ancestor(mut pid: u32) -> Option<u32> {
    for _ in 0..48 {
        let comm = read_proc_comm(pid)?;
        if comm == "sshd" {
            return Some(pid);
        }
        let ppid = read_proc_ppid(pid)?;
        if ppid <= 1 {
            break;
        }
        pid = ppid;
    }
    None
}

fn collect_socket_inodes(pid: u32) -> HashSet<u64> {
    let mut out = HashSet::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return out;
    };
    for e in entries.flatten() {
        let Ok(link) = fs::read_link(e.path()) else {
            continue;
        };
        let text = link.to_string_lossy();
        if let Some(rest) = text.strip_prefix("socket:[") {
            if let Some(end) = rest.find(']') {
                if let Ok(inode) = rest[..end].parse::<u64>() {
                    out.insert(inode);
                }
            }
        }
    }
    out
}

fn ssh_client_ipv4_from_sshd(sshd_pid: u32, listen_ports: &HashSet<u16>) -> Option<String> {
    let inodes = collect_socket_inodes(sshd_pid);
    if inodes.is_empty() {
        return None;
    }

    let paths = [
        format!("/proc/{sshd_pid}/net/tcp"),
        "/proc/net/tcp".to_string(),
    ];
    for p in paths {
        let Ok(text) = fs::read_to_string(&p) else {
            continue;
        };
        let mut candidates: Vec<String> = Vec::new();
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 {
                continue;
            }
            if cols[3] != PROC_TCP_ESTABLISHED {
                continue;
            }
            let inode_col = cols[9];
            let Ok(row_inode) = inode_col.parse::<u64>() else {
                continue;
            };
            if !inodes.contains(&row_inode) {
                continue;
            }
            let local = cols[1];
            let remote = cols[2];
            let Some((_lip_hex, lport_hex)) = local.split_once(':') else {
                continue;
            };
            let Some((rip_hex, rport_hex)) = remote.split_once(':') else {
                continue;
            };
            let local_port = match u16::from_str_radix(lport_hex, 16) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if !listen_ports.contains(&local_port) {
                continue;
            }
            let Some(remote_ip) = parse_ipv4_hex_le(rip_hex) else {
                continue;
            };
            let Ok(remote_port) = u16::from_str_radix(rport_hex, 16) else {
                continue;
            };
            if remote_ip == "0.0.0.0" && remote_port == 0 {
                continue;
            }
            candidates.push(remote_ip);
        }
        if !candidates.is_empty() {
            if let Some(ip) = candidates.iter().find(|ip| *ip != "127.0.0.1") {
                return Some(ip.clone());
            }
            return Some(candidates[0].clone());
        }
    }
    None
}

fn resolve_ssh_client_ip_for_shell(shell_pid: u32, listen_ports: &HashSet<u16>) -> Option<String> {
    let sshd = find_sshd_ancestor(shell_pid)?;
    ssh_client_ipv4_from_sshd(sshd, listen_ports)
}

fn detect_local_ipv4s() -> Vec<String> {
    // best-effort: hostname -I is common on linux.
    let out = std::process::Command::new("hostname")
        .arg("-I")
        .output();
    let Ok(out) = out else {
        return Vec::new();
    };
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace()
        .filter_map(|tok| ipv4_str_to_be_u32(tok).map(|_| tok.to_string()))
        .collect()
}

#[derive(Debug)]
struct HttpL7Event {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    /// 请求方法；响应事件为空字符串。
    method: String,
    /// 请求路径；响应事件为空字符串。
    url: String,
    body_trunc: String,
    http_host: Option<String>,
    http_cookie_trunc: Option<String>,
    /// 仅响应：HTTP 状态码。
    http_status: Option<u16>,
    is_response: bool,
}

fn sanitize_text_200(s: &str) -> String {
    sanitize_text_n(s, 200)
}

fn sanitize_text_1024(s: &str) -> String {
    sanitize_text_n(s, 1024)
}

fn sanitize_text_n(s: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(max_len.min(1024));
    for ch in s.chars() {
        if out.len() >= max_len {
            break;
        }
        if ch.is_ascii_graphic() || ch == ' ' {
            out.push(ch);
        } else {
            out.push(' ');
        }
    }
    out.trim().to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TlsStreamKey {
    tgid: u32,
    ssl_ptr: u64,
    /// 0=ssl_write 1=ssl_read（与 eBPF direction 一致）
    direction: u8,
}

#[derive(Debug)]
struct TlsStreamBuf {
    buf: Vec<u8>,
    last_ts_ms: u64,
}

fn parse_content_length(header_part: &str) -> Option<usize> {
    for line in header_part.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse::<usize>().ok();
            }
        }
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn tls_http_message_complete(buf: &[u8]) -> Option<(usize, usize)> {
    // returns (header_end_index, total_message_len)
    let header_end = find_bytes(buf, b"\r\n\r\n")?;
    let header_part = String::from_utf8_lossy(&buf[..header_end]);
    let body_len = parse_content_length(&header_part).unwrap_or(0);
    let total = header_end + 4 + body_len;
    if buf.len() >= total {
        Some((header_end, total))
    } else {
        None
    }
}

/// 用户态 HTTP L7 嗅探线程与热重载共享的运行时参数（端口集合、静态路径过滤）。
#[derive(Debug, Clone)]
struct HttpL7Runtime {
    pub http_port_set: HashSet<u16>,
    pub ignore_path_prefixes: Vec<String>,
    pub ignore_path_suffixes: Vec<String>,
    pub capture_response: bool,
    pub response_min_status: u16,
}

impl HttpL7Runtime {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            http_port_set: cfg.http_l7_ports.iter().copied().collect(),
            ignore_path_prefixes: cfg.http_l7_ignore_path_prefixes.clone(),
            ignore_path_suffixes: cfg.http_l7_ignore_path_suffixes.clone(),
            capture_response: cfg.http_l7_capture_response,
            response_min_status: cfg.http_l7_response_min_status,
        }
    }

    /// 若应丢弃该 **入站请求**（静态资源等），返回 true。
    ///
    /// 安全约束：不丢弃 `POST`/`PUT`/`PATCH`/`DELETE`；不丢弃 URL 中带 `?` 的
    /// `GET`/`HEAD`（query 中常见注入）；`CONNECT` 等非常规方法也不按静态后缀丢。
    pub fn should_drop_request_url(&self, method: &str, url: &str) -> bool {
        let m = method.trim().to_ascii_uppercase();
        match m.as_str() {
            "POST" | "PUT" | "PATCH" | "DELETE" => return false,
            "GET" | "HEAD" => {
                if url.contains('?') {
                    return false;
                }
            }
            _ => return false,
        }

        let path = url.split('?').next().unwrap_or(url);
        let path_lc = path.to_ascii_lowercase();
        for p in &self.ignore_path_prefixes {
            if path.starts_with(p) {
                return true;
            }
        }
        for s in &self.ignore_path_suffixes {
            let s_lc = s.to_ascii_lowercase();
            if path_lc.ends_with(&s_lc) {
                return true;
            }
        }
        false
    }
}

/// 取 HTTP 报文头块（不含首行体），用于解析 `Content-Type`。
fn http_header_text(payload: &[u8]) -> Option<String> {
    let end = find_bytes(payload, b"\r\n\r\n")?;
    Some(String::from_utf8_lossy(&payload[..end]).into_owned())
}

fn parse_http_header_value_lc(headers: &str, name: &str) -> Option<String> {
    for line in headers.split("\r\n") {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(name) {
            return Some(v.trim().to_ascii_lowercase());
        }
    }
    None
}

fn main_content_type(ct: &str) -> &str {
    ct.split(';').next().unwrap_or(ct).trim()
}

/// 出站 TLS/HTTP 响应：高置信度静态资源（不丢 `text/html` / `application/json` / `image/svg+xml`）。
fn is_static_asset_response_content_type(ct: &str) -> bool {
    let m = main_content_type(ct);
    if m.starts_with("image/") {
        return m != "image/svg+xml";
    }
    m.starts_with("font/")
        || m.starts_with("video/")
        || m.starts_with("audio/")
        || m == "text/css"
        || m == "application/javascript"
        || m == "text/javascript"
        || m == "application/x-javascript"
        || m == "application/wasm"
        || m == "application/vnd.ms-fontobject"
}

fn should_drop_plaintext_http_static_response(payload: &[u8]) -> bool {
    let Some(hdr) = http_header_text(payload) else {
        return false;
    };
    let Some(ct) = parse_http_header_value_lc(&hdr, "content-type") else {
        return false;
    };
    is_static_asset_response_content_type(&ct)
}

fn parse_http_request_details(payload: &[u8]) -> Option<(String, String, Option<String>, Option<String>, String)> {
    let text = String::from_utf8_lossy(payload);
    let header_end = text.find("\r\n\r\n");
    let header_part = if let Some(i) = header_end {
        &text[..i]
    } else {
        text.as_ref()
    };
    let body = if let Some(i) = header_end {
        &text[i + 4..]
    } else {
        ""
    };

    let mut lines = header_part.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let url = parts.next().unwrap_or("/").to_string();

    match method.as_str() {
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" => {}
        _ => return None,
    }

    let mut host = None;
    let mut cookie = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let n = name.trim();
            let v = value.trim();
            if n.eq_ignore_ascii_case("host") {
                host = Some(sanitize_text_200(v));
            } else if n.eq_ignore_ascii_case("cookie") {
                cookie = Some(sanitize_text_200(v));
            }
        }
    }

    Some((
        sanitize_text_200(&method),
        sanitize_text_200(&url),
        host,
        cookie,
        sanitize_text_200(body),
    ))
}

fn parse_http_response_status(payload: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(payload);
    let first = text.split("\r\n").next()?;
    let mut parts = first.split_whitespace();
    let ver = parts.next()?;
    if !ver.to_ascii_uppercase().starts_with("HTTP/") {
        return None;
    }
    let code = parts.next()?.parse::<u16>().ok()?;
    Some(code)
}

fn spawn_http_sniffer(
    iface_name: String,
    local_ips: Vec<String>,
    runtime: Arc<RwLock<HttpL7Runtime>>,
) -> mpsc::Receiver<HttpL7Event> {
    let (tx, rx) = mpsc::channel::<HttpL7Event>();
    std::thread::spawn(move || {
        let local_set: HashSet<String> = local_ips.into_iter().collect();
        let interfaces = pnet_datalink::interfaces();
        let Some(interface) = interfaces.into_iter().find(|i| i.name == iface_name) else {
            return;
        };

        let cfg = DatalinkConfig {
            read_timeout: Some(Duration::from_millis(200)),
            ..Default::default()
        };

        let chan = pnet_datalink::channel(&interface, cfg);
        let Ok(Channel::Ethernet(_tx, mut rx_dl)) = chan else {
            return;
        };

        loop {
            let Ok(frame) = rx_dl.next() else {
                continue;
            };
            let Some(eth) = EthernetPacket::new(frame) else {
                continue;
            };
            if eth.get_ethertype() != EtherTypes::Ipv4 {
                continue;
            }
            let Some(ip) = Ipv4Packet::new(eth.payload()) else {
                continue;
            };
            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                continue;
            }
            let src_ip = ip.get_source().to_string();
            let dst_ip = ip.get_destination().to_string();

            let Some(tcp) = TcpPacket::new(ip.payload()) else {
                continue;
            };

            let is_inbound_request = local_set.contains(&dst_ip);
            let is_outbound_response =
                local_set.contains(&src_ip) && !local_set.contains(&dst_ip);

            if is_inbound_request {
                let dst_port = tcp.get_destination();
                {
                    let rt = match runtime.read() {
                        Ok(g) => g,
                        Err(_) => continue,
                    };
                    if !rt.http_port_set.contains(&dst_port) {
                        continue;
                    }
                }
                let payload = tcp.payload();
                if payload.is_empty() {
                    continue;
                }
                let Some((method, url, host, cookie, body_trunc)) =
                    parse_http_request_details(payload)
                else {
                    continue;
                };

                {
                    let rt = match runtime.read() {
                        Ok(g) => g,
                        Err(_) => continue,
                    };
                    if rt.should_drop_request_url(&method, &url) {
                        continue;
                    }
                }

                let _ = tx.send(HttpL7Event {
                    src_ip,
                    dst_ip,
                    src_port: tcp.get_source(),
                    dst_port,
                    method,
                    url,
                    body_trunc,
                    http_host: host,
                    http_cookie_trunc: cookie,
                    http_status: None,
                    is_response: false,
                });
            } else if is_outbound_response {
                let capture = {
                    let rt = match runtime.read() {
                        Ok(g) => g,
                        Err(_) => continue,
                    };
                    rt.capture_response
                };
                if !capture {
                    continue;
                }
                let src_port = tcp.get_source();
                {
                    let rt = match runtime.read() {
                        Ok(g) => g,
                        Err(_) => continue,
                    };
                    if !rt.http_port_set.contains(&src_port) {
                        continue;
                    }
                }
                let payload = tcp.payload();
                if payload.is_empty() {
                    continue;
                }
                let Some(status) = parse_http_response_status(payload) else {
                    continue;
                };
                let min_status = {
                    let rt = match runtime.read() {
                        Ok(g) => g,
                        Err(_) => continue,
                    };
                    rt.response_min_status
                };
                if !collect_policy::should_emit_http_response(
                    status,
                    true,
                    min_status,
                ) {
                    continue;
                };
                let text = String::from_utf8_lossy(payload);
                let text_lc = text.to_ascii_lowercase();
                if should_drop_plaintext_http_static_response(payload)
                    && detect_sqli_keyword(&text_lc).is_none()
                {
                    continue;
                }
                let body_trunc = if let Some(idx) = text.find("\r\n\r\n") {
                    sanitize_text_200(&text[idx + 4..])
                } else {
                    String::new()
                };

                let _ = tx.send(HttpL7Event {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port: tcp.get_destination(),
                    method: String::new(),
                    url: String::new(),
                    body_trunc,
                    http_host: None,
                    http_cookie_trunc: None,
                    http_status: Some(status),
                    is_response: true,
                });
            }
        }
    });
    rx
}

fn parse_dev_from_ip_route(s: &str) -> Option<String> {
    // Example:
    // default via 192.168.1.1 dev eth0 proto dhcp metric 100
    let toks: Vec<&str> = s.split_whitespace().collect();
    for i in 0..toks.len().saturating_sub(1) {
        if toks[i] == "dev" {
            return Some(toks[i + 1].to_string());
        }
    }
    None
}

fn detect_external_iface() -> Option<String> {
    // Prefer the default route's interface (best-effort).
    let out = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output();
    if let Ok(out) = out {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(dev) = parse_dev_from_ip_route(&s) {
                return Some(dev);
            }
        }
    }

    // Another common fallback.
    let out = std::process::Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output();
    if let Ok(out) = out {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(dev) = parse_dev_from_ip_route(&s) {
                return Some(dev);
            }
        }
    }

    // Last fallback: first "up" non-loopback interface.
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show", "up"])
        .output();
    if let Ok(out) = out {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                // Example: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
                if let Some((_, rest)) = line.split_once(':') {
                    let rest = rest.trim_start();
                    let ifname = rest.split(':').next().unwrap_or("").trim();
                    if ifname.is_empty() {
                        continue;
                    }
                    if ifname == "lo" {
                        continue;
                    }
                    if ifname.starts_with("docker")
                        || ifname.starts_with("br-")
                        || ifname.starts_with("veth")
                        || ifname.starts_with("virbr")
                    {
                        continue;
                    }
                    return Some(ifname.to_string());
                }
            }
        }
    }

    None
}

async fn send_envelope(
    client: &reqwest::Client,
    url: &str,
    envelope: &IngestEnvelope,
) -> anyhow::Result<()> {
    let res = client
        .post(url)
        .json(envelope)
        .send()
        .await
        .context("send http request")?;
    let status = res.status();
    if !status.is_success() {
        // Avoid dumping huge HTML debug pages or other large responses into logs.
        let text = res.text().await.unwrap_or_default();
        let mut preview = sanitize_text_n(&text, 400);
        if text.len() > preview.len() {
            preview.push_str(" ...");
        }
        anyhow::bail!("http status={status} body_preview={preview}");
    }
    Ok(())
}

pub async fn run() -> Result<(), anyhow::Error> {
    let mut cfg = Config::load()?;
    let agent_local_ip: Option<String> = detect_local_ipv4s()
        .into_iter()
        .find(|ip| ip != "127.0.0.1")
        .or_else(|| Some("127.0.0.1".to_string()));

    const AGENT_VERSION: &str = env!("HIDS_GIT_SHA");
    let schema_version: u32 = env!("HIDS_SCHEMA_VERSION")
        .parse()
        .unwrap_or(1);
    let agent_version: String = AGENT_VERSION.to_string();

    println!(
        "hids agent start: version={} schema_version={} collect_mode={:?}",
        AGENT_VERSION, schema_version, cfg.collect_mode
    );

    // disk spool budget: <= 100MB as requested
    let spool = Spool::new(cfg.spool_dir.clone(), cfg.spool_max_bytes);

    // Built by `hids/build.rs` into OUT_DIR.
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/hids")))?;

    let program: &mut UProbe = bpf
        .program_mut("uretprobe_readline")
        .context("program uretprobe_readline not found")?
        .try_into()?;
    program.load().context("load uretprobe")?;

    program
        .attach("readline", "/bin/bash", None)
        .context("attach uretprobe to /bin/bash:readline")?;

    println!("Attached to /bin/bash:readline. Type commands in bash to see events.");

    let events_map = bpf
        .take_map("EVENTS")
        .context("map EVENTS not found")?;
    let mut ringbuf_cmd = RingBuf::try_from(events_map)?;

    let mut ringbuf_tls = None;
    let mut tls_flow_resolver = None;
    let mut tls_ssl_fd_map: Option<AyaHashMap<_, tls_flow::TlsFdKeyPod, i32>> = None;
    if cfg.tls_monitor_enabled {
        let mut tls_ports: HashSet<u16> = cfg.http_l7_ports.iter().copied().collect();
        tls_ports.insert(cfg.tls_target_port);
        tls_flow_resolver = Some(TlsFlowResolver::new(tls_ports));

        if let Some(map_data) = bpf.take_map("TLS_SSL_FD") {
            if let Ok(map) = AyaHashMap::try_from(map_data) {
                tls_ssl_fd_map = Some(map);
                eprintln!("hids: TLS_SSL_FD map ready (ssl_ptr -> socket fd)");
            }
        }

        let libssl_path = detect_libssl_path(&cfg.tls_libssl_path)
            .ok_or_else(|| anyhow::anyhow!("libssl path not found; set tls_libssl_path"))?;

        let ssl_write_prog: &mut UProbe = bpf
            .program_mut("uprobe_ssl_write")
            .context("program uprobe_ssl_write not found")?
            .try_into()?;
        ssl_write_prog.load().context("load uprobe_ssl_write")?;
        ssl_write_prog
            .attach("SSL_write", &libssl_path, None)
            .with_context(|| format!("attach SSL_write to {libssl_path}"))?;

        let ssl_read_prog: &mut UProbe = bpf
            .program_mut("uretprobe_ssl_read")
            .context("program uretprobe_ssl_read not found")?
            .try_into()?;
        ssl_read_prog.load().context("load uretprobe_ssl_read")?;
        ssl_read_prog
            .attach("SSL_read", &libssl_path, None)
            .with_context(|| format!("attach SSL_read to {libssl_path}"))?;

        let ssl_read_enter_prog: &mut UProbe = bpf
            .program_mut("uprobe_ssl_read_enter")
            .context("program uprobe_ssl_read_enter not found")?
            .try_into()?;
        ssl_read_enter_prog
            .load()
            .context("load uprobe_ssl_read_enter")?;
        ssl_read_enter_prog
            .attach("SSL_read", &libssl_path, None)
            .with_context(|| format!("attach SSL_read(entry) to {libssl_path}"))?;

        // Best-effort: bind TLS `SSL*` to socket fd so event_kind=7 can carry src/dst tuple.
        if let Some(p) = bpf.program_mut("uprobe_ssl_set_fd") {
            let prog: &mut UProbe = p.try_into()?;
            prog.load().context("load uprobe_ssl_set_fd")?;
            let _ = prog.attach("SSL_set_fd", &libssl_path, None);
        }
        if let Some(p) = bpf.program_mut("uprobe_ssl_set_rfd") {
            let prog: &mut UProbe = p.try_into()?;
            prog.load().context("load uprobe_ssl_set_rfd")?;
            let _ = prog.attach("SSL_set_rfd", &libssl_path, None);
        }
        if let Some(p) = bpf.program_mut("uprobe_ssl_set_wfd") {
            let prog: &mut UProbe = p.try_into()?;
            prog.load().context("load uprobe_ssl_set_wfd")?;
            let _ = prog.attach("SSL_set_wfd", &libssl_path, None);
        }
        if let Some(p) = bpf.program_mut("uprobe_ssl_free") {
            let prog: &mut UProbe = p.try_into()?;
            prog.load().context("load uprobe_ssl_free")?;
            let _ = prog.attach("SSL_free", &libssl_path, None);
        }

        let tls_map = bpf.take_map("TLS_EVENTS").context("map TLS_EVENTS not found")?;
        ringbuf_tls = Some(RingBuf::try_from(tls_map)?);
        println!(
            "Attached TLS uprobes on {} (target_comm='{}' target_port={})",
            libssl_path, cfg.tls_target_comm, cfg.tls_target_port
        );
    }

    let mut ringbuf_exec = None;
    let mut ringbuf_exit = None;
    if cfg.proc_monitor_enabled {
        const TP: &[(&str, &str, &str)] = &[
            ("trace_enter_execve", "syscalls", "sys_enter_execve"),
            ("trace_enter_exit", "syscalls", "sys_enter_exit"),
            ("trace_enter_exit_group", "syscalls", "sys_enter_exit_group"),
        ];
        for &(prog, cat, name) in TP {
            let program: &mut TracePoint = bpf
                .program_mut(prog)
                .with_context(|| format!("program {prog} not found"))?
                .try_into()
                .with_context(|| format!("program {prog} is not a TracePoint"))?;
            program.load().with_context(|| format!("load {prog}"))?;
            program
                .attach(cat, name)
                .with_context(|| format!("attach {prog} -> {cat}/{name}"))?;
        }
        println!("Attached tracepoints: execve, exit, exit_group (proc monitor).");

        let exec_map = bpf
            .take_map("EXEC_EVENTS")
            .context("map EXEC_EVENTS not found")?;
        ringbuf_exec = Some(RingBuf::try_from(exec_map)?);

        let exit_map = bpf
            .take_map("EXIT_EVENTS")
            .context("map EXIT_EVENTS not found")?;
        ringbuf_exit = Some(RingBuf::try_from(exit_map)?);
    }

    let file_watch_rx = if !cfg.file_watch_paths.is_empty() {
        let paths: Vec<PathBuf> = cfg.file_watch_paths.iter().map(PathBuf::from).collect();
        file_change::spawn_file_watcher(paths)
    } else {
        None
    };

    // XDP flow collection (five tuple)
    let mut ringbuf_flow = None;
    let mut http_l7_rx: Option<mpsc::Receiver<HttpL7Event>> = None;
    let mut http_l7_runtime: Option<Arc<RwLock<HttpL7Runtime>>> = None;
    if cfg.xdp_enabled {
        // 1) configure maps
        let skip_map_data = bpf.take_map("SKIP_IPS").context("map SKIP_IPS not found")?;
        let mut skip_map = AyaHashMap::<_, u32, u8>::try_from(skip_map_data)?;

        let local_ips_map_data = bpf.take_map("LOCAL_IPS").context("map LOCAL_IPS not found")?;
        let mut local_ips_map = AyaHashMap::<_, u32, u8>::try_from(local_ips_map_data)?;
        let sensitive_ports_map_data = bpf
            .take_map("SENSITIVE_PORTS")
            .context("map SENSITIVE_PORTS not found")?;
        let mut sensitive_ports_map = AyaHashMap::<_, u16, u8>::try_from(sensitive_ports_map_data)?;
        let capture_all_ports_map_data = bpf
            .take_map("CAPTURE_ALL_PORTS")
            .context("map CAPTURE_ALL_PORTS not found")?;
        let mut capture_all_ports_map =
            AyaHashMap::<_, u8, u8>::try_from(capture_all_ports_map_data)?;

        // always mark loopback/local for direction detection
        if let Some(ip) = ipv4_str_to_be_u32("127.0.0.1") {
            let _ = local_ips_map.insert(ip, 1, 0);
            // keep loopback also in skip to avoid useless localhost traffic
            let _ = skip_map.insert(ip, 1, 0);
        }
        for ip in detect_local_ipv4s() {
            if let Some(ip_be) = ipv4_str_to_be_u32(&ip) {
                let _ = local_ips_map.insert(ip_be, 1, 0);
            }
        }
        for ip in &cfg.xdp_skip_ips {
            if let Some(ip_be) = ipv4_str_to_be_u32(ip) {
                let _ = skip_map.insert(ip_be, 1, 0);
            }
        }
        for p in &cfg.xdp_sensitive_ports {
            let _ = sensitive_ports_map.insert(*p, 1, 0);
        }
        if cfg.xdp_capture_all_ports {
            let _ = capture_all_ports_map.insert(0, 1, 0);
        }

        // 2) attach XDP
        let iface = if cfg.xdp_iface.trim().is_empty() || cfg.xdp_iface == "auto" {
            detect_external_iface().unwrap_or_else(|| "eth0".to_string())
        } else {
            cfg.xdp_iface.clone()
        };

        let xdp_program: &mut Xdp = bpf
            .program_mut("xdp_flow5tuple")
            .context("program xdp_flow5tuple not found")?
            .try_into()?;
        xdp_program.load().context("load xdp program")?;
        xdp_program
            .attach(&iface, XdpFlags::default())
            .context("attach xdp program")?;

        println!(
            "Attached XDP: iface={} (event_kind=2 flow five-tuple).",
            iface
        );

        // Formal approach: keep XDP lightweight and collect HTTP URL/body
        // in userspace from the selected interface.
        let rt = Arc::new(RwLock::new(HttpL7Runtime::from_config(&cfg)));
        http_l7_runtime = Some(rt.clone());
        http_l7_rx = Some(spawn_http_sniffer(
            iface.clone(),
            detect_local_ipv4s(),
            rt,
        ));

        let flow_map = bpf
            .take_map("FLOW_EVENTS")
            .context("map FLOW_EVENTS not found")?;
        ringbuf_flow = Some(RingBuf::try_from(flow_map)?);

    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build http client")?;

    let mut batcher = Batcher::new(
        cfg.flush_bytes,
        Duration::from_millis(cfg.flush_interval_ms),
        cfg.flush_max_events,
    );

    // pending serialized batches kept in memory before spilling
    let mut mem_queue_max: usize = cfg.mem_queue_max_bytes;
    let mut pending: VecDeque<Vec<AgentEvent>> = VecDeque::new();
    let mut pending_bytes: usize = 0;
    let mut max_send_batches_per_iter: usize = cfg.max_send_batches_per_iter;
    let mut spool_drain_interval_secs: u64 = cfg.spool_drain_interval_secs;
    let mut last_cfg_reload = std::time::Instant::now();

    let mut last_spool_drain = std::time::Instant::now();

    // HTTP L7 去重：相同五元组 + 请求/响应语义标签 在窗口内只上报一次。
    type HttpDedupKey = (String, String, u16, u16, String);
    let mut http_dedup: HashMap<HttpDedupKey, u64> = HashMap::new();
    let mut last_http_dedup_prune = Instant::now();
    let mut flow_syn_dedup: HashMap<(String, u16), u64> = HashMap::new();

    // TLS 明文流式拼接（最佳努力）：按 (tgid, direction) 拼接连续的 SSL_read/write 片段，
    // 尝试重组出完整的 HTTP/1.x 请求/响应（Content-Length 场景优先）。
    let mut tls_streams: HashMap<TlsStreamKey, TlsStreamBuf> = HashMap::new();
    let mut last_tls_streams_prune = Instant::now();
    let mut last_tls_flow_prune = Instant::now();

    // bash `tgid` -> 已解析的 SSH 客户端 IPv4（同一 shell 会话内避免重复扫 /proc）。
    let mut ssh_client_ip_by_tgid: HashMap<u32, String> = HashMap::new();

    loop {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // 0) hot reload config (best-effort)
        if last_cfg_reload.elapsed().as_secs() >= cfg.config_reload_interval_secs {
            if let Ok(new_cfg) = Config::load() {
                // HTTP L7：端口与静态路径过滤可热更新（与嗅探线程共享；需先借用 new_cfg）。
                if let Some(rt) = http_l7_runtime.as_ref() {
                    if let Ok(mut w) = rt.write() {
                        *w = HttpL7Runtime::from_config(&new_cfg);
                    }
                }

                // Keep spool configuration stable during runtime to avoid inconsistencies.
                cfg.ingest_url = new_cfg.ingest_url;

                mem_queue_max = new_cfg.mem_queue_max_bytes;
                max_send_batches_per_iter = new_cfg.max_send_batches_per_iter;
                spool_drain_interval_secs = new_cfg.spool_drain_interval_secs;

                // Update flush thresholds for the next flush window.
                batcher.update_params(
                    new_cfg.flush_bytes,
                    Duration::from_millis(new_cfg.flush_interval_ms),
                    new_cfg.flush_max_events,
                );

                cfg.http_l7_dedup_window_ms = new_cfg.http_l7_dedup_window_ms;
                cfg.http_l7_ignore_path_prefixes = new_cfg.http_l7_ignore_path_prefixes.clone();
                cfg.http_l7_ignore_path_suffixes = new_cfg.http_l7_ignore_path_suffixes.clone();
                cfg.http_l7_ports = new_cfg.http_l7_ports.clone();
                cfg.http_l7_capture_response = new_cfg.http_l7_capture_response;
                cfg.http_l7_response_min_status = new_cfg.http_l7_response_min_status;
                cfg.collect_mode = new_cfg.collect_mode;
                cfg.bash_filter_boring = new_cfg.bash_filter_boring;
                cfg.flow_syn_dedup_window_ms = new_cfg.flow_syn_dedup_window_ms;
                cfg.tls_emit_incomplete_chunks = new_cfg.tls_emit_incomplete_chunks;
                cfg.tls_target_comm = new_cfg.tls_target_comm.clone();
                cfg.tls_target_port = new_cfg.tls_target_port;

                cfg.host_id = new_cfg.host_id;
                cfg.ssh_listen_ports = new_cfg.ssh_listen_ports.clone();

                last_cfg_reload = std::time::Instant::now();
            }
        }

        // 去重表定期裁剪，避免长期运行内存增长。
        if last_http_dedup_prune.elapsed() >= Duration::from_secs(60) {
            let max_age = cfg
                .http_l7_dedup_window_ms
                .saturating_mul(10)
                .max(60_000);
            http_dedup.retain(|_, ts| now_ms.saturating_sub(*ts) < max_age);
            flow_syn_dedup.retain(|_, ts| now_ms.saturating_sub(*ts) < max_age);
            last_http_dedup_prune = Instant::now();
        }

        // TLS 流缓存定期裁剪（避免长期运行/异常流量导致内存增长）。
        if last_tls_streams_prune.elapsed() >= Duration::from_secs(2) {
            let ttl_ms: u64 = 10_000;
            tls_streams.retain(|_, st| now_ms.saturating_sub(st.last_ts_ms) < ttl_ms);
            // hard cap: keep only the most recent N streams
            const MAX_TLS_STREAMS: usize = 1024;
            if tls_streams.len() > MAX_TLS_STREAMS {
                // best-effort: drop arbitrary extras (HashMap order is unspecified).
                let drop_n = tls_streams.len() - MAX_TLS_STREAMS;
                let mut dropped = 0usize;
                let keys: Vec<TlsStreamKey> = tls_streams.keys().copied().take(drop_n).collect();
                for k in keys {
                    tls_streams.remove(&k);
                    dropped += 1;
                    if dropped >= drop_n {
                        break;
                    }
                }
            }
            last_tls_streams_prune = Instant::now();
        }

        if let Some(resolver) = tls_flow_resolver.as_mut() {
            if last_tls_flow_prune.elapsed() >= Duration::from_secs(60) {
                resolver.prune(Duration::from_secs(300));
                last_tls_flow_prune = Instant::now();
            }
        }

        // 1) read events (fast)
        let ssh_listen_ports_set: HashSet<u16> = cfg.ssh_listen_ports.iter().copied().collect();
        while let Some(item) = ringbuf_cmd.next() {
            if item.len() < core::mem::size_of::<CommandEvent>() {
                continue;
            }
            let ptr = item.as_ptr() as *const CommandEvent;
            // SAFETY: kernel wrote a C struct into the ringbuf; we only read it.
            let ev = unsafe { core::ptr::read_unaligned(ptr) };
            let comm = cstr_from_fixed(&ev.comm);
            let line = cstr_from_fixed(&ev.line);
            let ts_ms = now_ms;

            let mut ae = base_event(
                0,
                ts_ms,
                agent_local_ip.as_deref(),
                ev.uid,
                ev.tgid,
                ev.pid,
                comm,
            );
            ae.line = Some(line.clone());
            if !collect_policy::should_emit_bash_line(&line, cfg.bash_filter_boring) {
                continue;
            }
            if let Some(ip) = ssh_client_ip_by_tgid
                .get(&ev.tgid)
                .cloned()
                .or_else(|| {
                    let ip = resolve_ssh_client_ip_for_shell(ev.pid, &ssh_listen_ports_set);
                    if let Some(ref s) = ip {
                        ssh_client_ip_by_tgid.insert(ev.tgid, s.clone());
                    }
                    ip
                })
            {
                ae.ssh_client_ip = Some(ip);
            }
            batcher.push(ae);
        }

        if let Some(rb) = ringbuf_exec.as_mut() {
            while let Some(item) = rb.next() {
                if item.len() < core::mem::size_of::<ExecEvent>() {
                    continue;
                }
                let ptr = item.as_ptr() as *const ExecEvent;
                let ev = unsafe { core::ptr::read_unaligned(ptr) };
                let comm = cstr_from_fixed(&ev.comm);
                let path = exec_filename_to_string(&ev.filename, ev.filename_len);
                let mut ae = base_event(
                    4,
                    now_ms,
                    agent_local_ip.as_deref(),
                    ev.uid,
                    ev.tgid,
                    ev.pid,
                    comm,
                );
                ae.exec_path = Some(path);
                batcher.push(ae);
            }
        }

        if let Some(rb) = ringbuf_exit.as_mut() {
            while let Some(item) = rb.next() {
                if item.len() < core::mem::size_of::<ExitEvent>() {
                    continue;
                }
                let ptr = item.as_ptr() as *const ExitEvent;
                let ev = unsafe { core::ptr::read_unaligned(ptr) };
                let comm = cstr_from_fixed(&ev.comm);
                let mut ae = base_event(
                    5,
                    now_ms,
                    agent_local_ip.as_deref(),
                    ev.uid,
                    ev.tgid,
                    ev.pid,
                    comm,
                );
                ae.exit_code = Some(ev.exit_code);
                batcher.push(ae);
            }
        }

        if let Some(rb) = ringbuf_tls.as_mut() {
            while let Some(item) = rb.next() {
                if item.len() < core::mem::size_of::<TlsEvent>() {
                    continue;
                }
                let ptr = item.as_ptr() as *const TlsEvent;
                let ev = unsafe { core::ptr::read_unaligned(ptr) };
                let comm = cstr_from_fixed(&ev.comm);
                if !cfg.tls_target_comm.is_empty() && !comm.contains(&cfg.tls_target_comm) {
                    continue;
                }

                let n = (ev.len as usize).min(ev.data.len());
                if n == 0 {
                    continue;
                }
                let key = TlsStreamKey {
                    tgid: ev.tgid,
                    ssl_ptr: ev.ssl_ptr,
                    direction: ev.direction,
                };
                let st = tls_streams.entry(key).or_insert_with(|| TlsStreamBuf {
                    buf: Vec::with_capacity(4096),
                    last_ts_ms: now_ms,
                });
                st.last_ts_ms = now_ms;
                st.buf.extend_from_slice(&ev.data[..n]);

                // avoid unbounded growth (best-effort)
                const MAX_TLS_BUF: usize = 128 * 1024;
                if st.buf.len() > MAX_TLS_BUF {
                    let drain_n = st.buf.len() - MAX_TLS_BUF;
                    st.buf.drain(0..drain_n);
                }

                // Try to extract as many complete HTTP messages as possible from the buffer.
                let mut emitted = false;
                loop {
                    let Some((_hdr_end, total_len)) = tls_http_message_complete(&st.buf) else {
                        break;
                    };
                    let msg: Vec<u8> = st.buf.drain(0..total_len).collect();

                    // `msg` should be a full HTTP/1.x message (best-effort).
                    let payload_raw = String::from_utf8_lossy(&msg).to_string();
                    if !payload_hits_target_port(&payload_raw, cfg.tls_target_port) {
                        continue;
                    }

                    let payload_lc = payload_raw.to_ascii_lowercase();
                    // 出站完整 TLS 明文响应：去掉 favicon/图片/字体等高置信度静态体（不丢 svg、不丢含 SQLi 线索的报文）。
                    if ev.direction != 1
                        && parse_http_response_status(&msg).is_some()
                        && should_drop_plaintext_http_static_response(&msg)
                        && detect_sqli_keyword(&payload_lc).is_none()
                    {
                        continue;
                    }

                    let mut ae = base_event(
                        7,
                        now_ms,
                        agent_local_ip.as_deref(),
                        ev.uid,
                        ev.tgid,
                        ev.pid,
                        comm.clone(),
                    );
                    ae.tls_direction = Some(if ev.direction == 1 {
                        "ssl_read".to_string()
                    } else {
                        "ssl_write".to_string()
                    });
                    ae.tls_payload_trunc = Some(sanitize_text_1024(&payload_raw));
                    if let Some(resolver) = tls_flow_resolver.as_mut() {
                        let hint = tls_flow::hint_local_port_from_http(&payload_raw);
                        let mut fd = ev.fd;
                        if fd < 0 {
                            if let Some(map) = tls_ssl_fd_map.as_mut() {
                                let key = tls_flow::TlsFdKeyPod {
                                    tgid: ev.tgid,
                                    ssl_ptr: ev.ssl_ptr,
                                };
                                if let Ok(stored) = map.get(&key, 0) {
                                    fd = stored;
                                }
                            }
                        }
                        resolver.apply_to_event(
                            &mut ae,
                            ev.tgid,
                            ev.pid,
                            ev.ssl_ptr,
                            fd,
                            ev.direction,
                            hint,
                        );
                    } else {
                        ae.flow_correlation_key = Some(format!("ssl:{:x}", ev.ssl_ptr));
                    }

                    // Fill HTTP semantic fields if possible (so server can index/query easily).
                    let threat = detect_sqli_keyword(&payload_lc);
                    ae.tls_threat = threat;

                    if let Some((method, url, host, cookie, body_trunc)) =
                        parse_http_request_details(&msg)
                    {
                        // Reuse the same static ignore rules as HTTP L7 sniffer (if available).
                        let drop = if let Some(rt) = http_l7_runtime.as_ref() {
                            rt.read()
                                .map(|g| g.should_drop_request_url(&method, &url))
                                .unwrap_or(false)
                        } else {
                            false
                        };
                        if drop {
                            continue;
                        }

                        ae.http_method = Some(method);
                        ae.http_url = Some(url);
                        ae.http_body_trunc = Some(body_trunc);
                        ae.http_host = host;
                        ae.http_cookie_trunc = cookie;
                    } else if let Some(status) = parse_http_response_status(&msg) {
                        ae.http_status = Some(status);
                        // keep a light body trunc for response visibility
                        if let Some(idx) = payload_raw.find("\r\n\r\n") {
                            ae.http_body_trunc = Some(sanitize_text_200(&payload_raw[idx + 4..]));
                        }
                    }

                    if !collect_policy::should_emit_tls_event(
                        cfg.collect_mode,
                        cfg.tls_emit_incomplete_chunks,
                        true,
                        ae.http_method.as_deref(),
                        ae.http_url.as_deref(),
                        ae.http_status,
                        ae.tls_threat.as_deref(),
                    ) {
                        continue;
                    }

                    batcher.push(ae);
                    emitted = true;
                }

                // Fallback: incomplete TLS chunks (high noise; disabled in balanced/security).
                if !emitted && cfg.tls_emit_incomplete_chunks {
                    let chunk_raw = String::from_utf8_lossy(&ev.data[..n]).to_string();
                    let chunk_lc = chunk_raw.to_ascii_lowercase();
                    let looks_http_req = chunk_lc.starts_with("get ")
                        || chunk_lc.starts_with("post ")
                        || chunk_lc.starts_with("put ")
                        || chunk_lc.starts_with("delete ")
                        || chunk_lc.starts_with("head ")
                        || chunk_lc.starts_with("options ")
                        || chunk_lc.starts_with("patch ");
                    let looks_http_resp = chunk_lc.starts_with("http/");
                    let looks_h2_preface = chunk_raw.starts_with("PRI * HTTP/2.0");
                    if looks_http_req || looks_http_resp || looks_h2_preface {
                        if payload_hits_target_port(&chunk_raw, cfg.tls_target_port) {
                            if looks_http_resp
                                && ev.direction != 1
                                && should_drop_plaintext_http_static_response(&ev.data[..n])
                                && detect_sqli_keyword(&chunk_lc).is_none()
                            {
                                continue;
                            }

                            if looks_http_req {
                                if let Some((ref method, ref url, _, _, _)) =
                                    parse_http_request_details(&ev.data[..n])
                                {
                                    let drop_req = if let Some(rt) = http_l7_runtime.as_ref() {
                                        rt.read()
                                            .map(|g| g.should_drop_request_url(method, url))
                                            .unwrap_or(false)
                                    } else {
                                        false
                                    };
                                    if drop_req {
                                        continue;
                                    }
                                }
                            }

                            let mut ae = base_event(
                                7,
                                now_ms,
                                agent_local_ip.as_deref(),
                                ev.uid,
                                ev.tgid,
                                ev.pid,
                                comm.clone(),
                            );
                            ae.tls_direction = Some(if ev.direction == 1 {
                                "ssl_read".to_string()
                            } else {
                                "ssl_write".to_string()
                            });
                            ae.tls_payload_trunc = Some(sanitize_text_1024(&chunk_raw));
                            if let Some(resolver) = tls_flow_resolver.as_mut() {
                                let hint = tls_flow::hint_local_port_from_http(&chunk_raw);
                                let mut fd = ev.fd;
                                if fd < 0 {
                                    if let Some(map) = tls_ssl_fd_map.as_mut() {
                                        let key = tls_flow::TlsFdKeyPod {
                                            tgid: ev.tgid,
                                            ssl_ptr: ev.ssl_ptr,
                                        };
                                        if let Ok(stored) = map.get(&key, 0) {
                                            fd = stored;
                                        }
                                    }
                                }
                                resolver.apply_to_event(
                                    &mut ae,
                                    ev.tgid,
                                    ev.pid,
                                    ev.ssl_ptr,
                                    fd,
                                    ev.direction,
                                    hint,
                                );
                            } else {
                                ae.flow_correlation_key = Some(format!("ssl:{:x}", ev.ssl_ptr));
                            }
                            ae.tls_threat = detect_sqli_keyword(&chunk_lc);

                            if looks_http_req {
                                if let Some((method, url, host, cookie, body_trunc)) =
                                    parse_http_request_details(&ev.data[..n])
                                {
                                    ae.http_method = Some(method);
                                    ae.http_url = Some(url);
                                    ae.http_body_trunc = Some(body_trunc);
                                    ae.http_host = host;
                                    ae.http_cookie_trunc = cookie;
                                }
                            } else if looks_http_resp {
                                if let Some(status) = parse_http_response_status(&ev.data[..n]) {
                                    ae.http_status = Some(status);
                                }
                            }
                            batcher.push(ae);
                        }
                    }
                }
            }
        }

        // read flow events (fast)
        if let Some(ringbuf_flow) = ringbuf_flow.as_mut() {
            while let Some(item) = ringbuf_flow.next() {
                if item.len() < core::mem::size_of::<FlowEvent>() {
                    continue;
                }
                let ptr = item.as_ptr() as *const FlowEvent;
                // SAFETY: kernel wrote a C struct into the ringbuf; we only read it.
                let ev = unsafe { core::ptr::read_unaligned(ptr) };

                let s_ip = be_u32_to_ipv4_str(ev.src_ip);
                let d_ip = be_u32_to_ipv4_str(ev.dst_ip);
                if !collect_policy::should_emit_flow_syn(
                    &s_ip,
                    ev.dst_port,
                    cfg.flow_syn_dedup_window_ms,
                    now_ms,
                    &mut flow_syn_dedup,
                ) {
                    continue;
                }
                let flow_key =
                    tls_flow::tcp_flow_correlation_key(&s_ip, ev.src_port, &d_ip, ev.dst_port);

                let mut ae = base_event(
                    2,
                    now_ms,
                    agent_local_ip.as_deref(),
                    0,
                    0,
                    0,
                    "xdp".to_string(),
                );
                ae.flow_correlation_key = Some(flow_key);
                ae.flow_src_ip = Some(s_ip);
                ae.flow_dst_ip = Some(d_ip);
                ae.flow_src_port = Some(ev.src_port);
                ae.flow_dst_port = Some(ev.dst_port);
                ae.flow_proto = Some(ev.proto);
                ae.flow_tcp_flags = Some(ev.tcp_flags);
                ae.flow_direction = Some(ev.direction);
                ae.flow_is_sensitive_port = Some(ev.is_sensitive_port != 0);
                ae.flow_payload_len = Some(ev.payload_len);
                batcher.push(ae);
            }
        }

        // userspace HTTP L7 events (URL + body trunc)
        if let Some(rx) = http_l7_rx.as_ref() {
            while let Ok(ev) = rx.try_recv() {
                let window_ms = cfg.http_l7_dedup_window_ms;
                if window_ms > 0 {
                    let dedup_tag = if ev.is_response {
                        format!("RESP:{}", ev.http_status.unwrap_or(0))
                    } else {
                        format!(
                            "REQ:{}:{}|{}",
                            ev.method,
                            ev.url,
                            ev.http_host.as_deref().unwrap_or("")
                        )
                    };
                    let key = (
                        ev.src_ip.clone(),
                        ev.dst_ip.clone(),
                        ev.src_port,
                        ev.dst_port,
                        dedup_tag,
                    );
                    if let Some(&last) = http_dedup.get(&key) {
                        if now_ms.saturating_sub(last) < window_ms {
                            continue;
                        }
                    }
                    http_dedup.insert(key, now_ms);
                }

                if ev.is_response {
                    if let Some(st) = ev.http_status {
                        if !collect_policy::should_emit_http_response(
                            st,
                            cfg.http_l7_capture_response,
                            cfg.http_l7_response_min_status,
                        ) {
                            continue;
                        }
                    } else if !cfg.http_l7_capture_response {
                        continue;
                    }
                }

                let flow_key = if ev.is_response {
                    // 出站响应：包内 src=服务端，dst=客户端 → 规范化为 客户端->服务端
                    tls_flow::tcp_flow_correlation_key(&ev.dst_ip, ev.dst_port, &ev.src_ip, ev.src_port)
                } else {
                    tls_flow::tcp_flow_correlation_key(&ev.src_ip, ev.src_port, &ev.dst_ip, ev.dst_port)
                };

                let mut ae = base_event(
                    3,
                    now_ms,
                    agent_local_ip.as_deref(),
                    0,
                    0,
                    0,
                    "http_l7".to_string(),
                );
                ae.flow_correlation_key = Some(flow_key);
                ae.flow_src_ip = Some(ev.src_ip);
                ae.flow_dst_ip = Some(ev.dst_ip);
                ae.flow_src_port = Some(ev.src_port);
                ae.flow_dst_port = Some(ev.dst_port);
                ae.flow_proto = Some(6);
                ae.flow_direction = Some(if ev.is_response { 2 } else { 1 });
                ae.flow_is_sensitive_port = Some(true);
                ae.http_trunc_len = Some(200);
                ae.http_method = if ev.is_response {
                    None
                } else {
                    Some(ev.method)
                };
                ae.http_url = if ev.is_response {
                    None
                } else {
                    Some(ev.url)
                };
                ae.http_body_trunc = Some(ev.body_trunc);
                ae.http_host = ev.http_host;
                ae.http_cookie_trunc = ev.http_cookie_trunc;
                ae.http_status = ev.http_status;
                batcher.push(ae);
            }
        }

        if let Some(fw_rx) = file_watch_rx.as_ref() {
            while let Ok(ev) = fw_rx.try_recv() {
                let mut ae = base_event(
                    6,
                    now_ms,
                    agent_local_ip.as_deref(),
                    0,
                    0,
                    0,
                    "file_watch".to_string(),
                );
                ae.file_path = Some(ev.path);
                ae.file_op = Some(ev.op);
                batcher.push(ae);
            }
        }

        // 2) flush trigger: size/time/max_events
        if batcher.should_flush() {
            if let Some(batch) = batcher.take_batch() {
                pending_bytes = pending_bytes.saturating_add(
                    serde_json::to_vec(&batch)
                        .map(|b| b.len())
                        .unwrap_or(0),
                );
                pending.push_back(batch);
            }
        }

        // 3) attempt send (at-least-once); on failure -> spool
        let mut sent_batches = 0usize;
        while let Some(batch) = pending.pop_front() {
            if sent_batches >= max_send_batches_per_iter {
                pending.push_front(batch);
                break;
            }

            let envelope = IngestEnvelope {
                agent_version: agent_version.clone(),
                schema_version,
                host_id: Some(cfg.host_id.clone()),
                agent_stats: Some(AgentStats {
                    pending_batches: pending.len(),
                    pending_bytes,
                    spool_pending_files: Some(spool.pending_file_count()),
                }),
                events: batch,
            };
            let body = serde_json::to_vec(&envelope).unwrap_or_default();
            pending_bytes = pending_bytes.saturating_sub(body.len());

            match send_envelope(&client, &cfg.ingest_url, &envelope).await {
                Ok(()) => {}
                Err(err) => {
                    eprintln!("send failed: {err}; spooling");
                    let _ = spool.enqueue(&body);
                }
            }

            // backpressure: if too much queued in memory, spill oldest to disk
            if pending_bytes > mem_queue_max {
                if let Some(old) = pending.pop_front() {
                    let old_env = IngestEnvelope {
                        agent_version: agent_version.clone(),
                        schema_version,
                        host_id: Some(cfg.host_id.clone()),
                        agent_stats: Some(AgentStats {
                            pending_batches: pending.len(),
                            pending_bytes,
                            spool_pending_files: Some(spool.pending_file_count()),
                        }),
                        events: old,
                    };
                    let bytes = serde_json::to_vec(&old_env).unwrap_or_default();
                    pending_bytes = pending_bytes.saturating_sub(bytes.len());
                    let _ = spool.enqueue(&bytes);
                }
            }

            sent_batches += 1;
        }

        // 4) periodically drain spool (if network is back)
        if last_spool_drain.elapsed() >= Duration::from_secs(spool_drain_interval_secs) {
            let _ = drain_spool(&client, &cfg.ingest_url, &spool).await;
            last_spool_drain = std::time::Instant::now();
        }

        // idle: no new behavior => no send (batcher empty => no flush)
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

