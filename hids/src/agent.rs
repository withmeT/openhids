use std::{
    collections::{HashMap, HashSet, VecDeque},
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
    config::Config,
    events::{AgentEvent, IngestEnvelope},
    features::file_change,
    http_client::drain_spool,
    spool::Spool,
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
    uid: u32,
    tgid: u32,
    pid: u32,
    comm: impl Into<String>,
) -> AgentEvent {
    AgentEvent {
        event_kind,
        ts_ms,
        uid,
        tgid,
        pid,
        comm: comm.into(),
        line: None,
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

fn payload_hits_target_port(payload: &str, port: u16) -> bool {
    let token = format!(":{port}");
    payload.contains(&token)
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
    let mut out = String::with_capacity(200);
    for ch in s.chars() {
        if out.len() >= 200 {
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

/// 用户态 HTTP L7 嗅探线程与热重载共享的运行时参数（端口集合、静态路径过滤）。
#[derive(Debug, Clone)]
struct HttpL7Runtime {
    pub http_port_set: HashSet<u16>,
    pub ignore_path_prefixes: Vec<String>,
    pub ignore_path_suffixes: Vec<String>,
    pub capture_response: bool,
}

impl HttpL7Runtime {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            http_port_set: cfg.http_l7_ports.iter().copied().collect(),
            ignore_path_prefixes: cfg.http_l7_ignore_path_prefixes.clone(),
            ignore_path_suffixes: cfg.http_l7_ignore_path_suffixes.clone(),
            capture_response: cfg.http_l7_capture_response,
        }
    }

    /// 若应丢弃该 URL（静态资源等），返回 true。
    pub fn should_drop_url(&self, url: &str) -> bool {
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

/// 与 XDP flow（入站 SYN）及 HTTP 请求对齐的关联键：客户端 -> 服务端。
fn tcp_flow_correlation_key(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> String {
    format!("tcp:{}:{}->{}:{}", src_ip, src_port, dst_ip, dst_port)
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
                    if rt.should_drop_url(&url) {
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
                let text = String::from_utf8_lossy(payload);
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
        let text = res.text().await.unwrap_or_default();
        anyhow::bail!("http status={status} body={text}");
    }
    Ok(())
}

pub async fn run() -> Result<(), anyhow::Error> {
    let mut cfg = Config::load()?;

    const AGENT_VERSION: &str = env!("HIDS_GIT_SHA");
    let schema_version: u32 = env!("HIDS_SCHEMA_VERSION")
        .parse()
        .unwrap_or(1);
    let agent_version: String = AGENT_VERSION.to_string();

    println!(
        "hids agent start: version={} schema_version={}",
        AGENT_VERSION, schema_version
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
    if cfg.tls_monitor_enabled {
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
                cfg.tls_target_comm = new_cfg.tls_target_comm.clone();
                cfg.tls_target_port = new_cfg.tls_target_port;

                cfg.host_id = new_cfg.host_id;

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
            last_http_dedup_prune = Instant::now();
        }

        // 1) read events (fast)
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

            let mut ae = base_event(0, ts_ms, ev.uid, ev.tgid, ev.pid, comm);
            ae.line = Some(line);
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
                let mut ae = base_event(4, now_ms, ev.uid, ev.tgid, ev.pid, comm);
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
                let mut ae = base_event(5, now_ms, ev.uid, ev.tgid, ev.pid, comm);
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
                let payload_raw = String::from_utf8_lossy(&ev.data[..n]).to_string();
                if !payload_hits_target_port(&payload_raw, cfg.tls_target_port) {
                    continue;
                }

                let payload_lc = payload_raw.to_ascii_lowercase();
                let is_post = payload_lc.contains("post ");
                let threat = detect_sqli_keyword(&payload_lc);
                if !is_post && threat.is_none() {
                    continue;
                }

                let mut ae = base_event(7, now_ms, ev.uid, ev.tgid, ev.pid, comm);
                ae.tls_direction = Some(if ev.direction == 1 {
                    "ssl_read".to_string()
                } else {
                    "ssl_write".to_string()
                });
                ae.tls_payload_trunc = Some(sanitize_text_200(&payload_raw));
                ae.tls_threat = threat;
                batcher.push(ae);
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
                let flow_key = tcp_flow_correlation_key(&s_ip, ev.src_port, &d_ip, ev.dst_port);

                let mut ae = base_event(2, now_ms, 0, 0, 0, "xdp".to_string());
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

                let flow_key = if ev.is_response {
                    // 出站响应：包内 src=服务端，dst=客户端 → 规范化为 客户端->服务端
                    tcp_flow_correlation_key(&ev.dst_ip, ev.dst_port, &ev.src_ip, ev.src_port)
                } else {
                    tcp_flow_correlation_key(&ev.src_ip, ev.src_port, &ev.dst_ip, ev.dst_port)
                };

                let mut ae = base_event(3, now_ms, 0, 0, 0, "http_l7".to_string());
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
                let mut ae = base_event(6, now_ms, 0, 0, 0, "file_watch".to_string());
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

