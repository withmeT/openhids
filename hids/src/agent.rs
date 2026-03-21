use std::{
    collections::VecDeque,
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::RingBuf;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{UProbe, Xdp, XdpFlags};
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
    http_client::drain_spool,
    spool::Spool,
    utils::cstr_from_fixed,
};

use hids_common::{CommandEvent, FlowEvent};

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
    method: String,
    url: String,
    body_trunc: String,
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

fn parse_http_l7(payload: &[u8]) -> Option<(String, String, String)> {
    let text = String::from_utf8_lossy(payload);
    let mut lines = text.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let url = parts.next().unwrap_or("/").to_string();

    // Basic method guard
    match method.as_str() {
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" => {}
        _ => return None,
    }

    let body = if let Some(idx) = text.find("\r\n\r\n") {
        &text[idx + 4..]
    } else {
        ""
    };
    Some((
        sanitize_text_200(&method),
        sanitize_text_200(&url),
        sanitize_text_200(body),
    ))
}

fn spawn_http_sniffer(
    iface_name: String,
    local_ips: Vec<String>,
    http_ports: Vec<u16>,
) -> mpsc::Receiver<HttpL7Event> {
    let (tx, rx) = mpsc::channel::<HttpL7Event>();
    std::thread::spawn(move || {
        let local_set: std::collections::HashSet<String> = local_ips.into_iter().collect();
        let http_port_set: std::collections::HashSet<u16> = http_ports.into_iter().collect();
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

            // inbound only
            if !local_set.contains(&dst_ip) {
                continue;
            }

            let Some(tcp) = TcpPacket::new(ip.payload()) else {
                continue;
            };
            let dst_port = tcp.get_destination();
            if !http_port_set.contains(&dst_port) {
                continue;
            }
            let payload = tcp.payload();
            if payload.is_empty() {
                continue;
            }
            let Some((method, url, body_trunc)) = parse_http_l7(payload) else {
                continue;
            };

            let _ = tx.send(HttpL7Event {
                src_ip,
                dst_ip,
                src_port: tcp.get_source(),
                dst_port,
                method,
                url,
                body_trunc,
            });
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

    // XDP flow collection (five tuple)
    let mut ringbuf_flow = None;
    let mut http_l7_rx: Option<mpsc::Receiver<HttpL7Event>> = None;
    if cfg.xdp_enabled {
        // 1) configure maps
        let skip_map_data = bpf.take_map("SKIP_IPS").context("map SKIP_IPS not found")?;
        let mut skip_map = AyaHashMap::<_, u32, u8>::try_from(skip_map_data)?;

        let local_ips_map_data = bpf.take_map("LOCAL_IPS").context("map LOCAL_IPS not found")?;
        let mut local_ips_map = AyaHashMap::<_, u32, u8>::try_from(local_ips_map_data)?;

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
        http_l7_rx = Some(spawn_http_sniffer(
            iface.clone(),
            detect_local_ipv4s(),
            cfg.http_l7_ports.clone(),
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

    loop {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // 0) hot reload config (best-effort)
        if last_cfg_reload.elapsed().as_secs() >= cfg.config_reload_interval_secs {
            if let Ok(new_cfg) = Config::load() {
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

                cfg.host_id = new_cfg.host_id;
                last_cfg_reload = std::time::Instant::now();
            }
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

            batcher.push(AgentEvent {
                event_kind: 0,
                ts_ms,
                uid: ev.uid,
                tgid: ev.tgid,
                pid: ev.pid,
                comm,
                line: Some(line),
                exit_code: None,
                success: None,
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
            });
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

                batcher.push(AgentEvent {
                    event_kind: 2,
                    ts_ms: now_ms,
                    uid: 0,
                    tgid: 0,
                    pid: 0,
                    comm: "xdp".to_string(),
                    line: None,
                    exit_code: None,
                    success: None,
                    flow_src_ip: Some(be_u32_to_ipv4_str(ev.src_ip)),
                    flow_dst_ip: Some(be_u32_to_ipv4_str(ev.dst_ip)),
                    flow_src_port: Some(ev.src_port),
                    flow_dst_port: Some(ev.dst_port),
                    flow_proto: Some(ev.proto),
                    flow_tcp_flags: Some(ev.tcp_flags),
                    flow_direction: Some(ev.direction),
                    flow_is_sensitive_port: Some(ev.is_sensitive_port != 0),
                    flow_payload_len: Some(ev.payload_len),
                    http_payload_trunc: None,
                    http_trunc_len: None,
                    http_method: None,
                    http_url: None,
                    http_body_trunc: None,
                });
            }
        }

        // userspace HTTP L7 events (URL + body trunc)
        if let Some(rx) = http_l7_rx.as_ref() {
            while let Ok(ev) = rx.try_recv() {
                batcher.push(AgentEvent {
                    event_kind: 3,
                    ts_ms: now_ms,
                    uid: 0,
                    tgid: 0,
                    pid: 0,
                    comm: "http_l7".to_string(),
                    line: None,
                    exit_code: None,
                    success: None,
                    flow_src_ip: Some(ev.src_ip),
                    flow_dst_ip: Some(ev.dst_ip),
                    flow_src_port: Some(ev.src_port),
                    flow_dst_port: Some(ev.dst_port),
                    flow_proto: Some(6),
                    flow_tcp_flags: None,
                    flow_direction: Some(1),
                    flow_is_sensitive_port: Some(true),
                    flow_payload_len: None,
                    http_payload_trunc: None,
                    http_trunc_len: Some(200),
                    http_method: Some(ev.method),
                    http_url: Some(ev.url),
                    http_body_trunc: Some(ev.body_trunc),
                });
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

