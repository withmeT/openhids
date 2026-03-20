use std::{
    collections::VecDeque,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::RingBuf;
use aya::programs::UProbe;

use crate::{
    batcher::Batcher,
    config::Config,
    events::{AgentEvent, IngestEnvelope},
    http_client::drain_spool,
    spool::Spool,
    utils::cstr_from_fixed,
};

use hids_common::CommandEvent;

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
            });
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

