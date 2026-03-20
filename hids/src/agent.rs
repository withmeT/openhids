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
    events::AgentEvent,
    http_client::drain_spool,
    spool::Spool,
    utils::cstr_from_fixed,
};

use hids_common::CommandEvent;

async fn send_batch(
    client: &reqwest::Client,
    url: &str,
    batch: &[AgentEvent],
) -> anyhow::Result<()> {
    let res = client
        .post(url)
        .json(batch)
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
    let ingest_url =
        std::env::var("HIDS_INGEST_URL").unwrap_or_else(|_| "http://127.0.0.1:8000/ingest".to_string());

    let flush_bytes = std::env::var("HIDS_FLUSH_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1 * 1024 * 1024);
    let flush_interval_ms = std::env::var("HIDS_FLUSH_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2_000);
    let flush_max_events = std::env::var("HIDS_FLUSH_MAX_EVENTS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2000);

    // disk spool budget: <= 100MB as requested
    let spool = Spool::new("./spool", 100 * 1024 * 1024);

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

    let events_map = bpf.map_mut("EVENTS").context("map EVENTS not found")?;
    let mut ringbuf = RingBuf::try_from(events_map)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build http client")?;

    let mut batcher = Batcher::new(
        flush_bytes,
        Duration::from_millis(flush_interval_ms),
        flush_max_events,
    );

    // pending serialized batches kept in memory before spilling
    let mem_queue_max: usize = 10 * 1024 * 1024;
    let mut pending: VecDeque<Vec<AgentEvent>> = VecDeque::new();
    let mut pending_bytes: usize = 0;

    let max_send_batches_per_iter: usize = std::env::var("HIDS_MAX_SEND_BATCHES_PER_ITER")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2);

    let mut last_spool_drain = std::time::Instant::now();
    loop {
        // 1) read events (fast)
        while let Some(item) = ringbuf.next() {
            if item.len() < core::mem::size_of::<CommandEvent>() {
                continue;
            }
            let ptr = item.as_ptr() as *const CommandEvent;
            // SAFETY: kernel wrote a C struct into the ringbuf; we only read it.
            let ev = unsafe { core::ptr::read_unaligned(ptr) };
            let comm = cstr_from_fixed(&ev.comm);
            let line = cstr_from_fixed(&ev.line);
            let ts_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            batcher.push(AgentEvent {
                ts_ms,
                uid: ev.uid,
                tgid: ev.tgid,
                pid: ev.pid,
                comm,
                line,
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

            let body = serde_json::to_vec(&batch).unwrap_or_default();
            pending_bytes = pending_bytes.saturating_sub(body.len());

            match send_batch(&client, &ingest_url, &batch).await {
                Ok(()) => {}
                Err(err) => {
                    eprintln!("send failed: {err}; spooling");
                    let _ = spool.enqueue(&body);
                }
            }

            // backpressure: if too much queued in memory, spill oldest to disk
            if pending_bytes > mem_queue_max {
                if let Some(old) = pending.pop_front() {
                    let bytes = serde_json::to_vec(&old).unwrap_or_default();
                    pending_bytes = pending_bytes.saturating_sub(bytes.len());
                    let _ = spool.enqueue(&bytes);
                }
            }

            sent_batches += 1;
        }

        // 4) periodically drain spool (if network is back)
        if last_spool_drain.elapsed() >= Duration::from_secs(2) {
            let _ = drain_spool(&client, &ingest_url, &spool).await;
            last_spool_drain = std::time::Instant::now();
        }

        // idle: no new behavior => no send (batcher empty => no flush)
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

