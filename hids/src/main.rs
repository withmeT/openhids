use std::{
    collections::VecDeque,
    convert::TryInto as _,
    fs,
    io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::RingBuf;
use aya::programs::UProbe;
use serde::{Deserialize, Serialize};

use hids_common::CommandEvent;

fn cstr_from_fixed(buf: &[u8]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentEvent {
    ts_ms: u64,
    uid: u32,
    tgid: u32,
    pid: u32,
    comm: String,
    line: String,
}

struct Spool {
    dir: PathBuf,
    max_bytes: u64,
}

impl Spool {
    fn new(dir: impl Into<PathBuf>, max_bytes: u64) -> Self {
        Self {
            dir: dir.into(),
            max_bytes,
        }
    }

    fn ensure_dir(&self) -> io::Result<()> {
        fs::create_dir_all(&self.dir)
    }

    fn enqueue(&self, bytes: &[u8]) -> io::Result<PathBuf> {
        self.ensure_dir()?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let pid = std::process::id();
        let path = self.dir.join(format!("{ts}-{pid}.json"));
        fs::write(&path, bytes)?;
        self.enforce_budget()?;
        Ok(path)
    }

    fn list_files_oldest_first(&self) -> io::Result<Vec<PathBuf>> {
        let mut items = Vec::new();
        if !self.dir.exists() {
            return Ok(items);
        }
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let meta = entry.metadata().ok();
            let mtime = meta
                .and_then(|m| m.modified().ok())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            items.push((mtime, path));
        }
        items.sort_by_key(|(t, _)| *t);
        Ok(items.into_iter().map(|(_, p)| p).collect())
    }

    fn total_bytes(&self) -> io::Result<u64> {
        let mut sum = 0u64;
        if !self.dir.exists() {
            return Ok(0);
        }
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                sum = sum.saturating_add(meta.len());
            }
        }
        Ok(sum)
    }

    fn enforce_budget(&self) -> io::Result<()> {
        let mut total = self.total_bytes()?;
        if total <= self.max_bytes {
            return Ok(());
        }
        let files = self.list_files_oldest_first()?;
        for f in files {
            if total <= self.max_bytes {
                break;
            }
            if let Ok(meta) = fs::metadata(&f) {
                let _ = fs::remove_file(&f);
                total = total.saturating_sub(meta.len());
            } else {
                let _ = fs::remove_file(&f);
            }
        }
        Ok(())
    }
}

struct Batcher {
    flush_bytes: usize,
    flush_interval: Duration,
    flush_max_events: usize,
    current: Vec<AgentEvent>,
    current_bytes_est: usize,
    started_at: Option<std::time::Instant>,
}

impl Batcher {
    fn new(flush_bytes: usize, flush_interval: Duration, flush_max_events: usize) -> Self {
        Self {
            flush_bytes,
            flush_interval,
            flush_max_events,
            current: Vec::new(),
            current_bytes_est: 0,
            started_at: None,
        }
    }

    fn push(&mut self, ev: AgentEvent) {
        if self.started_at.is_none() {
            self.started_at = Some(std::time::Instant::now());
        }
        // rough estimate; real size determined at serialization time
        self.current_bytes_est = self
            .current_bytes_est
            .saturating_add(ev.comm.len() + ev.line.len() + 64);
        self.current.push(ev);
    }

    fn should_flush(&self) -> bool {
        if self.current.is_empty() {
            return false;
        }
        if self.current.len() >= self.flush_max_events {
            return true;
        }
        if self.current_bytes_est >= self.flush_bytes {
            return true;
        }
        if let Some(t0) = self.started_at {
            if t0.elapsed() >= self.flush_interval {
                return true;
            }
        }
        false
    }

    fn take_batch(&mut self) -> Option<Vec<AgentEvent>> {
        if self.current.is_empty() {
            return None;
        }
        self.current_bytes_est = 0;
        self.started_at = None;
        Some(std::mem::take(&mut self.current))
    }
}

async fn send_batch(client: &reqwest::Client, url: &str, batch: &[AgentEvent]) -> anyhow::Result<()> {
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

async fn drain_spool(client: &reqwest::Client, url: &str, spool: &Spool) -> anyhow::Result<()> {
    let files = spool.list_files_oldest_first().unwrap_or_default();
    for f in files {
        let bytes = match fs::read(&f) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let batch: Vec<AgentEvent> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                let _ = fs::remove_file(&f);
                continue;
            }
        };
        if send_batch(client, url, &batch).await.is_ok() {
            let _ = fs::remove_file(&f);
        } else {
            // network/server still bad; stop here
            break;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let ingest_url = std::env::var("HIDS_INGEST_URL").unwrap_or_else(|_| "http://127.0.0.1:8000/ingest".to_string());
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

    let mut batcher = Batcher::new(flush_bytes, Duration::from_millis(flush_interval_ms), flush_max_events);

    // pending serialized batches kept in memory before spilling
    let mem_queue_max: usize = 10 * 1024 * 1024;
    let mut pending: VecDeque<Vec<AgentEvent>> = VecDeque::new();
    let mut pending_bytes: usize = 0;

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
                pending_bytes = pending_bytes.saturating_add(serde_json::to_vec(&batch).map(|b| b.len()).unwrap_or(0));
                pending.push_back(batch);
            }
        }

        // 3) attempt send (at-least-once); on failure -> spool
        while let Some(batch) = pending.pop_front() {
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