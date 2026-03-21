use crate::events::AgentEvent;

use std::time::Duration;

/// “双阈值批量”：达到 size/time/max_events 任一条件就 flush。
pub struct Batcher {
    flush_bytes: usize,
    flush_interval: Duration,
    flush_max_events: usize,
    current: Vec<AgentEvent>,
    current_bytes_est: usize,
    started_at: Option<std::time::Instant>,
}

impl Batcher {
    pub fn new(flush_bytes: usize, flush_interval: Duration, flush_max_events: usize) -> Self {
        Self {
            flush_bytes,
            flush_interval,
            flush_max_events,
            current: Vec::new(),
            current_bytes_est: 0,
            started_at: None,
        }
    }

    /// 热更新批量阈值，不影响当前未 flush 的事件数组。
    pub fn update_params(
        &mut self,
        flush_bytes: usize,
        flush_interval: Duration,
        flush_max_events: usize,
    ) {
        self.flush_bytes = flush_bytes;
        self.flush_interval = flush_interval;
        self.flush_max_events = flush_max_events;
    }

    pub fn push(&mut self, ev: AgentEvent) {
        if self.started_at.is_none() {
            self.started_at = Some(std::time::Instant::now());
        }
        // rough estimate; real size determined at serialization time
        let line_len = ev.line.as_ref().map(|s| s.len()).unwrap_or(0);
        let http_len = ev.http_payload_trunc.as_ref().map(|s| s.len()).unwrap_or(0);
        let http_method_len = ev.http_method.as_ref().map(|s| s.len()).unwrap_or(0);
        let http_url_len = ev.http_url.as_ref().map(|s| s.len()).unwrap_or(0);
        let http_body_len = ev.http_body_trunc.as_ref().map(|s| s.len()).unwrap_or(0);
        self.current_bytes_est = self
            .current_bytes_est
            .saturating_add(
                ev.comm.len() + line_len + http_len + http_method_len + http_url_len + http_body_len + 128,
            );
        self.current.push(ev);
    }

    pub fn should_flush(&self) -> bool {
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

    pub fn take_batch(&mut self) -> Option<Vec<AgentEvent>> {
        if self.current.is_empty() {
            return None;
        }
        self.current_bytes_est = 0;
        self.started_at = None;
        Some(std::mem::take(&mut self.current))
    }
}

