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

    pub fn push(&mut self, ev: AgentEvent) {
        if self.started_at.is_none() {
            self.started_at = Some(std::time::Instant::now());
        }
        // rough estimate; real size determined at serialization time
        self.current_bytes_est = self
            .current_bytes_est
            .saturating_add(ev.comm.len() + ev.line.len() + 64);
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

