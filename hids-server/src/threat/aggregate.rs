//! Short-window SYN counting per (host, src, dst_port) for coarse scan detection.

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;

/// Tracks SYN (`flow_tcp_flags == 2`) counts in fixed time buckets.
pub struct SynBurstTracker {
    inner: DashMap<String, (u64, u32)>,
    /// Bucket width in milliseconds (from config: `window_sec * 1000`).
    window_ms: u64,
    threshold: u32,
}

impl SynBurstTracker {
    pub fn new(window_sec: u64, threshold: u32) -> Self {
        let window_ms = window_sec.saturating_mul(1000).max(1);
        Self {
            inner: DashMap::new(),
            window_ms,
            threshold,
        }
    }

    /// Increments SYN count for the current bucket. Returns `true` when the count
    /// **first reaches** `threshold` in that bucket (one signal per burst per key).
    pub fn observe_syn(&self, host_key: &str, src_ip: &str, dst_port: i64, ts_ms: u64) -> bool {
        let bucket = ts_ms / self.window_ms;
        let key = format!("{host_key}|{src_ip}|{dst_port}");

        match self.inner.entry(key) {
            Entry::Occupied(mut o) => {
                let e = o.get_mut();
                if e.0 != bucket {
                    e.0 = bucket;
                    e.1 = 1;
                    return self.threshold == 1;
                }
                e.1 = e.1.saturating_add(1);
                e.1 == self.threshold
            }
            Entry::Vacant(v) => {
                v.insert((bucket, 1));
                self.threshold == 1
            }
        }
    }
}
