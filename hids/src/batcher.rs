use crate::events::AgentEvent;

use std::time::Duration;

/// "双阈值批量"：达到 size/time/max_events 任一条件就 flush。
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
            current: Vec::with_capacity(256),
            current_bytes_est: 0,
            started_at: None,
        }
    }

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
        // 更精准的字节估算：覆盖所有字符串字段 + JSON 结构开销
        let est = estimate_event_bytes(&ev);
        self.current_bytes_est = self.current_bytes_est.saturating_add(est);
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
        // 取出数据，用预分配容量的空 Vec 替换，避免下次 push 时重新分配
        let cap = self.current.capacity().min(512);
        let taken = std::mem::replace(&mut self.current, Vec::with_capacity(cap));
        Some(taken)
    }

    /// 当前批次事件数
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.current.len()
    }

    /// 当前批次估算字节数
    #[allow(dead_code)]
    pub fn estimated_bytes(&self) -> usize {
        self.current_bytes_est
    }

    /// 距下次超时刷新剩余时间（用于自适应 sleep）
    #[allow(dead_code)]
    pub fn time_until_flush(&self) -> Option<Duration> {
        let t0 = self.started_at?;
        let elapsed = t0.elapsed();
        if elapsed >= self.flush_interval {
            Some(Duration::ZERO)
        } else {
            Some(self.flush_interval - elapsed)
        }
    }
}

/// 估算单个 AgentEvent 序列化后的字节数（覆盖全部字段）。
///
/// 策略：每个字段取实际字符串长度，加上 JSON key 名称开销 + 引号/逗号等结构，
/// 再加固定开销。相比原来只统计 5 个字段，能更准确触发 flush_bytes 阈值。
#[inline]
pub fn estimate_event_bytes(ev: &AgentEvent) -> usize {
    // 固定字段开销（event_kind, ts_ms, uid, tgid, pid + JSON 结构）
    let mut est: usize = 160;

    macro_rules! add_opt_str {
        ($field:expr, $key_len:expr) => {
            if let Some(ref s) = $field {
                est += $key_len + s.len() + 4; // key + quotes + colon + comma
            }
        };
    }

    est += ev.comm.len() + 10;

    add_opt_str!(ev.local_ip, 10);
    add_opt_str!(ev.line, 6);
    add_opt_str!(ev.ssh_client_ip, 15);
    add_opt_str!(ev.flow_correlation_key, 22);
    add_opt_str!(ev.flow_src_ip, 13);
    add_opt_str!(ev.flow_dst_ip, 13);
    add_opt_str!(ev.http_payload_trunc, 20);
    add_opt_str!(ev.http_method, 13);
    add_opt_str!(ev.http_url, 10);
    add_opt_str!(ev.http_body_trunc, 16);
    add_opt_str!(ev.http_host, 11);
    add_opt_str!(ev.http_cookie_trunc, 19);
    add_opt_str!(ev.exec_path, 11);
    add_opt_str!(ev.file_path, 11);
    add_opt_str!(ev.file_op, 9);
    add_opt_str!(ev.tls_direction, 15);
    add_opt_str!(ev.tls_payload_trunc, 19);
    add_opt_str!(ev.tls_threat, 12);

    // 数值型可选字段（各约 20 字节）
    let num_fields = [
        ev.exit_code.is_some(),
        ev.success.is_some(),
        ev.flow_src_port.is_some(),
        ev.flow_dst_port.is_some(),
        ev.flow_proto.is_some(),
        ev.flow_tcp_flags.is_some(),
        ev.flow_direction.is_some(),
        ev.flow_is_sensitive_port.is_some(),
        ev.flow_payload_len.is_some(),
        ev.http_trunc_len.is_some(),
        ev.http_status.is_some(),
    ];
    est += num_fields.iter().filter(|&&v| v).count() * 20;

    est
}
