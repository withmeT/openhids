//! Agent 侧运行时指标（原子计数器），用于观测性能瓶颈和背压状态。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Agent 运行时指标快照（可序列化为 JSON 上报）
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentMetricsSnapshot {
    /// 从启动到现在的运行秒数
    pub uptime_secs: u64,

    // ── 事件采集 ──
    /// 总采集事件数
    pub events_collected: u64,
    /// bash 命令行事件数
    pub events_bash: u64,
    /// exec 事件数
    pub events_exec: u64,
    /// exit 事件数
    pub events_exit: u64,
    /// XDP flow 事件数（去重前）
    pub events_flow_raw: u64,
    /// XDP flow 事件数（去重后）
    pub events_flow_emitted: u64,
    /// HTTP L7 事件数（去重前）
    pub events_http_raw: u64,
    /// HTTP L7 事件数（去重后发送）
    pub events_http_emitted: u64,
    /// TLS 明文事件数
    pub events_tls: u64,
    /// 文件变更事件数
    pub events_file: u64,

    // ── 上报 ──
    /// 成功发送的批次数
    pub batches_sent: u64,
    /// 发送失败的批次数（已落 spool）
    pub batches_failed: u64,
    /// spool 落盘的批次数
    pub batches_spooled: u64,
    /// spool 回放成功的批次数
    pub batches_replayed: u64,

    // ── 去重 ──
    /// HTTP 去重丢弃数
    pub http_dedup_dropped: u64,
    /// Flow SYN 去重丢弃数
    pub flow_dedup_dropped: u64,

    // ── 背压 ──
    /// 内存队列溢出被 spool 的批次数
    pub mem_overflow_spooled: u64,
    /// 当前内存队列待发批次数（快照时）
    pub pending_batches_now: u64,

    // ── SSH IP 解析 ──
    /// SSH 客户端 IP 缓存命中数
    pub ssh_cache_hits: u64,
    /// SSH 客户端 IP 缓存未命中数
    pub ssh_cache_misses: u64,
}

/// 全局 Agent 指标（原子计数器，零开销）
pub struct AgentMetrics {
    pub start_time: Instant,

    pub events_bash: AtomicU64,
    pub events_exec: AtomicU64,
    pub events_exit: AtomicU64,
    pub events_flow_raw: AtomicU64,
    pub events_flow_emitted: AtomicU64,
    pub events_http_raw: AtomicU64,
    pub events_http_emitted: AtomicU64,
    pub events_tls: AtomicU64,
    pub events_file: AtomicU64,

    pub batches_sent: AtomicU64,
    pub batches_failed: AtomicU64,
    pub batches_spooled: AtomicU64,
    pub batches_replayed: AtomicU64,

    pub http_dedup_dropped: AtomicU64,
    pub flow_dedup_dropped: AtomicU64,

    pub mem_overflow_spooled: AtomicU64,
    pub ssh_cache_hits: AtomicU64,
    pub ssh_cache_misses: AtomicU64,
}

impl Default for AgentMetrics {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            events_bash: AtomicU64::new(0),
            events_exec: AtomicU64::new(0),
            events_exit: AtomicU64::new(0),
            events_flow_raw: AtomicU64::new(0),
            events_flow_emitted: AtomicU64::new(0),
            events_http_raw: AtomicU64::new(0),
            events_http_emitted: AtomicU64::new(0),
            events_tls: AtomicU64::new(0),
            events_file: AtomicU64::new(0),
            batches_sent: AtomicU64::new(0),
            batches_failed: AtomicU64::new(0),
            batches_spooled: AtomicU64::new(0),
            batches_replayed: AtomicU64::new(0),
            http_dedup_dropped: AtomicU64::new(0),
            flow_dedup_dropped: AtomicU64::new(0),
            mem_overflow_spooled: AtomicU64::new(0),
            ssh_cache_hits: AtomicU64::new(0),
            ssh_cache_misses: AtomicU64::new(0),
        }
    }
}

impl AgentMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[inline]
    pub fn inc(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    #[allow(dead_code)]
    pub fn add(&self, counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self, pending_batches: usize) -> AgentMetricsSnapshot {
        let r = Ordering::Relaxed;
        let bash = self.events_bash.load(r);
        let exec = self.events_exec.load(r);
        let exit = self.events_exit.load(r);
        let flow_emitted = self.events_flow_emitted.load(r);
        let http_emitted = self.events_http_emitted.load(r);
        let tls = self.events_tls.load(r);
        let file = self.events_file.load(r);

        AgentMetricsSnapshot {
            uptime_secs: self.start_time.elapsed().as_secs(),
            events_collected: bash + exec + exit + flow_emitted + http_emitted + tls + file,
            events_bash: bash,
            events_exec: exec,
            events_exit: exit,
            events_flow_raw: self.events_flow_raw.load(r),
            events_flow_emitted: flow_emitted,
            events_http_raw: self.events_http_raw.load(r),
            events_http_emitted: http_emitted,
            events_tls: tls,
            events_file: file,
            batches_sent: self.batches_sent.load(r),
            batches_failed: self.batches_failed.load(r),
            batches_spooled: self.batches_spooled.load(r),
            batches_replayed: self.batches_replayed.load(r),
            http_dedup_dropped: self.http_dedup_dropped.load(r),
            flow_dedup_dropped: self.flow_dedup_dropped.load(r),
            mem_overflow_spooled: self.mem_overflow_spooled.load(r),
            pending_batches_now: pending_batches as u64,
            ssh_cache_hits: self.ssh_cache_hits.load(r),
            ssh_cache_misses: self.ssh_cache_misses.load(r),
        }
    }

    /// 每隔指定秒数打印一次指标摘要（轻量日志）
    pub fn log_summary(&self, pending_batches: usize) {
        let snap = self.snapshot(pending_batches);
        let r = Ordering::Relaxed;
        let total_http = self.events_http_raw.load(r);
        let total_flow = self.events_flow_raw.load(r);
        let http_drop_rate = if total_http > 0 {
            snap.http_dedup_dropped * 100 / total_http
        } else {
            0
        };
        let flow_drop_rate = if total_flow > 0 {
            snap.flow_dedup_dropped * 100 / total_flow
        } else {
            0
        };

        eprintln!(
            "[hids metrics] uptime={}s events={{bash={} exec={} exit={} flow={} http={} tls={} file={}}} \
             batches={{sent={} fail={} spool={}}} \
             dedup={{http_drop={}% flow_drop={}%}} \
             ssh_cache={{hit={} miss={}}} pending={}",
            snap.uptime_secs,
            snap.events_bash, snap.events_exec, snap.events_exit,
            snap.events_flow_emitted, snap.events_http_emitted,
            snap.events_tls, snap.events_file,
            snap.batches_sent, snap.batches_failed, snap.batches_spooled,
            http_drop_rate, flow_drop_rate,
            snap.ssh_cache_hits, snap.ssh_cache_misses,
            snap.pending_batches_now,
        );
    }
}
