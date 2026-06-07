//! In-process counters for `/stats` and operations.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct IngestMetrics {
    pub accepted: AtomicU64,
    pub dropped_plain_syn_flow: AtomicU64,
    pub rejected_queue_full: AtomicU64,
    pub rejected_unauthorized: AtomicU64,
    pub rejected_bad_request: AtomicU64,
    pub es_flushed_docs: AtomicU64,
    pub es_alerts_flushed_docs: AtomicU64,
    pub es_bulk_requests: AtomicU64,
    pub es_bulk_item_errors: AtomicU64,
    pub es_bulk_failures: AtomicU64,
    pub es_spooled_batches: AtomicU64,
}

impl IngestMetrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            dropped_plain_syn_flow: self.dropped_plain_syn_flow.load(Ordering::Relaxed),
            rejected_queue_full: self.rejected_queue_full.load(Ordering::Relaxed),
            rejected_unauthorized: self.rejected_unauthorized.load(Ordering::Relaxed),
            rejected_bad_request: self.rejected_bad_request.load(Ordering::Relaxed),
            es_flushed_docs: self.es_flushed_docs.load(Ordering::Relaxed),
            es_alerts_flushed_docs: self.es_alerts_flushed_docs.load(Ordering::Relaxed),
            es_bulk_requests: self.es_bulk_requests.load(Ordering::Relaxed),
            es_bulk_item_errors: self.es_bulk_item_errors.load(Ordering::Relaxed),
            es_bulk_failures: self.es_bulk_failures.load(Ordering::Relaxed),
            es_spooled_batches: self.es_spooled_batches.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct MetricsSnapshot {
    pub accepted: u64,
    pub dropped_plain_syn_flow: u64,
    pub rejected_queue_full: u64,
    pub rejected_unauthorized: u64,
    pub rejected_bad_request: u64,
    pub es_flushed_docs: u64,
    pub es_alerts_flushed_docs: u64,
    pub es_bulk_requests: u64,
    pub es_bulk_item_errors: u64,
    pub es_bulk_failures: u64,
    pub es_spooled_batches: u64,
}
