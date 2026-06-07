//! Elasticsearch `_bulk` writer (NDJSON, timed flush + size flush).

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use chrono::Utc;
use reqwest::Client;
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::{
    sync::mpsc,
    time::{sleep, Instant},
};
use tracing::{error, info, warn};

use crate::config::Config;
use crate::doc_id;
use crate::metrics::IngestMetrics;
use crate::models::AgentEvent;
use crate::spool;
use crate::threat;

#[derive(Debug, Deserialize)]
struct BulkResponse {
    errors: bool,
    #[serde(default)]
    items: Vec<serde_json::Value>,
}

pub struct EsBulkWriter {
    client: Client,
    base_url: String,
    index_base: String,
    alerts_index_base: String,
    alerts_enabled: bool,
    alerts_min_level: String,
    auth: Option<(String, String)>,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_base_ms: u64,
    daily_index: bool,
    document_id: bool,
    spool_dir: std::path::PathBuf,
    spool_enabled: bool,
    metrics: Arc<IngestMetrics>,
}

impl EsBulkWriter {
    pub fn new(cfg: &Config, metrics: Arc<IngestMetrics>) -> anyhow::Result<Self> {
        let client = Client::builder()
            .pool_max_idle_per_host(128)
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .context("failed to build reqwest client")?;
        let auth = match (&cfg.es_username, &cfg.es_password) {
            (Some(u), Some(p)) => Some((u.clone(), p.clone())),
            _ => None,
        };

        Ok(Self {
            client,
            base_url: cfg.es_url.trim_end_matches('/').to_string(),
            index_base: cfg.es_index.clone(),
            alerts_index_base: cfg.es_alerts_index.clone(),
            alerts_enabled: cfg.es_alerts_enabled,
            alerts_min_level: cfg.es_alerts_min_level.clone(),
            auth,
            batch_size: cfg.batch_size,
            flush_interval: Duration::from_millis(cfg.flush_ms),
            max_retries: cfg.es_max_retries,
            retry_base_ms: cfg.es_retry_base_ms,
            daily_index: cfg.es_daily_index,
            document_id: cfg.es_document_id,
            spool_dir: cfg.spool_dir.clone(),
            spool_enabled: cfg.spool_enabled,
            metrics,
        })
    }

    fn index_name(&self, base: &str) -> String {
        if self.daily_index {
            let day = Utc::now().format("%Y.%m.%d");
            format!("{base}-{day}")
        } else {
            base.to_string()
        }
    }

    pub async fn run(self, mut rx: mpsc::Receiver<AgentEvent>) -> anyhow::Result<()> {
        let mut buffer = Vec::with_capacity(self.batch_size);
        let mut next_flush = Instant::now() + self.flush_interval;

        loop {
            tokio::select! {
                maybe_doc = rx.recv() => {
                    match maybe_doc {
                        Some(doc) => {
                            buffer.push(doc);
                            if buffer.len() >= self.batch_size {
                                self.flush(&mut buffer).await;
                                next_flush = Instant::now() + self.flush_interval;
                            }
                        }
                        None => {
                            if !buffer.is_empty() {
                                self.flush(&mut buffer).await;
                            }
                            warn!("ingest channel closed, es writer stopping");
                            break;
                        }
                    }
                }
                _ = sleep_until(next_flush), if !buffer.is_empty() => {
                    self.flush(&mut buffer).await;
                    next_flush = Instant::now() + self.flush_interval;
                }
            }
        }

        Ok(())
    }

    async fn flush(&self, docs: &mut Vec<AgentEvent>) {
        if docs.is_empty() {
            return;
        }

        let index = self.index_name(&self.index_base);
        let count = docs.len();
        let body = match build_bulk_body(docs, self.document_id) {
            Ok(b) => b,
            Err(err) => {
                error!("failed to serialize bulk body (dropping {count} docs): {err:#}");
                docs.clear();
                return;
            }
        };

        self.post_bulk_batch(&index, &body, count, "events").await;

        if self.alerts_enabled {
            let alert_docs: Vec<AgentEvent> = docs
                .iter()
                .filter(|d| threat::should_index_alert(&d.0, &self.alerts_min_level))
                .cloned()
                .collect();
            if !alert_docs.is_empty() {
                let alert_index = self.index_name(&self.alerts_index_base);
                let alert_count = alert_docs.len();
                if let Ok(alert_body) = build_bulk_body(&alert_docs, self.document_id) {
                    self.post_bulk_batch(&alert_index, &alert_body, alert_count, "alerts")
                        .await;
                }
            }
        }

        docs.clear();
    }

    async fn post_bulk_batch(&self, index: &str, body: &str, count: usize, label: &str) {
        match self.post_bulk_with_retry(index, body).await {
            Ok(item_errors) => {
                if label == "events" {
                    self.metrics
                        .es_flushed_docs
                        .fetch_add(count as u64, std::sync::atomic::Ordering::Relaxed);
                } else {
                    self.metrics.es_alerts_flushed_docs.fetch_add(
                        count as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
                if item_errors > 0 {
                    self.metrics.es_bulk_item_errors.fetch_add(
                        item_errors,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    warn!(
                        "bulk indexed {count} {label} docs into {index} with {item_errors} item-level errors"
                    );
                } else {
                    info!("flushed {count} {label} into elasticsearch index={index}");
                }
            }
            Err(err) => {
                self.metrics
                    .es_bulk_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                error!("bulk flush failed after retries ({count} {label} docs): {err:#}");
                if self.spool_enabled && label == "events" {
                    if let Err(spool_err) = spool::write_failed_bulk(&self.spool_dir, body) {
                        error!("failed to spool bulk batch: {spool_err:#}");
                    } else {
                        self.metrics.es_spooled_batches.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                }
            }
        }
    }

    async fn post_bulk_with_retry(&self, index: &str, body: &str) -> anyhow::Result<u64> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self.post_bulk_once(index, body).await {
                Ok(item_errors) => return Ok(item_errors),
                Err(err) if attempt < self.max_retries && err.is_retryable() => {
                    let delay = self.retry_base_ms.saturating_mul(1u64 << (attempt - 1).min(6));
                    warn!(
                        "bulk attempt {attempt}/{} failed (retry in {delay}ms): {}",
                        self.max_retries,
                        err.log_message()
                    );
                    sleep(Duration::from_millis(delay)).await;
                }
                Err(err) => return Err(err.into_inner()),
            }
        }
    }

    async fn post_bulk_once(&self, index: &str, body: &str) -> Result<u64, BulkError> {
        self.metrics
            .es_bulk_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let url = format!("{}/{}/_bulk", self.base_url, index);
        let mut req = self
            .client
            .post(&url)
            .header("content-type", "application/x-ndjson")
            .body(body.to_string());
        if let Some((ref user, ref pass)) = self.auth {
            req = req.basic_auth(user, Some(pass));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| BulkError::retryable(anyhow::Error::from(e)))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if status == StatusCode::TOO_MANY_REQUESTS
            || status.is_server_error()
        {
            return Err(BulkError::retryable(anyhow::anyhow!(
                "bulk HTTP {status}: {text}"
            )));
        }
        if !status.is_success() {
            return Err(BulkError::fatal(anyhow::anyhow!(
                "bulk HTTP {status}: {text}"
            )));
        }

        let parsed: BulkResponse = serde_json::from_str(&text).unwrap_or(BulkResponse {
            errors: text.contains("\"errors\":true"),
            items: Vec::new(),
        });

        let mut item_errors = 0u64;
        if parsed.errors {
            for item in &parsed.items {
                if item
                    .get("index")
                    .and_then(|v| v.get("error"))
                    .is_some()
                {
                    item_errors += 1;
                }
            }
            if item_errors == 0 && text.contains("\"error\"") {
                item_errors = 1;
            }
        }

        Ok(item_errors)
    }
}

struct BulkError {
    retryable: bool,
    inner: anyhow::Error,
}

impl BulkError {
    fn retryable(inner: anyhow::Error) -> Self {
        Self {
            retryable: true,
            inner,
        }
    }

    fn fatal(inner: anyhow::Error) -> Self {
        Self {
            retryable: false,
            inner,
        }
    }

    fn is_retryable(&self) -> bool {
        self.retryable
    }

    fn log_message(&self) -> String {
        format!("{}", self.inner)
    }

    fn into_inner(self) -> anyhow::Error {
        self.inner
    }
}

fn build_bulk_body(docs: &[AgentEvent], document_id: bool) -> anyhow::Result<String> {
    let mut body = String::with_capacity(docs.len() * 512);
    for doc in docs {
        if document_id {
            if let Some(id) = doc_id::stable_document_id(&doc.0) {
                body.push_str(&format!("{{\"index\":{{\"_id\":\"{id}\"}}}}\n"));
            } else {
                body.push_str("{\"index\":{}}\n");
            }
        } else {
            body.push_str("{\"index\":{}}\n");
        }
        body.push_str(
            &serde_json::to_string(&doc.0).context("serialize AgentEvent for bulk")?,
        );
        body.push('\n');
    }
    Ok(body)
}

async fn sleep_until(deadline: Instant) {
    let now = Instant::now();
    if deadline > now {
        sleep(deadline - now).await;
    }
}
