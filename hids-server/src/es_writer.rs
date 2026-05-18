//! Elasticsearch `_bulk` writer (NDJSON, timed flush + size flush).

use std::time::Duration;

use anyhow::Context;
use reqwest::Client;
use tokio::{
    sync::mpsc,
    time::{Instant, sleep},
};
use tracing::{info, warn};

use crate::models::AgentEvent;

pub struct EsBulkWriter {
    client: Client,
    base_url: String,
    index: String,
    auth: Option<(String, String)>,
    batch_size: usize,
    flush_interval: Duration,
}

impl EsBulkWriter {
    pub fn new(
        base_url: String,
        index: String,
        username: Option<String>,
        password: Option<String>,
        batch_size: usize,
        flush_interval: Duration,
    ) -> anyhow::Result<Self> {
        let client = Client::builder()
            .pool_max_idle_per_host(128)
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .context("failed to build reqwest client")?;
        let auth = match (username, password) {
            (Some(u), Some(p)) => Some((u, p)),
            _ => None,
        };

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            index,
            auth,
            batch_size,
            flush_interval,
        })
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
                                self.flush(&mut buffer).await?;
                                next_flush = Instant::now() + self.flush_interval;
                            }
                        }
                        None => {
                            if !buffer.is_empty() {
                                self.flush(&mut buffer).await?;
                            }
                            warn!("ingest channel closed, es writer stopping");
                            break;
                        }
                    }
                }
                _ = sleep_until(next_flush), if !buffer.is_empty() => {
                    self.flush(&mut buffer).await?;
                    next_flush = Instant::now() + self.flush_interval;
                }
            }
        }

        Ok(())
    }

    async fn flush(&self, docs: &mut Vec<AgentEvent>) -> anyhow::Result<()> {
        if docs.is_empty() {
            return Ok(());
        }

        let mut body = String::with_capacity(docs.len() * 384);
        for doc in docs.iter() {
            body.push_str("{\"index\":{}}\n");
            body.push_str(
                &serde_json::to_string(&doc.0)
                    .context("failed to serialize AgentEvent for bulk body")?,
            );
            body.push('\n');
        }

        let url = format!("{}/{}/_bulk", self.base_url, self.index);
        let mut req = self
            .client
            .post(url)
            .header("content-type", "application/x-ndjson")
            .body(body);
        if let Some((ref user, ref pass)) = self.auth {
            req = req.basic_auth(user, Some(pass));
        }

        let resp = req.send().await.context("failed to send bulk request")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("bulk request failed: status={status}, body={text}");
        }
        if text.contains("\"errors\":true") {
            warn!("bulk response has partial failures: {text}");
        }

        info!("flushed {} events into elasticsearch", docs.len());
        docs.clear();
        Ok(())
    }
}

async fn sleep_until(deadline: Instant) {
    let now = Instant::now();
    if deadline > now {
        sleep(deadline - now).await;
    }
}
