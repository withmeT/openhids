use crate::{
    events::IngestEnvelope,
    spool::Spool,
};

use anyhow::Context as _;
use flate2::{Compression, write::GzEncoder};

async fn send_envelope(
    client: &reqwest::Client,
    url: &str,
    envelope: &IngestEnvelope,
    token: &str,
) -> anyhow::Result<()> {
    let json = serde_json::to_vec(envelope).context("serialize ingest envelope")?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    std::io::Write::write_all(&mut encoder, &json).context("compress ingest envelope")?;
    let body = encoder.finish().context("finish ingest compression")?;
    let mut request = client
        .post(url)
        .header("content-type", "application/json")
        .header("content-encoding", "gzip")
        .body(body);
    if !token.trim().is_empty() {
        request = request.header("x-api-key", token.trim());
    }
    let res = request
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

pub async fn drain_spool(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    spool: &Spool,
) -> anyhow::Result<()> {
    let files = spool.list_files_oldest_first().unwrap_or_default();
    for f in files {
        let bytes = match std::fs::read(&f) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let envelope: IngestEnvelope = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                let _ = std::fs::remove_file(&f);
                continue;
            }
        };

        if send_envelope(client, url, &envelope, token).await.is_ok() {
            let _ = std::fs::remove_file(&f);
        } else {
            // network/server still bad; stop here
            break;
        }
    }
    Ok(())
}

// Intentionally no extra helpers for now; sending is handled inline in `agent.rs`.
