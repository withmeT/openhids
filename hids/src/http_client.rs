use crate::{
    events::IngestEnvelope,
    spool::Spool,
};

use anyhow::Context as _;

async fn send_envelope(
    client: &reqwest::Client,
    url: &str,
    envelope: &IngestEnvelope,
) -> anyhow::Result<()> {
    let res = client
        .post(url)
        .json(envelope)
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

        if send_envelope(client, url, &envelope).await.is_ok() {
            let _ = std::fs::remove_file(&f);
        } else {
            // network/server still bad; stop here
            break;
        }
    }
    Ok(())
}

// Intentionally no extra helpers for now; sending is handled inline in `agent.rs`.

