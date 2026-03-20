use crate::{events::AgentEvent, spool::Spool};

use anyhow::Context as _;

async fn send_batch(
    client: &reqwest::Client,
    url: &str,
    batch: &[AgentEvent],
) -> anyhow::Result<()> {
    let res = client
        .post(url)
        .json(batch)
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
        let batch: Vec<AgentEvent> = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                let _ = std::fs::remove_file(&f);
                continue;
            }
        };

        if send_batch(client, url, &batch).await.is_ok() {
            let _ = std::fs::remove_file(&f);
        } else {
            // network/server still bad; stop here
            break;
        }
    }
    Ok(())
}

pub async fn send_pending_batch(
    client: &reqwest::Client,
    url: &str,
    batch: &[AgentEvent],
) -> anyhow::Result<()> {
    send_batch(client, url, batch).await
}

