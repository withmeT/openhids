//! Encrypted control-plane polling and baseline result reporting.

use anyhow::Context as _;
use hids_protocol::{
    BaselineCommand, BaselineResult, SecureEnvelope, open_json, parse_key, seal_json,
};
use reqwest::{Client, StatusCode};

use crate::{baseline, config::Config};

pub async fn poll_once(client: &Client, cfg: &Config) -> anyhow::Result<bool> {
    if cfg.command_key.trim().is_empty() {
        return Ok(false);
    }

    let key = parse_key(&cfg.command_key)?;
    let mut request = client
        .get(&cfg.command_poll_url)
        .query(&[("host_id", cfg.host_id.as_str())]);
    if !cfg.ingest_token.trim().is_empty() {
        request = request.header("x-api-key", cfg.ingest_token.trim());
    }

    let response = request.send().await.context("poll baseline command")?;
    if response.status() == StatusCode::NO_CONTENT {
        return Ok(false);
    }
    if !response.status().is_success() {
        anyhow::bail!("baseline command poll status={}", response.status());
    }

    let envelope: SecureEnvelope = response
        .json()
        .await
        .context("decode encrypted baseline command")?;
    let command: BaselineCommand = open_json(&envelope, &key)?;
    if command.host_id != cfg.host_id {
        anyhow::bail!("baseline command host_id mismatch");
    }

    let result: BaselineResult = baseline::execute(&command, &cfg.baseline_allowed_paths);
    let encrypted = seal_json(&result, &key)?;

    let mut report = client.post(&cfg.command_result_url).json(&encrypted);
    if !cfg.ingest_token.trim().is_empty() {
        report = report.header("x-api-key", cfg.ingest_token.trim());
    }
    let response = report.send().await.context("report baseline result")?;
    if !response.status().is_success() {
        anyhow::bail!("baseline result status={}", response.status());
    }

    Ok(true)
}
