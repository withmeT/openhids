//! HIDS ingest server: HTTP envelope → per-event Elasticsearch bulk index.

pub mod app;
pub mod config;
pub mod enrich;
pub mod error;
pub mod es_writer;
pub mod models;
pub mod routes;
pub mod threat;

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::app::AppState;
use crate::config::Config;
use crate::es_writer::EsBulkWriter;
use crate::threat::aggregate::SynBurstTracker;

/// Run HTTP server and background ES bulk writer until shutdown.
pub async fn run() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,hids_server=debug".to_string()),
        )
        .init();

    let cfg = Config::from_env();
    let syn_tracker = Arc::new(SynBurstTracker::new(
        cfg.threat_syn_window_sec,
        cfg.threat_syn_threshold,
    ));

    let (tx, rx) = mpsc::channel(cfg.queue_capacity);
    let es_writer = EsBulkWriter::new(
        cfg.es_url.clone(),
        cfg.es_index.clone(),
        cfg.es_username.clone(),
        cfg.es_password.clone(),
        cfg.batch_size,
        std::time::Duration::from_millis(cfg.flush_ms),
    )?;

    tokio::spawn(async move {
        if let Err(err) = es_writer.run(rx).await {
            error!("es writer stopped unexpectedly: {err:#}");
        }
    });

    let app = routes::router(AppState {
        tx,
        syn_tracker,
    });

    info!("listening on http://{}", cfg.bind_addr);
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", cfg.bind_addr))?;
    axum::serve(listener, app)
        .await
        .context("server terminated unexpectedly")
}
