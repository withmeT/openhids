//! HIDS ingest server: HTTP envelope → enrich → threat → Elasticsearch bulk index.

pub mod app;
pub mod config;
pub mod doc_id;
pub mod enrich;
pub mod error;
pub mod es_writer;
pub mod filter;
pub mod metrics;
pub mod models;
pub mod routes;
pub mod spool;
pub mod threat;
pub mod time_fmt;

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::mpsc;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{error, info};

use crate::app::AppState;
use crate::config::Config;
use crate::es_writer::EsBulkWriter;
use crate::metrics::IngestMetrics;
use crate::threat::aggregate::SynBurstTracker;
use crate::threat::rules_yaml::Ruleset;

/// Run HTTP server and background ES bulk writer until shutdown.
pub async fn run() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,hids_server=debug".to_string()),
        )
        .init();

    let cfg = Config::from_env();
    let metrics = Arc::new(IngestMetrics::default());
    let syn_tracker = Arc::new(SynBurstTracker::new(
        cfg.threat_syn_window_sec,
        cfg.threat_syn_threshold,
    ));

    let ruleset: Option<Arc<Ruleset>> = match cfg.threat_rules_path.as_ref() {
        Some(path) => {
            let rs = Ruleset::load(path)
                .with_context(|| format!("load threat rules from {}", path.display()))?;
            info!(
                "loaded {} yaml threat rules (version={})",
                rs.rule_count(),
                rs.version
            );
            Some(Arc::new(rs))
        }
        None => {
            info!("yaml threat rules disabled (built-in rules only)");
            None
        }
    };

    let (tx, rx) = mpsc::channel(cfg.queue_capacity);
    let writer_metrics = metrics.clone();
    let es_writer = EsBulkWriter::new(&cfg, writer_metrics)?;
    let writer_handle = tokio::spawn(async move {
        if let Err(err) = es_writer.run(rx).await {
            error!("es writer stopped unexpectedly: {err:#}");
        }
    });

    let state = AppState::new(&cfg, tx.clone(), syn_tracker, ruleset, metrics);
    let app = routes::router(state).layer(RequestBodyLimitLayer::new(cfg.max_body_bytes));

    info!(
        "listening on http://{} (queue={}, es_index={}, alerts={}, daily_index={}, doc_id={}, spool={}, flow_drop_syn={})",
        cfg.bind_addr,
        cfg.queue_capacity,
        cfg.es_index,
        cfg.es_alerts_enabled,
        cfg.es_daily_index,
        cfg.es_document_id,
        cfg.spool_enabled,
        cfg.flow_drop_plain_syn,
    );
    if let Some(p) = cfg.threat_rules_path_display() {
        info!("threat rules file: {}", p.display());
    }
    if cfg.ingest_token.is_some() {
        info!("ingest authentication enabled");
    }

    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", cfg.bind_addr))?;

    let shutdown = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            error!("failed to install ctrl_c handler: {err}");
        }
        info!("shutdown signal received, draining ingest queue");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("http server terminated")?;

    drop(tx);
    if let Err(err) = writer_handle.await {
        error!("es writer task join error: {err}");
    }

    info!("hids-server stopped");
    Ok(())
}
