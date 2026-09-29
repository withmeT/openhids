//! HTTP routes (`/healthz`, `/stats`, `/ingest`, `/events/*`, `/alerts`, `/hosts`, `/ws/events`).

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use tower_http::services::{ServeDir, ServeFile};
use tokio::sync::mpsc;

use crate::app::AppState;
use crate::enrich;
use crate::error::AppError;
use crate::filter;
use crate::metrics::MetricsSnapshot;
use crate::models::IngestEnvelope;
use crate::query;
use crate::threat;
use crate::ws;

pub fn router(state: AppState) -> Router {
    let static_dir = std::env::var("STATIC_DIR").unwrap_or_else(|_| "static".to_string());

    Router::new()
        .route("/healthz", get(healthz))
        .route("/stats", get(stats))
        .route("/ingest", post(ingest))
        // 查询 API
        .route("/events/search", get(query::events_search))
        .route("/events/recent", get(query::events_recent))
        .route("/alerts", get(query::alerts_search))
        .route("/hosts", get(query::hosts_list))
        // WebSocket 实时推送
        .route("/ws/events", get(ws::ws_events))
        // 静态前端文件
        .fallback_service(
            ServeDir::new(&static_dir)
                .fallback(ServeFile::new(format!("{}/index.html", static_dir))),
        )
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "queue_capacity": state.queue_capacity,
        "ingest_auth_required": state.ingest_token.is_some(),
        "yaml_rules": state.ruleset.is_some(),
        "flow_drop_plain_syn": state.flow_drop_plain_syn,
    }))
}

async fn stats(State(state): State<AppState>) -> Json<MetricsSnapshot> {
    Json(state.metrics.snapshot())
}

async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<IngestEnvelope>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    if let Some(expected) = state.ingest_token.as_deref() {
        if !authorize_ingest(&headers, expected) {
            state
                .metrics
                .rejected_unauthorized
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(AppError::Unauthorized);
        }
    }

    if envelope.events.is_empty() {
        state
            .metrics
            .rejected_bad_request
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(AppError::BadRequest("events array must not be empty".to_string()));
    }

    let meta = enrich::EnvelopeMeta {
        agent_version: envelope.agent_version.clone(),
        schema_version: envelope.schema_version,
        host_id: envelope.host_id.clone(),
        batch_event_count: envelope.event_count(),
        agent_stats: envelope.agent_stats.clone(),
    };
    let mut accepted = 0usize;
    for ev in envelope.events {
        if filter::should_drop_plain_syn_flow(&ev.0, state.flow_drop_plain_syn) {
            state
                .metrics
                .dropped_plain_syn_flow
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            continue;
        }

        let mut ev = enrich::enrich_event(ev, &meta);
        threat::analyze_event(&mut ev, &state.syn_tracker, state.ruleset.as_ref());

        // 广播到 WebSocket 订阅者
        let _ = state.event_broadcast.send(Arc::new(ev.0.clone()));

        state
            .tx
            .try_send(ev)
            .map_err(|err| map_send_error(&state, err))?;
        accepted += 1;
    }

    if accepted == 0 {
        state
            .metrics
            .rejected_bad_request
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Err(AppError::BadRequest(
            "no events accepted after filtering".to_string(),
        ));
    }

    state
        .metrics
        .accepted
        .fetch_add(accepted as u64, std::sync::atomic::Ordering::Relaxed);

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "accepted": accepted,
            "batch_size": accepted,
        })),
    ))
}

fn authorize_ingest(headers: &HeaderMap, expected: &str) -> bool {
    if let Some(value) = headers.get("authorization") {
        if let Ok(s) = value.to_str() {
            if let Some(token) = s.strip_prefix("Bearer ") {
                if token.trim() == expected {
                    return true;
                }
            }
        }
    }
    if let Some(value) = headers.get("x-api-key") {
        if let Ok(s) = value.to_str() {
            if s.trim() == expected {
                return true;
            }
        }
    }
    false
}

fn map_send_error(state: &AppState, err: mpsc::error::TrySendError<crate::models::AgentEvent>) -> AppError {
    match err {
        mpsc::error::TrySendError::Full(_) => {
            state
                .metrics
                .rejected_queue_full
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            AppError::QueueFull
        }
        mpsc::error::TrySendError::Closed(_) => {
            AppError::BadRequest("ingest service is not ready".to_string())
        }
    }
}
