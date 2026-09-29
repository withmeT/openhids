//! HTTP routes (`/healthz`, `/stats`, `/ingest`, `/events/*`, `/alerts`, `/hosts`, `/ws/events`).

use std::{
    collections::VecDeque,
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use flate2::read::GzDecoder;
use hids_protocol::{
    BaselineCheckSpec, BaselineCommand, BaselineResult, SecureEnvelope, open_json, seal_json,
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

static COMMAND_SEQ: AtomicU64 = AtomicU64::new(1);
const MAX_COMMAND_CHECKS: usize = 32;
const MAX_COMMAND_PATHS: usize = 64;
const MAX_COMMAND_QUEUE_PER_HOST: usize = 64;
const MAX_COMMAND_TEXT_BYTES: usize = 512;
const MAX_COMMAND_DETAIL_BYTES: usize = 512;
const MAX_COMMAND_RESULT_ITEMS: usize = 64;

pub fn router(state: AppState) -> Router {
    let static_dir = std::env::var("STATIC_DIR").unwrap_or_else(|_| "static".to_string());

    Router::new()
        .route("/healthz", get(healthz))
        .route("/stats", get(stats))
        .route("/ingest", post(ingest))
        .route("/commands", post(enqueue_command))
        .route("/commands/next", get(next_command))
        .route("/commands/result", post(command_result))
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
        "baseline_control_enabled": state.command_key.is_some(),
    }))
}

async fn stats(State(state): State<AppState>) -> Json<MetricsSnapshot> {
    Json(state.metrics.snapshot())
}

async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
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

    let envelope = decode_ingest_body(&headers, &body)?;
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

        ingest_one(&state, ev, &meta)?;
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

#[derive(Debug, serde::Deserialize)]
struct EnqueueCommandRequest {
    host_id: String,
    checks: Vec<BaselineCheckSpec>,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

async fn enqueue_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<EnqueueCommandRequest>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    let Some(expected) = state.ingest_token.as_deref() else {
        return Err(AppError::Unauthorized);
    };
    if !authorize_ingest(&headers, expected) {
        return Err(AppError::Unauthorized);
    }
    if state.command_key.is_none() {
        return Err(AppError::BadRequest(
            "HIDS_COMMAND_KEY is not configured".to_string(),
        ));
    }
    if request.host_id.trim().is_empty() || request.checks.is_empty() {
        return Err(AppError::BadRequest(
            "host_id and checks are required".to_string(),
        ));
    }
    if request.host_id.len() > MAX_COMMAND_TEXT_BYTES {
        return Err(AppError::BadRequest("host_id is too long".to_string()));
    }
    if request.checks.len() > MAX_COMMAND_CHECKS {
        return Err(AppError::BadRequest(format!(
            "at most {MAX_COMMAND_CHECKS} checks are allowed"
        )));
    }
    for check in &request.checks {
        if check.id.trim().is_empty() || check.id.len() > MAX_COMMAND_TEXT_BYTES {
            return Err(AppError::BadRequest(
                "each check id must be 1-512 bytes".to_string(),
            ));
        }
        if check.paths.len() > MAX_COMMAND_PATHS
            || check.paths.iter().any(|path| path.len() > MAX_COMMAND_TEXT_BYTES)
        {
            return Err(AppError::BadRequest(format!(
                "each file hash check supports at most {MAX_COMMAND_PATHS} paths of {MAX_COMMAND_TEXT_BYTES} bytes"
            )));
        }
    }

    let now = unix_millis_now();
    let request_id = format!(
        "baseline-{now}-{}",
        COMMAND_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let command = BaselineCommand {
        request_id: request_id.clone(),
        host_id: request.host_id.clone(),
        issued_at_ms: now,
        expires_at_ms: now.saturating_add(request.ttl_secs.unwrap_or(300).clamp(10, 3600) * 1000),
        checks: request.checks,
    };
    let mut queues = state.command_queue.lock().await;
    let queue = queues.entry(request.host_id).or_insert_with(VecDeque::new);
    if queue.len() >= MAX_COMMAND_QUEUE_PER_HOST {
        return Err(AppError::CommandQueueFull);
    }
    queue.push_back(command);

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "request_id": request_id })),
    ))
}

#[derive(Debug, serde::Deserialize)]
struct CommandHostQuery {
    host_id: String,
}

async fn next_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CommandHostQuery>,
) -> Result<axum::response::Response, AppError> {
    let Some(expected) = state.ingest_token.as_deref() else {
        return Err(AppError::Unauthorized);
    };
    if !authorize_ingest(&headers, expected) {
        return Err(AppError::Unauthorized);
    }
    let Some(key) = state.command_key.as_ref() else {
        return Err(AppError::BadRequest(
            "HIDS_COMMAND_KEY is not configured".to_string(),
        ));
    };

    let command = {
        let mut queues = state.command_queue.lock().await;
        queues.get_mut(&query.host_id).and_then(VecDeque::pop_front)
    };
    let Some(command) = command else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let encrypted = seal_json(&command, key)
        .map_err(|err| AppError::BadRequest(format!("encrypt command failed: {err}")))?;
    Ok((StatusCode::OK, Json(encrypted)).into_response())
}

async fn command_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<SecureEnvelope>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    let Some(expected) = state.ingest_token.as_deref() else {
        return Err(AppError::Unauthorized);
    };
    if !authorize_ingest(&headers, expected) {
        return Err(AppError::Unauthorized);
    }
    let Some(key) = state.command_key.as_ref() else {
        return Err(AppError::BadRequest(
            "HIDS_COMMAND_KEY is not configured".to_string(),
        ));
    };
    let result: BaselineResult = open_json(&envelope, key)
        .map_err(|err| AppError::BadRequest(format!("decrypt baseline result failed: {err}")))?;
    if result.request_id.trim().is_empty() || result.host_id.trim().is_empty() {
        return Err(AppError::BadRequest(
            "baseline result request_id and host_id are required".to_string(),
        ));
    }
    if result.results.is_empty() || result.results.len() > MAX_COMMAND_RESULT_ITEMS {
        return Err(AppError::BadRequest(format!(
            "baseline result must contain 1-{MAX_COMMAND_RESULT_ITEMS} items"
        )));
    }
    if result.request_id.len() > MAX_COMMAND_TEXT_BYTES
        || result.host_id.len() > MAX_COMMAND_TEXT_BYTES
        || result.results.iter().any(|item| {
            item.id.len() > MAX_COMMAND_TEXT_BYTES
                || item.summary.len() > MAX_COMMAND_TEXT_BYTES
                || item.details.len() > MAX_COMMAND_RESULT_ITEMS
                || item
                    .details
                    .iter()
                    .any(|detail| detail.len() > MAX_COMMAND_DETAIL_BYTES)
        })
    {
        return Err(AppError::BadRequest(
            "baseline result contains oversized fields".to_string(),
        ));
    }

    let mut accepted = 0usize;
    for item in result.results {
        let kind = serde_json::to_value(&item.kind)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "unknown".to_string());
        let status = serde_json::to_value(&item.status)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "unknown".to_string());
        let event = crate::models::AgentEvent(serde_json::json!({
            "event_kind": 8,
            "ts_ms": result.completed_at_ms,
            "uid": 0,
            "tgid": 0,
            "pid": 0,
            "comm": "baseline",
            "host_id": result.host_id,
            "baseline_request_id": result.request_id,
            "baseline_check": kind,
            "baseline_status": status,
            "baseline_result": serde_json::json!({
                "summary": item.summary,
                "details": item.details,
            }).to_string(),
        }));
        let meta = enrich::EnvelopeMeta {
            agent_version: Some("control-plane".to_string()),
            schema_version: Some(5),
            host_id: None,
            batch_event_count: 1,
            agent_stats: None,
        };
        ingest_one(&state, event, &meta)?;
        accepted += 1;
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "accepted": accepted })),
    ))
}

fn ingest_one(
    state: &AppState,
    ev: crate::models::AgentEvent,
    meta: &enrich::EnvelopeMeta,
) -> Result<(), AppError> {
    let mut ev = enrich::enrich_event(ev, meta);
    threat::analyze_event(&mut ev, &state.syn_tracker, state.ruleset.as_ref());
    state
        .tx
        .try_send(ev.clone())
        .map_err(|err| map_send_error(state, err))?;
    let _ = state.event_broadcast.send(Arc::new(ev.0));
    Ok(())
}

fn decode_ingest_body(headers: &HeaderMap, body: &[u8]) -> Result<IngestEnvelope, AppError> {
    let raw = if headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("gzip"))
    {
        let decoder = GzDecoder::new(body);
        let mut decoded = Vec::new();
        decoder
            .take(64 * 1024 * 1024)
            .read_to_end(&mut decoded)
            .map_err(|err| AppError::BadRequest(format!("decompress ingest body failed: {err}")))?;
        decoded
    } else {
        body.to_vec()
    };
    serde_json::from_slice(&raw)
        .map_err(|err| AppError::BadRequest(format!("parse ingest body failed: {err}")))
}

fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn authorize_ingest(headers: &HeaderMap, expected: &str) -> bool {
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
