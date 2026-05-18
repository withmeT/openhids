//! HTTP routes (`/healthz`, `/ingest`).

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use tokio::sync::mpsc;

use crate::app::AppState;
use crate::enrich;
use crate::error::AppError;
use crate::models::{AgentEvent, IngestEnvelope};
use crate::threat;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/ingest", post(ingest))
        .with_state(state)
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn ingest(
    State(state): State<AppState>,
    Json(envelope): Json<IngestEnvelope>,
) -> Result<impl axum::response::IntoResponse, AppError> {
    let mut accepted = 0usize;
    for ev in envelope.events {
        let mut ev = enrich::apply_ingest_timestamp(ev);
        threat::analyze_event(&mut ev, &state.syn_tracker);
        state
            .tx
            .try_send(ev)
            .map_err(map_send_error)?;
        accepted += 1;
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "accepted": accepted })),
    ))
}

fn map_send_error(err: mpsc::error::TrySendError<AgentEvent>) -> AppError {
    match err {
        mpsc::error::TrySendError::Full(_) => AppError::QueueFull,
        mpsc::error::TrySendError::Closed(_) => {
            AppError::BadRequest("ingest service is not ready".to_string())
        }
    }
}
