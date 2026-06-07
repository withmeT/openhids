//! HTTP-layer errors for ingest.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized,
    QueueFull,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "missing or invalid ingest credentials",
            )
                .into_response(),
            Self::QueueFull => (
                StatusCode::SERVICE_UNAVAILABLE,
                "ingest queue is full, please retry",
            )
                .into_response(),
        }
    }
}
