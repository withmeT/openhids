//! WebSocket 实时事件推送端点。

use axum::{
    extract::{Query, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::app::AppState;

#[derive(Debug, Deserialize)]
pub struct WsParams {
    /// 过滤 event_kind（逗号分隔，如 "0,3,7"）；为空则接收所有
    #[serde(default)]
    pub event_kinds: Option<String>,
    /// 过滤 host_id
    #[serde(default)]
    pub host_id: Option<String>,
    /// 只看告警（threat.level != none）
    #[serde(default)]
    pub alerts_only: Option<bool>,
}

pub async fn ws_events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(params): Query<WsParams>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state, params))
}

async fn handle_ws(socket: WebSocket, state: AppState, params: WsParams) {
    let mut rx = state.event_broadcast.subscribe();

    let filter_kinds: Option<Vec<i64>> = params.event_kinds.as_ref().map(|s| {
        s.split(',')
            .filter_map(|p| p.trim().parse::<i64>().ok())
            .collect()
    });
    let filter_host = params.host_id.clone();
    let alerts_only = params.alerts_only.unwrap_or(false);

    let (mut sender, mut receiver) = socket.split();

    let send_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if !matches_filter(&event, &filter_kinds, &filter_host, alerts_only) {
                        continue;
                    }

                    let text = serde_json::to_string(event.as_ref()).unwrap_or_default();
                    if sender.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    let msg = serde_json::json!({
                        "_system": "lagged",
                        "skipped": n,
                    });
                    let _ = sender
                        .send(Message::Text(msg.to_string().into()))
                        .await;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // 接收客户端消息（心跳 pong 或关闭）
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
}

fn matches_filter(
    event: &serde_json::Value,
    filter_kinds: &Option<Vec<i64>>,
    filter_host: &Option<String>,
    alerts_only: bool,
) -> bool {
    if let Some(kinds) = filter_kinds {
        if let Some(kind) = event.get("event_kind").and_then(|v| v.as_i64()) {
            if !kinds.contains(&kind) {
                return false;
            }
        }
    }

    if let Some(host) = filter_host {
        if let Some(h) = event.get("host_id").and_then(|v| v.as_str()) {
            if h != host.as_str() {
                return false;
            }
        }
    }

    if alerts_only {
        let level = event
            .get("threat")
            .and_then(|t| t.get("level"))
            .and_then(|v| v.as_str())
            .unwrap_or("none");
        if level == "none" {
            return false;
        }
    }

    true
}
