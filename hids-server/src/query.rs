//! 事件查询 API：代理查询 ES，返回结构化结果给前端。

use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::app::AppState;
use crate::error::AppError;

/// 查询参数
#[derive(Debug, Deserialize)]
pub struct EventSearchParams {
    /// 开始时间（ISO 8601 或 Unix ms）
    #[serde(default)]
    pub from: Option<String>,
    /// 结束时间
    #[serde(default)]
    pub to: Option<String>,
    /// 主机 ID 过滤
    #[serde(default)]
    pub host_id: Option<String>,
    /// 事件类型（0=bash, 2=flow, 3=http, 4=exec, 5=exit, 6=file, 7=tls）
    #[serde(default)]
    pub event_kind: Option<i64>,
    /// 关键字搜索（匹配 line / http_url / exec_path / file_path / tls_payload_trunc）
    #[serde(default)]
    pub keyword: Option<String>,
    /// 威胁等级过滤（high / medium / low）
    #[serde(default)]
    pub threat_level: Option<String>,
    /// 客户端 IP 过滤
    #[serde(default)]
    pub client_ip: Option<String>,
    /// 每页数量（默认 50，最大 500）
    #[serde(default = "default_size")]
    pub size: usize,
    /// 偏移量（用于分页）
    #[serde(default)]
    pub from_offset: usize,
    /// 排序字段
    #[serde(default = "default_sort")]
    pub sort: String,
    /// 排序方向
    #[serde(default = "default_order")]
    pub order: String,
}

fn default_size() -> usize {
    50
}
fn default_sort() -> String {
    "@timestamp".to_string()
}
fn default_order() -> String {
    "desc".to_string()
}

#[derive(Debug, Serialize)]
pub struct EventSearchResponse {
    pub total: u64,
    pub events: Vec<Value>,
}

/// GET /events/search - 查询事件
pub async fn events_search(
    State(state): State<AppState>,
    Query(params): Query<EventSearchParams>,
) -> Result<Json<EventSearchResponse>, AppError> {
    let size = params.size.min(500);
    let mut must_clauses: Vec<Value> = Vec::new();

    // 时间范围
    let mut range = json!({});
    if let Some(ref from) = params.from {
        range["gte"] = json!(from);
    }
    if let Some(ref to) = params.to {
        range["lte"] = json!(to);
    }
    if range.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
        must_clauses.push(json!({ "range": { "@timestamp": range } }));
    }

    // host_id
    if let Some(ref host) = params.host_id {
        must_clauses.push(json!({ "term": { "host_id": host } }));
    }

    // event_kind
    if let Some(kind) = params.event_kind {
        must_clauses.push(json!({ "term": { "event_kind": kind } }));
    }

    // threat_level
    if let Some(ref level) = params.threat_level {
        must_clauses.push(json!({ "term": { "threat.level": level } }));
    }

    // client_ip
    if let Some(ref ip) = params.client_ip {
        must_clauses.push(json!({ "term": { "client_ip": ip } }));
    }

    // 关键字搜索
    if let Some(ref kw) = params.keyword {
        if !kw.trim().is_empty() {
            must_clauses.push(json!({
                "multi_match": {
                    "query": kw,
                    "fields": ["line", "http_url", "exec_path", "file_path", "tls_payload_trunc", "http_body_trunc"],
                    "type": "phrase_prefix"
                }
            }));
        }
    }

    let query_body = if must_clauses.is_empty() {
        json!({ "match_all": {} })
    } else {
        json!({ "bool": { "must": must_clauses } })
    };

    let es_body = json!({
        "query": query_body,
        "size": size,
        "from": params.from_offset,
        "sort": [{ params.sort.clone(): { "order": params.order } }],
    });

    let index = resolve_index(&state);
    let url = format!("{}/{}/_search", state.es_query_url, index);

    let client = reqwest::Client::new();
    let mut req = client.post(&url).json(&es_body);
    if let Some((ref user, ref pass)) = state.es_query_auth {
        req = req.basic_auth(user, Some(pass));
    }

    let resp = req.send().await.map_err(|e| {
        AppError::BadRequest(format!("ES query failed: {e}"))
    })?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::BadRequest(format!("ES error: {text}")));
    }

    let body: Value = resp.json().await.map_err(|e| {
        AppError::BadRequest(format!("ES response parse failed: {e}"))
    })?;

    let total = body["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let events: Vec<Value> = body["hits"]["hits"]
        .as_array()
        .map(|arr| arr.iter().map(|h| h["_source"].clone()).collect())
        .unwrap_or_default();

    Ok(Json(EventSearchResponse { total, events }))
}

/// GET /events/recent - 最近 N 条事件（快捷接口）
pub async fn events_recent(
    State(state): State<AppState>,
    Query(params): Query<RecentParams>,
) -> Result<Json<EventSearchResponse>, AppError> {
    let size = params.size.unwrap_or(20).min(200);

    let mut query_body = json!({ "match_all": {} });
    if let Some(kind) = params.event_kind {
        query_body = json!({ "term": { "event_kind": kind } });
    }

    let es_body = json!({
        "query": query_body,
        "size": size,
        "sort": [{ "@timestamp": { "order": "desc" } }],
    });

    let index = resolve_index(&state);
    let url = format!("{}/{}/_search", state.es_query_url, index);

    let client = reqwest::Client::new();
    let mut req = client.post(&url).json(&es_body);
    if let Some((ref user, ref pass)) = state.es_query_auth {
        req = req.basic_auth(user, Some(pass));
    }

    let resp = req.send().await.map_err(|e| {
        AppError::BadRequest(format!("ES query failed: {e}"))
    })?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::BadRequest(format!("ES error: {text}")));
    }

    let body: Value = resp.json().await.map_err(|e| {
        AppError::BadRequest(format!("ES response parse failed: {e}"))
    })?;

    let total = body["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let events: Vec<Value> = body["hits"]["hits"]
        .as_array()
        .map(|arr| arr.iter().map(|h| h["_source"].clone()).collect())
        .unwrap_or_default();

    Ok(Json(EventSearchResponse { total, events }))
}

#[derive(Debug, Deserialize)]
pub struct RecentParams {
    pub size: Option<usize>,
    pub event_kind: Option<i64>,
}

/// GET /alerts - 查询告警事件
pub async fn alerts_search(
    State(state): State<AppState>,
    Query(params): Query<AlertsParams>,
) -> Result<Json<EventSearchResponse>, AppError> {
    let size = params.size.unwrap_or(50).min(500);

    let mut must_clauses: Vec<Value> = Vec::new();

    // 只查 threat.level != "none"
    must_clauses.push(json!({
        "bool": {
            "must_not": [{ "term": { "threat.level": "none" } }]
        }
    }));

    if let Some(ref level) = params.level {
        must_clauses.push(json!({ "term": { "threat.level": level } }));
    }
    if let Some(ref host) = params.host_id {
        must_clauses.push(json!({ "term": { "host_id": host } }));
    }

    let mut range = json!({});
    if let Some(ref from) = params.from {
        range["gte"] = json!(from);
    }
    if let Some(ref to) = params.to {
        range["lte"] = json!(to);
    }
    if range.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
        must_clauses.push(json!({ "range": { "@timestamp": range } }));
    }

    let es_body = json!({
        "query": { "bool": { "must": must_clauses } },
        "size": size,
        "from": params.from_offset.unwrap_or(0),
        "sort": [{ "@timestamp": { "order": "desc" } }],
    });

    let index = if state.es_daily_index {
        format!("{}*", state.es_query_index)
    } else {
        state.es_query_index.clone()
    };
    let url = format!("{}/{}/_search", state.es_query_url, index);

    let client = reqwest::Client::new();
    let mut req = client.post(&url).json(&es_body);
    if let Some((ref user, ref pass)) = state.es_query_auth {
        req = req.basic_auth(user, Some(pass));
    }

    let resp = req.send().await.map_err(|e| {
        AppError::BadRequest(format!("ES query failed: {e}"))
    })?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::BadRequest(format!("ES error: {text}")));
    }

    let body: Value = resp.json().await.map_err(|e| {
        AppError::BadRequest(format!("ES response parse failed: {e}"))
    })?;

    let total = body["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let events: Vec<Value> = body["hits"]["hits"]
        .as_array()
        .map(|arr| arr.iter().map(|h| h["_source"].clone()).collect())
        .unwrap_or_default();

    Ok(Json(EventSearchResponse { total, events }))
}

#[derive(Debug, Deserialize)]
pub struct AlertsParams {
    pub size: Option<usize>,
    pub from_offset: Option<usize>,
    pub level: Option<String>,
    pub host_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// GET /hosts - 活跃主机列表（按 host_id 聚合）
pub async fn hosts_list(
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let es_body = json!({
        "size": 0,
        "aggs": {
            "hosts": {
                "terms": {
                    "field": "host_id",
                    "size": 1000
                },
                "aggs": {
                    "last_seen": { "max": { "field": "@timestamp" } },
                    "event_count": { "value_count": { "field": "event_kind" } }
                }
            }
        }
    });

    let index = resolve_index(&state);
    let url = format!("{}/{}/_search", state.es_query_url, index);

    let client = reqwest::Client::new();
    let mut req = client.post(&url).json(&es_body);
    if let Some((ref user, ref pass)) = state.es_query_auth {
        req = req.basic_auth(user, Some(pass));
    }

    let resp = req.send().await.map_err(|e| {
        AppError::BadRequest(format!("ES query failed: {e}"))
    })?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(AppError::BadRequest(format!("ES error: {text}")));
    }

    let body: Value = resp.json().await.map_err(|e| {
        AppError::BadRequest(format!("ES response parse failed: {e}"))
    })?;

    let buckets = body["aggregations"]["hosts"]["buckets"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let hosts: Vec<Value> = buckets
        .iter()
        .map(|b| {
            json!({
                "host_id": b["key"],
                "event_count": b["event_count"]["value"],
                "last_seen": b["last_seen"]["value_as_string"],
            })
        })
        .collect();

    Ok(Json(json!({ "hosts": hosts, "total": hosts.len() })))
}

fn resolve_index(state: &AppState) -> String {
    if state.es_daily_index {
        format!("{}*", state.es_query_index)
    } else {
        state.es_query_index.clone()
    }
}
