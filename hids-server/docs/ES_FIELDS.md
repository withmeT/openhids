# HIDS Elasticsearch 字段字典

面向「只查 ES、不做前端」的消费方。事件由 `hids-server` 在 ingest 时富化后写入 `hids-events-*`；`threat.level >= low` 的文档会镜像到 `hids-alerts-*`。

## 时间与排序

| 字段 | 类型建议 | 说明 |
|------|----------|------|
| `@timestamp` | `date` | 优先 `event_time_iso`，否则由 `ts_ms` 推导（+08:00） |
| `ts_ms` | `long` | Agent 事件时间（Unix 毫秒） |
| `ingest_ts_ms` | `long` | 服务端接收时间 |
| `ingest_time` / `event_time` | `keyword` | 中国时间可读字符串 |
| `ingest_time_iso` / `event_time_iso` | `date` | ISO +08:00，适合范围查询 |

**Kibana 时间轴**：使用 `@timestamp` 或 `event_time_iso`。

## 关联与 IP 归一化

| 字段 | 说明 |
|------|------|
| `client_ip` | 客户端：bash→`ssh_client_ip`，flow→`flow_src_ip`，HTTP/TLS→从 `flow_correlation_key` 解析 |
| `server_ip` | 服务端：`local_ip` 或 `flow_dst_ip` |
| `correlation_key` | 跨类型关联；优先 Agent 的 `flow_correlation_key` |
| `host_id` | 主机标识 |

## 威胁对象 `threat`

```json
{
  "level": "medium",
  "score": 22,
  "categories": ["shell"],
  "model_version": "hids-threat-0.2.0",
  "rules": [{ "id": "shell_suspicious_pattern", "severity": "medium", "category": "shell" }],
  "context": { "ssh_client_ip": "10.0.0.5" }
}
```

- `level`: `none` | `low` | `medium` | `high`
- `model_version`: 内置为 `hids-threat-0.1.0`；加载 YAML 时为 `rules/threat-rules.yaml` 中的 `version`

## event_kind 速查

| kind | 含义 |
|------|------|
| 0 | bash 命令行 |
| 2 | XDP flow |
| 3 | HTTP L7 |
| 7 | TLS 明文（uprobe） |

## 示例查询（Dev Tools）

最近 1 小时高危告警：

```json
GET hids-alerts-*/_search
{
  "size": 50,
  "query": {
    "bool": {
      "filter": [
        { "range": { "@timestamp": { "gte": "now-1h" } } },
        { "terms": { "threat.level": ["high", "medium"] } }
      ]
    }
  },
  "sort": [{ "@timestamp": "desc" }]
}
```

按客户端 IP 聚合 shell 威胁：

```json
GET hids-events-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term": { "event_kind": 0 } },
        { "range": { "threat.score": { "gte": 10 } } }
      ]
    }
  },
  "aggs": {
    "by_client": { "terms": { "field": "client_ip", "size": 20 } }
  }
}
```

同一关联键下的 HTTP + flow：

```json
GET hids-events-*/_search
{
  "query": {
    "term": { "correlation_key": "tcp:10.0.0.5:54321->10.0.0.1:443" }
  }
}
```
