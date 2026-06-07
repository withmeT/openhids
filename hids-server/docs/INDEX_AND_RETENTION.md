# 索引与保留策略

## 索引命名

| 环境变量 | 默认 | 说明 |
|----------|------|------|
| `ES_INDEX` | `hids-events` | 全量事件 |
| `ES_ALERTS_INDEX` | `hids-alerts` | 威胁镜像（`threat.level` ≥ `ES_ALERTS_MIN_LEVEL`） |
| `ES_DAILY_INDEX` | 建议生产 `true` | 追加 `-YYYY.MM.DD`，如 `hids-events-2026.05.19` |

模板 `elasticsearch/index-template.json` 匹配 `hids-events-*` 与 `hids-alerts-*`。

## 初始化 ES

```bash
cd hids-server
cp .env.example .env   # 按需修改 ES_URL / 认证
chmod +x scripts/apply-es-template.sh scripts/replay-spool.sh
./scripts/apply-es-template.sh
```

## ILM

`elasticsearch/ilm-policy.json` 定义 `hids-events-policy`：

- **hot**：rollover（1 天或 30GB）
- **warm**：7 天后 shrink + forcemerge
- **delete**：30 天后删除

若集群未启用 ILM，可仅使用 index template 的 mapping，手动按日创建索引。

## Spool 重放

Bulk 失败时 NDJSON 落在 `SPOOL_DIR`（默认 `./spool-server`）：

```bash
ES_URL=http://127.0.0.1:9200 ES_INDEX=hids-events ES_DAILY_INDEX=true ./scripts/replay-spool.sh
```

## 运维接口

- `GET /healthz` — 队列容量、是否启用 YAML 规则、flow 过滤开关
- `GET /stats` — accepted、dropped_plain_syn_flow、ES flush 计数
