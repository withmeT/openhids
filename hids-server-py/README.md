# hids-server (Python)

HIDS 服务端的 Python / FastAPI 实现：接收 eBPF agent 上报的安全事件，完成富化、威胁检测、
Elasticsearch 批量入库，并提供查询 API、WebSocket 实时流、Web 控制台与加密基线控制面。

与 Rust agent（`hids/`）协议完全互通；功能上是 Rust 版 `hids-server` 的对等移植。

## 功能

| 能力 | 说明 |
|---|---|
| 事件摄取 | `POST /ingest`，Bearer/X-Api-Key 鉴权，gzip 批量上报，队满 503 背压 |
| 富化 | 时间戳/IP 归一化、跨事件 `correlation_key`、信封元数据注入 |
| 威胁检测 | 内建规则 + YAML 规则（`rules/threat-rules.yaml`）+ SYN 突发统计 → `threat.*` 字段 |
| ES 入库 | 后台聚批 `_bulk`（批满或 `FLUSH_MS` 到期冲刷）、SipHash 稳定 `_id` 幂等、指数退避重试、失败 spool 落盘 |
| 告警双写 | 达到 `ES_ALERTS_MIN_LEVEL` 的事件额外写入 `hids-alerts-*` |
| 查询 API | `/events/search` `/events/recent` `/alerts` `/hosts` |
| 实时流 | `GET /ws/events`（支持 kind / host / alerts_only 过滤） |
| Web 控制台 | `static/index.html` 单页应用，根路径直接访问 |
| 加密控制面 | `/commands*` 下发基线核查命令（AES-GCM + zstd，与 agent 二进制互通） |
| 运维 | `/healthz` `/stats`，ES 索引模板 + ILM 脚本 |

## 快速开始

要求 Python ≥ 3.11。

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e .

cp .env.example .env        # 按需修改 ES 地址、INGEST_TOKEN 等
python -m hids_server       # 或: hids-server
```

启动后：

- 控制台: http://127.0.0.1:8000/
- 健康检查: `curl http://127.0.0.1:8000/healthz`

首次使用前应用 ES 索引模板与 ILM 策略：

```bash
ES_URL=http://127.0.0.1:9200 ./scripts/apply-es-template.sh
```

## 配置

全部通过环境变量（自动加载当前目录 `.env`），与 Rust 版同名兼容。常用项见
[`.env.example`](.env.example)；完整列表与默认值见 [`hids_server/config.py`](hids_server/config.py)。

## 目录结构

```
hids_server/
  app.py         FastAPI 应用与全部路由（摄取/查询/控制面/WS/静态页）
  enrich.py      事件富化与 correlation_key
  filter.py      纯 SYN flow 降噪
  threat.py      内建 + YAML 威胁规则、SYN 突发统计
  es_writer.py   ES 聚批写入（重试/告警双写/spool 兜底）
  query.py       ES 查询封装
  ws.py          WebSocket 广播
  protocol.py    加密控制面协议（AES-GCM + zstd，与 Rust hids-protocol 互通）
  doc_id.py      SipHash-1-3 稳定文档 _id
  spool.py       失败批次落盘
  config.py      环境变量配置
elasticsearch/   索引模板 + ILM 策略
rules/           YAML 威胁规则
scripts/         apply-es-template.sh / replay-spool.sh
static/          Web 控制台
docs/            设计文档（入库链路见 docs/INGEST_PIPELINE.md）
tests/           pytest 单测
```

## 测试

```bash
pip install -e '.[dev]'
pytest
```

## 入库数据流

详见 [docs/INGEST_PIPELINE.md](docs/INGEST_PIPELINE.md)。概要：

```
POST /ingest → 鉴权 → gzip 解压 → SYN 降噪 → enrich → threat 打标
  → asyncio.Queue（背压）→ EsBulkWriter 聚批 → _bulk（幂等 _id）
  → 失败重试 → 永久失败 spool 落盘（replay-spool.sh 回放）
```

## License

MIT OR Apache-2.0
