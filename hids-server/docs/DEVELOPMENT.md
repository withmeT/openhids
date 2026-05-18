# HIDS Server 开发文档（ingest → 预处理 → Elasticsearch）

本文档面向后续开发：统一事件模型、写入 ES 的文档结构建议、按 `event_kind` 的分析与威胁检测扩展点。样例数据见仓库根目录 `test.jsonl` 及下文补充的 **Shell 遥测** 样例。

---

## 1. 当前服务行为（基线）

| 项目 | 说明 |
|------|------|
| HTTP 入口 | `POST /ingest`，请求体为 `{ "events": [ ... ] }`，数组内每项为一条 **Agent 事件**（JSON object）。 |
| ES 写入 | 每条 `events[]` 对应 bulk 中 **一行 `index` + 一行文档**；与客户端是否批量发送无关。 |
| 时间戳 | 若文档中无 `ingest_ts_ms`，服务端在入队前补充 **Unix 毫秒**（表示服务端接收时间）；已有则不改写。 |
| 配置 | 通过 `.env` / 环境变量（`BIND_ADDR`、`ES_URL`、`ES_INDEX`、认证、队列与 bulk 参数等）。 |
| 威胁预处理 | 入队前写入根字段 **`threat`**（`level` / `score` / `categories` / `rules` / `model_version`）；规则见 `src/threat/rules.rs`，SYN 短窗计数见 `src/threat/aggregate.rs`。 |

### 1.1 源码布局（按职责分文件，便于单步调试）

| 文件 | 职责 |
|------|------|
| `src/main.rs` | 进程入口，调用 `hids_server::run()`。 |
| `src/lib.rs` | 组装配置、后台 ES 任务、HTTP 服务。 |
| `src/config.rs` | 从环境变量读取运行参数（含 `THREAT_SYN_*`）。 |
| `src/models.rs` | `AgentEvent`、`IngestEnvelope`、`THREAT_MODEL_VERSION`。 |
| `src/enrich.rs` | `ingest_ts_ms` 等服务端富化。 |
| `src/error.rs` | HTTP 层 `AppError`。 |
| `src/app.rs` | `AppState`（队列发送端 + `SynBurstTracker`）。 |
| `src/routes.rs` | `/healthz`、`/ingest` 路由与 handler。 |
| `src/es_writer.rs` | Elasticsearch `_bulk` 批量写入。 |
| `src/threat/mod.rs` | 威胁合并逻辑（评分与 `threat` JSON）。 |
| `src/threat/rules.rs` | 粗粒度规则（可按 `event_kind` 扩展）。 |
| `src/threat/aggregate.rs` | SYN 短窗计数（DashMap，低开销并发）。 |

后续可在 `threat/` 下继续拆文件（例如 `rules_web.rs`、`rules_shell.rs`），无需胀大单一 `main.rs`。

---

## 2. 事件模型与 `event_kind` 对照（基于现有样例）

以下为根据 `test.jsonl` 与补充样例归纳的 **工程侧分类**，正式含义以探针/Schema 文档为准；实现时建议用 `schema_version` 做兼容分支。

| `event_kind` | 典型 `comm` / 场景 | 主要字段（非穷尽） | 分析侧重点 |
|----------------|-------------------|-------------------|------------|
| **0** | `bash` 等 Shell | `line`, `comm`, `uid`, `pid`, `tgid`, **`ssh_client_ip`**（若存在） | 交互式命令、危险命令模式、与 SSH 来源 IP 关联 |
| **2** | `xdp` | `flow_*`, `flow_correlation_key`, `flow_tcp_flags`, `local_ip` | SYN 扫描、敏感端口触碰、短窗口内高频连接 |
| **3** | `http_l7` | `http_status`, `http_body_trunc`, `flow_correlation_key` | 畸形请求、扫描佐证（常与 kind 2 同键关联） |
| **7** | `nginx` | `http_method`, `http_url`, `http_host`, `http_body_trunc`, `tls_*`, `flow_correlation_key` | Web 攻击语义、敏感 body、与 TLS/TCP 会话对齐 |

### 2.1 补充样例：Shell 遥测（`event_kind: 0`）

```json
{
  "event_kind": 0,
  "ts_ms": 1778756052602,
  "local_ip": "23.95.43.102",
  "uid": 0,
  "tgid": 188311,
  "pid": 188311,
  "comm": "bash",
  "line": "vim index.html ",
  "ssh_client_ip": "223.160.137.187",
  "agent_version": "ceb60f5b71b5",
  "schema_version": 4,
  "host_id": "6f9b28a107671d35d565db8d4fdf10a8"
}
```

**解读要点（写入 ES 前可做的分析，不等同最终定性）：**

1. **`line`**：原始命令行文本（注意首尾空格）；适合关键字/正则、分词、或后续接「命令解析器」（解析 argv、管道、下载器等）。
2. **`ssh_client_ip`**：表明该 Shell 会话与 **某 SSH 客户端 IP** 可关联；与 `event_kind: 2` 中同一 IP 对 22/443 的访问、或 `event_kind: 7` 的 Web 日志可做 **跨类型关联**（需统一时间窗与 `host_id`）。
3. **`uid` / `pid` / `tgid`**：区分 root 与普通用户、会话线程组；规则可区分「低权限可疑」与「高权限高危」。
4. **与网络样例的叙事关系（示例思路）**：若同一 `host_id`、相近 `ts_ms` 内，先出现来自 `223.160.137.187` 的敏感端口流，再出现带相同 `ssh_client_ip` 的 `bash` 行，可提升「需人工确认」优先级（仍建议输出 **证据链** 而非单一布尔「已入侵」）。

---

## 3. 写入 Elasticsearch 的文档结构建议

### 3.1 原则

- **一条 ES 文档 = 一条 Agent 事件**（当前已实现）。
- 探针原始字段 **平铺保留**（`event_kind`、`ts_ms`、`line`、`ssh_client_ip` 等），避免破坏下游已有查询。
- 服务端富化统一放在 **`hids`** 或 **`threat`** 命名空间下**（二选一或分层：`hids.*` 管道元数据，`threat.*` 安全结论）。

### 3.2 推荐嵌套字段（后续开发目标形态）

```json
{
  "event_kind": 0,
  "ts_ms": 1778756052602,
  "line": "vim index.html ",
  "ssh_client_ip": "223.160.137.187",
  "host_id": "...",
  "ingest_ts_ms": 1730000000000,

  "threat": {
    "level": "low",
    "score": 12,
    "categories": ["shell_activity"],
    "rules": [
      {
        "id": "shell_editor_invoked",
        "severity": "low",
        "evidence": { "pattern": "\\b(vim|vi|nano)\\b", "field": "line" }
      }
    ],
    "model_version": "ruleset-0.1.0"
  },

  "hids": {
    "pipeline": { "stage": "enrich_v0", "schema_version": 4 }
  }
}
```

字段说明：

| 字段 | 类型建议 | 含义 |
|------|-----------|------|
| `threat.level` | `keyword` | `none` / `low` / `medium` / `high`（或数值映射） |
| `threat.score` | `integer` | 多规则加权后的排序分 |
| `threat.categories` | `keyword` | 战术分类标签，便于聚合 |
| `threat.rules` | `nested` 或 `object`（数组） | 命中规则列表，**必须可解释**（`id` + `evidence`） |
| `threat.model_version` | `keyword` | 规则集 / 模型版本，便于回放与对比 |
| `hids.pipeline` | `object` | 预处理阶段、探针 `schema_version` 副本等 |

索引模板（index template）建议在 ES 侧为 `threat.*`、`hids.*` 显式 mapping，避免动态映射把数组字段映错。

---

## 4. 预处理流水线（后期开发拆分）

建议与 HTTP 接收解耦：**接收快路径 → 有界队列 → Worker 池（可选多阶段）→ Bulk 写 ES**。

| 阶段 | 输入 | 输出 | 说明 |
|------|------|------|------|
| **P0 校验** | 单条 JSON object | 合法则入队 | 已具备：对象校验、`ingest_ts_ms` |
| **P1 分类路由** | `event_kind` + `comm` | 内部枚举 / 小结构体 | 只把相关字段送入对应检测器，减少误匹配 |
| **P2 无状态规则** | 单条事件 | `threat.rules` 追加 | 正则、敏感端口、敏感 URL 前缀、敏感 body 模式等 |
| **P3 有状态聚合** | 流式键（如 `host_id`+`flow_src_ip`+`flow_dst_port`） | 窗口计数、扫描标记 | 针对 SYN 风暴、多源端口扫描（见既有 `test.jsonl` 中 80 端口样例） |
| **P4 关联** | `flow_correlation_key`、`ts_ms`、`host_id` | 跨 `event_kind` 证据链 | 2 → 3 → 7 或 2 → 0（IP 与时间对齐） |
| **P5 外部情报（可选）** | `flow_src_ip` / `ssh_client_ip` | 信誉标签 | 本地缓存 + 定期更新，避免 ingest 同步打外部 API |

失败策略：检测阶段异常不应丢原始事件；可写 `threat.error` 或降级为 `threat.level: none` 并打日志。

---

## 5. 按类型的检测扩展清单（实现 backlog）

### 5.1 `event_kind: 0`（Shell）

- [ ] 危险命令词典（下载执行、反弹 shell、chmod +x、/dev/tcp、base64 管道等），**分级**输出。
- [ ] 编辑器/解释器调用（`vim`/`vi`/`nano`/`python`）→ 低～中，结合路径与 `uid`。
- [ ] **`ssh_client_ip` 存在时**：写入 `threat.context.ssh_client_ip` 副本便于检索；与网络事件按 IP + 时间窗关联。
- [ ] 白名单：已知部署用户、自动化用户、`line` 前缀（CI、监控脚本）。

### 5.2 `event_kind: 2`（XDP 流）

- [ ] 敏感端口 + SYN + `flow_direction` 判定外网入站。
- [ ] 滑动窗口：同 src 对同 dst 端口的高频 distinct sport / SYN 计数 → `network_scan`。
- [ ] 与情报库匹配（可选）。

### 5.3 `event_kind: 3`（http_l7）

- [ ] 与 kind 2 同 `flow_correlation_key` 聚合，佐证扫描或畸形请求。

### 5.4 `event_kind: 7`（nginx L7）

- [ ] URL + body + `tls_payload_trunc` 的 Web 类规则（后续可映射 Sigma 子集或 CRS 类分类）。
- [ ] 登录路径 + 高频失败（需状态或 ES 侧聚合）→ 撞库/爆破 **候选**。
- [ ] 凭证形态出现在日志 → **敏感数据** 标签（合规向，不等同漏洞利用）。

---

## 6. 与开源 / 规则生态的衔接（后期）

- **Sigma**：将检测逻辑以 YAML 维护，Rust 侧实现「字段映射 + 条件求值」子集，或生成 ES DSL 做离线回放。
- **Suricata / Zeek**：若未来有镜像流量，可与主机 JSON **互补**，不在本文档范围内替代当前 ingest。
- **SamWAF / OWASP CRS 思路**：用于 **HTTP 语义层** 规则分类参考；不必嵌入 WAF 进程。

---

## 7. 开发检查清单（上线前）

- [ ] ES 索引模板：`threat`、`hids`、`ingest_ts_ms`、`ts_ms` 类型明确。
- [ ] 规则版本 `threat.model_version` 与发布流程绑定。
- [ ] 压测：队列满时返回码与客户端重试约定（当前为 503 类语义）。
- [ ] 隐私：`line`、`http_body_trunc` 是否需脱敏后再写 ES（合规需求单独立项）。

---

## 8. 文档维护

- 探针新增字段或 `event_kind` 枚举变更时：更新 **第 2 节表** 与 **第 5 节 backlog**。
- 规则调参记录：建议在独立仓库或本仓库 `docs/RULE_CHANGELOG.md` 维护（按需新增文件）。
