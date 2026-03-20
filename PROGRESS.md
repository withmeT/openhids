# HIDS 项目进度文档（当前工作流）

## 1. 当前状态（已完成）

### 命令记录（核心链路）

- eBPF：对 `/bin/bash` 的 `readline` 返回点挂载 `uretprobe`，捕获用户在 bash 里输入的命令行字符串
- eBPF -> 用户态：通过 `RingBuf`（map 名称：`EVENTS`）上报 `CommandEvent`（pid/uid/tgid/comm/line）
- 命令执行结果（Scheme A，当前最小实现）：用户态基于额外的 `execve`/`exit` tracepoint 事件，在“时间窗口内”把子进程退出码关联到最近的 bash 输入命令，生成 `event_kind=1` 的 `command_result` 事件。注意：bash 内建命令（如 `cd`）通常没有 execve，因此结果可能缺失；复杂并发/流水线的精确关联是 best-effort
- 用户态 Agent：
  - 从 `RingBuf` 持续消费事件
  - 使用“**双阈值批量**”：达到 `flush_bytes` 或 `flush_interval_ms` 或 `flush_max_events` 任一条件就 flush
  - 空闲不发送（没有新事件不会触发 flush）
  - 失败发送：落盘 spool（`./spool`），并在网络恢复时后台重放
  - spool 预算：**<= 100MB**（超出会删最旧文件，保证磁盘上限）
- 传输：HTTP `POST` 到接收端 `HIDS_INGEST_URL`（默认 `http://127.0.0.1:8000/ingest`）

### 结构重构（为后续扩展做准备）

- `hids/src/main.rs`：仅保留入口，转为调用模块
- `hids/src/` 已拆分为：
  - `agent.rs`：主流程（load/attach、ringbuf consume、batch/send/spool/retry）
  - `batcher.rs`：双阈值批量器
  - `events.rs`：事件结构（AgentEvent）
  - `spool.rs`：落盘 spool 队列（<=100MB）
  - `http_client.rs`：HTTP 发送与 spool drain
  - `utils.rs`：字符串/comm 解析等小工具
  - `features/`：未来功能占位（文件变动检测、XDP 流量分析）
- `hids-ebpf/src/` 已拆分为：
  - `maps.rs`：共享 map（`EVENTS` ringbuf）
  - `probes/readline_uretprobe.rs`：当前实现的 readline 探针
  - `main.rs`：只保留 license/panic_handler + `mod maps; mod probes;`

### 本地测试工具

- 当前目录提供了临时接收端 `receiver.py`：会把收到的 batch 中每条写入 `received.jsonl`，用于验证“每条都到达”。

## 2. 当前缺口（尚未实现）

- 文件变动检测（占位模块，未做实际采集逻辑）
- XDP 流量分析（占位模块，未做实际 eBPF 采集与用户态聚合/发送）
- 多探针的统一事件模式（目前事件格式只覆盖命令记录；后续会增加网络/文件等事件类型）
- ES 索引/字段模板（目前只是本地 HTTP + json 验证链路）

## 3. 下一步推荐功能（优先级）

### 工程增强（建议在 P1 之前做，避免后续改动影响现有链路）
- **配置集中管理**：把所有 `HIDS_*` 配置（如 `HIDS_INGEST_URL`、`HIDS_FLUSH_*`、spool 路径、max send batches 等）统一放到 `config` 模块中，导出一个 `Config` 结构体，`agent` 只读取 `Config`，避免主循环里散落环境变量读取逻辑。
- **动态调整方式**：配置文件（默认 `./hids-agent.json`）提供默认值；环境变量仅用于覆盖。Agent 运行时会按 `HIDS_CONFIG_RELOAD_INTERVAL_SECS` 周期性重载配置，并热更新 `ingest_url/flush` 等可安全变更项。
- **版本控制（agent/schema 版本）**：在构建阶段注入 `git commit sha`、构建时间和 `schema_version`；运行时打印版本，并把版本字段随同事件一起发送（便于 ES 入库时做解析兼容，避免升级后字段类型变化导致写入失败）。
- **host_id（机器标识）**：每个上报 batch envelope 都携带 `host_id`（默认从 `/etc/machine-id`/`/var/lib/dbus/machine-id`/`HOSTNAME` 兜底），便于多主机索引与关联。

### P1：网络流量分析（你提到“加个流量分析”）

推荐优先级最高的原因：

- 能快速和命令记录形成关联（时间轴对齐：某条命令后产生的网络流量）
- XDP/TC 的采集可以在保持性能的同时给出可观测的网络行为
- 工程上容易复用现有“ringbuf -> batch/send/spool”的框架

推荐实现顺序（不改变你现有可靠送达框架）：

1. 基线：先做“可用的网络流聚合”（XDP 侧仅做 L3/L4 分类）
   - 解析：IPv4/IPv6 + TCP/UDP
   - key：5-tuple（先做准确聚合）；威胁检测可以额外准备更粗粒度 key（如 `src_ip + dst_port`）
   - 内核侧 map：
     - `FLOW_STATS`：每个 flow 的包数/字节数/首次与最后时间戳
     - `THREAT_COUNTERS`：按威胁类型聚合计数（用于阈值触发）
2. 威胁检测：把你要识别的攻击拆成可落地的特征类别（先支持明文，后续再增强）
   - 现实约束：SSH/MySQL/HTTPS 常见是加密的
   - 建议优先用“行为/协议特征”：
     - SSH 弱口令/爆破：短窗口内同一 `src_ip` 对 `dst:22` 的连接/认证尝试次数过高 -> `ssh_bruteforce_suspected`
     - MySQL 弱口令/爆破：`dst:3306` 下握手与认证阶段尝试模式聚合（明文时可更细）-> `mysql_bruteforce_suspected`
     - 应用层目录扫描：明文 HTTP 下对 `path` 做高基数统计（unique paths 突增、敏感路径命中率高）-> `web_dir_scan_suspected`
     - 应用层 XSS/SQL 注入：明文 HTTP 对 query/body 做有限深度签名匹配（URL decode + 截断 + 大小写忽略）-> `web_xss_suspected` / `web_sqli_suspected`
3. 用户态聚合/发送（沿用你现有可靠送达框架）
   - 从 XDP 侧 map 周期性读取增量，或者在阈值命中时由内核 ringbuf 推事件
   - 归一化为统一事件格式（与命令事件共用发送通道：双阈值 batch + HTTP + spool <= 100MB + 失败重放）
4. 测试（建议先跑明文基线，再扩展）
   - SSH/MySQL：尽量用非 TLS 环境先验证“行为触发”是否生效
   - Web：用 nginx/apache 明文 HTTP；目录扫描用路径字典触发；XSS/SQLi 用 OWASP payload 触发签名匹配
   - 全流程：burst 压测下验证“接收端可验证到达”（复用 receiver.jsonl 行数/内容校验）

### P2：execve / openat / file-access 采集（与“文件变动检测”方向一致）

- 先做“事件级可用”（exec/open 的元信息），再做完整策略（规则/告警/完整性基线）

### P3：更强关联（命令 <-> 网络/文件的进程级关联）

- 对“精确到进程的网络连接/文件打开”一般需要在 socket/LSM/tracepoint 层面做额外采集与关联

## 4. 预计开发节奏（粗略）

- 0.5-1 天：把 XDP 采集链路从占位变为可跑（eBPF + 用户态聚合 + 发送 + receiver 验证）
- 0.5-1 天：完善事件结构（事件类型、字段、去重策略、时间戳、主机标识 host_id）
- 0.5 天：加入 ES 落库前的字段规范/索引模板草案（保证 mapping 不炸）

## 5. 你接下来需要做的选择（建议）

- XDP 采集目标粒度：只做流（5-tuple 统计）还是要进程级网络（更复杂，涉及更多探针/关联）
- 你的环境网络接口：agent 需要知道把 XDP 挂到哪个网卡（自动枚举也可以后续做）

