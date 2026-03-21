1. 概述
本客户端是一款基于 eBPF/XDP 实现的轻量级主机入侵检测系统（HIDS）代理。
设计目标：

极低的 CPU 与内存开销
高吞吐事件采集
将分析逻辑卸载至服务端
聚焦网络与主机遥测数据


2. 核心职责
客户端负责：

采集遥测数据
过滤低价值流量
执行轻量级数据 enrichment（增强）
控制数据发送速率（采样 / 限流）
将事件上报至后端服务

客户端绝对不能执行威胁检测逻辑。

3. 事件类型
3.1 流事件（XDP）
表示网络连接尝试行为。
示例：json{
"event_kind": 2,
"ts_ms": 1773996945389,
"flow_src_ip": "27.185.27.40",
"flow_dst_ip": "192.168.4.169",
"flow_src_port": 3349,
"flow_dst_port": 22,
"flow_proto": 6,
"flow_payload_len": 72,
"tcp_flags": "SYN",
"direction": "inbound",
"is_sensitive_port": true
}


3.2 命令事件
表示进程执行活动。
示例：json{
"ts_ms": 1773988768041,
"uid": 1000,
"pid": 2036008,
"ppid": 2036000,
"comm": "bash",
"parent_comm": "sshd",
"line": "exit",
"cwd": "/home/user",
"tty": "/dev/pts/0"
}


4. 流过滤规则（关键）
仅上报高价值流量：
包含规则：

仅 TCP SYN 包
目标 IP 为本地主机
目标端口属于监控端口列表

默认监控端口：
22、80、443、3306、6379、8080、8000
排除规则：

DNS 响应（源端口 = 53）
已建立连接（ACK/PSH 包）
非服务类流量


5. 轻量级数据增强
每个流事件应包含：

tcp_flags（SYN/ACK/RST 等）
direction（入站 / 出站）
is_sensitive_port（布尔值）


6. 速率控制
防止系统过载：
采样（推荐）：

默认：高负载下 1/10 采样率

限流：

每秒最大事件数限制


7. 去重（可选）
在短时间窗口内（如 1 秒）：

合并相同五元组的流事件


8. 批量处理与传输

使用环形缓冲区（ring buffer）实现内核→用户空间数据传递
事件批量聚合后再发送
推荐传输协议：HTTP /gRPC


9. 性能要求

极小的内存占用
无锁或低锁设计
避免使用大型内存映射（maps）
避免按 IP 跟踪状态


10. 非目标范围
客户端绝对不能：

执行威胁检测
维护滑动时间窗口
运行正则表达式或 payload 深度检测
存储大量历史状态

所有分析逻辑必须在服务端完成。

11. 未来增强方向（可选）

捕获 payload 前 N 字节（如 64 字节）
增加 TCP 握手跟踪
支持 TLS 指纹（JA3）
扩展进程上下文（容器 / 命名空间）


12. 架构总结
XDP → 环形缓冲区 → 用户空间 → 过滤 → 批量聚合 → 上报
服务端负责：

数据聚合
威胁检测
告警生成




# eBPF HIDS 客户端（支持应用层检测）README

## 1. 设计目标

本客户端在保证低开销的前提下，支持基础应用层攻击检测能力。

原则：

* 不全量上传 payload
* 仅采集高价值数据
* 应用层分析在服务端完成

---

## 2. 数据采集策略

客户端采集两类数据：

### 2.1 流量事件（Flow）

用于行为分析（扫描 / 爆破 / DDoS）

### 2.2 应用层片段（Payload）

用于应用层攻击检测（SQLi / XSS / 扫描）

---

## 3. Payload 采集规则（核心）

### 3.1 采集范围（仅限以下端口）

```text
80, 8080, 8000
```

（仅支持明文 HTTP，不包含 HTTPS）

---

### 3.2 采集条件

仅当满足以下条件时采集 payload：

```text
- TCP 流量
- payload_len > 0
- 目标为本机
```

---

### 3.3 采集内容

仅提取：

```text
payload 前 64~128 字节
```

示例：

```text
GET /login.php?id=1 HTTP/1.1
```

---

### 3.4 数据结构示例

```json
{
  "event_kind": "http_payload",
  "ts_ms": 1773996945389,
  "src_ip": "1.2.3.4",
  "dst_ip": "192.168.4.169",
  "dst_port": 80,
  "payload_trunc": "GET /login.php?id=1 HTTP/1.1"
}
```

---

## 4. 流量控制（必须）

### 4.1 采样机制

高流量情况下：

```text
1/10 或 1/100 采样
```

---

### 4.2 限速机制

```text
限制每秒最大 payload 事件数
```

---

## 5. 客户端职责

客户端仅负责：

1. 采集 flow 数据
2. 过滤低价值流量
3. 提取少量 payload（截断）
4. 控制数据量
5. 上报服务端

---

## 6. 服务端职责

服务端负责：

1. HTTP 请求解析
2. URI / Query 提取
3. 攻击检测（SQLi / XSS / 扫描）
4. 威胁建模与告警

---

## 7. 不支持场景

当前方案不支持：

* HTTPS（443）内容分析
* 完整请求体分析
* 深度协议解析

---

## 8. 性能原则

* payload 必须截断
* 严禁全量上传
* 优先保证客户端稳定性

---

## 9. 后续扩展方向

* TLS 指纹（JA3）
* L7 代理（Envoy / Sidecar）
* 用户态 HTTP 解析优化

---

## 可操作优化清单（资源/效果优先级最高）

> 说明：本节把“设计目标”改写成工程可执行的 TODO，重点优化：
> 1) 客户端噪声（事件量）最小化
> 2) 服务端状态有界（滑动窗口/聚合内存不会无限增长）
> 3) 威胁规则可验收（每条规则都能用合成流量触发）

---

### A) 客户端（XDP）对齐规则：先把事件量砍下来

1. **Flow 只上报 TCP SYN（必须）**
   - 仅当 `proto=TCP 且 tcp_flags.SYN=1 且 tcp_flags.ACK=0`（即初始握手包）才上报 `event_kind=2`
   - 非 SYN 包（ACK/PSH/RST/FIN 等）直接丢弃（客户端职责：过滤低价值流量）
2. **仅监控本机（必须）**
   - `direction`：
     - `inbound`：`dst_ip` 属于本机地址
     - `outbound`：`src_ip` 属于本机地址
   - `is_sensitive_port`：`dst_port` 是否属于监控端口列表（`22/80/443/3306/6379/8080/8000`）
   - 只上报：`inbound 且 is_sensitive_port=true`（若你希望覆盖出站也可扩展，但先做 inbound）
3. **排除规则要落地**
   - DNS 响应：`src_port=53` 的包直接丢弃
   - 非服务类流量：`dst_port` 不在监控列表则丢弃
4. **enrichment（轻量字段，不要做深度解析）**
   - Flow 事件必须携带以下字段之一（推荐全带）：
     - `tcp_flags`（至少：SYN/ACK/RST）
     - `direction`（inbound/outbound）
     - `is_sensitive_port`（bool）
     - `payload_len`（可用 ip total_len 的粗略值）
5. **采样/限流（必须有界）**
   - 采样：高负载时对 `event_kind=2` 做 `1/10` 或 `1/100`（推荐使用 5-tuple 哈希确定采样，避免随机导致时窗抖动）
   - 限流：每秒最大事件数（建议 per-interface 或 per-CPU 维度限流）
6. **去重（可选但强烈建议）**
   - 1 秒内相同五元组（或 src_ip+dst_port+dst_ip+proto）去重，避免 burst 重复上报
   - 实现上推荐：
     - `LRU map`（大小受控）或
     - ringbuf 端快速 drop（不用维护复杂滑窗）

---

### B) 服务端（Threat Model）状态有界：滑动窗口聚合不能无限长

1. **每个窗口（30s/60s/5min/1s）都必须“可逐出（evict）”**
   - 维护结构里保存时间戳，并在每次写入/读取时逐出过期数据
   - 禁止：永远累积的 `dict[key] -> list`（会在高吞吐下爆内存）
2. **每个 key 维护上限（max samples / max keys）**
   - 例如：
     - beaconing：每个 `(src_ip,dst_ip)` 最多保留最后 N 个间隔样本（N=24）
     - unique 计数：每个窗口只保留最近一段时间，且对 key 总数设上限（超出丢弃/替换最旧 key）
3. **unique 计数的实现策略**
   - 简单版本：精确 unique（用时间逐出队列 + Counter）——可用于低中等 key 数
   - 高吞吐版本：建议替换为近似去重（如 HyperLogLog 或 Bloom/Count-Min 类），但必须有“可逐出”的近似结构

---

### C) 威胁检测规则：把 demo.md 的规则“工程化公式化”

> 规则应建立在客户端提供的 `event_kind=2`（flow）之上，且尽量依赖“行为计数/去重”，不依赖 payload。

#### 1. 端口扫描（Port Scan）
- 输入事件：`event_kind=2`（仅 SYN、inbound、is_sensitive_port=true）
- key：`src_ip`
- 30s 内：
  - `unique_dst_port > 20`
  - `total_conn > 30`
- 告警：`port_scan_suspected`

#### 2. 横向扫描（Lateral Movement）
- key：`(src_ip, dst_port)`
- 60s 内：
  - `unique_dst_ip > 20`
  - 且 `dst_port` 为固定监控端口（22/445/3306 等，先从 22/3306 做）
- 告警：`lateral_movement_suspected`

#### 3. 爆破攻击（Brute Force）
- key：`(src_ip, dst_port)`
- 30s 内：
  - `dst_port=22` 且 `connection_count > 20` -> `bruteforce_suspected (ssh)`
  - `dst_port=3306` 且 `connection_count > 10` -> `bruteforce_suspected (mysql)`
- 注意：只有 SYN 也能做（不依赖密码 payload）

#### 4. C2 / Beaconing
- key：`(src_ip, dst_ip)`
- 5min 内至少 N=6 次间隔样本
- 计算：
  - interval_mean（平均间隔）
  - interval_stddev（间隔标准差）
- 规则（建议可调）：
  - `stddev_ms < 300` 且 `mean_interval_ms` 落在合理范围（例如 5s~60s）
- 告警：`c2_beaconing_suspected`

#### 5. DDoS / Flood
- key：`dst_ip`
- 1s 内 `conn_rate = connections_count`
- 告警（示例阈值，需你根据环境压测调参）：
  - `conn_rate > 500` -> `ddos_flood_suspected`

---

### D) 告警生成与去重（避免刷屏）

1. **告警字段统一**
   - `alert_kind`
   - `ts_ms`
   - `key`
   - `severity`（可选）
   - `features`（规则命中的指标：unique_dst_port/conn_rate/stddev 等）
2. **冷却时间 cool_down（必须）**
   - 同一个 `(alert_kind, key)` 在 10s 内只输出一次（或你希望的更长时间）
3. **全局告警上限**
   - 每秒最多写入 N 条告警（防止服务端被告警 IO 打爆）

---

### E) 测试与验收（强制）

1. **合成 flow 触发器（建议保留脚本/命令）**
   - port scan：同 src_ip 在 30s 内访问 >20 个 dst_port 且 total_conn >30
   - brute force：同 src_ip 在 30s 内访问 dst_port=22 连接 >20 次
   - lateral：同 src_ip+dst_port 在 60s 内访问 >20 个 dst_ip
   - beacon：对同 src/dst 以近似固定间隔发包，验证 stddev 规则
2. **验收输出**
   - `received.jsonl`：原始 flow 事件必须连续写入
   - `alerts.jsonl`：每条规则命中至少输出 1 条告警
3. **容量验证**
   - burst 压测（例如模拟百万级 flow 的速率范围），确认：
     - 服务端内存稳定（key 数逐出）
     - ringbuf/批处理不无限增长（spool 预算上限生效）
