# 代码文件概览

本文档描述本仓库中**每个代码/配置相关文件**的职责，便于导航与二次开发。

---

## 仓库根目录


| 文件                        | 概述                                                               |
| ------------------------- | ---------------------------------------------------------------- |
| `Cargo.toml`              | Workspace 根：成员 crate（`hids`、`hids-common`、`hids-ebpf`）、共用依赖与许可证。 |
| `Cargo.lock`              | 依赖锁定版本，保证可复现构建。                                                  |
| `rustfmt.toml`            | `rustfmt` 格式化约定。                                                 |
| `.gitignore`              | Git 忽略规则（构建产物、本地配置等）。                                            |
| `README.md`               | 构建运行、校验、权限、路线图（P1/P2/P3）、配置说明。                                   |
| `MONITORING.md`           | **监测架构**：eBPF 与 `event_kind`、Maps、XDP 逻辑、用户态补充、运维建议。                    |
| `LICENSE-*`               | 许可证：用户态双许可；eBPF 代码 GPL2/MIT 可选。                                  |
| `hids-agent.json.example` | Agent JSON 配置示例（ingest、XDP、HTTP L7、exec/exit、TLS 明文观测等）。      |
| `hids-agent.json`         | 本地运行时配置（若存在；默认路径可被 `HIDS_CONFIG_PATH` 覆盖）。**通常不提交含密钥的真实文件。**     |


---

## `hids/`（用户态 Agent）


| 文件                                 | 概述                                                                                                                                        |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `hids/Cargo.toml`                  | Agent 二进制 crate：依赖 `aya`、`pnet_*`、`reqwest`、`tokio`、`hids-common` 等。                                                                      |
| `hids/build.rs`                    | 构建脚本：注入 `HIDS_GIT_SHA`、`HIDS_SCHEMA_VERSION`；调用 `aya_build` 编译并链接 `hids-ebpf`。                                                            |
| `hids/src/main.rs`                 | 程序入口：初始化日志，调用 `agent::run()`。                                                                                                             |
| `hids/src/agent.rs`                | **核心**：加载 eBPF（bash readline uprobe、可选 exec/exit tracepoint、可选 XDP）、RingBuf 消费、HTTP L7 嗅探、可选文件监视（notify）、配置热重载、批次与上报/spool。 |
| `hids/src/config.rs`               | 从 `hids-agent.json` 与 `HIDS_*` 环境变量加载/合并配置。                                                                                               |
| `hids/src/events.rs`               | 用户态事件与 ingest 信封的 **serde** 结构体（`AgentEvent`、`IngestEnvelope`），含 flow/HTTP 字段与 **P2** 扩展字段。                                               |
| `hids/src/batcher.rs`              | 按字节数/时间/条数阈值将 `AgentEvent` 聚批，减少 HTTP 请求次数。                                                                                               |
| `hids/src/http_client.rs`          | HTTP 客户端辅助（如 spool 回放/drain）。                                                                                                             |
| `hids/src/spool.rs`                | 磁盘队列：发送失败时落盘，恢复后重试。                                                                                                                       |
| `hids/src/utils.rs`                | 通用工具（如固定 C 字符串转 `String`）。                                                                                                                |
| `hids/src/features/mod.rs`         | 功能模块占位说明与 `pub mod`。                                                                                                                      |
| `hids/src/features/file_change.rs` | 用户态 **inotify 类** 目录/文件监听，产出 `event_kind=6`。                                                                 |
| `hids/src/features/xdp_traffic.rs` | XDP 相关用户态分析占位（未来扩展）。                                                                                                                      |


---

## `hids-common/`（内核与用户态共享类型）


| 文件                       | 概述                                                                                         |
| ------------------------ | ------------------------------------------------------------------------------------------ |
| `hids-common/Cargo.toml` | `no_std` 友好 crate，定义与 eBPF 共用的结构体布局。                                                       |
| `hids-common/src/lib.rs` | `**CommandEvent`**（readline）、`**FlowEvent**`（XDP 五元组）、以及预留的 Exec/Exit 等事件结构（`#[repr(C)]`）。 |


---

## `hids-ebpf/`（eBPF 程序）


| 文件                                                   | 概述                                                                         |
| ---------------------------------------------------- | -------------------------------------------------------------------------- |
| `hids-ebpf/Cargo.toml`                               | eBPF crate：`aya-ebpf`、`hids-common`（无 `user` feature）。                     |
| `hids-ebpf/build.rs`                                 | eBPF 侧构建辅助（由 workspace/aya 调用链处理）。                                         |
| `hids-ebpf/src/lib.rs`                               | eBPF crate 根，导出子模块。                                                        |
| `hids-ebpf/src/main.rs`                              | eBPF 程序镜像入口（`#![no_main]`），链接 maps 与 probes。 |
| `hids-ebpf/src/maps.rs`                              | eBPF **maps**：RingBuf（命令、exec、exit、flow）、SKIP_IPS、LOCAL_IPS、SENSITIVE_PORTS 等。 |
| `hids-ebpf/src/probes/mod.rs`                        | 探针子模块声明。                                                                   |
| `hids-ebpf/src/probes/readline_uretprobe.rs`         | 对 `/bin/bash` `readline` 的 **uretprobe**：将命令行写入 RingBuf（`CommandEvent`）。   |
| `hids-ebpf/src/probes/tls_ssl_uprobes.rs`            | OpenSSL `SSL_write`/`SSL_read` uprobe/uretprobe：输出 TLS 明文截断（测试场景）。 |
| `hids-ebpf/src/probes/xdp_flow5tuple.rs`             | **XDP**：解析 IPv4 TCP，**入站**敏感端口 **SYN** 上报 `FlowEvent`，全程 **XDP_PASS** 不丢包。 |
| `hids-ebpf/src/probes/proc_exec_exit_tracepoints.rs` | **tracepoint**：`sys_enter_execve`、`sys_enter_exit` / `exit_group`，写入 `EXEC_EVENTS` / `EXIT_EVENTS`。 |


---

## 其他（若存在于工作区）


| 文件                        | 概述                                   |
| ------------------------- | ------------------------------------ |
| `main.py` / `receiver.py` | 若存在：本地接收 ingest 的示例脚本（非 Agent 核心路径）。 |
| `PROGRESS.md`             | 若存在：项目进度/设计笔记。                       |


---

## 维护说明

- 修改 **`AgentEvent` 字段**时：同步更新 `hids/src/agent.rs` 中所有构造处、文档与 **`hids/build.rs` 默认 `HIDS_SCHEMA_VERSION`**（或通过环境变量显式指定）。
- **eBPF 与用户态**共享结构必须在 `hids-common` 中保持 **ABI 一致**（字段顺序与类型）。

