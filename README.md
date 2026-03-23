# hids

各源码文件职责说明见 **[CODE_OVERVIEW.md](./CODE_OVERVIEW.md)**。

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. Linux kernel >= 5.8（RingBuf 需要；建议 >= 5.15）
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)
1. (recommended) `bpftool` for debugging: install from your distro packages

## Build & Run

本项目是一个最小可跑的 HIDS 原型：

- eBPF 程序：对 `/bin/bash` 的 `readline` 做 `uretprobe`，捕获返回值（用户刚输入的命令行）
- 用户态：从 eBPF `RingBuf` 读取事件并打印

Use `cargo build`, `cargo check`, etc. as normal. Build & run with:

```shell
cargo build -p hids --release
sudo ./target/release/hids
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Validate (quick test)

1. 开一个新的终端，运行上面的 `sudo ./target/release/hids`，看到提示 `Attached to /bin/bash:readline...`
2. 再开一个终端启动 bash：`/bin/bash`
3. 在 bash 里随便输入几条命令（例如 `id`、`uname -a`、`echo hello`）
4. 回到 hids 终端，你应该能看到类似输出：

```text
uid=0 tgid=12345 pid=12345 comm=bash line=id
```

注意：如果你在 bash 里执行的是 shell 内建命令（如 `cd`），依然会被捕获，因为它来自 readline 输入。

## Troubleshooting

- **无法 attach / 没有输出**：确认目标是 `/bin/bash`，以及 bash 确实使用了 `readline`（多数发行版默认是）。
- **权限错误**：需要 root（或者正确配置 `CAP_BPF`/`CAP_SYS_ADMIN`，以及允许加载 eBPF）。
- **内核限制/安全策略**：某些环境（如容器、受限内核、SELinux policy）可能阻止 uprobe 或 BPF；可用 `dmesg` / `bpftool prog show` 辅助排查。
- **访问了某端口（如 9200 ES、自定义业务口）但没有任何 flow / HTTP 提示**：
  - **XDP flow（event_kind=2）** 只在 **目标端口** 属于 eBPF 内建的「敏感端口」列表时才会对 **入站 TCP SYN** 上报；不在列表里的端口不会出现 flow 事件（**改列表需改 eBPF 并重编、重启 Agent**）。
  - **HTTP L7（event_kind=3）** 只嗅探配置里的 **`http_l7_ports`**（默认含 80、8080、8000、**9200**）；请把业务明文 HTTP 端口写进 `hids-agent.json` 或 `HIDS_HTTP_L7_PORTS`，修改后热重载即可（无需重启）。
  - **Docker 映射**：若你从外网打的是 **宿主机 IP:9200**，数据包目的 IP 应是宿主机网卡 IP，一般能命中「入站」；若直接访问 **容器 IP**（非 `LOCAL_IPS` 里的地址），XDP 可能不把该流标成入站，需把该网段纳入本机 IP 检测或调整部署。

## 运行权限与能力（建议阅读）

Agent 默认以 **root** 运行（`sudo ./target/release/hids`），典型需求如下：

| 能力 | 用途 |
|------|------|
| **root** 或 **`CAP_BPF` + `CAP_PERFMON` 等** | 加载 eBPF、挂载 uprobe/XDP（具体以发行版/内核策略为准）。 |
| **root** 或 **`CAP_NET_RAW` + `CAP_NET_ADMIN`**（视实现） | 用户态 **HTTP L7** 嗅探使用 `pnet_datalink` 抓包；无足够权限时网卡可能打开失败或收不到帧。 |
| **root**（推荐） | **XDP** 挂载到网卡；非 root 场景依赖内核/策略，通常仍建议 root。 |

精简结论：**生产环境建议直接 `sudo` 运行**；若坚持非 root，需按环境逐项授予上述 capability，并自行验证 attach/抓包是否成功。

## 路线图（P1 / P2 / P3）

### P1 — 采集更准、更稳（当前优先）

1. **配置热重载**：在 `config_reload_interval_secs` 周期内重读 `HIDS_CONFIG_PATH`（默认 `./hids-agent.json`）。**HTTP L7** 相关的 `http_l7_ports`、静态路径过滤、去重窗口可在运行时生效（嗅探线程通过共享状态更新）。**XDP**（`xdp_enabled` / `xdp_iface` / `xdp_skip_ips`）在进程启动时已加载 eBPF 并挂载网卡，**修改后需重启进程**才能重配 maps/挂载点。
2. **HTTP L7 去重**：相同五元组 + HTTP 方法 + URL 在 `http_l7_dedup_window_ms` 内只上报一次；`0` 关闭去重。
3. **静态资源过滤（可配置）**：`http_l7_ignore_path_prefixes` / `http_l7_ignore_path_suffixes` 用于降噪（如 `/favicon.ico`、`*.js`）。
4. **权限与运行说明**：见上文「运行权限与能力」。

### P2 — 协议与关联增强（已实现）

1. **更细的 HTTP 解析**：请求行解析外，提取 **Host**、**Cookie**（截断为线索字段）；可选嗅探本机 **出站 HTTP 响应**首行以解析 **状态码**（`http_l7_capture_response`，默认 `true`；可用 `HIDS_HTTP_L7_CAPTURE_RESPONSE=false` 关闭）。
2. **与 flow 关联**：`event_kind=2`（XDP flow）与 `event_kind=3`（HTTP L7）均带 **`flow_correlation_key`**，格式为 `tcp:客户端IP:端口->服务端IP:端口`（响应事件已规范化为与入站 flow 同一客户端→服务端方向，便于 JOIN）。时间对齐仍在平台侧按 `ts_ms` 窗口完成。
3. **schema**：默认 **`schema_version=2`**（新增字段）；旧接收端若只忽略未知字段可继续工作。

### P3 — 规模化与运维

- 采集端采样、限流、多队列；与 ingest 的背压策略文档化。
- HTTPS 侧信道（如 **TLS ClientHello 的 SNI**、**JA3** 等）需独立方案与合规评估，可作为后续阶段。

## 配置片段（HTTP L7，P1 / P2）

示例见 `hids-agent.json.example`。环境变量覆盖示例：

- `HIDS_HTTP_L7_PORTS=80,8080`
- `HIDS_HTTP_L7_DEDUP_WINDOW_MS=2000`（`0` 关闭去重）
- `HIDS_HTTP_L7_IGNORE_PREFIXES`：分号分隔，如 `/favicon.ico;/static/`
- `HIDS_HTTP_L7_IGNORE_SUFFIXES`：分号分隔，如 `.js;.css;.map`
- `HIDS_HTTP_L7_CAPTURE_RESPONSE=true|false`（P2：是否解析本机发出的 HTTP 响应状态码）
- `HIDS_XDP_CAPTURE_ALL_PORTS=true|false`（XDP 是否全端口采集；开启后事件量会明显增加）
- `HIDS_XDP_SENSITIVE_PORTS=22,80,443,3306,6379,8080,8000,9200`（仅在 `HIDS_XDP_CAPTURE_ALL_PORTS=false` 时生效）

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package hids --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/hids` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, hids is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
