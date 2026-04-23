# hids

当前项目是一个以 eBPF 为核心的主机侧监测 Agent，默认只做采集和上报，不做阻断。

各源码文件职责见 **[CODE_OVERVIEW.md](./CODE_OVERVIEW.md)**，架构说明见 **[MONITORING.md](./MONITORING.md)**。

## 环境要求

1. stable rust: `rustup toolchain install stable`
1. nightly rust: `rustup toolchain install nightly --component rust-src`
1. Linux kernel >= 5.8（建议 >= 5.15）
1. `bpf-linker`: `cargo install bpf-linker`
1. 建议安装 `bpftool` 便于排障

## 构建与运行

```shell
cargo build -p hids --release
sudo ./target/release/hids
```

## 当前功能总览

### 事件类型（`event_kind`）

- `0`: bash 命令行（`/bin/bash:readline` uretprobe）
- `2`: XDP 五元组流（重点是入站 TCP SYN）
- `3`: 用户态明文 HTTP L7（请求/响应解析）
- `4`: 进程创建（`execve`）
- `5`: 进程退出（`exit/exit_group`）
- `6`: 文件变更（inotify 类监听）
- `7`: TLS 明文（OpenSSL `SSL_read` / `SSL_write`）

### 网络与协议能力

- **XDP（kind=2）**
  - 端口可配置：`xdp_capture_all_ports` 或 `xdp_sensitive_ports`
  - 上报五元组、方向、flags、关联键

- **HTTP L7（kind=3）**
  - 监听 `http_l7_ports`（明文 HTTP）
  - 解析 method/url/host/cookie/status/body_trunc
  - 去重窗口 + 静态资源过滤
  - 与 flow 用 `flow_correlation_key` 对齐

- **TLS 明文（kind=7）**
  - uprobe OpenSSL `SSL_write` / `SSL_read`
  - 支持按 `tls_target_comm`、`tls_target_port` 过滤
  - 尽量重组 HTTP/1.x，无法完整重组时回退上报片段
  - 解析 `http_method` / `http_url` / `http_status` / `http_body_trunc`
  - SQLi 关键字检测：命中填 `tls_threat=sqli_keyword`
  - 支持连接级关联键（`ssl_ptr`）
  - **best-effort 绑定来源/目的 IP**
    - 内核记录 `SSL* -> fd`
    - 用户态通过 `/proc/<tgid>/fd` + `/proc/*/net/tcp` 还原四元组并回填到 `flow_src_*`/`flow_dst_*`
    - 若连接复用或时序未命中，可能出现少量 kind=7 无 IP（这是当前已知边界）

### 通用字段与上报

- 每条事件携带 `local_ip`（本机地址）
- 批量发送（envelope + `events[]`），服务端可拆分逐条入库
- 失败时写入 spool，网络恢复后回放（at-least-once）
- 当前默认 `schema_version=3`

## 配置说明（核心项）

可用 `hids-agent.json` 或环境变量覆盖（`HIDS_*`）。

- `ingest_url`: 上报地址（如 `http://127.0.0.1:8000/ingest`）
- `config_reload_interval_secs`: 热重载轮询间隔
- `xdp_enabled` / `xdp_iface` / `xdp_skip_ips`
- `xdp_capture_all_ports` / `xdp_sensitive_ports`
- `http_l7_ports`
- `http_l7_dedup_window_ms`
- `http_l7_ignore_path_prefixes` / `http_l7_ignore_path_suffixes`
- `http_l7_capture_response`
- `proc_monitor_enabled`
- `file_watch_paths`
- `tls_monitor_enabled`
- `tls_libssl_path`（`auto` 或绝对路径）
- `tls_target_comm`（如 `nginx`）
- `tls_target_port`（`0` 表示关闭端口过滤）

## 运行权限建议

建议直接 root 运行。若非 root，需要按环境补齐 eBPF / raw socket / XDP 相关 capability。

## 常见问题

- **只看到 443 的 kind=2，没有 kind=7**
  - 说明 XDP 命中但 TLS 明文链路未命中或被过滤
  - 检查：`tls_monitor_enabled`、`tls_target_comm`、`tls_target_port`
  - 建议先用 `curl -k --http1.1 -H "Connection: close"` 触发新连接验证

- **kind=7 有明文但缺少来源 IP**
  - 当前是 best-effort 绑定（依赖 `SSL*->fd` 和 `/proc/net/tcp`）
  - 连接复用、时序、命名空间等因素可能导致个别事件无 IP

- **日志刷屏 HTML 报错页**
  - 客户端已改为仅打印失败 body 预览
  - 服务端请确认 `ingest_url` 路径和协议正确（通常是 `/ingest`）

## 快速验证（HTTPS POST）

1. `hids-agent.json` 里开启 TLS：
   - `tls_monitor_enabled: true`
   - `tls_target_comm: "nginx"`
   - `tls_target_port: 443`（或先设 `0` 排障）
2. 启动 agent：`sudo ./target/release/hids`
3. 发请求：
   - `curl -k --http1.1 -H "Connection: close" -X POST "https://127.0.0.1/login" -d '{"id":1}'`
4. 预期：
   - kind=7 出现 `tls_payload_trunc`
   - POST 出现 `http_method=http POST`（字段为 `POST`）和 `http_body_trunc`
   - 条件命中时出现 `flow_src_ip`/`flow_dst_ip`

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
