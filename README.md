# hids

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
