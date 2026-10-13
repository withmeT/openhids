# 兼容性矩阵

> 原则：**只记录实际测试过的组合**。未列出 = 未验证，不代表不支持。
> 欢迎提交 Issue 补充你的环境测试结果（附内核版本与功能验证情况）。

## Agent（Rust + eBPF）

| 发行版 | 版本 | 架构 | 内核 | 探针验证 | 状态 | 测试时间 |
|---|---|---|---|---|---|---|
| EL9 系（RHEL/Rocky/Alma） | 9.7 | x86_64 | 5.14.0-611 | readline / exec·exit / XDP / SSL uprobe | ✅ 通过 | 2026-10 |
| openEuler | — | x86_64 / AArch64 | — | — | 未验证 | — |
| Anolis OS | — | x86_64 | — | — | 未验证 | — |
| 麒麟 | — | — | — | — | 未验证 | — |
| 统信 UOS | — | — | — | — | 未验证 | — |
| Ubuntu | — | x86_64 | — | — | 未验证 | — |
| Debian | — | x86_64 | — | — | 未验证 | — |

最低要求：Linux kernel ≥ 5.8（RingBuf），建议 ≥ 5.15。

## 服务端

| 组件 | 验证版本 | 状态 |
|---|---|---|
| Python | 3.11 | ✅ CI + 实机 |
| FastAPI | 0.143 | ✅ |
| Elasticsearch | 8.15 | ✅ |
| Rust（服务端/agent 构建） | stable（edition 2024） | ✅ CI |

## 已知限制

- 仅支持 OpenSSL 动态链接的进程做 TLS 明文采集（静态链接/其他 TLS 库不支持）
- bash 命令采集依赖 `/bin/bash` 的 `readline` 符号（其他 shell 不采集）
- XDP 需网卡驱动支持（generic 模式兜底，性能略降）

## 如何提交兼容性报告

1. 跑通 [README 快速开始](../README.md#快速开始) 全流程
2. 记录：发行版/内核版本（`uname -r`）、架构、哪些 event_kind 正常产生
3. 提交 Issue，标题 `[compat] <发行版> <版本> <架构>`
