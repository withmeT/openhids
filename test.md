README: eBPF HTTPS 威胁分析探测器 (Rust & Aya)
1. 项目概述
本项目是一个基于 eBPF (Aya 框架) 的主机入侵检测系统 (HIDS) 原型。其核心目标是在不配置代理、不导入证书、不修改业务逻辑的前提下，实现对主机上所有基于 OpenSSL 的 HTTPS 流量的无感解密，并重点审计 HTTP POST Body 中的 SQL 注入等威胁。

2. 核心技术栈
开发语言: Rust (Nightly 编译链)

eBPF 框架: Aya (纯 Rust 实现)

挂载点: Uprobe & Uretprobe (目标：libssl.so)

内核数据交换: BPF_MAP_TYPE_RINGBUF (高效、异步)

3. 拦截逻辑 (AI 实现指南)
A. 内核态 (eBPF 程序)
函数挂载: * SSL_write(SSL *ssl, const void *buf, int num): 挂载 uprobe。此时 buf 包含明文。

SSL_read(SSL *ssl, void *buf, int num): 挂载 uretprobe。函数返回后 buf 包含解密后的明文。

数据拷贝: 使用 bpf_probe_read_user 将用户态缓冲区数据拷贝到 eBPF 定义的结构体中。

数据结构:

Rust
#[repr(C)]
pub struct SslEvent {
    pub pid: u32,
    pub comm: [u8; 16], // 进程名
    pub len: u32,       // 实际数据长度
    pub data: [u8; 1024], // 截取前 1KB 数据进行分析
}
B. 用户态 (Rust Agent)
动态库发现: 自动定位系统中 libssl.so.3 或 libssl.so.1.1 的路径。

事件监听: 持续读取 RingBuffer。

威胁分析:

将接收到的字节流转为字符串。

SQL 注入检测逻辑: 使用正则或字符串匹配，搜索 SELECT, UNION, ' OR '1'='1', SLEEP( 等关键字。

输出格式: [DETECTION] PID: 123 | APP: curl | Payload: ... | Threat: SQL Injection

4. 给 AI 助手的 Prompt 指令 (直接复制使用)
"请基于 Aya 框架为我编写一个 Rust eBPF 项目。

内核态代码: 使用 uprobe 挂载到 /usr/lib/x86_64-linux-gnu/libssl.so.3 的 SSL_write 函数。通过 ctx.arg(1) 获取缓冲区指针，并使用 bpf_probe_read_user 拷贝前 512 字节的数据，通过 RingBuf 发送给用户态。

用户态代码: 负责加载 eBPF 程序，解析 RingBuf 传回的 SslEvent 结构体。如果 data 字段中包含关键词 'UNION SELECT' 或 'OR 1=1'，则在终端以红色高亮打印告警。

要求: 请给出 common.rs (共享结构体), main.rs (内核态), main.rs (用户态) 的核心代码片段。"

5. 本地环境要求
OS: Linux Kernel 5.8+ (为了支持 RingBuffer)

工具链: * rustup toolchain install nightly

cargo install bpf-linker

依赖库: libssl-dev

6. 验证测试
运行 Agent 后，在另一个终端执行以下命令模拟黑客攻击：

Bash
# 模拟一个带 SQL 注入载荷的 POST 请求
curl -X POST -d "username=admin&id=1' UNION SELECT 1,2,3--" https://www.google.com
预期结果: HIDS 终端应捕获到该明文 POST Body，并识别出 SQL 注入关键字。