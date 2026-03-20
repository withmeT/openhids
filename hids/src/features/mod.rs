//! 未来 HIDS 功能扩展的模块占位。
//!
//! 当前原型只实现了 eBPF -> ringbuf -> batch -> http ingest。
//! 这里为后续“文件变动检测、XDP 流量分析、多 eBPF 探针”等预留结构，
//! 避免你扩展时把现有逻辑继续塞进同一个大文件里。

pub mod file_change;
pub mod xdp_traffic;

