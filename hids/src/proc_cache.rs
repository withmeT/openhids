//! /proc 文件系统读取缓存，减少系统调用。

use std::collections::HashMap;
use std::fs;
use std::time::{Duration, Instant};

/// SSH 客户端 IP 解析结果缓存
pub struct SshClientCache {
    /// tgid -> (ssh_client_ip, last_seen)
    cache: HashMap<u32, (String, Instant)>,
    ttl: Duration,
}

impl SshClientCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            ttl,
        }
    }

    pub fn get_or_resolve<F>(&mut self, tgid: u32, resolver: F) -> Option<String>
    where
        F: FnOnce() -> Option<String>,
    {
        let now = Instant::now();

        // 检查缓存是否有效
        if let Some((ip, last_seen)) = self.cache.get(&tgid) {
            if now.duration_since(*last_seen) < self.ttl {
                return Some(ip.clone());
            }
        }

        // 缓存未命中或过期，重新解析
        if let Some(ip) = resolver() {
            self.cache.insert(tgid, (ip.clone(), now));
            Some(ip)
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn prune(&mut self) {
        let now = Instant::now();
        self.cache
            .retain(|_, (_, last_seen)| now.duration_since(*last_seen) < self.ttl);
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.cache.len()
    }
}

/// /proc/net/tcp 文件内容缓存
#[allow(dead_code)]
pub struct ProcNetTcpCache {
    content: String,
    last_read: Instant,
    ttl: Duration,
}

impl ProcNetTcpCache {
    #[allow(dead_code)]
    pub fn new(ttl: Duration) -> Self {
        Self {
            content: String::new(),
            last_read: Instant::now() - ttl,
            ttl,
        }
    }

    #[allow(dead_code)]
    pub fn get(&mut self) -> &str {
        let now = Instant::now();
        if now.duration_since(self.last_read) >= self.ttl {
            if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
                self.content = content;
                self.last_read = now;
            }
        }
        &self.content
    }

    #[allow(dead_code)]
    pub fn invalidate(&mut self) {
        self.last_read = Instant::now() - self.ttl;
    }
}

/// SSHD 祖先进程查找结果缓存（pid -> sshd_pid）
pub struct SshdAncestorCache {
    /// shell_pid -> (sshd_pid, last_seen)
    cache: HashMap<u32, (u32, Instant)>,
    ttl: Duration,
    max_entries: usize,
}

impl SshdAncestorCache {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            cache: HashMap::new(),
            ttl,
            max_entries,
        }
    }

    pub fn get_or_find<F>(&mut self, shell_pid: u32, finder: F) -> Option<u32>
    where
        F: FnOnce() -> Option<u32>,
    {
        let now = Instant::now();

        // 检查缓存
        if let Some((sshd_pid, last_seen)) = self.cache.get(&shell_pid) {
            if now.duration_since(*last_seen) < self.ttl {
                return Some(*sshd_pid);
            }
        }

        // 缓存未命中，执行查找
        if let Some(sshd_pid) = finder() {
            // 防止缓存无限增长
            if self.cache.len() >= self.max_entries {
                // 简单策略：清空一半最老的条目
                let mut entries: Vec<_> = self.cache.iter().map(|(k, (_, ts))| (*k, *ts)).collect();
                entries.sort_by_key(|(_, ts)| *ts);
                let remove_count = self.max_entries / 2;
                for (pid, _) in entries.iter().take(remove_count) {
                    self.cache.remove(pid);
                }
            }

            self.cache.insert(shell_pid, (sshd_pid, now));
            Some(sshd_pid)
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn prune(&mut self) {
        let now = Instant::now();
        self.cache
            .retain(|_, (_, last_seen)| now.duration_since(*last_seen) < self.ttl);
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.cache.len()
    }
}

/// 本机 IP 地址缓存（启动时检测一次，除非手动刷新）
pub struct LocalIpsCache {
    ips: Vec<String>,
    last_detected: Instant,
    ttl: Duration,
}

impl LocalIpsCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ips: Vec::new(),
            last_detected: Instant::now() - ttl,
            ttl,
        }
    }

    pub fn get<F>(&mut self, detector: F) -> &[String]
    where
        F: FnOnce() -> Vec<String>,
    {
        let now = Instant::now();
        if now.duration_since(self.last_detected) >= self.ttl {
            self.ips = detector();
            self.last_detected = now;
        }
        &self.ips
    }

    #[allow(dead_code)]
    pub fn invalidate(&mut self) {
        self.last_detected = Instant::now() - self.ttl;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_client_cache() {
        let mut cache = SshClientCache::new(Duration::from_secs(5));

        // 首次解析
        let ip = cache.get_or_resolve(1234, || Some("192.168.1.100".to_string()));
        assert_eq!(ip, Some("192.168.1.100".to_string()));

        // 缓存命中，resolver 不会被调用
        let ip = cache.get_or_resolve(1234, || panic!("should not be called"));
        assert_eq!(ip, Some("192.168.1.100".to_string()));

        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_sshd_ancestor_cache_max_entries() {
        let mut cache = SshdAncestorCache::new(Duration::from_secs(60), 5);

        // 填充超过 max_entries
        for i in 1..=10 {
            cache.get_or_find(i * 100, || Some(i * 10));
        }

        // 应该触发清理，保持在限制以下
        assert!(cache.len() <= 5);
    }
}
