//! HTTP 去重优化：使用哈希值作为 key，避免存储完整字符串。

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;

/// HTTP 去重键（使用哈希值而非完整字符串）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HttpDedupKey {
    /// 五元组 + 方法 + URL 的组合哈希
    combined_hash: u64,
}

impl HttpDedupKey {
    /// 从请求参数创建去重键
    #[inline]
    pub fn from_request(
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        method: &str,
        url: &str,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        src_ip.hash(&mut hasher);
        dst_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
        dst_port.hash(&mut hasher);
        method.hash(&mut hasher);
        url.hash(&mut hasher);
        Self {
            combined_hash: hasher.finish(),
        }
    }

    /// 从响应参数创建去重键
    #[inline]
    pub fn from_response(
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        status: u16,
    ) -> Self {
        let mut hasher = DefaultHasher::new();
        src_ip.hash(&mut hasher);
        dst_ip.hash(&mut hasher);
        src_port.hash(&mut hasher);
        dst_port.hash(&mut hasher);
        status.hash(&mut hasher);
        Self {
            combined_hash: hasher.finish(),
        }
    }
}

/// HTTP L7 去重窗口管理
pub struct HttpDedupWindow {
    /// key -> last_seen_timestamp_ms
    window: HashMap<HttpDedupKey, u64>,
    window_ms: u64,
    last_prune: Instant,
}

impl HttpDedupWindow {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window: HashMap::with_capacity(4096),
            window_ms,
            last_prune: Instant::now(),
        }
    }

    /// 检查是否应该丢弃（已存在且在窗口内），返回 true 表示需要丢弃
    #[inline]
    pub fn should_drop(&mut self, key: HttpDedupKey, now_ms: u64) -> bool {
        if self.window_ms == 0 {
            return false;
        }

        if let Some(&last_ts) = self.window.get(&key) {
            if now_ms.saturating_sub(last_ts) < self.window_ms {
                // 在窗口内，更新时间戳并丢弃
                self.window.insert(key, now_ms);
                return true;
            }
        }

        // 不在窗口内或首次出现，记录并允许
        self.window.insert(key, now_ms);
        false
    }

    /// 定期清理过期条目
    pub fn prune(&mut self, now_ms: u64) {
        if self.last_prune.elapsed().as_secs() < 60 {
            return;
        }

        let max_age = self.window_ms.saturating_mul(10).max(60_000);
        self.window
            .retain(|_, ts| now_ms.saturating_sub(*ts) < max_age);
        self.last_prune = Instant::now();
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.window.len()
    }

    pub fn update_window(&mut self, window_ms: u64) {
        self.window_ms = window_ms;
    }
}

/// Flow SYN 去重（按 src_ip + dst_port）
pub struct FlowSynDedupWindow {
    /// (src_ip_hash, dst_port) -> last_seen_ms
    window: HashMap<(u64, u16), u64>,
    window_ms: u64,
}

impl FlowSynDedupWindow {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window: HashMap::with_capacity(2048),
            window_ms,
        }
    }

    #[inline]
    pub fn should_drop(&mut self, src_ip: &str, dst_port: u16, now_ms: u64) -> bool {
        if self.window_ms == 0 {
            return false;
        }

        // 使用哈希值而非完整字符串
        let mut hasher = DefaultHasher::new();
        src_ip.hash(&mut hasher);
        let src_hash = hasher.finish();

        let key = (src_hash, dst_port);

        if let Some(&last_ts) = self.window.get(&key) {
            if now_ms.saturating_sub(last_ts) < self.window_ms {
                self.window.insert(key, now_ms);
                return true;
            }
        }

        self.window.insert(key, now_ms);
        false
    }

    pub fn prune(&mut self, now_ms: u64) {
        let max_age = self.window_ms.saturating_mul(10).max(60_000);
        self.window
            .retain(|_, ts| now_ms.saturating_sub(*ts) < max_age);
    }

    #[allow(dead_code)]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.window.len()
    }

    pub fn update_window(&mut self, window_ms: u64) {
        self.window_ms = window_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_dedup_window() {
        let mut window = HttpDedupWindow::new(1000);

        let key = HttpDedupKey::from_request(
            "192.168.1.1",
            "192.168.1.2",
            12345,
            80,
            "GET",
            "/index.html",
        );

        // 首次出现，不丢弃
        assert!(!window.should_drop(key, 1000));

        // 在窗口内再次出现，应该丢弃
        assert!(window.should_drop(key, 1500));

        // 超出窗口，不丢弃
        assert!(!window.should_drop(key, 3000));
    }

    #[test]
    fn test_flow_syn_dedup() {
        let mut window = FlowSynDedupWindow::new(1000);

        // 首次
        assert!(!window.should_drop("1.2.3.4", 443, 1000));

        // 窗口内重复
        assert!(window.should_drop("1.2.3.4", 443, 1500));

        // 窗口外
        assert!(!window.should_drop("1.2.3.4", 443, 3000));
    }

    #[test]
    fn test_dedup_key_different_urls() {
        let key1 = HttpDedupKey::from_request("1.1.1.1", "2.2.2.2", 1, 80, "GET", "/a");
        let key2 = HttpDedupKey::from_request("1.1.1.1", "2.2.2.2", 1, 80, "GET", "/b");

        // 不同 URL 应该产生不同的 key
        assert_ne!(key1, key2);
    }
}
