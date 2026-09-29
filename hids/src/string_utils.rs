//! 高效字符串处理工具，减少内存分配和拷贝。

use std::borrow::Cow;

/// 快速过滤不可打印字符，使用 Cow 避免不必要的分配。
#[inline]
pub fn sanitize_text_cow(s: &str, max_len: usize) -> Cow<'_, str> {
    if s.is_empty() {
        return Cow::Borrowed("");
    }

    // Fast path: 如果字符串全部可打印且未超长，直接返回原字符串引用
    let take_len = s.len().min(max_len);
    let slice = &s[..take_len];

    if slice.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        return Cow::Borrowed(slice.trim());
    }

    // Slow path: 需要过滤字符
    let mut out = String::with_capacity(take_len);
    for ch in slice.chars() {
        if out.len() >= max_len {
            break;
        }
        if ch.is_ascii_graphic() || ch == ' ' {
            out.push(ch);
        } else {
            out.push(' ');
        }
    }
    Cow::Owned(out.trim().to_string())
}

/// 优化的固定大小文本过滤（200 字符）
#[inline]
pub fn sanitize_text_200(s: &str) -> String {
    sanitize_text_cow(s, 200).into_owned()
}

/// 优化的固定大小文本过滤（1024 字符）
#[inline]
pub fn sanitize_text_1024(s: &str) -> String {
    sanitize_text_cow(s, 1024).into_owned()
}

/// 通用大小文本过滤
#[inline]
pub fn sanitize_text_n(s: &str, max_len: usize) -> String {
    sanitize_text_cow(s, max_len).into_owned()
}

/// 从固定大小的 C 字符串缓冲区提取字符串（优化版本）
#[inline]
pub fn cstr_from_fixed(buf: &[u8]) -> String {
    // 快速查找 NUL 终止符
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());

    if end == 0 {
        return String::new();
    }

    // 直接从 UTF-8 转换，避免额外分配
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_cow_no_allocation() {
        let s = "hello world";
        let result = sanitize_text_cow(s, 100);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_sanitize_with_filter() {
        let s = "hello\nworld\x00test";
        let result = sanitize_text_cow(s, 100);
        assert!(matches!(result, Cow::Owned(_)));
        assert!(result.contains("hello"));
    }

    #[test]
    fn test_cstr_from_fixed() {
        let buf = b"test\0\0\0\0";
        assert_eq!(cstr_from_fixed(buf), "test");

        let buf = b"\0\0\0\0";
        assert_eq!(cstr_from_fixed(buf), "");
    }
}
