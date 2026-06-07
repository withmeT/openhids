//! Format Unix epoch millis as China Standard Time (UTC+8) for Elasticsearch display.

use chrono::{DateTime, FixedOffset};

/// 中国大陆常用时区（无夏令时），固定 UTC+8。
const CHINA_OFFSET_SEC: i32 = 8 * 3600;

fn china_offset() -> FixedOffset {
    FixedOffset::east_opt(CHINA_OFFSET_SEC).expect("UTC+8 offset")
}

/// `2026-05-14 18:55:48.222`（中国时间，便于 Kibana/控制台直接阅读）。
pub fn millis_to_china_display(millis: u64) -> Option<String> {
    let dt = DateTime::from_timestamp_millis(millis as i64)?.with_timezone(&china_offset());
    Some(dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
}

/// `2026-05-14T18:55:48.222+08:00`（ISO-8601，建议 ES `date` 映射）。
pub fn millis_to_china_iso(millis: u64) -> Option<String> {
    let dt = DateTime::from_timestamp_millis(millis as i64)?.with_timezone(&china_offset());
    Some(dt.format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string())
}

/// 从 JSON 数字字段读取毫秒时间戳（`u64` / `i64`）。
pub fn json_value_as_millis(v: &serde_json::Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    v.as_i64().and_then(|n| u64::try_from(n).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_china_time() {
        // 2026-05-14 10:55:48.222 UTC -> 18:55:48.222 +08:00
        let ms = 1_778_756_148_222u64;
        let s = millis_to_china_display(ms).unwrap();
        assert!(s.contains("18:55:48"));
        let iso = millis_to_china_iso(ms).unwrap();
        assert!(iso.contains("+08:00") || iso.contains("+0800"));
    }
}
