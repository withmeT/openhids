use std::{
    fs,
    io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

/// 失败后落盘的简单 spool（JSON 文件），用于断网时的“至少一次”投递。
///
/// 注意：这里的预算逻辑只用于你当前的原型；后续如果你做大规模部署，可以替换为更完善的队列/日志系统。
pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
}

impl Spool {
    pub fn new(dir: impl Into<PathBuf>, max_bytes: u64) -> Self {
        Self {
            dir: dir.into(),
            max_bytes,
        }
    }

    fn ensure_dir(&self) -> io::Result<()> {
        fs::create_dir_all(&self.dir)
    }

    pub fn enqueue(&self, bytes: &[u8]) -> io::Result<PathBuf> {
        self.ensure_dir()?;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let pid = std::process::id();
        let path = self.dir.join(format!("{ts}-{pid}.json"));
        fs::write(&path, bytes)?;
        self.enforce_budget()?;
        Ok(path)
    }

    pub fn list_files_oldest_first(&self) -> io::Result<Vec<PathBuf>> {
        let mut items: Vec<(SystemTime, PathBuf)> = Vec::new();
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let meta = entry.metadata().ok();
            let mtime = meta
                .and_then(|m| m.modified().ok())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            items.push((mtime, path));
        }
        items.sort_by_key(|(t, _)| *t);
        Ok(items.into_iter().map(|(_, p)| p).collect())
    }

    fn total_bytes(&self) -> io::Result<u64> {
        let mut sum = 0u64;
        if !self.dir.exists() {
            return Ok(0);
        }
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                sum = sum.saturating_add(meta.len());
            }
        }
        Ok(sum)
    }

    fn enforce_budget(&self) -> io::Result<()> {
        let mut total = self.total_bytes()?;
        if total <= self.max_bytes {
            return Ok(());
        }
        let files = self.list_files_oldest_first()?;
        for f in files {
            if total <= self.max_bytes {
                break;
            }
            if let Ok(meta) = fs::metadata(&f) {
                let _ = fs::remove_file(&f);
                total = total.saturating_sub(meta.len());
            } else {
                let _ = fs::remove_file(&f);
            }
        }
        Ok(())
    }
}

