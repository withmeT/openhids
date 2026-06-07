//! Best-effort on-disk spool when Elasticsearch bulk permanently fails.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use tracing::warn;

pub fn write_failed_bulk(spool_dir: &Path, body: &str) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(spool_dir).with_context(|| format!("create spool dir {}", spool_dir.display()))?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let path = spool_dir.join(format!("bulk-failed-{ts}.ndjson"));
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open spool file {}", path.display()))?;
    f.write_all(body.as_bytes())
        .with_context(|| format!("write spool file {}", path.display()))?;
    warn!("wrote failed bulk batch to {}", path.display());
    Ok(path)
}
