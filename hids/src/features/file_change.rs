//! 关键路径文件变更（用户态 inotify / notify）。

use std::path::PathBuf;
use std::sync::mpsc;

use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};

/// 单条文件变更通知（归一化后送入 Agent 主循环）。
#[derive(Debug, Clone)]
pub struct FileWatchEvent {
    pub path: String,
    pub op: String,
}

/// 在独立线程中监听给定路径；路径为空则返回 `None`。
///
/// 对目录使用递归监听；对单独文件使用非递归。路径不存在时跳过（可在配置层保证先创建目录）。
pub fn spawn_file_watcher(paths: Vec<PathBuf>) -> Option<mpsc::Receiver<FileWatchEvent>> {
    if paths.is_empty() {
        return None;
    }

    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let (tx_notify, rx_notify) = mpsc::channel();
        let mut watcher = match RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                let _ = tx_notify.send(res);
            },
            Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                log::warn!("file watcher create failed: {e}");
                return;
            }
        };

        for p in &paths {
            if !p.exists() {
                log::warn!("file_watch path missing, skip: {}", p.display());
                continue;
            }
            let mode = if p.is_dir() {
                RecursiveMode::Recursive
            } else {
                RecursiveMode::NonRecursive
            };
            if let Err(e) = watcher.watch(p, mode) {
                log::warn!("file_watch watch failed {}: {e}", p.display());
            }
        }

        while let Ok(res) = rx_notify.recv() {
            match res {
                Ok(event) => {
                    let op = format!("{:?}", event.kind);
                    for path in event.paths {
                        let s = path.to_string_lossy().to_string();
                        if tx.send(FileWatchEvent { path: s, op: op.clone() }).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => log::warn!("file watcher event error: {e}"),
            }
        }
    });

    Some(rx)
}
