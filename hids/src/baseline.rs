//! Built-in, non-shell baseline checks executed from authenticated commands.
//!
//! The server can choose which check kind to run, but it cannot provide an
//! arbitrary command line. This keeps the control plane useful for inventory
//! and baseline checks without turning the agent into remote shell execution.

use std::{
    fs,
    io::{BufRead, BufReader},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use hids_protocol::{
    BaselineCheckKind, BaselineCheckResult, BaselineCheckSpec, BaselineCommand,
    BaselineResult, BaselineStatus,
};
use sha2::{Digest, Sha256};

const MAX_DETAILS: usize = 200;
const MAX_HASH_BYTES: u64 = 10 * 1024 * 1024;

pub fn execute(command: &BaselineCommand, allowed_paths: &[String]) -> BaselineResult {
    let now = now_ms();
    let mut results = Vec::with_capacity(command.checks.len());

    if command.expires_at_ms < now {
        results.push(BaselineCheckResult {
            id: "command".to_string(),
            kind: BaselineCheckKind::SystemInfo,
            status: BaselineStatus::Rejected,
            summary: "command expired".to_string(),
            details: Vec::new(),
        });
        return BaselineResult {
            request_id: command.request_id.clone(),
            host_id: command.host_id.clone(),
            completed_at_ms: now,
            results,
        };
    }

    for check in &command.checks {
        results.push(run_check(check, allowed_paths));
    }

    BaselineResult {
        request_id: command.request_id.clone(),
        host_id: command.host_id.clone(),
        completed_at_ms: now_ms(),
        results,
    }
}

fn run_check(check: &BaselineCheckSpec, allowed_paths: &[String]) -> BaselineCheckResult {
    match &check.kind {
        BaselineCheckKind::SystemInfo => system_info(check),
        BaselineCheckKind::ListeningPorts => command_output_check(
            check,
            "listening_ports",
            "ss",
            &["-lntup"],
        ),
        BaselineCheckKind::ProcessSummary => command_output_check(
            check,
            "process_summary",
            "ps",
            &["-eo", "pid=,comm=,user="],
        ),
        BaselineCheckKind::FileHashes => file_hashes(check, allowed_paths),
    }
}

fn system_info(check: &BaselineCheckSpec) -> BaselineCheckResult {
    let mut details = Vec::new();
    if let Ok(file) = fs::File::open("/etc/os-release") {
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if line.starts_with("PRETTY_NAME=")
                || line.starts_with("ID=")
                || line.starts_with("VERSION_ID=")
            {
                details.push(line);
            }
        }
    }
    if let Ok(output) = Command::new("uname").arg("-srmo").output() {
        if output.status.success() {
            details.push(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
    }
    let status = if details.is_empty() {
        BaselineStatus::Failed
    } else {
        BaselineStatus::Ok
    };
    BaselineCheckResult {
        id: check.id.clone(),
        kind: check.kind.clone(),
        status,
        summary: format!("collected {} system fields", details.len()),
        details,
    }
}

fn command_output_check(
    check: &BaselineCheckSpec,
    summary_name: &str,
    program: &str,
    args: &[&str],
) -> BaselineCheckResult {
    let output = Command::new(program).args(args).output();
    let Ok(output) = output else {
        return BaselineCheckResult {
            id: check.id.clone(),
            kind: check.kind.clone(),
            status: BaselineStatus::Failed,
            summary: format!("{summary_name} command unavailable"),
            details: Vec::new(),
        };
    };

    let details: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .take(MAX_DETAILS)
        .map(sanitize_line)
        .filter(|line| !line.is_empty())
        .collect();
    let status = if output.status.success() {
        BaselineStatus::Ok
    } else {
        BaselineStatus::Failed
    };
    BaselineCheckResult {
        id: check.id.clone(),
        kind: check.kind.clone(),
        status,
        summary: format!("{summary_name}: {} rows", details.len()),
        details,
    }
}

fn file_hashes(
    check: &BaselineCheckSpec,
    allowed_paths: &[String],
) -> BaselineCheckResult {
    let mut details = Vec::new();
    let mut rejected = 0usize;
    let mut failed = 0usize;

    for path in check.paths.iter().take(64) {
        let Some(canonical) = allowed_canonical_path(path, allowed_paths) else {
            rejected += 1;
            continue;
        };
        let Ok(meta) = fs::metadata(&canonical) else {
            failed += 1;
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
            failed += 1;
            continue;
        }
        let Ok(bytes) = fs::read(&canonical) else {
            failed += 1;
            continue;
        };
        let digest = Sha256::digest(&bytes);
        details.push(format!(
            "{} size={} sha256={:x}",
            canonical.display(),
            bytes.len(),
            digest
        ));
    }

    let status = if rejected > 0 {
        BaselineStatus::Rejected
    } else if failed > 0 {
        BaselineStatus::Failed
    } else {
        BaselineStatus::Ok
    };
    BaselineCheckResult {
        id: check.id.clone(),
        kind: check.kind.clone(),
        status,
        summary: format!(
            "hashed={} rejected={} failed={}",
            details.len(),
            rejected,
            failed
        ),
        details,
    }
}

fn allowed_canonical_path(path: &str, allowed_paths: &[String]) -> Option<std::path::PathBuf> {
    let target = fs::canonicalize(path).ok()?;
    allowed_paths.iter().filter_map(|prefix| fs::canonicalize(prefix).ok()).find_map(
        |prefix| {
            if target.starts_with(prefix) {
                Some(target.clone())
            } else {
                None
            }
        },
    )
}

fn sanitize_line(line: &str) -> String {
    line.chars()
        .take(512)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_string()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
