use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};

fn inject_build_version() -> anyhow::Result<()> {
    let schema_version = std::env::var("HIDS_SCHEMA_VERSION").unwrap_or_else(|_| "4".to_string());

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let repo_root = PathBuf::from(manifest_dir).join("..");
    let git_sha = std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(&repo_root)
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "dev".to_string());

    println!("cargo:rustc-env=HIDS_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=HIDS_SCHEMA_VERSION={schema_version}");
    println!("cargo:rerun-if-env-changed=HIDS_SCHEMA_VERSION");
    Ok(())
}

fn env_is_true(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn target_root() -> PathBuf {
    std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
                .join("..")
                .join("target")
        })
}

/// Copy a prebuilt `hids` eBPF blob into `OUT_DIR/hids`. Returns the source path used.
fn copy_bpf_artifact(src: &Path, dest: &Path) -> anyhow::Result<()> {
    std::fs::copy(src, dest).with_context(|| {
        format!(
            "copy eBPF artifact {} -> {}",
            src.display(),
            dest.display()
        )
    })?;
    println!(
        "cargo:warning=using prebuilt eBPF from {} (set AYA_BUILD_EBPF=1 to rebuild from source)",
        src.display()
    );
    Ok(())
}

fn find_cached_bpf_artifact() -> Option<PathBuf> {
    let target = target_root();
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();

    for profile in ["debug", "release"] {
        let build_root = target.join(profile).join("build");
        if !build_root.is_dir() {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&build_root) else {
            continue;
        };
        for entry in entries.flatten() {
            let candidate = entry.path().join("out").join("hids");
            if candidate.is_file() {
                if let Ok(meta) = std::fs::metadata(&candidate) {
                    let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                    candidates.push((mtime, candidate));
                }
            }
        }
    }

    candidates.sort_by_key(|(t, _)| *t);
    candidates.pop().map(|(_, p)| p)
}

/// Materialize `OUT_DIR/hids` without compiling eBPF. Returns `Ok(true)` if successful.
fn materialize_bpf_artifact(out_dir: &Path) -> anyhow::Result<bool> {
    let dest = out_dir.join("hids");
    if dest.is_file() {
        return Ok(true);
    }

    if let Ok(path) = std::env::var("HIDS_EBPF_ARTIFACT") {
        let src = PathBuf::from(path);
        if src.is_file() {
            copy_bpf_artifact(&src, &dest)?;
            return Ok(true);
        }
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let bundled = manifest_dir.join("ebpf").join("hids.bpf");
    if bundled.is_file() {
        copy_bpf_artifact(&bundled, &dest)?;
        return Ok(true);
    }

    if let Some(src) = find_cached_bpf_artifact() {
        copy_bpf_artifact(&src, &dest)?;
        return Ok(true);
    }

    Ok(false)
}

fn build_ebpf_from_source() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "hids-ebpf")
        .ok_or_else(|| anyhow!("hids-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], aya_build::Toolchain::default())?;
    println!("cargo:warning=compiled eBPF from source (hids-ebpf)");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    inject_build_version()?;

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    println!("cargo:rerun-if-env-changed=AYA_BUILD_EBPF");
    println!("cargo:rerun-if-env-changed=AYA_BUILD_SKIP");
    println!("cargo:rerun-if-env-changed=HIDS_EBPF_ARTIFACT");
    println!("cargo:rerun-if-changed=ebpf/hids.bpf");

    // Explicit rebuild from source (needs network + nightly for build-std).
    if env_is_true("AYA_BUILD_EBPF") {
        return build_ebpf_from_source();
    }

    // Default: offline-friendly prebuilt blob (bundled / cache / env path).
    if materialize_bpf_artifact(&out_dir)? {
        return Ok(());
    }

    // Legacy escape hatch: AYA_BUILD_SKIP=1 without any artifact is an error.
    if env_is_true("AYA_BUILD_SKIP") {
        return Err(anyhow!(
            "AYA_BUILD_SKIP=1 but no eBPF artifact found. \
             Ensure hids/ebpf/hids.bpf exists, set HIDS_EBPF_ARTIFACT, or run once with network and AYA_BUILD_EBPF=1"
        ));
    }

    // Last resort: try compiling (often fails in restricted networks).
    match build_ebpf_from_source() {
        Ok(()) => Ok(()),
        Err(err) => Err(anyhow!(
            "{err:#}\n\n\
             eBPF compile failed (often due to no crates.io access). \
             Use the bundled blob: hids/ebpf/hids.bpf is shipped with the repo; \
             or copy a prior out/hids to that path. \
             To force recompile when network is available: AYA_BUILD_EBPF=1 cargo build"
        )),
    }
}
