use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn inject_build_version() -> anyhow::Result<()> {
    // Default schema version for event compatibility.
    // You can override at build time: HIDS_SCHEMA_VERSION=2 cargo build ...
    let schema_version = std::env::var("HIDS_SCHEMA_VERSION").unwrap_or_else(|_| "3".to_string());

    // Try to read git SHA (best-effort).
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let repo_root = std::path::PathBuf::from(manifest_dir).join("..");
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

    // Re-run if schema version changes.
    println!("cargo:rerun-if-env-changed=HIDS_SCHEMA_VERSION");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    inject_build_version()?;

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
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
