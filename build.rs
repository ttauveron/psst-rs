use std::{
    env,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-env-changed=PSST_RS_BUILD_VERSION");
    println!("cargo:rerun-if-env-changed=PSST_RS_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_TYPE");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");

    register_git_rerun_paths();

    if let Some(version) = build_version() {
        println!("cargo:rustc-env=PSST_RS_BUILD_VERSION={version}");
    }

    if let Some(commit) = build_commit() {
        println!("cargo:rustc-env=PSST_RS_BUILD_COMMIT={commit}");
    }
}

fn build_version() -> Option<String> {
    env::var("PSST_RS_BUILD_VERSION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(github_tag_version)
        .or_else(git_exact_tag)
}

fn build_commit() -> Option<String> {
    env::var("PSST_RS_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| env::var("GITHUB_SHA").ok())
        .or_else(|| git_output(["rev-parse", "--short=12", "HEAD"]))
}

fn github_tag_version() -> Option<String> {
    match (
        env::var("GITHUB_REF_TYPE").ok(),
        env::var("GITHUB_REF_NAME").ok(),
    ) {
        (Some(ref_type), Some(ref_name)) if ref_type == "tag" && !ref_name.trim().is_empty() => {
            Some(ref_name)
        }
        _ => None,
    }
}

fn git_exact_tag() -> Option<String> {
    git_output(["describe", "--tags", "--exact-match", "HEAD"])
}

fn git_output<const N: usize>(args: [&str; N]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn register_git_rerun_paths() {
    let Some(git_dir_raw) = git_output(["rev-parse", "--git-dir"]) else {
        return;
    };

    let git_dir = PathBuf::from(git_dir_raw);
    let head_path = git_dir.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());

    if let Ok(head_contents) = fs::read_to_string(&head_path) {
        if let Some(reference) = head_contents.strip_prefix("ref:").map(str::trim) {
            let ref_path = git_dir.join(reference);
            println!("cargo:rerun-if-changed={}", ref_path.display());
        }
    }

    let packed_refs = git_dir.join("packed-refs");
    if Path::new(&packed_refs).exists() {
        println!("cargo:rerun-if-changed={}", packed_refs.display());
    }
}
