use std::path::Path;
use std::process::Command;

// SPEC-9.1.8: env override wins; else git/date; else "unknown"
fn main() {
    let commit = resolve("GIT_COMMIT", &["git", "rev-parse", "--short", "HEAD"]);
    let tag = resolve(
        "GIT_TAG",
        &["git", "describe", "--tags", "--always", "--dirty"],
    );
    let build_date = resolve("BUILD_DATE", &["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"]);

    println!("cargo:rustc-env=GIT_COMMIT={commit}");
    println!("cargo:rustc-env=GIT_TAG={tag}");
    println!("cargo:rustc-env=BUILD_DATE={build_date}");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=GIT_TAG");
    println!("cargo:rerun-if-env-changed=BUILD_DATE");
    emit_git_rerun_triggers();
}

// Rerun the script when the checked-out revision moves, and never otherwise.
// Cargo resolves a relative `rerun-if-changed` against the package root, and the
// git directory sits at the workspace root, so hardcoding `.git/HEAD` from here
// named a file that does not exist. Cargo treats a `rerun-if-changed` pointing at
// a missing file as permanently stale, which reran this script (and recompiled
// the crate) on every build. Ask git for the real paths instead, and emit a
// directive only for the ones that exist. `--git-path` returns the per-worktree
// HEAD and resolves refs to the common directory, so a linked worktree and a
// submodule work too. Watch `refs/heads` + `refs/tags`, not all of `refs`, so a
// `git fetch` that only moves a remote-tracking ref does not recompile the crate.
// SPEC-9.1.9: watch real git paths only, so builds are not perpetually stale
fn emit_git_rerun_triggers() {
    let output = Command::new("git")
        .args([
            "rev-parse",
            "--git-path",
            "HEAD",
            "--git-path",
            "refs/heads",
            "--git-path",
            "refs/tags",
            "--git-path",
            "packed-refs",
        ])
        .output();
    // No git, or not a repository: emit nothing and let GIT_COMMIT / GIT_TAG fall
    // back to `unknown`.
    let Some(output) = output.ok().filter(|o| o.status.success()) else {
        return;
    };
    let Ok(stdout) = String::from_utf8(output.stdout) else {
        return;
    };
    for path in stdout.lines().map(str::trim).filter(|p| !p.is_empty()) {
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

// SPEC-9.1.8
fn resolve(env_var: &str, cmd: &[&str]) -> String {
    if let Ok(value) = std::env::var(env_var) {
        if !value.is_empty() {
            return value;
        }
    }
    let resolved = Command::new(cmd[0])
        .args(&cmd[1..])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match resolved {
        Some(v) => v,
        None => {
            // BUNYIP-1052: a build whose git/date command silently failed
            // used to produce a binary labelled "unknown" with no record
            // in the build log. Emit a cargo:warning so an operator can
            // spot the fallback at build time.
            println!(
                "cargo:warning=build.rs: {} unresolved (command `{}` failed); falling back to \"unknown\"",
                env_var,
                cmd.join(" ")
            );
            "unknown".to_string()
        }
    }
}
