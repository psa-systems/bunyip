use std::path::Path;
use std::process::Command;

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

    // BUNYIP-554: the `?v=` every /assets reference carries, so the immutable
    // one-year Cache-Control on that directory is invalidated by a deploy. The
    // commit is the identity of the asset bytes; when git is unavailable
    // (a source tarball) the build timestamp still changes per build.
    let version = if commit == "unknown" {
        // Not silent: without a commit the version is a build timestamp, so
        // every rebuild of the same source busts the year-long asset cache.
        // Say so rather than letting the degradation ship unnoticed.
        println!(
            "cargo:warning=GIT_COMMIT unresolved; ASSET_VERSION falls back to the build timestamp, \
             so every rebuild invalidates the /assets cache. Pass --build-arg GIT_COMMIT=<sha>."
        );
        build_date.replace([':', '-'], "")
    } else {
        commit.clone()
    };
    println!("cargo:rustc-env=ASSET_VERSION={version}");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=GIT_TAG");
    println!("cargo:rerun-if-env-changed=BUILD_DATE");
    emit_git_rerun_triggers();
}

// Rerun the script when the checked-out revision moves, and never otherwise. The
// hardcoded `../.git/HEAD` resolved from a plain clone but named an absent path in
// a linked worktree or a submodule (where `.git` is a file) and in any context
// that excludes `.git` (the repo `.dockerignore` does), and cargo treats a
// `rerun-if-changed` pointing at a missing file as permanently stale, reruning
// this script on every build. Ask git for the real paths instead, and emit a
// directive only for the ones that exist. `--git-path` returns the per-worktree
// HEAD and resolves refs to the common directory, so a linked worktree and a
// submodule work too. Watch `refs/heads` + `refs/tags`, not all of `refs`, so a
// `git fetch` that only moves a remote-tracking ref does not recompile the crate.
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
    // back to `unknown` (and ASSET_VERSION to the build timestamp).
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

fn resolve(env_var: &str, cmd: &[&str]) -> String {
    if let Ok(value) = std::env::var(env_var) {
        // `unknown` is the Dockerfile's ARG default, i.e. "the caller passed
        // nothing"; fall through to the command rather than baking that string
        // into ASSET_VERSION, which would freeze the `?v=` across deploys.
        if !value.is_empty() && value != "unknown" {
            return value;
        }
    }
    Command::new(cmd[0])
        .args(&cmd[1..])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}
