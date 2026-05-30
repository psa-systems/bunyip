use std::process::Command;

fn main() {
    let commit = resolve(
        "GIT_COMMIT",
        &["git", "rev-parse", "--short", "HEAD"],
    );
    let tag = resolve(
        "GIT_TAG",
        &["git", "describe", "--tags", "--always", "--dirty"],
    );
    let build_date = resolve(
        "BUILD_DATE",
        &["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
    );

    println!("cargo:rustc-env=GIT_COMMIT={commit}");
    println!("cargo:rustc-env=GIT_TAG={tag}");
    println!("cargo:rustc-env=BUILD_DATE={build_date}");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=GIT_TAG");
    println!("cargo:rerun-if-env-changed=BUILD_DATE");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
}

fn resolve(env_var: &str, cmd: &[&str]) -> String {
    if let Ok(value) = std::env::var(env_var) {
        if !value.is_empty() {
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
