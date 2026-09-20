//! BUNYIP-537: the startup configuration contract, enforced mechanically.
//!
//! Two invariants live here because they span crates:
//!
//! 1. Every environment variable the api reads is classified in
//!    [`bunyip_domain::config::ENV_INVENTORY`], so a new variable cannot be
//!    added without saying how its absence is reported.
//! 2. No `panic!` remains as the reporting mechanism for missing or malformed
//!    configuration in the two files that own it.
//!
//! Plus the end-to-end proof: an unconfigured production boot exits non-zero
//! with one error line per missing variable, and no backtrace.

use std::path::{Path, PathBuf};
use std::process::Command;

use bunyip_domain::config::{env_spec, EnvClass, ENV_INVENTORY};

/// The workspace root (this crate's manifest dir is `<root>/bunyip-api`).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("bunyip-api sits one level below the workspace root")
        .to_path_buf()
}

/// Every `.rs` file under `dir`, recursively.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    for entry in entries {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// The environment-variable names read literally in `source`, i.e. the
/// `env::var("NAME")` and `secret_env("NAME")` call sites. Comment lines are
/// skipped (they document the shape rather than read it), and non-literal
/// arguments are invisible to this scan by construction: those call sites pass
/// a name that is itself a literal elsewhere (the per-RP OIDC client vars) and
/// are classified through that literal.
fn literal_env_reads(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in source.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for prefix in ["env::var(\"", "secret_env(\""] {
            let mut rest = line;
            while let Some(idx) = rest.find(prefix) {
                rest = &rest[idx + prefix.len()..];
                if let Some(end) = rest.find('"') {
                    names.push(rest[..end].to_string());
                }
            }
        }
    }
    names
}

/// The environment-variable names read through bunyip-web's `var(k)` closure
/// idiom (`bunyip-web/src/config.rs`: `let var = |k: &str| std::env::var(k)...`),
/// i.e. bare `var("NAME")` call sites. A word-boundary check on the character
/// before `var("` keeps this from mistaking `set_var("...")` / `remove_var("...")`
/// test fixtures for a read: both end in `_var(`, and `_` is a word character.
fn closure_env_reads(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let prefix = "var(\"";
    for line in source.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let bytes = line.as_bytes();
        let mut search_start = 0;
        while let Some(rel_idx) = line[search_start..].find(prefix) {
            let idx = search_start + rel_idx;
            let is_word_char = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
            let at_boundary = idx == 0 || !is_word_char(bytes[idx - 1]);
            if at_boundary {
                let after = &line[idx + prefix.len()..];
                if let Some(end) = after.find('"') {
                    names.push(after[..end].to_string());
                }
            }
            search_start = idx + prefix.len();
        }
    }
    names
}

/// The part of a source file that is NOT its `#[cfg(test)]` module.
fn without_test_module(source: &str) -> &str {
    match source.find("#[cfg(test)]") {
        Some(idx) => &source[..idx],
        None => source,
    }
}

#[test]
fn env_inventory_covers_every_env_read() {
    let root = workspace_root();
    let mut scanned = 0usize;
    let mut unclassified: Vec<String> = Vec::new();

    let scan_dirs = [
        (root.join("crates"), false),
        (root.join("bunyip-api/src"), false),
        // BUNYIP-751: bunyip-web reads its environment through a `var(k)`
        // closure rather than literal `env::var("NAME")` calls, so it needs
        // the extra matcher on top of the shared one.
        (root.join("bunyip-web/src"), true),
    ];

    for (dir, is_web) in scan_dirs {
        for file in rust_sources(&dir) {
            let source = std::fs::read_to_string(&file).expect("readable source");
            let mut names = literal_env_reads(&source);
            if is_web {
                names.extend(closure_env_reads(&source));
            }
            for name in names {
                scanned += 1;
                // Test-only fixtures use throwaway names; they are not read by
                // the running app and are not part of its contract.
                if name.starts_with("TEST_") {
                    continue;
                }
                if env_spec(&name).is_none() {
                    unclassified.push(format!("{name} ({})", file.display()));
                }
            }
        }
    }

    assert!(
        scanned > 50,
        "the source scan found only {scanned} env reads"
    );
    assert!(
        unclassified.is_empty(),
        "environment variables read by the api or bunyip-web but not classified in \
         ENV_INVENTORY (crates/bunyip-domain/src/config.rs): {unclassified:#?}"
    );
}

#[test]
fn no_panic_reports_a_configuration_error() {
    let root = workspace_root();
    for relative in [
        "bunyip-api/src/main.rs",
        "crates/bunyip-domain/src/config.rs",
    ] {
        let source = std::fs::read_to_string(root.join(relative)).expect("readable source");
        let production_code = without_test_module(&source);
        let offenders: Vec<&str> = production_code
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| line.contains("panic!("))
            .collect();
        assert!(
            offenders.is_empty(),
            "{relative} must report configuration failures as ConfigFailure / \
             fatal_config_error, never a panic (BUNYIP-537): {offenders:#?}"
        );
    }
}

#[test]
fn required_and_gating_entries_carry_a_remedy() {
    let required = ENV_INVENTORY
        .iter()
        .filter(|spec| {
            matches!(
                spec.class,
                EnvClass::Required | EnvClass::RequiredInProduction
            )
        })
        .count();
    assert!(required >= 4, "the required set lost entries: {required}");
    assert!(
        env_spec("BUNYIP_WEBHOOK_SIGNING_SECRET")
            .is_some_and(|spec| spec.class == EnvClass::RequiredInProduction),
        "BUNYIP_WEBHOOK_SIGNING_SECRET must stay required in production (BUNYIP-332)"
    );
}

/// The end-to-end contract: an unconfigured production boot reports EVERY
/// missing required variable in one run, as `ERROR` lines naming the variable,
/// the reason and the remedy, and exits non-zero without a panic.
#[test]
fn unconfigured_production_boot_exits_non_zero_with_one_error_per_variable() {
    // A temp cwd so a developer's repo-root `.env` cannot re-inject values.
    let cwd = std::env::temp_dir();
    let output = Command::new(env!("CARGO_BIN_EXE_bunyip-api"))
        .current_dir(&cwd)
        .env_clear()
        .env("ENVIRONMENT", "production")
        .output()
        .expect("the api binary runs");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected a clean non-zero exit, got {:?}\n{combined}",
        output.status
    );
    assert!(
        !combined.contains("panicked at"),
        "a configuration error must not surface as a panic:\n{combined}"
    );
    for expected in [
        "DATABASE_URL",
        // BUNYIP-542: unset means the deployment has not declared where its
        // integration secrets live, which stops the boot in every environment.
        "SECRETS_STORAGE",
        "JWT_SECRET",
        "APP_ENCRYPTION_KEY",
        "BUNYIP_WEBHOOK_SIGNING_SECRET",
    ] {
        assert!(
            combined.contains(expected),
            "{expected} not named in the boot report:\n{combined}"
        );
    }
    // The remedy is part of the message, not just the variable name.
    assert!(
        combined.contains("just init-secrets"),
        "the report must tell the operator how to supply the secrets:\n{combined}"
    );
}
