//! BUNYIP-579: file-based YAML layer for system-level settings.
//!
//! Precedence per setting: the environment variable (or its `{NAME}_FILE`
//! indirection) wins, then the YAML file, then the built-in default. The file is
//! written on first start from the built-in defaults and is NEVER overwritten
//! afterwards (the Forgejo `app.ini` precedent), so an operator edit survives a
//! restart. Loaded once at startup into [`SysConfig`]; reads then cost nothing.
//!
//! Scope is deployment-level system settings only: hostnames/origins, feature
//! toggles, and the country allow/deny list (BUNYIP-581). Branding and every
//! per-tenant or user-editable value stay in the database (BUNYIP-561), so they
//! remain live-editable without a restart.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The env var naming the config file; [`DEFAULT_PATH`] applies when it is unset.
pub const PATH_ENV: &str = "BUNYIP_CONFIG_FILE";
const DEFAULT_PATH: &str = "/app/config/config.yaml";

/// The on-disk shape. Every field is optional, so an absent key falls through to
/// the built-in default (and the env var still overrides both). Serialized with
/// the defaults filled in on first run, as a starting point for operator edits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SysConfigFile {
    pub hostnames: Hostnames,
    pub features: Features,
    pub country_access: CountryAccess,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Hostnames {
    pub cors_origin: Option<String>,
    pub web_origin: Option<String>,
    pub cookie_domain: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Features {
    pub login_approval_enabled: Option<bool>,
    pub signup_bot_guard_enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CountryAccess {
    /// ISO 3166-1 alpha-2 codes allowed to sign in. Empty means allow all.
    pub allow: Vec<String>,
    /// ISO 3166-1 alpha-2 codes denied. Applied after `allow` (BUNYIP-581).
    pub deny: Vec<String>,
}

/// The resolved, in-memory system config.
#[derive(Debug, Clone)]
pub struct SysConfig {
    pub cors_origin: String,
    pub web_origin: Option<String>,
    pub cookie_domain: Option<String>,
    pub login_approval_enabled: bool,
    pub signup_bot_guard_enabled: bool,
    pub country_allow: Vec<String>,
    pub country_deny: Vec<String>,
}

impl SysConfig {
    /// Resolve the system config from the file at [`config_path`], reading the
    /// real process environment for overrides. Generates the file from the
    /// defaults on first run; never overwrites it.
    pub fn load() -> Self {
        let file = read_or_generate(&config_path());
        Self::resolve(&file, &|name| env_layered(name))
    }

    /// The active config file path, for the admin screen and diagnostics.
    pub fn file_path() -> PathBuf {
        config_path()
    }

    /// Read the current on-disk config file WITHOUT generating it. Returns the
    /// built-in defaults when the file is absent or unparseable, so the admin
    /// screen always has a shape to render (BUNYIP-580).
    pub fn read_file() -> SysConfigFile {
        match std::fs::read_to_string(config_path()) {
            Ok(contents) => serde_yaml::from_str(&contents).unwrap_or_default(),
            Err(_) => SysConfigFile::default(),
        }
    }

    /// Write the config file atomically (a sibling temp file renamed over the
    /// target), so a failed or partial write never leaves the file broken
    /// (BUNYIP-580 AC4). Comments are NOT preserved: serde_yaml is a data
    /// serializer, so an operator's inline comments are lost on an admin save.
    pub fn write_file(file: &SysConfigFile) -> std::io::Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let yaml = serde_yaml::to_string(file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let body = format!(
            "# BUNYIP-579/580: system configuration. An environment variable (or its\n\
             # {{NAME}}_FILE indirection) overrides the value here; edit and restart to\n\
             # apply. Written by the admin System settings page.\n{yaml}"
        );
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, &path)
    }

    /// Whether an environment variable (`{NAME}` or `{NAME}_FILE`) overrides the
    /// file for this setting, so the admin screen can mark it read-only.
    pub fn env_overrides(name: &str) -> bool {
        env_layered(name).is_some()
    }

    /// The pure resolution, with the env layer injected so precedence is
    /// unit-tested without touching the process environment. `env` returns the
    /// value of a setting's `{NAME}` (or `{NAME}_FILE`) variable, or `None`.
    fn resolve(file: &SysConfigFile, env: &dyn Fn(&str) -> Option<String>) -> Self {
        SysConfig {
            cors_origin: str_setting(env, "CORS_ORIGIN", file.hostnames.cors_origin.as_deref())
                .unwrap_or_else(|| "http://localhost:5173".to_string()),
            web_origin: str_setting(
                env,
                "BUNYIP_WEB_ORIGIN",
                file.hostnames.web_origin.as_deref(),
            ),
            cookie_domain: str_setting(
                env,
                "COOKIE_DOMAIN",
                file.hostnames.cookie_domain.as_deref(),
            ),
            login_approval_enabled: bool_setting(
                env,
                "LOGIN_APPROVAL_ENABLED",
                file.features.login_approval_enabled,
            )
            .unwrap_or(false),
            signup_bot_guard_enabled: bool_setting(
                env,
                "SIGNUP_BOT_GUARD_ENABLED",
                file.features.signup_bot_guard_enabled,
            )
            .unwrap_or(false),
            country_allow: normalize_countries(&file.country_access.allow),
            country_deny: normalize_countries(&file.country_access.deny),
        }
    }
}

/// The config file path: `BUNYIP_CONFIG_FILE`, else the in-container default.
fn config_path() -> PathBuf {
    std::env::var(PATH_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PATH))
}

/// Read the YAML file; on first run (absent) write the defaults and return them.
/// A parse error or an unreadable path logs and falls back to the defaults, so a
/// bad file never blocks boot (the env layer still applies on top).
fn read_or_generate(path: &Path) -> SysConfigFile {
    match std::fs::read_to_string(path) {
        Ok(contents) => match serde_yaml::from_str::<SysConfigFile>(&contents) {
            Ok(file) => file,
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "system config YAML did not parse; using built-in defaults (env vars still apply)");
                SysConfigFile::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let defaults = SysConfigFile::default();
            generate(path, &defaults);
            defaults
        }
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "system config file unreadable; using built-in defaults");
            SysConfigFile::default()
        }
    }
}

/// First-run generation: write the defaults, creating the parent dir. Only
/// reached when the file does not exist, so it never overwrites operator edits.
/// Best-effort: an unwritable location logs a warning and boot continues.
fn generate(path: &Path, defaults: &SysConfigFile) {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(path = %path.display(), error = %e, "could not create the system config directory; skipping first-run generation");
            return;
        }
    }
    match serde_yaml::to_string(defaults) {
        Ok(yaml) => {
            let body = format!(
                "# BUNYIP-579: system configuration. An environment variable (or its\n\
                 # {{NAME}}_FILE indirection) overrides the value here; the value here\n\
                 # overrides the built-in default. Edit and restart to apply. Generated\n\
                 # once on first start and never overwritten.\n{yaml}"
            );
            match std::fs::write(path, body) {
                Ok(()) => {
                    tracing::info!(path = %path.display(), "generated the system config file (first run)")
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "could not write the system config file; continuing without it")
                }
            }
        }
        Err(e) => tracing::error!(error = %e, "could not serialize the default system config"),
    }
}

/// A string setting: the env layer (`{NAME}` or `{NAME}_FILE`) wins, else the
/// YAML value; an empty result is treated as unset so the caller's default wins.
fn str_setting(
    env: &dyn Fn(&str) -> Option<String>,
    name: &str,
    yaml: Option<&str>,
) -> Option<String> {
    env(name)
        .or_else(|| yaml.map(str::to_string))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// A boolean setting: the env layer wins (parsed as `true`/`1`), else the YAML value.
fn bool_setting(
    env: &dyn Fn(&str) -> Option<String>,
    name: &str,
    yaml: Option<bool>,
) -> Option<bool> {
    match env(name) {
        Some(v) => {
            let v = v.trim();
            Some(v.eq_ignore_ascii_case("true") || v == "1")
        }
        None => yaml,
    }
}

/// The env layer for one key: the plain `{NAME}` variable, or its `{NAME}_FILE`
/// indirection (a mounted file path). The `_FILE` form keeps a secret-bearing
/// value off the process environment and the Infisical path intact (the
/// BUNYIP-579 `_FILE` acceptance criterion).
fn env_layered(name: &str) -> Option<String> {
    if let Ok(v) = std::env::var(name) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    let file_var = format!("{name}_FILE");
    let path = std::env::var(&file_var).ok().filter(|s| !s.is_empty())?;
    match std::fs::read_to_string(&path) {
        Ok(contents) => Some(contents.trim().to_string()).filter(|s| !s.is_empty()),
        Err(e) => {
            tracing::error!(var = %file_var, error = %e, "could not read the config-file indirection");
            None
        }
    }
}

/// Normalise country codes to trimmed upper-case ISO alpha-2, dropping blanks.
fn normalize_countries(codes: &[String]) -> Vec<String> {
    codes
        .iter()
        .map(|c| c.trim().to_uppercase())
        .filter(|c| !c.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Env lookup backed by a fixed set of pairs, so precedence is tested without
    /// touching the real process environment.
    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn precedence_is_env_then_yaml_then_default() {
        let mut file = SysConfigFile::default();
        file.hostnames.cors_origin = Some("https://yaml.example".into());
        file.features.login_approval_enabled = Some(true);

        // Env wins over YAML.
        let env = env_of(&[("CORS_ORIGIN", "https://env.example")]);
        assert_eq!(
            SysConfig::resolve(&file, &env).cors_origin,
            "https://env.example"
        );

        // YAML wins over the default when the env is absent.
        let none = env_of(&[]);
        let resolved = SysConfig::resolve(&file, &none);
        assert_eq!(resolved.cors_origin, "https://yaml.example");
        assert!(resolved.login_approval_enabled, "YAML toggle applies");

        // Built-in default when both are absent.
        let bare = SysConfig::resolve(&SysConfigFile::default(), &none);
        assert_eq!(bare.cors_origin, "http://localhost:5173");
        assert!(!bare.login_approval_enabled);
        assert!(bare.country_allow.is_empty());
    }

    #[test]
    fn country_codes_are_normalised() {
        let mut file = SysConfigFile::default();
        file.country_access.allow = vec![" us ".into(), "gb".into(), "".into()];
        let resolved = SysConfig::resolve(&file, &env_of(&[]));
        assert_eq!(resolved.country_allow, vec!["US", "GB"]);
    }

    fn unique_temp_path() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "bunyip-sysconfig-{}-{}.yaml",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn generates_on_first_run_and_never_overwrites() {
        let path = unique_temp_path();
        let _ = std::fs::remove_file(&path);
        assert!(!path.exists());

        // First run generates the file from the defaults.
        let generated = read_or_generate(&path);
        assert!(path.exists(), "first run writes the file");
        assert!(generated.features.login_approval_enabled.is_none());

        // An operator edits it; a later start must NOT overwrite the edit.
        std::fs::write(&path, "features:\n  login_approval_enabled: true\n").unwrap();
        let reloaded = read_or_generate(&path);
        assert_eq!(
            reloaded.features.login_approval_enabled,
            Some(true),
            "the operator edit survives; the file is never overwritten"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// BUNYIP-592: generation follows `BUNYIP_CONFIG_FILE`, so a caller that
    /// sets it (every test reaching `Config::from_env_inner`) writes there and
    /// not into the working tree, and the generated file carries every default
    /// key an operator edits.
    #[test]
    fn load_generates_at_the_configured_path_with_the_default_keys() {
        let _env = crate::test_support::env_lock();
        let path = unique_temp_path();
        let _ = std::fs::remove_file(&path);
        std::env::set_var(PATH_ENV, &path);
        assert_eq!(SysConfig::file_path(), path);

        SysConfig::load();

        let contents =
            std::fs::read_to_string(&path).expect("first run generates at the configured path");
        for key in ["hostnames:", "features:", "country_access:"] {
            assert!(contents.contains(key), "{key} missing from {contents}");
        }

        std::env::remove_var(PATH_ENV);
        let _ = std::fs::remove_file(&path);
    }
}
