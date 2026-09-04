//! BUNYIP-579/622/644: the APPLICATION-LEVEL deployment settings and the write
//! path the admin System settings page uses.
//!
//! BUNYIP-622 draws the configuration boundary this file sits on. See
//! [`ConfigScope`] for the rule; in short:
//!
//! - System-level settings decide who the deployment trusts at the host, tenant
//!   or network boundary (the origins and domains it accepts, the database it
//!   connects to, the secrets backend it reaches). They are read from the
//!   ENVIRONMENT ONLY and have no file or API write path, because letting the
//!   API write one would turn any flaw that reaches the API into host- or
//!   network-level exposure (adding an origin you do not control, repointing the
//!   database). BUNYIP-579 originally placed the origins/hostnames here; that was
//!   the wrong side of the boundary and BUNYIP-622 moved them out.
//! - Application-level settings are everything else, including every integration.
//!   They are product-managed by the MSP. This file carries the application-level
//!   deployment toggles (the feature switches and the country allow/deny list,
//!   BUNYIP-581); integrations and branding live in the database (BUNYIP-561).
//!
//! The split is enforced by TYPE, not by a permission check: [`SystemSettings`]
//! has no field for any system-level key, and [`SystemSettings::entries`] is the
//! ONLY mapping from a field to a file the admin settings API
//! (`PUT /v1/admin/system-config`) writes, so that endpoint has no code path
//! that can persist one. A future refactor cannot drop a guard and reopen it,
//! because there is no guard to drop (BUNYIP-622 AC3).
//!
//! # One file layer (BUNYIP-644)
//!
//! There used to be TWO file-based layers with opposite precedence: this
//! module's YAML file at `BUNYIP_CONFIG_FILE`, and the BUNYIP-643 file provider,
//! a directory of one file per key. The directory survived, so an operator
//! learns one layout and one precedence rule:
//!
//! - Reads go through the provider stack, `database` > `file` > `environment`
//!   ([`crate::config_providers`]). These four settings are declared keys
//!   ([`SYSTEM_SETTINGS_KEYS`](crate::config_providers::SYSTEM_SETTINGS_KEYS))
//!   with no database provider, so in practice: the file layer, then the
//!   environment, then the built-in default.
//! - Writes go through [`SystemSettings::save`], which writes exactly one file
//!   per declared key into that same directory and nothing else.
//! - An existing YAML file is migrated into the directory once, on the first
//!   start after the upgrade, by [`migrate_legacy_file`], which never carries a
//!   value across that the environment was already overriding. A resolved value
//!   therefore does not move.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::config_providers::{file_layer_dir, ConfigProvider, ConfigStack, EnvironmentProvider};

/// BUNYIP-622: which side of the configuration boundary a setting is on.
///
/// The rule is security-led (David, 2026-08-24 standup): a setting is
/// [`ConfigScope::System`] when modifying it grants access to the host, other
/// tenants, or the network boundary. Everything else is
/// [`ConfigScope::Application`], including every integration, because
/// integrations must be manageable in-product by the MSP without a restart.
///
/// System-level settings are read from the environment only and never written
/// through the file layer or the admin API; application-level settings are
/// product-managed. The classification is documented in `docs/configuration.md`
/// and enforced structurally by the type split described on [`SystemSettings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigScope {
    /// Host / tenant / network boundary: origins and domains, the database
    /// connection, the secrets backend location and credentials. Environment
    /// only; no file or API write path.
    System,
    /// Everything else, including every integration. Product-managed.
    Application,
}

/// BUNYIP-622: the system-level environment variables. They are read from the
/// environment only and must never become writable through the file layer or the
/// admin API. `system_level_keys_never_enter_the_file_layer` asserts none of
/// these is ever a key [`SystemSettings::entries`] writes, nor a declared
/// configuration key the file layer could serve, so a future edit that tried to
/// move one back into the file layer would fail the build.
pub const SYSTEM_LEVEL_ENV_KEYS: &[&str] = &[
    // Origins and domains the deployment trusts (the "add a domain you do not
    // control" threat David raised). BUNYIP-622 moved these out of the file.
    "CORS_ORIGIN",
    "BUNYIP_WEB_ORIGIN",
    "COOKIE_DOMAIN",
    // Database connection.
    "DATABASE_URL",
    "APP_DATABASE_URL",
    // Secrets backend location and credentials.
    "SECRETS_STORAGE",
    "INFISICAL_HOST",
    "INFISICAL_CLIENT_ID",
    "INFISICAL_CLIENT_SECRET",
    "INFISICAL_PROJECT_ID",
    "INFISICAL_ENVIRONMENT",
];

/// The env var naming the LEGACY YAML file (BUNYIP-579/622). It is no longer a
/// configuration layer: it is read once, migrated into the file layer directory
/// and renamed aside (BUNYIP-644). [`LEGACY_FILE_NAME`] is where it is looked
/// for when the variable is unset.
pub const LEGACY_FILE_ENV: &str = "BUNYIP_CONFIG_FILE";

/// The legacy YAML file's name inside the file layer directory.
pub const LEGACY_FILE_NAME: &str = "config.yaml";

/// The suffix the migrated legacy file is renamed with, so it is never read as
/// configuration again and is never deleted either.
pub const LEGACY_MIGRATED_SUFFIX: &str = ".migrated";

/// The application-level deployment settings, as the admin System settings page
/// reads and writes them.
///
/// This struct is the structural enforcement of the configuration boundary: it
/// has NO field for a system-level key ([`SYSTEM_LEVEL_ENV_KEYS`]). The admin
/// settings API writes exactly this struct, through [`Self::entries`], which is
/// the only mapping this crate has from a field to a file in the layer, so
/// there is no code path through which that endpoint could persist a
/// system-level key. Adding one here would move a system-level setting onto the
/// API-writable side of the boundary and reopen the exposure BUNYIP-622 closed,
/// which is why the boundary test pins the written key set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemSettings {
    pub login_approval_enabled: bool,
    pub signup_bot_guard_enabled: bool,
    /// ISO 3166-1 alpha-2 codes allowed to sign in. Empty means allow all.
    pub country_allow: Vec<String>,
    /// ISO 3166-1 alpha-2 codes denied. Applied after `allow` (BUNYIP-581).
    pub country_deny: Vec<String>,
}

impl SystemSettings {
    /// The effective values, resolved through the provider stack: the file
    /// layer, then the environment, then the built-in default. The admin screen
    /// shows what the deployment actually uses, so a save persists what the
    /// operator is looking at rather than silently changing another provider's
    /// value.
    pub fn resolve(stack: &ConfigStack) -> Self {
        Self {
            login_approval_enabled: flag(stack, "LOGIN_APPROVAL_ENABLED"),
            signup_bot_guard_enabled: flag(stack, "SIGNUP_BOT_GUARD_ENABLED"),
            country_allow: countries(stack, "COUNTRY_ALLOW"),
            country_deny: countries(stack, "COUNTRY_DENY"),
        }
    }

    /// [`Self::resolve`] over the deployment stack (file layer, environment).
    pub fn current() -> Self {
        Self::resolve(&ConfigStack::deployment())
    }

    /// The declared key each field is carried by, and the text to store for it.
    /// `None` clears the setting, so the built-in default (or a lower provider)
    /// serves it again.
    ///
    /// This is the WHOLE write surface of the file layer. There is no field for
    /// a system-level key, so there is nothing here to write one with.
    pub fn entries(&self) -> Vec<(&'static str, Option<String>)> {
        vec![
            (
                "LOGIN_APPROVAL_ENABLED",
                Some(self.login_approval_enabled.to_string()),
            ),
            (
                "SIGNUP_BOT_GUARD_ENABLED",
                Some(self.signup_bot_guard_enabled.to_string()),
            ),
            ("COUNTRY_ALLOW", join_countries(&self.country_allow)),
            ("COUNTRY_DENY", join_countries(&self.country_deny)),
        ]
    }

    /// Write these settings into the file layer, one file per key.
    ///
    /// Each file is written atomically (a sibling temp file renamed over the
    /// target), so a failed or partial write never leaves a value half-written
    /// (BUNYIP-580 AC4). A cleared setting removes its file, which is what
    /// "absent" means in this layer.
    pub fn save(&self) -> std::io::Result<()> {
        let dir = file_layer_dir();
        std::fs::create_dir_all(&dir)?;
        for (key, value) in self.entries() {
            let path = dir.join(key);
            match value {
                Some(value) => write_key_file(&path, &value)?,
                None => match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                },
            }
        }
        Ok(())
    }

    /// The directory the settings are read from and written to, for the admin
    /// screen and diagnostics.
    pub fn directory() -> PathBuf {
        file_layer_dir()
    }
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
    /// Resolve the system config: the application-level settings through the
    /// provider stack, the system-level origins from the process environment
    /// only.
    pub fn load(stack: &ConfigStack) -> Self {
        Self::resolve(stack, &|name| env_layered(name))
    }

    /// The pure resolution, with the env layer injected so the system-level half
    /// is unit-tested without touching the process environment. `env` returns
    /// the value of a setting's `{NAME}` (or `{NAME}_FILE`) variable, or `None`.
    fn resolve(stack: &ConfigStack, env: &dyn Fn(&str) -> Option<String>) -> Self {
        // BUNYIP-622: the origins and domains are system-level. They resolve
        // from the environment ONLY (never the file layer, never the provider
        // stack), so no admin-API write can add an origin the deployment does
        // not control.
        let settings = SystemSettings::resolve(stack);
        SysConfig {
            cors_origin: str_setting(env, "CORS_ORIGIN")
                .unwrap_or_else(|| "http://localhost:5173".to_string()),
            web_origin: str_setting(env, "BUNYIP_WEB_ORIGIN"),
            cookie_domain: str_setting(env, "COOKIE_DOMAIN"),
            login_approval_enabled: settings.login_approval_enabled,
            signup_bot_guard_enabled: settings.signup_bot_guard_enabled,
            country_allow: settings.country_allow,
            country_deny: settings.country_deny,
        }
    }
}

/// The legacy YAML file's path: `BUNYIP_CONFIG_FILE`, else [`LEGACY_FILE_NAME`]
/// inside the file layer directory (which is where the in-container default
/// `/app/config/config.yaml` already sat).
pub fn legacy_file_path(dir: &Path) -> PathBuf {
    std::env::var(LEGACY_FILE_ENV)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join(LEGACY_FILE_NAME))
}

/// BUNYIP-644: fold an existing YAML file into the file layer, once.
///
/// Returns the values that could NOT be written, so the caller can still serve
/// them from memory for this boot: a directory the application cannot write must
/// not silently drop an operator's settings. An empty map means everything was
/// either written, already present as a per-key file, or deliberately dropped.
///
/// The legacy layer ranked BELOW the environment and the file layer ranks above
/// it, so a value the environment also holds is DROPPED rather than migrated:
/// carrying it across would flip a resolved value, which is exactly what this
/// migration must not do. Each drop is logged naming the key.
pub fn migrate_legacy_file(dir: &Path, legacy: &Path) -> BTreeMap<String, String> {
    let mut unwritten = BTreeMap::new();
    let contents = match std::fs::read_to_string(legacy) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return unwritten,
        Err(e) => {
            tracing::error!(path = %legacy.display(), error = %e, "the legacy system config YAML file could not be read, so its settings are not migrated into the file layer; move them across by hand (docs/configuration.md)");
            return unwritten;
        }
    };
    let file: LegacySysConfigFile = match serde_yaml::from_str(&contents) {
        Ok(file) => file,
        Err(e) => {
            tracing::error!(path = %legacy.display(), error = %e, "the legacy system config YAML file did not parse, so its settings are not migrated into the file layer; fix or remove it (docs/configuration.md)");
            return unwritten;
        }
    };

    let environment = EnvironmentProvider;
    for (key, value) in file.entries() {
        let Some(value) = value else { continue };
        let path = dir.join(key);
        if path.exists() {
            tracing::info!(config_key = key, path = %path.display(), "the file layer already holds {key}, so the legacy YAML value for it is dropped");
            continue;
        }
        if environment
            .get(key)
            .is_some_and(|value| !value.trim().is_empty())
        {
            tracing::warn!(
                config_key = key,
                legacy = %legacy.display(),
                "the environment holds {key} and outranked the legacy YAML file, so the YAML value \
                 is dropped rather than migrated: the file layer outranks the environment, and \
                 migrating it would change the value this deployment resolves. Set it in the file \
                 layer by hand if that is what you want (docs/configuration.md)."
            );
            continue;
        }
        if let Err(e) = write_key_file(&path, &value) {
            tracing::error!(config_key = key, path = %path.display(), error = %e, "could not migrate {key} from the legacy YAML file into the file layer; it is served from memory for this boot and the migration is retried on the next start");
            unwritten.insert(key.to_string(), value);
            continue;
        }
        tracing::info!(config_key = key, path = %path.display(), "migrated {key} from the legacy YAML file into the file layer");
    }

    if unwritten.is_empty() {
        // The name is always there: this path was just read as a file. Naming
        // it explicitly rather than substituting a default keeps the rename
        // from ever landing on a file the operator did not have.
        let Some(name) = legacy.file_name().and_then(|name| name.to_str()) else {
            tracing::error!(path = %legacy.display(), "the legacy system config YAML file has no readable file name, so it could not be renamed aside; remove it by hand once its settings are in the file layer");
            return unwritten;
        };
        let migrated = legacy.with_file_name(format!("{name}{LEGACY_MIGRATED_SUFFIX}"));
        match std::fs::rename(legacy, &migrated) {
            Ok(()) => {
                tracing::info!(from = %legacy.display(), to = %migrated.display(), "the legacy system config YAML file is migrated and has been renamed aside; the file layer directory is the one file-based configuration layer now")
            }
            Err(e) => {
                tracing::error!(from = %legacy.display(), to = %migrated.display(), error = %e, "the legacy system config YAML file was migrated but could not be renamed aside; it is inert either way, and the migration skips every key already in the file layer on the next start")
            }
        }
    }
    unwritten
}

/// Whether `name` is the legacy YAML file or its renamed-aside form, so the
/// file provider ignores it without the "not a declared key" warning every key
/// file gets: it is a file this migration itself put there.
pub fn is_legacy_file_name(name: &str) -> bool {
    name == LEGACY_FILE_NAME
        || name == format!("{LEGACY_FILE_NAME}{LEGACY_MIGRATED_SUFFIX}")
        || std::env::var(LEGACY_FILE_ENV)
            .ok()
            .and_then(|raw| {
                Path::new(raw.trim())
                    .file_name()
                    .map(|file| file.to_string_lossy().to_string())
            })
            .is_some_and(|legacy| {
                name == legacy || name == format!("{legacy}{LEGACY_MIGRATED_SUFFIX}")
            })
}

/// The legacy on-disk YAML shape, read by [`migrate_legacy_file`] and by
/// nothing else. It is deliberately read-only: `no_production_code_writes_the_legacy_yaml_format`
/// fails the build if anything serializes it again, because a written YAML file
/// would be a second file-based layer (BUNYIP-644 AC1).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct LegacySysConfigFile {
    features: LegacyFeatures,
    country_access: LegacyCountryAccess,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct LegacyFeatures {
    login_approval_enabled: Option<bool>,
    signup_bot_guard_enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct LegacyCountryAccess {
    allow: Vec<String>,
    deny: Vec<String>,
}

impl LegacySysConfigFile {
    /// The declared key each legacy field maps onto. The same key set
    /// [`SystemSettings::entries`] writes, so a migrated file and an admin save
    /// land on the same files.
    fn entries(&self) -> Vec<(&'static str, Option<String>)> {
        vec![
            (
                "LOGIN_APPROVAL_ENABLED",
                self.features.login_approval_enabled.map(|v| v.to_string()),
            ),
            (
                "SIGNUP_BOT_GUARD_ENABLED",
                self.features
                    .signup_bot_guard_enabled
                    .map(|v| v.to_string()),
            ),
            (
                "COUNTRY_ALLOW",
                join_countries(&normalize_countries(&self.country_access.allow)),
            ),
            (
                "COUNTRY_DENY",
                join_countries(&normalize_countries(&self.country_access.deny)),
            ),
        ]
    }
}

/// Write one key file atomically: a sibling temp file renamed over the target.
fn write_key_file(path: &Path, value: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{value}\n"))?;
    std::fs::rename(&tmp, path)
}

/// A boolean setting: any value but `true` / `1` is false, which is what the
/// YAML layer's env parser did and what every existing deployment resolves.
fn flag(stack: &ConfigStack, key: &str) -> bool {
    stack.get(key).is_some_and(|raw| {
        let raw = raw.trim();
        raw.eq_ignore_ascii_case("true") || raw == "1"
    })
}

/// A country list setting: comma or whitespace separated ISO alpha-2 codes.
fn countries(stack: &ConfigStack, key: &str) -> Vec<String> {
    let Some(raw) = stack.get(key) else {
        return Vec::new();
    };
    normalize_countries(
        &raw.split(|c: char| c == ',' || c.is_whitespace())
            .map(str::to_string)
            .collect::<Vec<String>>(),
    )
}

/// Normalise country codes to trimmed upper-case ISO alpha-2, dropping blanks.
fn normalize_countries(codes: &[String]) -> Vec<String> {
    codes
        .iter()
        .map(|c| c.trim().to_uppercase())
        .filter(|c| !c.is_empty())
        .collect()
}

/// The stored text for a country list; an empty list is stored as ABSENT, so
/// clearing the setting removes its file rather than writing an empty one.
fn join_countries(codes: &[String]) -> Option<String> {
    let joined = normalize_countries(codes).join(",");
    Some(joined).filter(|joined| !joined.is_empty())
}

/// A system-level string setting: the env layer only, trimmed, empty as unset.
fn str_setting(env: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    env(name)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The env layer for one system-level key: the plain `{NAME}` variable, or its
/// `{NAME}_FILE` indirection (a mounted file path). The `_FILE` form keeps a
/// secret-bearing value off the process environment and the Infisical path
/// intact (the BUNYIP-579 `_FILE` acceptance criterion).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_providers::{ConfigProviderKind, FileProvider, SYSTEM_SETTINGS_KEYS};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// Env lookup backed by a fixed set of pairs, so the system-level half is
    /// tested without touching the real process environment.
    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    fn unique_temp_dir(tag: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "bunyip-sysconfig-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// A stack of the file layer at `dir` alone, so precedence is exercised
    /// without the process environment.
    fn file_stack(dir: &Path) -> ConfigStack {
        ConfigStack::new(vec![Arc::new(FileProvider::load(dir.to_path_buf()))])
    }

    #[test]
    fn application_level_precedence_is_file_then_environment_then_default() {
        let dir = unique_temp_dir("precedence");
        // No file, no environment: the built-in default stands.
        let bare = SystemSettings::resolve(&file_stack(&dir));
        assert!(!bare.login_approval_enabled);
        assert!(bare.country_allow.is_empty());

        // The file layer serves what it holds.
        std::fs::write(dir.join("LOGIN_APPROVAL_ENABLED"), "true\n").unwrap();
        std::fs::write(dir.join("COUNTRY_ALLOW"), " us , gb\n").unwrap();
        let from_file = SystemSettings::resolve(&file_stack(&dir));
        assert!(from_file.login_approval_enabled);
        assert_eq!(from_file.country_allow, vec!["US", "GB"]);

        // BUNYIP-644: the file layer outranks the environment, the one
        // precedence rule the whole stack follows.
        let stack = ConfigStack::new(vec![
            Arc::new(FileProvider::load(dir.clone())),
            Arc::new(Fixed(
                ConfigProviderKind::Environment,
                vec![("LOGIN_APPROVAL_ENABLED", "false")],
            )),
        ]);
        assert!(SystemSettings::resolve(&stack).login_approval_enabled);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A provider that holds exactly what the test gives it.
    #[derive(Debug)]
    struct Fixed(ConfigProviderKind, Vec<(&'static str, &'static str)>);

    impl ConfigProvider for Fixed {
        fn kind(&self) -> ConfigProviderKind {
            self.0
        }
        fn get(&self, key: &str) -> Option<String> {
            self.1
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn origins_resolve_from_the_environment_only() {
        // BUNYIP-622: a system-level origin can never be set through the file
        // layer. A directory that smuggles a CORS_ORIGIN file is ignored: the
        // origin still comes from the env, or the built-in default, never a file.
        let dir = unique_temp_dir("origins");
        std::fs::write(dir.join("CORS_ORIGIN"), "https://attacker.example").unwrap();
        std::fs::write(dir.join("COOKIE_DOMAIN"), ".attacker.example").unwrap();
        std::fs::write(dir.join("LOGIN_APPROVAL_ENABLED"), "true").unwrap();

        let stack = file_stack(&dir);
        let none = env_of(&[]);
        let resolved = SysConfig::resolve(&stack, &none);
        assert_eq!(
            resolved.cors_origin, "http://localhost:5173",
            "the file layer must not set a system-level origin"
        );
        assert!(resolved.cookie_domain.is_none());
        // The application-level toggle in the same directory still applies.
        assert!(resolved.login_approval_enabled);

        // The environment is the only source that sets it.
        let env = env_of(&[("CORS_ORIGIN", "https://real.example")]);
        assert_eq!(
            SysConfig::resolve(&stack, &env).cors_origin,
            "https://real.example"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn system_level_keys_never_enter_the_file_layer() {
        // BUNYIP-622 AC3/AC5, BUNYIP-644 AC2/AC3: the admin settings API writes
        // ONLY the declared application-level keys. The written key set is
        // pinned here, no system-level key is in it, and no system-level key is
        // even a declared configuration key, so the file layer cannot serve one
        // however it is written.
        let settings = SystemSettings {
            login_approval_enabled: true,
            signup_bot_guard_enabled: false,
            country_allow: vec!["US".into()],
            country_deny: vec!["RU".into()],
        };
        let written: Vec<&str> = settings.entries().into_iter().map(|(key, _)| key).collect();
        assert_eq!(
            written, SYSTEM_SETTINGS_KEYS,
            "the write path must carry exactly the declared application-level keys"
        );
        for key in SYSTEM_LEVEL_ENV_KEYS {
            assert!(
                !written.contains(key),
                "system-level key {key} must never be writable through the settings API"
            );
            assert!(
                crate::config_providers::config_key(key).is_none(),
                "system-level key {key} must never be a declared configuration key: the file layer \
                 would serve it"
            );
        }

        // And the write actually touches those files and no others: a save into
        // an empty directory leaves exactly the declared key files behind.
        let dir = unique_temp_dir("write-surface");
        for (key, value) in settings.entries() {
            if let Some(value) = value {
                write_key_file(&dir.join(key), &value).expect("write");
            }
        }
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .expect("read_dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        names.sort();
        let mut expected: Vec<String> =
            SYSTEM_SETTINGS_KEYS.iter().map(|k| k.to_string()).collect();
        expected.sort();
        assert_eq!(names, expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// BUNYIP-644 AC1: the legacy YAML format is READ once and never written,
    /// so a second file-based layer cannot come back. `serde_yaml::to_string` in
    /// production code would be that second layer being written again.
    #[test]
    fn no_production_code_writes_the_legacy_yaml_format() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|crates| crates.parent())
            .expect("bunyip-domain sits two levels below the workspace root")
            .to_path_buf();

        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        for dir in [root.join("crates"), root.join("bunyip-api/src")] {
            for file in rust_sources(&dir) {
                let source = std::fs::read_to_string(&file).expect("readable source");
                scanned += 1;
                let production = match source.find("#[cfg(test)]") {
                    Some(idx) => &source[..idx],
                    None => source.as_str(),
                };
                for (number, line) in production.lines().enumerate() {
                    if line.trim_start().starts_with("//") {
                        continue;
                    }
                    if line.contains("serde_yaml::to_string")
                        || line.contains("serde_yaml::to_writer")
                    {
                        offenders.push(format!("{}:{}", file.display(), number + 1));
                    }
                }
            }
        }

        assert!(scanned > 50, "the source scan found only {scanned} files");
        assert!(
            offenders.is_empty(),
            "the YAML system-config file is a migration source, not a configuration layer \
             (BUNYIP-644): write settings with SystemSettings::save, which writes one file per \
             declared key into the file layer: {offenders:#?}"
        );
    }

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

    #[test]
    fn country_codes_are_normalised_on_the_way_in_and_out() {
        let dir = unique_temp_dir("countries");
        std::fs::write(dir.join("COUNTRY_ALLOW"), " us gb, ,\n").unwrap();
        assert_eq!(
            SystemSettings::resolve(&file_stack(&dir)).country_allow,
            vec!["US", "GB"]
        );
        assert_eq!(
            join_countries(&[" us ".to_string(), String::new()]),
            Some("US".to_string())
        );
        assert_eq!(
            join_countries(&[]),
            None,
            "an empty list clears the setting"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_save_writes_one_file_per_key_and_a_cleared_list_removes_its_file() {
        let _env = crate::test_support::env_lock();
        let dir = unique_temp_dir("save");
        std::env::set_var(crate::config_providers::CONFIG_DIR_ENV, &dir);

        let settings = SystemSettings {
            login_approval_enabled: true,
            signup_bot_guard_enabled: false,
            country_allow: vec!["us".into()],
            country_deny: vec![],
        };
        settings.save().expect("save");
        assert_eq!(
            std::fs::read_to_string(dir.join("LOGIN_APPROVAL_ENABLED")).unwrap(),
            "true\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("COUNTRY_ALLOW")).unwrap(),
            "US\n"
        );
        assert!(!dir.join("COUNTRY_DENY").exists());
        assert_eq!(SystemSettings::current(), settings.normalized());

        // Clearing the allow list removes its file, so the setting is absent
        // rather than an empty value.
        let cleared = SystemSettings {
            country_allow: vec![],
            ..settings
        };
        cleared.save().expect("save");
        assert!(!dir.join("COUNTRY_ALLOW").exists());

        std::env::remove_var(crate::config_providers::CONFIG_DIR_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }

    impl SystemSettings {
        /// The settings as they read back out of the layer (codes upper-cased).
        fn normalized(&self) -> Self {
            Self {
                country_allow: normalize_countries(&self.country_allow),
                country_deny: normalize_countries(&self.country_deny),
                ..self.clone()
            }
        }
    }

    #[test]
    fn the_legacy_yaml_file_is_migrated_once_and_renamed_aside() {
        let _env = crate::test_support::env_lock();
        let dir = unique_temp_dir("migrate");
        std::env::remove_var(LEGACY_FILE_ENV);
        let legacy = dir.join(LEGACY_FILE_NAME);
        std::fs::write(
            &legacy,
            "features:\n  login_approval_enabled: true\ncountry_access:\n  deny:\n    - ru\n",
        )
        .unwrap();

        let unwritten = migrate_legacy_file(&dir, &legacy);
        assert!(
            unwritten.is_empty(),
            "everything was written: {unwritten:?}"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("LOGIN_APPROVAL_ENABLED")).unwrap(),
            "true\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("COUNTRY_DENY")).unwrap(),
            "RU\n"
        );
        // An absent YAML key stays absent: it is not written as `false`.
        assert!(!dir.join("SIGNUP_BOT_GUARD_ENABLED").exists());
        assert!(!legacy.exists(), "the migrated file is renamed aside");
        assert!(dir
            .join(format!("{LEGACY_FILE_NAME}{LEGACY_MIGRATED_SUFFIX}"))
            .exists());

        // The resolved values are the ones the YAML layer resolved.
        let resolved = SystemSettings::resolve(&file_stack(&dir));
        assert!(resolved.login_approval_enabled);
        assert_eq!(resolved.country_deny, vec!["RU"]);

        // Re-running is a no-op: there is no file left to read.
        assert!(migrate_legacy_file(&dir, &legacy).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_value_the_environment_already_overrode_is_dropped_not_migrated() {
        // The YAML layer ranked BELOW the environment, so this value was inert.
        // Migrating it would make it live and flip the resolved value, which is
        // the one thing the migration must not do (BUNYIP-644 AC5).
        let _env = crate::test_support::env_lock();
        let dir = unique_temp_dir("migrate-env");
        std::env::remove_var(LEGACY_FILE_ENV);
        std::env::set_var("LOGIN_APPROVAL_ENABLED", "false");
        let legacy = dir.join(LEGACY_FILE_NAME);
        std::fs::write(&legacy, "features:\n  login_approval_enabled: true\n").unwrap();

        assert!(migrate_legacy_file(&dir, &legacy).is_empty());
        assert!(
            !dir.join("LOGIN_APPROVAL_ENABLED").exists(),
            "the environment already served this key, so the YAML value is dropped"
        );

        std::env::remove_var("LOGIN_APPROVAL_ENABLED");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_existing_key_file_wins_over_the_legacy_yaml_value() {
        let _env = crate::test_support::env_lock();
        let dir = unique_temp_dir("migrate-existing");
        std::env::remove_var(LEGACY_FILE_ENV);
        std::fs::write(dir.join("COUNTRY_DENY"), "KP\n").unwrap();
        let legacy = dir.join(LEGACY_FILE_NAME);
        std::fs::write(&legacy, "country_access:\n  deny:\n    - ru\n").unwrap();

        assert!(migrate_legacy_file(&dir, &legacy).is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.join("COUNTRY_DENY")).unwrap(),
            "KP\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_legacy_file_names_are_not_reported_as_stray_files() {
        let _env = crate::test_support::env_lock();
        std::env::remove_var(LEGACY_FILE_ENV);
        assert!(is_legacy_file_name(LEGACY_FILE_NAME));
        assert!(is_legacy_file_name(&format!(
            "{LEGACY_FILE_NAME}{LEGACY_MIGRATED_SUFFIX}"
        )));
        assert!(!is_legacy_file_name("SMTP_HOST"));

        std::env::set_var(LEGACY_FILE_ENV, "/etc/bunyip/system.yaml");
        assert!(is_legacy_file_name("system.yaml"));
        assert!(is_legacy_file_name("system.yaml.migrated"));
        std::env::remove_var(LEGACY_FILE_ENV);
    }
}
