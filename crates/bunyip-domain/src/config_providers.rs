//! BUNYIP-643: configuration providers with declared precedence.
//!
//! Secrets already come from ONE store the deployment declares (`SECRETS_STORAGE`,
//! BUNYIP-542). Configuration did not: `EmailConfig::from_db_row` /
//! `has_db_overrides` (and the same pair on [`AutoBanConfig`] and [`TierConfig`])
//! applied database values on top of the environment, and the precedence existed
//! only as the order two functions happened to be called in. This module makes
//! that precedence a declaration, adds the file provider an operator can edit
//! without a database write or a redeploy, and records which provider supplied
//! each value.
//!
//! [`AutoBanConfig`]: crate::config::AutoBanConfig
//! [`TierConfig`]: crate::config::TierConfig
//!
//! # Priority
//!
//! | Priority | Provider      | What it is                                                        |
//! |----------|---------------|-------------------------------------------------------------------|
//! | 1        | `database`    | the admin pages: in-product, per-deployment, applies without a restart |
//! | 2        | `file`        | `BUNYIP_CONFIG_DIR`, one file per key: the operator's on-disk edit |
//! | 3        | `environment` | the variables in [`ENV_INVENTORY`], the deployment's baked-in declaration |
//!
//! The database is highest because that is where it already was: an existing
//! deployment resolves exactly the values it resolved before, since the file
//! provider is off until an operator sets `BUNYIP_CONFIG_DIR`. The file sits
//! ABOVE the environment because a file that could not override a value baked
//! into compose would not be editable-without-a-redeploy, which is the whole
//! reason it exists. (The older YAML layer in [`crate::sys_config`] orders its
//! own, disjoint keys the other way round; it is API-writable, which this
//! provider is not, and BUNYIP-644 tracks unifying the two.)
//!
//! # The registry
//!
//! [`CONFIG_KEYS`] declares the settings with MORE THAN ONE possible provider,
//! the same rule [`GovernedSecret`](crate::config::GovernedSecret) applies to
//! secrets: a setting with exactly one source needs no declaration, because the
//! declaration would be a no-op. So the Stripe price ids, `pricing_enabled` and
//! `orgs_enabled` stay database-only columns and are read straight from their
//! row, and `SMTP_EHLO_NAME` and `APP_URL` stay environment reads.
//!
//! [`ENV_INVENTORY`](crate::config::ENV_INVENTORY) remains the declared registry
//! of environment variables; every key here names the variable it is carried by,
//! and `config_keys_name_an_inventory_variable` fails the build if one does not.
//!
//! Most of the registry is written down one `spec` per line. The
//! `RATE_LIMIT_{ACTION}_*` family is not: its names are built from the action,
//! so it is GENERATED, one pair per [`RateLimitConfig::ALL`] entry, by
//! [`rate_limit_vars`] (BUNYIP-645). That is why [`CONFIG_KEYS`] is materialized
//! at first use rather than being a plain `static` slice.
//!
//! [`RateLimitConfig::ALL`]: crate::models::RateLimitConfig::ALL
//! [`rate_limit_vars`]: crate::models::rate_limit_vars
//!
//! # Group-1 keys
//!
//! The startup values (`DATABASE_URL`, `APP_ENCRYPTION_KEY`, `JWT_SECRET`, ...)
//! are environment-and-file only: the database cannot hold the credential used
//! to reach the database. [`DatabaseProvider::set`] REFUSES a
//! [`GROUP_ONE_KEYS`] entry with a [`ConfigFailure`] naming it, so the refusal
//! is a startup error rather than a boot that deadlocks.
//!
//! # Reporting
//!
//! [`classify`] is the same 2x2 as `bunyip_api::secrets::classify`, over the
//! same two axes (does the highest-priority provider hold it; does any other):
//!
//! | Situation                                          | Secrets           | Configuration            |
//! |----------------------------------------------------|-------------------|--------------------------|
//! | only the top provider holds it                      | `Use`             | [`ConfigVerdict::Use`]   |
//! | no provider holds it                                | `FeatureOff`      | [`ConfigVerdict::Default`] |
//! | the top provider and another hold it                | `Duplicated`      | [`ConfigVerdict::Overridden`] |
//! | the top provider does not, a lower one does         | `Misplaced`       | [`ConfigVerdict::Shadowed`] |
//!
//! The one deliberate difference is severity, not shape. `Misplaced` is FATAL
//! for secrets because the deployment declared ONE store, so reading another is
//! the silent precedence BUNYIP-542 removed. Configuration declares an ORDER, so
//! a lower provider serving a key is how an override is meant to work:
//! [`ConfigVerdict::Shadowed`] is reported in the status contract, never fatal
//! and not logged at boot (it is the ordinary case for every environment-only
//! setting). [`ConfigVerdict::Overridden`] IS logged at boot, one `warn!` per
//! ignored provider, exactly as `Duplicated` is: that is the stale-copy case,
//! where a value in compose is dead because the admin page also holds one.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, OnceLock};

use crate::config::ConfigFailure;
use crate::models::rate_limit_vars;

/// A configuration provider, in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfigProviderKind {
    /// The admin-managed singleton rows (`email_config`, `auto_ban_config`,
    /// `tier_config`).
    Database,
    /// One file per key under `BUNYIP_CONFIG_DIR`.
    File,
    /// The process environment, i.e. [`ENV_INVENTORY`](crate::config::ENV_INVENTORY).
    Environment,
}

impl ConfigProviderKind {
    /// Every provider, highest priority first. The declaration this whole
    /// module exists to make.
    pub const BY_PRIORITY: [Self; 3] = [Self::Database, Self::File, Self::Environment];

    /// The wire/report spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::File => "file",
            Self::Environment => "environment",
        }
    }

    /// 1 is highest. Used to order holders in a report.
    pub fn priority(self) -> u8 {
        match self {
            Self::Database => 1,
            Self::File => 2,
            Self::Environment => 3,
        }
    }
}

impl std::fmt::Display for ConfigProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a provider can say about the keys it holds.
///
/// [`Enumeration::Unsupported`] is NOT an empty list: it is "I cannot tell you",
/// which the status contract renders as unknown rather than as "holds nothing".
/// The distinction is the configuration twin of `Survey::infisical_inspected`: a
/// store whose contents could not be read must never read as an empty store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enumeration {
    /// The keys this provider holds.
    Keys(Vec<String>),
    /// This provider cannot list its keys.
    Unsupported,
}

/// One source of configuration values.
pub trait ConfigProvider: Send + Sync + std::fmt::Debug {
    /// Which provider this is; also its priority.
    fn kind(&self) -> ConfigProviderKind;

    /// This provider's value for `key`, or `None` when it holds none.
    fn get(&self, key: &str) -> Option<String>;

    /// Whether this provider holds `key`.
    fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// The keys this provider holds, when it can say.
    fn enumerate(&self) -> Enumeration {
        Enumeration::Unsupported
    }

    /// Why this provider could not be read, when it could not. `None` means the
    /// provider answered; it does not mean the provider held something.
    fn unreadable(&self) -> Option<&str> {
        None
    }

    /// Where this provider reads from, when that is a place an operator can go
    /// look (the file provider's directory). `None` for the providers whose
    /// location is the process itself.
    fn location(&self) -> Option<String> {
        None
    }
}

// =============================================================================
// The key registry
// =============================================================================

/// One configuration setting resolved through the provider stack.
#[derive(Clone, Copy)]
pub struct ConfigKeySpec {
    /// The provider-stack key, which is also the file name under
    /// `BUNYIP_CONFIG_DIR`.
    pub key: &'static str,
    /// The [`ENV_INVENTORY`](crate::config::ENV_INVENTORY) variable that carries
    /// it. Equal to `key` except where one variable carries two settings
    /// (`SMTP_FROM` carries the address and the display name).
    pub source_var: &'static str,
    /// What it configures, operator-facing, like `GovernedSecret::feature`.
    pub setting: &'static str,
    /// How the raw variable text becomes this key's value. Identity for every
    /// key but the two `SMTP_FROM` halves.
    pub derive: fn(&str) -> Option<String>,
}

fn verbatim(raw: &str) -> Option<String> {
    Some(raw.to_string())
}

fn from_address(raw: &str) -> Option<String> {
    Some(crate::config::parse_smtp_from_email(raw))
}

fn from_display_name(raw: &str) -> Option<String> {
    Some(crate::config::parse_smtp_from_name(raw))
}

const fn spec(key: &'static str, setting: &'static str) -> ConfigKeySpec {
    ConfigKeySpec {
        key,
        source_var: key,
        setting,
        derive: verbatim,
    }
}

/// The settings written down one line each: every declared key except the
/// generated `RATE_LIMIT_*` family (see [`CONFIG_KEYS`], which is the registry).
///
/// A setting joins this list the moment it gains a second provider, and leaves
/// it if it ever loses one. Group-1 startup values are structurally excluded
/// (see [`GROUP_ONE_KEYS`]).
static SINGLETON_ROW_KEYS: &[ConfigKeySpec] = &[
    // ---- Email (email_config) --------------------------------------------
    spec(
        "SMTP_HOST",
        "the SMTP relay host outbound mail is sent through",
    ),
    spec("SMTP_PORT", "the SMTP relay port"),
    spec("SMTP_TLS", "the SMTP TLS mode (implicit or starttls)"),
    spec("SMTP_USERNAME", "the SMTP relay username"),
    ConfigKeySpec {
        key: "SMTP_FROM_EMAIL",
        source_var: "SMTP_FROM",
        setting: "the From: address on every system email",
        derive: from_address,
    },
    ConfigKeySpec {
        key: "SMTP_FROM_NAME",
        source_var: "SMTP_FROM",
        setting: "the From: display name on every system email",
        derive: from_display_name,
    },
    spec(
        "ADMIN_NOTIFICATION_EMAILS",
        "the recipients of operational notifications",
    ),
    spec("EMAIL_ENABLED", "whether outbound email is actually sent"),
    spec("SUPPORT_IMAP_HOST", "the inbound support-mailbox IMAP host"),
    spec("SUPPORT_IMAP_PORT", "the inbound support-mailbox IMAP port"),
    spec(
        "SUPPORT_IMAP_USERNAME",
        "the inbound support-mailbox IMAP username",
    ),
    spec(
        "SUPPORT_IMAP_MAILBOX",
        "the inbound support-mailbox folder polled for replies",
    ),
    spec(
        "SUPPORT_IMAP_ENABLED",
        "whether the support-queue poller runs",
    ),
    // ---- Auto-ban (auto_ban_config) ---------------------------------------
    spec(
        "AUTO_BAN_ENABLED",
        "whether abusive IPs are banned automatically",
    ),
    spec(
        "AUTO_BAN_THRESHOLD",
        "suspicious requests before an IP is banned",
    ),
    spec(
        "AUTO_BAN_WINDOW_SECS",
        "the window strikes are counted over",
    ),
    spec("AUTO_BAN_DURATION_SECS", "how long an automatic ban lasts"),
    // ---- Tiers (tier_config) ----------------------------------------------
    spec("TIER_LIFETIME_SLOTS", "how many lifetime memberships exist"),
    spec(
        "TIER_EARLY_ADOPTER_SLOTS",
        "how many early-adopter memberships exist",
    ),
    spec(
        "TIER_EARLY_ADOPTER_TRIAL_DAYS",
        "the early-adopter trial length",
    ),
    spec("TIER_STANDARD_TRIAL_DAYS", "the standard trial length"),
];

/// The generated `RATE_LIMIT_{ACTION}_{MAX_REQUESTS,WINDOW_SECONDS}` family
/// (BUNYIP-645), one pair per rate-limit preset.
///
/// The caps were the one configuration left resolving through a precedence
/// chain that existed only as the body of one function
/// (`RateLimitConfigRepository::effective`), for a structural reason: the
/// variable names are built from the action, so they could be neither
/// `ENV_INVENTORY` entries nor keys here. Generating both registries from the
/// one action list removes that exception without letting either registry drift
/// from the presets.
static RATE_LIMIT_CONFIG_KEYS: LazyLock<Vec<ConfigKeySpec>> = LazyLock::new(|| {
    rate_limit_vars()
        .iter()
        .flat_map(|vars| {
            [
                ConfigKeySpec {
                    key: vars.max_requests,
                    source_var: vars.max_requests,
                    setting: vars.max_requests_setting,
                    derive: verbatim,
                },
                ConfigKeySpec {
                    key: vars.window_seconds,
                    source_var: vars.window_seconds,
                    setting: vars.window_seconds_setting,
                    derive: verbatim,
                },
            ]
        })
        .collect()
});

/// Every configuration setting with more than one possible provider: the
/// written-down [`SINGLETON_ROW_KEYS`] plus the generated rate-limit family.
pub static CONFIG_KEYS: LazyLock<Vec<ConfigKeySpec>> = LazyLock::new(|| {
    SINGLETON_ROW_KEYS
        .iter()
        .copied()
        .chain(RATE_LIMIT_CONFIG_KEYS.iter().copied())
        .collect()
});

/// The spec for `key`, or `None` when it is not a declared configuration key.
pub fn config_key(key: &str) -> Option<&'static ConfigKeySpec> {
    CONFIG_KEYS.iter().find(|spec| spec.key == key)
}

/// The keys of the `email_config` section, for the admin page's source label.
pub const EMAIL_KEYS: &[&str] = &[
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_TLS",
    "SMTP_USERNAME",
    "SMTP_FROM_EMAIL",
    "SMTP_FROM_NAME",
    "ADMIN_NOTIFICATION_EMAILS",
    "EMAIL_ENABLED",
    "SUPPORT_IMAP_HOST",
    "SUPPORT_IMAP_PORT",
    "SUPPORT_IMAP_USERNAME",
    "SUPPORT_IMAP_MAILBOX",
    "SUPPORT_IMAP_ENABLED",
];

/// The keys of the `auto_ban_config` section.
pub const AUTO_BAN_KEYS: &[&str] = &[
    "AUTO_BAN_ENABLED",
    "AUTO_BAN_THRESHOLD",
    "AUTO_BAN_WINDOW_SECS",
    "AUTO_BAN_DURATION_SECS",
];

/// The keys of the `tier_config` section that have more than one provider. The
/// price ids and the feature switches are database-only and not declared keys.
pub const TIER_KEYS: &[&str] = &[
    "TIER_LIFETIME_SLOTS",
    "TIER_EARLY_ADOPTER_SLOTS",
    "TIER_EARLY_ADOPTER_TRIAL_DAYS",
    "TIER_STANDARD_TRIAL_DAYS",
];

/// The keys of the `rate_limit_configs` section (BUNYIP-645), generated like
/// the specs themselves so the section can never lag the preset list.
pub static RATE_LIMIT_KEYS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| RATE_LIMIT_CONFIG_KEYS.iter().map(|spec| spec.key).collect());

/// The Group-1 startup values: environment-and-file only, never the database.
///
/// The reason `CLAUDE.md` already gives: the database cannot hold the credential
/// used to reach the database, and a key set that could would deadlock the boot.
/// The at-rest and signing key material is here for the same reason - the
/// ciphertext in the database is unreadable without it.
pub const GROUP_ONE_KEYS: &[&str] = &[
    "DATABASE_URL",
    "APP_DATABASE_URL",
    "BUNYIP_APP_PASSWORD",
    "JWT_SECRET",
    "APP_ENCRYPTION_KEY",
    "APP_ENCRYPTION_KEY_PREV",
    "APP_KEY_VERSION",
    "BUNYIP_WEBHOOK_SIGNING_SECRET",
    "SECRETS_STORAGE",
    "INFISICAL_ADDRESS",
    "INFISICAL_CLIENT_ID",
    "INFISICAL_CLIENT_SECRET",
    "INFISICAL_PROJECT_ID",
    "INFISICAL_ENVIRONMENT",
];

/// Whether `key` is a Group-1 startup value.
pub fn is_group_one(key: &str) -> bool {
    GROUP_ONE_KEYS.contains(&key)
}

// =============================================================================
// The providers
// =============================================================================

/// The process environment: [`ENV_INVENTORY`](crate::config::ENV_INVENTORY) as
/// it stands, so today's behaviour is the default and no deployment changes.
///
/// An empty variable is a VALUE here, not an absence, because that is what the
/// existing readers do (`SMTP_USERNAME=` means "no username", not "fall back").
/// The `{NAME}_FILE` indirection is deliberately not consulted: it is the secret
/// convention, and no configuration key in [`CONFIG_KEYS`] is a secret.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvironmentProvider;

impl ConfigProvider for EnvironmentProvider {
    fn kind(&self) -> ConfigProviderKind {
        ConfigProviderKind::Environment
    }

    fn get(&self, key: &str) -> Option<String> {
        let spec = config_key(key)?;
        let raw = std::env::var(spec.source_var).ok()?;
        (spec.derive)(&raw)
    }

    fn enumerate(&self) -> Enumeration {
        Enumeration::Keys(
            CONFIG_KEYS
                .iter()
                .filter(|spec| self.has(spec.key))
                .map(|spec| spec.key.to_string())
                .collect(),
        )
    }
}

/// The env var naming the file provider's directory. Unset means the file
/// provider is not enabled, which is every deployment until an operator mounts
/// one.
pub const CONFIG_DIR_ENV: &str = "BUNYIP_CONFIG_DIR";

/// A directory of one file per key, the shape Traefik's file provider and
/// PMS-987 use, so the two repositories take the same shape.
///
/// A file is named for the key (`SMTP_HOST`) or for the variable that carries it
/// (`SMTP_FROM`), and its trimmed contents are the value; an empty file counts
/// as absent. A file whose name is not a declared key is IGNORED with a `warn!`,
/// so a typo is visible rather than silently inert.
#[derive(Debug, Clone)]
pub struct FileProvider {
    dir: PathBuf,
    values: BTreeMap<String, String>,
    /// Why the directory could not be read. The provider then holds nothing AND
    /// says so: an unreadable directory must never read as an empty one.
    error: Option<String>,
}

impl FileProvider {
    /// Load the directory named by `BUNYIP_CONFIG_DIR`. `None` when the variable
    /// is unset or empty: the provider is not enabled and is left out of the
    /// stack entirely, rather than joining it as a provider that holds nothing.
    pub fn from_env() -> Option<Self> {
        let dir = std::env::var(CONFIG_DIR_ENV)
            .ok()
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty())?;
        Some(Self::load(PathBuf::from(dir)))
    }

    /// Load one directory. Public so the tests drive it without the environment.
    pub fn load(dir: PathBuf) -> Self {
        let mut values = BTreeMap::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                let error = format!("{}: {e}", dir.display());
                tracing::error!(
                    config_dir = %dir.display(),
                    error = %e,
                    "the file configuration provider directory could not be read, so it holds no \
                     values; `bunyip-api config-status` reports it as unreadable rather than empty"
                );
                return Self {
                    dir,
                    values,
                    error: Some(error),
                };
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    tracing::error!(config_dir = %dir.display(), error = %e, "skipping an unreadable entry in the file configuration provider directory");
                    continue;
                }
            };
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let known = CONFIG_KEYS
                .iter()
                .any(|spec| spec.key == name || spec.source_var == name);
            if !known {
                tracing::warn!(
                    config_dir = %dir.display(),
                    file = name,
                    "ignoring {name} in the file configuration provider directory: it is not a \
                     declared configuration key (see CONFIG_KEYS / docs/configuration.md)"
                );
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    let trimmed = contents.trim().to_string();
                    if !trimmed.is_empty() {
                        values.insert(name.to_string(), trimmed);
                    }
                }
                Err(e) => tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "the file configuration provider could not read {name}, so it holds no value \
                     for it"
                ),
            }
        }

        Self {
            dir,
            values,
            error: None,
        }
    }

    /// The directory this provider reads.
    pub fn directory(&self) -> &std::path::Path {
        &self.dir
    }
}

impl ConfigProvider for FileProvider {
    fn kind(&self) -> ConfigProviderKind {
        ConfigProviderKind::File
    }

    fn get(&self, key: &str) -> Option<String> {
        let spec = config_key(key)?;
        // A file named for the key wins over one named for the variable that
        // carries it, so `SMTP_FROM_EMAIL` can be set without restating
        // `SMTP_FROM`.
        if let Some(value) = self.values.get(spec.key) {
            return (spec.derive)(value).filter(|v| !v.is_empty());
        }
        let raw = self.values.get(spec.source_var)?;
        (spec.derive)(raw).filter(|v| !v.is_empty())
    }

    fn enumerate(&self) -> Enumeration {
        if self.error.is_some() {
            return Enumeration::Unsupported;
        }
        Enumeration::Keys(
            CONFIG_KEYS
                .iter()
                .filter(|spec| self.has(spec.key))
                .map(|spec| spec.key.to_string())
                .collect(),
        )
    }

    fn unreadable(&self) -> Option<&str> {
        self.error.as_deref()
    }

    fn location(&self) -> Option<String> {
        Some(self.dir.display().to_string())
    }
}

/// The admin-managed singleton rows, as a provider.
///
/// This is where `from_db_row` / `has_db_overrides` went. A column is inserted
/// here only when it would have won the old per-field fallback (a NULL, an empty
/// string where the old code filtered one, or an out-of-range number is not
/// inserted), so the resolved value for an existing deployment is unchanged and
/// `is_empty` answers exactly the question `has_db_overrides` answered.
#[derive(Debug, Default, Clone)]
pub struct DatabaseProvider {
    values: BTreeMap<&'static str, String>,
}

impl DatabaseProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `value` for `key`.
    ///
    /// REFUSES a Group-1 startup value and an undeclared key, both as a
    /// [`ConfigFailure`] naming the key, so the refusal reaches the operator as
    /// a startup configuration error and exit 1 rather than as a boot that
    /// cannot reach the database it is trying to read the database URL from.
    pub fn set(
        &mut self,
        key: &'static str,
        value: impl Into<String>,
    ) -> Result<(), ConfigFailure> {
        if is_group_one(key) {
            return Err(ConfigFailure {
                var: key,
                reason: format!(
                    "{key} is a Group-1 startup value and the database provider refuses it: the \
                     database cannot hold the credential used to reach the database"
                ),
                remedy: format!(
                    "Supply {key} from the environment ({key}_FILE) or the file provider \
                     ({CONFIG_DIR_ENV}), and remove it from the database provider."
                ),
            });
        }
        let Some(spec) = config_key(key) else {
            return Err(ConfigFailure {
                var: key,
                reason: format!("{key} is not a declared configuration key"),
                remedy: format!(
                    "Add {key} to CONFIG_KEYS in crates/bunyip-domain/src/config_providers.rs, \
                     or stop writing it to the database provider."
                ),
            });
        };
        self.values.insert(spec.key, value.into());
        Ok(())
    }

    /// [`Self::set`] for a nullable column: `None` holds nothing.
    pub fn set_opt(
        &mut self,
        key: &'static str,
        value: Option<impl Into<String>>,
    ) -> Result<(), ConfigFailure> {
        match value {
            Some(value) => self.set(key, value),
            None => Ok(()),
        }
    }

    /// [`Self::set_opt`] that also drops an empty string, for the columns whose
    /// old fallback filtered one (`smtp_host`, `from_email`, `imap_mailbox`, ...).
    pub fn set_non_empty(
        &mut self,
        key: &'static str,
        value: Option<String>,
    ) -> Result<(), ConfigFailure> {
        self.set_opt(key, value.filter(|v| !v.is_empty()))
    }

    /// Whether this provider holds nothing. Replaces `has_db_overrides`.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Merge another provider's keys in. Used by `config-status`, which surveys
    /// every singleton row at once.
    pub fn merge(&mut self, other: Self) {
        self.values.extend(other.values);
    }
}

impl ConfigProvider for DatabaseProvider {
    fn kind(&self) -> ConfigProviderKind {
        ConfigProviderKind::Database
    }

    fn get(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }

    fn enumerate(&self) -> Enumeration {
        Enumeration::Keys(self.values.keys().map(|key| (*key).to_string()).collect())
    }
}

// =============================================================================
// The stack
// =============================================================================

/// The providers in declared priority order.
#[derive(Debug, Clone)]
pub struct ConfigStack {
    providers: Vec<Arc<dyn ConfigProvider>>,
}

impl ConfigStack {
    /// Build a stack from providers in any order; they are sorted by priority
    /// here so the order can never be an accident of the call site, which is the
    /// defect this module removes.
    pub fn new(providers: Vec<Arc<dyn ConfigProvider>>) -> Self {
        let mut providers = providers;
        providers.sort_by_key(|provider| provider.kind().priority());
        Self { providers }
    }

    /// The environment provider alone: no file, no database. What
    /// `EmailConfig::from_env` and its siblings resolve through, so a caller
    /// that wants only what the process environment declares can say so.
    pub fn environment_only() -> Self {
        Self::new(vec![Arc::new(EnvironmentProvider)])
    }

    /// The deployment providers: file (when enabled) then environment. No
    /// database, for the readers that run before or without a pool.
    pub fn deployment() -> Self {
        let mut providers: Vec<Arc<dyn ConfigProvider>> = vec![Arc::new(EnvironmentProvider)];
        if let Some(file) = FileProvider::from_env() {
            providers.push(Arc::new(file));
        }
        Self::new(providers)
    }

    /// [`Self::deployment`], loaded once per process.
    ///
    /// The file provider reads a directory, so a caller on a hot path must not
    /// rebuild it: the rate-limit caps resolve underneath every request, which
    /// is the same reason their database layer is a TTL snapshot (BUNYIP-556).
    /// The values it serves cannot go stale within a process anyway: a file
    /// provider edit and an environment change both need a restart to apply.
    pub fn deployment_cached() -> &'static Self {
        static STACK: OnceLock<ConfigStack> = OnceLock::new();
        STACK.get_or_init(Self::deployment)
    }

    /// [`Self::deployment`] with the database provider on top.
    pub fn with_database(database: DatabaseProvider) -> Self {
        Self::database_over(database, &Self::deployment())
    }

    /// [`Self::with_database`] over an ALREADY-LOADED lower stack, so a caller
    /// that layers a fresh database provider repeatedly (the rate-limit
    /// snapshot, once per TTL window) pays for the file provider once.
    pub fn database_over(database: DatabaseProvider, lower: &Self) -> Self {
        let mut providers = lower.providers.clone();
        providers.insert(0, Arc::new(database));
        // Sorted, not merely prepended: `lower` may already carry a database
        // provider, and the order must never depend on the call site.
        Self::new(providers)
    }

    /// The providers, highest priority first.
    pub fn providers(&self) -> &[Arc<dyn ConfigProvider>] {
        &self.providers
    }

    /// The highest-priority provider in this stack. The pivot [`classify`] uses.
    pub fn top(&self) -> Option<ConfigProviderKind> {
        self.providers.first().map(|provider| provider.kind())
    }

    /// Every provider holding `key`, highest priority first.
    pub fn holders(&self, key: &str) -> Vec<ConfigProviderKind> {
        self.providers
            .iter()
            .filter(|provider| provider.has(key))
            .map(|provider| provider.kind())
            .collect()
    }

    /// The value the highest-priority holder supplies, or `None` when no
    /// provider holds `key` and the caller's built-in default stands.
    pub fn get(&self, key: &str) -> Option<String> {
        self.providers.iter().find_map(|provider| provider.get(key))
    }

    /// [`Self::get`] restricted to providers ABOVE `kind`.
    pub fn get_above(&self, kind: ConfigProviderKind, key: &str) -> Option<String> {
        self.providers
            .iter()
            .filter(|provider| provider.kind().priority() < kind.priority())
            .find_map(|provider| provider.get(key))
    }

    /// [`Self::get`] restricted to providers BELOW `kind`.
    pub fn get_below(&self, kind: ConfigProviderKind, key: &str) -> Option<String> {
        self.providers
            .iter()
            .filter(|provider| provider.kind().priority() > kind.priority())
            .find_map(|provider| provider.get(key))
    }

    /// [`Self::get`], parsed. A held value that does not parse is logged at
    /// `warn` naming the key and the provider that holds it, then treated as
    /// absent so the caller's default stands: the substitution is never silent.
    pub fn get_parsed<T: std::str::FromStr>(&self, key: &str) -> Option<T> {
        self.get_parsed_where(key, |_| true)
    }

    /// [`Self::get_parsed`] with a validity rule, for a key whose type admits
    /// values it cannot use (a rate-limit cap of zero would refuse every
    /// request for the action). A value that fails `valid` is treated exactly
    /// like one that does not parse: logged at `warn`, then the next provider,
    /// or the built-in default, serves it.
    pub fn get_parsed_where<T: std::str::FromStr>(
        &self,
        key: &str,
        valid: impl Fn(&T) -> bool,
    ) -> Option<T> {
        for provider in &self.providers {
            let Some(raw) = provider.get(key) else {
                continue;
            };
            match raw.trim().parse::<T>() {
                Ok(value) if valid(&value) => return Some(value),
                Ok(_) => tracing::warn!(
                    config_key = key,
                    provider = %provider.kind(),
                    "the {} configuration provider holds a value for {key} that {key} cannot use; \
                     the next provider, or the built-in default, serves it instead",
                    provider.kind(),
                ),
                // A value this key cannot use is not a value: the next provider
                // serves, and the built-in default stands if none can. Same rule
                // the database provider applies at insertion time, where an
                // out-of-range column is never held in the first place.
                Err(_) => tracing::warn!(
                    config_key = key,
                    provider = %provider.kind(),
                    "the {} configuration provider holds a value for {key} that does not parse; \
                     the next provider, or the built-in default, serves it instead",
                    provider.kind(),
                ),
            }
        }
        None
    }

    /// Which provider supplied `key`, and what the stack made of the holders.
    pub fn resolve(&self, key: &str) -> ConfigVerdict {
        classify(self.top(), &self.holders(key))
    }

    /// The highest-priority provider holding ANY of `keys`, which is the
    /// one-word source label the admin pages show for a section. `None` means no
    /// provider holds any of them, so the built-in defaults stand.
    pub fn serving_any(&self, keys: &[&str]) -> Option<ConfigProviderKind> {
        self.providers
            .iter()
            .find(|provider| keys.iter().any(|key| provider.has(key)))
            .map(|provider| provider.kind())
    }

    /// One `warn!` per ignored provider, for every key the database provider
    /// holds that a lower provider also holds. Mirrors the `Duplicated` arm of
    /// the secrets boot enforcement: the lower copy is dead today and becomes
    /// live the moment the higher one is cleared.
    pub fn log_shadowed_providers(&self) {
        for spec in CONFIG_KEYS.iter() {
            let ConfigVerdict::Overridden { serving, ignored } = self.resolve(spec.key) else {
                continue;
            };
            for provider in ignored {
                tracing::warn!(
                    config_key = spec.key,
                    serving = %serving,
                    ignored_provider = %provider,
                    "{} is set in the {provider} configuration provider and in the higher-priority \
                     {serving} provider, which wins. The {provider} value is ignored today and \
                     becomes live if the {serving} value is cleared. It configures {}.",
                    spec.key,
                    spec.setting,
                );
            }
        }
    }
}

/// What the provider stack decides for one key.
///
/// The same 2x2 as `bunyip_api::secrets::classify`; see the module docs for the
/// one place the SEVERITY deliberately differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigVerdict {
    /// Only the highest-priority provider holds it.
    Use(ConfigProviderKind),
    /// No provider holds it: the built-in default stands.
    Default,
    /// The highest-priority provider holds it and so do others, whose values are
    /// ignored.
    Overridden {
        serving: ConfigProviderKind,
        ignored: Vec<ConfigProviderKind>,
    },
    /// The highest-priority provider does not hold it, a lower one does. Normal
    /// for configuration, and the flag BUNYIP-634 surfaces.
    ///
    /// `ignored` carries the still-lower providers that also hold it, so the
    /// held-by-several fact is never lost when the top provider is not one of
    /// the holders (a file value shadowing an environment value, for instance).
    Shadowed {
        serving: ConfigProviderKind,
        absent_from: ConfigProviderKind,
        ignored: Vec<ConfigProviderKind>,
    },
}

impl ConfigVerdict {
    /// The provider that supplied the value: the per-key provenance. `None`
    /// means the built-in default.
    pub fn serving(&self) -> Option<ConfigProviderKind> {
        match self {
            Self::Use(kind) => Some(*kind),
            Self::Default => None,
            Self::Overridden { serving, .. } | Self::Shadowed { serving, .. } => Some(*serving),
        }
    }

    /// The short condition name used in the status contract.
    pub fn condition(&self) -> &'static str {
        match self {
            Self::Use(_) => "use",
            Self::Default => "default",
            Self::Overridden { .. } => "overridden",
            Self::Shadowed { .. } => "shadowed",
        }
    }
}

/// The pure classification: which provider is highest priority, which hold a
/// value. Kept free of IO so every cell of the table is unit-tested, exactly as
/// the secrets `classify` is.
pub fn classify(top: Option<ConfigProviderKind>, holders: &[ConfigProviderKind]) -> ConfigVerdict {
    let Some(top) = top else {
        return ConfigVerdict::Default;
    };
    let others: Vec<ConfigProviderKind> = holders
        .iter()
        .copied()
        .filter(|kind| *kind != top)
        .collect();
    match (holders.contains(&top), others.first().copied()) {
        (true, None) => ConfigVerdict::Use(top),
        (true, Some(_)) => ConfigVerdict::Overridden {
            serving: top,
            ignored: others,
        },
        (false, None) => ConfigVerdict::Default,
        (false, Some(serving)) => ConfigVerdict::Shadowed {
            serving,
            absent_from: top,
            ignored: others[1..].to_vec(),
        },
    }
}

// =============================================================================
// The status contract
// =============================================================================

/// The `config-status` report: per-key provenance and provider membership.
///
/// Carries no VALUE, for the same reason the secrets report carries none: the
/// report is what an operator (and, once BUNYIP-634 lands, another application)
/// reads to answer "which provider is serving this", and a value in it would put
/// configuration into a channel sized for membership.
#[derive(Debug, serde::Serialize)]
pub struct ConfigStatusReport {
    /// The providers in force, highest priority first.
    pub priority: Vec<String>,
    /// The file provider's directory, when it is enabled.
    pub file_directory: Option<String>,
    /// Set when a provider could not be read, so its rows read "unknown" rather
    /// than "empty".
    pub unreadable: Vec<ProviderError>,
    pub keys: Vec<ConfigKeyStatus>,
}

/// One provider that could not be read.
#[derive(Debug, serde::Serialize)]
pub struct ProviderError {
    pub provider: String,
    pub error: String,
}

/// One configuration key's status.
#[derive(Debug, serde::Serialize)]
pub struct ConfigKeyStatus {
    pub key: String,
    /// The variable that carries it, for the operator looking for it in compose.
    pub source_var: String,
    /// Every provider holding a value, highest priority first.
    pub providers: Vec<String>,
    /// The provider that supplied the value: the provenance. `None` is the
    /// built-in default.
    pub serving: Option<String>,
    /// `use` / `default` / `overridden` / `shadowed`.
    pub condition: String,
    /// The operator-facing line, the same shape the secrets report uses.
    pub note: String,
}

/// Build the status report from a stack. Pure, so the report shapes are testable
/// and nothing here can mutate a provider.
pub fn status_report(stack: &ConfigStack) -> ConfigStatusReport {
    let keys = CONFIG_KEYS
        .iter()
        .map(|spec| {
            let holders = stack.holders(spec.key);
            let verdict = classify(stack.top(), &holders);
            ConfigKeyStatus {
                key: spec.key.to_string(),
                source_var: spec.source_var.to_string(),
                providers: holders.iter().map(|kind| kind.to_string()).collect(),
                serving: verdict.serving().map(|kind| kind.to_string()),
                condition: verdict.condition().to_string(),
                note: verdict_note(spec, &verdict),
            }
        })
        .collect();

    ConfigStatusReport {
        priority: stack
            .providers()
            .iter()
            .map(|provider| provider.kind().to_string())
            .collect(),
        file_directory: stack
            .providers()
            .iter()
            .find(|provider| provider.kind() == ConfigProviderKind::File)
            .and_then(|provider| provider.location()),
        unreadable: stack
            .providers()
            .iter()
            .filter_map(|provider| {
                provider.unreadable().map(|error| ProviderError {
                    provider: provider.kind().to_string(),
                    error: error.to_string(),
                })
            })
            .collect(),
        keys,
    }
}

/// The operator-facing sentence for one verdict, mirroring the four secrets
/// enforcement messages.
fn verdict_note(spec: &ConfigKeySpec, verdict: &ConfigVerdict) -> String {
    match verdict {
        ConfigVerdict::Use(kind) => format!("{kind} holds it and no other provider does"),
        ConfigVerdict::Default => format!(
            "no provider holds it, so the built-in default configures {}",
            spec.setting
        ),
        ConfigVerdict::Overridden { serving, ignored } => format!(
            "{serving} holds it and so does {}, whose value is ignored today and becomes live if \
             the {serving} value is cleared",
            provider_list(ignored)
        ),
        ConfigVerdict::Shadowed {
            serving,
            absent_from,
            ignored,
        } if ignored.is_empty() => format!(
            "{absent_from} does not hold it, so the lower-priority {serving} provider serves it"
        ),
        ConfigVerdict::Shadowed {
            serving,
            absent_from,
            ignored,
        } => format!(
            "{absent_from} does not hold it, so the lower-priority {serving} provider serves it; \
             {} also holds it and is ignored",
            provider_list(ignored)
        ),
    }
}

/// Render a provider list for an operator message ("file and environment").
fn provider_list(providers: &[ConfigProviderKind]) -> String {
    let names: Vec<&str> = providers.iter().map(|kind| kind.as_str()).collect();
    match names.as_slice() {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Render the status report as the operator-facing table. Mirrors the JSON
/// exactly, and like it never prints a value.
pub fn render_status(report: &ConfigStatusReport) -> String {
    let mut out = format!(
        "configuration providers, highest priority first: {}\n",
        report.priority.join(", ")
    );
    if let Some(dir) = &report.file_directory {
        out.push_str(&format!("{CONFIG_DIR_ENV}={dir}\n"));
    }
    for failure in &report.unreadable {
        out.push_str(&format!(
            "warning: the {} provider could not be read: {}\n",
            failure.provider, failure.error
        ));
    }
    for key in &report.keys {
        let providers = if key.providers.is_empty() {
            "(none)".to_string()
        } else {
            key.providers.join(", ")
        };
        out.push_str(&format!("\n{} (from {})\n", key.key, key.source_var));
        out.push_str(&format!("  held by:  {providers}\n"));
        out.push_str(&format!(
            "  serving:  {}\n",
            key.serving
                .clone()
                .unwrap_or_else(|| "(none: the built-in default)".to_string())
        ));
        out.push_str(&format!("  {:<9} {}\n", key.condition, key.note));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AC2: every configuration key names a variable that ENV_INVENTORY
    /// classifies, so the inventory stays the declared registry rather than
    /// being duplicated here.
    #[test]
    fn config_keys_name_an_inventory_variable() {
        let missing: Vec<&str> = CONFIG_KEYS
            .iter()
            .filter(|spec| crate::config::env_spec(spec.source_var).is_none())
            .map(|spec| spec.source_var)
            .collect();
        assert!(
            missing.is_empty(),
            "every CONFIG_KEYS entry must be carried by a variable classified in ENV_INVENTORY: \
             {missing:?}"
        );
    }

    /// The registry is settings with MORE THAN ONE provider, so a Group-1 key
    /// can never appear in it: it would declare a database source for a value
    /// the database provider refuses.
    #[test]
    fn no_config_key_is_a_group_one_startup_value() {
        let offenders: Vec<&str> = CONFIG_KEYS
            .iter()
            .filter(|spec| is_group_one(spec.key) || is_group_one(spec.source_var))
            .map(|spec| spec.key)
            .collect();
        assert!(
            offenders.is_empty(),
            "a Group-1 startup value must not be a configuration provider key: {offenders:?}"
        );
    }

    /// Every declared key belongs to exactly one section, so the admin pages'
    /// source label cannot silently stop covering a key someone adds.
    #[test]
    fn every_config_key_belongs_to_exactly_one_section() {
        let sections: [&[&str]; 4] = [EMAIL_KEYS, AUTO_BAN_KEYS, TIER_KEYS, &RATE_LIMIT_KEYS];
        for spec in CONFIG_KEYS.iter() {
            let found = sections
                .iter()
                .filter(|section| section.contains(&spec.key))
                .count();
            assert_eq!(
                found, 1,
                "{} must be in exactly one of EMAIL_KEYS / AUTO_BAN_KEYS / TIER_KEYS / \
                 RATE_LIMIT_KEYS",
                spec.key
            );
        }
        let declared: usize = sections.iter().map(|section| section.len()).sum();
        assert_eq!(
            declared,
            CONFIG_KEYS.len(),
            "a section names a key that is not declared in CONFIG_KEYS"
        );
    }

    /// AC4 (BUNYIP-645): `config-status` reports the per-action provenance
    /// alongside every other key, so an operator can ask which provider is
    /// serving one action's cap.
    #[test]
    fn the_status_report_covers_every_rate_limit_action() {
        let stack = stack_of(vec![
            Fixed::provider(
                ConfigProviderKind::Environment,
                &[("RATE_LIMIT_LOGIN_MAX_REQUESTS", "7")],
            ),
            Fixed::provider(
                ConfigProviderKind::Database,
                &[("RATE_LIMIT_LOGIN_MAX_REQUESTS", "9")],
            ),
        ]);
        let report = status_report(&stack);
        for key in RATE_LIMIT_KEYS.iter() {
            assert!(
                report.keys.iter().any(|row| row.key == *key),
                "{key} is missing from the config-status report"
            );
        }

        let login = report
            .keys
            .iter()
            .find(|row| row.key == "RATE_LIMIT_LOGIN_MAX_REQUESTS")
            .expect("the login cap is reported");
        assert_eq!(login.condition, "overridden");
        assert_eq!(login.serving.as_deref(), Some("database"));

        let window = report
            .keys
            .iter()
            .find(|row| row.key == "RATE_LIMIT_LOGIN_WINDOW_SECONDS")
            .expect("the login window is reported");
        assert_eq!(window.condition, "default");
        assert_eq!(window.serving, None);

        let rendered = render_status(&report);
        assert!(rendered.contains("RATE_LIMIT_LOGIN_MAX_REQUESTS"));
        assert!(
            !rendered.contains(" 9\n"),
            "the report must never print a cap:\n{rendered}"
        );
    }

    /// AC2 (BUNYIP-645): the rate-limit family is declared, one pair per
    /// preset, so `config-status` reports every action and no action's cap looks
    /// like a setting with no environment source.
    #[test]
    fn every_rate_limit_action_declares_both_of_its_keys() {
        for cfg in crate::models::RateLimitConfig::ALL {
            let vars = crate::models::RateLimitConfig::vars_for(cfg.action)
                .unwrap_or_else(|| panic!("{} has no generated variables", cfg.action));
            for key in [vars.max_requests, vars.window_seconds] {
                let spec = config_key(key)
                    .unwrap_or_else(|| panic!("{key} must be a declared configuration key"));
                assert_eq!(spec.source_var, key);
                assert!(
                    crate::config::env_spec(key).is_some(),
                    "{key} must be classified in ENV_INVENTORY"
                );
                assert!(RATE_LIMIT_KEYS.contains(&key));
            }
        }
        assert_eq!(
            RATE_LIMIT_KEYS.len(),
            crate::models::RateLimitConfig::ALL.len() * 2
        );
    }

    /// AC3, enforced mechanically: the undeclared database override path is gone
    /// and cannot come back. `from_db_row` and `has_db_overrides` were its two
    /// halves - a per-field fallback plus a boolean that decided, by call order
    /// alone, whether it ran - and both are now the database provider. A new
    /// `from_db_row` would be a second, undeclared source again.
    #[test]
    fn the_undeclared_database_override_path_does_not_come_back() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
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
                // Everything from `#[cfg(test)]` on is test scaffolding, which
                // is where this guard's own message lives. Same cut the
                // BUNYIP-537 inventory guard makes, for the same reason.
                let production = match source.find("#[cfg(test)]") {
                    Some(idx) => &source[..idx],
                    None => source.as_str(),
                };
                for (number, line) in production.lines().enumerate() {
                    // Comments and doc comments may name the removed pair: this
                    // module's own docs explain what replaced it.
                    if line.trim_start().starts_with("//") {
                        continue;
                    }
                    if line.contains("from_db_row") || line.contains("has_db_overrides") {
                        offenders.push(format!("{}:{}", file.display(), number + 1));
                    }
                }
            }
        }

        assert!(scanned > 50, "the source scan found only {scanned} files");
        assert!(
            offenders.is_empty(),
            "the database override path is a ConfigProvider now (BUNYIP-643): build the row into \
             a DatabaseProvider and resolve through a ConfigStack instead of reintroducing \
             from_db_row / has_db_overrides: {offenders:#?}"
        );
    }

    /// Every `.rs` file under `dir`, recursively.
    fn rust_sources(dir: &std::path::Path) -> Vec<PathBuf> {
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
    fn the_database_provider_refuses_a_group_one_key() {
        let mut provider = DatabaseProvider::new();
        for key in GROUP_ONE_KEYS {
            let failure = provider
                .set(key, "anything")
                .expect_err("the database provider must refuse a Group-1 startup value");
            assert_eq!(failure.var, *key);
            assert!(
                failure.reason.contains(key),
                "the startup error must name the key: {failure:?}"
            );
        }
        assert!(
            provider.is_empty(),
            "a refused key must not be held anyway: {provider:?}"
        );
    }

    #[test]
    fn the_database_provider_refuses_an_undeclared_key() {
        let mut provider = DatabaseProvider::new();
        let failure = provider
            .set("NOT_A_CONFIG_KEY", "x")
            .expect_err("an undeclared key is refused");
        assert_eq!(failure.var, "NOT_A_CONFIG_KEY");
        assert!(provider.is_empty());
    }

    /// AC6, cell by cell: the same 2x2 as the secrets classifier.
    #[test]
    fn classify_covers_every_cell() {
        use ConfigProviderKind::*;
        let top = Some(Database);
        assert_eq!(classify(top, &[Database]), ConfigVerdict::Use(Database));
        assert_eq!(classify(top, &[]), ConfigVerdict::Default);
        assert_eq!(
            classify(top, &[Database, File, Environment]),
            ConfigVerdict::Overridden {
                serving: Database,
                ignored: vec![File, Environment],
            }
        );
        // Absent from the top provider AND held by several: the file serves,
        // and the environment copy is still named rather than lost.
        assert_eq!(
            classify(top, &[File, Environment]),
            ConfigVerdict::Shadowed {
                serving: File,
                absent_from: Database,
                ignored: vec![Environment],
            }
        );
        assert_eq!(
            classify(top, &[Environment]),
            ConfigVerdict::Shadowed {
                serving: Environment,
                absent_from: Database,
                ignored: vec![],
            }
        );
    }

    #[test]
    fn a_verdict_records_which_provider_served_the_value() {
        use ConfigProviderKind::*;
        assert_eq!(
            classify(Some(Database), &[Database]).serving(),
            Some(Database)
        );
        assert_eq!(
            classify(Some(Database), &[Environment]).serving(),
            Some(Environment)
        );
        assert_eq!(classify(Some(Database), &[]).serving(), None);
    }

    fn stack_of(providers: Vec<Arc<dyn ConfigProvider>>) -> ConfigStack {
        ConfigStack::new(providers)
    }

    /// A provider that holds exactly what the test gives it, so precedence is
    /// exercised without touching the process environment or a database.
    #[derive(Debug)]
    struct Fixed {
        kind: ConfigProviderKind,
        values: BTreeMap<String, String>,
    }

    impl Fixed {
        fn provider(kind: ConfigProviderKind, pairs: &[(&str, &str)]) -> Arc<dyn ConfigProvider> {
            Arc::new(Self {
                kind,
                values: pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            })
        }
    }

    impl ConfigProvider for Fixed {
        fn kind(&self) -> ConfigProviderKind {
            self.kind
        }
        fn get(&self, key: &str) -> Option<String> {
            self.values.get(key).cloned()
        }
        fn enumerate(&self) -> Enumeration {
            Enumeration::Keys(self.values.keys().cloned().collect())
        }
    }

    #[test]
    fn the_declared_priority_decides_which_provider_serves() {
        let stack = stack_of(vec![
            Fixed::provider(ConfigProviderKind::Environment, &[("SMTP_HOST", "env")]),
            Fixed::provider(ConfigProviderKind::File, &[("SMTP_HOST", "file")]),
            Fixed::provider(ConfigProviderKind::Database, &[("SMTP_HOST", "db")]),
        ]);
        assert_eq!(stack.get("SMTP_HOST").as_deref(), Some("db"));
        assert_eq!(
            stack.holders("SMTP_HOST"),
            vec![
                ConfigProviderKind::Database,
                ConfigProviderKind::File,
                ConfigProviderKind::Environment
            ]
        );

        // The stack sorts by priority, so a caller cannot install the providers
        // in the wrong order: this is the same list in the opposite order.
        let reversed = stack_of(vec![
            Fixed::provider(ConfigProviderKind::Database, &[("SMTP_HOST", "db")]),
            Fixed::provider(ConfigProviderKind::File, &[("SMTP_HOST", "file")]),
            Fixed::provider(ConfigProviderKind::Environment, &[("SMTP_HOST", "env")]),
        ]);
        assert_eq!(reversed.get("SMTP_HOST").as_deref(), Some("db"));
    }

    #[test]
    fn the_file_provider_outranks_the_environment() {
        let stack = stack_of(vec![
            Fixed::provider(ConfigProviderKind::Environment, &[("SMTP_HOST", "env")]),
            Fixed::provider(ConfigProviderKind::File, &[("SMTP_HOST", "file")]),
        ]);
        assert_eq!(stack.get("SMTP_HOST").as_deref(), Some("file"));
        assert_eq!(
            stack
                .get_below(ConfigProviderKind::File, "SMTP_HOST")
                .as_deref(),
            Some("env")
        );
        assert_eq!(
            stack
                .get_above(ConfigProviderKind::Environment, "SMTP_HOST")
                .as_deref(),
            Some("file")
        );
    }

    #[test]
    fn an_unparseable_value_falls_through_to_the_next_provider_then_the_default() {
        // Nothing below it: the caller's built-in default stands, which is what
        // an unparseable environment value has always produced.
        let alone = stack_of(vec![Fixed::provider(
            ConfigProviderKind::Environment,
            &[("SMTP_PORT", "not-a-port")],
        )]);
        assert_eq!(alone.get_parsed::<u16>("SMTP_PORT"), None);

        // A usable value below it serves, rather than the whole key being lost
        // because a higher provider holds a typo.
        let layered = stack_of(vec![
            Fixed::provider(ConfigProviderKind::File, &[("SMTP_PORT", "not-a-port")]),
            Fixed::provider(ConfigProviderKind::Environment, &[("SMTP_PORT", "2525")]),
        ]);
        assert_eq!(layered.get_parsed::<u16>("SMTP_PORT"), Some(2525));
    }

    #[test]
    fn an_unreadable_file_directory_reports_unsupported_rather_than_empty() {
        let provider = FileProvider::load(PathBuf::from("/nonexistent/bunyip-643"));
        assert_eq!(provider.enumerate(), Enumeration::Unsupported);
        assert!(provider.unreadable().is_some());
        assert_eq!(provider.get("SMTP_HOST"), None);
    }

    #[test]
    fn the_file_provider_reads_a_directory_of_one_file_per_key() {
        let dir = std::env::temp_dir().join(format!("bunyip-643-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("SMTP_HOST"), "smtp.example.net\n").expect("write");
        std::fs::write(dir.join("SMTP_FROM"), "Ops <ops@example.net>").expect("write");
        std::fs::write(dir.join("SMTP_USERNAME"), "   ").expect("write");
        std::fs::write(dir.join("NOT_A_KEY"), "ignored").expect("write");

        let provider = FileProvider::load(dir.clone());
        assert_eq!(
            provider.get("SMTP_HOST").as_deref(),
            Some("smtp.example.net")
        );
        // One variable, two derived keys, exactly as the environment reads it.
        assert_eq!(
            provider.get("SMTP_FROM_EMAIL").as_deref(),
            Some("ops@example.net")
        );
        assert_eq!(provider.get("SMTP_FROM_NAME").as_deref(), Some("Ops"));
        // An empty file is absent, not an empty value.
        assert_eq!(provider.get("SMTP_USERNAME"), None);
        // An undeclared file name is ignored, never resolved.
        assert_eq!(provider.get("NOT_A_KEY"), None);
        assert!(provider.unreadable().is_none());
        match provider.enumerate() {
            Enumeration::Keys(keys) => {
                assert!(keys.contains(&"SMTP_HOST".to_string()));
                assert!(!keys.contains(&"SMTP_USERNAME".to_string()));
            }
            Enumeration::Unsupported => panic!("a readable directory can list its keys"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// AC5/AC6: the report carries the provenance and one line per report shape,
    /// and never a value.
    #[test]
    fn the_status_report_names_the_serving_provider_for_every_shape() {
        let stack = stack_of(vec![
            Fixed::provider(
                ConfigProviderKind::Environment,
                &[("SMTP_HOST", "env-host"), ("SMTP_PORT", "2525")],
            ),
            Fixed::provider(ConfigProviderKind::File, &[("SMTP_USERNAME", "file-user")]),
            Fixed::provider(ConfigProviderKind::Database, &[("SMTP_HOST", "db-host")]),
        ]);
        let report = status_report(&stack);
        let by_key = |key: &str| {
            report
                .keys
                .iter()
                .find(|row| row.key == key)
                .unwrap_or_else(|| panic!("{key} is in the report"))
        };

        // held by several -> the database serves, the environment is ignored
        let host = by_key("SMTP_HOST");
        assert_eq!(host.condition, "overridden");
        assert_eq!(host.serving.as_deref(), Some("database"));
        assert_eq!(host.providers, vec!["database", "environment"]);

        // absent from the highest-priority provider -> a lower one serves
        let port = by_key("SMTP_PORT");
        assert_eq!(port.condition, "shadowed");
        assert_eq!(port.serving.as_deref(), Some("environment"));

        let username = by_key("SMTP_USERNAME");
        assert_eq!(username.condition, "shadowed");
        assert_eq!(username.serving.as_deref(), Some("file"));

        // held by none -> the built-in default
        let tls = by_key("SMTP_TLS");
        assert_eq!(tls.condition, "default");
        assert_eq!(tls.serving, None);

        let rendered = render_status(&report);
        assert!(rendered.contains("SMTP_HOST"));
        assert!(
            !rendered.contains("db-host") && !rendered.contains("env-host"),
            "the status report must never print a configuration value:\n{rendered}"
        );
    }
}
