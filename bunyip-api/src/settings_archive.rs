//! Passphrase-encrypted export and replace-import of every admin-managed
//! database setting (BUNYIP-714).
//!
//! bunyip keeps its configuration in the database on purpose: branding, the
//! palette and the brand assets, the tier and pricing flags, the email and
//! Stripe rows, the rate-limit overrides, the application catalogue and the
//! OAuth client registrations are all edited from the admin pages rather than
//! compiled in or set in compose. That is what makes a rebrand or a cap change
//! reversible with no deploy, and it is also what makes a wiped volume lose
//! every one of them at once. A `pg_dump` is the wrong instrument for the job:
//! it carries the users, the sessions, the audit log and the download cache
//! too, and it cannot be handed to anyone, because the encrypted secret columns
//! travel with it while the key that reads them does not.
//!
//! So this module archives the SETTINGS and nothing else, into ONE file an
//! operator can keep: the governed integration secrets are resolved to
//! plaintext through the declared provider and the whole archive is sealed
//! under a passphrase (Argon2id to a 32-byte key, then the same AES-256-GCM
//! path every at-rest secret uses), so the file is readable on a machine that
//! has neither `APP_ENCRYPTION_KEY` nor the old database. Users, per-user data,
//! `ip_bans`, `mailer_suppressions`, `application_versions`, `download_cache`
//! and `audit_logs` are deliberately absent: they are operational history, not
//! configuration, and restoring them over a live deployment would be a data
//! migration wearing a settings restore's clothes.
//!
//! Import is REPLACE, not merge. A section present in the archive ends up
//! holding exactly the archive's content, so restoring twice lands in the same
//! place as restoring once, and the operator never has to reason about what a
//! half-applied merge left behind. A section absent from the archive (the two
//! flag-gated ones) is not touched at all.
//!
//! Everything is validated before anything is written, the database half runs
//! in ONE transaction, and the two steps that cannot join it (the governed
//! secrets, which may live in Infisical or the environment, and the system
//! settings, which are a file layer) are reported per step so a partial run
//! names exactly what applied. Nothing falls back silently: every failure is a
//! named cause and a non-zero exit.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bunyip_domain::config::{Config, GovernedSecret, SecretsProvider};
use bunyip_domain::errors::AppError;
use bunyip_domain::models::branding::{validate_branding, UpdateBrandingRequest};
use bunyip_domain::services::argon2_offload;
use bunyip_domain::services::encryption::{decrypt_with_key, EncryptionKeySet};
use bunyip_domain::services::AppKeySet;
use bunyip_domain::sys_config::SystemSettings;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::handlers::admin::{refuse_disabled_email_in_production, visible_without_price_error};
use crate::handlers::admin_rate_limits::validate_limits;

// =============================================================================
// Archive format
// =============================================================================

/// The `format` discriminator. Refused by name on `open`, so a JSON file that
/// merely looks similar is rejected before a passphrase is even derived.
pub const ARCHIVE_FORMAT: &str = "bunyip-settings-archive";

/// The one format version this binary writes and reads.
pub const ARCHIVE_FORMAT_VERSION: u32 = 1;

/// Argon2id parameters written into a version-1 archive: the password preset
/// (`PasswordService`) uses, expressed here rather than borrowed, because the
/// archive carries its own parameters and must keep opening under them even if
/// the login preset later moves.
const KDF_MEMORY_KIB: u32 = 65536;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 4;
const KDF_SALT_LEN: usize = 16;
/// Argon2 version 0x13 as the decimal the envelope carries.
const KDF_ARGON2_VERSION: u32 = 19;

/// Upper bound on the `memory_kib` an archive may ask for (1 GiB). The
/// parameters are READ FROM THE FILE so a future format version can raise them
/// without stranding old archives, which means an attacker-supplied file would
/// otherwise choose this process's allocation size.
const KDF_MAX_MEMORY_KIB: u32 = 1024 * 1024;

/// Shortest passphrase `seal` accepts, in characters (BUNYIP-714). Length is
/// checked on its own, ahead of the strength score, so the message can name the
/// rule that actually failed.
pub const MIN_PASSPHRASE_CHARS: usize = 16;

/// The sealed file: a JSON envelope whose `ciphertext` is the encrypted
/// [`SettingsSnapshot`]. The KDF parameters and the salt travel with it, so an
/// archive written under one parameter set still opens after the defaults move.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Envelope {
    format: String,
    format_version: u32,
    kdf: KdfParams,
    cipher: CipherParams,
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KdfParams {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CipherParams {
    algorithm: String,
    nonce: String,
}

// =============================================================================
// Column coverage
//
// Every archived table declares which of its columns this module carries and
// which it deliberately leaves behind. A column that is in neither list is a
// column a schema change added and nobody taught the archive about, which would
// silently drop a new setting from every export. `settings_archive.rs`'s
// integration test reads `information_schema.columns` and fails the build on
// one, which is why these lists are data rather than prose.
// =============================================================================

/// One archived table's column split.
#[derive(Debug, Clone, Copy)]
pub struct ArchivedTable {
    /// The table in the `public` schema.
    pub table: &'static str,
    /// Columns whose value the archive carries. `group_id` and `application_id`
    /// appear here even though the archive stores the referenced row's SLUG
    /// rather than its uuid: the setting travels, only its spelling changes.
    pub archived: &'static [&'static str],
    /// Columns deliberately left behind, which is always one of three reasons:
    /// a surrogate key or timestamp the target owns, an attribution column
    /// (`updated_by` / `created_by`) that is a FK to `users` and is written from
    /// the importing operator instead, or a secret ciphertext pair whose
    /// plaintext is archived under `governed_secrets`.
    pub excluded: &'static [&'static str],
}

/// Every table the archive reads, with its column split.
pub const ARCHIVED_TABLES: &[ArchivedTable] = &[
    ArchivedTable {
        table: "branding",
        archived: &[
            "brand_name",
            "tagline",
            "meta_description",
            "og_image_url",
            "theme_css",
            "theme_color_light",
            "theme_color_dark",
            "mark_updated_at",
            "favicon_updated_at",
            "mascot_updated_at",
        ],
        excluded: &["id", "updated_at", "updated_by"],
    },
    ArchivedTable {
        table: "branding_assets",
        archived: &["kind", "mime_type", "size_bytes", "data"],
        excluded: &["updated_at"],
    },
    ArchivedTable {
        table: "tier_config",
        archived: &[
            "lifetime_slots",
            "early_adopter_slots",
            "early_adopter_trial_days",
            "standard_trial_days",
            "free_price_id",
            "early_adopter_price_id",
            "standard_price_id",
            "lifetime_product_id",
            "early_adopter_product_id",
            "standard_product_id",
            "pricing_enabled",
            "lifetime_visible",
            "early_adopter_visible",
            "standard_visible",
            "orgs_enabled",
        ],
        excluded: &["id", "updated_at", "updated_by"],
    },
    ArchivedTable {
        table: "auto_ban_config",
        archived: &["enabled", "threshold", "window_secs", "ban_duration_secs"],
        excluded: &["id", "updated_at", "updated_by"],
    },
    ArchivedTable {
        table: "email_config",
        archived: &[
            "enabled",
            "smtp_host",
            "smtp_port",
            "smtp_tls",
            "smtp_username",
            "from_email",
            "from_name",
            "admin_notification_emails",
            "imap_host",
            "imap_port",
            "imap_username",
            "imap_mailbox",
            "imap_enabled",
        ],
        excluded: &[
            "id",
            "updated_at",
            "updated_by",
            "key_version",
            "smtp_password",
            "smtp_password_nonce",
            "imap_password",
            "imap_password_nonce",
        ],
    },
    ArchivedTable {
        table: "stripe_config",
        archived: &["app_tag", "success_url", "cancel_url", "trial_period_days"],
        excluded: &[
            "id",
            "updated_at",
            "updated_by",
            "key_version",
            "secret_key",
            "secret_key_nonce",
            "webhook_secret",
            "webhook_secret_nonce",
        ],
    },
    ArchivedTable {
        table: "rate_limit_configs",
        archived: &["action", "max_requests", "window_seconds"],
        excluded: &["updated_at", "updated_by"],
    },
    ArchivedTable {
        table: "application_groups",
        archived: &[
            "name",
            "slug",
            "display_name",
            "description",
            "icon_url",
            "sort_order",
        ],
        excluded: &["id", "created_at", "updated_at"],
    },
    ArchivedTable {
        table: "applications",
        archived: &[
            "name",
            "slug",
            "display_name",
            "description",
            "icon_url",
            "is_active",
            "maintenance_mode",
            "maintenance_message",
            "container_name",
            "health_check_url",
            "version",
            "source_code_url",
            "subdomain",
            "webhook_url",
            "sort_order",
            "forgejo_owner",
            "forgejo_repo",
            "pinned_release_tag",
            "oci_image_owner",
            "oci_image_name",
            "pinned_image_tag",
            "artifact_source",
            "forgejo_package",
            "is_hosted",
            "requires_entitlement",
            "group_id",
            "release_notes_url",
        ],
        excluded: &["id", "created_at", "updated_at"],
    },
    ArchivedTable {
        table: "application_docs",
        archived: &["slug", "title", "body", "sort_order"],
        excluded: &["id", "application_id", "created_at", "updated_at"],
    },
    ArchivedTable {
        table: "stripe_price_entitlements",
        archived: &["stripe_price_id", "application_id"],
        excluded: &["created_at"],
    },
    ArchivedTable {
        table: "oauth_clients",
        archived: &[
            "client_id",
            "client_secret_hash",
            "client_type",
            "name",
            "redirect_uris",
            "post_logout_redirect_uris",
            "backchannel_logout_uri",
            "lifecycle_event_uri",
            "allowed_scopes",
            "allowed_grant_types",
            "token_endpoint_auth_method",
            "require_pkce",
            "access_token_ttl_seconds",
            "refresh_token_ttl_seconds",
            "refresh_idle_ttl_seconds",
            "audience",
            "dpop_bound",
            "disabled_at",
            "tenant_claim_name",
            "first_party",
            "logo_uri",
        ],
        excluded: &["id", "created_at", "created_by"],
    },
];

/// What deleting one `applications` row takes with it, named in the plan so an
/// operator sees the blast radius before confirming a restore.
const APPLICATION_CASCADES: &[&str] = &[
    "application_docs",
    "application_versions",
    "application_entitlements",
    "stripe_price_entitlements",
    "download_cache",
];

/// What deleting one `oauth_clients` row takes with it. The first three are
/// deleted EXPLICITLY by [`apply`] because their foreign keys carry no
/// `ON DELETE` action and would otherwise block the delete outright.
const OAUTH_CLIENT_CASCADES: &[&str] = &[
    "oauth_authorization_codes",
    "refresh_token_families",
    "refresh_tokens_v2",
    "oauth_client_user_tenants",
    "user_application_access",
    "lifecycle_event_delivery",
];

// =============================================================================
// Snapshot
// =============================================================================

/// Which optional sections an export carries.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExportOptions {
    /// `--include-catalog`: the application groups, applications, per-application
    /// documentation and Stripe price entitlements.
    pub include_catalog: bool,
    /// `--include-oauth-clients`: the `oauth_clients` registrations, hashed
    /// client secrets included.
    pub include_oauth_clients: bool,
}

/// The archive plaintext.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsSnapshot {
    /// When the export ran.
    pub created_at: DateTime<Utc>,
    /// The bunyip version that wrote it, for the operator reading a file that
    /// will not import.
    pub bunyip_version: String,
    /// The highest applied migration at export time. Import refuses a mismatch
    /// rather than writing a row shaped for another schema.
    pub schema_version: i64,
    pub sections: Sections,
}

/// The archived sections. The two `Option` fields are the flag-gated ones:
/// `None` means the export did not carry them, and import leaves the target's
/// own rows alone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sections {
    pub branding: BrandingSection,
    pub branding_assets: Vec<BrandingAssetRow>,
    pub tier_config: TierConfigSection,
    pub auto_ban_config: AutoBanConfigSection,
    pub email_config: EmailConfigSection,
    pub stripe_config: StripeConfigSection,
    pub rate_limit_configs: Vec<RateLimitConfigRow>,
    pub system_settings: SystemSettingsSection,
    /// Plaintext of every [`GovernedSecret`], keyed by its variable name.
    /// `None` means the declared provider holds no value for it.
    pub governed_secrets: BTreeMap<String, Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<CatalogSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_clients: Option<Vec<OauthClientRow>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct BrandingSection {
    pub brand_name: String,
    pub tagline: String,
    pub meta_description: String,
    pub og_image_url: String,
    pub theme_css: String,
    pub theme_color_light: String,
    pub theme_color_dark: String,
    pub mark_updated_at: Option<DateTime<Utc>>,
    pub favicon_updated_at: Option<DateTime<Utc>>,
    pub mascot_updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct BrandingAssetRow {
    pub kind: String,
    pub mime_type: String,
    pub size_bytes: i32,
    /// The stored bytes, base64 in the archive. Every derived favicon size is
    /// archived alongside the source, so a restore reproduces the exact icon set
    /// rather than re-deriving one that may differ with the `image` crate.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct TierConfigSection {
    pub lifetime_slots: Option<i64>,
    pub early_adopter_slots: Option<i64>,
    pub early_adopter_trial_days: Option<i64>,
    pub standard_trial_days: Option<i64>,
    pub free_price_id: Option<String>,
    pub early_adopter_price_id: Option<String>,
    pub standard_price_id: Option<String>,
    pub lifetime_product_id: Option<String>,
    pub early_adopter_product_id: Option<String>,
    pub standard_product_id: Option<String>,
    pub pricing_enabled: bool,
    pub lifetime_visible: bool,
    pub early_adopter_visible: bool,
    pub standard_visible: bool,
    pub orgs_enabled: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct AutoBanConfigSection {
    pub enabled: Option<bool>,
    pub threshold: Option<i64>,
    pub window_secs: Option<i64>,
    pub ban_duration_secs: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct EmailConfigSection {
    pub enabled: Option<bool>,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<i32>,
    pub smtp_tls: Option<String>,
    pub smtp_username: Option<String>,
    pub from_email: Option<String>,
    pub from_name: Option<String>,
    pub admin_notification_emails: Option<String>,
    pub imap_host: Option<String>,
    pub imap_port: Option<i32>,
    pub imap_username: Option<String>,
    pub imap_mailbox: Option<String>,
    pub imap_enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct StripeConfigSection {
    pub app_tag: Option<String>,
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
    pub trial_period_days: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfigRow {
    pub action: String,
    pub max_requests: i32,
    pub window_seconds: i64,
}

/// The four settings the `file` configuration layer carries, read through
/// [`SystemSettings`] rather than from a table.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSettingsSection {
    pub login_approval_enabled: bool,
    pub signup_bot_guard_enabled: bool,
    pub country_allow: Vec<String>,
    pub country_deny: Vec<String>,
}

impl From<SystemSettings> for SystemSettingsSection {
    fn from(s: SystemSettings) -> Self {
        Self {
            login_approval_enabled: s.login_approval_enabled,
            signup_bot_guard_enabled: s.signup_bot_guard_enabled,
            country_allow: s.country_allow,
            country_deny: s.country_deny,
        }
    }
}

impl From<&SystemSettingsSection> for SystemSettings {
    fn from(s: &SystemSettingsSection) -> Self {
        Self {
            login_approval_enabled: s.login_approval_enabled,
            signup_bot_guard_enabled: s.signup_bot_guard_enabled,
            country_allow: s.country_allow.clone(),
            country_deny: s.country_deny.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSection {
    pub application_groups: Vec<ApplicationGroupRow>,
    pub applications: Vec<ApplicationRow>,
    pub application_docs: Vec<ApplicationDocRow>,
    pub stripe_price_entitlements: Vec<PriceEntitlementRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct ApplicationGroupRow {
    pub slug: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub sort_order: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRow {
    pub slug: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub is_active: bool,
    pub maintenance_mode: bool,
    pub maintenance_message: Option<String>,
    pub container_name: String,
    pub health_check_url: Option<String>,
    pub version: Option<String>,
    pub source_code_url: Option<String>,
    pub subdomain: Option<String>,
    pub webhook_url: Option<String>,
    pub sort_order: i32,
    pub forgejo_owner: Option<String>,
    pub forgejo_repo: Option<String>,
    pub pinned_release_tag: Option<String>,
    pub oci_image_owner: Option<String>,
    pub oci_image_name: Option<String>,
    pub pinned_image_tag: Option<String>,
    pub artifact_source: String,
    pub forgejo_package: Option<String>,
    pub is_hosted: bool,
    pub requires_entitlement: bool,
    /// `applications.group_id` carried as the referenced group's slug: a uuid
    /// generated in the old database names nothing in the new one.
    pub group_slug: Option<String>,
    pub release_notes_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct ApplicationDocRow {
    pub application_slug: String,
    pub slug: String,
    pub title: String,
    pub body: String,
    pub sort_order: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct PriceEntitlementRow {
    pub stripe_price_id: String,
    pub application_slug: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct OauthClientRow {
    pub client_id: Uuid,
    /// The Argon2 hash, not the secret. A restore keeps every calling app's
    /// existing credential working; the plaintext exists only where
    /// `bunyip-api machine-client register` printed it.
    pub client_secret_hash: Option<String>,
    pub client_type: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub backchannel_logout_uri: Option<String>,
    pub lifecycle_event_uri: Option<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub require_pkce: bool,
    pub access_token_ttl_seconds: i32,
    pub refresh_token_ttl_seconds: i32,
    pub refresh_idle_ttl_seconds: i32,
    pub audience: String,
    pub dpop_bound: bool,
    pub disabled_at: Option<DateTime<Utc>>,
    pub tenant_claim_name: Option<String>,
    pub first_party: bool,
    pub logo_uri: Option<String>,
}

/// Base64 for the one binary field in the snapshot. A `Vec<u8>` serialises as a
/// JSON array of integers, which is roughly four bytes of text per byte of
/// image; the whole favicon set would dominate the archive.
mod base64_bytes {
    use super::BASE64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        BASE64
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

// =============================================================================
// Schema-state guards
// =============================================================================

/// The highest migration compiled into this binary.
fn compiled_schema_version() -> i64 {
    sqlx::migrate!("./migrations")
        .migrations
        .iter()
        .map(|m| m.version)
        .max()
        .unwrap_or(0)
}

/// The highest migration applied to `pool`.
async fn applied_schema_version(pool: &PgPool) -> Result<i64, AppError> {
    let applied: Option<i64> = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await
        .map_err(|e| {
            AppError::internal(format!(
                "could not read _sqlx_migrations to establish the database schema version: {e}. \
                 Start bunyip-api once so it migrates, then re-run this subcommand."
            ))
        })?;
    applied.ok_or_else(|| {
        AppError::internal(
            "_sqlx_migrations holds no applied migration, so this database has never been \
             migrated. Start bunyip-api once so it migrates, then re-run this subcommand."
                .to_string(),
        )
    })
}

/// Refuse to read or write settings against a database whose schema is not the
/// one this binary was built for, and return the agreed version.
///
/// A subcommand runs BEFORE the server's migration step, deliberately (a
/// maintenance command must not be the thing that migrates production). That
/// makes "the binary is newer than the volume" the ordinary state right after a
/// deploy, and an export taken then would be shaped for columns the database
/// does not have. Naming both versions is the whole message: the remedy is to
/// start the server once.
pub async fn require_matching_schema(pool: &PgPool) -> Result<i64, AppError> {
    let applied = applied_schema_version(pool).await?;
    let compiled = compiled_schema_version();
    if applied != compiled {
        return Err(AppError::internal(format!(
            "this bunyip-api binary carries migrations up to {compiled}, but the database has \
             applied up to {applied}. The settings archive is shaped by the schema, so it refuses \
             to run against a database at another version. Start bunyip-api once so it applies \
             its migrations, then re-run this subcommand."
        )));
    }
    Ok(applied)
}

// =============================================================================
// Export
// =============================================================================

/// Read every archived section out of `pool` and the declared providers.
pub async fn export(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    options: ExportOptions,
) -> Result<SettingsSnapshot, AppError> {
    let schema_version = require_matching_schema(pool).await?;

    let sections = Sections {
        branding: read_branding(pool).await?,
        branding_assets: read_branding_assets(pool).await?,
        tier_config: read_tier_config(pool).await?,
        auto_ban_config: read_auto_ban_config(pool).await?,
        email_config: read_email_config(pool).await?,
        stripe_config: read_stripe_config(pool).await?,
        rate_limit_configs: read_rate_limit_configs(pool).await?,
        system_settings: SystemSettings::current().into(),
        governed_secrets: read_governed_secrets(pool, config, key_set).await?,
        catalog: if options.include_catalog {
            Some(read_catalog(pool).await?)
        } else {
            None
        },
        oauth_clients: if options.include_oauth_clients {
            Some(read_oauth_clients(pool).await?)
        } else {
            None
        },
    };

    Ok(SettingsSnapshot {
        created_at: Utc::now(),
        bunyip_version: env!("CARGO_PKG_VERSION").to_string(),
        schema_version,
        sections,
    })
}

async fn read_branding(pool: &PgPool) -> Result<BrandingSection, AppError> {
    Ok(sqlx::query_as::<_, BrandingSection>(
        "SELECT brand_name, tagline, meta_description, og_image_url, theme_css, \
         theme_color_light, theme_color_dark, mark_updated_at, favicon_updated_at, \
         mascot_updated_at FROM branding WHERE id = 1",
    )
    .fetch_one(pool)
    .await?)
}

async fn read_branding_assets(pool: &PgPool) -> Result<Vec<BrandingAssetRow>, AppError> {
    Ok(sqlx::query_as::<_, BrandingAssetRow>(
        "SELECT kind, mime_type, size_bytes, data FROM branding_assets ORDER BY kind",
    )
    .fetch_all(pool)
    .await?)
}

async fn read_tier_config(pool: &PgPool) -> Result<TierConfigSection, AppError> {
    Ok(sqlx::query_as::<_, TierConfigSection>(
        "SELECT lifetime_slots, early_adopter_slots, early_adopter_trial_days, \
         standard_trial_days, free_price_id, early_adopter_price_id, standard_price_id, \
         lifetime_product_id, early_adopter_product_id, standard_product_id, pricing_enabled, \
         lifetime_visible, early_adopter_visible, standard_visible, orgs_enabled \
         FROM tier_config WHERE id = 1",
    )
    .fetch_one(pool)
    .await?)
}

async fn read_auto_ban_config(pool: &PgPool) -> Result<AutoBanConfigSection, AppError> {
    Ok(sqlx::query_as::<_, AutoBanConfigSection>(
        "SELECT enabled, threshold, window_secs, ban_duration_secs \
         FROM auto_ban_config WHERE id = 1",
    )
    .fetch_one(pool)
    .await?)
}

async fn read_email_config(pool: &PgPool) -> Result<EmailConfigSection, AppError> {
    Ok(sqlx::query_as::<_, EmailConfigSection>(
        "SELECT enabled, smtp_host, smtp_port, smtp_tls, smtp_username, from_email, from_name, \
         admin_notification_emails, imap_host, imap_port, imap_username, imap_mailbox, \
         imap_enabled FROM email_config WHERE id = 1",
    )
    .fetch_one(pool)
    .await?)
}

async fn read_stripe_config(pool: &PgPool) -> Result<StripeConfigSection, AppError> {
    Ok(sqlx::query_as::<_, StripeConfigSection>(
        "SELECT app_tag, success_url, cancel_url, trial_period_days \
         FROM stripe_config WHERE id = 1",
    )
    .fetch_one(pool)
    .await?)
}

async fn read_rate_limit_configs(pool: &PgPool) -> Result<Vec<RateLimitConfigRow>, AppError> {
    Ok(sqlx::query_as::<_, RateLimitConfigRow>(
        "SELECT action, max_requests, window_seconds FROM rate_limit_configs ORDER BY action",
    )
    .fetch_all(pool)
    .await?)
}

async fn read_governed_secrets(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
) -> Result<BTreeMap<String, Option<String>>, AppError> {
    let mut out = BTreeMap::new();
    for secret in GovernedSecret::ALL {
        let value = crate::secrets::read_secret(pool, config, key_set, secret).await?;
        out.insert(secret.name().to_string(), value);
    }
    Ok(out)
}

async fn read_catalog(pool: &PgPool) -> Result<CatalogSection, AppError> {
    let application_groups = sqlx::query_as::<_, ApplicationGroupRow>(
        "SELECT slug, name, display_name, description, icon_url, sort_order \
         FROM application_groups ORDER BY slug",
    )
    .fetch_all(pool)
    .await?;

    let applications = sqlx::query_as::<_, ApplicationRow>(
        "SELECT a.slug, a.name, a.display_name, a.description, a.icon_url, a.is_active, \
         a.maintenance_mode, a.maintenance_message, a.container_name, a.health_check_url, \
         a.version, a.source_code_url, a.subdomain, a.webhook_url, a.sort_order, \
         a.forgejo_owner, a.forgejo_repo, a.pinned_release_tag, a.oci_image_owner, \
         a.oci_image_name, a.pinned_image_tag, a.artifact_source, a.forgejo_package, \
         a.is_hosted, a.requires_entitlement, g.slug AS group_slug, a.release_notes_url \
         FROM applications a LEFT JOIN application_groups g ON g.id = a.group_id \
         ORDER BY a.slug",
    )
    .fetch_all(pool)
    .await?;

    let application_docs = sqlx::query_as::<_, ApplicationDocRow>(
        "SELECT a.slug AS application_slug, d.slug, d.title, d.body, d.sort_order \
         FROM application_docs d JOIN applications a ON a.id = d.application_id \
         ORDER BY a.slug, d.slug",
    )
    .fetch_all(pool)
    .await?;

    let stripe_price_entitlements = sqlx::query_as::<_, PriceEntitlementRow>(
        "SELECT e.stripe_price_id, a.slug AS application_slug \
         FROM stripe_price_entitlements e JOIN applications a ON a.id = e.application_id \
         ORDER BY e.stripe_price_id, a.slug",
    )
    .fetch_all(pool)
    .await?;

    Ok(CatalogSection {
        application_groups,
        applications,
        application_docs,
        stripe_price_entitlements,
    })
}

async fn read_oauth_clients(pool: &PgPool) -> Result<Vec<OauthClientRow>, AppError> {
    Ok(sqlx::query_as::<_, OauthClientRow>(
        "SELECT client_id, client_secret_hash, client_type, name, redirect_uris, \
         post_logout_redirect_uris, backchannel_logout_uri, lifecycle_event_uri, \
         allowed_scopes, allowed_grant_types, token_endpoint_auth_method, require_pkce, \
         access_token_ttl_seconds, refresh_token_ttl_seconds, refresh_idle_ttl_seconds, \
         audience, dpop_bound, disabled_at, tenant_claim_name, first_party, logo_uri \
         FROM oauth_clients ORDER BY client_id",
    )
    .fetch_all(pool)
    .await?)
}

// =============================================================================
// Seal / open
// =============================================================================

/// The zxcvbn `user_inputs` for a passphrase check: the resolved brand name and
/// the host of `APP_URL`.
///
/// A passphrase built out of the deployment's own name is exactly the one an
/// attacker holding the archive guesses first, and zxcvbn only knows that if it
/// is told. Deriving them here (rather than inside [`seal`]) keeps `seal` pure
/// enough to unit-test without a `Config`.
pub fn passphrase_inputs(snapshot: &SettingsSnapshot, config: &Config) -> Vec<String> {
    let brand = snapshot.sections.branding.brand_name.trim();
    let brand = if brand.is_empty() {
        config.app_name.clone()
    } else {
        brand.to_string()
    };
    let mut inputs = vec![brand];
    if let Some(host) = url::Url::parse(&config.email.base_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
    {
        inputs.push(host);
    }
    inputs.retain(|i| !i.trim().is_empty());
    inputs
}

/// Refuse a passphrase that a leaked archive would not survive.
///
/// Length and strength are separate rules with separate messages: "too short"
/// and "too guessable" have different remedies, and a single blended verdict
/// leaves the operator guessing which one they tripped. The passphrase itself
/// is NEVER echoed, into the message or anywhere else.
fn check_passphrase(passphrase: &str, user_inputs: &[&str]) -> Result<(), AppError> {
    let len = passphrase.chars().count();
    if len < MIN_PASSPHRASE_CHARS {
        return Err(AppError::validation(
            "passphrase",
            format!(
                "the archive passphrase is {len} characters; at least {MIN_PASSPHRASE_CHARS} are \
                 required. The file it protects holds every integration secret in plaintext, so \
                 use a passphrase of several unrelated words."
            ),
        ));
    }

    let entropy = zxcvbn::zxcvbn(passphrase, user_inputs);
    if entropy.score() < zxcvbn::Score::Four {
        let mut message = format!(
            "the archive passphrase scores {}/4 for guessability; 4 is required. The file it \
             protects holds every integration secret in plaintext.",
            u8::from(entropy.score())
        );
        if let Some(feedback) = entropy.feedback() {
            if let Some(warning) = feedback.warning() {
                message.push_str(&format!(" {warning}"));
            }
            for suggestion in feedback.suggestions() {
                message.push_str(&format!(" {suggestion}"));
            }
        }
        return Err(AppError::validation("passphrase", message));
    }
    Ok(())
}

/// Derive the 32-byte archive key from a passphrase and the stored parameters.
///
/// Argon2id at these parameters is ~100 ms of CPU and 64 MiB resident, which is
/// exactly the work `argon2_offload` exists to keep off a request future. No
/// request reaches this module today, but the rule is about the shape rather
/// than the current call graph: an Argon2 that runs inline is one route
/// registration away from stalling an arbiter.
async fn derive_key(
    passphrase: &str,
    params: KdfParams,
    salt: Vec<u8>,
) -> Result<[u8; 32], AppError> {
    if params.algorithm != "argon2id" {
        return Err(AppError::validation(
            "kdf.algorithm",
            format!(
                "the archive declares KDF `{}`, which this binary cannot derive. Only `argon2id` \
                 is supported.",
                params.algorithm
            ),
        ));
    }
    if params.version != KDF_ARGON2_VERSION {
        return Err(AppError::validation(
            "kdf.version",
            format!(
                "the archive declares Argon2 version {}, which this binary cannot derive. Only \
                 version {KDF_ARGON2_VERSION} is supported.",
                params.version
            ),
        ));
    }
    if params.memory_kib > KDF_MAX_MEMORY_KIB {
        return Err(AppError::validation(
            "kdf.memory_kib",
            format!(
                "the archive asks for {} KiB of Argon2 memory, above the {KDF_MAX_MEMORY_KIB} KiB \
                 ceiling this binary will allocate for an untrusted file.",
                params.memory_kib
            ),
        ));
    }

    let passphrase = passphrase.to_string();
    argon2_offload::offload("settings-archive-kdf", move || {
        let argon_params = argon2::Params::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            Some(32),
        )
        .map_err(|e| {
            AppError::validation(
                "kdf",
                format!("the archive's Argon2 parameters are not usable: {e}"),
            )
        })?;
        let argon = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon_params,
        );
        let mut key = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|e| AppError::internal(format!("archive key derivation failed: {e}")))?;
        Ok(key)
    })
    .await
}

/// Encrypt a snapshot into the archive bytes, after checking the passphrase.
///
/// Deviates from a bare `(snapshot, passphrase)` signature by taking the zxcvbn
/// `user_inputs` explicitly: the brand name and the `APP_URL` host live in
/// `Config`, and threading a whole `Config` through would make the strength rule
/// untestable without one. [`passphrase_inputs`] is the one caller-side helper
/// that builds them.
pub async fn seal(
    snapshot: &SettingsSnapshot,
    passphrase: &str,
    user_inputs: &[&str],
) -> Result<Vec<u8>, AppError> {
    check_passphrase(passphrase, user_inputs)?;

    let salt: Vec<u8> = {
        use rand::RngCore;
        let mut salt = vec![0u8; KDF_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    };
    let params = KdfParams {
        algorithm: "argon2id".to_string(),
        version: KDF_ARGON2_VERSION,
        memory_kib: KDF_MEMORY_KIB,
        iterations: KDF_ITERATIONS,
        parallelism: KDF_PARALLELISM,
        salt: BASE64.encode(&salt),
    };
    let key = derive_key(passphrase, params.clone(), salt).await?;

    let plaintext = serde_json::to_vec(snapshot).map_err(|e| {
        AppError::internal(format!("could not serialise the settings archive: {e}"))
    })?;
    let (ciphertext, nonce, _version) = EncryptionKeySet {
        current: key,
        current_version: 1,
        previous: None,
    }
    .encrypt(&plaintext)?;

    let envelope = Envelope {
        format: ARCHIVE_FORMAT.to_string(),
        format_version: ARCHIVE_FORMAT_VERSION,
        kdf: params,
        cipher: CipherParams {
            algorithm: "aes-256-gcm".to_string(),
            nonce: BASE64.encode(&nonce),
        },
        ciphertext: BASE64.encode(&ciphertext),
    };
    serde_json::to_vec_pretty(&envelope)
        .map_err(|e| AppError::internal(format!("could not serialise the settings archive: {e}")))
}

/// Decrypt archive bytes back into a snapshot.
pub async fn open(bytes: &[u8], passphrase: &str) -> Result<SettingsSnapshot, AppError> {
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|e| {
        AppError::validation(
            "archive",
            format!("this file is not a bunyip settings archive: {e}"),
        )
    })?;

    if envelope.format != ARCHIVE_FORMAT {
        return Err(AppError::validation(
            "format",
            format!(
                "this file declares format `{}`, not `{ARCHIVE_FORMAT}`.",
                envelope.format
            ),
        ));
    }
    if envelope.format_version != ARCHIVE_FORMAT_VERSION {
        return Err(AppError::validation(
            "format_version",
            format!(
                "this archive is format version {}, and this bunyip-api reads version \
                 {ARCHIVE_FORMAT_VERSION}. Import it with the bunyip-api release that wrote it.",
                envelope.format_version
            ),
        ));
    }
    if envelope.cipher.algorithm != "aes-256-gcm" {
        return Err(AppError::validation(
            "cipher.algorithm",
            format!(
                "this archive declares cipher `{}`, which this binary cannot read. Only \
                 `aes-256-gcm` is supported.",
                envelope.cipher.algorithm
            ),
        ));
    }

    let decode = |what: &str, value: &str| -> Result<Vec<u8>, AppError> {
        BASE64.decode(value.as_bytes()).map_err(|e| {
            AppError::validation(what.to_string(), format!("{what} is not valid base64: {e}"))
        })
    };
    let salt = decode("kdf.salt", &envelope.kdf.salt)?;
    let nonce = decode("cipher.nonce", &envelope.cipher.nonce)?;
    let ciphertext = decode("ciphertext", &envelope.ciphertext)?;

    let key = derive_key(passphrase, envelope.kdf.clone(), salt).await?;

    // AES-GCM authenticates the whole ciphertext, so a wrong key and a mangled
    // byte are the same failure to it. Saying so is more useful than guessing
    // one of the two.
    let plaintext = decrypt_with_key(&key, &ciphertext, &nonce).map_err(|_| {
        AppError::validation(
            "passphrase",
            "the archive did not decrypt: wrong passphrase, or the archive is damaged. \
             AES-256-GCM cannot tell the two apart."
                .to_string(),
        )
    })?;

    serde_json::from_slice(&plaintext).map_err(|e| {
        AppError::validation(
            "archive",
            format!("the archive decrypted but its contents are not a settings snapshot: {e}"),
        )
    })
}

// =============================================================================
// Plan
// =============================================================================

/// A singleton section's diff: either unchanged, or the names of the columns
/// whose value differs. Values never appear; a settings plan that printed them
/// would print `smtp_username`, the Stripe ids and the whole theme.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SingletonPlan {
    pub section: String,
    pub changed_columns: Vec<String>,
}

impl SingletonPlan {
    pub fn is_unchanged(&self) -> bool {
        self.changed_columns.is_empty()
    }
}

/// A keyed table's diff, as the keys that move in each direction.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TablePlan {
    pub section: String,
    pub inserted: Vec<String>,
    pub updated: Vec<String>,
    pub deleted: Vec<DeletedRow>,
}

impl TablePlan {
    pub fn is_unchanged(&self) -> bool {
        self.inserted.is_empty() && self.updated.is_empty() && self.deleted.is_empty()
    }
}

/// One row the import will delete, and what goes with it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeletedRow {
    pub key: String,
    pub cascades: Vec<String>,
}

/// What an import does to one governed secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretOutcome {
    /// The archive holds a value the provider does not: write it.
    Set,
    /// The archive holds none and the provider does: remove it.
    Cleared,
    /// Both sides already agree.
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SecretPlan {
    pub name: String,
    pub outcome: SecretOutcome,
}

/// The whole diff between the target and the archive.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportPlan {
    pub schema_version: i64,
    pub singletons: Vec<SingletonPlan>,
    pub tables: Vec<TablePlan>,
    pub secrets: Vec<SecretPlan>,
    /// The provider the governed secrets resolve through, named in the report
    /// because `environment` is read-only and changes nothing.
    pub secrets_provider: String,
}

impl ImportPlan {
    pub fn is_unchanged(&self) -> bool {
        self.singletons.iter().all(SingletonPlan::is_unchanged)
            && self.tables.iter().all(TablePlan::is_unchanged)
            && self
                .secrets
                .iter()
                .all(|s| s.outcome == SecretOutcome::Unchanged)
    }
}

/// Diff one singleton section. Pure: both sides are already JSON objects, so
/// the changed-column list is the set of keys whose values differ.
fn plan_singleton<T: Serialize>(section: &str, target: &T, archive: &T) -> SingletonPlan {
    let to_map = |value: &T| -> serde_json::Map<String, serde_json::Value> {
        match serde_json::to_value(value) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    };
    let (target, archive) = (to_map(target), to_map(archive));
    let mut changed: Vec<String> = archive
        .iter()
        .filter(|(key, value)| target.get(*key) != Some(*value))
        .map(|(key, _)| key.clone())
        .collect();
    changed.sort();
    SingletonPlan {
        section: section.to_string(),
        changed_columns: changed,
    }
}

/// Diff one keyed table. Pure: both sides are `key -> row fingerprint` maps, so
/// the three buckets are a set difference and a value comparison.
///
/// This is the whole of replace semantics in one place: a key only the target
/// has is DELETED, which is what makes a restore land on exactly the archive's
/// content rather than the union of the two.
fn plan_table(
    section: &str,
    target: &BTreeMap<String, String>,
    archive: &BTreeMap<String, String>,
    cascades: &[&str],
) -> TablePlan {
    let mut inserted = Vec::new();
    let mut updated = Vec::new();
    for (key, fingerprint) in archive {
        match target.get(key) {
            None => inserted.push(key.clone()),
            Some(existing) if existing != fingerprint => updated.push(key.clone()),
            Some(_) => {}
        }
    }
    let deleted = target
        .keys()
        .filter(|key| !archive.contains_key(*key))
        .map(|key| DeletedRow {
            key: key.clone(),
            cascades: cascades.iter().map(|c| (*c).to_string()).collect(),
        })
        .collect();
    TablePlan {
        section: section.to_string(),
        inserted,
        updated,
        deleted,
    }
}

/// Diff one governed secret. Pure.
fn plan_secret(name: &str, target: Option<&str>, archive: Option<&str>) -> SecretPlan {
    let outcome = match (archive, target) {
        (Some(a), Some(t)) if a == t => SecretOutcome::Unchanged,
        (None, None) => SecretOutcome::Unchanged,
        (Some(_), _) => SecretOutcome::Set,
        (None, Some(_)) => SecretOutcome::Cleared,
    };
    SecretPlan {
        name: name.to_string(),
        outcome,
    }
}

/// Fingerprint a row for the diff: its JSON, which changes exactly when one of
/// its archived columns does.
fn fingerprint<T: Serialize>(row: &T) -> String {
    serde_json::to_string(row).unwrap_or_default()
}

fn keyed<T: Serialize, F: Fn(&T) -> String>(rows: &[T], key: F) -> BTreeMap<String, String> {
    rows.iter()
        .map(|row| (key(row), fingerprint(row)))
        .collect()
}

/// Validate every section, then diff the target against the archive.
///
/// Validation runs HERE rather than in [`apply`] so `--dry-run` reports a
/// rejected archive as loudly as a real run would, and so a real run has nothing
/// left to reject once it has begun writing.
pub async fn plan(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    snapshot: &SettingsSnapshot,
) -> Result<ImportPlan, AppError> {
    let schema_version = require_matching_schema(pool).await?;
    if snapshot.schema_version != schema_version {
        return Err(AppError::validation(
            "schema_version",
            format!(
                "this archive was exported from schema version {}, and this database is at \
                 {schema_version}. A settings row is shaped by the schema, so importing across \
                 versions is refused. Export again from a deployment at {schema_version}, or \
                 restore into one at {}.",
                snapshot.schema_version, snapshot.schema_version
            ),
        ));
    }

    validate_snapshot(config, snapshot)?;

    let target = export(
        pool,
        config,
        key_set,
        ExportOptions {
            include_catalog: snapshot.sections.catalog.is_some(),
            include_oauth_clients: snapshot.sections.oauth_clients.is_some(),
        },
    )
    .await?;

    let mut plan = diff(config, &target.sections, &snapshot.sections);
    // `diff` is pure and has no database to ask, so the version both sides
    // agreed on above is stamped here rather than guessed there.
    plan.schema_version = schema_version;
    Ok(plan)
}

/// Everything the archive must satisfy before a single row is written. Reuses
/// the admin path's own validators so a restored row can never be one the admin
/// pages would have refused.
fn validate_snapshot(config: &Config, snapshot: &SettingsSnapshot) -> Result<(), AppError> {
    let branding = &snapshot.sections.branding;
    validate_branding(&UpdateBrandingRequest {
        brand_name: branding.brand_name.clone(),
        tagline: branding.tagline.clone(),
        meta_description: branding.meta_description.clone(),
        og_image_url: branding.og_image_url.clone(),
        theme_css: branding.theme_css.clone(),
        theme_color_light: branding.theme_color_light.clone(),
        theme_color_dark: branding.theme_color_dark.clone(),
    })
    .map_err(|e| AppError::validation(e.field, e.message))?;

    let tier = &snapshot.sections.tier_config;
    let has = |id: &Option<String>| id.as_deref().map(str::trim).is_some_and(|s| !s.is_empty());
    if let Some(e) = visible_without_price_error(&[
        (
            "Free / lifetime",
            tier.lifetime_visible,
            has(&tier.free_price_id),
        ),
        (
            "Early adopter",
            tier.early_adopter_visible,
            has(&tier.early_adopter_price_id),
        ),
        (
            "Standard",
            tier.standard_visible,
            has(&tier.standard_price_id),
        ),
    ]) {
        return Err(e);
    }

    for row in &snapshot.sections.rate_limit_configs {
        validate_limits(row.max_requests, row.window_seconds).map_err(|e| {
            AppError::bad_request(format!(
                "rate_limit_configs `{}` in the archive is not a legal override: {e}",
                row.action
            ))
        })?;
    }

    refuse_disabled_email_in_production(
        config.is_production(),
        snapshot.sections.email_config.enabled.unwrap_or(false),
    )?;

    if let Some(catalog) = &snapshot.sections.catalog {
        let groups: BTreeSet<&str> = catalog
            .application_groups
            .iter()
            .map(|g| g.slug.as_str())
            .collect();
        let apps: BTreeSet<&str> = catalog
            .applications
            .iter()
            .map(|a| a.slug.as_str())
            .collect();
        for app in &catalog.applications {
            if let Some(group) = app.group_slug.as_deref() {
                if !groups.contains(group) {
                    return Err(AppError::validation(
                        "catalog.applications",
                        format!(
                            "application `{}` names group `{group}`, which the archive does not \
                             carry. Export the catalog again from a deployment where the group \
                             exists.",
                            app.slug
                        ),
                    ));
                }
            }
        }
        for doc in &catalog.application_docs {
            if !apps.contains(doc.application_slug.as_str()) {
                return Err(AppError::validation(
                    "catalog.application_docs",
                    format!(
                        "documentation page `{}` names application `{}`, which the archive does \
                         not carry.",
                        doc.slug, doc.application_slug
                    ),
                ));
            }
        }
        for entitlement in &catalog.stripe_price_entitlements {
            if !apps.contains(entitlement.application_slug.as_str()) {
                return Err(AppError::validation(
                    "catalog.stripe_price_entitlements",
                    format!(
                        "price `{}` is entitled to application `{}`, which the archive does not \
                         carry.",
                        entitlement.stripe_price_id, entitlement.application_slug
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// The pure diff, given both sides' sections.
fn diff(config: &Config, target: &Sections, archive: &Sections) -> ImportPlan {
    let mut singletons = vec![
        plan_singleton("branding", &target.branding, &archive.branding),
        plan_singleton("tier_config", &target.tier_config, &archive.tier_config),
        plan_singleton(
            "auto_ban_config",
            &target.auto_ban_config,
            &archive.auto_ban_config,
        ),
        plan_singleton("email_config", &target.email_config, &archive.email_config),
        plan_singleton(
            "stripe_config",
            &target.stripe_config,
            &archive.stripe_config,
        ),
    ];
    singletons.push(plan_singleton(
        "system_settings",
        &target.system_settings,
        &archive.system_settings,
    ));

    let mut tables = vec![
        plan_table(
            "branding_assets",
            &keyed(&target.branding_assets, |r| r.kind.clone()),
            &keyed(&archive.branding_assets, |r| r.kind.clone()),
            &[],
        ),
        plan_table(
            "rate_limit_configs",
            &keyed(&target.rate_limit_configs, |r| r.action.clone()),
            &keyed(&archive.rate_limit_configs, |r| r.action.clone()),
            &[],
        ),
    ];

    if let Some(archive_catalog) = &archive.catalog {
        let empty = CatalogSection::default();
        let target_catalog = target.catalog.as_ref().unwrap_or(&empty);
        tables.push(plan_table(
            "application_groups",
            &keyed(&target_catalog.application_groups, |r| r.slug.clone()),
            &keyed(&archive_catalog.application_groups, |r| r.slug.clone()),
            &[],
        ));
        tables.push(plan_table(
            "applications",
            &keyed(&target_catalog.applications, |r| r.slug.clone()),
            &keyed(&archive_catalog.applications, |r| r.slug.clone()),
            APPLICATION_CASCADES,
        ));
        tables.push(plan_table(
            "application_docs",
            &keyed(&target_catalog.application_docs, doc_key),
            &keyed(&archive_catalog.application_docs, doc_key),
            &[],
        ));
        tables.push(plan_table(
            "stripe_price_entitlements",
            &keyed(&target_catalog.stripe_price_entitlements, entitlement_key),
            &keyed(&archive_catalog.stripe_price_entitlements, entitlement_key),
            &[],
        ));
    }

    if let Some(archive_clients) = &archive.oauth_clients {
        let empty = Vec::new();
        let target_clients = target.oauth_clients.as_ref().unwrap_or(&empty);
        tables.push(plan_table(
            "oauth_clients",
            &keyed(target_clients, |r| r.client_id.to_string()),
            &keyed(archive_clients, |r| r.client_id.to_string()),
            OAUTH_CLIENT_CASCADES,
        ));
    }

    let secrets = GovernedSecret::ALL
        .iter()
        .map(|secret| {
            plan_secret(
                secret.name(),
                target
                    .governed_secrets
                    .get(secret.name())
                    .and_then(Option::as_deref),
                archive
                    .governed_secrets
                    .get(secret.name())
                    .and_then(Option::as_deref),
            )
        })
        .collect();

    ImportPlan {
        schema_version: 0,
        singletons,
        tables,
        secrets,
        secrets_provider: config.secrets_provider.to_string(),
    }
}

fn doc_key(row: &ApplicationDocRow) -> String {
    format!("{}/{}", row.application_slug, row.slug)
}

fn entitlement_key(row: &PriceEntitlementRow) -> String {
    format!("{} -> {}", row.stripe_price_id, row.application_slug)
}

// =============================================================================
// Apply
// =============================================================================

/// One import step and whether it reached the target.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StepOutcome {
    pub step: String,
    pub applied: bool,
    pub detail: Option<String>,
}

/// The result of a real (non-dry-run) import.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportReport {
    pub plan: ImportPlan,
    pub steps: Vec<StepOutcome>,
}

impl ImportReport {
    /// Steps that did not apply, so the caller can exit 1 naming them.
    pub fn unapplied(&self) -> Vec<&StepOutcome> {
        self.steps.iter().filter(|s| !s.applied).collect()
    }
}

/// Validate, plan and write. `updated_by` stamps every attribution column; the
/// CLI passes `None`, which is the honest value for a run no admin account made.
///
/// The three write steps cannot be one unit. The database half is a single
/// transaction, so it is all-or-nothing on its own; the governed secrets may
/// live in Infisical or be owned by the environment, and the system settings are
/// a file layer. Rather than pretend, each step is reported separately and a
/// failure names what applied and what did not. Re-running after fixing the
/// cause is safe: every step is a replace, so a second run is a no-op for the
/// steps that already landed.
pub async fn apply(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    snapshot: &SettingsSnapshot,
    updated_by: Option<Uuid>,
) -> Result<ImportReport, AppError> {
    let plan = plan(pool, config, key_set, snapshot).await?;
    let mut steps = Vec::new();

    write_database_sections(pool, snapshot, updated_by).await?;
    steps.push(StepOutcome {
        step: "database sections".to_string(),
        applied: true,
        detail: None,
    });

    let secrets_result = write_governed_secrets(pool, config, key_set, snapshot, &plan).await;
    steps.push(match &secrets_result {
        Ok(()) => StepOutcome {
            step: "governed secrets".to_string(),
            applied: true,
            detail: None,
        },
        Err(e) => StepOutcome {
            step: "governed secrets".to_string(),
            applied: false,
            detail: Some(e.to_string()),
        },
    });

    let settings_result = SystemSettings::from(&snapshot.sections.system_settings).save();
    steps.push(match &settings_result {
        Ok(()) => StepOutcome {
            step: "system settings (file layer)".to_string(),
            applied: true,
            detail: None,
        },
        Err(e) => StepOutcome {
            step: "system settings (file layer)".to_string(),
            applied: false,
            detail: Some(e.to_string()),
        },
    });

    // Verification: re-read every section and require it to equal the archive.
    // A write that reported success but did not land (a trigger, a stricter
    // column, an Infisical write that was accepted and dropped) is the failure
    // mode a restore cannot afford to discover later.
    let verification = verify(pool, config, key_set, snapshot).await;
    steps.push(match &verification {
        Ok(()) => StepOutcome {
            step: "verification".to_string(),
            applied: true,
            detail: None,
        },
        Err(e) => StepOutcome {
            step: "verification".to_string(),
            applied: false,
            detail: Some(e.to_string()),
        },
    });

    Ok(ImportReport { plan, steps })
}

/// Re-export and compare. Only the sections the archive carries are compared,
/// so an archive without the catalog does not fail on the target's own.
async fn verify(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    snapshot: &SettingsSnapshot,
) -> Result<(), AppError> {
    let fresh = export(
        pool,
        config,
        key_set,
        ExportOptions {
            include_catalog: snapshot.sections.catalog.is_some(),
            include_oauth_clients: snapshot.sections.oauth_clients.is_some(),
        },
    )
    .await?;

    let residue = diff(config, &fresh.sections, &snapshot.sections);
    if residue.is_unchanged() {
        return Ok(());
    }
    Err(AppError::internal(format!(
        "the import wrote successfully but the database does not match the archive afterwards. \
         Still differing: {}",
        render_differences(&residue)
    )))
}

/// The section names still differing after a write, for the verification error.
/// Names only, never values.
fn render_differences(plan: &ImportPlan) -> String {
    let mut parts = Vec::new();
    for singleton in &plan.singletons {
        if !singleton.is_unchanged() {
            parts.push(format!(
                "{} ({})",
                singleton.section,
                singleton.changed_columns.join(", ")
            ));
        }
    }
    for table in &plan.tables {
        if !table.is_unchanged() {
            parts.push(format!(
                "{} ({} to insert, {} to update, {} to delete)",
                table.section,
                table.inserted.len(),
                table.updated.len(),
                table.deleted.len()
            ));
        }
    }
    for secret in &plan.secrets {
        if secret.outcome != SecretOutcome::Unchanged {
            parts.push(secret.name.clone());
        }
    }
    parts.join("; ")
}

/// Write every database section in ONE transaction.
///
/// The repositories take a `&PgPool` rather than a transaction, so joining them
/// into one unit is not possible; this module issues the SQL itself instead. The
/// alternative (a repository call per section) would leave a failure halfway
/// through with branding restored and the catalogue not, which is the state a
/// settings restore exists to avoid.
async fn write_database_sections(
    pool: &PgPool,
    snapshot: &SettingsSnapshot,
    updated_by: Option<Uuid>,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;
    let sections = &snapshot.sections;

    // --- branding -----------------------------------------------------------
    let b = &sections.branding;
    sqlx::query(
        "UPDATE branding SET brand_name = $1, tagline = $2, meta_description = $3, \
         og_image_url = $4, theme_css = $5, theme_color_light = $6, theme_color_dark = $7, \
         mark_updated_at = $8, favicon_updated_at = $9, mascot_updated_at = $10, \
         updated_at = NOW(), updated_by = $11 WHERE id = 1",
    )
    .bind(&b.brand_name)
    .bind(&b.tagline)
    .bind(&b.meta_description)
    .bind(&b.og_image_url)
    .bind(&b.theme_css)
    .bind(&b.theme_color_light)
    .bind(&b.theme_color_dark)
    .bind(b.mark_updated_at)
    .bind(b.favicon_updated_at)
    .bind(b.mascot_updated_at)
    .bind(updated_by)
    .execute(&mut *tx)
    .await?;

    // --- branding_assets ----------------------------------------------------
    let kinds: Vec<String> = sections
        .branding_assets
        .iter()
        .map(|a| a.kind.clone())
        .collect();
    sqlx::query("DELETE FROM branding_assets WHERE NOT (kind = ANY($1))")
        .bind(&kinds)
        .execute(&mut *tx)
        .await?;
    for asset in &sections.branding_assets {
        sqlx::query(
            "INSERT INTO branding_assets (kind, mime_type, size_bytes, data, updated_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (kind) DO UPDATE SET mime_type = EXCLUDED.mime_type, \
             size_bytes = EXCLUDED.size_bytes, data = EXCLUDED.data, updated_at = NOW()",
        )
        .bind(&asset.kind)
        .bind(&asset.mime_type)
        .bind(asset.size_bytes)
        .bind(&asset.data)
        .execute(&mut *tx)
        .await?;
    }

    // --- tier_config --------------------------------------------------------
    let t = &sections.tier_config;
    sqlx::query(
        "UPDATE tier_config SET lifetime_slots = $1, early_adopter_slots = $2, \
         early_adopter_trial_days = $3, standard_trial_days = $4, free_price_id = $5, \
         early_adopter_price_id = $6, standard_price_id = $7, lifetime_product_id = $8, \
         early_adopter_product_id = $9, standard_product_id = $10, pricing_enabled = $11, \
         lifetime_visible = $12, early_adopter_visible = $13, standard_visible = $14, \
         orgs_enabled = $15, updated_at = NOW(), updated_by = $16 WHERE id = 1",
    )
    .bind(t.lifetime_slots)
    .bind(t.early_adopter_slots)
    .bind(t.early_adopter_trial_days)
    .bind(t.standard_trial_days)
    .bind(&t.free_price_id)
    .bind(&t.early_adopter_price_id)
    .bind(&t.standard_price_id)
    .bind(&t.lifetime_product_id)
    .bind(&t.early_adopter_product_id)
    .bind(&t.standard_product_id)
    .bind(t.pricing_enabled)
    .bind(t.lifetime_visible)
    .bind(t.early_adopter_visible)
    .bind(t.standard_visible)
    .bind(t.orgs_enabled)
    .bind(updated_by)
    .execute(&mut *tx)
    .await?;

    // --- auto_ban_config ----------------------------------------------------
    let a = &sections.auto_ban_config;
    sqlx::query(
        "UPDATE auto_ban_config SET enabled = $1, threshold = $2, window_secs = $3, \
         ban_duration_secs = $4, updated_at = NOW(), updated_by = $5 WHERE id = 1",
    )
    .bind(a.enabled)
    .bind(a.threshold)
    .bind(a.window_secs)
    .bind(a.ban_duration_secs)
    .bind(updated_by)
    .execute(&mut *tx)
    .await?;

    // --- email_config -------------------------------------------------------
    let e = &sections.email_config;
    sqlx::query(
        "UPDATE email_config SET enabled = $1, smtp_host = $2, smtp_port = $3, smtp_tls = $4, \
         smtp_username = $5, from_email = $6, from_name = $7, admin_notification_emails = $8, \
         imap_host = $9, imap_port = $10, imap_username = $11, imap_mailbox = $12, \
         imap_enabled = $13, updated_at = NOW(), updated_by = $14 WHERE id = 1",
    )
    .bind(e.enabled)
    .bind(&e.smtp_host)
    .bind(e.smtp_port)
    .bind(&e.smtp_tls)
    .bind(&e.smtp_username)
    .bind(&e.from_email)
    .bind(&e.from_name)
    .bind(&e.admin_notification_emails)
    .bind(&e.imap_host)
    .bind(e.imap_port)
    .bind(&e.imap_username)
    .bind(&e.imap_mailbox)
    .bind(e.imap_enabled)
    .bind(updated_by)
    .execute(&mut *tx)
    .await?;

    // --- stripe_config ------------------------------------------------------
    let s = &sections.stripe_config;
    sqlx::query(
        "UPDATE stripe_config SET app_tag = $1, success_url = $2, cancel_url = $3, \
         trial_period_days = $4, updated_at = NOW(), updated_by = $5 WHERE id = 1",
    )
    .bind(&s.app_tag)
    .bind(&s.success_url)
    .bind(&s.cancel_url)
    .bind(s.trial_period_days)
    .bind(updated_by)
    .execute(&mut *tx)
    .await?;

    // --- rate_limit_configs -------------------------------------------------
    let actions: Vec<String> = sections
        .rate_limit_configs
        .iter()
        .map(|r| r.action.clone())
        .collect();
    sqlx::query("DELETE FROM rate_limit_configs WHERE NOT (action = ANY($1))")
        .bind(&actions)
        .execute(&mut *tx)
        .await?;
    for row in &sections.rate_limit_configs {
        sqlx::query(
            "INSERT INTO rate_limit_configs (action, max_requests, window_seconds, updated_at, \
             updated_by) VALUES ($1, $2, $3, NOW(), $4) \
             ON CONFLICT (action) DO UPDATE SET max_requests = EXCLUDED.max_requests, \
             window_seconds = EXCLUDED.window_seconds, updated_at = NOW(), \
             updated_by = EXCLUDED.updated_by",
        )
        .bind(&row.action)
        .bind(row.max_requests)
        .bind(row.window_seconds)
        .bind(updated_by)
        .execute(&mut *tx)
        .await?;
    }

    if let Some(catalog) = &sections.catalog {
        write_catalog(&mut tx, catalog).await?;
    }
    if let Some(clients) = &sections.oauth_clients {
        write_oauth_clients(&mut tx, clients, updated_by).await?;
    }

    tx.commit().await?;
    Ok(())
}

/// The catalogue, in the order the foreign keys allow.
///
/// Groups are inserted BEFORE applications (an application names its group) and
/// deleted AFTER them (`applications.group_id` is `ON DELETE SET NULL`, so
/// dropping a group first would silently unparent an application this import is
/// about to reparent anyway).
async fn write_catalog(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    catalog: &CatalogSection,
) -> Result<(), AppError> {
    for group in &catalog.application_groups {
        sqlx::query(
            "INSERT INTO application_groups (slug, name, display_name, description, icon_url, \
             sort_order, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW()) \
             ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, \
             display_name = EXCLUDED.display_name, description = EXCLUDED.description, \
             icon_url = EXCLUDED.icon_url, sort_order = EXCLUDED.sort_order, updated_at = NOW()",
        )
        .bind(&group.slug)
        .bind(&group.name)
        .bind(&group.display_name)
        .bind(&group.description)
        .bind(&group.icon_url)
        .bind(group.sort_order)
        .execute(&mut **tx)
        .await?;
    }

    let app_slugs: Vec<String> = catalog
        .applications
        .iter()
        .map(|a| a.slug.clone())
        .collect();
    sqlx::query("DELETE FROM applications WHERE NOT (slug = ANY($1))")
        .bind(&app_slugs)
        .execute(&mut **tx)
        .await?;

    for app in &catalog.applications {
        sqlx::query(
            "INSERT INTO applications (slug, name, display_name, description, icon_url, \
             is_active, maintenance_mode, maintenance_message, container_name, health_check_url, \
             version, source_code_url, subdomain, webhook_url, sort_order, forgejo_owner, \
             forgejo_repo, pinned_release_tag, oci_image_owner, oci_image_name, pinned_image_tag, \
             artifact_source, forgejo_package, is_hosted, requires_entitlement, group_id, \
             release_notes_url, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
             $18, $19, $20, $21, $22, $23, $24, $25, \
             (SELECT id FROM application_groups WHERE slug = $26), $27, NOW(), NOW()) \
             ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, \
             display_name = EXCLUDED.display_name, description = EXCLUDED.description, \
             icon_url = EXCLUDED.icon_url, is_active = EXCLUDED.is_active, \
             maintenance_mode = EXCLUDED.maintenance_mode, \
             maintenance_message = EXCLUDED.maintenance_message, \
             container_name = EXCLUDED.container_name, \
             health_check_url = EXCLUDED.health_check_url, version = EXCLUDED.version, \
             source_code_url = EXCLUDED.source_code_url, subdomain = EXCLUDED.subdomain, \
             webhook_url = EXCLUDED.webhook_url, sort_order = EXCLUDED.sort_order, \
             forgejo_owner = EXCLUDED.forgejo_owner, forgejo_repo = EXCLUDED.forgejo_repo, \
             pinned_release_tag = EXCLUDED.pinned_release_tag, \
             oci_image_owner = EXCLUDED.oci_image_owner, \
             oci_image_name = EXCLUDED.oci_image_name, \
             pinned_image_tag = EXCLUDED.pinned_image_tag, \
             artifact_source = EXCLUDED.artifact_source, \
             forgejo_package = EXCLUDED.forgejo_package, is_hosted = EXCLUDED.is_hosted, \
             requires_entitlement = EXCLUDED.requires_entitlement, group_id = EXCLUDED.group_id, \
             release_notes_url = EXCLUDED.release_notes_url, updated_at = NOW()",
        )
        .bind(&app.slug)
        .bind(&app.name)
        .bind(&app.display_name)
        .bind(&app.description)
        .bind(&app.icon_url)
        .bind(app.is_active)
        .bind(app.maintenance_mode)
        .bind(&app.maintenance_message)
        .bind(&app.container_name)
        .bind(&app.health_check_url)
        .bind(&app.version)
        .bind(&app.source_code_url)
        .bind(&app.subdomain)
        .bind(&app.webhook_url)
        .bind(app.sort_order)
        .bind(&app.forgejo_owner)
        .bind(&app.forgejo_repo)
        .bind(&app.pinned_release_tag)
        .bind(&app.oci_image_owner)
        .bind(&app.oci_image_name)
        .bind(&app.pinned_image_tag)
        .bind(&app.artifact_source)
        .bind(&app.forgejo_package)
        .bind(app.is_hosted)
        .bind(app.requires_entitlement)
        .bind(&app.group_slug)
        .bind(&app.release_notes_url)
        .execute(&mut **tx)
        .await?;
    }

    let group_slugs: Vec<String> = catalog
        .application_groups
        .iter()
        .map(|g| g.slug.clone())
        .collect();
    sqlx::query("DELETE FROM application_groups WHERE NOT (slug = ANY($1))")
        .bind(&group_slugs)
        .execute(&mut **tx)
        .await?;

    let doc_keys: Vec<String> = catalog.application_docs.iter().map(doc_key).collect();
    sqlx::query(
        "DELETE FROM application_docs d USING applications a WHERE a.id = d.application_id \
         AND NOT (a.slug || '/' || d.slug = ANY($1))",
    )
    .bind(&doc_keys)
    .execute(&mut **tx)
    .await?;
    for doc in &catalog.application_docs {
        sqlx::query(
            "INSERT INTO application_docs (application_id, slug, title, body, sort_order, \
             created_at, updated_at) \
             VALUES ((SELECT id FROM applications WHERE slug = $1), $2, $3, $4, $5, NOW(), NOW()) \
             ON CONFLICT (application_id, slug) DO UPDATE SET title = EXCLUDED.title, \
             body = EXCLUDED.body, sort_order = EXCLUDED.sort_order, updated_at = NOW()",
        )
        .bind(&doc.application_slug)
        .bind(&doc.slug)
        .bind(&doc.title)
        .bind(&doc.body)
        .bind(doc.sort_order)
        .execute(&mut **tx)
        .await?;
    }

    let entitlement_keys: Vec<String> = catalog
        .stripe_price_entitlements
        .iter()
        .map(entitlement_key)
        .collect();
    sqlx::query(
        "DELETE FROM stripe_price_entitlements e USING applications a \
         WHERE a.id = e.application_id \
         AND NOT (e.stripe_price_id || ' -> ' || a.slug = ANY($1))",
    )
    .bind(&entitlement_keys)
    .execute(&mut **tx)
    .await?;
    for entitlement in &catalog.stripe_price_entitlements {
        sqlx::query(
            "INSERT INTO stripe_price_entitlements (stripe_price_id, application_id, created_at) \
             VALUES ($1, (SELECT id FROM applications WHERE slug = $2), NOW()) \
             ON CONFLICT (stripe_price_id, application_id) DO NOTHING",
        )
        .bind(&entitlement.stripe_price_id)
        .bind(&entitlement.application_slug)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

/// The OAuth client registrations.
///
/// Three of the tables that reference `oauth_clients(client_id)` carry no
/// `ON DELETE` action (`oauth_authorization_codes`, `refresh_token_families`,
/// `refresh_tokens_v2`), so a client the archive does not carry cannot simply be
/// deleted: the foreign key blocks it. Those rows are live authorisation codes
/// and refresh tokens for a registration that is going away, so deleting them is
/// the correct reading rather than a workaround, and the plan names all three.
async fn write_oauth_clients(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    clients: &[OauthClientRow],
    created_by: Option<Uuid>,
) -> Result<(), AppError> {
    let ids: Vec<Uuid> = clients.iter().map(|c| c.client_id).collect();

    for table in ["refresh_tokens_v2", "refresh_token_families"] {
        sqlx::query(&format!(
            "DELETE FROM {table} WHERE client_id IN \
             (SELECT client_id FROM oauth_clients WHERE NOT (client_id = ANY($1)))"
        ))
        .bind(&ids)
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query(
        "DELETE FROM oauth_authorization_codes WHERE client_id IN \
         (SELECT client_id FROM oauth_clients WHERE NOT (client_id = ANY($1)))",
    )
    .bind(&ids)
    .execute(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM oauth_clients WHERE NOT (client_id = ANY($1))")
        .bind(&ids)
        .execute(&mut **tx)
        .await?;

    for client in clients {
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, client_secret_hash, client_type, name, \
             redirect_uris, post_logout_redirect_uris, backchannel_logout_uri, \
             lifecycle_event_uri, allowed_scopes, allowed_grant_types, \
             token_endpoint_auth_method, require_pkce, access_token_ttl_seconds, \
             refresh_token_ttl_seconds, refresh_idle_ttl_seconds, audience, dpop_bound, \
             disabled_at, tenant_claim_name, first_party, logo_uri, created_at, created_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
             $18, $19, $20, $21, NOW(), $22) \
             ON CONFLICT (client_id) DO UPDATE SET \
             client_secret_hash = EXCLUDED.client_secret_hash, \
             client_type = EXCLUDED.client_type, name = EXCLUDED.name, \
             redirect_uris = EXCLUDED.redirect_uris, \
             post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris, \
             backchannel_logout_uri = EXCLUDED.backchannel_logout_uri, \
             lifecycle_event_uri = EXCLUDED.lifecycle_event_uri, \
             allowed_scopes = EXCLUDED.allowed_scopes, \
             allowed_grant_types = EXCLUDED.allowed_grant_types, \
             token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method, \
             require_pkce = EXCLUDED.require_pkce, \
             access_token_ttl_seconds = EXCLUDED.access_token_ttl_seconds, \
             refresh_token_ttl_seconds = EXCLUDED.refresh_token_ttl_seconds, \
             refresh_idle_ttl_seconds = EXCLUDED.refresh_idle_ttl_seconds, \
             audience = EXCLUDED.audience, dpop_bound = EXCLUDED.dpop_bound, \
             disabled_at = EXCLUDED.disabled_at, \
             tenant_claim_name = EXCLUDED.tenant_claim_name, \
             first_party = EXCLUDED.first_party, logo_uri = EXCLUDED.logo_uri",
        )
        .bind(client.client_id)
        .bind(&client.client_secret_hash)
        .bind(&client.client_type)
        .bind(&client.name)
        .bind(&client.redirect_uris)
        .bind(&client.post_logout_redirect_uris)
        .bind(&client.backchannel_logout_uri)
        .bind(&client.lifecycle_event_uri)
        .bind(&client.allowed_scopes)
        .bind(&client.allowed_grant_types)
        .bind(&client.token_endpoint_auth_method)
        .bind(client.require_pkce)
        .bind(client.access_token_ttl_seconds)
        .bind(client.refresh_token_ttl_seconds)
        .bind(client.refresh_idle_ttl_seconds)
        .bind(&client.audience)
        .bind(client.dpop_bound)
        .bind(client.disabled_at)
        .bind(&client.tenant_claim_name)
        .bind(client.first_party)
        .bind(&client.logo_uri)
        .bind(created_by)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

/// Write the governed secrets through the declared provider.
///
/// `environment` is read-only by nature (a process cannot set a variable for its
/// own next boot, and the compose secret files are mounted read-only), so this
/// step cannot write in that mode. Rather than report a success nothing acted
/// on, the plan already required the environment to hold exactly the archived
/// value, and anything else fails here naming the `{NAME}_FILE` to fix.
async fn write_governed_secrets(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    snapshot: &SettingsSnapshot,
    plan: &ImportPlan,
) -> Result<(), AppError> {
    let provider = config.secrets_provider;
    for secret in GovernedSecret::ALL {
        let outcome = plan
            .secrets
            .iter()
            .find(|s| s.name == secret.name())
            .map(|s| s.outcome)
            .unwrap_or(SecretOutcome::Unchanged);
        if outcome == SecretOutcome::Unchanged {
            continue;
        }
        if provider == SecretsProvider::Environment {
            return Err(environment_provider_error(secret, outcome));
        }
        match snapshot
            .sections
            .governed_secrets
            .get(secret.name())
            .and_then(Option::as_deref)
        {
            Some(value) => {
                crate::secrets::write_secret(pool, config, key_set, provider, secret, value, None)
                    .await?
            }
            None => {
                crate::secrets::purge_secret(pool, config, secret, provider).await?;
            }
        }
    }
    Ok(())
}

/// The refusal in `environment` mode, naming the file the operator must change.
fn environment_provider_error(secret: GovernedSecret, outcome: SecretOutcome) -> AppError {
    let remedy = match outcome {
        SecretOutcome::Cleared => format!(
            "remove {}_FILE (and the ./secrets/{} file it points at) from the api service",
            secret.name(),
            secret.secret_file()
        ),
        _ => format!(
            "write the archived value into the file {}_FILE points at (./secrets/{})",
            secret.name(),
            secret.secret_file()
        ),
    };
    AppError::Conflict {
        message: format!(
            "SECRETS_STORAGE=environment, so {} is owned by the environment and the import cannot \
             write it. To restore this deployment: {remedy}, then re-run the import.",
            secret.name()
        ),
    }
}

// =============================================================================
// Rendering
//
// A plan and a report name sections, columns, keys and counts. They NEVER carry
// a setting value, a secret, a client-secret hash or asset bytes: the whole
// point of the archive is that those exist in one encrypted file, and echoing
// one into a terminal (and from there into a shell history, a CI log or a
// screenshot) would undo that.
// =============================================================================

/// Render a plan for `--dry-run`.
pub fn render_plan(plan: &ImportPlan) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "settings-import plan (schema version {})\n\n",
        plan.schema_version
    ));
    render_sections(&mut out, plan);
    out.push_str("\nNothing has been written. Re-run without --dry-run to apply.\n");
    out
}

fn render_sections(out: &mut String, plan: &ImportPlan) {
    for singleton in &plan.singletons {
        if singleton.is_unchanged() {
            out.push_str(&format!("  {}: unchanged\n", singleton.section));
        } else {
            out.push_str(&format!(
                "  {}: {} column(s) change: {}\n",
                singleton.section,
                singleton.changed_columns.len(),
                singleton.changed_columns.join(", ")
            ));
        }
    }
    for table in &plan.tables {
        if table.is_unchanged() {
            out.push_str(&format!("  {}: unchanged\n", table.section));
            continue;
        }
        out.push_str(&format!("  {}:\n", table.section));
        if !table.inserted.is_empty() {
            out.push_str(&format!("    insert: {}\n", table.inserted.join(", ")));
        }
        if !table.updated.is_empty() {
            out.push_str(&format!("    update: {}\n", table.updated.join(", ")));
        }
        for row in &table.deleted {
            if row.cascades.is_empty() {
                out.push_str(&format!("    delete: {}\n", row.key));
            } else {
                out.push_str(&format!(
                    "    delete: {} (also removes its rows in {})\n",
                    row.key,
                    row.cascades.join(", ")
                ));
            }
        }
    }
    out.push_str(&format!(
        "  governed secrets (provider: {}):\n",
        plan.secrets_provider
    ));
    for secret in &plan.secrets {
        let verdict = match secret.outcome {
            SecretOutcome::Set => "set",
            SecretOutcome::Cleared => "cleared",
            SecretOutcome::Unchanged => "unchanged",
        };
        out.push_str(&format!("    {}: {verdict}\n", secret.name));
    }
}

/// Render the outcome of a real import.
pub fn render_report(report: &ImportReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "settings-import applied (schema version {})\n\n",
        report.plan.schema_version
    ));
    render_sections(&mut out, &report.plan);
    out.push_str("\n  steps:\n");
    for step in &report.steps {
        let verdict = if step.applied {
            "applied".to_string()
        } else {
            match &step.detail {
                Some(detail) => format!("NOT applied: {detail}"),
                None => "NOT applied".to_string(),
            }
        };
        out.push_str(&format!("    {}: {verdict}\n", step.step));
    }
    // The last line, deliberately: a running process holds the tier-config
    // snapshot in memory and reloads it only on an admin save, and the system
    // settings are read at boot. An operator who skips this reads the old values
    // back off a live deployment and concludes the import did nothing.
    out.push_str("\nRestart bunyip-api so every process picks the restored settings up.\n");
    out
}

// =============================================================================
// File handling for the subcommands
// =============================================================================

/// Read a passphrase from a file, or from stdin when the path is `-`.
///
/// No flag takes the passphrase literally: an argument is visible in `ps`, in
/// the shell history and in a container's `docker inspect` output, which is the
/// exposure the whole two-tier secret convention exists to avoid. At most one
/// trailing newline is stripped, so a passphrase that genuinely ends in
/// whitespace survives an `echo` into a file.
pub fn read_passphrase(path: &str) -> Result<String, AppError> {
    let raw = if path == "-" {
        use std::io::Read as _;
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).map_err(|e| {
            AppError::internal(format!("could not read the passphrase from stdin: {e}"))
        })?;
        buf
    } else {
        std::fs::read_to_string(path).map_err(|e| {
            AppError::internal(format!("could not read the passphrase file {path}: {e}"))
        })?
    };

    let trimmed = raw
        .strip_suffix('\n')
        .map(|s| s.strip_suffix('\r').unwrap_or(s))
        .unwrap_or(&raw);
    if trimmed.is_empty() {
        return Err(AppError::validation(
            "passphrase",
            format!("the passphrase source {path} is empty."),
        ));
    }
    Ok(trimmed.to_string())
}

/// Create the archive file at `path`, refusing to overwrite an existing one, and
/// give it mode 0600 as it is created.
///
/// There is no `--force`: the file holds every integration secret in plaintext
/// under one passphrase, so overwriting one archive with another is exactly the
/// mistake that cannot be undone. Creating with the mode (rather than
/// `chmod`-ing afterwards) leaves no window in which the bytes are world
/// readable.
pub fn write_archive(path: &str, bytes: &[u8]) -> Result<(), AppError> {
    if path == "-" {
        return Err(AppError::validation(
            "output",
            "--output must be a file path: stdout carries the log lines too, so an archive \
             written there would be interleaved with them."
                .to_string(),
        ));
    }
    if std::path::Path::new(path).exists() {
        return Err(AppError::validation(
            "output",
            format!(
                "{path} already exists. An archive is not overwritten: choose another path, or \
                 move the existing file aside."
            ),
        ));
    }

    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| AppError::internal(format!("could not create {path}: {e}")))?;
    file.write_all(bytes)
        .map_err(|e| AppError::internal(format!("could not write {path}: {e}")))?;
    Ok(())
}

/// Read archive bytes from `path`. `-` is refused for the same reason `--output`
/// refuses it: the stream is shared with the log.
pub fn read_archive(path: &str) -> Result<Vec<u8>, AppError> {
    if path == "-" {
        return Err(AppError::validation(
            "input",
            "--input must be a file path, not `-`.".to_string(),
        ));
    }
    std::fs::read(path).map_err(|e| AppError::internal(format!("could not read {path}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A passphrase that clears both rules, so the crypto tests are testing the
    /// crypto rather than the strength gate.
    const STRONG: &str = "correct-horse-battery-staple-vault-27";

    fn sample_snapshot() -> SettingsSnapshot {
        let mut governed_secrets = BTreeMap::new();
        governed_secrets.insert("SMTP_PASSWORD".to_string(), Some("hunter2".to_string()));
        governed_secrets.insert("STRIPE_SECRET_KEY".to_string(), None);
        SettingsSnapshot {
            created_at: Utc::now(),
            bunyip_version: "0.0.0-test".to_string(),
            schema_version: 20260101000001,
            sections: Sections {
                branding: BrandingSection {
                    brand_name: "Example".to_string(),
                    ..BrandingSection::default()
                },
                branding_assets: vec![BrandingAssetRow {
                    kind: "mark".to_string(),
                    mime_type: "image/png".to_string(),
                    size_bytes: 4,
                    data: vec![1, 2, 3, 4],
                }],
                tier_config: TierConfigSection::default(),
                auto_ban_config: AutoBanConfigSection::default(),
                email_config: EmailConfigSection::default(),
                stripe_config: StripeConfigSection::default(),
                rate_limit_configs: vec![RateLimitConfigRow {
                    action: "login".to_string(),
                    max_requests: 5,
                    window_seconds: 60,
                }],
                system_settings: SystemSettingsSection::default(),
                governed_secrets,
                catalog: None,
                oauth_clients: None,
            },
        }
    }

    #[tokio::test]
    async fn seal_then_open_round_trips_the_snapshot() {
        let snapshot = sample_snapshot();
        let bytes = seal(&snapshot, STRONG, &[]).await.unwrap();
        let reopened = open(&bytes, STRONG).await.unwrap();
        assert_eq!(reopened, snapshot);
        // The asset bytes survive exactly, which is the whole reason the derived
        // favicon set is archived rather than re-derived.
        assert_eq!(reopened.sections.branding_assets[0].data, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn a_wrong_passphrase_is_refused_rather_than_guessed_at() {
        let bytes = seal(&sample_snapshot(), STRONG, &[]).await.unwrap();
        let err = open(&bytes, "another-long-enough-passphrase-9")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("wrong passphrase, or the archive is damaged"),
            "{err}"
        );
    }

    /// AES-GCM authenticates the ciphertext, so one flipped byte must fail the
    /// open outright rather than yield partial plaintext.
    #[tokio::test]
    async fn a_damaged_archive_does_not_decrypt() {
        let bytes = seal(&sample_snapshot(), STRONG, &[]).await.unwrap();
        let mut envelope: Envelope = serde_json::from_slice(&bytes).unwrap();
        let mut ciphertext = BASE64.decode(envelope.ciphertext.as_bytes()).unwrap();
        ciphertext[0] ^= 0xFF;
        envelope.ciphertext = BASE64.encode(&ciphertext);
        let damaged = serde_json::to_vec(&envelope).unwrap();

        let err = open(&damaged, STRONG).await.unwrap_err().to_string();
        assert!(
            err.contains("wrong passphrase, or the archive is damaged"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_unknown_format_version_is_refused_by_name() {
        let bytes = seal(&sample_snapshot(), STRONG, &[]).await.unwrap();
        let mut envelope: Envelope = serde_json::from_slice(&bytes).unwrap();
        envelope.format_version = 99;
        let future = serde_json::to_vec(&envelope).unwrap();

        let err = open(&future, STRONG).await.unwrap_err().to_string();
        assert!(err.contains("format version 99"), "{err}");
        assert!(err.contains("reads version 1"), "{err}");
    }

    #[tokio::test]
    async fn a_passphrase_one_character_short_is_refused_on_length() {
        // 15 characters, and strong enough that only the length rule can reject
        // it: the two rules must stay distinguishable in the message.
        let fifteen = "qu4rtz-mBlem9z";
        assert_eq!(fifteen.chars().count(), 14);
        let fifteen = format!("{fifteen}K");
        assert_eq!(fifteen.chars().count(), 15);

        let err = seal(&sample_snapshot(), &fifteen, &[])
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("15 characters"), "{err}");
        assert!(err.contains("at least 16"), "{err}");
        assert!(!err.contains(&fifteen), "the message echoed the passphrase");
    }

    #[tokio::test]
    async fn a_long_but_guessable_passphrase_is_refused_on_strength() {
        let weak = "passwordpasswordpassword";
        assert!(weak.chars().count() >= MIN_PASSPHRASE_CHARS);

        let err = seal(&sample_snapshot(), weak, &[])
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("guessability"), "{err}");
        assert!(!err.contains(weak), "the message echoed the passphrase");
    }

    #[tokio::test]
    async fn a_strong_passphrase_is_accepted() {
        assert!(seal(&sample_snapshot(), STRONG, &[]).await.is_ok());
    }

    /// The deployment's own name is the first thing an attacker holding the
    /// archive tries, so it is fed to zxcvbn as a user input rather than left to
    /// score as an ordinary word.
    #[tokio::test]
    async fn the_brand_name_does_not_make_a_passphrase_strong() {
        let brand = "Bunyipshire Managed Services";
        let passphrase = "Bunyipshire Managed Services";
        assert!(passphrase.chars().count() >= MIN_PASSPHRASE_CHARS);
        assert!(
            seal(&sample_snapshot(), passphrase, &[brand])
                .await
                .is_err(),
            "a passphrase that is exactly the brand name was accepted"
        );
    }

    /// Replace semantics, on the pure diff: a key only the target has is
    /// DELETED, a changed row is UPDATED, an unchanged one is left alone, and an
    /// absent section produces no plan entry at all.
    #[test]
    fn the_plan_replaces_rather_than_merges() {
        let target = BTreeMap::from([
            ("keep".to_string(), "{\"v\":1}".to_string()),
            ("change".to_string(), "{\"v\":1}".to_string()),
            ("target-only".to_string(), "{\"v\":1}".to_string()),
        ]);
        let archive = BTreeMap::from([
            ("keep".to_string(), "{\"v\":1}".to_string()),
            ("change".to_string(), "{\"v\":2}".to_string()),
            ("archive-only".to_string(), "{\"v\":1}".to_string()),
        ]);

        let plan = plan_table("applications", &target, &archive, APPLICATION_CASCADES);
        assert_eq!(plan.inserted, vec!["archive-only".to_string()]);
        assert_eq!(plan.updated, vec!["change".to_string()]);
        assert_eq!(plan.deleted.len(), 1);
        assert_eq!(plan.deleted[0].key, "target-only");
        // A delete is never silent about its blast radius.
        assert!(plan.deleted[0]
            .cascades
            .contains(&"application_docs".to_string()));
        assert!(!plan.is_unchanged());

        // "keep" appears in none of the three buckets: an unchanged row is not
        // rewritten, so its id and its cascaded children survive the import.
        assert!(!plan.inserted.contains(&"keep".to_string()));
        assert!(!plan.updated.contains(&"keep".to_string()));
        assert!(plan.deleted.iter().all(|d| d.key != "keep"));

        // An absent section is untouched: both sides empty is no work at all,
        // which is what "section absent from the archive" reduces to.
        let untouched = plan_table("oauth_clients", &BTreeMap::new(), &BTreeMap::new(), &[]);
        assert!(untouched.is_unchanged());
    }

    /// A singleton reports the columns that move and nothing else.
    #[test]
    fn a_singleton_plan_names_only_the_changed_columns() {
        let target = BrandingSection {
            brand_name: "Old".to_string(),
            tagline: "Same".to_string(),
            ..BrandingSection::default()
        };
        let archive = BrandingSection {
            brand_name: "New".to_string(),
            tagline: "Same".to_string(),
            ..BrandingSection::default()
        };
        let plan = plan_singleton("branding", &target, &archive);
        assert_eq!(plan.changed_columns, vec!["brand_name".to_string()]);
        assert!(plan_singleton("branding", &archive, &archive).is_unchanged());
    }

    /// Every governed-secret outcome is reachable, and the value never leaves
    /// the comparison.
    #[test]
    fn every_governed_secret_outcome_occurs() {
        assert_eq!(
            plan_secret("SMTP_PASSWORD", None, Some("new")).outcome,
            SecretOutcome::Set
        );
        assert_eq!(
            plan_secret("SMTP_PASSWORD", Some("old"), Some("new")).outcome,
            SecretOutcome::Set
        );
        assert_eq!(
            plan_secret("STRIPE_SECRET_KEY", Some("old"), None).outcome,
            SecretOutcome::Cleared
        );
        assert_eq!(
            plan_secret("STRIPE_WEBHOOK_SECRET", Some("same"), Some("same")).outcome,
            SecretOutcome::Unchanged
        );
        assert_eq!(
            plan_secret("SUPPORT_IMAP_PASSWORD", None, None).outcome,
            SecretOutcome::Unchanged
        );
    }

    /// A plan is printed into a terminal, a CI log and a screenshot. It carries
    /// names, keys and counts, never a value: the archive exists precisely so
    /// the values live in one encrypted file.
    #[test]
    fn a_rendered_plan_carries_no_setting_value() {
        let plan = ImportPlan {
            schema_version: 20260101000001,
            singletons: vec![plan_singleton(
                "branding",
                &BrandingSection {
                    brand_name: "OldSecretBrand".to_string(),
                    ..BrandingSection::default()
                },
                &BrandingSection {
                    brand_name: "NewSecretBrand".to_string(),
                    ..BrandingSection::default()
                },
            )],
            tables: vec![plan_table(
                "branding_assets",
                &BTreeMap::new(),
                &BTreeMap::from([("mark".to_string(), "{\"data\":\"AQIDBA==\"}".to_string())]),
                &[],
            )],
            secrets: vec![plan_secret("SMTP_PASSWORD", None, Some("hunter2"))],
            secrets_provider: "database".to_string(),
        };
        let rendered = render_plan(&plan);
        for value in ["OldSecretBrand", "NewSecretBrand", "hunter2", "AQIDBA=="] {
            assert!(
                !rendered.contains(value),
                "the rendered plan leaked {value}:\n{rendered}"
            );
        }
        assert!(rendered.contains("brand_name"));
        assert!(rendered.contains("SMTP_PASSWORD: set"));
    }

    /// Each table declares its columns exactly once across the two lists. The
    /// integration test checks them against the live schema; this one catches
    /// the typo that would make that check pass vacuously.
    #[test]
    fn no_column_is_both_archived_and_excluded() {
        for table in ARCHIVED_TABLES {
            for column in table.archived {
                assert!(
                    !table.excluded.contains(column),
                    "{}.{column} is listed as both archived and excluded",
                    table.table
                );
            }
            let mut seen = BTreeSet::new();
            for column in table.archived.iter().chain(table.excluded.iter()) {
                assert!(
                    seen.insert(*column),
                    "{}.{column} is listed twice",
                    table.table
                );
            }
        }
    }

    #[test]
    fn a_passphrase_file_loses_at_most_one_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pass");
        std::fs::write(&path, "my passphrase\n").unwrap();
        assert_eq!(
            read_passphrase(path.to_str().unwrap()).unwrap(),
            "my passphrase"
        );

        std::fs::write(&path, "my passphrase\r\n").unwrap();
        assert_eq!(
            read_passphrase(path.to_str().unwrap()).unwrap(),
            "my passphrase"
        );

        // A second newline is part of the passphrase, not framing.
        std::fs::write(&path, "my passphrase\n\n").unwrap();
        assert_eq!(
            read_passphrase(path.to_str().unwrap()).unwrap(),
            "my passphrase\n"
        );
    }

    #[test]
    fn the_output_path_is_never_overwritten_and_is_created_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.json");
        let path = path.to_str().unwrap();

        write_archive(path, b"{}").unwrap();
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the archive was created world readable");

        let err = write_archive(path, b"{}").unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");

        // stdout is shared with the log lines, so it is never an archive target.
        assert!(write_archive("-", b"{}").is_err());
        assert!(read_archive("-").is_err());
    }
}
