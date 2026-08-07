//! File-driven seed data: canonical schema, validation, and safety gates (PSA-50).
//!
//! Seed data lives as a JSON file, not in code. This module is the foundation
//! the loader and `seed` CLI build on: it defines the canonical schema, parses
//! and validates a file (structure plus referential integrity), derives the
//! reset scope from the file's declared `owns`, and enforces the non-production
//! guard. The DB loader that turns a validated [`SeedFile`] into rows through
//! the domain repositories lands on top of this.
//!
//! Two safety invariants are enforced here, before any row is written:
//!   - Every seeded user (and feedback-author) email is covered by the file's
//!     declared `owns` scope - its email domains plus explicit emails,
//!     defaulting to the reserved [`SEED_EMAIL_DOMAIN`] when a file omits it
//!     (PSA-56). A reset reclaims exactly what the file owns, so no file can
//!     touch another's rows. This is weaker than the pre-PSA-56 hardcoded
//!     reserved domain: a file may own a real domain (the E2E accounts own
//!     `@a8n.run`), so reset safety now rests on the non-production guard plus
//!     files being trusted and scoping real domains via explicit emails.
//!   - Import/reset refuse to run against a production (or unset) environment.

use std::collections::HashSet;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::models::entitlement::entitlement_source;
use crate::models::{
    CreateApplication, CreateApplicationGroup, CreateFeedback, CreateUser, MembershipStatus,
    MembershipTier, UserRole,
};
use crate::repositories::{
    ApplicationGroupRepository, ApplicationRepository, EntitlementRepository, FeedbackRepository,
    UserRepository,
};
use crate::services::PasswordService;

/// Canonical schema version this build understands. A file declaring any other
/// version is rejected rather than silently mis-read.
pub const SEED_SCHEMA_VERSION: u32 = 1;

/// Reserved email domain every seeded user must use. It is the reset key: a
/// reset deletes exactly the rows whose email sits under this domain, so real
/// accounts are structurally out of reach. Obviously-fake, and needs no schema
/// change (chosen over a `seed_tag` column, PSA-50).
pub const SEED_EMAIL_DOMAIN: &str = "demo.psa-systems.test";

/// Accepted (lowercase) values for the enum-backed string fields. Validation
/// rejects anything outside these sets so a template typo (`amdin`, `actve`)
/// fails loudly instead of silently seeding wrong-but-valid data - the loader's
/// string -> enum mapping otherwise falls back to a default. Kept in lock-step
/// with `UserRole`, `MembershipStatus`, and `MembershipTier`.
const VALID_ROLES: [&str; 2] = ["subscriber", "admin"];
const VALID_STATUSES: [&str; 5] = ["none", "active", "past_due", "canceled", "grace_period"];
const VALID_TIERS: [&str; 4] = ["free", "standard", "early_adopter", "lifetime"];

/// A named seed template compiled into the binary (PSA-57), so the admin
/// first-run setup can offer it by name without a filesystem path.
pub struct SeedTemplate {
    pub name: &'static str,
    pub description: &'static str,
    pub json: &'static str,
}

/// The template library. Each `json` is a committed file under `seed/`, embedded
/// via `include_str!`; a test asserts every one parses + validates.
pub const SEED_TEMPLATES: &[SeedTemplate] = &[
    SeedTemplate {
        name: "demo-msp",
        description: "Full MSP demo: ~42 users across tiers, the app catalog with groups, and a support inbox.",
        json: include_str!("../seed/demo-msp.json"),
    },
    SeedTemplate {
        name: "minimal",
        description: "Minimal baseline: the app catalog plus a few users, no bulk volume.",
        json: include_str!("../seed/minimal.json"),
    },
];

/// Look up a template by name.
pub fn find_template(name: &str) -> Option<&'static SeedTemplate> {
    SEED_TEMPLATES.iter().find(|t| t.name == name)
}

/// A parsed seed file. Section order is irrelevant; the loader resolves
/// cross-references (app -> group, entitlement -> user/app) by slug/email.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedFile {
    pub version: u32,
    /// Password applied to any user that does not carry its own. Hashed by the
    /// loader via the real `PasswordService`; never stored pre-hashed.
    #[serde(default)]
    pub default_password: Option<String>,
    /// Email domains and explicit emails this file is allowed to create and a
    /// reset may reclaim (PSA-56). When omitted it defaults to the reserved seed
    /// domain (back-compat). Every user and feedback-author email must be
    /// covered by this scope, so a reset deletes exactly what the file created
    /// and one file can never reclaim another's rows.
    #[serde(default)]
    pub owns: SeedOwns,
    #[serde(default)]
    pub application_groups: Vec<SeedGroup>,
    #[serde(default)]
    pub applications: Vec<SeedApp>,
    #[serde(default)]
    pub users: Vec<SeedUser>,
    #[serde(default)]
    pub entitlements: Vec<SeedEntitlement>,
    #[serde(default)]
    pub feedback: Vec<SeedFeedback>,
}

/// The reclaim scope a seed file declares (PSA-56): the email domains and the
/// explicit emails it owns. `covers` decides whether an email belongs to the
/// file, and a reset targets exactly this set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedOwns {
    /// Owned email domains, WITHOUT the leading `@` (e.g. `demo.psa-systems.test`).
    #[serde(default)]
    pub domains: Vec<String>,
    /// Owned individual emails, for files (like the E2E accounts) that seed a
    /// fixed set of addresses rather than a whole domain.
    #[serde(default)]
    pub emails: Vec<String>,
}

impl SeedOwns {
    /// The default scope when a file declares no `owns`: the reserved seed
    /// domain, preserving pre-PSA-56 behaviour for files that omit the block.
    pub fn reserved() -> Self {
        SeedOwns {
            domains: vec![SEED_EMAIL_DOMAIN.to_string()],
            emails: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.emails.is_empty()
    }

    /// True when `email` sits under an owned domain or matches an owned email
    /// (both case-insensitive). Domain matching anchors on `@` so a sibling
    /// domain (`x@evil-demo.psa-systems.test`) can never sneak in.
    pub fn covers(&self, email: &str) -> bool {
        let lower = email.to_ascii_lowercase();
        self.domains
            .iter()
            .any(|d| lower.ends_with(&format!("@{}", d.to_ascii_lowercase())))
            || self.emails.iter().any(|e| e.to_ascii_lowercase() == lower)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedGroup {
    pub slug: String,
    pub name: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub sort_order: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedApp {
    pub slug: String,
    pub name: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub container_name: Option<String>,
    /// Slug of an `application_groups` entry in the same file, if this app
    /// belongs to a group.
    #[serde(default)]
    pub group_slug: Option<String>,
    /// Whether the app is entitlement-gated (only granted users see it).
    #[serde(default)]
    pub restricted: bool,
    #[serde(default)]
    pub is_hosted: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedUser {
    pub email: String,
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    /// Per-user override of `default_password`.
    #[serde(default)]
    pub password: Option<String>,
    /// Name of an environment variable to read the password from at load time
    /// (honouring the `_FILE` convention, like `secret_env`), so a secret stays
    /// out of the committed file (PSA-56). Takes precedence over `password` /
    /// `default_password` when set. Used by the E2E template.
    #[serde(default)]
    pub password_env: Option<String>,
    #[serde(default)]
    pub membership: SeedMembership,
}

/// Membership state applied to a seeded user as DB state (no Stripe objects).
/// Strings here are validated into the domain enums by the loader, so the
/// schema stays decoupled from the enum variants.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedMembership {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub lifetime: bool,
    #[serde(default)]
    pub price_locked: bool,
    #[serde(default)]
    pub locked_price_amount: Option<i32>,
    #[serde(default)]
    pub trial_ends_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedEntitlement {
    pub user_email: String,
    pub app_slug: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedFeedback {
    #[serde(default)]
    pub name: Option<String>,
    /// Required by validation and must be covered by the file's `owns` scope,
    /// so a reset can reclaim it (an email-less row would leak).
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    pub message: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub is_spam: bool,
    #[serde(default)]
    pub page_path: Option<String>,
    /// Optional admin response, so the template can seed already-answered items.
    #[serde(default)]
    pub response: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

fn default_role() -> String {
    "subscriber".to_string()
}

/// True when `email` sits under the reserved seed domain (case-insensitive).
/// This is the reserved-domain default only; validation and reset key on the
/// file's declared `owns` scope ([`SeedOwns::covers`]) since PSA-56, so this is
/// retained for the default / back-compat path.
pub fn is_seed_email(email: &str) -> bool {
    email
        .to_ascii_lowercase()
        .ends_with(&format!("@{SEED_EMAIL_DOMAIN}"))
}

/// Refuse to run against anything that could be production. Mirrors the
/// `bunyip-e2e-bootstrap` gate: an explicit `allow` flag AND a non-production
/// environment. An empty/unset environment is treated as production and
/// blocked (callers resolve unset to "production" upstream).
pub fn seed_guard(environment: &str, allow: bool) -> Result<(), SeedError> {
    if !allow {
        return Err(SeedError::Guard(
            "refusing to run: pass the explicit allow flag to confirm this is a non-production environment".into(),
        ));
    }
    let env = environment.trim();
    let prod_like = env.is_empty()
        || env.eq_ignore_ascii_case("production")
        || env.eq_ignore_ascii_case("prod");
    if prod_like {
        return Err(SeedError::Guard(format!(
            "refusing to run: ENVIRONMENT is '{environment}' (production-like or unset); seeding is non-production only"
        )));
    }
    Ok(())
}

/// Parse and validate a seed file. Returns the [`SeedFile`] only when the
/// version matches and every structural + referential invariant holds, so the
/// loader can insert without re-checking.
pub fn parse(json: &str) -> Result<SeedFile, SeedError> {
    let file: SeedFile = serde_json::from_str(json).map_err(SeedError::Parse)?;
    if file.version != SEED_SCHEMA_VERSION {
        return Err(SeedError::UnsupportedVersion {
            found: file.version,
            expected: SEED_SCHEMA_VERSION,
        });
    }
    file.validate()?;
    Ok(file)
}

impl SeedFile {
    /// The file's declared reclaim scope, or the reserved-domain default when
    /// it declares none (PSA-56 back-compat). Validation, the loader's
    /// feedback-clear, and reset all key on this.
    pub fn effective_owns(&self) -> SeedOwns {
        if self.owns.is_empty() {
            SeedOwns::reserved()
        } else {
            self.owns.clone()
        }
    }

    /// Structural + referential integrity. Collects every problem so the
    /// operator sees them all at once, not one per run.
    pub fn validate(&self) -> Result<(), SeedError> {
        let mut errs: Vec<String> = Vec::new();

        // Unique slugs / emails (case-insensitive for emails).
        let mut group_slugs: HashSet<&str> = HashSet::new();
        for g in &self.application_groups {
            if !group_slugs.insert(g.slug.as_str()) {
                errs.push(format!("duplicate application_group slug '{}'", g.slug));
            }
        }
        let mut app_slugs: HashSet<&str> = HashSet::new();
        for a in &self.applications {
            if !app_slugs.insert(a.slug.as_str()) {
                errs.push(format!("duplicate application slug '{}'", a.slug));
            }
            if let Some(gs) = &a.group_slug {
                if !group_slugs.contains(gs.as_str()) {
                    errs.push(format!(
                        "application '{}' references unknown group_slug '{}'",
                        a.slug, gs
                    ));
                }
            }
        }

        let owns = self.effective_owns();
        // `owns.domains` may only name the reserved domain: a whole-domain reset
        // is refused for any other (real) domain, so a real domain must be
        // scoped via `owns.emails`. Enforce it here so a file fails at parse
        // rather than validating and then failing at load (PSA-56 review).
        for d in &owns.domains {
            if !domain_reset_allowed(d) {
                errs.push(format!(
                    "owns.domains may only contain the reserved domain '{SEED_EMAIL_DOMAIN}'; scope a real domain like '{d}' via owns.emails so a reset cannot reclaim every account under it"
                ));
            }
        }
        let mut user_emails: HashSet<String> = HashSet::new();
        for u in &self.users {
            let lower = u.email.to_ascii_lowercase();
            if !owns.covers(&u.email) {
                errs.push(format!(
                    "user '{}' is not covered by the file's `owns` scope (domains {:?}, emails {:?}); a reset could not reclaim it",
                    u.email, owns.domains, owns.emails
                ));
            }
            if !user_emails.insert(lower) {
                errs.push(format!("duplicate user email '{}'", u.email));
            }
            // A `password_env` reference, when present, must name a variable.
            if let Some(var) = &u.password_env {
                if var.trim().is_empty() {
                    errs.push(format!("user '{}' has an empty password_env", u.email));
                }
            }
            // Reject enum typos loudly (the loader would otherwise map an unknown
            // value to a silent default: subscriber / none / free).
            if !VALID_ROLES.contains(&u.role.to_ascii_lowercase().as_str()) {
                errs.push(format!(
                    "user '{}' has unknown role '{}' (expected one of {VALID_ROLES:?})",
                    u.email, u.role
                ));
            }
            if let Some(status) = &u.membership.status {
                if !VALID_STATUSES.contains(&status.to_ascii_lowercase().as_str()) {
                    errs.push(format!(
                        "user '{}' has unknown membership status '{}' (expected one of {VALID_STATUSES:?})",
                        u.email, status
                    ));
                }
            }
            if let Some(tier) = &u.membership.tier {
                if !VALID_TIERS.contains(&tier.to_ascii_lowercase().as_str()) {
                    errs.push(format!(
                        "user '{}' has unknown membership tier '{}' (expected one of {VALID_TIERS:?})",
                        u.email, tier
                    ));
                }
            }
        }

        // Entitlements must reference a user and an app declared in this file.
        for e in &self.entitlements {
            if !user_emails.contains(&e.user_email.to_ascii_lowercase()) {
                errs.push(format!(
                    "entitlement references unknown user_email '{}'",
                    e.user_email
                ));
            }
            if !app_slugs.contains(e.app_slug.as_str()) {
                errs.push(format!(
                    "entitlement references unknown app_slug '{}'",
                    e.app_slug
                ));
            }
        }

        // Feedback must carry a message and a seed-owned author email. The email
        // is REQUIRED (not just validated when present): the reset and the
        // idempotent re-import clear seed feedback by that email, so a row with
        // no email would leak on reset and duplicate on every re-import.
        for (i, f) in self.feedback.iter().enumerate() {
            if f.message.trim().is_empty() {
                errs.push(format!("feedback[{i}] has an empty message"));
            }
            match &f.email {
                None => errs.push(format!(
                    "feedback[{i}] has no author email; seed feedback must carry an owned email so a reset can reclaim it"
                )),
                Some(email) if !owns.covers(email) => errs.push(format!(
                    "feedback[{i}] author email '{email}' is not covered by the file's `owns` scope; a reset could not reclaim it"
                )),
                Some(_) => {}
            }
        }

        if errs.is_empty() {
            Ok(())
        } else {
            Err(SeedError::Validation(errs))
        }
    }
}

/// Errors from parsing, versioning, validating, or guarding a seed run.
#[derive(Debug)]
pub enum SeedError {
    Parse(serde_json::Error),
    UnsupportedVersion { found: u32, expected: u32 },
    Validation(Vec<String>),
    Guard(String),
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeedError::Parse(e) => write!(f, "seed file is not valid JSON: {e}"),
            SeedError::UnsupportedVersion { found, expected } => write!(
                f,
                "seed file version {found} is not supported (this build expects version {expected})"
            ),
            SeedError::Validation(errs) => {
                writeln!(f, "seed file failed validation ({} problems):", errs.len())?;
                for e in errs {
                    writeln!(f, "  - {e}")?;
                }
                Ok(())
            }
            SeedError::Guard(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for SeedError {}

// ===========================================================================
// Loader (PSA-50): map a validated SeedFile to rows via the domain
// repositories. All writes go through the repository layer, so seeding shares
// the same validation/hashing path a future customer-data import will use.
// ===========================================================================

/// Per-section counts from a load, for the CLI to report.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoadSummary {
    pub groups: usize,
    pub applications: usize,
    pub users: usize,
    pub entitlements: usize,
    pub feedback: usize,
}

/// Rows removed by a reset.
#[derive(Debug, Default, Clone, Copy)]
pub struct ResetSummary {
    pub users: u64,
    pub feedback: u64,
}

/// Failures while loading a validated file into the database.
#[derive(Debug)]
pub enum LoadError {
    /// A user carries no password and the file sets no `default_password`.
    MissingPassword(String),
    /// Password hashing failed.
    Hash(String),
    /// A cross-reference did not resolve against the live DB (validation catches
    /// intra-file references; this guards against races/partial state).
    Reference(String),
    /// A membership trial timestamp was not valid RFC3339.
    BadTimestamp {
        value: String,
        source: String,
    },
    /// A reset targeted a whole non-reserved domain, which the guardrail refuses
    /// (real domains must be reset via explicit `owns.emails`, PSA-56).
    UnsafeReset(String),
    /// A user's `password_env` names an environment variable that is unset.
    PasswordEnvUnset {
        email: String,
        var: String,
    },
    /// A user's resolved password was empty (would seed a broken account).
    EmptyPassword(String),
    Db(AppError),
}

impl From<AppError> for LoadError {
    fn from(e: AppError) -> Self {
        LoadError::Db(e)
    }
}

// DEV-516: the shared dunite-feedback repository returns `sqlx::Error`; the seed
// path uses `?` into `LoadError`, so route it through the existing `AppError`
// (which already maps `sqlx::Error`) to keep those call sites unchanged.
impl From<sqlx::Error> for LoadError {
    fn from(e: sqlx::Error) -> Self {
        LoadError::Db(AppError::from(e))
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::MissingPassword(email) => write!(
                f,
                "user '{email}' has no password and the file sets no default_password"
            ),
            LoadError::Hash(e) => write!(f, "failed to hash a seed password: {e}"),
            LoadError::Reference(m) => write!(f, "unresolved reference: {m}"),
            LoadError::BadTimestamp { value, source } => {
                write!(f, "invalid RFC3339 timestamp '{value}' ({source})")
            }
            LoadError::UnsafeReset(m) => write!(f, "{m}"),
            LoadError::PasswordEnvUnset { email, var } => write!(
                f,
                "user '{email}' sources its password from env var '{var}', which is unset"
            ),
            LoadError::EmptyPassword(email) => {
                write!(f, "user '{email}' resolved an empty password")
            }
            LoadError::Db(e) => write!(f, "database error: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}

fn parse_role(role: &str) -> UserRole {
    if role.eq_ignore_ascii_case("admin") {
        UserRole::Admin
    } else {
        UserRole::Subscriber
    }
}

/// Map a template tier string to a [`MembershipTier`]. `lifetime = true`
/// forces `Lifetime`; an unknown/absent tier falls back to `Free`.
fn parse_tier(tier: Option<&str>, lifetime: bool) -> MembershipTier {
    if lifetime {
        return MembershipTier::Lifetime;
    }
    match tier.map(str::to_ascii_lowercase).as_deref() {
        Some("lifetime") => MembershipTier::Lifetime,
        Some("early_adopter") => MembershipTier::EarlyAdopter,
        Some("standard") => MembershipTier::Standard,
        _ => MembershipTier::Free,
    }
}

fn parse_ts(value: &Option<String>, source: &str) -> Result<Option<DateTime<Utc>>, LoadError> {
    match value {
        None => Ok(None),
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|dt| Some(dt.with_timezone(&Utc)))
            .map_err(|_| LoadError::BadTimestamp {
                value: s.clone(),
                source: source.to_string(),
            }),
    }
}

/// Resolve a seed user's password: an env-var reference (a secret, `_FILE`-aware
/// via `secret_env`) wins, then a literal per-user password, then the file
/// default. Rejects an unset env var and an empty resolved value so a
/// misconfigured secret fails loud instead of seeding a broken, empty-password
/// account (PSA-56 review). Trimming happens at the hash call site.
fn resolve_password(user: &SeedUser, default_password: Option<&str>) -> Result<String, LoadError> {
    let raw = match &user.password_env {
        Some(var) => crate::config::secret_env(var).ok_or_else(|| LoadError::PasswordEnvUnset {
            email: user.email.clone(),
            var: var.clone(),
        })?,
        None => user
            .password
            .clone()
            .or_else(|| default_password.map(str::to_string))
            .ok_or_else(|| LoadError::MissingPassword(user.email.clone()))?,
    };
    if raw.trim().is_empty() {
        return Err(LoadError::EmptyPassword(user.email.clone()));
    }
    Ok(raw)
}

/// Load a validated [`SeedFile`] into the database through the domain
/// repositories. Idempotent: users are upserted by email, groups and
/// applications are created-if-absent, entitlement grants are upserts, and seed
/// feedback is cleared (by the reserved domain) before re-insert. Catalog
/// groups/applications are shared config and are never removed by a reset.
pub async fn load(pool: &PgPool, file: &SeedFile) -> Result<LoadSummary, LoadError> {
    let mut summary = LoadSummary::default();
    let hasher = PasswordService::new();

    // 1. Application groups (create-if-absent).
    for g in &file.application_groups {
        if ApplicationGroupRepository::find_by_slug(pool, &g.slug)
            .await?
            .is_none()
        {
            ApplicationGroupRepository::create(
                pool,
                &CreateApplicationGroup {
                    name: g.name.clone(),
                    slug: g.slug.clone(),
                    display_name: g.display_name.clone(),
                    description: g.description.clone(),
                    icon_url: g.icon_url.clone(),
                    sort_order: g.sort_order,
                },
            )
            .await?;
        }
        summary.groups += 1;
    }

    // 2. Applications (create-if-absent), then link each to its group.
    for a in &file.applications {
        let app_id = match ApplicationRepository::find_by_slug(pool, &a.slug).await? {
            Some(app) => app.id,
            None => {
                ApplicationRepository::create(
                    pool,
                    &CreateApplication {
                        name: a.name.clone(),
                        slug: a.slug.clone(),
                        display_name: a.display_name.clone(),
                        description: a.description.clone(),
                        icon_url: a.icon_url.clone(),
                        container_name: a.container_name.clone().unwrap_or_else(|| a.slug.clone()),
                        health_check_url: None,
                        subdomain: None,
                        webhook_url: None,
                        version: None,
                        source_code_url: None,
                        release_notes_url: None,
                        is_hosted: a.is_hosted,
                        forgejo_owner: None,
                        forgejo_repo: None,
                        forgejo_package: None,
                        pinned_release_tag: None,
                        artifact_source: None,
                        oci_image_owner: None,
                        oci_image_name: None,
                        pinned_image_tag: None,
                    },
                )
                .await?
                .id
            }
        };
        if let Some(group_slug) = &a.group_slug {
            let group = ApplicationGroupRepository::find_by_slug(pool, group_slug)
                .await?
                .ok_or_else(|| {
                    LoadError::Reference(format!(
                        "group_slug '{group_slug}' not found for app '{}'",
                        a.slug
                    ))
                })?;
            ApplicationRepository::set_group(pool, app_id, Some(group.id)).await?;
        }
        // The `restricted` flag is not applied here yet (its setter is a
        // handler-level concern); entitlement grants below still make a
        // restricted app visible to its granted users.
        summary.applications += 1;
    }

    // 3. Users (upsert by email), then apply verified/profile/membership state.
    for u in &file.users {
        // Resolve the password: an env-var reference (a secret, `_FILE`-aware
        // via secret_env) wins, then a literal per-user password, then the file
        // default. Trimmed before hashing so a newline from a secret store does
        // not diverge from what the login path sends (PSA-56).
        let raw_password = resolve_password(u, file.default_password.as_deref())?;
        let hash = hasher
            .hash(raw_password.trim())
            .map_err(|e| LoadError::Hash(e.to_string()))?;
        let role = parse_role(&u.role);

        let user = match UserRepository::find_by_email(pool, &u.email).await? {
            Some(existing) => {
                UserRepository::update_password(pool, existing.id, &hash).await?;
                UserRepository::update_role(pool, existing.id, role.as_str()).await?;
                existing
            }
            None => {
                UserRepository::create(
                    pool,
                    CreateUser {
                        email: u.email.clone(),
                        password_hash: Some(hash),
                        role,
                    },
                )
                .await?
            }
        };

        if u.verified {
            UserRepository::set_email_verified(pool, user.id).await?;
        }
        if u.first_name.is_some() || u.last_name.is_some() || u.phone.is_some() {
            UserRepository::update_profile(
                pool,
                user.id,
                u.first_name.as_deref(),
                u.last_name.as_deref(),
                u.phone.as_deref(),
            )
            .await?;
        }
        let status = MembershipStatus::from(u.membership.status.as_deref().unwrap_or("none"));
        let tier = parse_tier(u.membership.tier.as_deref(), u.membership.lifetime);
        let trial = parse_ts(&u.membership.trial_ends_at, "membership.trial_ends_at")?;
        UserRepository::apply_seed_membership(
            pool,
            user.id,
            status,
            &tier,
            u.membership.lifetime,
            u.membership.price_locked,
            u.membership.locked_price_amount,
            trial,
        )
        .await?;
        summary.users += 1;
    }

    // 4. Entitlements (upsert grants).
    for e in &file.entitlements {
        let user = UserRepository::find_by_email(pool, &e.user_email)
            .await?
            .ok_or_else(|| {
                LoadError::Reference(format!("entitlement user '{}' not found", e.user_email))
            })?;
        let app = ApplicationRepository::find_by_slug(pool, &e.app_slug)
            .await?
            .ok_or_else(|| {
                LoadError::Reference(format!("entitlement app '{}' not found", e.app_slug))
            })?;
        EntitlementRepository::grant(pool, user.id, app.id, None, entitlement_source::SEED).await?;
        summary.entitlements += 1;
    }

    // 5. Feedback: clear prior owned feedback, then insert fresh, so re-import
    //    stays idempotent (feedback has no natural key).
    delete_owned_feedback(pool, &file.effective_owns()).await?;
    for fb in &file.feedback {
        FeedbackRepository::create(
            pool,
            CreateFeedback {
                name: fb.name.clone(),
                email: fb.email.clone(),
                subject: fb.subject.clone(),
                tags: fb.tags.clone(),
                message: fb.message.clone(),
                page_path: fb.page_path.clone(),
                is_spam: fb.is_spam,
                // Seeded feedback has no live request; BUNYIP-411 metadata is
                // only captured on real submissions.
                submitter_ip: None,
                user_agent: None,
            },
        )
        .await?;
        summary.feedback += 1;
    }

    Ok(summary)
}

/// Whether a domain may be reset by a whole-domain delete. Only the reserved
/// seed domain qualifies; any other (potentially real) domain must be reset via
/// explicit `owns.emails`, so a file can never delete every account under a real
/// domain like `a8n.run` (PSA-56). The E2E template owns its two accounts as
/// explicit emails precisely for this reason.
fn domain_reset_allowed(domain: &str) -> bool {
    domain.eq_ignore_ascii_case(SEED_EMAIL_DOMAIN)
}

/// Delete the users an `owns` scope covers (guardrailed): whole-domain delete
/// for the reserved domain, exact-email delete for explicit emails. A
/// non-reserved domain is refused. Returns the rows removed.
async fn delete_owned_users(pool: &PgPool, owns: &SeedOwns) -> Result<u64, LoadError> {
    let mut removed = 0u64;
    for domain in &owns.domains {
        if !domain_reset_allowed(domain) {
            return Err(LoadError::UnsafeReset(format!(
                "refusing to reset the whole domain '{domain}': only '{SEED_EMAIL_DOMAIN}' may be reset by domain; scope real domains via explicit owns.emails"
            )));
        }
        removed += UserRepository::hard_delete_seed_users(pool, domain).await?;
    }
    for email in &owns.emails {
        removed += UserRepository::hard_delete_by_email(pool, email).await?;
    }
    Ok(removed)
}

/// Delete the feedback an `owns` scope covers, with the same guardrail as
/// [`delete_owned_users`]. Used by both reset and the loader's idempotent
/// feedback-clear.
async fn delete_owned_feedback(pool: &PgPool, owns: &SeedOwns) -> Result<u64, LoadError> {
    let mut removed = 0u64;
    for domain in &owns.domains {
        if !domain_reset_allowed(domain) {
            return Err(LoadError::UnsafeReset(format!(
                "refusing to clear feedback for the whole domain '{domain}': only '{SEED_EMAIL_DOMAIN}' may be cleared by domain; scope real domains via explicit owns.emails"
            )));
        }
        removed += FeedbackRepository::delete_seed_by_domain(pool, domain).await?;
    }
    for email in &owns.emails {
        removed += FeedbackRepository::delete_by_email(pool, email).await?;
    }
    Ok(removed)
}

/// Remove all seed data an `owns` scope reclaims: the seed users (with their
/// cascaded dependencies) and their feedback. Catalog groups/applications are
/// shared config and are left intact - deleting a catalog app could orphan a
/// real user's entitlement. Guardrailed: a whole-domain reset is only allowed
/// for the reserved domain (PSA-56).
pub async fn reset(pool: &PgPool, owns: &SeedOwns) -> Result<ResetSummary, LoadError> {
    let feedback = delete_owned_feedback(pool, owns).await?;
    let users = delete_owned_users(pool, owns).await?;
    Ok(ResetSummary { users, feedback })
}

/// Serialize the current seed-owned data back into a [`SeedFile`] (PSA-52
/// export): users and feedback under the reserved domain, plus the full catalog
/// of groups/applications (catalog is shared config, not email-scoped).
///
/// Password hashes are NEVER emitted - the schema has no field for them - so a
/// re-import assigns `default_password`; the export sets a placeholder and
/// callers should treat exported accounts as needing a password reset. This is
/// the export half of the round-trippable canonical format the admin UI uses.
pub async fn export(pool: &PgPool, domain: &str) -> Result<SeedFile, LoadError> {
    let groups = ApplicationGroupRepository::list(pool).await?;
    let apps = ApplicationRepository::list_all(pool).await?;
    let users = UserRepository::list_seed_users(pool, domain).await?;
    let feedback_rows = FeedbackRepository::list_seed_by_domain(pool, domain).await?;

    let group_slug_by_id: std::collections::HashMap<uuid::Uuid, String> =
        groups.iter().map(|g| (g.id, g.slug.clone())).collect();

    let application_groups = groups
        .iter()
        .map(|g| SeedGroup {
            slug: g.slug.clone(),
            name: g.name.clone(),
            display_name: g.display_name.clone(),
            description: g.description.clone(),
            icon_url: g.icon_url.clone(),
            sort_order: Some(g.sort_order),
        })
        .collect();

    let applications = apps
        .iter()
        .map(|a| SeedApp {
            slug: a.slug.clone(),
            name: a.name.clone(),
            display_name: a.display_name.clone(),
            description: a.description.clone(),
            icon_url: a.icon_url.clone(),
            container_name: Some(a.container_name.clone()),
            group_slug: a.group_id.and_then(|id| group_slug_by_id.get(&id).cloned()),
            restricted: a.requires_entitlement,
            is_hosted: Some(a.is_hosted),
        })
        .collect();

    let mut seed_users = Vec::with_capacity(users.len());
    let mut entitlements = Vec::new();
    for u in &users {
        seed_users.push(SeedUser {
            email: u.email.clone(),
            role: u.role.clone(),
            verified: u.email_verified,
            first_name: u.first_name.clone(),
            last_name: u.last_name.clone(),
            phone: u.phone.clone(),
            // Hashes are never exportable; a re-import falls back to the file's
            // default_password.
            password: None,
            password_env: None,
            membership: SeedMembership {
                status: Some(u.membership_status.clone()),
                tier: Some(u.membership_tier.clone()),
                lifetime: u.lifetime_member,
                price_locked: u.price_locked,
                locked_price_amount: u.locked_price_amount,
                trial_ends_at: u.trial_ends_at.map(|t| t.to_rfc3339()),
            },
        });
        for row in EntitlementRepository::list_for_user(pool, u.id).await? {
            entitlements.push(SeedEntitlement {
                user_email: u.email.clone(),
                app_slug: row.slug,
            });
        }
    }

    let feedback = feedback_rows
        .iter()
        .map(|f| SeedFeedback {
            name: f.name.clone(),
            email: f.email.clone(),
            subject: f.subject.clone(),
            message: f.message.clone(),
            tags: f.tags.clone(),
            is_spam: f.is_spam,
            page_path: f.page_path.clone(),
            response: f.admin_response.clone(),
            status: Some(f.status.clone()),
        })
        .collect();

    Ok(SeedFile {
        version: SEED_SCHEMA_VERSION,
        default_password: Some("change-me-after-import".to_string()),
        // The export owns exactly the domain it was scoped to, so a re-import
        // validates and a later reset reclaims the same set (PSA-56).
        owns: SeedOwns {
            domains: vec![domain.to_string()],
            emails: Vec::new(),
        },
        application_groups,
        applications,
        users: seed_users,
        entitlements,
        feedback,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "version": 1,
      "default_password": "demo-pass-123",
      "application_groups": [
        {"slug": "core", "name": "core", "display_name": "Core", "sort_order": 0}
      ],
      "applications": [
        {"slug": "mokosh", "name": "mokosh", "display_name": "Mokosh", "group_slug": "core"},
        {"slug": "vault", "name": "vault", "display_name": "Vault", "restricted": true}
      ],
      "users": [
        {"email": "ada@demo.psa-systems.test", "role": "admin", "verified": true,
         "first_name": "Ada", "last_name": "Lovelace",
         "membership": {"status": "active", "tier": "lifetime", "lifetime": true}}
      ],
      "entitlements": [
        {"user_email": "ada@demo.psa-systems.test", "app_slug": "vault"}
      ],
      "feedback": [
        {"email": "ada@demo.psa-systems.test", "subject": "Hi", "message": "Love it"}
      ]
    }"#;

    #[test]
    fn parses_and_validates_a_good_file() {
        let f = parse(SAMPLE).expect("valid sample");
        assert_eq!(f.version, 1);
        assert_eq!(f.users.len(), 1);
        assert_eq!(f.applications.len(), 2);
        assert!(f.applications.iter().any(|a| a.restricted));
        assert_eq!(f.default_password.as_deref(), Some("demo-pass-123"));
    }

    #[test]
    fn canonical_format_round_trips() {
        // Serialize -> parse must reproduce the SeedFile. This is the format
        // guarantee behind PSA-52's "export then import reproduces state": the
        // export serializes a SeedFile, the import parses it back.
        let a = parse(SAMPLE).expect("valid sample");
        let json = serde_json::to_string(&a).expect("serialize");
        let b = parse(&json).expect("re-parse serialized output");
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_wrong_version() {
        let json = SAMPLE.replacen("\"version\": 1", "\"version\": 2", 1);
        match parse(&json) {
            Err(SeedError::UnsupportedVersion { found, expected }) => {
                assert_eq!(found, 2);
                assert_eq!(expected, 1);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_fields() {
        let json = SAMPLE.replacen(
            "\"default_password\": \"demo-pass-123\",",
            "\"default_password\": \"demo-pass-123\", \"surprise\": true,",
            1,
        );
        assert!(matches!(parse(&json), Err(SeedError::Parse(_))));
    }

    #[test]
    fn is_seed_email_matches_reserved_domain_only() {
        assert!(is_seed_email("x@demo.psa-systems.test"));
        assert!(is_seed_email("X@DEMO.PSA-SYSTEMS.TEST"));
        assert!(!is_seed_email("x@a8n.run"));
        assert!(!is_seed_email("x@demo.psa-systems.test.evil.com"));
    }

    #[test]
    fn guard_blocks_prod_and_unset_allows_nonprod() {
        assert!(seed_guard("development", true).is_ok());
        assert!(seed_guard("staging", true).is_ok());
        // allow flag missing
        assert!(matches!(
            seed_guard("development", false),
            Err(SeedError::Guard(_))
        ));
        // production-like or unset environments
        assert!(matches!(
            seed_guard("production", true),
            Err(SeedError::Guard(_))
        ));
        assert!(matches!(seed_guard("prod", true), Err(SeedError::Guard(_))));
        assert!(matches!(seed_guard("", true), Err(SeedError::Guard(_))));
        assert!(matches!(seed_guard("  ", true), Err(SeedError::Guard(_))));
    }

    #[test]
    fn validation_flags_non_seed_user_email() {
        let json = SAMPLE.replace("ada@demo.psa-systems.test", "ada@real-company.com");
        match parse(&json) {
            Err(SeedError::Validation(errs)) => {
                assert!(errs.iter().any(|e| e.contains("owns")));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validation_flags_dangling_references() {
        // Point the entitlement at an app slug that does not exist.
        let json = SAMPLE.replace("\"app_slug\": \"vault\"", "\"app_slug\": \"ghost\"");
        match parse(&json) {
            Err(SeedError::Validation(errs)) => {
                assert!(errs.iter().any(|e| e.contains("unknown app_slug 'ghost'")));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validation_flags_duplicate_and_unknown_group() {
        let json = r#"{
          "version": 1,
          "application_groups": [
            {"slug": "core", "name": "core", "display_name": "Core"},
            {"slug": "core", "name": "core2", "display_name": "Core 2"}
          ],
          "applications": [
            {"slug": "a", "name": "a", "display_name": "A", "group_slug": "missing"}
          ]
        }"#;
        match parse(json) {
            Err(SeedError::Validation(errs)) => {
                assert!(errs
                    .iter()
                    .any(|e| e.contains("duplicate application_group slug 'core'")));
                assert!(errs
                    .iter()
                    .any(|e| e.contains("unknown group_slug 'missing'")));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validation_flags_empty_feedback_and_non_seed_author() {
        let json = r#"{
          "version": 1,
          "feedback": [
            {"message": "   "},
            {"email": "x@real.com", "message": "hi"}
          ]
        }"#;
        match parse(json) {
            Err(SeedError::Validation(errs)) => {
                assert!(errs.iter().any(|e| e.contains("empty message")));
                assert!(errs.iter().any(|e| e.contains("owns")));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validation_flags_unknown_role_status_and_tier() {
        // Typos that the loader's string -> enum mapping would otherwise
        // swallow into subscriber / none / free.
        let json = r#"{
          "version": 1,
          "default_password": "p",
          "users": [
            {"email": "a@demo.psa-systems.test", "role": "amdin",
             "membership": {"status": "actve", "tier": "anual"}}
          ]
        }"#;
        match parse(json) {
            Err(SeedError::Validation(errs)) => {
                assert!(errs.iter().any(|e| e.contains("unknown role 'amdin'")));
                assert!(errs
                    .iter()
                    .any(|e| e.contains("unknown membership status 'actve'")));
                assert!(errs
                    .iter()
                    .any(|e| e.contains("unknown membership tier 'anual'")));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn validation_requires_a_feedback_author_email() {
        // Email-less feedback would neither reset nor re-import cleanly.
        let json = r#"{
          "version": 1,
          "feedback": [ {"message": "orphan"} ]
        }"#;
        match parse(json) {
            Err(SeedError::Validation(errs)) => {
                assert!(errs.iter().any(|e| e.contains("no author email")));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn every_embedded_template_parses_and_validates() {
        assert!(!SEED_TEMPLATES.is_empty());
        for t in SEED_TEMPLATES {
            parse(t.json).unwrap_or_else(|e| panic!("template '{}' is invalid: {e}", t.name));
        }
    }

    #[test]
    fn owns_covers_domains_and_explicit_emails() {
        let owns = SeedOwns {
            domains: vec!["demo.psa-systems.test".into()],
            emails: vec!["e2e-user@a8n.run".into()],
        };
        assert!(owns.covers("x@demo.psa-systems.test"));
        assert!(owns.covers("X@DEMO.PSA-SYSTEMS.TEST"));
        assert!(owns.covers("E2E-User@A8N.run")); // explicit email, case-insensitive
        assert!(!owns.covers("someone@a8n.run")); // a8n.run domain not owned, only the one email
        assert!(!owns.covers("x@evil-demo.psa-systems.test")); // sibling domain, no `@` anchor match
    }

    #[test]
    fn validation_accepts_owned_explicit_emails() {
        // The E2E-style file: owns two explicit @a8n.run emails and seeds exactly
        // them. They are not under the reserved demo domain but ARE owned.
        let json = r#"{
          "version": 1,
          "owns": { "emails": ["e2e-user@a8n.run", "e2e-admin@a8n.run"] },
          "users": [
            {"email": "e2e-user@a8n.run", "role": "subscriber", "password_env": "BUNYIP_E2E_TEST_USER_PASSWORD"},
            {"email": "e2e-admin@a8n.run", "role": "admin", "password_env": "BUNYIP_E2E_TEST_USER_PASSWORD"}
          ]
        }"#;
        let f = parse(json).expect("owned explicit emails must validate");
        assert_eq!(f.users.len(), 2);
        assert_eq!(
            f.users[0].password_env.as_deref(),
            Some("BUNYIP_E2E_TEST_USER_PASSWORD")
        );
    }

    #[test]
    fn validation_rejects_email_outside_owns() {
        // owns only the demo domain, but a user is @a8n.run -> not reclaimable.
        let json = r#"{
          "version": 1,
          "owns": { "domains": ["demo.psa-systems.test"] },
          "default_password": "p",
          "users": [ {"email": "stray@a8n.run", "role": "subscriber"} ]
        }"#;
        match parse(json) {
            Err(SeedError::Validation(errs)) => {
                assert!(errs.iter().any(|e| e.contains("owns")));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn find_template_by_name() {
        assert!(find_template("demo-msp").is_some());
        assert!(find_template("minimal").is_some());
        assert!(find_template("nope").is_none());
    }

    #[test]
    fn minimal_template_is_a_small_baseline() {
        let f = parse(find_template("minimal").expect("minimal exists").json).expect("valid");
        assert_eq!(f.users.len(), 3);
        assert_eq!(f.application_groups.len(), 2);
        assert_eq!(f.applications.len(), 3);
        assert!(f.feedback.is_empty());
        assert!(f.entitlements.is_empty());
        assert_eq!(f.users.iter().filter(|u| u.role == "admin").count(), 1);
    }

    #[test]
    fn validation_rejects_empty_password_env() {
        let json = r#"{
          "version": 1,
          "owns": { "emails": ["u@x.test"] },
          "users": [ {"email": "u@x.test", "role": "subscriber", "password_env": "  "} ]
        }"#;
        match parse(json) {
            Err(SeedError::Validation(errs)) => {
                assert!(errs.iter().any(|e| e.contains("empty password_env")));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn domain_reset_allowed_only_for_reserved() {
        // The guardrail: only the reserved domain may be reset by whole domain;
        // a real domain must be reset via explicit emails (PSA-56).
        assert!(domain_reset_allowed("demo.psa-systems.test"));
        assert!(domain_reset_allowed("DEMO.PSA-SYSTEMS.TEST"));
        assert!(!domain_reset_allowed("a8n.run"));
        assert!(!domain_reset_allowed("gmail.com"));
    }

    #[test]
    fn resolve_password_rejects_empty_and_unset_env() {
        // Pull a SeedUser out of a one-user file with the given extra fields.
        let mk = |extra: &str| -> SeedUser {
            let json = format!(
                r#"{{"version":1,"owns":{{"emails":["u@x.test"]}},"users":[{{"email":"u@x.test","role":"subscriber"{extra}}}]}}"#
            );
            parse(&json)
                .expect("valid one-user file")
                .users
                .into_iter()
                .next()
                .unwrap()
        };

        assert_eq!(
            resolve_password(&mk(r#","password":"secret""#), None).unwrap(),
            "secret"
        );
        assert_eq!(resolve_password(&mk(""), Some("dflt")).unwrap(), "dflt");
        // An empty literal password would seed a broken account -> rejected.
        assert!(matches!(
            resolve_password(&mk(r#","password":"  ""#), None),
            Err(LoadError::EmptyPassword(_))
        ));
        // No password anywhere.
        assert!(matches!(
            resolve_password(&mk(""), None),
            Err(LoadError::MissingPassword(_))
        ));
        // password_env pointing at an unset var fails loud and specifically.
        assert!(matches!(
            resolve_password(
                &mk(r#","password_env":"BUNYIP_SEED_DEFINITELY_UNSET_VAR_zzz""#),
                None
            ),
            Err(LoadError::PasswordEnvUnset { .. })
        ));
    }

    #[test]
    fn validation_rejects_nonreserved_owns_domain() {
        // A real domain must be scoped via owns.emails, not owns.domains, so a
        // reset can never reclaim every account under it (PSA-56 guardrail).
        let json = r#"{
          "version": 1,
          "owns": { "domains": ["a8n.run"] },
          "default_password": "p",
          "users": [ {"email": "x@a8n.run", "role": "subscriber"} ]
        }"#;
        match parse(json) {
            Err(SeedError::Validation(errs)) => {
                assert!(errs
                    .iter()
                    .any(|e| e.contains("owns.domains may only contain the reserved domain")));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }
}
