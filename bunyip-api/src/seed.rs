//! File-driven seed data: canonical schema, validation, and safety gates (PSA-50).
//!
//! Seed data lives as a JSON file, not in code. This module is the foundation
//! the loader and `seed` CLI build on: it defines the canonical schema, parses
//! and validates a file (structure plus referential integrity), decides the
//! reserved-domain reset scope, and enforces the non-production guard. The DB
//! loader that turns a validated [`SeedFile`] into rows through the domain
//! repositories lands on top of this.
//!
//! Two safety invariants are enforced here, before any row is written:
//!   - Every seeded user email sits under [`SEED_EMAIL_DOMAIN`], so a reset can
//!     scope to exactly the seed rows and never touch a real account.
//!   - Import/reset refuse to run against a production (or unset) environment.

use std::collections::HashSet;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::PgPool;

use crate::errors::AppError;
use crate::models::{
    CreateApplication, CreateApplicationGroup, CreateFeedback, CreateUser, MembershipStatus,
    SubscriptionTier, UserRole,
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
/// with `UserRole`, `MembershipStatus`, and `SubscriptionTier`.
const VALID_ROLES: [&str; 2] = ["subscriber", "admin"];
const VALID_STATUSES: [&str; 5] = ["none", "active", "past_due", "canceled", "grace_period"];
const VALID_TIERS: [&str; 4] = ["free", "standard", "early_adopter", "lifetime"];

/// A parsed seed file. Section order is irrelevant; the loader resolves
/// cross-references (app -> group, entitlement -> user/app) by slug/email.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedFile {
    pub version: u32,
    /// Password applied to any user that does not carry its own. Hashed by the
    /// loader via the real `PasswordService`; never stored pre-hashed.
    #[serde(default)]
    pub default_password: Option<String>,
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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
    #[serde(default)]
    pub membership: SeedMembership,
}

/// Membership state applied to a seeded user as DB state (no Stripe objects).
/// Strings here are validated into the domain enums by the loader, so the
/// schema stays decoupled from the enum variants.
#[derive(Debug, Clone, Default, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedEntitlement {
    pub user_email: String,
    pub app_slug: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedFeedback {
    #[serde(default)]
    pub name: Option<String>,
    /// If set, must be under [`SEED_EMAIL_DOMAIN`] so a reset can reclaim it.
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
/// The reset scope and the seed-only invariant both key on this.
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

        let mut user_emails: HashSet<String> = HashSet::new();
        for u in &self.users {
            let lower = u.email.to_ascii_lowercase();
            if !is_seed_email(&u.email) {
                errs.push(format!(
                    "user '{}' is not under the reserved seed domain @{SEED_EMAIL_DOMAIN}; reset could not reclaim it",
                    u.email
                ));
            }
            if !user_emails.insert(lower) {
                errs.push(format!("duplicate user email '{}'", u.email));
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
                        "user '{}' has unknown subscription tier '{}' (expected one of {VALID_TIERS:?})",
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
                    "feedback[{i}] has no author email; seed feedback must carry a seed-domain email so a reset can reclaim it"
                )),
                Some(email) if !is_seed_email(email) => errs.push(format!(
                    "feedback[{i}] author email '{email}' is not under @{SEED_EMAIL_DOMAIN}; reset could not reclaim it"
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
    Db(AppError),
}

impl From<AppError> for LoadError {
    fn from(e: AppError) -> Self {
        LoadError::Db(e)
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

/// Map a template tier string to a [`SubscriptionTier`]. `lifetime = true`
/// forces `Lifetime`; an unknown/absent tier falls back to `Free`.
fn parse_tier(tier: Option<&str>, lifetime: bool) -> SubscriptionTier {
    if lifetime {
        return SubscriptionTier::Lifetime;
    }
    match tier.map(str::to_ascii_lowercase).as_deref() {
        Some("lifetime") => SubscriptionTier::Lifetime,
        Some("early_adopter") => SubscriptionTier::EarlyAdopter,
        Some("standard") => SubscriptionTier::Standard,
        _ => SubscriptionTier::Free,
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
        let raw_password = u
            .password
            .as_deref()
            .or(file.default_password.as_deref())
            .ok_or_else(|| LoadError::MissingPassword(u.email.clone()))?;
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
        EntitlementRepository::grant(pool, user.id, app.id, None, "seed").await?;
        summary.entitlements += 1;
    }

    // 5. Feedback: clear prior seed feedback (by domain), then insert fresh, so
    //    re-import stays idempotent (feedback has no natural key).
    FeedbackRepository::delete_seed_by_domain(pool, SEED_EMAIL_DOMAIN).await?;
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
            },
        )
        .await?;
        summary.feedback += 1;
    }

    Ok(summary)
}

/// Remove all seed data reclaimable by the reserved domain: seed users (with
/// their cascaded dependencies) and seed feedback. Catalog groups/applications
/// are shared config and are left intact - deleting a catalog app could orphan
/// a real user's entitlement.
pub async fn reset(pool: &PgPool) -> Result<ResetSummary, LoadError> {
    let users = UserRepository::hard_delete_seed_users(pool, SEED_EMAIL_DOMAIN).await?;
    let feedback = FeedbackRepository::delete_seed_by_domain(pool, SEED_EMAIL_DOMAIN).await?;
    Ok(ResetSummary { users, feedback })
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
                assert!(errs.iter().any(|e| e.contains("reserved seed domain")));
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
                assert!(errs.iter().any(|e| e.contains("not under")));
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
                    .any(|e| e.contains("unknown subscription tier 'anual'")));
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
}
