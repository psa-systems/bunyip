//! BUNYIP-353: account-level backup and restore.
//!
//! Bunyip is the account / SaaS control plane. This service captures an
//! account's Bunyip-side state (owner profile + entitled app slugs) plus, for
//! each entitled app, a per-app backup obtained through a pluggable
//! [`AppBackupAdapter`], and reverses the operation on restore.
//!
//! ## Why an adapter seam
//!
//! bunyip has no request/response transport to app backends today (it is the
//! OIDC issuer; apps are relying parties, and the only outbound-to-app path is
//! the fire-and-forget webhook push). The per-app backup API for the first
//! target (Mokosh) is also not shipped yet. So per-app backup/restore is
//! expressed behind [`AppBackupAdapter`]: the account orchestration is built
//! and tested now against a fake adapter, and the real Mokosh HTTP client
//! drops into [`MokoshBackupAdapter`] once its endpoint exists.
//!
//! ## Why a store seam
//!
//! [`BackupService`] reaches the database through [`AccountBackupStore`] rather
//! than a `PgPool` directly, so the backup -> restore round-trip is unit-tested
//! with an in-memory fake and needs no Postgres (the domain crate's tests are
//! pure).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::entitlement::entitlement_source;
use crate::repositories::{ApplicationRepository, EntitlementRepository, UserRepository};
use crate::AppError;

/// Wire format version of the account bundle. Bumped only on a
/// backwards-incompatible change to [`AccountBackup`]; restore refuses a bundle
/// whose version it does not understand.
pub const BACKUP_FORMAT_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Bundle format
// ---------------------------------------------------------------------------

/// One account backup bundle: the whole thing an admin downloads and later
/// uploads to restore. Serialized as a single JSON document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountBackup {
    pub format_version: u32,
    pub created_at: DateTime<Utc>,
    pub account: AccountSection,
    pub apps: Vec<AppBackupSection>,
}

/// The Bunyip-side account state. Excludes system-global singletons (email /
/// auto-ban / stripe config), which are platform-wide, not per-account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSection {
    pub profile: AccountProfile,
    /// Slugs of the apps the account is entitled to at backup time.
    pub entitlements: Vec<String>,
}

/// The account owner's restorable profile fields. `email` is captured for
/// reference but is NOT re-applied on restore (email changes go through a
/// separate verified-change flow).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProfile {
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
}

/// One app's slot in the bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppBackupSection {
    pub slug: String,
    pub status: AppBackupStatus,
    /// The app's opaque backup payload; present only when `status` is
    /// `Included`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<Value>,
}

/// Backup-time outcome for one app.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AppBackupStatus {
    /// The app produced a bundle.
    Included,
    /// No adapter is registered for this app slug.
    Skipped { reason: String },
    /// An adapter exists but its backend is not available yet (e.g. the Mokosh
    /// backup API is still pending).
    Unavailable { reason: String },
}

// ---------------------------------------------------------------------------
// Restore report
// ---------------------------------------------------------------------------

/// The result of restoring a bundle, surfaced back to the admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreReport {
    pub profile_restored: bool,
    pub entitlements_granted: Vec<String>,
    pub apps: Vec<AppRestoreOutcome>,
}

/// Per-app restore result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRestoreOutcome {
    pub slug: String,
    pub status: AppRestoreStatus,
}

/// Restore-time outcome for one app.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AppRestoreStatus {
    /// The app accepted the bundle.
    Restored,
    /// Skipped: account not entitled, no adapter, no bundle in the archive, or
    /// the app backend is not available yet. `reason` says which.
    Skipped { reason: String },
}

// ---------------------------------------------------------------------------
// Adapter seam
// ---------------------------------------------------------------------------

/// Context handed to an [`AppBackupAdapter`] for one account operation. Carries
/// what a future per-app HTTP call will need to scope the request.
#[derive(Debug, Clone)]
pub struct AppBackupContext {
    pub user_id: Uuid,
    /// The app tenant the account lands in. Today every account JIT-lands in
    /// the single default tenant; kept explicit so the real adapter can scope
    /// its call once multi-tenant ships.
    pub tenant_id: Uuid,
}

/// What an adapter's [`backup`](AppBackupAdapter::backup) produced.
pub enum AppBackupOutcome {
    /// The app returned a backup payload.
    Produced(Value),
    /// The app's backup backend is not available yet.
    Unavailable(String),
}

/// A per-app backup/restore driver. One impl per entitled app; registered in
/// [`BackupService`] by its [`slug`](AppBackupAdapter::slug).
#[async_trait]
pub trait AppBackupAdapter: Send + Sync {
    /// The application slug this adapter serves (matches `applications.slug`).
    fn slug(&self) -> &str;

    /// Produce this app's backup payload for the account in `ctx`.
    async fn backup(&self, ctx: &AppBackupContext) -> Result<AppBackupOutcome, AppError>;

    /// Re-apply a previously produced payload for the account in `ctx`. Returns
    /// `true` if the app accepted the bundle, `false` if the backend is not
    /// available yet (the caller records that as a skip).
    async fn restore(&self, ctx: &AppBackupContext, bundle: &Value) -> Result<bool, AppError>;
}

/// Pending stub for Mokosh. Mokosh's tenant-scoped backup API is not shipped
/// yet, so backup reports `Unavailable` and restore is a no-op skip. Replace
/// the two method bodies with the real HTTP client once the endpoint exists;
/// nothing else in the orchestration changes.
pub struct MokoshBackupAdapter;

const MOKOSH_PENDING: &str = "Mokosh backup API not yet available";

#[async_trait]
impl AppBackupAdapter for MokoshBackupAdapter {
    fn slug(&self) -> &str {
        "mokosh"
    }

    async fn backup(&self, _ctx: &AppBackupContext) -> Result<AppBackupOutcome, AppError> {
        Ok(AppBackupOutcome::Unavailable(MOKOSH_PENDING.to_string()))
    }

    async fn restore(&self, _ctx: &AppBackupContext, _bundle: &Value) -> Result<bool, AppError> {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Store seam
// ---------------------------------------------------------------------------

/// The account owner's profile as loaded for a backup.
#[derive(Debug, Clone)]
pub struct StoredProfile {
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
}

/// Database access [`BackupService`] needs, behind a trait so the round-trip is
/// unit-tested without Postgres.
#[async_trait]
pub trait AccountBackupStore: Send + Sync {
    /// Load the account owner's profile.
    async fn load_profile(&self, user_id: Uuid) -> Result<StoredProfile, AppError>;
    /// Active entitlement slugs for the account.
    async fn load_entitlement_slugs(&self, user_id: Uuid) -> Result<Vec<String>, AppError>;
    /// Overwrite the account owner's profile fields (email is not touched).
    async fn save_profile(
        &self,
        user_id: Uuid,
        first_name: Option<&str>,
        last_name: Option<&str>,
        phone: Option<&str>,
    ) -> Result<(), AppError>;
    /// Whether an application with this slug exists (gates restore-time grants).
    async fn app_exists(&self, slug: &str) -> Result<bool, AppError>;
    /// Grant the account an entitlement to `slug` (idempotent). `granted_by` is
    /// the acting admin.
    async fn grant_entitlement(
        &self,
        user_id: Uuid,
        slug: &str,
        granted_by: Uuid,
    ) -> Result<(), AppError>;
}

/// Postgres-backed [`AccountBackupStore`] over the existing repositories.
pub struct PgAccountBackupStore {
    pool: PgPool,
}

impl PgAccountBackupStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AccountBackupStore for PgAccountBackupStore {
    async fn load_profile(&self, user_id: Uuid) -> Result<StoredProfile, AppError> {
        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or_else(|| AppError::not_found("User"))?;
        Ok(StoredProfile {
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            phone: user.phone,
        })
    }

    async fn load_entitlement_slugs(&self, user_id: Uuid) -> Result<Vec<String>, AppError> {
        let rows = EntitlementRepository::list_for_user(&self.pool, user_id).await?;
        Ok(rows.into_iter().map(|r| r.slug).collect())
    }

    async fn save_profile(
        &self,
        user_id: Uuid,
        first_name: Option<&str>,
        last_name: Option<&str>,
        phone: Option<&str>,
    ) -> Result<(), AppError> {
        UserRepository::update_profile(&self.pool, user_id, first_name, last_name, phone).await?;
        Ok(())
    }

    async fn app_exists(&self, slug: &str) -> Result<bool, AppError> {
        Ok(ApplicationRepository::find_by_slug(&self.pool, slug)
            .await?
            .is_some())
    }

    async fn grant_entitlement(
        &self,
        user_id: Uuid,
        slug: &str,
        granted_by: Uuid,
    ) -> Result<(), AppError> {
        let app = ApplicationRepository::find_by_slug(&self.pool, slug)
            .await?
            .ok_or_else(|| AppError::not_found("Application"))?;
        EntitlementRepository::grant(
            &self.pool,
            user_id,
            app.id,
            Some(granted_by),
            entitlement_source::ADMIN,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Account backup/restore orchestrator. Holds one [`AppBackupAdapter`] per app
/// slug; the database is reached through an [`AccountBackupStore`].
#[derive(Clone)]
pub struct BackupService {
    adapters: HashMap<String, Arc<dyn AppBackupAdapter>>,
}

impl BackupService {
    /// Build a service from a set of adapters, keyed by each adapter's slug.
    pub fn new(adapters: Vec<Arc<dyn AppBackupAdapter>>) -> Self {
        let adapters = adapters
            .into_iter()
            .map(|a| (a.slug().to_string(), a))
            .collect();
        Self { adapters }
    }

    /// Capture an account backup: profile + entitled app slugs, plus a per-app
    /// section for each entitled app.
    pub async fn create_backup(
        &self,
        store: &dyn AccountBackupStore,
        user_id: Uuid,
        tenant_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<AccountBackup, AppError> {
        let profile = store.load_profile(user_id).await?;
        let slugs = store.load_entitlement_slugs(user_id).await?;
        let ctx = AppBackupContext { user_id, tenant_id };

        let mut apps = Vec::with_capacity(slugs.len());
        for slug in &slugs {
            let section = match self.adapters.get(slug) {
                None => AppBackupSection {
                    slug: slug.clone(),
                    status: AppBackupStatus::Skipped {
                        reason: "no backup adapter for this app".to_string(),
                    },
                    bundle: None,
                },
                Some(adapter) => match adapter.backup(&ctx).await? {
                    AppBackupOutcome::Produced(bundle) => AppBackupSection {
                        slug: slug.clone(),
                        status: AppBackupStatus::Included,
                        bundle: Some(bundle),
                    },
                    AppBackupOutcome::Unavailable(reason) => AppBackupSection {
                        slug: slug.clone(),
                        status: AppBackupStatus::Unavailable { reason },
                        bundle: None,
                    },
                },
            };
            apps.push(section);
        }

        Ok(AccountBackup {
            format_version: BACKUP_FORMAT_VERSION,
            created_at,
            account: AccountSection {
                profile: AccountProfile {
                    email: profile.email,
                    first_name: profile.first_name,
                    last_name: profile.last_name,
                    phone: profile.phone,
                },
                entitlements: slugs,
            },
            apps,
        })
    }

    /// Re-apply a bundle to the account: restore the profile, re-grant listed
    /// entitlements (only for apps that still exist), then dispatch each app
    /// bundle to its adapter, but only for apps the account is entitled to.
    pub async fn restore_backup(
        &self,
        store: &dyn AccountBackupStore,
        user_id: Uuid,
        tenant_id: Uuid,
        acting_admin: Uuid,
        backup: AccountBackup,
    ) -> Result<RestoreReport, AppError> {
        if backup.format_version != BACKUP_FORMAT_VERSION {
            return Err(AppError::validation(
                "format_version",
                format!(
                    "unsupported backup format_version {} (expected {})",
                    backup.format_version, BACKUP_FORMAT_VERSION
                ),
            ));
        }

        // 1. Restore the account owner profile. Email is intentionally left
        //    unchanged; it moves through the verified email-change flow.
        let profile = &backup.account.profile;
        store
            .save_profile(
                user_id,
                profile.first_name.as_deref(),
                profile.last_name.as_deref(),
                profile.phone.as_deref(),
            )
            .await?;

        // 2. Re-grant entitlements listed in the bundle, skipping any app slug
        //    that no longer exists.
        let mut entitlements_granted = Vec::new();
        for slug in &backup.account.entitlements {
            if store.app_exists(slug).await? {
                store.grant_entitlement(user_id, slug, acting_admin).await?;
                entitlements_granted.push(slug.clone());
            }
        }

        // 3. Dispatch each app bundle to its adapter, gated on the account now
        //    being entitled to that app.
        let ctx = AppBackupContext { user_id, tenant_id };
        let mut apps = Vec::with_capacity(backup.apps.len());
        for section in &backup.apps {
            let status = self
                .restore_one_app(&ctx, &entitlements_granted, section)
                .await?;
            apps.push(AppRestoreOutcome {
                slug: section.slug.clone(),
                status,
            });
        }

        Ok(RestoreReport {
            profile_restored: true,
            entitlements_granted,
            apps,
        })
    }

    async fn restore_one_app(
        &self,
        ctx: &AppBackupContext,
        entitled: &[String],
        section: &AppBackupSection,
    ) -> Result<AppRestoreStatus, AppError> {
        if !entitled.contains(&section.slug) {
            return Ok(AppRestoreStatus::Skipped {
                reason: "account not entitled to this app".to_string(),
            });
        }
        let Some(adapter) = self.adapters.get(&section.slug) else {
            return Ok(AppRestoreStatus::Skipped {
                reason: "no backup adapter for this app".to_string(),
            });
        };
        let Some(bundle) = &section.bundle else {
            return Ok(AppRestoreStatus::Skipped {
                reason: "no bundle captured for this app".to_string(),
            });
        };
        if adapter.restore(ctx, bundle).await? {
            Ok(AppRestoreStatus::Restored)
        } else {
            Ok(AppRestoreStatus::Skipped {
                reason: "app backup backend not available yet".to_string(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (pure: in-memory store + fake adapter, no Postgres)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    /// In-memory [`AccountBackupStore`]. `grant_entitlement` also appends to the
    /// entitlement list so a later `load_entitlement_slugs` reflects the grant.
    struct FakeStore {
        profile: Mutex<StoredProfile>,
        entitlements: Mutex<Vec<String>>,
        existing_apps: Vec<String>,
        grants: Mutex<Vec<(String, Uuid)>>,
    }

    impl FakeStore {
        fn new(
            profile: StoredProfile,
            entitlements: Vec<String>,
            existing_apps: Vec<&str>,
        ) -> Self {
            Self {
                profile: Mutex::new(profile),
                entitlements: Mutex::new(entitlements),
                existing_apps: existing_apps.into_iter().map(String::from).collect(),
                grants: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl AccountBackupStore for FakeStore {
        async fn load_profile(&self, _user_id: Uuid) -> Result<StoredProfile, AppError> {
            Ok(self.profile.lock().unwrap().clone())
        }
        async fn load_entitlement_slugs(&self, _user_id: Uuid) -> Result<Vec<String>, AppError> {
            Ok(self.entitlements.lock().unwrap().clone())
        }
        async fn save_profile(
            &self,
            _user_id: Uuid,
            first_name: Option<&str>,
            last_name: Option<&str>,
            phone: Option<&str>,
        ) -> Result<(), AppError> {
            let mut p = self.profile.lock().unwrap();
            p.first_name = first_name.map(String::from);
            p.last_name = last_name.map(String::from);
            p.phone = phone.map(String::from);
            Ok(())
        }
        async fn app_exists(&self, slug: &str) -> Result<bool, AppError> {
            Ok(self.existing_apps.iter().any(|s| s == slug))
        }
        async fn grant_entitlement(
            &self,
            _user_id: Uuid,
            slug: &str,
            granted_by: Uuid,
        ) -> Result<(), AppError> {
            self.grants
                .lock()
                .unwrap()
                .push((slug.to_string(), granted_by));
            let mut ents = self.entitlements.lock().unwrap();
            if !ents.iter().any(|s| s == slug) {
                ents.push(slug.to_string());
            }
            Ok(())
        }
    }

    /// Adapter that actually produces and consumes a bundle, so a real
    /// round-trip can be asserted.
    struct FakeAdapter {
        slug: String,
        payload: Value,
        restored: Mutex<Vec<Value>>,
    }

    impl FakeAdapter {
        fn new(slug: &str, payload: Value) -> Self {
            Self {
                slug: slug.to_string(),
                payload,
                restored: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl AppBackupAdapter for FakeAdapter {
        fn slug(&self) -> &str {
            &self.slug
        }
        async fn backup(&self, _ctx: &AppBackupContext) -> Result<AppBackupOutcome, AppError> {
            Ok(AppBackupOutcome::Produced(self.payload.clone()))
        }
        async fn restore(&self, _ctx: &AppBackupContext, bundle: &Value) -> Result<bool, AppError> {
            self.restored.lock().unwrap().push(bundle.clone());
            Ok(true)
        }
    }

    fn profile(email: &str, first: Option<&str>) -> StoredProfile {
        StoredProfile {
            email: email.to_string(),
            first_name: first.map(String::from),
            last_name: None,
            phone: None,
        }
    }

    fn ts() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    const USER: Uuid = Uuid::from_u128(0x1111);
    const TENANT: Uuid = Uuid::from_u128(1);
    const ADMIN: Uuid = Uuid::from_u128(0x9999);

    #[tokio::test]
    async fn backup_then_restore_round_trips_profile_entitlements_and_app_bundle() {
        let widget_payload = json!({ "widgets": [1, 2, 3] });
        let svc = BackupService::new(vec![
            Arc::new(MokoshBackupAdapter),
            Arc::new(FakeAdapter::new("widgets", widget_payload.clone())),
        ]);

        // Source account: entitled to mokosh + widgets.
        let source = FakeStore::new(
            profile("owner@example.com", Some("New")),
            vec!["mokosh".to_string(), "widgets".to_string()],
            vec!["mokosh", "widgets"],
        );
        let backup = svc
            .create_backup(&source, USER, TENANT, ts())
            .await
            .unwrap();

        assert_eq!(backup.format_version, BACKUP_FORMAT_VERSION);
        assert_eq!(backup.account.profile.email, "owner@example.com");
        assert_eq!(backup.account.entitlements, vec!["mokosh", "widgets"]);
        // mokosh: pending -> Unavailable, no bundle. widgets: Included w/ bundle.
        let mokosh = backup.apps.iter().find(|a| a.slug == "mokosh").unwrap();
        assert!(matches!(mokosh.status, AppBackupStatus::Unavailable { .. }));
        assert!(mokosh.bundle.is_none());
        let widgets = backup.apps.iter().find(|a| a.slug == "widgets").unwrap();
        assert_eq!(widgets.status, AppBackupStatus::Included);
        assert_eq!(widgets.bundle.as_ref(), Some(&widget_payload));

        // Restore into a fresh, empty account with its own email.
        let widget_adapter = Arc::new(FakeAdapter::new("widgets", widget_payload.clone()));
        let restore_svc =
            BackupService::new(vec![Arc::new(MokoshBackupAdapter), widget_adapter.clone()]);
        let target = FakeStore::new(
            profile("fresh@example.com", Some("Old")),
            vec![],
            vec!["mokosh", "widgets"],
        );
        let report = restore_svc
            .restore_backup(&target, USER, TENANT, ADMIN, backup)
            .await
            .unwrap();

        assert!(report.profile_restored);
        assert_eq!(report.entitlements_granted, vec!["mokosh", "widgets"]);
        // Profile fields applied, email left as the target's own.
        let p = target.profile.lock().unwrap();
        assert_eq!(p.first_name.as_deref(), Some("New"));
        assert_eq!(p.email, "fresh@example.com");
        drop(p);
        // Entitlements now present; grants attributed to the acting admin.
        assert_eq!(target.entitlements.lock().unwrap().len(), 2);
        assert!(target
            .grants
            .lock()
            .unwrap()
            .iter()
            .all(|(_, by)| *by == ADMIN));
        // widgets restored with the exact payload; mokosh skipped (pending).
        assert_eq!(
            widget_adapter.restored.lock().unwrap().as_slice(),
            &[widget_payload]
        );
        let w = report.apps.iter().find(|a| a.slug == "widgets").unwrap();
        assert_eq!(w.status, AppRestoreStatus::Restored);
        let m = report.apps.iter().find(|a| a.slug == "mokosh").unwrap();
        assert!(matches!(m.status, AppRestoreStatus::Skipped { .. }));
    }

    #[tokio::test]
    async fn restore_skips_apps_the_account_is_not_entitled_to() {
        let payload = json!({ "x": 1 });
        let adapter = Arc::new(FakeAdapter::new("widgets", payload.clone()));
        let svc = BackupService::new(vec![adapter.clone()]);

        // Bundle carries a widgets section, but the account is only entitled to
        // mokosh -> widgets must not be dispatched.
        let backup = AccountBackup {
            format_version: BACKUP_FORMAT_VERSION,
            created_at: ts(),
            account: AccountSection {
                profile: profile("a@b.com", None).into_account(),
                entitlements: vec!["mokosh".to_string()],
            },
            apps: vec![AppBackupSection {
                slug: "widgets".to_string(),
                status: AppBackupStatus::Included,
                bundle: Some(payload),
            }],
        };
        let store = FakeStore::new(profile("a@b.com", None), vec![], vec!["mokosh", "widgets"]);
        let report = svc
            .restore_backup(&store, USER, TENANT, ADMIN, backup)
            .await
            .unwrap();

        assert_eq!(report.entitlements_granted, vec!["mokosh"]);
        assert!(adapter.restored.lock().unwrap().is_empty());
        let w = report.apps.iter().find(|a| a.slug == "widgets").unwrap();
        assert!(matches!(w.status, AppRestoreStatus::Skipped { .. }));
    }

    #[tokio::test]
    async fn mokosh_backup_reports_unavailable() {
        let svc = BackupService::new(vec![Arc::new(MokoshBackupAdapter)]);
        let store = FakeStore::new(
            profile("a@b.com", None),
            vec!["mokosh".to_string()],
            vec!["mokosh"],
        );
        let backup = svc.create_backup(&store, USER, TENANT, ts()).await.unwrap();
        let mokosh = &backup.apps[0];
        assert!(matches!(mokosh.status, AppBackupStatus::Unavailable { .. }));
        assert!(mokosh.bundle.is_none());
    }

    #[tokio::test]
    async fn entitled_app_with_no_adapter_is_skipped_in_backup() {
        let svc = BackupService::new(vec![]);
        let store = FakeStore::new(
            profile("a@b.com", None),
            vec!["ghost".to_string()],
            vec!["ghost"],
        );
        let backup = svc.create_backup(&store, USER, TENANT, ts()).await.unwrap();
        assert!(matches!(
            backup.apps[0].status,
            AppBackupStatus::Skipped { .. }
        ));
    }

    #[tokio::test]
    async fn restore_rejects_unknown_format_version() {
        let svc = BackupService::new(vec![]);
        let store = FakeStore::new(profile("a@b.com", None), vec![], vec![]);
        let backup = AccountBackup {
            format_version: 999,
            created_at: ts(),
            account: AccountSection {
                profile: profile("a@b.com", None).into_account(),
                entitlements: vec![],
            },
            apps: vec![],
        };
        let err = svc
            .restore_backup(&store, USER, TENANT, ADMIN, backup)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::ValidationError { .. }));
    }

    impl StoredProfile {
        fn into_account(self) -> AccountProfile {
            AccountProfile {
                email: self.email,
                first_name: self.first_name,
                last_name: self.last_name,
                phone: self.phone,
            }
        }
    }
}
