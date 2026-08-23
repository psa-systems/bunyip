//! Business logic services.
//!
//! Domain services live here. The generic primitive services (AES-GCM
//! encryption key set, Argon2 password hashing, JWT config) come from
//! dunite-core; the binary-distribution engine (Forgejo asset client,
//! release/asset caches, download limiter) comes from dunite-download. Both
//! are re-exported below.

pub mod app_key;
pub mod argon2_offload;
pub mod auth;
pub mod backup;
pub mod email;
pub mod event_bus;
pub mod geoip;
pub mod infisical;
pub mod ip_enrich;
pub mod jwt;
pub mod mailer_relay;
pub mod password_breach;
pub mod stripe;
pub mod totp;
pub mod webhook;

// BUNYIP-483: the one at-rest key set (APP_ENCRYPTION_KEY). Wraps the kernel's
// `EncryptionKeySet` to accept several previous keys.
pub use app_key::AppKeySet;

// Generic kernel services (re-exported from dunite-core).
pub use dunite_core::services::{EncryptionKeySet, JwtConfig, PasswordService};
// Re-export the kernel service submodules so `crate::services::encryption::*`
// and `crate::services::password::*` paths resolve unchanged.
pub use dunite_core::services::{encryption, password};

// Binary-distribution engine (re-exported from dunite-download). Bunyip
// implements the engine's store traits in `crate::repositories`.
pub use dunite_download::services::{
    DownloadCache, DownloadCacheError, DownloadGuard, DownloadLimiter, ErrorClass,
    ForgejoAssetClient, ForgejoError, LimitDenial, ReleaseCache,
};

/// The concrete download cache: the generic dunite-download `DownloadCache`
/// engine backed by Bunyip's Postgres `DownloadCacheRepository` store.
///
/// Defined here (the one module visible to bunyip-api's handlers, admin
/// handlers, and main.rs wiring alike) rather than in the binary, so the
/// engine-over-store binding has exactly one definition. The OCI vertical
/// predates this convention and still defines its `AppBlobCache` alias
/// per-module; aligning it is tracked separately.
pub type AppDownloadCache = DownloadCache<crate::repositories::DownloadCacheRepository>;

// Domain service types.
pub use auth::{
    AcceptInviteResult, AuthService, AuthTokens, LoginResult, MagicLinkResult, TierGrantTrigger,
};
pub use backup::{
    AccountBackup, AccountBackupStore, AccountProfile, AccountSection, AppBackupAdapter,
    AppBackupContext, AppBackupOutcome, AppBackupSection, AppBackupStatus, AppRestoreOutcome,
    AppRestoreStatus, BackupService, MokoshBackupAdapter, PgAccountBackupStore, RestoreReport,
    StoredProfile, BACKUP_FORMAT_VERSION,
};
pub use email::{AsyncStubTransport, EmailService, SmtpTestError, SmtpTestStage};
pub use event_bus::{BunyipEvent, EventBus};
pub use geoip::GeoIpService;
pub use infisical::{InfisicalClient, InfisicalError};
pub use ip_enrich::{IpEnrichService, IpEnrichment, NetworkCategory, VpnLikelihood};
pub use jwt::{AccessTokenClaims, JwtService, RefreshTokenClaims, TwoFactorChallengeClaims};
pub use mailer_relay::{
    MailerRelay, NoSuppression, RelayMessage, RelayOutcome, SuppressionList, MAX_ADDRESS_LEN,
    MAX_BODY_LEN, MAX_SUBJECT_LEN,
};
pub use stripe::{
    classify_probe, stripe_config_from_db_model, stripe_err, stripe_err_for,
    stripe_settings_from_db_model, unconfigured_stripe_config, ProbeStatus, StripeConfig,
    StripeErrorDetails, StripePermission, StripeService, StripeServiceError,
};
pub use totp::TotpService;
pub use webhook::WebhookService;
