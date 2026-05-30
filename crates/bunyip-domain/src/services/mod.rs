//! Business logic services.
//!
//! Domain services live here. The generic primitive services (AES-GCM
//! encryption key set, Argon2 password hashing, JWT config) come from
//! dunite-core and are re-exported below.

pub mod auth;
pub mod download_cache;
pub mod download_limiter;
pub mod email;
pub mod forgejo;
pub mod jwt;
pub mod release_cache;
pub mod stripe;
pub mod totp;
pub mod webhook;

// Generic kernel services (re-exported from dunite-core).
pub use dunite_core::services::{EncryptionKeySet, JwtConfig, PasswordService};
// Re-export the kernel service submodules so `crate::services::encryption::*`
// and `crate::services::password::*` paths resolve unchanged.
pub use dunite_core::services::{encryption, password};

// Domain service types.
pub use auth::{AcceptInviteResult, AuthService, AuthTokens, LoginResult, MagicLinkResult};
pub use download_cache::{DownloadCache, DownloadCacheError};
pub use download_limiter::{DownloadGuard, DownloadLimiter, LimitDenial};
pub use email::EmailService;
pub use forgejo::{ForgejoClient, ForgejoError};
pub use jwt::{AccessTokenClaims, JwtService, RefreshTokenClaims, TwoFactorChallengeClaims};
pub use release_cache::ReleaseCache;
pub use stripe::{StripeConfig, StripeService};
pub use totp::TotpService;
pub use webhook::WebhookService;
