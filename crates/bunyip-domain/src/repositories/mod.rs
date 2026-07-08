//! Database repository layer
//!
//! This module contains all database access logic organized by domain.

pub mod account_delete_dispatch_failure;
pub mod application;
pub mod application_group;
pub mod audit;
pub mod auto_ban;
pub mod download_cache;
pub mod download_daily_count;
pub mod email;
pub mod entitlement;
pub mod feedback;
pub mod invite;
pub mod notification;
pub mod oauth_client_user_tenant;
pub mod rate_limit;
pub mod stripe;
pub mod tier;
pub mod token;
pub mod totp;
pub mod trusted_device;
pub mod user;

// Re-export repositories
pub use account_delete_dispatch_failure::{
    AccountDeleteDispatchFailure, AccountDeleteDispatchFailureRepository,
};
pub use application::ApplicationRepository;
pub use application_group::ApplicationGroupRepository;
pub use audit::AuditLogRepository;
pub use auto_ban::AutoBanConfigRepository;
pub use download_cache::DownloadCacheRepository;
pub use download_daily_count::DownloadDailyCountRepository;
pub use email::EmailConfigRepository;
pub use entitlement::EntitlementRepository;
pub use feedback::FeedbackRepository;
pub use invite::InviteRepository;
pub use notification::NotificationRepository;
pub use oauth_client_user_tenant::OAuthClientUserTenantRepository;
pub use rate_limit::RateLimitRepository;
pub use stripe::StripeConfigRepository;
pub use tier::TierConfigRepository;
pub use token::{EmailResendLimiterRow, TokenRepository};
pub use totp::TotpRepository;
pub use trusted_device::TrustedDeviceRepository;
pub use user::UserRepository;
