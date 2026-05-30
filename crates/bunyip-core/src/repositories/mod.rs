//! Database repository layer
//!
//! This module contains all database access logic organized by domain.

pub mod application;
pub mod audit;
pub mod download_cache;
pub mod download_daily_count;
pub mod feedback;
pub mod invite;
pub mod notification;
pub mod rate_limit;
pub mod stripe;
pub mod tier;
pub mod token;
pub mod totp;
pub mod user;

// Re-export repositories
pub use application::ApplicationRepository;
pub use audit::AuditLogRepository;
pub use download_cache::DownloadCacheRepository;
pub use download_daily_count::DownloadDailyCountRepository;
pub use feedback::FeedbackRepository;
pub use invite::InviteRepository;
pub use notification::NotificationRepository;
pub use rate_limit::RateLimitRepository;
pub use stripe::StripeConfigRepository;
pub use tier::TierConfigRepository;
pub use token::TokenRepository;
pub use totp::TotpRepository;
pub use user::UserRepository;
