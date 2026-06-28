//! Database models
//!
//! This module contains all database models and data transfer objects.

pub mod application;
pub mod application_group;
pub mod audit;
pub mod download;
pub mod entitlement;
pub mod feedback;
pub mod membership;
pub mod oauth_client_user_tenant;
pub mod rate_limit;
pub mod stripe;
pub mod tier;
pub mod token;
pub mod totp;
pub mod user;

// Re-export commonly used types
pub use application::{
    Application, ApplicationResponse, CreateApplication, DeleteApplicationRequest,
    DistributionConfig, SwapApplicationOrderRequest, UpdateApplication,
    ARTIFACT_SOURCE_GENERIC_PACKAGE, ARTIFACT_SOURCE_RELEASE,
};
pub use application_group::{
    ApplicationGroup, CreateApplicationGroup, SetApplicationGroupRequest, UpdateApplicationGroup,
};
pub use audit::{
    AdminNotification, AuditAction, AuditLog, AuditSeverity, CreateAdminNotification,
    CreateAuditLog, NotificationType,
};
pub use download::{
    AppDownloadGroup, AppDownloadsResponse, AppOciImage, DownloadAsset, DownloadCacheRow,
    ReleaseAsset, ReleaseMetadata,
};
pub use entitlement::{ApplicationEntitlement, UserEntitlementRow};
pub use feedback::{
    AdminFeedbackDetail, AdminFeedbackSummary, ArchivedFeedbackItem, CreateFeedback, Feedback,
    FeedbackAttachmentMeta, FeedbackStatus, FeedbackSubmissionResponse, RespondToFeedback,
    RespondToFeedbackRequest, UpdateFeedbackStatusRequest,
};
pub use membership::{AdminMembershipResponse, MembershipResponse};
pub use oauth_client_user_tenant::{CreateUserTenantAssignment, OAuthClientUserTenant};
pub use rate_limit::{RateLimit, RateLimitConfig};
pub use stripe::{
    StripeConfig, StripeConfigResponse, StripeInvoiceResponse, StripePriceResponse,
    StripeProductResponse, StripeSubscriptionItemResponse, StripeSubscriptionResponse,
    StripeWebhookEndpointResponse,
};
pub use tier::{TierConfigResponse, TierConfigRow};
pub use token::{
    AdminInvite, CreateAdminInvite, CreateEmailChangeRequest, CreateEmailVerificationToken,
    CreateMagicLinkToken, CreatePasswordResetToken, CreateRefreshToken, CreateTrustedDevice,
    EmailChangeRequest, EmailVerificationToken, MagicLinkToken, PasswordResetToken, RefreshToken,
    SessionInfo, TrustedDevice, TrustedDeviceInfo,
};
pub use totp::{RecoveryCode, UserTotp};
pub use user::{CreateUser, MembershipStatus, SubscriptionTier, User, UserResponse, UserRole};
