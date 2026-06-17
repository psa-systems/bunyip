//! Request handlers
//!
//! This module contains all HTTP request handlers organized by domain.

use sqlx::PgPool;

use crate::errors::AppError;
use crate::models::RateLimitConfig;
use crate::repositories::RateLimitRepository;

/// Check a rate limit and return `RateLimited` when the window is exceeded.
///
/// Single shared implementation for every handler that gates on a
/// `RateLimitConfig` (auth, totp, feedback). Increments the counter and, when
/// the cap is hit, looks up the reset window so the error carries an accurate
/// `Retry-After`.
pub(crate) async fn check_rate_limit(
    pool: &PgPool,
    key: &str,
    config: &RateLimitConfig,
) -> Result<(), AppError> {
    let (_count, exceeded) = RateLimitRepository::check_and_increment(pool, key, config).await?;
    if exceeded {
        let retry_after = RateLimitRepository::get_retry_after(pool, key, config).await?;
        return Err(AppError::RateLimited { retry_after });
    }
    Ok(())
}

pub mod admin;
pub mod admin_entitlements;
pub mod admin_oauth_tenants;
pub mod admin_stripe;
pub mod application;
pub mod auth;
pub mod billing;
pub mod download;
pub mod feedback;
pub mod membership;
pub mod totp;
pub mod user;
pub mod webhook;

// Re-export handler functions for convenience
pub use application::{get_application, list_application_groups, list_applications};
pub use auth::{
    accept_admin_invite, auth_redirect, confirm_password_reset, get_memberships, login, logout,
    logout_all, logout_redirect, refresh_token, register, request_magic_link,
    request_password_reset, setup_admin, setup_status, verify_magic_link,
    verify_password_reset_token,
};
pub use billing::{create_setup_intent, download_invoice, list_invoices};
pub use download::{admin_refresh_release, download_asset, list_all_downloads, list_app_downloads};
pub use feedback::{
    archive_feedback, delete_feedback, export_feedback, get_attachment, get_feedback,
    list_feedback, list_feedback_archive, mark_feedback_spam, respond_to_feedback,
    restore_feedback, submit_feedback, unmark_feedback_spam, update_feedback_status,
};
pub use membership::{
    billing_portal, cancel_membership, cancel_membership_immediate, create_checkout,
    get_membership, get_payment_history, reactivate_membership,
};
pub use totp::{
    confirm_2fa, disable_2fa, get_2fa_status, regenerate_recovery_codes, setup_2fa, verify_2fa,
};
pub use user::{
    change_password, confirm_email_change, confirm_email_verification, delete_account,
    get_current_user, list_sessions, request_email_change, request_email_verification,
    revoke_session,
};
pub use webhook::stripe_webhook;

// Admin handlers
pub use admin::{
    admin_reset_password, create_admin_invite, create_application, create_application_group,
    delete_application, delete_application_group, delete_user, get_dashboard_stats, get_key_health,
    get_key_health_by_id, get_stripe_config, get_system_health, get_tier_config, get_user,
    grant_lifetime_membership, grant_membership, impersonate_user, key_rotation_status,
    list_admin_invites, list_all_application_groups, list_all_applications, list_audit_logs,
    list_memberships, list_notifications, list_users, mark_all_notifications_read,
    mark_notification_read, reencrypt_key, reset_user_two_factor, revoke_admin_invite,
    revoke_lifetime_membership, revoke_membership, send_test_email, set_application_group,
    swap_application_order, update_application, update_application_group, update_stripe_config,
    update_tier_config, update_user_email, update_user_role, update_user_status, verify_user_email,
};
pub use admin_entitlements::{
    add_price_mapping, grant_entitlement, list_user_entitlements, remove_price_mapping,
    revoke_entitlement, set_application_restricted,
};
pub use admin_oauth_tenants::{assign_user_tenant, list_client_assignments, unassign_user_tenant};
pub use admin_stripe::{
    archive_stripe_price, archive_stripe_product, create_stripe_price, create_stripe_product,
    create_stripe_webhook, delete_stripe_webhook, list_stripe_prices, list_stripe_products,
    list_stripe_webhooks, update_stripe_product,
};
