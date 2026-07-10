//! Request handlers
//!
//! This module contains all HTTP request handlers organized by domain.

use std::sync::Arc;

use sqlx::PgPool;

use crate::errors::AppError;
use crate::models::RateLimitConfig;
use crate::repositories::{RateLimitRepository, TotpRepository};
use crate::services::TotpService;

/// Check a rate limit and return `RateLimited` when the window is exceeded.
///
/// Single shared implementation for every handler that gates on a
/// `RateLimitConfig` (auth, totp, feedback). Increments the counter and, when
/// the cap is hit, looks up the reset window so the error carries an accurate
/// `Retry-After`.
/// Whether a rate-limit trip should be logged, given the post-increment
/// `count` and the window `max_requests`. Only the FIRST request past the cap
/// in a window is logged (`count == max_requests + 1`); the counter increments
/// monotonically on every attempt within the window, so later over-limit
/// requests are silent. This keeps a credential-stuffing burst from flooding
/// the admin error log and evicting other diagnostics from the shared ring
/// (BUNYIP-327 review). The counter resets when the window rolls over, so each
/// new window logs its first trip again. Pure + unit-tested.
fn should_log_rate_limit_trip(count: i32, max_requests: i32) -> bool {
    count == max_requests + 1
}

pub(crate) async fn check_rate_limit(
    pool: &PgPool,
    key: &str,
    config: &RateLimitConfig,
) -> Result<(), AppError> {
    let (count, exceeded) = RateLimitRepository::check_and_increment(pool, key, config).await?;
    if exceeded {
        let retry_after = RateLimitRepository::get_retry_after(pool, key, config).await?;
        // BUNYIP-327: surface the trip at ERROR with the affected client so it
        // lands in the admin error-log view and is attributable. `key` is the
        // client identity for this action (IP or email, per the caller). Logged
        // once per window (see `should_log_rate_limit_trip`) so a burst does not
        // flood the buffer; the 429 itself is still returned on every request.
        if should_log_rate_limit_trip(count, config.max_requests) {
            tracing::error!(
                category = "rate_limit",
                client = %key,
                action = %config.action,
                retry_after,
                "rate limit exceeded"
            );
        }
        return Err(AppError::RateLimited { retry_after });
    }
    Ok(())
}

/// Require a fresh TOTP (or recovery) code for a sensitive operation when the
/// account has 2FA enabled (BUNYIP-138). A no-op for accounts without a
/// verified TOTP. A trusted-device cookie never satisfies this; only a live
/// code does. Shared by password change and email change.
/// Whether a sensitive operation must demand a fresh TOTP code, given whether
/// the account has a verified TOTP. Pure decision (BUNYIP-138, unit-tested): a
/// trusted-device cookie never enters this; only a live code satisfies the
/// gate.
fn totp_reprompt_required(has_verified_totp: bool) -> bool {
    has_verified_totp
}

pub(crate) async fn require_totp_if_enabled(
    pool: &PgPool,
    totp_service: &Arc<TotpService>,
    user_id: uuid::Uuid,
    code: Option<&str>,
) -> Result<(), AppError> {
    let totp = TotpRepository::find_by_user_id(pool, user_id).await?;
    let has_verified = totp.map(|t| t.verified).unwrap_or(false);
    if !totp_reprompt_required(has_verified) {
        return Ok(());
    }
    let code = code
        .map(|c| c.trim().replace(' ', ""))
        .filter(|c| !c.is_empty())
        .ok_or_else(|| AppError::validation("totp_code", "Two-factor code required"))?;
    let ok = if code.contains('-') || code.len() > 6 {
        totp_service.verify_recovery_code(user_id, &code).await?
    } else {
        totp_service.verify_code(user_id, &code).await?
    };
    if !ok {
        return Err(AppError::validation(
            "totp_code",
            "Invalid verification code",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{should_log_rate_limit_trip, totp_reprompt_required};

    #[test]
    fn totp_reprompt_required_only_when_2fa_enabled() {
        // A trusted-device cookie does not enter this decision; only whether a
        // verified TOTP exists does (BUNYIP-138).
        assert!(totp_reprompt_required(true));
        assert!(!totp_reprompt_required(false));
    }

    #[test]
    fn rate_limit_trip_logs_only_the_first_over_limit_request() {
        // Config allowing 5/window: counts 1..=5 are within cap (not even a
        // trip); count 6 is the first over-limit request and is the only one
        // logged; counts 7+ in the same window stay silent (BUNYIP-327).
        let max = 5;
        assert!(
            !should_log_rate_limit_trip(5, max),
            "at the cap is not a trip"
        );
        assert!(should_log_rate_limit_trip(6, max), "first over-limit logs");
        assert!(
            !should_log_rate_limit_trip(7, max),
            "second over-limit is silent"
        );
        assert!(
            !should_log_rate_limit_trip(100, max),
            "later bursts stay silent"
        );
    }
}

pub mod admin;
pub mod admin_entitlements;
pub mod admin_ip_bans;
pub mod admin_oauth_tenants;
pub mod admin_rate_limits;
pub mod admin_stripe;
pub mod application;
pub mod auth;
pub mod billing;
pub mod download;
pub mod events;
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
    request_password_reset, setup_status, verify_magic_link, verify_password_reset_token,
};
pub use billing::{create_setup_intent, download_invoice, list_invoices};
pub use download::{admin_refresh_release, download_asset, list_all_downloads, list_app_downloads};
pub use events::events_stream;
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
    begin_rekey, confirm_2fa, confirm_rekey, disable_2fa, get_2fa_status,
    regenerate_recovery_codes, setup_2fa, verify_2fa,
};
pub use user::{
    change_password, confirm_email_change, confirm_email_verification, delete_account,
    get_current_user, grant_consent, list_sessions, list_trusted_devices, request_email_change,
    request_email_verification, revoke_other_sessions, revoke_session, revoke_trusted_device,
    update_current_user_profile,
};
pub use webhook::stripe_webhook;

// Admin handlers
pub use admin::{
    admin_reset_password, create_admin_invite, create_application, create_application_group,
    delete_application, delete_application_group, delete_user, export_seed_data,
    get_auto_ban_config, get_dashboard_stats, get_email_config, get_error_logs, get_key_health,
    get_key_health_by_id, get_stripe_config, get_system_health, get_tier_config, get_user,
    grant_lifetime_membership, grant_membership, impersonate_user, import_seed_data,
    key_rotation_status, list_admin_invites, list_all_application_groups, list_all_applications,
    list_audit_logs, list_memberships, list_notifications, list_seed_templates, list_users,
    mark_all_notifications_read, mark_notification_read, reencrypt_key, replay_account_delete,
    reset_user_two_factor, revoke_admin_invite, revoke_lifetime_membership, revoke_membership,
    send_test_email, set_application_group, swap_application_order, update_application,
    update_application_group, update_auto_ban_config, update_email_config, update_stripe_config,
    update_tier_config, update_user_email, update_user_role, update_user_status, verify_user_email,
};
pub use admin_entitlements::{
    add_price_mapping, grant_entitlement, list_user_entitlements, remove_price_mapping,
    revoke_entitlement, set_application_restricted,
};
pub use admin_ip_bans::{list_ip_bans, unban_ip};
pub use admin_oauth_tenants::{assign_user_tenant, list_client_assignments, unassign_user_tenant};
pub use admin_rate_limits::{list_rate_limits, reset_rate_limit};
pub use admin_stripe::{
    archive_stripe_price, archive_stripe_product, create_stripe_price, create_stripe_product,
    create_stripe_webhook, delete_stripe_webhook, list_stripe_prices, list_stripe_products,
    list_stripe_webhooks, update_stripe_product,
};
