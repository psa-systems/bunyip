//! Admin API calls.

use serde_json::{json, Value};

use super::types::{
    AdminApplication, AdminApplicationList, AdminAuditLog, AdminFeedbackDetail,
    AdminFeedbackSummary, AdminIpBan, AdminRateLimit, AdminRateLimitConfig, AdminStatsResponse,
    AdminUser, AppDoc, ApplicationGroup, ApplicationGroupList, ArchivedFeedback,
    AutoBanConfigResponse, EmailConfigResponse, ErrorLogsResponse, FeedbackStatus, ImportSummary,
    PaginatedResponse, RestoreReport, SeedTemplateInfo, StripeConfigResponse, StripePrice,
    StripeProduct, TierConfigResponse, UserEntitlement,
};
use super::{ok_data, parse, Api, ApiError};
use crate::util::urlenc;

// --- stats ------------------------------------------------------------------

pub async fn stats(api: &Api, cookie: Option<&str>) -> Result<AdminStatsResponse, ApiError> {
    parse(api.get("/admin/stats", cookie).await?)
}

// --- users ------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn users(
    api: &Api,
    cookie: Option<&str>,
    page: u32,
    page_size: u32,
    search: &str,
    // BUNYIP-410 overhaul: soft-delete segment - "active" / "suspended" / "all".
    status: &str,
    // Empty `tier` / `None` `verified` = unfiltered.
    tier: &str,
    verified: Option<bool>,
    // Whitelisted sort column + direction ("asc" / "desc"); empty = server
    // default (newest-first).
    sort: &str,
    dir: &str,
) -> Result<PaginatedResponse<AdminUser>, ApiError> {
    let mut path = format!("/admin/users?page={page}&page_size={page_size}");
    if !search.is_empty() {
        path.push_str(&format!("&search={}", urlenc(search)));
    }
    // The API's `active` flag is tri-state: true = live only, false =
    // soft-deleted only (BUNYIP-120), omitted = both ("All"). Send it explicitly
    // for active/suspended so the default page is not the "All" view.
    match status {
        "suspended" => path.push_str("&active=false"),
        "all" => {}
        _ => path.push_str("&active=true"),
    }
    if !tier.is_empty() {
        path.push_str(&format!("&tier={}", urlenc(tier)));
    }
    if let Some(v) = verified {
        path.push_str(&format!("&verified={v}"));
    }
    if !sort.is_empty() {
        path.push_str(&format!("&sort={}&dir={}", urlenc(sort), urlenc(dir)));
    }
    parse(api.get(&path, cookie).await?)
}

pub async fn update_user_role(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
    role: &str,
) -> Result<(), ApiError> {
    let r = api
        .put(
            &format!("/admin/users/{user_id}/role"),
            cookie,
            Some(json!({ "role": role })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Correct a user's email address (BUNYIP-119). PUT /admin/users/{id}/email
/// with `{email, verified}`; the API normalizes + validates the address and
/// rejects a collision with another live account.
pub async fn update_user_email(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
    email: &str,
    verified: bool,
) -> Result<(), ApiError> {
    let r = api
        .put(
            &format!("/admin/users/{user_id}/email"),
            cookie,
            Some(json!({ "email": email, "verified": verified })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Force-verify a user's email (BUNYIP-119). POST /admin/users/{id}/email/verify.
pub async fn verify_user_email(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            &format!("/admin/users/{user_id}/email/verify"),
            cookie,
            None,
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Clear a user's two-factor authentication (BUNYIP-119), letting a locked-out
/// user re-enrol. POST /admin/users/{id}/two-factor/reset.
pub async fn reset_user_two_factor(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            &format!("/admin/users/{user_id}/two-factor/reset"),
            cookie,
            None,
        )
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn delete_user(api: &Api, cookie: Option<&str>, user_id: &str) -> Result<(), ApiError> {
    let r = api
        .delete(&format!("/admin/users/{user_id}"), cookie, None)
        .await?;
    ok_data(&r).map(|_| ())
}

/// Hard-delete an application. The API gates this on the admin's password + 2FA
/// code (DELETE /admin/applications/{id} with a JSON body), so both are required
/// and an invalid value surfaces as a validation ApiError.
pub async fn delete_application(
    api: &Api,
    cookie: Option<&str>,
    app_id: &str,
    password: &str,
    totp_code: &str,
) -> Result<(), ApiError> {
    let r = api
        .delete(
            &format!("/admin/applications/{app_id}"),
            cookie,
            Some(json!({ "password": password, "totp_code": totp_code })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Single-user details for the admin user-detail page. Wraps GET /admin/users/{id}.
pub async fn get_user(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
) -> Result<AdminUser, ApiError> {
    parse(api.get(&format!("/admin/users/{user_id}"), cookie).await?)
}

/// Soft-delete a user. (PUT /admin/users/{id}/status with active=false.)
pub async fn suspend_user(api: &Api, cookie: Option<&str>, user_id: &str) -> Result<(), ApiError> {
    let r = api
        .put(
            &format!("/admin/users/{user_id}/status"),
            cookie,
            Some(json!({ "active": false })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Reactivate a suspended user. (PUT /admin/users/{id}/status with active=true.)
/// The API clears `deleted_at`; it 404s when the id is not a soft-deleted row
/// (already active or unknown), so reactivation cannot silently no-op (BUNYIP-120).
pub async fn reactivate_user(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .put(
            &format!("/admin/users/{user_id}/status"),
            cookie,
            Some(json!({ "active": true })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Admin-triggered password reset. The backend emails the user a reset link.
pub async fn admin_reset_password(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            &format!("/admin/users/{user_id}/reset-password"),
            cookie,
            None,
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Grant lifetime membership. Creates a $0 Stripe subscription on the backend
/// so invoices still flow.
pub async fn grant_lifetime(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(&format!("/admin/users/{user_id}/lifetime"), cookie, None)
        .await?;
    ok_data(&r).map(|_| ())
}

/// Revoke a previously-granted lifetime membership. Returns the user to the
/// standard tier with no active subscription.
pub async fn revoke_lifetime(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            &format!("/admin/users/{user_id}/lifetime/revoke"),
            cookie,
            None,
        )
        .await?;
    ok_data(&r).map(|_| ())
}

// --- memberships ------------------------------------------------------------
//
// BUNYIP-410: the members-by-tier list fetch (`memberships`) was removed with
// the standalone Memberships page (tier + verified now live on the users list).
// The grant / revoke override actions below stay - they remain reachable via
// `/admin/memberships/{id}/grant|revoke`, which now redirect to the user detail.

/// Grant an admin-override membership (free tier, `subscription_override_by` set
/// to the acting admin). Wraps POST /admin/memberships/grant. BUNYIP-118.
pub async fn grant_membership(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            "/admin/memberships/grant",
            cookie,
            Some(json!({ "user_id": user_id })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Revoke an admin-override membership: cancels status, resets tier to standard
/// and clears `subscription_override_by`. Wraps POST /admin/memberships/revoke.
/// BUNYIP-118.
pub async fn revoke_membership(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            "/admin/memberships/revoke",
            cookie,
            Some(json!({ "user_id": user_id })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

// --- applications -----------------------------------------------------------

pub async fn applications(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<AdminApplication>, ApiError> {
    let list: AdminApplicationList = parse(api.get("/admin/applications", cookie).await?)?;
    Ok(list.applications)
}

pub async fn update_application(
    api: &Api,
    cookie: Option<&str>,
    app_id: &str,
    body: Value,
) -> Result<(), ApiError> {
    let r = api
        .put(&format!("/admin/applications/{app_id}"), cookie, Some(body))
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn create_application(
    api: &Api,
    cookie: Option<&str>,
    body: Value,
) -> Result<(), ApiError> {
    let r = api.post("/admin/applications", cookie, Some(body)).await?;
    ok_data(&r).map(|_| ())
}

/// Swap the sort order of two applications, moving `app_id` past its neighbour
/// `target_app_id` in the admin list. BUNYIP-121.
pub async fn swap_application_order(
    api: &Api,
    cookie: Option<&str>,
    app_id: &str,
    target_app_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .put(
            &format!("/admin/applications/{app_id}/swap-order"),
            cookie,
            Some(json!({ "target_app_id": target_app_id })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Assign an application to a group, or clear it (`group_id = null`). BUNYIP-100.
pub async fn set_application_group(
    api: &Api,
    cookie: Option<&str>,
    app_id: &str,
    group_id: Option<&str>,
) -> Result<(), ApiError> {
    let r = api
        .put(
            &format!("/admin/applications/{app_id}/group"),
            cookie,
            Some(json!({ "group_id": group_id })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

// --- application groups (BUNYIP-100) ----------------------------------------

pub async fn application_groups(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<ApplicationGroup>, ApiError> {
    let list: ApplicationGroupList = parse(api.get("/admin/application-groups", cookie).await?)?;
    Ok(list.groups)
}

pub async fn create_application_group(
    api: &Api,
    cookie: Option<&str>,
    body: Value,
) -> Result<(), ApiError> {
    let r = api
        .post("/admin/application-groups", cookie, Some(body))
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn update_application_group(
    api: &Api,
    cookie: Option<&str>,
    group_id: &str,
    body: Value,
) -> Result<(), ApiError> {
    let r = api
        .put(
            &format!("/admin/application-groups/{group_id}"),
            cookie,
            Some(body),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn delete_application_group(
    api: &Api,
    cookie: Option<&str>,
    group_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .delete(
            &format!("/admin/application-groups/{group_id}"),
            cookie,
            None,
        )
        .await?;
    ok_data(&r).map(|_| ())
}

// --- entitlements -----------------------------------------------------------

pub async fn list_user_entitlements(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
) -> Result<Vec<UserEntitlement>, ApiError> {
    parse(
        api.get(&format!("/admin/users/{user_id}/entitlements"), cookie)
            .await?,
    )
}

pub async fn grant_user_entitlement(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
    slug: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            &format!("/admin/users/{user_id}/entitlements"),
            cookie,
            Some(json!({ "slug": slug })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn revoke_user_entitlement(
    api: &Api,
    cookie: Option<&str>,
    user_id: &str,
    slug: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            &format!("/admin/users/{user_id}/entitlements/revoke"),
            cookie,
            Some(json!({ "slug": slug })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn set_application_restricted(
    api: &Api,
    cookie: Option<&str>,
    slug: &str,
    requires_entitlement: bool,
) -> Result<(), ApiError> {
    let r = api
        .put(
            &format!("/admin/applications/{slug}/restricted"),
            cookie,
            Some(json!({ "requires_entitlement": requires_entitlement })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

// --- audit logs -------------------------------------------------------------

pub async fn audit_logs(
    api: &Api,
    cookie: Option<&str>,
    page: u32,
    page_size: u32,
    admin_only: bool,
) -> Result<PaginatedResponse<AdminAuditLog>, ApiError> {
    let mut path = format!("/admin/audit-logs?page={page}&page_size={page_size}");
    if admin_only {
        path.push_str("&admin_only=true");
    }
    parse(api.get(&path, cookie).await?)
}

// --- error log (BUNYIP-327) -------------------------------------------------

/// Fetch the in-memory error-log ring buffer, optionally filtered to one
/// category. Newest-first; the buffer is bounded so no pagination is needed.
pub async fn error_logs(
    api: &Api,
    cookie: Option<&str>,
    category: Option<&str>,
) -> Result<ErrorLogsResponse, ApiError> {
    let path = match category {
        Some(c) if !c.is_empty() => format!("/admin/logs?category={}", urlenc(c)),
        _ => "/admin/logs".to_string(),
    };
    parse(api.get(&path, cookie).await?)
}

// --- seed data import (PSA-52) ----------------------------------------------

/// Load a canonical seed file through the API's shared loader. The file is a
/// pre-parsed JSON value (the web handler validates it is JSON first). Export
/// is a direct download via `Api::get_stream`, so it needs no client method.
pub async fn import_seed(
    api: &Api,
    cookie: Option<&str>,
    file: Value,
) -> Result<ImportSummary, ApiError> {
    parse(api.post("/admin/seed/import", cookie, Some(file)).await?)
}

/// List the embedded seed templates (PSA-57) for the first-run setup picker.
/// Wraps `GET /v1/admin/seed/templates`, whose `data` is a bare array.
pub async fn seed_templates(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<SeedTemplateInfo>, ApiError> {
    parse(api.get("/admin/seed/templates", cookie).await?)
}

/// Load a named embedded template through the API loader (PSA-57). Sends the
/// name as the `?template=` query with no body; the API 400s an unknown name.
pub async fn import_seed_template(
    api: &Api,
    cookie: Option<&str>,
    name: &str,
) -> Result<ImportSummary, ApiError> {
    let path = format!("/admin/seed/import?template={}", urlenc(name));
    parse(api.post(&path, cookie, None).await?)
}

// --- IP auto-bans (BUNYIP-320) ----------------------------------------------

/// List the currently-active IP auto-bans (IP, reason, strikes, banned-at,
/// expires-at). Wraps `GET /v1/admin/ip-bans` (BUNYIP-319), whose `data` is a
/// bare array of ban objects.
pub async fn ip_bans(api: &Api, cookie: Option<&str>) -> Result<Vec<AdminIpBan>, ApiError> {
    parse(api.get("/admin/ip-bans", cookie).await?)
}

/// Ban `ip` by hand for `duration_secs` with `reason` (BUNYIP-413). Wraps
/// `POST /v1/admin/ip-bans`, which is super-admin-only and audits the ban; a
/// non-super-admin gets a 403 that surfaces as a permission ApiError.
pub async fn create_ip_ban(
    api: &Api,
    cookie: Option<&str>,
    ip: &str,
    reason: &str,
    duration_secs: i64,
) -> Result<(), ApiError> {
    let r = api
        .post(
            "/admin/ip-bans",
            cookie,
            Some(json!({ "ip": ip, "reason": reason, "duration_secs": duration_secs })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Lift the auto-ban for `ip`, effective on the next request. Wraps
/// `DELETE /v1/admin/ip-bans/{ip}` (BUNYIP-319); the API audits the lift and
/// 404s when the IP was not banned. `ip` is percent-encoded into the path so an
/// IPv6 address (with `:`) is a single safe path segment.
pub async fn unban_ip(api: &Api, cookie: Option<&str>, ip: &str) -> Result<(), ApiError> {
    let r = api
        .delete(&format!("/admin/ip-bans/{}", urlenc(ip)), cookie, None)
        .await?;
    ok_data(&r).map(|_| ())
}

// --- rate limits (BUNYIP-317) -----------------------------------------------

/// List the currently-active throttles (user/IP, action, count/cap, window
/// start, retry-in), each resolved to a user where possible. Wraps
/// `GET /v1/admin/rate-limits` (BUNYIP-315), which paginates the unified list;
/// the API's page-size query param is `per_page`.
pub async fn rate_limits(
    api: &Api,
    cookie: Option<&str>,
    page: u32,
    per_page: u32,
) -> Result<PaginatedResponse<AdminRateLimit>, ApiError> {
    parse(
        api.get(
            &format!("/admin/rate-limits?page={page}&per_page={per_page}"),
            cookie,
        )
        .await?,
    )
}

/// Clear one active throttle so the affected user/IP can act again immediately.
/// Wraps `POST /v1/admin/rate-limits/reset` (BUNYIP-316); `action` and `key` are
/// exactly the identifiers `rate_limits` returns for the row. The API audits the
/// reset and 400s on an unknown action, which surfaces as a validation ApiError.
pub async fn reset_rate_limit(
    api: &Api,
    cookie: Option<&str>,
    action: &str,
    key: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            "/admin/rate-limits/reset",
            cookie,
            Some(json!({ "action": action, "key": key })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

// --- rate-limit configuration (BUNYIP-413) ----------------------------------

/// The configured cap/window for every known rate-limit action, marking which
/// ones a persisted override is in force for. Wraps
/// `GET /v1/admin/rate-limit-configs`, whose `data` is a bare array.
pub async fn rate_limit_configs(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<AdminRateLimitConfig>, ApiError> {
    parse(api.get("/admin/rate-limit-configs", cookie).await?)
}

/// Create or update the persisted override for `action`. Wraps
/// `PUT /v1/admin/rate-limit-configs/{action}`, which is super-admin-only,
/// audits the change and 400s on an unknown action or out-of-range values.
pub async fn set_rate_limit_config(
    api: &Api,
    cookie: Option<&str>,
    action: &str,
    max_requests: i32,
    window_seconds: i64,
) -> Result<(), ApiError> {
    let r = api
        .put(
            &format!("/admin/rate-limit-configs/{}", urlenc(action)),
            cookie,
            Some(json!({ "max_requests": max_requests, "window_seconds": window_seconds })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Drop the persisted override for `action`, reverting it to the bootstrap
/// default. Wraps `DELETE /v1/admin/rate-limit-configs/{action}`, which 404s
/// when no override was in force.
pub async fn delete_rate_limit_config(
    api: &Api,
    cookie: Option<&str>,
    action: &str,
) -> Result<(), ApiError> {
    let r = api
        .delete(
            &format!("/admin/rate-limit-configs/{}", urlenc(action)),
            cookie,
            None,
        )
        .await?;
    ok_data(&r).map(|_| ())
}

// --- feedback ---------------------------------------------------------------

/// Feedback list bucketed by admin tab (BUNYIP-92). Bucket strings map
/// 1:1 to the API's accepted set: `active` (default, excludes closed +
/// spam), `closed` (closed and not spam), `spam` (is_spam=true, any
/// status). The `archive` view has its own endpoint.
pub async fn feedback(
    api: &Api,
    cookie: Option<&str>,
    page: u32,
    page_size: u32,
    bucket: &str,
) -> Result<PaginatedResponse<AdminFeedbackSummary>, ApiError> {
    parse(
        api.get(
            &format!("/admin/feedback?page={page}&page_size={page_size}&bucket={bucket}"),
            cookie,
        )
        .await?,
    )
}

pub async fn update_feedback_status(
    api: &Api,
    cookie: Option<&str>,
    id: &str,
    status: FeedbackStatus,
) -> Result<(), ApiError> {
    let r = api
        .put(
            &format!("/admin/feedback/{id}/status"),
            cookie,
            Some(json!({ "status": status.as_str() })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn feedback_detail(
    api: &Api,
    cookie: Option<&str>,
    id: &str,
) -> Result<AdminFeedbackDetail, ApiError> {
    parse(api.get(&format!("/admin/feedback/{id}"), cookie).await?)
}

/// POST `/v1/admin/feedback/{id}/respond` with `{response, status?}`. When
/// `status` is `None` the API defaults the row to `Responded`; we pass the
/// explicit `Responded` for clarity. The bunyip-api handler sends an email
/// to the original submitter when they left an email address.
pub async fn respond_to_feedback(
    api: &Api,
    cookie: Option<&str>,
    id: &str,
    response: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            &format!("/admin/feedback/{id}/respond"),
            cookie,
            Some(json!({
                "response": response,
                "status": FeedbackStatus::Responded.as_str(),
            })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn feedback_archive(
    api: &Api,
    cookie: Option<&str>,
    page: u32,
    page_size: u32,
) -> Result<PaginatedResponse<ArchivedFeedback>, ApiError> {
    parse(
        api.get(
            &format!("/admin/feedback/archive?page={page}&page_size={page_size}"),
            cookie,
        )
        .await?,
    )
}

pub async fn restore_feedback(
    api: &Api,
    cookie: Option<&str>,
    archive_id: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(
            &format!("/admin/feedback/archive/{archive_id}/restore"),
            cookie,
            None,
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// BUNYIP-92: flip `is_spam` to TRUE.
pub async fn mark_feedback_spam(api: &Api, cookie: Option<&str>, id: &str) -> Result<(), ApiError> {
    let r = api
        .post(&format!("/admin/feedback/{id}/mark-spam"), cookie, None)
        .await?;
    ok_data(&r).map(|_| ())
}

/// BUNYIP-92: flip `is_spam` back to FALSE (false-positive recovery).
pub async fn unmark_feedback_spam(
    api: &Api,
    cookie: Option<&str>,
    id: &str,
) -> Result<(), ApiError> {
    let r = api
        .post(&format!("/admin/feedback/{id}/unmark-spam"), cookie, None)
        .await?;
    ok_data(&r).map(|_| ())
}

/// BUNYIP-92: hard delete. Writes a `FeedbackDeleted` audit row on the
/// API; the row is unrecoverable after this returns.
pub async fn delete_feedback(api: &Api, cookie: Option<&str>, id: &str) -> Result<(), ApiError> {
    let r = api
        .delete(&format!("/admin/feedback/{id}"), cookie, None)
        .await?;
    ok_data(&r).map(|_| ())
}

/// BUNYIP-93: move a single row from `feedback` to `feedback_archive`.
/// Reversible via the existing archive-restore endpoint.
pub async fn archive_feedback(api: &Api, cookie: Option<&str>, id: &str) -> Result<(), ApiError> {
    let r = api
        .post(&format!("/admin/feedback/{id}/archive"), cookie, None)
        .await?;
    ok_data(&r).map(|_| ())
}

// --- stripe + tier config ---------------------------------------------------

pub async fn stripe_config(
    api: &Api,
    cookie: Option<&str>,
) -> Result<StripeConfigResponse, ApiError> {
    parse(api.get("/admin/stripe", cookie).await?)
}

pub async fn update_stripe_config(
    api: &Api,
    cookie: Option<&str>,
    body: Value,
) -> Result<(), ApiError> {
    let r = api.put("/admin/stripe", cookie, Some(body)).await?;
    ok_data(&r).map(|_| ())
}

// --- stripe products + prices (BUNYIP-416) ----------------------------------

pub async fn list_stripe_products(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<StripeProduct>, ApiError> {
    parse(api.get("/admin/stripe/products", cookie).await?)
}

pub async fn create_stripe_product(
    api: &Api,
    cookie: Option<&str>,
    body: Value,
) -> Result<(), ApiError> {
    let r = api
        .post("/admin/stripe/products", cookie, Some(body))
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn archive_stripe_product(
    api: &Api,
    cookie: Option<&str>,
    id: &str,
) -> Result<(), ApiError> {
    let r = api
        .delete(&format!("/admin/stripe/products/{id}"), cookie, None)
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn list_stripe_prices(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Vec<StripePrice>, ApiError> {
    parse(api.get("/admin/stripe/prices", cookie).await?)
}

pub async fn create_stripe_price(
    api: &Api,
    cookie: Option<&str>,
    body: Value,
) -> Result<(), ApiError> {
    let r = api.post("/admin/stripe/prices", cookie, Some(body)).await?;
    ok_data(&r).map(|_| ())
}

pub async fn archive_stripe_price(
    api: &Api,
    cookie: Option<&str>,
    id: &str,
) -> Result<(), ApiError> {
    let r = api
        .delete(&format!("/admin/stripe/prices/{id}"), cookie, None)
        .await?;
    ok_data(&r).map(|_| ())
}

pub async fn email_config(
    api: &Api,
    cookie: Option<&str>,
) -> Result<EmailConfigResponse, ApiError> {
    parse(api.get("/admin/email", cookie).await?)
}

pub async fn update_email_config(
    api: &Api,
    cookie: Option<&str>,
    body: Value,
) -> Result<(), ApiError> {
    let r = api.put("/admin/email", cookie, Some(body)).await?;
    ok_data(&r).map(|_| ())
}

/// BUNYIP-353: POST an uploaded account backup bundle to the restore endpoint
/// and return the resulting report. `bundle` is the parsed JSON of the file the
/// admin uploaded.
pub async fn restore_account(
    api: &Api,
    cookie: Option<&str>,
    bundle: Value,
) -> Result<RestoreReport, ApiError> {
    parse(api.post("/account/restore", cookie, Some(bundle)).await?)
}

pub async fn tier_config(api: &Api, cookie: Option<&str>) -> Result<TierConfigResponse, ApiError> {
    parse(api.get("/admin/tier-config", cookie).await?)
}

pub async fn update_tier_config(
    api: &Api,
    cookie: Option<&str>,
    body: Value,
) -> Result<(), ApiError> {
    let r = api.put("/admin/tier-config", cookie, Some(body)).await?;
    ok_data(&r).map(|_| ())
}

pub async fn auto_ban_config(
    api: &Api,
    cookie: Option<&str>,
) -> Result<AutoBanConfigResponse, ApiError> {
    parse(api.get("/admin/auto-ban-config", cookie).await?)
}

pub async fn update_auto_ban_config(
    api: &Api,
    cookie: Option<&str>,
    body: Value,
) -> Result<(), ApiError> {
    let r = api
        .put("/admin/auto-ban-config", cookie, Some(body))
        .await?;
    ok_data(&r).map(|_| ())
}

// --- application docs (BUNYIP-388, admin authoring) -------------------------

/// Admin: all documentation pages for an app (full rows, ordered).
pub async fn app_docs(
    api: &Api,
    cookie: Option<&str>,
    app_id: &str,
) -> Result<Vec<AppDoc>, ApiError> {
    parse(
        api.get(&format!("/admin/applications/{app_id}/docs"), cookie)
            .await?,
    )
}

/// Admin: create a documentation page for an app.
pub async fn create_app_doc(
    api: &Api,
    cookie: Option<&str>,
    app_id: &str,
    slug: &str,
    title: &str,
    body: &str,
    sort_order: i32,
) -> Result<(), ApiError> {
    let r = api
        .post(
            &format!("/admin/applications/{app_id}/docs"),
            cookie,
            Some(json!({ "slug": slug, "title": title, "body": body, "sort_order": sort_order })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Admin: update a documentation page.
pub async fn update_app_doc(
    api: &Api,
    cookie: Option<&str>,
    doc_id: &str,
    slug: &str,
    title: &str,
    body: &str,
    sort_order: i32,
) -> Result<(), ApiError> {
    let r = api
        .put(
            &format!("/admin/application-docs/{doc_id}"),
            cookie,
            Some(json!({ "slug": slug, "title": title, "body": body, "sort_order": sort_order })),
        )
        .await?;
    ok_data(&r).map(|_| ())
}

/// Admin: delete a documentation page.
pub async fn delete_app_doc(api: &Api, cookie: Option<&str>, doc_id: &str) -> Result<(), ApiError> {
    let r = api
        .delete(&format!("/admin/application-docs/{doc_id}"), cookie, None)
        .await?;
    ok_data(&r).map(|_| ())
}
