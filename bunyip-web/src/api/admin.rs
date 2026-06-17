//! Admin API calls.

use serde_json::{json, Value};

use super::types::{
    AdminApplication, AdminApplicationList, AdminAuditLog, AdminFeedbackDetail,
    AdminFeedbackSummary, AdminMembership, AdminStatsResponse, AdminUser, ApplicationGroup,
    ApplicationGroupList, ArchivedFeedback, FeedbackStatus, PaginatedResponse,
    StripeConfigResponse, TierConfigResponse, UserEntitlement,
};
use super::{ok_data, parse, Api, ApiError};
use crate::util::urlenc;

// --- stats ------------------------------------------------------------------

pub async fn stats(api: &Api, cookie: Option<&str>) -> Result<AdminStatsResponse, ApiError> {
    parse(api.get("/admin/stats", cookie).await?)
}

// --- users ------------------------------------------------------------------

pub async fn users(
    api: &Api,
    cookie: Option<&str>,
    page: u32,
    page_size: u32,
    search: &str,
    suspended: bool,
) -> Result<PaginatedResponse<AdminUser>, ApiError> {
    let mut path = format!("/admin/users?page={page}&page_size={page_size}");
    if !search.is_empty() {
        path.push_str(&format!("&search={}", urlenc(search)));
    }
    // `active=false` flips the API to the soft-deleted side so suspended users
    // can be listed and reactivated (BUNYIP-120).
    if suspended {
        path.push_str("&active=false");
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

pub async fn memberships(
    api: &Api,
    cookie: Option<&str>,
    page: u32,
    page_size: u32,
    status: &str,
) -> Result<PaginatedResponse<AdminMembership>, ApiError> {
    let mut path = format!("/admin/memberships?page={page}&page_size={page_size}");
    if !status.is_empty() {
        path.push_str(&format!("&status={status}"));
    }
    parse(api.get(&path, cookie).await?)
}

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
