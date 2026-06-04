//! Admin API calls.

use serde_json::{json, Value};

use super::types::{
    AdminApplication, AdminApplicationList, AdminAuditLog, AdminFeedbackSummary, AdminMembership,
    AdminStatsResponse, AdminUser, FeedbackStatus, PaginatedResponse, StripeConfigResponse,
    TierConfigResponse, UserEntitlement,
};
use super::{ok_data, parse, Api, ApiError};

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

pub fn feedback_status_str(s: FeedbackStatus) -> &'static str {
    match s {
        FeedbackStatus::New => "new",
        FeedbackStatus::Reviewed => "reviewed",
        FeedbackStatus::Responded => "responded",
        FeedbackStatus::Closed => "closed",
    }
}

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
) -> Result<PaginatedResponse<AdminUser>, ApiError> {
    let mut path = format!("/admin/users?page={page}&page_size={page_size}");
    if !search.is_empty() {
        path.push_str(&format!("&search={}", urlencode(search)));
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

pub async fn delete_user(api: &Api, cookie: Option<&str>, user_id: &str) -> Result<(), ApiError> {
    let r = api
        .delete(&format!("/admin/users/{user_id}"), cookie, None)
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

/// Soft-delete a user. (PUT /admin/users/{id}/status with active=false.) The
/// backend rejects active=true today, so this only handles the suspend
/// direction; reactivation is a follow-up that needs a new endpoint.
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

pub async fn feedback(
    api: &Api,
    cookie: Option<&str>,
    page: u32,
    page_size: u32,
) -> Result<PaginatedResponse<AdminFeedbackSummary>, ApiError> {
    parse(
        api.get(
            &format!("/admin/feedback?page={page}&page_size={page_size}"),
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
            Some(json!({ "status": feedback_status_str(status) })),
        )
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
