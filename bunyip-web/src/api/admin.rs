//! Admin API calls.

use serde_json::{json, Value};

use super::types::{
    AdminApplication, AdminApplicationList, AdminAuditLog, AdminFeedbackSummary, AdminMembership,
    AdminStatsResponse, AdminUser, FeedbackStatus, PaginatedResponse, StripeConfigResponse,
    TierConfigResponse,
};
use super::{ok_data, parse, Api, ApiError};

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
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

pub async fn users(api: &Api, cookie: Option<&str>, page: u32, page_size: u32, search: &str) -> Result<PaginatedResponse<AdminUser>, ApiError> {
    let mut path = format!("/admin/users?page={page}&page_size={page_size}");
    if !search.is_empty() {
        path.push_str(&format!("&search={}", urlencode(search)));
    }
    parse(api.get(&path, cookie).await?)
}

pub async fn update_user_role(api: &Api, cookie: Option<&str>, user_id: &str, role: &str) -> Result<(), ApiError> {
    let r = api.put(&format!("/admin/users/{user_id}/role"), cookie, Some(json!({ "role": role }))).await?;
    ok_data(&r).map(|_| ())
}

pub async fn delete_user(api: &Api, cookie: Option<&str>, user_id: &str) -> Result<(), ApiError> {
    let r = api.delete(&format!("/admin/users/{user_id}"), cookie, None).await?;
    ok_data(&r).map(|_| ())
}

// --- memberships ------------------------------------------------------------

pub async fn memberships(api: &Api, cookie: Option<&str>, page: u32, page_size: u32, status: &str) -> Result<PaginatedResponse<AdminMembership>, ApiError> {
    let mut path = format!("/admin/memberships?page={page}&page_size={page_size}");
    if !status.is_empty() {
        path.push_str(&format!("&status={status}"));
    }
    parse(api.get(&path, cookie).await?)
}

// --- applications -----------------------------------------------------------

pub async fn applications(api: &Api, cookie: Option<&str>) -> Result<Vec<AdminApplication>, ApiError> {
    let list: AdminApplicationList = parse(api.get("/admin/applications", cookie).await?)?;
    Ok(list.applications)
}

pub async fn update_application(api: &Api, cookie: Option<&str>, app_id: &str, body: Value) -> Result<(), ApiError> {
    let r = api.put(&format!("/admin/applications/{app_id}"), cookie, Some(body)).await?;
    ok_data(&r).map(|_| ())
}

// --- audit logs -------------------------------------------------------------

pub async fn audit_logs(api: &Api, cookie: Option<&str>, page: u32, page_size: u32, admin_only: bool) -> Result<PaginatedResponse<AdminAuditLog>, ApiError> {
    let mut path = format!("/admin/audit-logs?page={page}&page_size={page_size}");
    if admin_only {
        path.push_str("&admin_only=true");
    }
    parse(api.get(&path, cookie).await?)
}

// --- feedback ---------------------------------------------------------------

pub async fn feedback(api: &Api, cookie: Option<&str>, page: u32, page_size: u32) -> Result<PaginatedResponse<AdminFeedbackSummary>, ApiError> {
    parse(api.get(&format!("/admin/feedback?page={page}&page_size={page_size}"), cookie).await?)
}

pub async fn update_feedback_status(api: &Api, cookie: Option<&str>, id: &str, status: FeedbackStatus) -> Result<(), ApiError> {
    let r = api.put(&format!("/admin/feedback/{id}/status"), cookie, Some(json!({ "status": feedback_status_str(status) }))).await?;
    ok_data(&r).map(|_| ())
}

// --- stripe + tier config ---------------------------------------------------

pub async fn stripe_config(api: &Api, cookie: Option<&str>) -> Result<StripeConfigResponse, ApiError> {
    parse(api.get("/admin/stripe", cookie).await?)
}

pub async fn update_stripe_config(api: &Api, cookie: Option<&str>, body: Value) -> Result<(), ApiError> {
    let r = api.put("/admin/stripe", cookie, Some(body)).await?;
    ok_data(&r).map(|_| ())
}

pub async fn tier_config(api: &Api, cookie: Option<&str>) -> Result<TierConfigResponse, ApiError> {
    parse(api.get("/admin/tier-config", cookie).await?)
}

pub async fn update_tier_config(api: &Api, cookie: Option<&str>, body: Value) -> Result<(), ApiError> {
    let r = api.put("/admin/tier-config", cookie, Some(body)).await?;
    ok_data(&r).map(|_| ())
}
