//! Admin panel: Memberships.

use axum::body::Body;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::api::types::{
    AdminApplication, AdminAuditLog, AdminErrorLog, AdminFeedbackDetail, AdminIpBan,
    AdminRateLimit, AdminRateLimitConfig, AdminUser, AppRestoreStatus, ApplicationGroup,
    FeedbackAttachmentMeta, FeedbackStatus, RestoreReport, User, UserEntitlement,
};
use crate::auth::AuthCtx;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::{relative_time, urlenc};
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{badge, button_class, error_box, icon, success_box, toggle_switch};
use crate::web::{redirect, redirect_cookies, AppState};

use super::PageQuery;
use super::{pager, title_case};

/// BUNYIP-410: the standalone Memberships page was consolidated into the users
/// list (which now shows tier + verified with a filter bar). `/admin/memberships`
/// redirects to the users list, preserving any tier filter as `?tier=` so old
/// links and bookmarks land on the filtered view. The grant / revoke actions
/// below remain and are reachable from the user-detail page.
pub async fn memberships(Query(q): Query<PageQuery>) -> Response {
    let tier = match q.tier.as_deref() {
        Some("early_adopter") => "early_adopter",
        Some("standard") => "standard",
        Some("lifetime") => "lifetime",
        Some("free") => "free",
        _ => "",
    };
    if tier.is_empty() {
        redirect("/admin/users")
    } else {
        redirect(&format!("/admin/users?tier={tier}"))
    }
}

/// POST /admin/memberships/{user_id}/grant - grant a free admin-override
/// membership (sets `subscription_override_by`). Forwards to the existing API
/// endpoint; redirects back to the listing. BUNYIP-118.
pub async fn membership_grant(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ = admin_api::grant_membership(&st.api, c.forward.as_deref(), &user_id).await;
    // BUNYIP-410: the Memberships page is gone; return to the user detail where
    // the action now lives.
    redirect_cookies(&format!("/admin/users/{user_id}"), &c.set_cookies)
}

/// POST /admin/memberships/{user_id}/revoke - revoke an admin-override
/// membership (resets tier to standard, clears `subscription_override_by`).
/// BUNYIP-118.
pub async fn membership_revoke(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // BUNYIP-410: return to the user detail (the Memberships page is gone).
    let target = match admin_api::revoke_membership(&st.api, c.forward.as_deref(), &user_id).await {
        Ok(_) => format!("/admin/users/{user_id}"),
        Err(e) => {
            tracing::warn!(user_id = %user_id, error = ?e, "admin revoke membership failed");
            format!(
                "/admin/users/{user_id}?toast_err={}",
                urlenc("Could not revoke membership")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}
