//! Admin panel: Audit logs.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::admin as admin_api;
use crate::api::types::AdminAuditLog;
use crate::handlers::{admin_guard, admin_response};
use crate::util::{rel_time, urlenc};
use crate::views::ui::{badge, button_class, empty_state, error_box_for, icon, pager};
use crate::web::AppState;

use super::title_case;

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    pub page: Option<u32>,
    pub admin_only: Option<String>,
    /// BUNYIP-930: narrow the view to one user's actions, from the "View full
    /// audit log" link on the user detail page.
    pub user_id: Option<String>,
    /// BUNYIP-936: action-name filter (closed enum, matches
    /// `AuditAction::as_str`). Empty treated as unset.
    pub action: Option<String>,
    /// BUNYIP-936: severity filter (info / warning / error / critical).
    /// Empty treated as unset.
    pub severity: Option<String>,
    /// BUNYIP-936: time-window filter. Accepts `1h`, `24h`, `7d`, `30d`,
    /// or an RFC3339 timestamp. Empty treated as unset.
    pub since: Option<String>,
    /// BUNYIP-937: free-text search over `actor_email` + `resource_id`.
    /// Empty treated as unset; the API caps the length.
    pub q: Option<String>,
}

/// BUNYIP-930: public so the user-detail page can render the user's own
/// activity using the same row shape as the global audit page.
pub fn audit_row(log: &AdminAuditLog) -> Markup {
    let ic = match log.action.as_str() {
        a if a.contains("login") => "log-in",
        a if a.contains("membership") || a.contains("payment") => "credit-card",
        a if a.contains("password") => "key",
        a if a.contains("magic_link") => "mail",
        a if a.contains("register") => "user-plus",
        a if a.contains("admin") || a.contains("deactivate") => "shield",
        _ => "user",
    };
    html! {
        div class="flex items-start justify-between py-4 border-b last:border-0" {
            div class="flex items-start gap-4" {
                div class="flex h-10 w-10 items-center justify-center rounded-full bg-muted" { (icon(ic, "h-5 w-5 text-muted-foreground")) }
                div {
                    div class="flex items-center gap-2" {
                        p class="font-medium" { (title_case(&log.action)) }
                        @if log.is_admin_action { (badge("default", "Admin")) }
                        @if log.severity == "warning" { (badge("warning", "Warning")) }
                        @if log.severity == "error" { (badge("destructive", "Error")) }
                    }
                    p class="text-sm text-muted-foreground" {
                        (log.actor_email.clone().unwrap_or_else(|| "System".into()))
                        @if let Some(ip) = &log.actor_ip_address { " · " (ip) }
                    }
                }
            }
            p class="text-sm text-muted-foreground whitespace-nowrap" { (rel_time(&log.created_at)) }
        }
    }
}

/// BUNYIP-936: the five time-window options the Since chip offers.
const SINCE_OPTIONS: &[(&str, &str)] = &[
    ("", "All time"),
    ("1h", "Last hour"),
    ("24h", "Last 24 hours"),
    ("7d", "Last 7 days"),
    ("30d", "Last 30 days"),
];

/// BUNYIP-936: the severity values the Severity chip offers; stored
/// spelling matches `AuditSeverity::as_str`.
const SEVERITY_OPTIONS: &[(&str, &str)] = &[
    ("", "All severities"),
    ("info", "Info"),
    ("warning", "Warning"),
    ("error", "Error"),
    ("critical", "Critical"),
];

/// BUNYIP-936: the action-name values the Action chip offers. Covers the
/// categories that appear across the admin paths without listing every
/// enum variant (there are 50+). A free-text search covers the long tail.
const ACTION_OPTIONS: &[(&str, &str)] = &[
    ("", "All actions"),
    ("user_login", "User login"),
    ("user_logout", "User logout"),
    ("password_changed", "Password changed"),
    ("password_reset_completed", "Password reset"),
    ("admin_user_impersonated", "Impersonation"),
    ("admin_user_role_changed", "Role changed"),
    ("admin_user_deactivated", "User deactivated"),
    ("admin_user_activated", "User activated"),
    ("admin_user_deleted", "User deleted"),
    ("admin_user_email_changed", "Email changed"),
    ("admin_rate_limit_reset", "Rate limit reset"),
    ("admin_ip_ban_created", "IP ban added"),
    ("admin_ip_ban_lifted", "IP ban lifted"),
    ("admin_feature_toggle_updated", "Feature toggle"),
];

/// BUNYIP-936: render a `<select>` chip bound to one query key, so a
/// submit on any chip reloads the page with that chip's value in the
/// query string. One form wraps every chip + the search box so a single
/// submit carries them all.
fn filter_select(name: &str, current: &str, options: &[(&str, &str)]) -> Markup {
    html! {
        select name=(name) class="h-9 rounded-md border border-input bg-background px-3 text-sm" data-submit-on-change {
            @for (value, label) in options {
                option value=(value) selected[current == *value] { (label) }
            }
        }
    }
}

/// BUNYIP-936: hidden inputs that preserve the filter query string across
/// the Admin-actions-only toggle link and the pager. Rendered inside the
/// clickable toggle so the toggle doesn't drop the active filters.
fn preserved_hidden(q: &AuditQuery) -> Markup {
    html! {
        @if let Some(uid) = q.user_id.as_deref().filter(|s| !s.is_empty()) {
            input type="hidden" name="user_id" value=(uid);
        }
        @if let Some(a) = q.action.as_deref().filter(|s| !s.is_empty()) {
            input type="hidden" name="action" value=(a);
        }
        @if let Some(s) = q.severity.as_deref().filter(|s| !s.is_empty()) {
            input type="hidden" name="severity" value=(s);
        }
        @if let Some(s) = q.since.as_deref().filter(|s| !s.is_empty()) {
            input type="hidden" name="since" value=(s);
        }
        @if let Some(q_) = q.q.as_deref().filter(|s| !s.is_empty()) {
            input type="hidden" name="q" value=(q_);
        }
    }
}

/// Build the pager base URL carrying every active filter. The pager
/// appends `&page=N`.
fn pager_base(q: &AuditQuery, admin_only: bool) -> String {
    let mut params: Vec<String> = Vec::new();
    if admin_only {
        params.push("admin_only=true".to_string());
    }
    if let Some(uid) = q.user_id.as_deref().filter(|s| !s.is_empty()) {
        params.push(format!("user_id={}", urlenc(uid)));
    }
    if let Some(a) = q.action.as_deref().filter(|s| !s.is_empty()) {
        params.push(format!("action={}", urlenc(a)));
    }
    if let Some(s) = q.severity.as_deref().filter(|s| !s.is_empty()) {
        params.push(format!("severity={}", urlenc(s)));
    }
    if let Some(s) = q.since.as_deref().filter(|s| !s.is_empty()) {
        params.push(format!("since={}", urlenc(s)));
    }
    if let Some(q_) = q.q.as_deref().filter(|s| !s.is_empty()) {
        params.push(format!("q={}", urlenc(q_)));
    }
    if params.is_empty() {
        "/admin/audit-logs".to_string()
    } else {
        format!("/admin/audit-logs?{}", params.join("&"))
    }
}

pub async fn audit_logs(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let admin_only = q.admin_only.as_deref() == Some("true");
    let filters = admin_api::AuditFilters {
        user_id: q.user_id.as_deref().filter(|s| !s.is_empty()),
        action: q.action.as_deref().filter(|s| !s.is_empty()),
        severity: q.severity.as_deref().filter(|s| !s.is_empty()),
        since: q.since.as_deref().filter(|s| !s.is_empty()),
        q: q.q.as_deref().filter(|s| !s.is_empty()),
    };
    let result = admin_api::audit_logs(
        &st.api,
        c.forward.as_deref(),
        page,
        50,
        admin_only,
        filters.clone(),
    )
    .await;
    let fetch_error = result.as_ref().err().cloned();
    let data = result.ok();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);
    let base = pager_base(&q, admin_only);
    let search_value = q.q.as_deref().unwrap_or("");

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Audit Logs" } p class="mt-2 text-muted-foreground" { "View security events and user activity." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center justify-between" {
                        div class="flex items-center gap-3" { (icon("file-text", "h-5 w-5 text-primary-text")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Recent Activity" } }
                        div class="flex items-center gap-2 text-sm" {
                            @if admin_only {
                                // BUNYIP-936: clearing admin_only must keep every other filter alive.
                                form method="get" action="/admin/audit-logs" {
                                    (preserved_hidden(&q))
                                    button type="submit" class=(button_class("secondary", "sm", "")) { "Showing: Admin only" }
                                }
                            } @else {
                                form method="get" action="/admin/audit-logs" {
                                    (preserved_hidden(&q))
                                    input type="hidden" name="admin_only" value="true";
                                    button type="submit" class=(button_class("outline", "sm", "")) { "Admin actions only" }
                                }
                            }
                        }
                    }
                    // BUNYIP-936 / BUNYIP-937: filter chips + search. One
                    // form wraps the row so any `onchange` or Enter submit
                    // carries every chip to the server.
                    form method="get" action="/admin/audit-logs" class="mt-4 flex flex-wrap items-center gap-2" {
                        @if admin_only { input type="hidden" name="admin_only" value="true"; }
                        @if let Some(uid) = q.user_id.as_deref().filter(|s| !s.is_empty()) {
                            input type="hidden" name="user_id" value=(uid);
                        }
                        (filter_select("action", q.action.as_deref().unwrap_or(""), ACTION_OPTIONS))
                        (filter_select("severity", q.severity.as_deref().unwrap_or(""), SEVERITY_OPTIONS))
                        (filter_select("since", q.since.as_deref().unwrap_or(""), SINCE_OPTIONS))
                        input type="text" name="q" value=(search_value) placeholder="Search email or resource id…" maxlength="128" class="h-9 flex-1 min-w-[16rem] rounded-md border border-input bg-background px-3 text-sm";
                        button type="submit" class=(button_class("outline", "sm", "")) { "Apply" }
                        @if filters.action.is_some() || filters.severity.is_some() || filters.since.is_some() || filters.q.is_some() {
                            @let clear = pager_base(&AuditQuery { user_id: q.user_id.clone(), admin_only: q.admin_only.clone(), ..Default::default() }, admin_only);
                            a href=(clear) class=(button_class("ghost", "sm", "")) { "Clear" }
                        }
                    }
                }
                div class="p-6 pt-0" {
                    @if let Some(e) = &fetch_error { (error_box_for("Could not reach the API to load audit logs.", e)) }
                    @else if items.is_empty() { (empty_state("file-text", "No audit logs found.", None)) }
                    @else { div class="space-y-0" { @for log in &items { (audit_row(log)) } } }
                    (pager(&base, "page", page, total_pages))
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/audit-logs", "Audit Logs", content)
}
