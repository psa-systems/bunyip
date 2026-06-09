//! Admin handlers. Server-rendered tables with query-param pagination and
//! form-based mutations (htmx is loaded for progressive enhancement, but the
//! baseline works without JS). Mirrors the Dioxus admin pages; the heavyweight
//! Stripe product/price/webhook managers remain condensed (see ROADMAP.md).

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::api::types::{AdminAuditLog, FeedbackStatus, UserEntitlement};
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::relative_time;
use crate::views::ui::{badge, button_class, error_box, icon};
use crate::web::{redirect_cookies, AppState};

fn title_case(action: &str) -> String {
    action
        .split('_')
        .map(|w| {
            let mut ch = w.chars();
            match ch.next() {
                Some(f) => f.to_uppercase().chain(ch).collect::<String>(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn pager(base: &str, page: u32, total_pages: i64) -> Markup {
    let sep = if base.contains('?') { "&" } else { "?" };
    html! {
        @if total_pages > 1 {
            div class="flex justify-center gap-2 mt-6" {
                @if page > 1 { a href=(format!("{base}{sep}page={}", page - 1)) class=(button_class("outline", "sm", "")) { "Previous" } }
                span class="flex items-center px-3 text-sm" { "Page " (page) " of " (total_pages) }
                @if (page as i64) < total_pages { a href=(format!("{base}{sep}page={}", page + 1)) class=(button_class("outline", "sm", "")) { "Next" } }
            }
        }
    }
}

// ===========================================================================
// Dashboard
// ===========================================================================

pub async fn dashboard(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let stats = admin_api::stats(&st.api, fwd).await.ok();
    let logs = admin_api::audit_logs(&st.api, fwd, 1, 5, false)
        .await
        .map(|p| p.items)
        .unwrap_or_default();

    let stat = |label: &str, value: String, sub: &str, ic: &str| {
        html! {
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6 flex-row items-center justify-between pb-2" {
                    h3 class="text-sm font-medium" { (label) } (icon(ic, "h-4 w-4 text-muted-foreground"))
                }
                div class="p-6 pt-0" { div class="text-2xl font-bold" { (value) } p class="text-xs text-muted-foreground" { (sub) } }
            }
        }
    };

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Admin Dashboard" } p class="mt-2 text-muted-foreground" { "Overview of your platform." } }
            div class="grid gap-4 md:grid-cols-2 lg:grid-cols-4" {
                (stat("Total Users", stats.as_ref().map(|s| s.total_users.to_string()).unwrap_or_else(|| "0".into()), "Registered accounts", "users"))
                (stat("Active Memberships", stats.as_ref().map(|s| s.active_members.to_string()).unwrap_or_else(|| "0".into()), "Paying customers", "credit-card"))
                (stat("Active Apps", stats.as_ref().map(|s| format!("{}/{}", s.active_applications, s.total_applications)).unwrap_or_else(|| "0/0".into()), "Applications online", "trending-up"))
                (stat("Past Due", stats.as_ref().map(|s| s.past_due_members.to_string()).unwrap_or_else(|| "0".into()), "In grace period", "alert-triangle"))
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Recent Activity" } p class="text-sm text-muted-foreground" { "Latest platform events" } }
                div class="p-6 pt-0" {
                    @if logs.is_empty() { p class="text-muted-foreground text-center py-8" { "No recent activity" } }
                    @else {
                        div class="space-y-4" {
                            @for log in &logs {
                                div class="flex items-center gap-3" {
                                    (icon("activity", "h-4 w-4 text-muted-foreground"))
                                    div class="flex-1 min-w-0" { p class="text-sm font-medium truncate" { (title_case(&log.action)) } p class="text-xs text-muted-foreground truncate" { (log.actor_email.clone().unwrap_or_else(|| "System".into())) } }
                                    span class="text-xs text-muted-foreground" { (relative_time(&log.created_at)) }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    admin_response(&c, &user, "/admin", "Admin · Bunyip", content)
}

// ===========================================================================
// Audit logs
// ===========================================================================

#[derive(Deserialize)]
pub struct AuditQuery {
    pub page: Option<u32>,
    pub admin_only: Option<String>,
}

fn audit_row(log: &AdminAuditLog) -> Markup {
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
                        @if let Some(ip) = &log.actor_ip_address { " • " (ip) }
                    }
                }
            }
            p class="text-sm text-muted-foreground whitespace-nowrap" { (relative_time(&log.created_at)) }
        }
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
    let data = admin_api::audit_logs(&st.api, c.forward.as_deref(), page, 50, admin_only)
        .await
        .ok();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);
    let base = if admin_only {
        "/admin/audit-logs?admin_only=true"
    } else {
        "/admin/audit-logs"
    };

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Audit Logs" } p class="mt-2 text-muted-foreground" { "View security events and user activity." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center justify-between" {
                        div class="flex items-center gap-3" { (icon("file-text", "h-5 w-5 text-primary")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Recent Activity" } }
                        div class="flex items-center gap-2 text-sm" {
                            @if admin_only { a href="/admin/audit-logs" class=(button_class("secondary", "sm", "")) { "Showing: Admin only" } }
                            @else { a href="/admin/audit-logs?admin_only=true" class=(button_class("outline", "sm", "")) { "Admin actions only" } }
                        }
                    }
                }
                div class="p-6 pt-0" {
                    @if items.is_empty() { p class="text-center text-muted-foreground py-8" { "No audit logs found" } }
                    @else { div class="space-y-0" { @for log in &items { (audit_row(log)) } } }
                    (pager(base, page, total_pages))
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/audit-logs",
        "Audit Logs · Bunyip",
        content,
    )
}

// ===========================================================================
// Users
// ===========================================================================

#[derive(Deserialize)]
pub struct UserQuery {
    pub page: Option<u32>,
    pub search: Option<String>,
}

pub async fn users(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<UserQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let search = q.search.unwrap_or_default();
    let data = admin_api::users(&st.api, c.forward.as_deref(), page, 20, &search)
        .await
        .ok();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);
    let base = if search.is_empty() {
        "/admin/users".to_string()
    } else {
        format!("/admin/users?search={}", urlenc(&search))
    };

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Users" } p class="mt-2 text-muted-foreground" { "Manage user accounts." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center justify-between gap-4" {
                        h3 class="text-2xl font-semibold leading-none tracking-tight" { "All Users" }
                        form method="get" action="/admin/users" class="w-64" { input name="search" value=(search) placeholder="Search by email…" class=(dashboard_input()); }
                    }
                }
                div class="p-6 pt-0" {
                    div class="divide-y" {
                        @for u in &items {
                            @let is_admin = matches!(u.role, crate::api::types::UserRole::Admin);
                            div class="flex items-center justify-between py-3" {
                                div {
                                    p class="font-medium flex items-center gap-2" { (u.email) @if is_admin { (badge("default", "Admin")) } @if !u.email_verified { (badge("outline", "Unverified")) } }
                                    p class="text-xs text-muted-foreground" { "Joined " (relative_time(&u.created_at)) }
                                }
                                div class="flex items-center gap-2 flex-wrap" {
                                    a href=(format!("/admin/users/{}", u.id)) class=(button_class("outline", "sm", "")) { "View" }
                                    a href=(format!("/admin/users/{}/entitlements", u.id)) class=(button_class("outline", "sm", "")) { "Entitlements" }
                                    form method="post" action=(format!("/admin/users/{}/role", u.id)) {
                                        input type="hidden" name="role" value=(if is_admin { "subscriber" } else { "admin" });
                                        button type="submit" class=(button_class("outline", "sm", "")) { @if is_admin { "Demote" } @else { "Make Admin" } }
                                    }
                                    form method="post" action=(format!("/admin/users/{}/reset-password", u.id)) onsubmit="return confirm('Send a password reset email to this user?')" {
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Reset Password" }
                                    }
                                    @if u.lifetime_member {
                                        form method="post" action=(format!("/admin/users/{}/lifetime/revoke", u.id)) onsubmit="return confirm('Revoke lifetime membership? User will be returned to standard tier with no active subscription.')" {
                                            button type="submit" class=(button_class("outline", "sm", "")) { "Revoke Lifetime" }
                                        }
                                    } @else {
                                        form method="post" action=(format!("/admin/users/{}/lifetime", u.id)) onsubmit="return confirm('Grant lifetime membership? Creates a $0 Stripe subscription.')" {
                                            button type="submit" class=(button_class("outline", "sm", "")) { "Lifetime" }
                                        }
                                    }
                                    form method="post" action=(format!("/admin/users/{}/suspend", u.id)) onsubmit="return confirm('Suspend (soft-delete) this user?')" {
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Suspend" }
                                    }
                                    form method="post" action=(format!("/admin/users/{}/delete", u.id)) onsubmit="return confirm('Delete this user? This cannot be undone.')" {
                                        button type="submit" class=(button_class("outline", "sm", "text-destructive hover:text-destructive")) { (icon("trash", "h-4 w-4")) }
                                    }
                                }
                            }
                        }
                        @if items.is_empty() { p class="text-center text-muted-foreground py-8" { "No users found" } }
                    }
                    (pager(&base, page, total_pages))
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/users", "Users · Bunyip", content)
}

#[derive(Deserialize)]
pub struct RoleForm {
    pub role: String,
}
pub async fn user_role(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<RoleForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ = admin_api::update_user_role(&st.api, c.forward.as_deref(), &id, &f.role).await;
    redirect_cookies("/admin/users", &c.set_cookies)
}
pub async fn user_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ = admin_api::delete_user(&st.api, c.forward.as_deref(), &id).await;
    redirect_cookies("/admin/users", &c.set_cookies)
}

pub async fn user_suspend(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ = admin_api::suspend_user(&st.api, c.forward.as_deref(), &id).await;
    redirect_cookies("/admin/users", &c.set_cookies)
}

pub async fn user_reset_password(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ = admin_api::admin_reset_password(&st.api, c.forward.as_deref(), &id).await;
    redirect_cookies(&format!("/admin/users/{id}"), &c.set_cookies)
}

pub async fn user_grant_lifetime(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ = admin_api::grant_lifetime(&st.api, c.forward.as_deref(), &id).await;
    redirect_cookies(&format!("/admin/users/{id}"), &c.set_cookies)
}

pub async fn user_revoke_lifetime(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ = admin_api::revoke_lifetime(&st.api, c.forward.as_deref(), &id).await;
    redirect_cookies(&format!("/admin/users/{id}"), &c.set_cookies)
}

/// GET /admin/users/{id} - single-user detail page with all admin actions in one place.
pub async fn user_detail(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::get_user(&st.api, c.forward.as_deref(), &id).await {
        Ok(u) => u,
        Err(_) => {
            return admin_response(
                &c,
                &user,
                "/admin/users",
                "User not found",
                html! {
                    div class="rounded-lg border bg-card text-card-foreground shadow-sm p-6" {
                        p { "Could not load user " (id) "." }
                        p class="mt-2" { a href="/admin/users" class="text-primary hover:underline" { "Back to users" } }
                    }
                },
            )
        }
    };
    let is_admin_target = matches!(target.role, crate::api::types::UserRole::Admin);

    let content = html! {
        div class="space-y-6" {
            div class="flex items-center justify-between" {
                div {
                    h1 class="text-2xl font-bold flex items-center gap-2" {
                        (target.email)
                        @if is_admin_target { (badge("default", "Admin")) }
                        @if target.lifetime_member { (badge("default", "Lifetime")) }
                        @if !target.email_verified { (badge("outline", "Unverified")) }
                    }
                    p class="text-sm text-muted-foreground mt-1" {
                        "Joined " (relative_time(&target.created_at))
                        @if let Some(last) = target.last_login_at.as_deref() {
                            " · last login " (relative_time(last))
                        }
                    }
                }
                a href="/admin/users" class=(button_class("outline", "sm", "")) { (icon("arrow-left", "h-4 w-4 mr-1")) "Back" }
            }

            // Profile card
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6 pb-2" {
                    h3 class="text-base font-semibold leading-none tracking-tight" { "Profile" }
                }
                div class="p-6 pt-0 grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm" {
                    div { span class="text-muted-foreground" { "User ID: " } code class="font-mono text-xs" { (target.id) } }
                    div { span class="text-muted-foreground" { "Email: " } (target.email) }
                    div { span class="text-muted-foreground" { "Role: " } (format!("{:?}", target.role)) }
                    div { span class="text-muted-foreground" { "Email verified: " } @if target.email_verified { "Yes" } @else { "No" } }
                    div { span class="text-muted-foreground" { "Two-factor: " } @if target.two_factor_enabled { "Enabled" } @else { "Disabled" } }
                    div { span class="text-muted-foreground" { "Membership: " } (format!("{:?}", target.membership_status)) }
                    div { span class="text-muted-foreground" { "Tier: " } (format!("{:?}", target.subscription_tier)) }
                    @if target.lifetime_member { div { span class="text-muted-foreground" { "Lifetime: " } "Yes" } }
                    @if let Some(grace) = target.grace_period_end.as_deref() {
                        div { span class="text-muted-foreground" { "Grace ends: " } (relative_time(grace)) }
                    }
                }
            }

            // Actions card
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6 pb-2" {
                    h3 class="text-base font-semibold leading-none tracking-tight" { "Actions" }
                    p class="text-xs text-muted-foreground" { "All actions write an audit-log entry." }
                }
                div class="p-6 pt-2 flex flex-wrap gap-2" {
                    a href=(format!("/admin/users/{}/entitlements", target.id)) class=(button_class("outline", "default", "")) { "Manage Entitlements" }
                    form method="post" action=(format!("/admin/users/{}/role", target.id)) {
                        input type="hidden" name="role" value=(if is_admin_target { "subscriber" } else { "admin" });
                        button type="submit" class=(button_class("outline", "default", "")) { @if is_admin_target { "Demote to subscriber" } @else { "Promote to admin" } }
                    }
                    form method="post" action=(format!("/admin/users/{}/reset-password", target.id)) onsubmit="return confirm('Send a password reset email to this user?')" {
                        button type="submit" class=(button_class("outline", "default", "")) { "Send password reset" }
                    }
                    @if target.lifetime_member {
                        form method="post" action=(format!("/admin/users/{}/lifetime/revoke", target.id)) onsubmit="return confirm('Revoke lifetime membership? User will be returned to standard tier with no active subscription.')" {
                            button type="submit" class=(button_class("outline", "default", "")) { "Revoke lifetime" }
                        }
                    } @else {
                        form method="post" action=(format!("/admin/users/{}/lifetime", target.id)) onsubmit="return confirm('Grant lifetime membership? Creates a $0 Stripe subscription.')" {
                            button type="submit" class=(button_class("outline", "default", "")) { "Grant lifetime" }
                        }
                    }
                    form method="post" action=(format!("/admin/users/{}/suspend", target.id)) onsubmit="return confirm('Suspend (soft-delete) this user?')" {
                        button type="submit" class=(button_class("outline", "default", "")) { "Suspend" }
                    }
                    form method="post" action=(format!("/admin/users/{}/delete", target.id)) onsubmit="return confirm('Delete this user? This cannot be undone.')" {
                        button type="submit" class=(button_class("outline", "default", "text-destructive hover:text-destructive")) { "Delete user" }
                    }
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/users", "User · Bunyip", content)
}

// ===========================================================================
// Memberships
// ===========================================================================

#[derive(Deserialize)]
pub struct PageQuery {
    pub page: Option<u32>,
}

pub async fn memberships(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let data = admin_api::memberships(&st.api, c.forward.as_deref(), page, 20, "")
        .await
        .ok();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Memberships" } p class="mt-2 text-muted-foreground" { "Review members and their subscription status." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "All Memberships" } }
                div class="p-6 pt-0" {
                    div class="divide-y" {
                        @for m in &items {
                            div class="flex items-center justify-between py-3" {
                                div { p class="font-medium" { (m.user_email) } p class="text-xs text-muted-foreground" { (m.subscription_tier) } }
                                (badge("outline", &m.status))
                            }
                        }
                        @if items.is_empty() { p class="text-center text-muted-foreground py-8" { "No memberships found" } }
                    }
                    (pager("/admin/memberships", page, total_pages))
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/memberships",
        "Memberships · Bunyip",
        content,
    )
}

// ===========================================================================
// Feedback
// ===========================================================================

pub async fn feedback(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let data = admin_api::feedback(&st.api, c.forward.as_deref(), page, 20)
        .await
        .ok();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Feedback" } p class="mt-2 text-muted-foreground" { "Triage submitted feedback." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Submissions" } }
                div class="p-6 pt-0" {
                    div class="divide-y" {
                        @for f in &items {
                            div class="py-3 flex items-start justify-between gap-4" {
                                div class="min-w-0" {
                                    p class="font-medium truncate" { (f.subject.clone().unwrap_or_else(|| "(no subject)".into())) }
                                    p class="text-sm text-muted-foreground truncate" { (f.message_excerpt) }
                                    p class="text-xs text-muted-foreground" { (relative_time(&f.created_at)) }
                                }
                                div class="flex items-center gap-2 shrink-0" {
                                    (badge("outline", admin_api::feedback_status_str(f.status.clone())))
                                    form method="post" action=(format!("/admin/feedback/{}/status", f.id)) { input type="hidden" name="status" value="reviewed"; button type="submit" class=(button_class("outline", "sm", "")) { "Reviewed" } }
                                    form method="post" action=(format!("/admin/feedback/{}/status", f.id)) { input type="hidden" name="status" value="closed"; button type="submit" class=(button_class("outline", "sm", "")) { "Close" } }
                                }
                            }
                        }
                        @if items.is_empty() { p class="text-center text-muted-foreground py-8" { "No feedback yet" } }
                    }
                    (pager("/admin/feedback", page, total_pages))
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/feedback", "Feedback · Bunyip", content)
}

#[derive(Deserialize)]
pub struct StatusForm {
    pub status: String,
}
pub async fn feedback_status(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<StatusForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let status = match f.status.as_str() {
        "reviewed" => FeedbackStatus::Reviewed,
        "responded" => FeedbackStatus::Responded,
        "closed" => FeedbackStatus::Closed,
        _ => FeedbackStatus::New,
    };
    let _ = admin_api::update_feedback_status(&st.api, c.forward.as_deref(), &id, status).await;
    redirect_cookies("/admin/feedback", &c.set_cookies)
}

// ===========================================================================
// Applications
// ===========================================================================

pub async fn applications(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let apps = admin_api::applications(&st.api, c.forward.as_deref())
        .await
        .unwrap_or_default();

    let content = html! {
        div class="space-y-6" {
            div class="flex items-center justify-between gap-4" {
                div { h1 class="text-3xl font-bold" { "Applications" } p class="mt-2 text-muted-foreground" { "Configure available applications." } }
                a href="/admin/applications/new" class=(button_class("default", "default", "")) { "New application" }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "All Applications" } }
                div class="p-6 pt-0" {
                    div class="divide-y" {
                        @for app in &apps {
                            div class="py-3 flex items-center justify-between gap-4" {
                                div { p class="font-medium" { (app.display_name) } p class="text-xs text-muted-foreground" { (app.slug) } }
                                div class="flex items-center gap-6" {
                                    form method="post" action=(format!("/admin/applications/{}/field", app.id)) class="flex items-center gap-2" {
                                        input type="hidden" name="field" value="is_active";
                                        input type="hidden" name="value" value=(if app.is_active { "false" } else { "true" });
                                        span class="text-sm text-muted-foreground" { "Active: " (if app.is_active { "on" } else { "off" }) }
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Toggle" }
                                    }
                                    form method="post" action=(format!("/admin/applications/{}/field", app.id)) class="flex items-center gap-2" {
                                        input type="hidden" name="field" value="maintenance_mode";
                                        input type="hidden" name="value" value=(if app.maintenance_mode { "false" } else { "true" });
                                        span class="text-sm text-muted-foreground" { "Maintenance: " (if app.maintenance_mode { "on" } else { "off" }) }
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Toggle" }
                                    }
                                    a href=(format!("/admin/applications/{}/edit", app.id)) class=(button_class("outline", "sm", "")) { "Edit" }
                                }
                            }
                        }
                        @if apps.is_empty() { p class="text-center text-muted-foreground py-8" { "No applications" } }
                    }
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/applications",
        "Applications · Bunyip",
        content,
    )
}

#[derive(Deserialize)]
pub struct AppFieldForm {
    pub field: String,
    pub value: String,
}
pub async fn application_field(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<AppFieldForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let val = f.value == "true";
    let mut map = serde_json::Map::new();
    map.insert(f.field.clone(), json!(val));
    let body = serde_json::Value::Object(map);
    let _ = admin_api::update_application(&st.api, c.forward.as_deref(), &id, body).await;
    redirect_cookies("/admin/applications", &c.set_cookies)
}

// --- application distribution edit / create --------------------------------

/// Current values of the distribution form, borrowed for rendering. Shared by
/// the create and edit forms so the field layout cannot drift between them.
struct DistView<'a> {
    artifact_source: &'a str,
    forgejo_owner: &'a str,
    forgejo_repo: &'a str,
    forgejo_package: &'a str,
    pinned_release_tag: &'a str,
    oci_image_owner: &'a str,
    oci_image_name: &'a str,
    pinned_image_tag: &'a str,
}

/// Identity fields shown only on the create form (the backend requires them;
/// they are immutable afterwards, so the edit form omits them).
struct IdentityView<'a> {
    name: &'a str,
    slug: &'a str,
    display_name: &'a str,
    container_name: &'a str,
}

/// An HTML checkbox submits its value only when checked, so an unchecked box is
/// absent from the form body (serde default `""`). Treat the standard checked
/// markers as true.
fn checkbox_on(s: &str) -> bool {
    s == "true" || s == "on"
}

fn distribution_fields(v: &DistView) -> Markup {
    html! {
        h4 class="text-lg font-semibold pt-2" { "Binary (Forgejo)" }
        div class="space-y-2" {
            label class="text-sm font-medium" { "Artifact source" }
            select name="artifact_source" class=(dashboard_input()) {
                option value="release" selected[v.artifact_source != "generic_package"] { "release" }
                option value="generic_package" selected[v.artifact_source == "generic_package"] { "generic_package" }
            }
        }
        div class="space-y-2" { label class="text-sm font-medium" { "Forgejo owner" } input name="forgejo_owner" value=(v.forgejo_owner) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Forgejo repo" } input name="forgejo_repo" value=(v.forgejo_repo) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Forgejo package" } p class="text-xs text-muted-foreground" { "generic_package sources only; leave blank to clear back to the repo name." } input name="forgejo_package" value=(v.forgejo_package) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Pinned release tag" } input name="pinned_release_tag" value=(v.pinned_release_tag) class=(dashboard_input()); }
        h4 class="text-lg font-semibold pt-2" { "Container (OCI)" }
        div class="space-y-2" { label class="text-sm font-medium" { "OCI image owner" } input name="oci_image_owner" value=(v.oci_image_owner) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "OCI image name" } input name="oci_image_name" value=(v.oci_image_name) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Pinned image tag" } input name="pinned_image_tag" value=(v.pinned_image_tag) class=(dashboard_input()); }
    }
}

/// Render the application create/edit form. `identity` is `Some` only for
/// create (the edit form posts distribution fields only). `error` renders a
/// banner and the form keeps the submitted values for correction.
fn application_form(
    action: &str,
    heading: &str,
    blurb: &str,
    identity: Option<&IdentityView>,
    is_hosted: bool,
    v: &DistView,
    error: Option<&str>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { (heading) } p class="mt-2 text-muted-foreground" { (blurb) } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="p-6" {
                    form method="post" action=(action) class="space-y-4 max-w-md" {
                        @if let Some(err) = error { (error_box(err)) }
                        @if let Some(id) = identity {
                            h4 class="text-lg font-semibold" { "Identity" }
                            div class="space-y-2" { label class="text-sm font-medium" { "Name" } input name="name" value=(id.name) required class=(dashboard_input()); }
                            div class="space-y-2" { label class="text-sm font-medium" { "Slug" } input name="slug" value=(id.slug) required class=(dashboard_input()); }
                            div class="space-y-2" { label class="text-sm font-medium" { "Display name" } input name="display_name" value=(id.display_name) required class=(dashboard_input()); }
                            div class="space-y-2" { label class="text-sm font-medium" { "Container name" } input name="container_name" value=(id.container_name) required class=(dashboard_input()); }
                        }
                        div class="flex items-start gap-2" {
                            input type="checkbox" name="is_hosted" value="true" checked[is_hosted] id="is_hosted" class="mt-1";
                            label for="is_hosted" class="text-sm font-medium" { "Hosted app" p class="text-xs font-normal text-muted-foreground" { "Checked: shows as a launchable hub tile. Unchecked: catalog-only distribution product (downloads / OCI pulls only)." } }
                        }
                        (distribution_fields(v))
                        div class="flex items-center gap-2 pt-2" {
                            button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                            a href="/admin/applications" class=(button_class("outline", "default", "")) { "Cancel" }
                        }
                    }
                }
            }
        }
    }
}

fn dist_view_from_form(f: &DistributionForm) -> DistView<'_> {
    DistView {
        artifact_source: &f.artifact_source,
        forgejo_owner: &f.forgejo_owner,
        forgejo_repo: &f.forgejo_repo,
        forgejo_package: &f.forgejo_package,
        pinned_release_tag: &f.pinned_release_tag,
        oci_image_owner: &f.oci_image_owner,
        oci_image_name: &f.oci_image_name,
        pinned_image_tag: &f.pinned_image_tag,
    }
}

/// Body for PUT /admin/applications/{id}: set every non-empty distribution
/// field. Empty inputs are omitted so the backend keeps the existing column
/// (its UPDATE COALESCEs a NULL to the old value), EXCEPT `forgejo_package`,
/// which is always sent so an empty value clears it to NULL (the documented
/// backend sentinel). `forgejo_package` is also forced empty on non-generic
/// sources: it is meaningless there, and re-sending a prefilled package while
/// the admin flips the source to `release` would fail backend validation.
/// `is_hosted` is always sent so the checkbox can toggle it in both directions.
fn distribution_update_body(f: &DistributionForm) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    if !f.artifact_source.trim().is_empty() {
        m.insert("artifact_source".into(), json!(f.artifact_source.trim()));
    }
    for (k, val) in [
        ("forgejo_owner", &f.forgejo_owner),
        ("forgejo_repo", &f.forgejo_repo),
        ("pinned_release_tag", &f.pinned_release_tag),
        ("oci_image_owner", &f.oci_image_owner),
        ("oci_image_name", &f.oci_image_name),
        ("pinned_image_tag", &f.pinned_image_tag),
    ] {
        if !val.trim().is_empty() {
            m.insert(k.into(), json!(val.trim()));
        }
    }
    let package = if f.artifact_source.trim() == "generic_package" {
        f.forgejo_package.trim()
    } else {
        ""
    };
    m.insert("forgejo_package".into(), json!(package));
    m.insert("is_hosted".into(), json!(checkbox_on(&f.is_hosted)));
    serde_json::Value::Object(m)
}

#[derive(Deserialize, Default)]
pub struct DistributionForm {
    #[serde(default)]
    pub artifact_source: String,
    #[serde(default)]
    pub forgejo_owner: String,
    #[serde(default)]
    pub forgejo_repo: String,
    #[serde(default)]
    pub forgejo_package: String,
    #[serde(default)]
    pub pinned_release_tag: String,
    #[serde(default)]
    pub oci_image_owner: String,
    #[serde(default)]
    pub oci_image_name: String,
    #[serde(default)]
    pub pinned_image_tag: String,
    #[serde(default)]
    pub is_hosted: String,
}

/// GET /admin/applications/{id}/edit
/// Query params on the edit page. `error` is set when a delete attempt bounces
/// back (bad password / 2FA code) so the danger zone can show why.
#[derive(Deserialize)]
pub struct AppEditQuery {
    pub error: Option<String>,
}

pub async fn application_edit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<AppEditQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Distinguish a failed list fetch (network / auth / 5xx) from a genuinely
    // missing application; collapsing both to "not found" would mislead.
    let apps = match admin_api::applications(&st.api, c.forward.as_deref()).await {
        Ok(apps) => apps,
        Err(e) => {
            let content = html! {
                div class="space-y-6" {
                    h1 class="text-3xl font-bold" { "Edit application" }
                    (error_box(&e.user_message()))
                }
            };
            return admin_response(
                &c,
                &user,
                "/admin/applications",
                "Edit application · Bunyip",
                content,
            );
        }
    };
    let content = match apps.iter().find(|a| a.id == id) {
        None => {
            html! { div class="space-y-6" { h1 class="text-3xl font-bold" { "Edit application" } p class="text-muted-foreground" { "Application not found." } } }
        }
        Some(app) => {
            let v = DistView {
                artifact_source: app.artifact_source.as_deref().unwrap_or("release"),
                forgejo_owner: app.forgejo_owner.as_deref().unwrap_or_default(),
                forgejo_repo: app.forgejo_repo.as_deref().unwrap_or_default(),
                forgejo_package: app.forgejo_package.as_deref().unwrap_or_default(),
                pinned_release_tag: app.pinned_release_tag.as_deref().unwrap_or_default(),
                oci_image_owner: app.oci_image_owner.as_deref().unwrap_or_default(),
                oci_image_name: app.oci_image_name.as_deref().unwrap_or_default(),
                pinned_image_tag: app.pinned_image_tag.as_deref().unwrap_or_default(),
            };
            html! {
                (application_form(
                    &format!("/admin/applications/{id}/distribution"),
                    &format!("Edit {}", app.display_name),
                    "Set the Forgejo binary and OCI container coordinates. Blank fields keep their current value.",
                    None,
                    app.is_hosted,
                    &v,
                    None,
                ))
                (app_danger_zone(&id, q.error.as_deref()))
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/applications",
        "Edit application · Bunyip",
        content,
    )
}

/// Danger zone on the edit page: hard-delete the application. Mirrors the
/// account self-delete UI; the API requires the admin's password + 2FA code, so
/// both fields are collected and posted to the delete handler.
fn app_danger_zone(id: &str, error: Option<&str>) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm border-red-200 dark:border-red-900 mt-8 max-w-2xl" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight text-red-600 dark:text-red-400 flex items-center gap-2" { (icon("alert-triangle", "h-5 w-5")) "Danger Zone" }
                p class="text-sm text-muted-foreground" { "Permanently delete this application. Its entitlements, price links, and download caches are removed with it. This cannot be undone." }
            }
            div class="p-6 pt-0" {
                @if let Some(e) = error { (error_box(e)) }
                form method="post" action=(format!("/admin/applications/{id}/delete")) class="space-y-3 max-w-md mt-2" onsubmit="return confirm('Permanently delete this application? This cannot be undone.')" {
                    div class="space-y-2" { label class="text-sm font-medium" { "Password" } input name="password" type="password" placeholder="Enter your password to confirm" class=(dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "Two-Factor Code" } input name="totp_code" placeholder="6-digit code" class=(dashboard_input()); }
                    button type="submit" class=(button_class("destructive", "default", "")) { (icon("trash", "mr-2 h-4 w-4")) "Delete application" }
                }
            }
        }
    }
}

/// POST /admin/applications/{id}/distribution
pub async fn application_distribution_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<DistributionForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let body = distribution_update_body(&f);
    match admin_api::update_application(&st.api, c.forward.as_deref(), &id, body).await {
        Ok(()) => redirect_cookies("/admin/applications", &c.set_cookies),
        Err(e) => {
            let v = dist_view_from_form(&f);
            let content = application_form(
                &format!("/admin/applications/{id}/distribution"),
                "Edit application",
                "Set the Forgejo binary and OCI container coordinates. Blank fields keep their current value.",
                None,
                checkbox_on(&f.is_hosted),
                &v,
                Some(&e.user_message()),
            );
            admin_response(
                &c,
                &user,
                "/admin/applications",
                "Edit application · Bunyip",
                content,
            )
        }
    }
}

#[derive(Deserialize)]
pub struct DeleteAppForm {
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub totp_code: String,
}

/// POST /admin/applications/{id}/delete
pub async fn application_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<DeleteAppForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match admin_api::delete_application(
        &st.api,
        c.forward.as_deref(),
        &id,
        &f.password,
        &f.totp_code,
    )
    .await
    {
        // Relay any cookie the guard rotated on both paths (mirrors user_delete);
        // a plain redirect would drop a refreshed session.
        Ok(()) => redirect_cookies("/admin/applications", &c.set_cookies),
        // Bad password / 2FA code (or any failure): bounce back to this app's
        // danger zone with the API's message rather than dropping the admin on a
        // blank page.
        Err(e) => redirect_cookies(
            &format!(
                "/admin/applications/{id}/edit?error={}",
                urlenc(&e.user_message())
            ),
            &c.set_cookies,
        ),
    }
}

#[derive(Deserialize, Default)]
pub struct CreateAppForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub container_name: String,
    #[serde(default)]
    pub artifact_source: String,
    #[serde(default)]
    pub forgejo_owner: String,
    #[serde(default)]
    pub forgejo_repo: String,
    #[serde(default)]
    pub forgejo_package: String,
    #[serde(default)]
    pub pinned_release_tag: String,
    #[serde(default)]
    pub oci_image_owner: String,
    #[serde(default)]
    pub oci_image_name: String,
    #[serde(default)]
    pub pinned_image_tag: String,
    #[serde(default)]
    pub is_hosted: String,
}

/// Body for POST /admin/applications: required identity fields plus every
/// non-empty distribution field. Empty distribution inputs are omitted (a new
/// row has nothing to clear, and an empty string would fail backend
/// validation). `forgejo_package` is only sent on a `generic_package` source
/// (it is invalid on `release`). `is_hosted` reflects the checkbox so a
/// catalog-only product (unchecked) is not forced to the DB default of hosted.
fn create_app_body(f: &CreateAppForm) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(f.name.trim()));
    m.insert("slug".into(), json!(f.slug.trim()));
    m.insert("display_name".into(), json!(f.display_name.trim()));
    m.insert("container_name".into(), json!(f.container_name.trim()));
    m.insert("is_hosted".into(), json!(checkbox_on(&f.is_hosted)));
    if !f.artifact_source.trim().is_empty() {
        m.insert("artifact_source".into(), json!(f.artifact_source.trim()));
    }
    for (k, val) in [
        ("forgejo_owner", &f.forgejo_owner),
        ("forgejo_repo", &f.forgejo_repo),
        ("pinned_release_tag", &f.pinned_release_tag),
        ("oci_image_owner", &f.oci_image_owner),
        ("oci_image_name", &f.oci_image_name),
        ("pinned_image_tag", &f.pinned_image_tag),
    ] {
        if !val.trim().is_empty() {
            m.insert(k.into(), json!(val.trim()));
        }
    }
    if f.artifact_source.trim() == "generic_package" && !f.forgejo_package.trim().is_empty() {
        m.insert("forgejo_package".into(), json!(f.forgejo_package.trim()));
    }
    serde_json::Value::Object(m)
}

/// GET /admin/applications/new
pub async fn application_new(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let id = IdentityView {
        name: "",
        slug: "",
        display_name: "",
        container_name: "",
    };
    let v = DistView {
        artifact_source: "release",
        forgejo_owner: "",
        forgejo_repo: "",
        forgejo_package: "",
        pinned_release_tag: "",
        oci_image_owner: "",
        oci_image_name: "",
        pinned_image_tag: "",
    };
    let content = application_form(
        "/admin/applications",
        "New application",
        "Create a catalog application and (optionally) its Forgejo binary and OCI container coordinates.",
        Some(&id),
        true,
        &v,
        None,
    );
    admin_response(
        &c,
        &user,
        "/admin/applications",
        "New application · Bunyip",
        content,
    )
}

/// POST /admin/applications
pub async fn application_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CreateAppForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let body = create_app_body(&f);
    match admin_api::create_application(&st.api, c.forward.as_deref(), body).await {
        Ok(()) => redirect_cookies("/admin/applications", &c.set_cookies),
        Err(e) => {
            let id = IdentityView {
                name: &f.name,
                slug: &f.slug,
                display_name: &f.display_name,
                container_name: &f.container_name,
            };
            let v = DistView {
                artifact_source: &f.artifact_source,
                forgejo_owner: &f.forgejo_owner,
                forgejo_repo: &f.forgejo_repo,
                forgejo_package: &f.forgejo_package,
                pinned_release_tag: &f.pinned_release_tag,
                oci_image_owner: &f.oci_image_owner,
                oci_image_name: &f.oci_image_name,
                pinned_image_tag: &f.pinned_image_tag,
            };
            let content = application_form(
                "/admin/applications",
                "New application",
                "Create a catalog application and (optionally) its Forgejo binary and OCI container coordinates.",
                Some(&id),
                checkbox_on(&f.is_hosted),
                &v,
                Some(&e.user_message()),
            );
            admin_response(
                &c,
                &user,
                "/admin/applications",
                "New application · Bunyip",
                content,
            )
        }
    }
}

// ===========================================================================
// Entitlements
// ===========================================================================

pub async fn entitlements(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let apps = admin_api::applications(&st.api, c.forward.as_deref())
        .await
        .unwrap_or_default();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Entitlements" } p class="mt-2 text-muted-foreground" { "Control which applications require a per-product entitlement to access." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Products" } p class="text-sm text-muted-foreground" { "Restricted products are only available to users who have been granted an entitlement." } }
                div class="p-6 pt-0" {
                    div class="divide-y" {
                        @for app in &apps {
                            div class="py-3 flex items-center justify-between gap-4" {
                                div {
                                    p class="font-medium flex items-center gap-2" { (app.display_name) @if app.requires_entitlement { (badge("default", "Restricted")) } }
                                    p class="text-xs text-muted-foreground" { (app.slug) }
                                }
                                form method="post" action=(format!("/admin/applications/{}/restricted-toggle", app.slug)) {
                                    input type="hidden" name="value" value=(if app.requires_entitlement { "false" } else { "true" });
                                    button type="submit" class=(button_class("outline", "sm", "")) { @if app.requires_entitlement { "Open" } @else { "Restrict" } }
                                }
                            }
                        }
                        @if apps.is_empty() { p class="text-center text-muted-foreground py-8" { "No applications" } }
                    }
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/entitlements",
        "Entitlements · Bunyip",
        content,
    )
}

#[derive(Deserialize)]
pub struct RestrictedForm {
    pub value: String,
}
pub async fn set_app_restricted(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(f): Form<RestrictedForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let requires_entitlement = f.value == "true";
    let _ = admin_api::set_application_restricted(
        &st.api,
        c.forward.as_deref(),
        &slug,
        requires_entitlement,
    )
    .await;
    redirect_cookies("/admin/entitlements", &c.set_cookies)
}

pub async fn user_entitlements(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let granted: Vec<UserEntitlement> = admin_api::list_user_entitlements(&st.api, fwd, &user_id)
        .await
        .unwrap_or_default();
    let apps = admin_api::applications(&st.api, fwd)
        .await
        .unwrap_or_default();

    let content = html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "User Entitlements" }
                p class="mt-2 text-muted-foreground" { "Grant or revoke per-product access for this user." }
                p class="mt-1 text-xs text-muted-foreground" { a href="/admin/users" class="hover:underline" { "Back to users" } }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Granted Entitlements" } }
                div class="p-6 pt-0" {
                    div class="divide-y" {
                        @for e in &granted {
                            div class="flex items-center justify-between py-3" {
                                div {
                                    p class="font-medium flex items-center gap-2" { (e.display_name) (badge("outline", &e.source)) }
                                    p class="text-xs text-muted-foreground" { (e.slug) " · granted " (relative_time(&e.granted_at)) }
                                }
                            }
                        }
                        @if granted.is_empty() { p class="text-center text-muted-foreground py-8" { "No entitlements granted" } }
                    }
                }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "All Products" } p class="text-sm text-muted-foreground" { "Grant or revoke any product for this user." } }
                div class="p-6 pt-0" {
                    div class="divide-y" {
                        @for app in &apps {
                            @let has = granted.iter().any(|e| e.slug == app.slug);
                            div class="py-3 flex items-center justify-between gap-4" {
                                div {
                                    p class="font-medium flex items-center gap-2" { (app.display_name) @if app.requires_entitlement { (badge("default", "Restricted")) } @if has { (badge("outline", "Granted")) } }
                                    p class="text-xs text-muted-foreground" { (app.slug) }
                                }
                                @if has {
                                    form method="post" action=(format!("/admin/users/{}/entitlements/revoke", user_id)) {
                                        input type="hidden" name="slug" value=(app.slug);
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Revoke" }
                                    }
                                } @else {
                                    form method="post" action=(format!("/admin/users/{}/entitlements/grant", user_id)) {
                                        input type="hidden" name="slug" value=(app.slug);
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Grant" }
                                    }
                                }
                            }
                        }
                        @if apps.is_empty() { p class="text-center text-muted-foreground py-8" { "No applications" } }
                    }
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/users",
        "User Entitlements · Bunyip",
        content,
    )
}

#[derive(Deserialize)]
pub struct SlugForm {
    pub slug: String,
}
pub async fn grant_user_entitlement_h(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(f): Form<SlugForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ =
        admin_api::grant_user_entitlement(&st.api, c.forward.as_deref(), &user_id, &f.slug).await;
    redirect_cookies(
        &format!("/admin/users/{user_id}/entitlements"),
        &c.set_cookies,
    )
}
pub async fn revoke_user_entitlement_h(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Form(f): Form<SlugForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ =
        admin_api::revoke_user_entitlement(&st.api, c.forward.as_deref(), &user_id, &f.slug).await;
    redirect_cookies(
        &format!("/admin/users/{user_id}/entitlements"),
        &c.set_cookies,
    )
}

// ===========================================================================
// Tier settings
// ===========================================================================

pub async fn tier_settings(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cfg = admin_api::tier_config(&st.api, c.forward.as_deref())
        .await
        .ok();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Tier Settings" } p class="mt-2 text-muted-foreground" { "Configure pricing tiers, trials, and slot limits." } }
            @match cfg {
                None => p class="text-muted-foreground" { "Could not load tier config." },
                Some(c) => div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                    div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Tiers & Slots" } p class="text-sm text-muted-foreground" { (c.lifetime_slots_used) " lifetime and " (c.early_adopter_slots_used) " early-adopter slots used." } }
                    div class="p-6 pt-0" {
                        form method="post" action="/admin/tier-settings" class="space-y-4 max-w-md" {
                            div class="space-y-2" { label class="text-sm font-medium" { "Lifetime slots" } input name="lifetime_slots" type="number" value=(c.lifetime_slots) class=(dashboard_input()); }
                            div class="space-y-2" { label class="text-sm font-medium" { "Early-adopter slots" } input name="early_adopter_slots" type="number" value=(c.early_adopter_slots) class=(dashboard_input()); }
                            div class="space-y-2" { label class="text-sm font-medium" { "Early-adopter trial days" } input name="early_adopter_trial_days" type="number" value=(c.early_adopter_trial_days) class=(dashboard_input()); }
                            div class="space-y-2" { label class="text-sm font-medium" { "Standard trial days" } input name="standard_trial_days" type="number" value=(c.standard_trial_days) class=(dashboard_input()); }
                            button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                        }
                    }
                },
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/tier-settings",
        "Tier settings · Bunyip",
        content,
    )
}

#[derive(Deserialize)]
pub struct TierForm {
    pub lifetime_slots: i64,
    pub early_adopter_slots: i64,
    pub early_adopter_trial_days: i64,
    pub standard_trial_days: i64,
}
pub async fn tier_settings_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TierForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let body = json!({ "lifetime_slots": f.lifetime_slots, "early_adopter_slots": f.early_adopter_slots, "early_adopter_trial_days": f.early_adopter_trial_days, "standard_trial_days": f.standard_trial_days });
    let _ = admin_api::update_tier_config(&st.api, c.forward.as_deref(), body).await;
    redirect_cookies("/admin/tier-settings", &c.set_cookies)
}

// ===========================================================================
// Stripe config (condensed: keys + app tag)
// ===========================================================================

pub async fn stripe(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cfg = admin_api::stripe_config(&st.api, c.forward.as_deref())
        .await
        .ok();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Stripe" } p class="mt-2 text-muted-foreground" { "Connect and configure Stripe billing." } }
            @match cfg {
                None => p class="text-muted-foreground" { "Could not load Stripe config." },
                Some(s) => div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                    div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Stripe Configuration" } p class="text-sm text-muted-foreground" { "Source: " (s.source) ". Leave a field blank to keep the existing value." } }
                    div class="p-6 pt-0" {
                        form method="post" action="/admin/stripe" class="space-y-4 max-w-md" {
                            div class="space-y-2" { label class="text-sm font-medium" { "Secret key" } input name="secret_key" type="password" placeholder=(s.secret_key_masked.clone().unwrap_or_else(|| "sk_live_…".into())) class=(dashboard_input()); }
                            div class="space-y-2" { label class="text-sm font-medium" { "Webhook secret" } input name="webhook_secret" type="password" placeholder=(s.webhook_secret_masked.clone().unwrap_or_else(|| "whsec_…".into())) class=(dashboard_input()); }
                            div class="space-y-2" { label class="text-sm font-medium" { "App tag" } input name="app_tag" value=(s.app_tag) class=(dashboard_input()); }
                            button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                        }
                    }
                },
            }
        }
    };
    admin_response(&c, &user, "/admin/stripe", "Stripe · Bunyip", content)
}

#[derive(Deserialize)]
pub struct StripeForm {
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub webhook_secret: String,
    pub app_tag: String,
}
pub async fn stripe_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<StripeForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut body = json!({ "app_tag": f.app_tag });
    if !f.secret_key.is_empty() {
        body["secret_key"] = json!(f.secret_key);
    }
    if !f.webhook_secret.is_empty() {
        body["webhook_secret"] = json!(f.webhook_secret);
    }
    let _ = admin_api::update_stripe_config(&st.api, c.forward.as_deref(), body).await;
    redirect_cookies("/admin/stripe", &c.set_cookies)
}

fn urlenc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_body_omits_empty_but_always_sends_forgejo_package() {
        // Empty optional inputs are dropped so the backend keeps the existing
        // column; forgejo_package is always present as the clear-to-NULL sentinel.
        let f = DistributionForm {
            artifact_source: "release".into(),
            forgejo_owner: "acme".into(),
            ..Default::default()
        };
        let body = distribution_update_body(&f);
        assert_eq!(body["artifact_source"], json!("release"));
        assert_eq!(body["forgejo_owner"], json!("acme"));
        assert_eq!(body["forgejo_package"], json!(""));
        assert!(body.get("forgejo_repo").is_none());
        assert!(body.get("oci_image_owner").is_none());
        // Unchecked checkbox (absent field) is sent as false, not omitted, so
        // the toggle works in both directions.
        assert_eq!(body["is_hosted"], json!(false));
    }

    #[test]
    fn update_body_sends_set_forgejo_package_and_trims() {
        let f = DistributionForm {
            artifact_source: "generic_package".into(),
            forgejo_package: "  mypkg  ".into(),
            ..Default::default()
        };
        let body = distribution_update_body(&f);
        assert_eq!(body["forgejo_package"], json!("mypkg"));
    }

    #[test]
    fn update_body_clears_package_on_release_even_if_prefilled() {
        // Switching a generic_package app to release must not re-send the stale
        // package, which would fail backend validation.
        let f = DistributionForm {
            artifact_source: "release".into(),
            forgejo_package: "leftover-pkg".into(),
            is_hosted: "true".into(),
            ..Default::default()
        };
        let body = distribution_update_body(&f);
        assert_eq!(body["forgejo_package"], json!(""));
        assert_eq!(body["is_hosted"], json!(true));
    }

    #[test]
    fn create_body_requires_identity_and_omits_empty_package() {
        // A new row has nothing to clear, so an empty forgejo_package is omitted
        // (an empty string would fail backend non-empty validation).
        let f = CreateAppForm {
            name: "Mokosh".into(),
            slug: "mokosh".into(),
            display_name: "Mokosh".into(),
            container_name: "mokosh".into(),
            ..Default::default()
        };
        let body = create_app_body(&f);
        assert_eq!(body["name"], json!("Mokosh"));
        assert_eq!(body["slug"], json!("mokosh"));
        assert_eq!(body["display_name"], json!("Mokosh"));
        assert_eq!(body["container_name"], json!("mokosh"));
        assert!(body.get("forgejo_package").is_none());
        assert!(body.get("forgejo_owner").is_none());
        // Unchecked "Hosted app" creates a catalog-only product (is_hosted=false)
        // instead of inheriting the DB default of true.
        assert_eq!(body["is_hosted"], json!(false));
    }

    #[test]
    fn create_body_sends_generic_package_and_hosted_flag() {
        let f = CreateAppForm {
            name: "Mokosh".into(),
            slug: "mokosh".into(),
            display_name: "Mokosh".into(),
            container_name: "mokosh".into(),
            artifact_source: "generic_package".into(),
            forgejo_package: "mokosh-cli".into(),
            is_hosted: "true".into(),
            ..Default::default()
        };
        let body = create_app_body(&f);
        assert_eq!(body["forgejo_package"], json!("mokosh-cli"));
        assert_eq!(body["is_hosted"], json!(true));
    }
}
