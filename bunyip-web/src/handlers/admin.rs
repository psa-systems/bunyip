//! Admin handlers. Server-rendered tables with query-param pagination and
//! form-based mutations (htmx is loaded for progressive enhancement, but the
//! baseline works without JS). Mirrors the Dioxus admin pages; the heavyweight
//! Stripe product/price/webhook managers remain condensed (see ROADMAP.md).

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
    // Only prompt when we positively know the catalog is empty (stats fetched
    // and zero apps), not when the stats call failed (PSA-57).
    let catalog_empty = stats
        .as_ref()
        .map(|s| s.total_applications == 0)
        .unwrap_or(false);

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
            @if catalog_empty {
                div class="rounded-lg border border-primary/30 bg-primary/5 p-6" {
                    div class="flex items-start gap-3" {
                        (icon("layers", "h-5 w-5 text-primary mt-0.5"))
                        div class="flex-1" {
                            h3 class="text-lg font-semibold" { "This environment has no applications yet" }
                            p class="text-sm text-muted-foreground mt-1" { "Load a starter template or import your own data to populate the catalog." }
                            a href="/admin/seed" class=(button_class("default", "sm", "mt-3")) { (icon("layers", "mr-2 h-4 w-4")) "Set up seed data" }
                        }
                    }
                }
            }
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
// Error Log (BUNYIP-327)
// ===========================================================================

#[derive(Deserialize)]
pub struct LogsQuery {
    pub category: Option<String>,
}

/// Render a single captured ERROR entry: message + category/level badges, the
/// route/client attribution line, and any extra structured fields.
fn log_row(e: &AdminErrorLog) -> Markup {
    html! {
        div class="flex items-start justify-between py-4 border-b last:border-0" {
            div class="flex items-start gap-4 min-w-0" {
                div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-destructive/10" { (icon("alert-triangle", "h-5 w-5 text-destructive")) }
                div class="min-w-0" {
                    div class="flex items-center gap-2 flex-wrap" {
                        p class="font-medium break-words" { (e.message) }
                        (badge("destructive", "Error"))
                        @if let Some(cat) = &e.category { (badge("warning", cat)) }
                    }
                    p class="text-sm text-muted-foreground break-words" {
                        span class="font-mono" { (e.target) }
                        @if let Some(r) = &e.route { " • " (r) }
                        @if let Some(cl) = &e.client { " • client " span class="font-medium text-foreground" { (cl) } }
                    }
                    @if !e.fields.is_empty() {
                        p class="text-xs text-muted-foreground mt-1 font-mono break-words" {
                            @for (k, v) in &e.fields { (k) "=" (v) "  " }
                        }
                    }
                }
            }
            p class="text-sm text-muted-foreground whitespace-nowrap" { (relative_time(&e.timestamp)) }
        }
    }
}

/// Admin error-log view (BUNYIP-327): newest-first ERROR events from the API's
/// in-memory ring buffer, filterable by category. Warnings never appear (the
/// buffer captures ERROR only).
pub async fn logs(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LogsQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let category = q
        .category
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let data = admin_api::error_logs(&st.api, c.forward.as_deref(), category)
        .await
        .ok();
    let entries = data.as_ref().map(|d| d.entries.clone()).unwrap_or_default();
    let matched = data.as_ref().map(|d| d.matched).unwrap_or(0);
    let buffered = data.as_ref().map(|d| d.buffered).unwrap_or(0);
    let capacity = data.as_ref().map(|d| d.capacity).unwrap_or(0);
    let reachable = data.is_some();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Error Logs" } p class="mt-2 text-muted-foreground" { "Live ERROR-level events from the API, held in memory and rotated (newest first). Warnings are excluded." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center justify-between gap-4 flex-wrap" {
                        div class="flex items-center gap-3" { (icon("alert-triangle", "h-5 w-5 text-destructive")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Captured Errors" } }
                        div class="flex items-center gap-2 text-sm" {
                            a href="/admin/logs" class=(button_class(if category.is_none() { "secondary" } else { "outline" }, "sm", "")) { "All" }
                            a href="/admin/logs?category=rate_limit" class=(button_class(if category == Some("rate_limit") { "secondary" } else { "outline" }, "sm", "")) { "Rate limit" }
                        }
                    }
                    @if reachable {
                        p class="text-sm text-muted-foreground" { "Showing " (matched) " of " (buffered) " buffered (capacity " (capacity) ")." }
                    }
                }
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load error logs."))
                    } @else if entries.is_empty() {
                        p class="text-center text-muted-foreground py-8" { "No errors captured" @if category.is_some() { " in this category" } "." }
                    } @else {
                        div class="space-y-0" { @for e in &entries { (log_row(e)) } }
                    }
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/logs", "Error Logs · Bunyip", content)
}

// ===========================================================================
// Seed data import / export (PSA-52)
// ===========================================================================

#[derive(Deserialize)]
pub struct SeedQuery {
    pub ok: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct SeedImportForm {
    #[serde(default)]
    pub seed_json: String,
}

#[derive(Deserialize)]
pub struct SeedTemplateForm {
    #[serde(default)]
    pub template: String,
}

/// Admin data import/export page (PSA-52): download the current seed-owned data
/// as a canonical file, or paste one to load it. Import is enforced
/// non-production by the API; the note here sets that expectation.
pub async fn seed_data(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SeedQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let templates = admin_api::seed_templates(&st.api, c.forward.as_deref())
        .await
        .unwrap_or_default();
    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Seed Data" } p class="mt-2 text-muted-foreground" { "Export the current demo data as a canonical file, or import one to populate this environment. Import is disabled in production." } }
            @if let Some(ok) = &q.ok { (success_box(ok)) }
            @if let Some(e) = &q.error { (error_box(e)) }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center gap-3" { (icon("layers", "h-5 w-5 text-primary")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Set up this environment" } }
                }
                div class="p-6 pt-0 space-y-4" {
                    p class="text-sm text-muted-foreground" { "Start empty and add your own data, or load a starter template below. Loading is idempotent and scoped to the reserved demo domain, so it only ever adds or refreshes demo rows." }
                    @if templates.is_empty() {
                        p class="text-sm text-muted-foreground" { "No starter templates are available." }
                    } @else {
                        div class="grid gap-4 md:grid-cols-2" {
                            @for t in &templates {
                                div class="rounded-md border p-4 flex flex-col gap-2" {
                                    div { h4 class="font-semibold" { (t.name) } p class="text-sm text-muted-foreground" { (t.description) } }
                                    p class="text-xs text-muted-foreground" { (format!("{} users · {} apps · {} groups · {} feedback", t.users, t.applications, t.groups, t.feedback)) }
                                    form method="post" action="/admin/seed/template" class="mt-auto" {
                                        input type="hidden" name="template" value=(t.name);
                                        button type="submit" class=(button_class("default", "sm", "")) { (icon("download", "mr-2 h-4 w-4")) "Load " (t.name) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center gap-3" { (icon("download", "h-5 w-5 text-primary")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Export" } }
                }
                div class="p-6 pt-0" {
                    p class="text-sm text-muted-foreground mb-4" { "Download the demo-domain users, feedback, and the full application catalog as a canonical seed JSON file. Passwords are never exported; re-imported accounts use the file's default password." }
                    a href="/admin/seed/export" class=(button_class("default", "default", "")) { (icon("download", "mr-2 h-4 w-4")) "Download seed export" }
                }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center gap-3" { (icon("layers", "h-5 w-5 text-primary")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Import" } }
                }
                div class="p-6 pt-0" {
                    p class="text-sm text-muted-foreground mb-4" { "Paste a canonical seed JSON file. The import is idempotent and scoped to the reserved demo domain, so it only ever adds or refreshes seed rows." }
                    form method="post" action="/admin/seed/import" class="space-y-4" {
                        textarea name="seed_json" rows="12" required placeholder="{ \"version\": 1, ... }" class="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" {}
                        button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Import seed data" }
                    }
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/seed", "Seed Data · Bunyip", content)
}

/// Stream the API's seed export straight to the browser as a file download
/// (mirrors `feedback_export`). Admin-gated; the API redacts secrets.
pub async fn seed_export(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    match st.api.get_stream("/admin/seed/export", fwd).await {
        Ok(resp) if resp.status().is_success() => {
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let disposition = resp
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .unwrap_or_else(|| "attachment; filename=\"seed-export.json\"".to_string());
            let mut builder = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_DISPOSITION, disposition);
            builder = with_attachment_hardening(builder);
            builder
                .body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| redirect_cookies("/admin/seed", &c.set_cookies))
        }
        _ => redirect_cookies(
            &format!(
                "/admin/seed?error={}",
                urlenc("Could not export seed data.")
            ),
            &c.set_cookies,
        ),
    }
}

/// Handle the paste-and-import form: validate the text is JSON, forward it to
/// the API loader, and report the section counts (or the error) back on the
/// page.
pub async fn seed_import(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<SeedImportForm>,
) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let value: serde_json::Value = match serde_json::from_str(&f.seed_json) {
        Ok(v) => v,
        Err(e) => {
            return redirect_cookies(
                &format!(
                    "/admin/seed?error={}",
                    urlenc(&format!("That is not valid JSON: {e}"))
                ),
                &c.set_cookies,
            );
        }
    };
    match admin_api::import_seed(&st.api, c.forward.as_deref(), value).await {
        Ok(s) => redirect_cookies(
            &format!(
                "/admin/seed?ok={}",
                urlenc(&format!(
                    "Imported {} users, {} apps, {} groups, {} entitlements, {} feedback.",
                    s.users, s.applications, s.groups, s.entitlements, s.feedback
                ))
            ),
            &c.set_cookies,
        ),
        Err(e) => redirect_cookies(
            &format!("/admin/seed?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

/// Load a named starter template (PSA-57): forward the selected name to the API
/// loader and report the section counts (or the error) back on the page.
pub async fn seed_load_template(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<SeedTemplateForm>,
) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = f.template.trim();
    if name.is_empty() {
        return redirect_cookies(
            &format!("/admin/seed?error={}", urlenc("No template selected.")),
            &c.set_cookies,
        );
    }
    match admin_api::import_seed_template(&st.api, c.forward.as_deref(), name).await {
        Ok(s) => redirect_cookies(
            &format!(
                "/admin/seed?ok={}",
                urlenc(&format!(
                    "Loaded template '{name}': {} users, {} apps, {} groups, {} entitlements, {} feedback.",
                    s.users, s.applications, s.groups, s.entitlements, s.feedback
                ))
            ),
            &c.set_cookies,
        ),
        Err(e) => redirect_cookies(
            &format!("/admin/seed?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

// ===========================================================================
// IP auto-bans (BUNYIP-320)
// ===========================================================================

/// Render one active IP auto-ban row: the banned IP, reason, strike count, when
/// it was banned and when it expires, plus an Unban button that POSTs to the
/// lift handler.
fn ip_ban_row(b: &AdminIpBan) -> Markup {
    html! {
        div class="flex items-start justify-between py-4 border-b last:border-0" {
            div class="flex items-start gap-4 min-w-0" {
                div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-destructive/10" { (icon("shield-off", "h-5 w-5 text-destructive")) }
                div class="min-w-0" {
                    div class="flex items-center gap-2 flex-wrap" {
                        p class="font-medium font-mono break-all" { (b.ip) }
                        (badge("destructive", "Banned"))
                        (badge("warning", &format!("{} strikes", b.strikes)))
                    }
                    p class="text-sm text-muted-foreground break-words" { (b.reason) }
                    p class="text-xs text-muted-foreground" {
                        "Banned " (relative_time(&b.banned_at)) " • expires " (relative_time(&b.expires_at))
                    }
                }
            }
            form method="post" action="/admin/ip-bans/unban" data-confirm=(format!("Lift the ban on {}? It takes effect on the next request.", b.ip)) {
                input type="hidden" name="ip" value=(b.ip);
                button type="submit" class=(button_class("outline", "sm", "")) { "Unban" }
            }
        }
    }
}

/// BUNYIP-413: refuse a super-admin-only form to everybody else, as a redirect
/// back to `back` carrying a refusal toast. The API enforces the same gate, so
/// this is a friendlier message rather than the security boundary.
fn refuse_non_super_admin(user: &User, c: &AuthCtx, back: &str) -> Option<Response> {
    if user.is_super_admin {
        return None;
    }
    Some(redirect_cookies(
        &format!("{back}?toast_err=Only%20the%20super%20admin%20can%20change%20this"),
        &c.set_cookies,
    ))
}

/// Default manual-ban duration offered by the form: 24 hours, matching the
/// API's default. The API bounds the value; the input mirrors those bounds.
const DEFAULT_MANUAL_BAN_SECS: i64 = 86_400;
const MIN_MANUAL_BAN_SECS: i64 = 60;
const MAX_MANUAL_BAN_SECS: i64 = 31_536_000;

/// The "add a ban" card (BUNYIP-413): address, reason and duration. Rendered
/// only for the super admin, who is the only account the API will accept it
/// from.
/// `prefill_ip` seeds the address field so a "Ban this address" link from
/// elsewhere (BUNYIP-436: the feedback detail IP) lands here ready to submit.
fn ip_ban_add_card(prefill_ip: Option<&str>) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex items-center gap-3" { (icon("shield-off", "h-5 w-5 text-primary")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Add Ban" } }
                p class="text-sm text-muted-foreground" { "Block an address by hand. The ban takes effect on its next request and expires on its own." }
            }
            div class="p-6 pt-0" {
                form method="post" action="/admin/ip-bans/add" class="grid gap-4 sm:grid-cols-4 sm:items-end" {
                    div class="space-y-2 sm:col-span-1" { label class="text-sm font-medium" { "IP address" } input name="ip" required placeholder="203.0.113.7" value=(prefill_ip.unwrap_or_default()) class=(dashboard_input()); }
                    div class="space-y-2 sm:col-span-2" { label class="text-sm font-medium" { "Reason" } input name="reason" required maxlength="255" placeholder="Credential stuffing" class=(dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "Duration (seconds)" } input name="duration_secs" type="number" min=(MIN_MANUAL_BAN_SECS) max=(MAX_MANUAL_BAN_SECS) value=(DEFAULT_MANUAL_BAN_SECS) class=(dashboard_input()); }
                    div class="sm:col-span-4" { button type="submit" class=(button_class("default", "default", "")) { (icon("shield-off", "mr-2 h-4 w-4")) "Ban address" } }
                }
            }
        }
    }
}

/// Query for the IP bans page. `ip` prefills the add-ban form so a
/// "Ban this address" link (BUNYIP-436: from the feedback detail IP) arrives
/// ready to submit.
#[derive(Deserialize)]
pub struct IpBansQuery {
    pub ip: Option<String>,
}

/// Admin IP auto-ban view (BUNYIP-320): the currently-active IP bans surfaced by
/// the subtask 7 endpoint, each liftable in place. AdminUser-guarded like the
/// other admin pages; the add form (BUNYIP-413) is super-admin-only.
pub async fn ip_bans(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<IpBansQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let data = admin_api::ip_bans(&st.api, c.forward.as_deref()).await;
    let reachable = data.is_ok();
    let bans = data.unwrap_or_default();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "IP Bans" } p class="mt-2 text-muted-foreground" { "IP addresses banned for abusive request patterns, automatically or by hand. Adding or lifting a ban takes effect on the address's next request." } }
            @if user.is_super_admin { (ip_ban_add_card(q.ip.as_deref())) }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center gap-3" { (icon("shield-off", "h-5 w-5 text-destructive")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Active Bans" } }
                    @if reachable { p class="text-sm text-muted-foreground" { (bans.len()) " active." } }
                }
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load IP bans."))
                    } @else if bans.is_empty() {
                        p class="text-center text-muted-foreground py-8" { "No active IP bans." }
                    } @else {
                        // BUNYIP-415: flow ban rows into two columns (one below
                        // lg) so the list uses the width instead of a single
                        // narrow stack.
                        div class="grid gap-x-8 lg:grid-cols-2" { @for b in &bans { (ip_ban_row(b)) } }
                    }
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/ip-bans", "IP Bans · Bunyip", content)
}

/// Form body for the add-ban action (BUNYIP-413). `duration_secs` is a string
/// so a typo comes back as a toast rather than a 422 from extraction.
#[derive(Deserialize)]
pub struct CreateBanForm {
    pub ip: String,
    pub reason: String,
    #[serde(default)]
    pub duration_secs: String,
}

/// Ban an IP by hand (BUNYIP-413), then redirect back to the list with a
/// success/error toast. Super-admin-only, enforced again by the API, which
/// validates the address, reason and duration and audits the ban.
pub async fn ip_ban_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<CreateBanForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(refusal) = refuse_non_super_admin(&user, &c, "/admin/ip-bans") {
        return refusal;
    }
    let duration = match f.duration_secs.trim() {
        "" => DEFAULT_MANUAL_BAN_SECS,
        raw => match raw.parse::<i64>() {
            Ok(n) => n,
            Err(_) => {
                return redirect_cookies(
                    "/admin/ip-bans?toast_err=Duration%20must%20be%20a%20whole%20number",
                    &c.set_cookies,
                )
            }
        },
    };
    let target = match admin_api::create_ip_ban(
        &st.api,
        c.forward.as_deref(),
        f.ip.trim(),
        f.reason.trim(),
        duration,
    )
    .await
    {
        Ok(()) => format!("/admin/ip-bans?toast_ok=Banned%20{}", urlenc(f.ip.trim())),
        Err(e) => format!("/admin/ip-bans?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// Form body for the unban action: the IP to lift, carried in a hidden field so
/// an IPv6 address never has to sit in the URL path.
#[derive(Deserialize)]
pub struct UnbanForm {
    pub ip: String,
}

/// Lift an IP auto-ban (BUNYIP-320), then redirect back to the list with a
/// success/error toast. AdminUser-guarded.
pub async fn ip_unban(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<UnbanForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::unban_ip(&st.api, c.forward.as_deref(), &f.ip).await {
        Ok(()) => format!(
            "/admin/ip-bans?toast_ok=Ban%20lifted%20for%20{}",
            urlenc(&f.ip)
        ),
        Err(_) => "/admin/ip-bans?toast_err=Could%20not%20lift%20ban".to_string(),
    };
    redirect_cookies(&target, &c.set_cookies)
}

// ===========================================================================
// Rate limits (BUNYIP-317)
// ===========================================================================

/// Format a `retry_after` second count as a compact "retry in" label
/// (e.g. `2m 5s`, `45s`). Zero (or a window that has just elapsed) reads as
/// "any moment", since the throttle clears on the next request.
fn fmt_retry_secs(secs: u64) -> String {
    if secs == 0 {
        return "any moment".to_string();
    }
    let mins = secs / 60;
    let rem = secs % 60;
    if mins == 0 {
        format!("{rem}s")
    } else if rem == 0 {
        format!("{mins}m")
    } else {
        format!("{mins}m {rem}s")
    }
}

/// Render one active throttle row: the subject (resolved user email, else the
/// source IP, else the raw key), the throttled action, the count vs cap, the
/// window start and the computed retry-in, plus a Reset button that POSTs the
/// `(action, key)` pair to the reset endpoint.
///
/// `return_user` carries the id of the user whose detail page this row is
/// rendered on (`None` on the standalone list): the reset redirects back there
/// so the user-detail context is preserved.
fn rate_limit_row(rl: &AdminRateLimit, return_user: Option<&str>) -> Markup {
    let (subject, subject_sub, icon_name) = if let Some(email) = &rl.user_email {
        (email.clone(), rl.user_id.clone(), "user")
    } else if let Some(ip) = &rl.ip {
        (ip.clone(), None, "globe")
    } else {
        (rl.key.clone(), None, "help-circle")
    };
    html! {
        div class="flex items-start justify-between py-4 border-b last:border-0" {
            div class="flex items-start gap-4 min-w-0" {
                div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-muted" { (icon(icon_name, "h-5 w-5 text-muted-foreground")) }
                div class="min-w-0" {
                    div class="flex items-center gap-2 flex-wrap" {
                        p class="font-medium break-all" { (subject) }
                        (badge("secondary", &title_case(&rl.action)))
                        (badge("warning", &format!("{}/{}", rl.count, rl.max_requests)))
                    }
                    @if let Some(sub) = &subject_sub {
                        p class="text-xs text-muted-foreground font-mono break-all" { (sub) }
                    }
                    p class="text-xs text-muted-foreground" {
                        "Window started " (relative_time(&rl.window_start)) " • retry in " (fmt_retry_secs(rl.retry_after))
                    }
                }
            }
            form method="post" action="/admin/rate-limits/reset" data-confirm=(format!("Reset the {} throttle? The affected user/IP can act again immediately.", title_case(&rl.action))) {
                input type="hidden" name="action" value=(rl.action);
                input type="hidden" name="key" value=(rl.key);
                @if let Some(uid) = return_user {
                    input type="hidden" name="return_user" value=(uid);
                }
                button type="submit" class=(button_class("outline", "sm", "")) { "Reset" }
            }
        }
    }
}

/// Bounds on an admin-set limit, mirroring the API's validation so the input
/// refuses out-of-range values before the round-trip.
const MAX_LIMIT_REQUESTS: i32 = 1_000_000;
const MAX_LIMIT_WINDOW_SECS: i64 = 604_800; // 7 days

/// Format a window length as a compact label (`60s`, `10m`, `1h`).
fn fmt_window_secs(secs: i64) -> String {
    if secs % 3600 == 0 && secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 && secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Render one configurable limit (BUNYIP-413): the action, its effective
/// cap/window as editable fields, and (when a persisted override is in force)
/// what the bootstrap default was plus a button to revert to it.
///
/// `editable` is the super-admin flag: everybody else sees the same numbers as
/// plain text, since the API would refuse their write anyway.
fn rate_limit_config_row(cfg: &AdminRateLimitConfig, editable: bool) -> Markup {
    html! {
        div class="flex items-start justify-between gap-4 py-4 border-b last:border-0" {
            div class="min-w-0" {
                div class="flex items-center gap-2 flex-wrap" {
                    p class="font-medium break-all" { (title_case(&cfg.action)) }
                    @if cfg.overridden { (badge("warning", "Overridden")) } @else { (badge("secondary", "Default")) }
                }
                p class="text-xs text-muted-foreground" {
                    @if cfg.overridden {
                        "Default " (cfg.default_max_requests) " per " (fmt_window_secs(cfg.default_window_seconds))
                    } @else {
                        (cfg.max_requests) " requests per " (fmt_window_secs(cfg.window_seconds))
                    }
                }
            }
            @if editable {
                div class="flex items-end gap-2 shrink-0" {
                    form method="post" action="/admin/rate-limits/config" class="flex items-end gap-2" {
                        input type="hidden" name="action" value=(cfg.action);
                        div class="space-y-1" { label class="text-xs text-muted-foreground" { "Requests" } input name="max_requests" type="number" min="1" max=(MAX_LIMIT_REQUESTS) value=(cfg.max_requests) class=(format!("{} w-28", dashboard_input())); }
                        div class="space-y-1" { label class="text-xs text-muted-foreground" { "Window (s)" } input name="window_seconds" type="number" min="1" max=(MAX_LIMIT_WINDOW_SECS) value=(cfg.window_seconds) class=(format!("{} w-28", dashboard_input())); }
                        button type="submit" class=(button_class("default", "sm", "")) { "Save" }
                    }
                    @if cfg.overridden {
                        form method="post" action="/admin/rate-limits/config/reset" data-confirm=(format!("Revert {} to its default limit?", title_case(&cfg.action))) {
                            input type="hidden" name="action" value=(cfg.action);
                            button type="submit" class=(button_class("outline", "sm", "")) { "Revert" }
                        }
                    }
                }
            } @else {
                p class="text-sm text-muted-foreground shrink-0" { (cfg.max_requests) " / " (fmt_window_secs(cfg.window_seconds)) }
            }
        }
    }
}

/// The "limit configuration" card (BUNYIP-413): every enforced action with its
/// cap and window, editable by the super admin. `reachable` distinguishes an
/// API that could not be reached from a genuinely empty list.
fn rate_limit_config_card(
    configs: &[AdminRateLimitConfig],
    reachable: bool,
    editable: bool,
) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex items-center gap-3" { (icon("sliders-horizontal", "h-5 w-5 text-primary")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Limit Configuration" } }
                p class="text-sm text-muted-foreground" {
                    @if editable {
                        "The cap and window enforced for each action. A saved value takes effect on the next request; Revert restores the built-in default."
                    } @else {
                        "The cap and window enforced for each action. Only the super admin can change them."
                    }
                }
            }
            div class="p-6 pt-0" {
                @if !reachable {
                    (error_box("Could not reach the API to load the limit configuration."))
                } @else {
                    div class="grid gap-x-8 lg:grid-cols-2" { @for cfg in configs { (rate_limit_config_row(cfg, editable)) } }
                }
            }
        }
    }
}

/// Admin rate-limit view (BUNYIP-317): the currently-active throttles surfaced
/// by the BUNYIP-315 endpoint, each resettable in place via the BUNYIP-316
/// endpoint, plus the configurable caps and windows themselves (BUNYIP-413).
/// AdminUser-guarded like the other admin pages; editing a limit is
/// super-admin-only.
pub async fn rate_limits(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let cfg_data = admin_api::rate_limit_configs(&st.api, c.forward.as_deref()).await;
    let configs_reachable = cfg_data.is_ok();
    let configs = cfg_data.unwrap_or_default();
    let data = admin_api::rate_limits(&st.api, c.forward.as_deref(), page, 20).await;
    let reachable = data.is_ok();
    let (items, total, total_pages) = match data {
        Ok(p) => (p.items, p.total, p.total_pages),
        Err(_) => (Vec::new(), 0, 1),
    };

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Rate Limits" } p class="mt-2 text-muted-foreground" { "Entities currently throttled by a rate limit. Resetting a throttle lets the affected user or IP act again immediately." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center gap-3" { (icon("gauge", "h-5 w-5 text-primary")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Active Throttles" } }
                    @if reachable { p class="text-sm text-muted-foreground" { (total) " active." } }
                }
                div class="p-6 pt-0" {
                    @if !reachable {
                        (error_box("Could not reach the API to load rate limits."))
                    } @else if items.is_empty() {
                        p class="text-center text-muted-foreground py-8" { "No active rate limits." }
                    } @else {
                        // BUNYIP-415: flow throttle rows into two columns (one
                        // below lg) so a long list uses the width. Each row keeps
                        // its own bottom-border separator.
                        div class="grid gap-x-8 lg:grid-cols-2" { @for rl in &items { (rate_limit_row(rl, None)) } }
                        (pager("/admin/rate-limits", page, total_pages))
                    }
                }
            }
            (rate_limit_config_card(&configs, configs_reachable, user.is_super_admin))
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/rate-limits",
        "Rate Limits · Bunyip",
        content,
    )
}

/// Form body for the reset action: the `(action, key)` identifying the throttle,
/// plus an optional `return_user` carrying the user-detail page to redirect back
/// to (empty/absent redirects to the standalone list).
#[derive(Deserialize)]
pub struct RateLimitResetForm {
    pub action: String,
    pub key: String,
    #[serde(default)]
    pub return_user: Option<String>,
}

/// Reset one active throttle (BUNYIP-317), then redirect back to the originating
/// view (the user-detail page when `return_user` is set, else the list) with a
/// success/error toast. AdminUser-guarded; the reset is audited on the API.
pub async fn rate_limit_reset(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<RateLimitResetForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // The return context is always a local admin path: a bare `return_user`
    // becomes `/admin/users/{id}`, never an attacker-controlled URL.
    let base = match f.return_user.as_deref() {
        Some(uid) if !uid.is_empty() => format!("/admin/users/{}", urlenc(uid)),
        _ => "/admin/rate-limits".to_string(),
    };
    let target =
        match admin_api::reset_rate_limit(&st.api, c.forward.as_deref(), &f.action, &f.key).await {
            Ok(()) => format!("{base}?toast_ok=Rate%20limit%20reset"),
            Err(_) => format!("{base}?toast_err=Could%20not%20reset%20rate%20limit"),
        };
    redirect_cookies(&target, &c.set_cookies)
}

/// Form body for saving one limit's configuration (BUNYIP-413). The numerics
/// are strings so a typo comes back as a toast rather than a 422.
#[derive(Deserialize)]
pub struct RateLimitConfigForm {
    pub action: String,
    pub max_requests: String,
    pub window_seconds: String,
}

/// Create or update the persisted override for one action (BUNYIP-413), then
/// redirect back to the list with a toast. Super-admin-only, enforced again by
/// the API, which validates and audits the change.
pub async fn rate_limit_config_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<RateLimitConfigForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(refusal) = refuse_non_super_admin(&user, &c, "/admin/rate-limits") {
        return refusal;
    }
    let (max_requests, window_seconds) = match (
        f.max_requests.trim().parse::<i32>(),
        f.window_seconds.trim().parse::<i64>(),
    ) {
        (Ok(m), Ok(w)) => (m, w),
        _ => return redirect_cookies(
            "/admin/rate-limits?toast_err=Requests%20and%20window%20must%20be%20whole%20numbers",
            &c.set_cookies,
        ),
    };
    let target = match admin_api::set_rate_limit_config(
        &st.api,
        c.forward.as_deref(),
        f.action.trim(),
        max_requests,
        window_seconds,
    )
    .await
    {
        Ok(()) => "/admin/rate-limits?toast_ok=Rate%20limit%20updated".to_string(),
        Err(e) => format!("/admin/rate-limits?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// Form body for reverting one limit to its default: the action alone.
#[derive(Deserialize)]
pub struct RateLimitConfigResetForm {
    pub action: String,
}

/// Drop the persisted override for one action (BUNYIP-413), reverting it to the
/// bootstrap default, then redirect back with a toast. Super-admin-only.
pub async fn rate_limit_config_reset(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<RateLimitConfigResetForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(refusal) = refuse_non_super_admin(&user, &c, "/admin/rate-limits") {
        return refusal;
    }
    let target =
        match admin_api::delete_rate_limit_config(&st.api, c.forward.as_deref(), f.action.trim())
            .await
        {
            Ok(()) => {
                "/admin/rate-limits?toast_ok=Reverted%20to%20the%20default%20limit".to_string()
            }
            Err(e) => format!("/admin/rate-limits?toast_err={}", urlenc(&e.user_message())),
        };
    redirect_cookies(&target, &c.set_cookies)
}

// ===========================================================================
// Users
// ===========================================================================

#[derive(Deserialize)]
pub struct UserQuery {
    pub page: Option<u32>,
    pub search: Option<String>,
    /// Soft-delete segment: `active` (default) / `suspended` / `all` (BUNYIP-410
    /// overhaul; was a bare `suspended` toggle).
    pub status: Option<String>,
    /// Membership-tier filter (`early_adopter` / `standard` / `lifetime` /
    /// `free`); blank / absent = all tiers.
    #[serde(default)]
    pub tier: Option<String>,
    /// Verification filter (`verified` / `unverified`); blank / absent = both.
    #[serde(default)]
    pub verified: Option<String>,
    /// Whitelisted sort column (`email` / `tier` / `verified` / `joined`).
    #[serde(default)]
    pub sort: Option<String>,
    /// Sort direction (`asc` / `desc`); absent = `desc`.
    #[serde(default)]
    pub dir: Option<String>,
    /// Rows per page (10 / 20 / 50 / 100); clamped server-side.
    #[serde(default)]
    pub page_size: Option<u32>,
}

/// BUNYIP-410 overhaul: map the `verified` filter query value to the API's
/// tri-state filter. `verified` -> only verified, `unverified` -> only
/// unverified, anything else -> no filter (both).
fn parse_verified_filter(s: &str) -> Option<bool> {
    match s {
        "verified" => Some(true),
        "unverified" => Some(false),
        _ => None,
    }
}

/// Human-readable label for a membership tier badge.
fn tier_label(tier: &crate::api::types::SubscriptionTier) -> &'static str {
    use crate::api::types::SubscriptionTier::*;
    match tier {
        Lifetime => "Lifetime",
        Free => "Free",
        EarlyAdopter => "Early Adopter",
        Standard => "Standard",
    }
}

/// Format an ISO-8601 timestamp as a compact absolute date for the `title`
/// tooltip on a relative "Joined X ago" label. Falls back to the raw string when
/// it does not parse.
fn abs_time(iso: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(iso)
        .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|_| iso.to_string())
}

/// BUNYIP-410 overhaul: the complete filter + sort + page state for the admin
/// users list. Every link on the page (dropdown option, segment, sort header,
/// chip removal, pager, page-size) is derived from this one struct via the
/// builder methods, so the URL is the single source of truth and stays
/// internally consistent (a filter change always resets the page to 1).
#[derive(Clone)]
struct UsersQ {
    search: String,
    status: String,
    tier: String,
    verified: String,
    sort: String,
    dir: String,
    page: u32,
    page_size: u32,
}

impl UsersQ {
    fn from_query(q: UserQuery) -> Self {
        let status = match q.status.as_deref() {
            Some("suspended") => "suspended",
            Some("all") => "all",
            _ => "active",
        }
        .to_string();
        let dir = match q.dir.as_deref() {
            Some("asc") => "asc",
            _ => "desc",
        }
        .to_string();
        Self {
            search: q.search.unwrap_or_default().trim().to_string(),
            status,
            tier: q.tier.unwrap_or_default(),
            verified: q.verified.unwrap_or_default(),
            sort: q.sort.unwrap_or_default(),
            dir,
            page: q.page.unwrap_or(1).max(1),
            page_size: q.page_size.unwrap_or(20).clamp(10, 100),
        }
    }

    /// Build the `/admin/users` URL for this state, emitting only non-default
    /// params so a clean list is a clean URL.
    fn href(&self) -> String {
        let mut p: Vec<String> = Vec::new();
        if !self.search.is_empty() {
            p.push(format!("search={}", urlenc(&self.search)));
        }
        if self.status != "active" {
            p.push(format!("status={}", self.status));
        }
        if !self.tier.is_empty() {
            p.push(format!("tier={}", self.tier));
        }
        if !self.verified.is_empty() {
            p.push(format!("verified={}", self.verified));
        }
        if !self.sort.is_empty() {
            p.push(format!("sort={}&dir={}", self.sort, self.dir));
        }
        if self.page > 1 {
            p.push(format!("page={}", self.page));
        }
        if self.page_size != 20 {
            p.push(format!("page_size={}", self.page_size));
        }
        if p.is_empty() {
            "/admin/users".to_string()
        } else {
            format!("/admin/users?{}", p.join("&"))
        }
    }

    fn with_search(&self, v: &str) -> Self {
        let mut q = self.clone();
        q.search = v.trim().to_string();
        q.page = 1;
        q
    }
    fn with_status(&self, v: &str) -> Self {
        let mut q = self.clone();
        q.status = v.to_string();
        q.page = 1;
        q
    }
    fn with_tier(&self, v: &str) -> Self {
        let mut q = self.clone();
        q.tier = v.to_string();
        q.page = 1;
        q
    }
    fn with_verified(&self, v: &str) -> Self {
        let mut q = self.clone();
        q.verified = v.to_string();
        q.page = 1;
        q
    }
    fn with_page(&self, v: u32) -> Self {
        let mut q = self.clone();
        q.page = v;
        q
    }
    fn with_page_size(&self, v: u32) -> Self {
        let mut q = self.clone();
        q.page_size = v;
        q.page = 1;
        q
    }
    /// Toggle sort on `col`: same column flips direction, a new column starts
    /// ascending.
    fn with_sort(&self, col: &str) -> Self {
        let mut q = self.clone();
        q.page = 1;
        if q.sort == col {
            q.dir = if q.dir == "asc" { "desc" } else { "asc" }.to_string();
        } else {
            q.sort = col.to_string();
            q.dir = "asc".to_string();
        }
        q
    }

    /// True when any content filter (search / tier / verification) or a
    /// non-default status segment is applied - i.e. the list is narrowed.
    fn is_filtered(&self) -> bool {
        !self.search.is_empty()
            || !self.tier.is_empty()
            || !self.verified.is_empty()
            || self.status != "active"
    }
}

/// Grid column template shared by the header row and every data row so the
/// columns line up. Inline (not a Tailwind arbitrary value) so it needs no
/// stylesheet rebuild. Columns: avatar, email, tier, verification, joined,
/// action.
const USERS_GRID: &str =
    "grid-template-columns:2.25rem minmax(0,1fr) auto auto 8.5rem 1.5rem;display:grid;align-items:center;gap:0.75rem";

pub async fn users(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<UserQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let uq = UsersQ::from_query(q);
    let data = admin_api::users(
        &st.api,
        c.forward.as_deref(),
        uq.page,
        uq.page_size,
        &uq.search,
        &uq.status,
        &uq.tier,
        parse_verified_filter(&uq.verified),
        &uq.sort,
        &uq.dir,
    )
    .await;
    // Denominator for "N of M users". stats.total_users counts live accounts;
    // good enough for the common Active view and only ever a hint.
    let total_all = admin_api::stats(&st.api, c.forward.as_deref())
        .await
        .map(|s| s.total_users)
        .ok();

    let panel = users_panel(&uq, data.as_ref().ok(), total_all);

    // BUNYIP-410 overhaul: htmx swaps just the panel (search-as-you-type, sort,
    // filter, page) so focus and scroll survive and there is no full reload. A
    // non-htmx request (first load, no-JS, refresh) gets the whole page. The URL
    // is pushed by htmx either way, so refresh / back / shareable links work.
    if headers.contains_key("HX-Request") {
        return Html(panel.into_string()).into_response();
    }

    let content = html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "Users" }
                p class="mt-2 text-muted-foreground" { "Manage user accounts, membership tier, and verification." }
            }
            (panel)
        }
        style { (maud::PreEscaped(USERS_FILTER_CSS)) }
        script src="/assets/js/admin-users.js" defer {}
    };
    admin_response(&c, &user, "/admin/users", "Users · Bunyip", content)
}

/// Friendly label for a tier slug (for chips).
fn tier_slug_label(slug: &str) -> &'static str {
    match slug {
        "early_adopter" => "Early Adopter",
        "standard" => "Standard",
        "lifetime" => "Lifetime",
        "free" => "Free",
        _ => "Any",
    }
}

/// One of the two filter dropdowns (verification / tier), styled with the app's
/// own `<details>` menu (matches the profile menu; `assets/js/app.js` closes it
/// on click-away / Escape). The trigger keeps a persistent prefix
/// ("Verification: Any") so a filtered state is always legible. `options` is
/// `(href, label, selected)`.
fn filter_dropdown(prefix: &str, current: &str, options: &[(String, String, bool)]) -> Markup {
    html! {
        details class="relative" data-menu {
            summary class="flex items-center gap-1.5 cursor-pointer list-none rounded-md border border-input bg-background px-3 h-10 text-sm hover:bg-accent hover:text-accent-foreground transition-colors [&::-webkit-details-marker]:hidden focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2" {
                span class="text-muted-foreground" { (prefix) ":" }
                span class="font-medium whitespace-nowrap" { (current) }
                (icon("chevron-down", "h-4 w-4 text-muted-foreground shrink-0"))
            }
            div class="absolute left-0 z-50 mt-1 min-w-[11rem] overflow-hidden rounded-md border border-border/60 bg-background py-1 shadow-lg" {
                @for (href, label, selected) in options {
                    a href=(href) hx-get=(href) hx-target="#users-panel" hx-swap="outerHTML" hx-push-url="true" hx-indicator="#users-loading"
                      class={ "flex items-center gap-2 px-3 py-2 text-sm hover:bg-accent hover:text-accent-foreground transition-colors " (if *selected { "font-medium text-foreground" } else { "text-muted-foreground" }) } {
                        span class="inline-flex w-4 shrink-0" { @if *selected { (icon("check", "h-4 w-4 text-primary")) } }
                        (label)
                    }
                }
            }
        }
    }
}

/// The Active / All / Suspended segmented control (single element, one selected,
/// arrow-key navigable via `data-segmented` in `assets/js/admin-users.js`, radiogroup
/// ARIA).
fn segmented_control(uq: &UsersQ) -> Markup {
    let seg = |value: &str, label: &str| -> Markup {
        let selected = uq.status == value;
        let href = uq.with_status(value).href();
        html! {
            a role="radio" aria-checked=(if selected { "true" } else { "false" })
              tabindex=(if selected { "0" } else { "-1" })
              href=(href) hx-get=(href) hx-target="#users-panel" hx-swap="outerHTML" hx-push-url="true" hx-indicator="#users-loading"
              class={ "px-3 h-8 inline-flex items-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring " (if selected { "bg-background text-foreground shadow-sm" } else { "text-muted-foreground hover:text-foreground" }) } {
                (label)
            }
        }
    };
    html! {
        div role="radiogroup" aria-label="Account status" data-segmented
            class="inline-flex items-center gap-1 rounded-lg border border-input bg-muted p-1" {
            (seg("active", "Active"))
            (seg("all", "All"))
            (seg("suspended", "Suspended"))
        }
    }
}

/// A sortable column header. A link (no-JS: navigates; JS: swaps the panel), with
/// Space-key activation added in `assets/js/admin-users.js` and a direction chevron on the
/// active column.
fn sort_header(uq: &UsersQ, col: &str, label: &str) -> Markup {
    let active = uq.sort == col;
    let href = uq.with_sort(col).href();
    html! {
        a data-sort-header href=(href) hx-get=(href) hx-target="#users-panel" hx-swap="outerHTML" hx-push-url="true" hx-indicator="#users-loading"
          aria-sort=(if active { if uq.dir == "asc" { "ascending" } else { "descending" } } else { "none" })
          class={ "inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wide rounded transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring " (if active { "text-foreground" } else { "text-muted-foreground hover:text-foreground" }) } {
            (label)
            @if active {
                @if uq.dir == "asc" { (icon("chevron-up", "h-3.5 w-3.5")) } @else { (icon("chevron-down", "h-3.5 w-3.5")) }
            }
        }
    }
}

/// The verification indicator (green check / amber alert), shared by rows.
fn verified_indicator(verified: bool) -> Markup {
    html! {
        @if verified {
            span class="inline-flex items-center gap-1 text-xs font-medium text-teal-600 dark:text-teal-400" { (icon("check-circle", "h-4 w-4")) "Verified" }
        } @else {
            span class="inline-flex items-center gap-1 text-xs font-medium text-yellow-600" { (icon("alert-circle", "h-4 w-4")) "Unverified" }
        }
    }
}

/// One user row in the grid. Active users are a whole-row link into the detail
/// (hover background + focus-visible ring, chevron hint). Suspended users cannot
/// open the detail (a soft-deleted lookup 404s), so their row is not a link and
/// carries an inline Reactivate action instead - this matters on the "All"
/// segment where the two are interleaved.
fn user_grid_row(u: &crate::api::types::AdminUser) -> Markup {
    let is_admin = matches!(u.role, crate::api::types::UserRole::Admin);
    let initial = u
        .email
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string());
    let avatar = html! {
        span class="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-primary to-indigo-500 text-white text-xs font-semibold" aria-hidden="true" { (initial) }
    };
    let identity = html! {
        div class="min-w-0" {
            // `truncate` must sit on the text span, not on this flex row:
            // ellipsis/nowrap do not apply to a flex container, so a long email
            // took its full width and pushed the badges outside the row's
            // `overflow:hidden`, clipping them away entirely (BUNYIP-421).
            p class="font-medium flex items-center gap-2 min-w-0" {
                span class="truncate" { (u.email) }
                @if is_admin { (badge("default", "Admin")) }
                @if u.suspended { (badge("outline", "Suspended")) }
            }
        }
    };
    let tier = html! { (badge("secondary", tier_label(&u.subscription_tier))) };
    let joined = html! {
        span class="text-xs text-muted-foreground" title=(abs_time(&u.created_at)) { "Joined " (relative_time(&u.created_at)) }
    };
    if u.suspended {
        html! {
            div style=(USERS_GRID) class="py-2.5 px-2 -mx-2 rounded-md" {
                (avatar) (identity) (tier) (verified_indicator(u.email_verified)) (joined)
                form method="post" action=(format!("/admin/users/{}/reactivate", u.id)) data-confirm="Reactivate this user? They will be able to sign in again." {
                    button type="submit" class=(button_class("outline", "sm", "h-8 px-2 text-xs")) { "Reactivate" }
                }
            }
        }
    } else {
        html! {
            a href=(format!("/admin/users/{}", u.id))
              style=(USERS_GRID)
              class="py-2.5 px-2 -mx-2 rounded-md hover:bg-accent hover:text-accent-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2" {
                (avatar) (identity) (tier) (verified_indicator(u.email_verified)) (joined)
                span class="flex justify-end" { (icon("chevron-right", "h-4 w-4 text-muted-foreground")) }
            }
        }
    }
}

/// Removable filter chips + "Clear all", in a reserved-height row so their
/// appearance never shifts the list. Empty (no chips) still occupies the row.
fn filter_chips(uq: &UsersQ) -> Markup {
    let mut chips: Vec<(String, String)> = Vec::new();
    if !uq.search.is_empty() {
        chips.push((format!("Search: {}", uq.search), uq.with_search("").href()));
    }
    if uq.status != "active" {
        let l = if uq.status == "suspended" {
            "Suspended"
        } else {
            "All"
        };
        chips.push((format!("Status: {l}"), uq.with_status("active").href()));
    }
    if !uq.verified.is_empty() {
        let l = if uq.verified == "verified" {
            "Verified"
        } else {
            "Unverified"
        };
        chips.push((format!("Verification: {l}"), uq.with_verified("").href()));
    }
    if !uq.tier.is_empty() {
        chips.push((
            format!("Tier: {}", tier_slug_label(&uq.tier)),
            uq.with_tier("").href(),
        ));
    }
    // Clear all keeps sort + page size, resets only the filters + page.
    let mut cleared = uq.clone();
    cleared.search = String::new();
    cleared.status = "active".to_string();
    cleared.tier = String::new();
    cleared.verified = String::new();
    cleared.page = 1;
    html! {
        div style="min-height:1.75rem" class="flex flex-wrap items-center gap-2" {
            @for (label, href) in &chips {
                span class="inline-flex items-center gap-1 rounded-full border border-border/60 bg-muted px-2.5 py-0.5 text-xs" {
                    span { (label) }
                    a href=(href) hx-get=(href) hx-target="#users-panel" hx-swap="outerHTML" hx-push-url="true" hx-indicator="#users-loading"
                      aria-label=(format!("Remove {label} filter")) class="inline-flex text-muted-foreground hover:text-foreground rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" {
                        (icon("x", "h-3 w-3"))
                    }
                }
            }
            @if !chips.is_empty() {
                @let href = cleared.href();
                a href=(href) hx-get=(href) hx-target="#users-panel" hx-swap="outerHTML" hx-push-url="true" hx-indicator="#users-loading"
                  class="text-xs font-medium text-primary hover:underline rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" { "Clear all" }
            }
        }
    }
}

/// Prev / next pager + a page-size dropdown, all as panel-swapping links.
fn users_pager(uq: &UsersQ, total_pages: i64) -> Markup {
    let size_opt = |n: u32| -> (String, String, bool) {
        (
            uq.with_page_size(n).href(),
            n.to_string(),
            uq.page_size == n,
        )
    };
    html! {
        div class="flex items-center justify-between gap-4 pt-4 flex-wrap" {
            (filter_dropdown("Per page", &uq.page_size.to_string(), &[size_opt(10), size_opt(20), size_opt(50), size_opt(100)]))
            @if total_pages > 1 {
                div class="flex items-center gap-2" {
                    @if uq.page > 1 {
                        @let href = uq.with_page(uq.page - 1).href();
                        a href=(href) hx-get=(href) hx-target="#users-panel" hx-swap="outerHTML" hx-push-url="true" hx-indicator="#users-loading" class=(button_class("outline", "sm", "")) { "Previous" }
                    }
                    span class="text-sm text-muted-foreground" { "Page " (uq.page) " of " (total_pages) }
                    @if (uq.page as i64) < total_pages {
                        @let href = uq.with_page(uq.page + 1).href();
                        a href=(href) hx-get=(href) hx-target="#users-panel" hx-swap="outerHTML" hx-push-url="true" hx-indicator="#users-loading" class=(button_class("outline", "sm", "")) { "Next" }
                    }
                }
            }
        }
    }
}

/// The swappable panel: heading + result count, filter bar, chips, the sortable
/// grid list, pager. `data == None` renders the error state with a retry.
fn users_panel(
    uq: &UsersQ,
    data: Option<&crate::api::types::PaginatedResponse<crate::api::types::AdminUser>>,
    total_all: Option<i64>,
) -> Markup {
    let heading = match uq.status.as_str() {
        "suspended" => "Suspended accounts",
        "all" => "All accounts",
        _ => "Active users",
    };
    let filtered_total = data.map(|p| p.total).unwrap_or(0);
    let total_pages = data.map(|p| p.total_pages).unwrap_or(1);
    let count_text = match (data, total_all) {
        (Some(_), Some(all)) if uq.is_filtered() => format!("{filtered_total} of {all} users"),
        (Some(_), _) => format!("{filtered_total} users"),
        (None, _) => "Could not load users".to_string(),
    };

    // Verification dropdown options.
    let ver_opts = vec![
        (
            uq.with_verified("").href(),
            "Any".to_string(),
            uq.verified.is_empty(),
        ),
        (
            uq.with_verified("verified").href(),
            "Verified".to_string(),
            uq.verified == "verified",
        ),
        (
            uq.with_verified("unverified").href(),
            "Unverified".to_string(),
            uq.verified == "unverified",
        ),
    ];
    let ver_current = match uq.verified.as_str() {
        "verified" => "Verified",
        "unverified" => "Unverified",
        _ => "Any",
    };
    // Tier dropdown options.
    let tier_opts = vec![
        (
            uq.with_tier("").href(),
            "Any".to_string(),
            uq.tier.is_empty(),
        ),
        (
            uq.with_tier("early_adopter").href(),
            "Early Adopter".to_string(),
            uq.tier == "early_adopter",
        ),
        (
            uq.with_tier("standard").href(),
            "Standard".to_string(),
            uq.tier == "standard",
        ),
        (
            uq.with_tier("lifetime").href(),
            "Lifetime".to_string(),
            uq.tier == "lifetime",
        ),
        (
            uq.with_tier("free").href(),
            "Free".to_string(),
            uq.tier == "free",
        ),
    ];

    html! {
        div id="users-panel" class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="p-6 space-y-4" {
                // Heading + live result count (announced on swap).
                div class="flex items-end justify-between gap-4 flex-wrap" {
                    h3 class="text-2xl font-semibold leading-none tracking-tight" { (heading) }
                    span aria-live="polite" class="text-sm text-muted-foreground" { (count_text) }
                }
                // Filter bar: search grows, dropdowns + segmented at content width.
                div class="flex flex-wrap items-center gap-2" {
                    form method="get" action="/admin/users" class="flex-1 min-w-[12rem]" role="search"
                        hx-get="/admin/users" hx-target="#users-panel" hx-swap="outerHTML" hx-push-url="true" hx-indicator="#users-loading"
                        hx-trigger="keyup changed delay:250ms from:input[name=search], search" {
                        // Carry the other filters + sort so a search keeps them.
                        @if uq.status != "active" { input type="hidden" name="status" value=(uq.status); }
                        @if !uq.tier.is_empty() { input type="hidden" name="tier" value=(uq.tier); }
                        @if !uq.verified.is_empty() { input type="hidden" name="verified" value=(uq.verified); }
                        @if !uq.sort.is_empty() { input type="hidden" name="sort" value=(uq.sort); input type="hidden" name="dir" value=(uq.dir); }
                        @if uq.page_size != 20 { input type="hidden" name="page_size" value=(uq.page_size.to_string()); }
                        input type="search" name="search" value=(uq.search) placeholder="Search by email…" aria-label="Search users by email" class=(dashboard_input());
                    }
                    (filter_dropdown("Verification", ver_current, &ver_opts))
                    (filter_dropdown("Tier", tier_slug_label(&uq.tier), &tier_opts))
                    (segmented_control(uq))
                }
                (filter_chips(uq))
            }
            // List. `relative` so the loading overlay can sit on top without
            // changing the container height (no jump).
            div class="relative px-6 pb-2" style="min-height:8rem" {
                // Column header row (sortable Email / Tier / Verification / Joined).
                div style=(USERS_GRID) class="border-b border-border/60 pb-2 mb-1" {
                    span {}
                    (sort_header(uq, "email", "Email"))
                    (sort_header(uq, "tier", "Tier"))
                    (sort_header(uq, "verified", "Verification"))
                    (sort_header(uq, "joined", "Joined"))
                    span {}
                }
                div class="divide-y divide-border/50" {
                    @match data {
                        Some(p) if !p.items.is_empty() => {
                            @for u in &p.items { (user_grid_row(u)) }
                        }
                        Some(_) => {
                            // Distinguish "filters match nothing" from "no users".
                            @if uq.is_filtered() {
                                div class="py-10 text-center" {
                                    p class="text-muted-foreground" { "No users match these filters." }
                                    @let cleared_href = {
                                        let mut c = uq.clone();
                                        c.search = String::new(); c.status = "active".into(); c.tier = String::new(); c.verified = String::new(); c.page = 1;
                                        c.href()
                                    };
                                    a href=(cleared_href) hx-get=(cleared_href) hx-target="#users-panel" hx-swap="outerHTML" hx-push-url="true" hx-indicator="#users-loading"
                                      class=(button_class("outline", "sm", "mt-3")) { "Clear all filters" }
                                }
                            } @else {
                                p class="py-10 text-center text-muted-foreground" { "No users yet." }
                            }
                        }
                        None => {
                            div class="py-10 text-center" {
                                p class="text-destructive" { "Could not load users." }
                                @let href = uq.href();
                                a href=(href) hx-get=(href) hx-target="#users-panel" hx-swap="outerHTML" hx-push-url="true" hx-indicator="#users-loading"
                                  class=(button_class("outline", "sm", "mt-3")) { "Retry" }
                            }
                        }
                    }
                }
                // Loading overlay (skeleton rows). Shown by htmx via the
                // `htmx-request` class while a swap is in flight; absolutely
                // positioned so it never changes the panel height.
                div id="users-loading" class="users-loading absolute inset-x-6 top-10 space-y-2" aria-hidden="true" {
                    @for _ in 0..3 {
                        div class="h-10 rounded-md bg-muted users-shimmer" {}
                    }
                }
            }
            div class="px-6 pb-6" { (users_pager(uq, total_pages)) }
        }
    }
}

/// BUNYIP-410 overhaul: inline styles for the users-list loading overlay. Kept
/// inline (not in the built stylesheet) so it needs no Tailwind rebuild and can
/// never be defeated by a stale cached `styles.css`. htmx toggles the
/// `htmx-request` class on `#users-loading` for the duration of a swap.
const USERS_FILTER_CSS: &str = r#".users-loading{opacity:0;pointer-events:none;transition:opacity .15s ease}
.users-loading.htmx-request,.htmx-request .users-loading{opacity:1}
.users-shimmer{position:relative;overflow:hidden}
.users-shimmer::after{content:"";position:absolute;inset:0;transform:translateX(-100%);background:linear-gradient(90deg,transparent,hsl(var(--foreground)/0.06),transparent);animation:users-shimmer 1.2s infinite}
@keyframes users-shimmer{100%{transform:translateX(100%)}}"#;

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
    // Only the known roles are accepted; reject anything else (the UI uses a
    // dropdown, so an arbitrary role string can only come from a crafted
    // request) before forwarding it to the API (BUNYIP-114).
    if !matches!(f.role.as_str(), "admin" | "subscriber") {
        return redirect_cookies("/admin/users", &c.set_cookies);
    }
    let target =
        match admin_api::update_user_role(&st.api, c.forward.as_deref(), &id, &f.role).await {
            Ok(_) => "/admin/users".to_string(),
            Err(e) => {
                tracing::warn!(user_id = %id, error = ?e, "admin update user role failed");
                format!(
                    "/admin/users?toast_err={}",
                    urlenc("Could not update user role")
                )
            }
        };
    redirect_cookies(&target, &c.set_cookies)
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
    let target = match admin_api::delete_user(&st.api, c.forward.as_deref(), &id).await {
        Ok(_) => "/admin/users".to_string(),
        Err(e) => {
            tracing::warn!(user_id = %id, error = ?e, "admin delete user failed");
            format!("/admin/users?toast_err={}", urlenc("Could not delete user"))
        }
    };
    redirect_cookies(&target, &c.set_cookies)
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
    let target = match admin_api::suspend_user(&st.api, c.forward.as_deref(), &id).await {
        Ok(_) => "/admin/users".to_string(),
        Err(e) => {
            tracing::warn!(user_id = %id, error = ?e, "admin suspend user failed");
            format!(
                "/admin/users?toast_err={}",
                urlenc("Could not suspend user")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// Reactivate a suspended user, then return to the suspended list so the admin
/// stays in the same view (BUNYIP-120).
pub async fn user_reactivate(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ = admin_api::reactivate_user(&st.api, c.forward.as_deref(), &id).await;
    redirect_cookies("/admin/users?status=suspended", &c.set_cookies)
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

/// Admin email correction (BUNYIP-119). `verified` is an HTML checkbox, so it
/// only arrives in the body when ticked; absence means "leave unverified".
#[derive(Deserialize)]
pub struct EmailForm {
    pub email: String,
    #[serde(default)]
    pub verified: Option<String>,
}

/// POST /admin/users/{id}/email - correct a user's email (BUNYIP-119).
pub async fn user_email(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<EmailForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let email = f.email.trim();
    if email.is_empty() {
        return redirect_cookies(
            &format!("/admin/users/{id}?toast_err=Email%20is%20required"),
            &c.set_cookies,
        );
    }
    let verified = f.verified.is_some();
    let target =
        match admin_api::update_user_email(&st.api, c.forward.as_deref(), &id, email, verified)
            .await
        {
            Ok(()) => format!("/admin/users/{id}?toast_ok=Email%20updated"),
            Err(_) => format!("/admin/users/{id}?toast_err=Could%20not%20update%20email"),
        };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/users/{id}/email/verify - force-verify a user's email (BUNYIP-119).
pub async fn user_verify_email(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::verify_user_email(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => format!("/admin/users/{id}?toast_ok=Email%20verified"),
        Err(_) => format!("/admin/users/{id}?toast_err=Could%20not%20verify%20email"),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/users/{id}/two-factor/reset - clear a user's 2FA (BUNYIP-119).
pub async fn user_reset_2fa(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::reset_user_two_factor(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => format!("/admin/users/{id}?toast_ok=Two-factor%20cleared"),
        Err(_) => format!("/admin/users/{id}?toast_err=Could%20not%20clear%20two-factor"),
    };
    redirect_cookies(&target, &c.set_cookies)
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
    let target = match admin_api::revoke_lifetime(&st.api, c.forward.as_deref(), &id).await {
        Ok(_) => format!("/admin/users/{id}"),
        Err(e) => {
            tracing::warn!(user_id = %id, error = ?e, "admin revoke lifetime membership failed");
            format!(
                "/admin/users/{id}?toast_err={}",
                urlenc("Could not revoke lifetime membership")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// Body for the BUNYIP-431 tier-change form: the destination tier plus the
/// acting admin's 2FA code.
#[derive(serde::Deserialize)]
pub struct TierChangeForm {
    pub tier: String,
    pub totp_code: String,
}

/// POST /admin/users/{id}/tier (BUNYIP-431). Relays the destination tier and the
/// admin's 2FA code to the API, which applies the move only on a valid code. On
/// a bad/absent code the API returns a validation error and nothing changes; we
/// bounce back to the user page with the message as a toast, so a cancelled 2FA
/// leaves the tier and slot counts untouched.
pub async fn user_set_tier(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<TierChangeForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::set_user_tier(
        &st.api,
        c.forward.as_deref(),
        &id,
        f.tier.trim(),
        f.totp_code.trim(),
    )
    .await
    {
        Ok(()) => format!("/admin/users/{id}?toast_ok=Tier%20updated"),
        Err(e) => format!("/admin/users/{id}?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// GET /admin/users/{id} - single-user detail page with all admin actions in one place.
/// BUNYIP-430: the per-user "Actions" card. Every state-changing control here
/// routes through the one shared confirmation dialog - the `data-confirm`
/// attribute, handled once in `assets/js/app.js`, which prompts on submit and
/// cancels the POST when the admin declines. Each prompt names both the action
/// and the specific user (by email), so an admin who opened the wrong row is
/// told who they are about to affect before anything happens. Extracted from
/// `user_detail` so the confirmations are unit-testable.
fn user_actions_card(target: &AdminUser, is_admin_target: bool) -> Markup {
    let who = target.email.as_str();
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6 pb-2" {
                h3 class="text-base font-semibold leading-none tracking-tight" { "Actions" }
                p class="text-xs text-muted-foreground" { "All actions write an audit-log entry." }
            }
            div class="p-6 pt-2 flex flex-wrap gap-2" {
                a href=(format!("/admin/users/{}/entitlements", target.id)) class=(button_class("outline", "default", "")) { "Manage Entitlements" }
                form method="post" action=(format!("/admin/users/{}/role", target.id)) data-confirm=(format!("Change {}'s role to {}? Admins have full platform access.", who, if is_admin_target { "subscriber" } else { "admin" })) {
                    input type="hidden" name="role" value=(if is_admin_target { "subscriber" } else { "admin" });
                    button type="submit" class=(button_class("outline", "default", "")) { @if is_admin_target { "Demote to subscriber" } @else { "Promote to admin" } }
                }
                form method="post" action=(format!("/admin/users/{}/reset-password", target.id)) data-confirm=(format!("Send a password reset email to {who}?")) {
                    button type="submit" class=(button_class("outline", "default", "")) { "Send password reset" }
                }
                // BUNYIP-431: the two lifetime-specific buttons were replaced by
                // the 2FA-gated tier selector in `tier_change_card` below, which
                // moves a member to any tier (including to/from lifetime).
                form method="post" action=(format!("/admin/users/{}/suspend", target.id)) data-confirm=(format!("Suspend (soft-delete) {who}?")) {
                    button type="submit" class=(button_class("outline", "default", "")) { "Suspend" }
                }
                form method="post" action=(format!("/admin/users/{}/delete", target.id)) data-confirm=(format!("Delete {who}? This cannot be undone.")) {
                    button type="submit" class=(button_class("outline", "default", "text-destructive hover:text-destructive")) { "Delete user" }
                }
            }
        }
    }
}

/// BUNYIP-431: move a member to any configured tier. The options never depend on
/// the member's current tier (any-to-any, including downgrades). Applying a
/// change requires the acting admin's own 2FA code - a stronger gate than the
/// shared confirm dialog, because a tier move has billing consequences. The API
/// records the before/after tiers in the audit log; the slot counts in Tier
/// Settings stay correct because usage is counted live from the tier column.
fn tier_change_card(target: &AdminUser) -> Markup {
    use crate::api::types::SubscriptionTier::*;
    let options = [
        (
            "lifetime",
            "Lifetime",
            matches!(target.subscription_tier, Lifetime),
        ),
        (
            "early_adopter",
            "Early Adopter",
            matches!(target.subscription_tier, EarlyAdopter),
        ),
        (
            "standard",
            "Standard",
            matches!(target.subscription_tier, Standard),
        ),
        ("free", "Free", matches!(target.subscription_tier, Free)),
    ];
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6 pb-2" {
                h3 class="text-base font-semibold leading-none tracking-tight" { "Membership tier" }
                p class="text-xs text-muted-foreground" { "Move this member to any tier, in either direction. Requires your two-factor code; the change and its before/after tiers are written to the audit log." }
            }
            div class="p-6 pt-2" {
                form method="post" action=(format!("/admin/users/{}/tier", target.id)) class="flex flex-wrap items-end gap-3" {
                    div class="space-y-2" {
                        label class="text-sm font-medium" for="tier" { "Tier" }
                        select id="tier" name="tier" class=(dashboard_input()) {
                            @for (value, label, is_current) in options {
                                option value=(value) selected[is_current] { (label) }
                            }
                        }
                    }
                    div class="space-y-2" {
                        label class="text-sm font-medium" for="tier-totp" { "Your 2FA code" }
                        input id="tier-totp" name="totp_code" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code" required class=(dashboard_input());
                    }
                    button type="submit" class=(button_class("default", "default", "")) { "Change tier" }
                }
            }
        }
    }
}

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

    // This user's currently-active throttles (BUNYIP-317). The active set is
    // small by design (the API builds it in memory), so a single page of the
    // API max (100) covers every realistic case; filter it to this user.
    let user_throttles: Vec<AdminRateLimit> =
        match admin_api::rate_limits(&st.api, c.forward.as_deref(), 1, 100).await {
            Ok(p) => p
                .items
                .into_iter()
                .filter(|rl| rl.user_id.as_deref() == Some(target.id.as_str()))
                .collect(),
            Err(_) => Vec::new(),
        };

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

            // Identity & security card (BUNYIP-119): the email, email-verified,
            // and two-factor fields are shown read-only above; this card makes
            // them editable so an admin can correct an address, force-verify
            // it, or clear a stuck second factor.
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6 pb-2" {
                    h3 class="text-base font-semibold leading-none tracking-tight" { "Identity & security" }
                    p class="text-xs text-muted-foreground" { "Correct the email, force-verify it, or clear a stuck second factor. All actions write an audit-log entry." }
                }
                div class="p-6 pt-2 space-y-4" {
                    form method="post" action=(format!("/admin/users/{}/email", target.id)) class="space-y-2" {
                        label class="text-sm font-medium" for="admin-email" { "Email" }
                        div class="flex flex-col sm:flex-row gap-2" {
                            input id="admin-email" name="email" type="email" required value=(target.email) class=(dashboard_input());
                            button type="submit" class=(button_class("default", "default", "")) { "Save email" }
                        }
                        label class="flex items-center gap-2 text-sm text-muted-foreground" {
                            input type="checkbox" name="verified" value="true" class="h-4 w-4";
                            "Mark this address verified (leave unchecked to require the user to re-verify)"
                        }
                    }
                    div class="flex flex-wrap gap-2" {
                        @if !target.email_verified {
                            form method="post" action=(format!("/admin/users/{}/email/verify", target.id)) data-confirm=(format!("Force-verify {}'s email without them confirming it?", target.email)) {
                                button type="submit" class=(button_class("outline", "default", "")) { "Force-verify email" }
                            }
                        }
                        @if target.two_factor_enabled {
                            form method="post" action=(format!("/admin/users/{}/two-factor/reset", target.id)) data-confirm=(format!("Clear {}'s 2FA? Their authenticator and recovery codes are removed and they must re-enrol.", target.email)) {
                                button type="submit" class=(button_class("outline", "default", "text-destructive hover:text-destructive")) { "Clear 2FA" }
                            }
                        } @else {
                            span class="text-xs text-muted-foreground self-center" { "Two-factor is not enabled for this user." }
                        }
                    }
                }
            }

            // Rate limits card (BUNYIP-317): this user's currently-active
            // throttles, each resettable in place. Hidden when the user is not
            // throttled to keep the page uncluttered.
            @if !user_throttles.is_empty() {
                div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                    div class="flex flex-col space-y-1.5 p-6 pb-2" {
                        div class="flex items-center gap-2" { (icon("gauge", "h-4 w-4 text-muted-foreground")) h3 class="text-base font-semibold leading-none tracking-tight" { "Active rate limits" } }
                        p class="text-xs text-muted-foreground" { "Throttles currently applied to this user. Resetting one lets them act again immediately; the reset is audited." }
                    }
                    div class="p-6 pt-0" {
                        div class="space-y-0" { @for rl in &user_throttles { (rate_limit_row(rl, Some(&target.id))) } }
                    }
                }
            }

            // Actions card (BUNYIP-430): extracted so every significant control
            // shares the one confirmation dialog and names the target user.
            (user_actions_card(&target, is_admin_target))
            // BUNYIP-431: 2FA-gated any-tier-to-any-tier move.
            (tier_change_card(&target))
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
    /// BUNYIP-291 AC4: active tier filter for the members-by-tier view.
    #[serde(default)]
    pub tier: Option<String>,
}

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

// ===========================================================================
// Feedback
// ===========================================================================

/// Top-of-page tabs that bucket the feedback queue by triage state.
/// Active is the working queue (new/reviewed/responded, not spam).
/// Closed is the resolved bin (status=closed, not spam). Spam is
/// quarantine. Archive is the long-term cold storage (BUNYIP-85).
/// BUNYIP-92 added Closed + Spam so "Close" produces a visible effect
/// (row leaves Active, lands in Closed) and spam never clutters
/// triage.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum FeedbackTab {
    Active,
    Closed,
    Spam,
    Archive,
}

impl FeedbackTab {
    /// Bucket string passed to the bunyip-api list endpoint.
    fn bucket(self) -> &'static str {
        match self {
            FeedbackTab::Active => "active",
            FeedbackTab::Closed => "closed",
            FeedbackTab::Spam => "spam",
            FeedbackTab::Archive => "active", // unused; archive has its own endpoint
        }
    }

    /// Path used to return to this tab after a row action (so the
    /// admin lands back on the same view they clicked from).
    fn path(self) -> &'static str {
        match self {
            FeedbackTab::Active => "/admin/feedback",
            FeedbackTab::Closed => "/admin/feedback/closed",
            FeedbackTab::Spam => "/admin/feedback/spam",
            FeedbackTab::Archive => "/admin/feedback/archive",
        }
    }

    /// Slug for the detail page's `?from=` param, tying a detail view back to
    /// the list tab it was opened from so its actions redirect there
    /// (BUNYIP-422). Distinct from [`bucket`](Self::bucket), which collapses
    /// Archive onto the active list endpoint; this preserves Archive.
    fn query_slug(self) -> &'static str {
        match self {
            FeedbackTab::Active => "active",
            FeedbackTab::Closed => "closed",
            FeedbackTab::Spam => "spam",
            FeedbackTab::Archive => "archive",
        }
    }

    /// Parse the `?from=` slug back into a tab; unknown / absent defaults to
    /// Active (the safe fallback, matching [`from_tab_path`]).
    fn from_query(from: Option<&str>) -> FeedbackTab {
        match from.unwrap_or("active") {
            "closed" => FeedbackTab::Closed,
            "spam" => FeedbackTab::Spam,
            "archive" => FeedbackTab::Archive,
            _ => FeedbackTab::Active,
        }
    }
}

fn feedback_tabs(current: FeedbackTab) -> Markup {
    let tab_class = |selected: bool| {
        if selected {
            "border-b-2 border-primary px-3 py-2 text-sm font-semibold text-foreground"
        } else {
            "border-b-2 border-transparent px-3 py-2 text-sm text-muted-foreground hover:text-foreground"
        }
    };
    html! {
        nav class="flex items-center gap-2 border-b border-border/50" aria-label="Feedback view" {
            a href="/admin/feedback" class=(tab_class(current == FeedbackTab::Active)) { "Active" }
            a href="/admin/feedback/closed" class=(tab_class(current == FeedbackTab::Closed)) { "Closed" }
            a href="/admin/feedback/spam" class=(tab_class(current == FeedbackTab::Spam)) { "Spam" }
            a href="/admin/feedback/archive" class=(tab_class(current == FeedbackTab::Archive)) { "Archive" }
        }
    }
}

pub async fn feedback(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    render_feedback_list(st, headers, q, FeedbackTab::Active).await
}

/// GET /admin/feedback/closed - BUNYIP-92. Rows where the admin clicked
/// Close (status=closed) land here, out of the active triage queue.
pub async fn feedback_closed(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    render_feedback_list(st, headers, q, FeedbackTab::Closed).await
}

/// GET /admin/feedback/spam - BUNYIP-92. Honeypot-detected rows plus
/// any admin-flagged spam. The default Active tab never surfaces these
/// (the repository now filters is_spam=false).
pub async fn feedback_spam(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    render_feedback_list(st, headers, q, FeedbackTab::Spam).await
}

async fn render_feedback_list(
    st: AppState,
    headers: HeaderMap,
    q: PageQuery,
    tab: FeedbackTab,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let data = admin_api::feedback(&st.api, c.forward.as_deref(), page, 20, tab.bucket())
        .await
        .ok();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);

    let (section_title, empty_msg) = match tab {
        FeedbackTab::Active => ("Submissions", "No feedback yet"),
        FeedbackTab::Closed => ("Closed", "No closed feedback"),
        FeedbackTab::Spam => ("Spam", "No spam"),
        FeedbackTab::Archive => ("Archive", "Archive is empty"),
    };

    let content = html! {
        div class="space-y-6" {
            div class="flex items-start justify-between gap-4" {
                div { h1 class="text-3xl font-bold" { "Feedback" } p class="mt-2 text-muted-foreground" { "Triage submitted feedback." } }
                a href="/admin/feedback/export" class=(button_class("outline", "sm", "")) { "Export CSV" }
            }
            (feedback_tabs(tab))
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { (section_title) } }
                div class="p-6 pt-0" {
                    div class="divide-y" {
                        @for f in &items {
                            (feedback_row(f, tab))
                        }
                        @if items.is_empty() { p class="text-center text-muted-foreground py-8" { (empty_msg) } }
                    }
                    (pager(tab.path(), page, total_pages))
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/feedback", "Feedback · Bunyip", content)
}

/// Inline status chip for a feedback row / detail header, mirroring the
/// users-list verification indicator (icon + short label, color-coded) so the
/// two admin lists read the same (BUNYIP-422).
fn feedback_status_chip(status: &FeedbackStatus) -> Markup {
    let (classes, icon_name, label) = match status {
        FeedbackStatus::New => ("text-yellow-600", "alert-circle", "New"),
        FeedbackStatus::Reviewed => (
            "text-teal-600 dark:text-teal-400",
            "check-circle",
            "Reviewed",
        ),
        FeedbackStatus::Responded => ("text-teal-600 dark:text-teal-400", "mail", "Responded"),
        FeedbackStatus::Closed => ("text-muted-foreground", "check", "Closed"),
    };
    html! {
        span class={ "inline-flex items-center gap-1 text-xs font-medium " (classes) } {
            (icon(icon_name, "h-4 w-4")) (label)
        }
    }
}

/// One feedback row: a whole-row link into the detail view (BUNYIP-422),
/// matching the users-list row-as-link pattern. The row surfaces subject,
/// submitter identity, source page, a message excerpt, the relative
/// submission time, and a status chip - no inline action buttons. All triage
/// actions moved to the detail page ([`feedback_detail_actions`]); the
/// `?from=` param carries the tab slug so those actions redirect back to the
/// view the admin came from.
fn feedback_row(f: &crate::api::types::AdminFeedbackSummary, tab: FeedbackTab) -> Markup {
    let name = f.name.clone().filter(|s| !s.trim().is_empty());
    let email = f.email_masked.clone().filter(|s| !s.trim().is_empty());
    let identity = match (name.as_deref(), email.as_deref()) {
        (Some(n), Some(e)) => Some(format!("{n} · {e}")),
        (Some(n), None) => Some(n.to_string()),
        (None, Some(e)) => Some(e.to_string()),
        (None, None) => None,
    };
    let from_path = f
        .page_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "/feedback");
    html! {
        a href=(format!("/admin/feedback/{}?from={}", f.id, tab.query_slug()))
          class="flex items-center gap-4 py-3 px-2 -mx-2 rounded-md hover:bg-accent hover:text-accent-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2" {
            div class="min-w-0 flex-1" {
                p class="font-medium truncate" {
                    (f.subject.clone().unwrap_or_else(|| "(no subject)".into()))
                }
                @if let Some(line) = &identity {
                    p class="text-xs text-muted-foreground truncate" { (line) }
                }
                @if let Some(p) = from_path {
                    p class="text-xs text-muted-foreground truncate" { "From: " (p) }
                }
                p class="text-sm text-muted-foreground truncate" { (f.message_excerpt) }
                p class="text-xs text-muted-foreground" { (relative_time(&f.created_at)) }
            }
            div class="flex items-center gap-3 shrink-0" {
                (feedback_status_chip(&f.status))
                (icon("chevron-right", "h-4 w-4 text-muted-foreground"))
            }
        }
    }
}

/// The tab-aware triage actions for one feedback item, shown on the detail
/// page (BUNYIP-422 moved these off the list rows). Mirrors the previous
/// per-row action set: Active gets review / close / archive / spam / delete,
/// Closed gets reopen / archive / spam / delete, Spam gets not-spam / archive
/// / delete, Archive gets delete. Each POSTs a `from` hidden field carrying
/// the tab slug so the handler redirects back to the list view the admin came
/// from.
fn feedback_detail_actions(id: &str, status: &FeedbackStatus, tab: FeedbackTab) -> Markup {
    let already_reviewed = matches!(status, FeedbackStatus::Reviewed);
    let review_action = if already_reviewed { "new" } else { "reviewed" };
    let review_label = if already_reviewed {
        "Un-review"
    } else {
        "Reviewed"
    };
    let from = tab.query_slug();
    html! {
        div class="flex flex-wrap items-center gap-2" {
            @match tab {
                FeedbackTab::Active => {
                    form method="post" action=(format!("/admin/feedback/{id}/status")) {
                        input type="hidden" name="status" value=(review_action);
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { (review_label) }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/status")) {
                        input type="hidden" name="status" value="closed";
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Close" }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/archive")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Archive" }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/mark-spam")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Mark as spam" }
                    }
                }
                FeedbackTab::Closed => {
                    form method="post" action=(format!("/admin/feedback/{id}/status")) {
                        input type="hidden" name="status" value="new";
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Re-open" }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/archive")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Archive" }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/mark-spam")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Mark as spam" }
                    }
                }
                FeedbackTab::Spam => {
                    form method="post" action=(format!("/admin/feedback/{id}/unmark-spam")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Not spam" }
                    }
                    form method="post" action=(format!("/admin/feedback/{id}/archive")) {
                        input type="hidden" name="from" value=(from);
                        button type="submit" class=(button_class("outline", "sm", "")) { "Archive" }
                    }
                }
                FeedbackTab::Archive => {}
            }
            form method="post" action=(format!("/admin/feedback/{id}/delete"))
                data-confirm="Delete this feedback permanently? This cannot be undone." {
                input type="hidden" name="from" value=(from);
                button type="submit" class=(button_class("outline", "sm", "text-destructive hover:text-destructive")) { "Delete" }
            }
        }
    }
}

#[derive(Deserialize)]
pub struct StatusForm {
    pub status: String,
    /// BUNYIP-92: the tab slug (active/closed/spam) the admin clicked
    /// from, so we redirect back to that view with a toast confirming
    /// the action.
    #[serde(default)]
    pub from: Option<String>,
}

/// Map a `from` form value to the tab path the BFF redirects back to
/// after a row action. Unknown values default to `/admin/feedback`
/// (Active) which is the safe fallback.
fn from_tab_path(from: Option<&str>) -> &'static str {
    match from.unwrap_or("active") {
        "closed" => "/admin/feedback/closed",
        "spam" => "/admin/feedback/spam",
        "archive" => "/admin/feedback/archive",
        _ => "/admin/feedback",
    }
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
    let toast = match status {
        FeedbackStatus::Closed => "Closed",
        FeedbackStatus::Reviewed => "Marked reviewed",
        FeedbackStatus::New => "Re-opened",
        FeedbackStatus::Responded => "Marked responded",
    };
    let target =
        match admin_api::update_feedback_status(&st.api, c.forward.as_deref(), &id, status).await {
            Ok(()) => format!(
                "{}?toast_ok={}",
                from_tab_path(f.from.as_deref()),
                urlencoding::encode(toast),
            ),
            Err(_) => format!(
                "{}?toast_err=Could%20not%20update%20status",
                from_tab_path(f.from.as_deref()),
            ),
        };
    redirect_cookies(&target, &c.set_cookies)
}

#[derive(Deserialize)]
pub struct FromForm {
    #[serde(default)]
    pub from: Option<String>,
}

/// POST /admin/feedback/:id/mark-spam (BUNYIP-92).
pub async fn feedback_mark_spam(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<FromForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::mark_feedback_spam(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => format!(
            "{}?toast_ok=Marked%20as%20spam",
            from_tab_path(f.from.as_deref()),
        ),
        Err(_) => format!(
            "{}?toast_err=Could%20not%20mark%20spam",
            from_tab_path(f.from.as_deref()),
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/feedback/:id/unmark-spam (BUNYIP-92).
pub async fn feedback_unmark_spam(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<FromForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::unmark_feedback_spam(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => format!(
            "{}?toast_ok=Restored%20from%20spam",
            from_tab_path(f.from.as_deref()),
        ),
        Err(_) => format!(
            "{}?toast_err=Could%20not%20unmark%20spam",
            from_tab_path(f.from.as_deref()),
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/feedback/:id/archive (BUNYIP-93). Per-row archive: the
/// row moves out of `feedback` and into `feedback_archive`. Reversible
/// from the Archive tab via the existing Restore button (BUNYIP-85).
pub async fn feedback_archive_action(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<FromForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::archive_feedback(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => format!("{}?toast_ok=Archived", from_tab_path(f.from.as_deref()),),
        Err(_) => format!(
            "{}?toast_err=Could%20not%20archive",
            from_tab_path(f.from.as_deref()),
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/feedback/:id/delete (BUNYIP-92). Hard delete, gated by a
/// JS confirm() on the form; the BFF does NOT add a second confirmation.
pub async fn feedback_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<FromForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::delete_feedback(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => format!("{}?toast_ok=Deleted", from_tab_path(f.from.as_deref()),),
        Err(_) => format!(
            "{}?toast_err=Could%20not%20delete",
            from_tab_path(f.from.as_deref()),
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// GET /admin/feedback/export
///
/// BFF proxy for the bunyip-api CSV export. The browser cannot hit
/// `<api>/v1/admin/feedback/export` directly (separate origin, the
/// session cookie is scoped to this app), so the "Export CSV" anchor on
/// the admin feedback page points here. We re-auth via `admin_guard`,
/// forward the session cookie to the API at `/admin/feedback/export`,
/// and stream the response body back with the upstream `Content-Type`
/// and `Content-Disposition` so the browser drives the download.
///
/// Pattern mirrors `dashboard::download_asset`; see its doc comment for
/// the upstream-status / fallback rationale.
pub async fn feedback_export(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    match st.api.get_stream("/admin/feedback/export", fwd).await {
        Ok(resp) if resp.status().is_success() => {
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("text/csv")
                .to_string();
            let disposition = resp
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .unwrap_or_else(|| "attachment; filename=\"feedback.csv\"".to_string());
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let content_length = resp
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let mut builder = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_DISPOSITION, disposition);
            builder = with_attachment_hardening(builder);
            if let Some(len) = content_length {
                builder = builder.header(header::CONTENT_LENGTH, len);
            }
            builder
                .body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| redirect_cookies("/admin/feedback", &c.set_cookies))
        }
        // 401 forces re-auth; everything else bounces back to the list
        // (lost privileges, upstream outage) so the browser never saves an
        // error blob as `feedback.csv`.
        Ok(resp) if resp.status().as_u16() == 401 => redirect_cookies("/login", &c.set_cookies),
        _ => redirect_cookies("/admin/feedback", &c.set_cookies),
    }
}

/// Apply the BUNYIP-90 hardening header triple to any binary-proxy
/// response (attachment download, CSV export). Keep the helper next to
/// the two callers so future binary-serving routes get the same
/// treatment by reference.
///
/// `X-Content-Type-Options: nosniff` forces the browser to respect the
/// upstream Content-Type and skip its own MIME sniffing - a text/plain
/// attachment that happens to contain `<script>` markup never becomes
/// HTML, even on legacy browsers.
///
/// `Content-Security-Policy: sandbox` sandboxes any inline-rendered
/// content (the strictest sandbox: no scripts, no forms, no
/// same-origin). Belt-and-suspenders defence in depth alongside
/// nosniff; if a future binary type accidentally lands HTML-ish into
/// this proxy, the sandbox neuters it.
///
/// `Referrer-Policy: no-referrer` prevents the attachment URL (which
/// contains feedback id + attachment id) from leaking via the Referer
/// header when the admin then navigates elsewhere.
fn with_attachment_hardening(
    builder: axum::http::response::Builder,
) -> axum::http::response::Builder {
    builder
        .header("X-Content-Type-Options", "nosniff")
        .header("Content-Security-Policy", "sandbox")
        .header("Referrer-Policy", "no-referrer")
}

/// GET /admin/feedback/:id
///
/// Detail subpage for a single feedback submission. Shows the unmasked
/// email (callers already pass `admin_guard`), full message, captured
/// `page_path`, current status, and either the existing admin response
/// or an inline form to send one.
pub async fn feedback_detail(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<FeedbackDetailQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // BUNYIP-422: the list rows link here with `?from=<tab>` so the triage
    // actions (now hosted on this page) render for the right tab and redirect
    // back to the list the admin came from.
    let tab = FeedbackTab::from_query(q.from.as_deref());
    let detail = match admin_api::feedback_detail(&st.api, c.forward.as_deref(), &id).await {
        Ok(d) => d,
        Err(_) => return redirect_cookies(tab.path(), &c.set_cookies),
    };
    let content = feedback_detail_view(&detail, tab);
    admin_response(&c, &user, "/admin/feedback", "Feedback · Bunyip", content)
}

/// Query for the feedback detail page. `from` names the list tab the admin
/// clicked from (BUNYIP-422); absent / unknown falls back to Active.
#[derive(Deserialize)]
pub struct FeedbackDetailQuery {
    #[serde(default)]
    pub from: Option<String>,
}

fn feedback_detail_view(f: &AdminFeedbackDetail, tab: FeedbackTab) -> Markup {
    // BUNYIP-94: render the masked email, never the raw one. Admins do
    // not need the raw address to reply (the API holds it and routes the
    // response server-side); leaking the raw address on the detail page
    // would violate the same masking posture the row list already uses.
    let identity_line = match (
        f.name.as_deref().map(str::trim).filter(|s| !s.is_empty()),
        f.email_masked
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    ) {
        (Some(n), Some(e)) => Some(format!("{n} · {e}")),
        (Some(n), None) => Some(n.to_string()),
        (None, Some(e)) => Some(e.to_string()),
        (None, None) => None,
    };
    // BUNYIP-94: explicit signal when the row has no email at all. The
    // reply form will still save the response to the DB, but no email
    // can be delivered. Surfacing this means an admin does not silently
    // assume the submitter received the reply.
    let has_email = f
        .email
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    let from_path = f
        .page_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "/feedback");
    html! {
        div class="space-y-6 max-w-3xl" {
            div class="flex items-center justify-between gap-4" {
                div {
                    h1 class="text-3xl font-bold" { (f.subject.clone().unwrap_or_else(|| "(no subject)".into())) }
                    p class="mt-2 text-muted-foreground text-sm" {
                        a href=(tab.path()) class="hover:underline" { "← Back to feedback" }
                    }
                }
                (feedback_status_chip(&f.status))
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="p-6 space-y-4" {
                    @if let Some(line) = &identity_line {
                        div { h3 class="text-sm font-semibold" { "From" } p class="text-sm text-muted-foreground" { (line) } }
                    }
                    @if let Some(p) = from_path {
                        div { h3 class="text-sm font-semibold" { "Page" } p class="text-sm text-muted-foreground" { (p) } }
                    }
                    @if !f.tags.is_empty() {
                        div {
                            h3 class="text-sm font-semibold" { "Tags" }
                            div class="mt-1 flex flex-wrap gap-1.5" {
                                @for t in &f.tags { (badge("outline", t)) }
                            }
                        }
                    }
                    div {
                        h3 class="text-sm font-semibold" { "Message" }
                        // Preserve newlines from the original submission; the
                        // submitter's paragraph breaks carry meaning when
                        // describing a repro.
                        p class="text-sm whitespace-pre-wrap" { (f.message) }
                    }
                    @if !f.attachments.is_empty() {
                        (feedback_attachments_view(&f.id, &f.attachments))
                    }
                    div { h3 class="text-sm font-semibold" { "Received" } p class="text-sm text-muted-foreground" { (relative_time(&f.created_at)) } }
                    // BUNYIP-411: request metadata for spam tracing. Shown only
                    // when captured (dev / direct-hit submissions resolve no
                    // forwarded IP). Maud escapes both values.
                    // BUNYIP-436: link the captured IP into the existing ban
                    // flow (the /admin/ip-bans add form prefills from `?ip=`),
                    // so a repeat spam source can be banned in one hop.
                    @if let Some(ip) = f.submitter_ip.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                        div {
                            h3 class="text-sm font-semibold" { "IP address" }
                            p class="text-sm" {
                                a href=(format!("/admin/ip-bans?ip={}", urlenc(ip))) class="font-mono text-primary underline-offset-4 hover:underline" title="Ban or look up this address" { (ip) }
                            }
                        }
                    }
                    @if let Some(ua) = f.user_agent.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                        div { h3 class="text-sm font-semibold" { "User agent" } p class="text-sm text-muted-foreground break-all" { (ua) } }
                    }
                }
            }
            // BUNYIP-422: the triage actions now live here (moved off the
            // list rows). They are tab-aware and each POSTs `from` = the tab
            // slug, so on success the admin lands back on the list view they
            // came from, not on a detail page for a row they just deleted.
            (feedback_detail_actions(&f.id, &f.status, tab))
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Response" } }
                div class="p-6 pt-0 space-y-4" {
                    // BUNYIP-94: when the submitter left no email, the
                    // reply form still saves the response to the DB but
                    // no email goes out. Make that explicit so admins do
                    // not silently assume the submitter received it.
                    @if !has_email {
                        div class="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300" {
                            "No email on record - the submitter did not provide an address. Your response will be saved but cannot be delivered."
                        }
                    }
                    // BUNYIP-123: a sent response is editable and
                    // resendable rather than one-shot. The respond route
                    // upserts admin_response, so re-submitting the
                    // (pre-filled) form overwrites the stored reply and,
                    // when an email is on record, re-delivers it - letting
                    // an admin fix a typo or wrong reply. When a response
                    // already exists, show when it was last sent above the
                    // form and pre-fill the textarea with the current text.
                    // No-email guard: `respond_to_feedback` on the API side
                    // just skips the email send when the submitter left no
                    // address, so the form does NOT need to gate on
                    // email_present here. The status update still happens
                    // either way. On success the POST bounces back to this
                    // same detail page with a `?toast_ok=` confirmation.
                    @let existing_response = f.admin_response.as_deref().map(str::trim).filter(|s| !s.is_empty());
                    @if existing_response.is_some() {
                        @if let Some(at) = &f.responded_at {
                            p class="text-xs text-muted-foreground" { "Sent " (relative_time(at)) }
                        }
                    }
                    form method="post" action=(format!("/admin/feedback/{}/respond", f.id)) class="space-y-3" {
                        div class="grid gap-2" {
                            label for="response" class="text-sm font-medium" { "Reply to the submitter" }
                            textarea id="response" name="response" rows="6" required placeholder="Type a response. The submitter will receive this verbatim by email." class="flex min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm" {
                                @if let Some(resp) = existing_response { (resp) }
                            }
                        }
                        div class="flex justify-end" {
                            button type="submit" class=(button_class("default", "default", "gap-2")) {
                                @if existing_response.is_some() { "Resend response" } @else { "Send response" }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Deserialize)]
pub struct RespondForm {
    pub response: String,
}

/// POST /admin/feedback/:id/respond
pub async fn feedback_respond(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(body): Form<RespondForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let response = body.response.trim();
    if response.is_empty() {
        // Empty body: short-circuit and reload the detail page; the user
        // can re-type. No toast - they will see the empty textarea and
        // figure it out.
        return redirect_cookies(&format!("/admin/feedback/{id}"), &c.set_cookies);
    }
    // BUNYIP-117: bound the admin response at the web edge. The body is
    // emailed verbatim and stored in feedback_responses (TEXT); 16k chars
    // is generous for a support reply while still rejecting a runaway
    // paste. Authoritative validation happens in
    // `services::feedback::respond` once the API tightens its own bound.
    const RESPONSE_MAX: usize = 16_000;
    if response.len() > RESPONSE_MAX {
        return redirect_cookies(
            &format!(
                "/admin/feedback/{id}?toast_err=Response%20must%20be%20{RESPONSE_MAX}%20characters%20or%20fewer"
            ),
            &c.set_cookies,
        );
    }
    let target =
        match admin_api::respond_to_feedback(&st.api, c.forward.as_deref(), &id, response).await {
            Ok(()) => format!("/admin/feedback/{id}?toast_ok=Response%20sent"),
            Err(_) => format!("/admin/feedback/{id}?toast_err=Could%20not%20send%20response"),
        };
    redirect_cookies(&target, &c.set_cookies)
}

/// GET /admin/feedback/archive
pub async fn feedback_archive(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let data = admin_api::feedback_archive(&st.api, c.forward.as_deref(), page, 20)
        .await
        .ok();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);

    let content = html! {
        div class="space-y-6" {
            div class="flex items-start justify-between gap-4" {
                div { h1 class="text-3xl font-bold" { "Feedback" } p class="mt-2 text-muted-foreground" { "Archived submissions. Restore moves a row back to the active list." } }
                a href="/admin/feedback/export" class=(button_class("outline", "sm", "")) { "Export CSV" }
            }
            (feedback_tabs(FeedbackTab::Archive))
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Archived" } }
                div class="p-6 pt-0" {
                    div class="divide-y" {
                        @for a in &items {
                            @let name = a.name.clone().filter(|s| !s.trim().is_empty());
                            @let email = a.email.clone().filter(|s| !s.trim().is_empty());
                            @let identity = match (name.as_deref(), email.as_deref()) {
                                (Some(n), Some(e)) => Some(format!("{n} · {e}")),
                                (Some(n), None) => Some(n.to_string()),
                                (None, Some(e)) => Some(e.to_string()),
                                (None, None) => None,
                            };
                            div class="py-3 flex items-start justify-between gap-4" {
                                div class="min-w-0" {
                                    p class="font-medium truncate" { (a.subject.clone().unwrap_or_else(|| "(no subject)".into())) }
                                    @if let Some(line) = &identity {
                                        p class="text-xs text-muted-foreground truncate" { (line) }
                                    }
                                    p class="text-sm text-muted-foreground truncate" { (a.message_excerpt) }
                                    p class="text-xs text-muted-foreground" {
                                        "Archived " (relative_time(&a.archived_at))
                                        @if let Some(orig) = &a.original_status {
                                            " · was " (orig)
                                        }
                                    }
                                }
                                div class="flex items-center gap-2 shrink-0" {
                                    form method="post" action=(format!("/admin/feedback/archive/{}/restore", a.id)) {
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Restore" }
                                    }
                                }
                            }
                        }
                        @if items.is_empty() { p class="text-center text-muted-foreground py-8" { "Archive is empty" } }
                    }
                    (pager("/admin/feedback/archive", page, total_pages))
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/feedback", "Feedback · Bunyip", content)
}

/// Render the attachments block on the feedback detail page. Image
/// MIMEs get an inline `<img>` thumbnail loaded from the same BFF
/// proxy URL; other MIMEs (text/plain) stay as a plain download link
/// with the filename and a human-readable size.
fn feedback_attachments_view(feedback_id: &str, atts: &[FeedbackAttachmentMeta]) -> Markup {
    html! {
        div {
            h3 class="text-sm font-semibold" { "Attachments" }
            div class="mt-2 grid gap-3 sm:grid-cols-2" {
                @for a in atts {
                    @let href = format!(
                        "/admin/feedback/{}/attachments/{}",
                        feedback_id, a.id,
                    );
                    @let is_image = a.mime_type.starts_with("image/");
                    div class="rounded-md border border-border/60 p-3 flex gap-3 items-start" {
                        @if is_image {
                            a href=(href) target="_blank" rel="noopener" class="shrink-0" {
                                img src=(href) alt=(a.filename)
                                    class="h-20 w-20 rounded object-cover bg-muted";
                            }
                        }
                        div class="min-w-0 flex-1" {
                            a href=(href) class="text-sm font-medium hover:underline truncate block" { (a.filename) }
                            p class="text-xs text-muted-foreground" { (format_size(a.size_bytes)) " · " (a.mime_type) }
                        }
                    }
                }
            }
        }
    }
}

/// Render byte count as KB / MB with one decimal. Bytes-only for tiny
/// (rare) values. Used in the attachments list.
fn format_size(bytes: i64) -> String {
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", b / 1024.0)
    } else {
        format!("{:.1} MB", b / (1024.0 * 1024.0))
    }
}

/// GET /admin/feedback/:id/attachments/:attachment_id
///
/// BFF proxy for a single feedback attachment. The browser cannot hit
/// bunyip-api directly (cross-origin cookie), so the `<img>` and
/// download anchors on the detail page point here. Re-auth via
/// `admin_guard`, forward to the API at
/// `/admin/feedback/{id}/attachments/{attachment_id}`, stream the
/// response body back with the upstream `Content-Type` and
/// `Content-Disposition`. Pattern mirrors `feedback_export` and
/// `dashboard::download_asset`.
pub async fn feedback_attachment(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((feedback_id, attachment_id)): Path<(String, String)>,
) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let path = format!("/admin/feedback/{feedback_id}/attachments/{attachment_id}");
    match st.api.get_stream(&path, c.forward.as_deref()).await {
        Ok(resp) if resp.status().is_success() => {
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let disposition = resp
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .unwrap_or_else(|| "attachment".to_string());
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let content_length = resp
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let mut builder = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_DISPOSITION, disposition);
            builder = with_attachment_hardening(builder);
            if let Some(len) = content_length {
                builder = builder.header(header::CONTENT_LENGTH, len);
            }
            builder
                .body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| {
                    redirect_cookies(&format!("/admin/feedback/{feedback_id}"), &c.set_cookies)
                })
        }
        Ok(resp) if resp.status().as_u16() == 401 => redirect_cookies("/login", &c.set_cookies),
        _ => redirect_cookies(&format!("/admin/feedback/{feedback_id}"), &c.set_cookies),
    }
}

/// POST /admin/feedback/archive/:archive_id/restore
pub async fn feedback_restore(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(archive_id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::restore_feedback(&st.api, c.forward.as_deref(), &archive_id).await
    {
        Ok(()) => "/admin/feedback/archive?toast_ok=Restored".to_string(),
        Err(_) => "/admin/feedback/archive?toast_err=Could%20not%20restore".to_string(),
    };
    redirect_cookies(&target, &c.set_cookies)
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
                        @for (i, app) in apps.iter().enumerate() {
                            div class="py-3 flex items-center justify-between gap-4" {
                                div class="flex items-center gap-3" {
                                    div class="flex flex-col gap-1" {
                                        @if i > 0 {
                                            form method="post" action=(format!("/admin/applications/{}/swap-order", app.id)) {
                                                input type="hidden" name="target_app_id" value=(apps[i - 1].id);
                                                button type="submit" title="Move up" aria-label="Move up" class=(button_class("outline", "sm", "")) { (icon("chevron-up", "h-4 w-4")) }
                                            }
                                        }
                                        @if i + 1 < apps.len() {
                                            form method="post" action=(format!("/admin/applications/{}/swap-order", app.id)) {
                                                input type="hidden" name="target_app_id" value=(apps[i + 1].id);
                                                button type="submit" title="Move down" aria-label="Move down" class=(button_class("outline", "sm", "")) { (icon("chevron-down", "h-4 w-4")) }
                                            }
                                        }
                                    }
                                    div class="space-y-1" {
                                        p class="font-medium" { (app.display_name) }
                                        p class="text-xs text-muted-foreground" { (app.slug) }
                                        (surface_tags(&SurfaceVisibility::of(app)))
                                    }
                                }
                                div class="flex items-center gap-6" {
                                    // BUNYIP-420: toggle switches (color + knob position
                                    // convey state, single click applies) replacing the old
                                    // "Active: on" text + separate Toggle button. Each switch
                                    // is the form's submit control, posting the flipped value
                                    // through the same /field path.
                                    form method="post" action=(format!("/admin/applications/{}/field", app.id)) class="flex items-center gap-2" {
                                        input type="hidden" name="field" value="is_active";
                                        input type="hidden" name="value" value=(if app.is_active { "false" } else { "true" });
                                        label class="text-sm text-muted-foreground" { "Active" }
                                        (toggle_switch(app.is_active, "Toggle active"))
                                    }
                                    form method="post" action=(format!("/admin/applications/{}/field", app.id)) class="flex items-center gap-2" {
                                        input type="hidden" name="field" value="maintenance_mode";
                                        input type="hidden" name="value" value=(if app.maintenance_mode { "false" } else { "true" });
                                        label class="text-sm text-muted-foreground" { "Maintenance" }
                                        (toggle_switch(app.maintenance_mode, "Toggle maintenance mode"))
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
    let target = match admin_api::update_application(&st.api, c.forward.as_deref(), &id, body).await
    {
        Ok(_) => "/admin/applications".to_string(),
        Err(e) => {
            tracing::warn!(app_id = %id, field = %f.field, error = ?e, "admin update application failed");
            format!(
                "/admin/applications?toast_err={}",
                urlenc("Could not update application")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
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

/// The descriptive / metadata fields the API accepts on both create and update
/// (`UpdateApplication` / `CreateApplication`): everything other than identity
/// and the distribution coordinates. Shared by the create and edit forms so the
/// field layout cannot drift between them. Borrowed for rendering.
struct DetailsView<'a> {
    description: &'a str,
    icon_url: &'a str,
    subdomain: &'a str,
    version: &'a str,
    source_code_url: &'a str,
    release_notes_url: &'a str,
    maintenance_message: &'a str,
}

/// An HTML checkbox submits its value only when checked, so an unchecked box is
/// absent from the form body (serde default `""`). Treat the standard checked
/// markers as true.
fn checkbox_on(s: &str) -> bool {
    s == "true" || s == "on"
}

fn details_fields(v: &DetailsView) -> Markup {
    html! {
        h4 class="text-lg font-semibold pt-2" { "Details" }
        div class="space-y-2" { label class="text-sm font-medium" { "Description" } input name="description" value=(v.description) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Icon URL" } input name="icon_url" value=(v.icon_url) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Subdomain" } input name="subdomain" value=(v.subdomain) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Version" } input name="version" value=(v.version) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Source code URL" } input name="source_code_url" value=(v.source_code_url) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Release notes URL" } p class="text-xs text-muted-foreground" { "Linked from the applications view so users can see what changed (e.g. the Forgejo releases page)." } input name="release_notes_url" value=(v.release_notes_url) class=(dashboard_input()); }
        div class="space-y-2" { label class="text-sm font-medium" { "Maintenance message" } p class="text-xs text-muted-foreground" { "Shown to users while maintenance mode is on." } input name="maintenance_message" value=(v.maintenance_message) class=(dashboard_input()); }
    }
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

/// At-a-glance visibility of an application across the three distribution
/// surfaces shown in the admin UI. Each field MIRRORS the canonical predicate
/// in `bunyip-domain` (`crates/bunyip-domain/src/models/application.rs`) so the
/// badges cannot silently disagree with what users actually see; if a domain
/// rule changes, update it here too:
/// - `hub`: the user Applications section / hub launch tile, listed by
///   `ApplicationRepository::list_active_hosted` (`is_active && is_hosted`).
/// - `binary`: `Application::is_downloadable` / `download_source` (forgejo_owner
///   + pinned_release_tag + repo-or-package depending on `artifact_source`).
/// - `oci`: `Application::is_pullable` (is_active + all three OCI fields set).
///
/// `None` and empty/whitespace string fields are both treated as absent.
struct SurfaceVisibility {
    hub: bool,
    binary: bool,
    oci: bool,
}

impl SurfaceVisibility {
    fn of(app: &AdminApplication) -> Self {
        fn present(field: &Option<String>) -> bool {
            field.as_deref().is_some_and(|s| !s.trim().is_empty())
        }
        // Mirrors `Application::download_source`: the `generic_package` source
        // accepts a package name or falls back to the repo; every other source
        // (including the `release` default) requires the repo.
        let binary = present(&app.forgejo_owner)
            && present(&app.pinned_release_tag)
            && if app.artifact_source.as_deref() == Some("generic_package") {
                present(&app.forgejo_package) || present(&app.forgejo_repo)
            } else {
                present(&app.forgejo_repo)
            };
        let oci = app.is_active
            && present(&app.oci_image_owner)
            && present(&app.oci_image_name)
            && present(&app.pinned_image_tag);
        Self {
            hub: app.is_active && app.is_hosted,
            binary,
            oci,
        }
    }
}

/// One surface badge: a colored `on_variant` when the app reaches the surface,
/// a muted outline `off_label` ("No X") when it does not.
fn surface_badge(on: bool, on_variant: &str, on_label: &str, off_label: &str) -> Markup {
    if on {
        badge(on_variant, on_label)
    } else {
        badge("outline", off_label)
    }
}

/// The Hub / Binary / OCI surface badges for one application. Rendered on the
/// admin Applications list and the edit page so an admin can see at a glance
/// which surfaces an app is (and is not) served in.
fn surface_tags(s: &SurfaceVisibility) -> Markup {
    html! {
        div class="flex flex-wrap items-center gap-1.5" {
            (surface_badge(s.hub, "success", "Hub", "No Hub"))
            (surface_badge(s.binary, "secondary", "Binary", "No Binary"))
            (surface_badge(s.oci, "secondary", "OCI", "No OCI"))
        }
    }
}

/// Render the application create/edit form. `identity` is `Some` only for
/// create (the edit form posts distribution fields only). `surfaces` is `Some`
/// only on the edit page of a persisted app, where the Hub/Binary/OCI badges
/// can be derived; create and error re-renders pass `None`. `error` renders a
/// banner and the form keeps the submitted values for correction.
fn application_form(
    action: &str,
    heading: &str,
    blurb: &str,
    identity: Option<&IdentityView>,
    is_hosted: bool,
    details: &DetailsView,
    v: &DistView,
    surfaces: Option<&SurfaceVisibility>,
    error: Option<&str>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { (heading) }
                p class="mt-2 text-muted-foreground" { (blurb) }
                @if let Some(s) = surfaces { div class="mt-3" { (surface_tags(s)) } }
            }
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
                        (details_fields(details))
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

fn details_view_from_dist_form(f: &DistributionForm) -> DetailsView<'_> {
    DetailsView {
        description: &f.description,
        icon_url: &f.icon_url,
        subdomain: &f.subdomain,
        version: &f.version,
        source_code_url: &f.source_code_url,
        release_notes_url: &f.release_notes_url,
        maintenance_message: &f.maintenance_message,
    }
}

/// Add every non-empty descriptive field (`DetailsView` columns) to an update /
/// create body, trimmed. Empty inputs are omitted so the backend keeps the
/// existing column (its UPDATE COALESCEs a NULL to the old value), matching the
/// "blank fields keep their current value" contract of the distribution fields.
fn insert_detail_fields(
    m: &mut serde_json::Map<String, serde_json::Value>,
    description: &str,
    icon_url: &str,
    subdomain: &str,
    version: &str,
    source_code_url: &str,
    release_notes_url: &str,
    maintenance_message: &str,
) {
    for (k, val) in [
        ("description", description),
        ("icon_url", icon_url),
        ("subdomain", subdomain),
        ("version", version),
        ("source_code_url", source_code_url),
        ("release_notes_url", release_notes_url),
        ("maintenance_message", maintenance_message),
    ] {
        if !val.trim().is_empty() {
            m.insert(k.into(), json!(val.trim()));
        }
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
    insert_detail_fields(
        &mut m,
        &f.description,
        &f.icon_url,
        &f.subdomain,
        &f.version,
        &f.source_code_url,
        &f.release_notes_url,
        &f.maintenance_message,
    );
    serde_json::Value::Object(m)
}

#[derive(Deserialize, Default)]
pub struct DistributionForm {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub icon_url: String,
    #[serde(default)]
    pub subdomain: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub source_code_url: String,
    #[serde(default)]
    pub release_notes_url: String,
    #[serde(default)]
    pub maintenance_message: String,
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
    // Groups for the assignment selector. A failed fetch degrades to no groups
    // (the selector still offers "Ungrouped") rather than blocking the edit.
    let groups = admin_api::application_groups(&st.api, c.forward.as_deref())
        .await
        .unwrap_or_default();
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
            let details = DetailsView {
                description: app.description.as_deref().unwrap_or_default(),
                icon_url: app.icon_url.as_deref().unwrap_or_default(),
                subdomain: app.subdomain.as_deref().unwrap_or_default(),
                version: app.version.as_deref().unwrap_or_default(),
                source_code_url: app.source_code_url.as_deref().unwrap_or_default(),
                release_notes_url: app.release_notes_url.as_deref().unwrap_or_default(),
                maintenance_message: app.maintenance_message.as_deref().unwrap_or_default(),
            };
            let surfaces = SurfaceVisibility::of(app);
            html! {
                div class="mb-4" {
                    a class=(button_class("outline", "sm", "")) href=(format!("/admin/applications/{id}/docs")) { "Manage documentation" }
                }
                (application_form(
                    &format!("/admin/applications/{id}/distribution"),
                    &format!("Edit {}", app.display_name),
                    "Edit the application details, Forgejo binary, and OCI container coordinates. Blank fields keep their current value.",
                    None,
                    app.is_hosted,
                    &details,
                    &v,
                    Some(&surfaces),
                    None,
                ))
                (group_assignment_form(&id, app.group_id.as_deref(), &groups))
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
                form method="post" action=(format!("/admin/applications/{id}/delete")) class="space-y-3 max-w-md mt-2" data-confirm="Permanently delete this application? This cannot be undone." {
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
            let details = details_view_from_dist_form(&f);
            let content = application_form(
                &format!("/admin/applications/{id}/distribution"),
                "Edit application",
                "Edit the application details, Forgejo binary, and OCI container coordinates. Blank fields keep their current value.",
                None,
                checkbox_on(&f.is_hosted),
                &details,
                &v,
                None,
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
pub struct SwapOrderForm {
    #[serde(default)]
    pub target_app_id: String,
}

/// POST /admin/applications/{id}/swap-order
/// Swap this application's sort order with the neighbour identified by
/// `target_app_id` (the adjacent row in the admin list), then return to the
/// list where the new ordering is visible. BUNYIP-121.
pub async fn application_swap_order(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<SwapOrderForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _ = admin_api::swap_application_order(&st.api, c.forward.as_deref(), &id, &f.target_app_id)
        .await;
    redirect_cookies("/admin/applications", &c.set_cookies)
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
    pub description: String,
    #[serde(default)]
    pub icon_url: String,
    #[serde(default)]
    pub subdomain: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub source_code_url: String,
    #[serde(default)]
    pub release_notes_url: String,
    #[serde(default)]
    pub maintenance_message: String,
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
fn create_app_body(f: &CreateAppForm) -> Result<serde_json::Value, String> {
    use crate::handlers::validate;
    // BUNYIP-112: identity fields are bounded + slug-checked at the edge.
    // `slug` is load-bearing for OCI repo paths in
    // `Application::oci_pull_image`, so an unconstrained value would
    // silently end up in pull URLs.
    let name = validate::trim_bounded(&f.name, "Name", 200)?;
    let slug = validate::slug(&f.slug, "Slug")?;
    let display_name = validate::trim_bounded(&f.display_name, "Display name", 200)?;
    let container_name = validate::trim_bounded(&f.container_name, "Container name", 200)?;
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(name));
    m.insert("slug".into(), json!(slug));
    m.insert("display_name".into(), json!(display_name));
    m.insert("container_name".into(), json!(container_name));
    m.insert("is_hosted".into(), json!(checkbox_on(&f.is_hosted)));
    insert_detail_fields(
        &mut m,
        &f.description,
        &f.icon_url,
        &f.subdomain,
        &f.version,
        &f.source_code_url,
        &f.release_notes_url,
        &f.maintenance_message,
    );
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
        if let Some(v) = validate::trim_bounded_opt(val, k, 200)? {
            m.insert(k.into(), json!(v));
        }
    }
    if f.artifact_source.trim() == "generic_package" && !f.forgejo_package.trim().is_empty() {
        let pkg = validate::trim_bounded(&f.forgejo_package, "forgejo_package", 200)?;
        m.insert("forgejo_package".into(), json!(pkg));
    }
    Ok(serde_json::Value::Object(m))
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
    let details = DetailsView {
        description: "",
        icon_url: "",
        subdomain: "",
        version: "",
        source_code_url: "",
        release_notes_url: "",
        maintenance_message: "",
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
        &details,
        &v,
        None,
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
    // Render helper so the validation-error and API-error paths share the
    // identical reconstruction of the form view (BUNYIP-112).
    let render_form_error = |err: &str| -> Response {
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
        let details = DetailsView {
            description: &f.description,
            icon_url: &f.icon_url,
            subdomain: &f.subdomain,
            version: &f.version,
            source_code_url: &f.source_code_url,
            release_notes_url: &f.release_notes_url,
            maintenance_message: &f.maintenance_message,
        };
        let content = application_form(
            "/admin/applications",
            "New application",
            "Create a catalog application and (optionally) its Forgejo binary and OCI container coordinates.",
            Some(&id),
            checkbox_on(&f.is_hosted),
            &details,
            &v,
            None,
            Some(err),
        );
        admin_response(
            &c,
            &user,
            "/admin/applications",
            "New application · Bunyip",
            content,
        )
    };
    let body = match create_app_body(&f) {
        Ok(b) => b,
        Err(msg) => return render_form_error(&msg),
    };
    match admin_api::create_application(&st.api, c.forward.as_deref(), body).await {
        Ok(()) => redirect_cookies("/admin/applications", &c.set_cookies),
        Err(e) => render_form_error(&e.user_message()),
    }
}

// ===========================================================================
// Application Groups (BUNYIP-100)
// ===========================================================================

#[derive(Deserialize, Default)]
pub struct GroupForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub icon_url: String,
    #[serde(default)]
    pub sort_order: String,
}

/// JSON body for create/update of a group. Required identity fields are
/// bounded and slug-checked; description / icon_url collapse empty to null;
/// sort_order is parsed as a bounded `i32` so non-numeric and out-of-INTEGER
/// inputs surface as inline errors instead of silently becoming 0 or
/// truncating (BUNYIP-113). Name / slug / icon_url validation lands here as
/// part of the BUNYIP-112 sweep so create + edit share the same edge.
fn group_body(f: &GroupForm) -> Result<serde_json::Value, String> {
    use crate::handlers::validate;
    let name = validate::trim_bounded(&f.name, "Name", 200)?;
    let slug = validate::slug(&f.slug, "Slug")?;
    let display_name = validate::trim_bounded(&f.display_name, "Display name", 200)?;
    let description = validate::trim_bounded_opt(&f.description, "Description", 1000)?;
    let icon_url = validate::url_opt(&f.icon_url, "Icon URL", 512)?;
    let sort_order = validate::parse_i32(&f.sort_order, "Sort order")?;
    Ok(json!({
        "name": name,
        "slug": slug,
        "display_name": display_name,
        "description": description,
        "icon_url": icon_url,
        "sort_order": sort_order,
    }))
}

/// Shared create/edit form for a group.
fn group_form(
    action: &str,
    heading: &str,
    g: Option<&ApplicationGroup>,
    error: Option<&str>,
) -> Markup {
    let name = g.map(|g| g.name.as_str()).unwrap_or_default();
    let slug = g.map(|g| g.slug.as_str()).unwrap_or_default();
    let display_name = g.map(|g| g.display_name.as_str()).unwrap_or_default();
    let description = g.and_then(|g| g.description.as_deref()).unwrap_or_default();
    let icon_url = g.and_then(|g| g.icon_url.as_deref()).unwrap_or_default();
    let sort_order = g.map(|g| g.sort_order).unwrap_or(0);
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { (heading) } p class="mt-2 text-muted-foreground" { "Group related applications under one heading on the Applications page." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="p-6" {
                    form method="post" action=(action) class="space-y-4 max-w-md" {
                        @if let Some(err) = error { (error_box(err)) }
                        div class="space-y-2" { label class="text-sm font-medium" { "Name" } input name="name" value=(name) required class=(dashboard_input()); }
                        div class="space-y-2" { label class="text-sm font-medium" { "Slug" } input name="slug" value=(slug) required class=(dashboard_input()); }
                        div class="space-y-2" { label class="text-sm font-medium" { "Display name" } input name="display_name" value=(display_name) required class=(dashboard_input()); }
                        div class="space-y-2" { label class="text-sm font-medium" { "Description" } input name="description" value=(description) class=(dashboard_input()); }
                        div class="space-y-2" { label class="text-sm font-medium" { "Icon URL" } input name="icon_url" value=(icon_url) class=(dashboard_input()); }
                        div class="space-y-2" { label class="text-sm font-medium" { "Sort order" } input name="sort_order" type="number" value=(sort_order) class=(dashboard_input()); }
                        div class="flex items-center gap-2 pt-2" {
                            button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                            a href="/admin/application-groups" class=(button_class("outline", "default", "")) { "Cancel" }
                        }
                    }
                }
            }
        }
    }
}

/// A group `<select>` + save button for the application edit page. Posts to the
/// dedicated set-group endpoint so it never collides with the distribution save
/// (which COALESCEs and cannot clear group_id).
fn group_assignment_form(
    app_id: &str,
    current: Option<&str>,
    groups: &[ApplicationGroup],
) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="p-6" {
                h4 class="text-lg font-semibold" { "Group" }
                p class="text-xs text-muted-foreground mb-3" { "Assign this application to a group, or leave it ungrouped." }
                form method="post" action=(format!("/admin/applications/{app_id}/group")) class="flex items-end gap-2 max-w-md" {
                    select name="group_id" class=(dashboard_input()) {
                        option value="" selected[current.is_none()] { "Ungrouped" }
                        @for g in groups {
                            option value=(g.id) selected[current == Some(g.id.as_str())] { (g.display_name) }
                        }
                    }
                    button type="submit" class=(button_class("default", "default", "")) { "Save" }
                }
            }
        }
    }
}

/// GET /admin/application-groups
pub async fn application_groups(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let groups = admin_api::application_groups(&st.api, c.forward.as_deref())
        .await
        .unwrap_or_default();
    let content = html! {
        div class="space-y-6" {
            div class="flex items-center justify-between gap-4" {
                div { h1 class="text-3xl font-bold" { "Application Groups" } p class="mt-2 text-muted-foreground" { "Group related applications under one heading." } }
                a href="/admin/application-groups/new" class=(button_class("default", "default", "")) { "New group" }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="p-6 pt-0" {
                    div class="divide-y" {
                        @for g in &groups {
                            div class="py-3 flex items-center justify-between gap-4" {
                                div { p class="font-medium" { (g.display_name) } p class="text-xs text-muted-foreground" { (g.slug) } }
                                div class="flex items-center gap-2" {
                                    a href=(format!("/admin/application-groups/{}/edit", g.id)) class=(button_class("outline", "sm", "")) { "Edit" }
                                    form method="post" action=(format!("/admin/application-groups/{}/delete", g.id)) data-confirm="Delete this application group? This cannot be undone." {
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Delete" }
                                    }
                                }
                            }
                        }
                        @if groups.is_empty() {
                            // BUNYIP-415: center the empty state as a block.
                            div class="flex flex-col items-center justify-center py-12 text-center text-muted-foreground" {
                                (icon("layers", "h-8 w-8 mb-2 opacity-50")) "No groups yet"
                            }
                        }
                    }
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/application-groups",
        "Application Groups · Bunyip",
        content,
    )
}

/// GET /admin/application-groups/new
pub async fn application_group_new(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let content = group_form("/admin/application-groups", "New group", None, None);
    admin_response(
        &c,
        &user,
        "/admin/application-groups",
        "New group · Bunyip",
        content,
    )
}

/// POST /admin/application-groups
pub async fn application_group_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<GroupForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let body = match group_body(&f) {
        Ok(b) => b,
        Err(msg) => {
            let content = group_form("/admin/application-groups", "New group", None, Some(&msg));
            return admin_response(
                &c,
                &user,
                "/admin/application-groups",
                "New group · Bunyip",
                content,
            );
        }
    };
    match admin_api::create_application_group(&st.api, c.forward.as_deref(), body).await {
        Ok(()) => redirect_cookies("/admin/application-groups", &c.set_cookies),
        Err(e) => {
            let content = group_form(
                "/admin/application-groups",
                "New group",
                None,
                Some(&e.user_message()),
            );
            admin_response(
                &c,
                &user,
                "/admin/application-groups",
                "New group · Bunyip",
                content,
            )
        }
    }
}

/// GET /admin/application-groups/{id}/edit
pub async fn application_group_edit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let groups = admin_api::application_groups(&st.api, c.forward.as_deref())
        .await
        .unwrap_or_default();
    let content = match groups.iter().find(|g| g.id == id) {
        None => {
            html! { div class="space-y-6" { h1 class="text-3xl font-bold" { "Edit group" } p class="text-muted-foreground" { "Group not found." } } }
        }
        Some(g) => group_form(
            &format!("/admin/application-groups/{id}"),
            &format!("Edit {}", g.display_name),
            Some(g),
            None,
        ),
    };
    admin_response(
        &c,
        &user,
        "/admin/application-groups",
        "Edit group · Bunyip",
        content,
    )
}

/// POST /admin/application-groups/{id}
pub async fn application_group_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<GroupForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let body = match group_body(&f) {
        Ok(b) => b,
        Err(msg) => {
            let content = group_form(
                &format!("/admin/application-groups/{id}"),
                "Edit group",
                None,
                Some(&msg),
            );
            return admin_response(
                &c,
                &user,
                "/admin/application-groups",
                "Edit group · Bunyip",
                content,
            );
        }
    };
    match admin_api::update_application_group(&st.api, c.forward.as_deref(), &id, body).await {
        Ok(()) => redirect_cookies("/admin/application-groups", &c.set_cookies),
        Err(e) => {
            let content = group_form(
                &format!("/admin/application-groups/{id}"),
                "Edit group",
                None,
                Some(&e.user_message()),
            );
            admin_response(
                &c,
                &user,
                "/admin/application-groups",
                "Edit group · Bunyip",
                content,
            )
        }
    }
}

/// POST /admin/application-groups/{id}/delete
pub async fn application_group_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::delete_application_group(&st.api, c.forward.as_deref(), &id).await
    {
        Ok(_) => "/admin/application-groups".to_string(),
        Err(e) => {
            tracing::warn!(group_id = %id, error = ?e, "admin delete application group failed");
            format!(
                "/admin/application-groups?toast_err={}",
                urlenc("Could not delete application group")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}

#[derive(Deserialize)]
pub struct SetGroupForm {
    #[serde(default)]
    pub group_id: String,
}

/// POST /admin/applications/{id}/group
pub async fn application_set_group(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<SetGroupForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let group_id = if f.group_id.trim().is_empty() {
        None
    } else {
        Some(f.group_id.trim())
    };
    let _ = admin_api::set_application_group(&st.api, c.forward.as_deref(), &id, group_id).await;
    redirect_cookies(&format!("/admin/applications/{id}/edit"), &c.set_cookies)
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
                    @if apps.is_empty() {
                        div class="flex flex-col items-center justify-center py-12 text-center text-muted-foreground" {
                            (icon("package", "h-8 w-8 mb-2 opacity-50")) "No applications"
                        }
                    } @else {
                        // BUNYIP-415: flow product rows into two columns (one
                        // below lg) so the catalog uses the width.
                        div class="grid gap-x-8 lg:grid-cols-2" {
                            @for app in &apps {
                                div class="py-3 flex items-center justify-between gap-4 border-b last:border-0" {
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
                        }
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
                                    form method="post" action=(format!("/admin/users/{}/entitlements/revoke", user_id)) data-confirm=(format!("Revoke the {} entitlement from this user? They immediately lose access to it.", app.display_name)) {
                                        input type="hidden" name="slug" value=(app.slug);
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Revoke" }
                                    }
                                } @else {
                                    form method="post" action=(format!("/admin/users/{}/entitlements/grant", user_id)) data-confirm=(format!("Grant the {} entitlement to this user?", app.display_name)) {
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

/// Upper bounds for tier-settings fields. Slots and trial days are i64 with no
/// business meaning beyond these caps; rejecting larger input keeps obvious
/// typos and overflow probes out of the config.
const MAX_TIER_SLOTS: i64 = 1_000_000;
const MAX_TRIAL_DAYS: i64 = 3_650;

/// Field values shown in the tier-settings form. Kept as strings so a failed
/// save can echo back exactly what the admin typed, including junk that did not
/// parse as an integer.
struct TierFormValues {
    lifetime_slots: String,
    early_adopter_slots: String,
    early_adopter_trial_days: String,
    standard_trial_days: String,
    // BUNYIP-122: Stripe catalog IDs echoed back on a failed save so the admin
    // does not lose what they typed when a numeric field fails validation.
    free_price_id: String,
    early_adopter_price_id: String,
    standard_price_id: String,
    lifetime_product_id: String,
    early_adopter_product_id: String,
    standard_product_id: String,
}

impl TierFormValues {
    fn from_config(c: &crate::api::types::TierConfigResponse) -> Self {
        TierFormValues {
            lifetime_slots: c.lifetime_slots.to_string(),
            early_adopter_slots: c.early_adopter_slots.to_string(),
            early_adopter_trial_days: c.early_adopter_trial_days.to_string(),
            standard_trial_days: c.standard_trial_days.to_string(),
            free_price_id: c.free_price_id.clone().unwrap_or_default(),
            early_adopter_price_id: c.early_adopter_price_id.clone().unwrap_or_default(),
            standard_price_id: c.standard_price_id.clone().unwrap_or_default(),
            lifetime_product_id: c.lifetime_product_id.clone().unwrap_or_default(),
            early_adopter_product_id: c.early_adopter_product_id.clone().unwrap_or_default(),
            standard_product_id: c.standard_product_id.clone().unwrap_or_default(),
        }
    }
}

/// Parse one tier-settings field: require a base-10 integer in `[0, max]`.
/// Returns a user-facing message naming the field on failure.
fn parse_tier_field(raw: &str, label: &str, max: i64) -> Result<i64, String> {
    let n: i64 = raw
        .trim()
        .parse()
        .map_err(|_| format!("{label} must be a whole number."))?;
    if n < 0 {
        return Err(format!("{label} must be zero or greater."));
    }
    if n > max {
        return Err(format!("{label} must be at most {max}."));
    }
    Ok(n)
}

fn tier_settings_content(
    cfg: Option<&crate::api::types::TierConfigResponse>,
    values: &TierFormValues,
    error: Option<&str>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Tier Settings" } p class="mt-2 text-muted-foreground" { "Trial lengths and membership slot limits. Stripe price / product mapping now lives on the " a href="/admin/stripe" class="text-primary hover:underline" { "Stripe" } " page." } }
            @match cfg {
                None => p class="text-muted-foreground" { "Could not load tier config." },
                // BUNYIP-417: the Stripe catalog price/product mappings moved to
                // the Stripe page to consolidate all Stripe config under one nav
                // entry. Tier Settings keeps only its non-Stripe concerns (slots
                // + trial lengths).
                Some(c) => form method="post" action="/admin/tier-settings" class="space-y-6" {
                    @if let Some(e) = error { (error_box(e)) }
                    (admin_block(
                        "Tiers & Slots",
                        Some(&format!("{} lifetime and {} early-adopter slots used.", c.lifetime_slots_used, c.early_adopter_slots_used)),
                        html! {
                            div class="space-y-4 max-w-md" {
                                div class="space-y-2" { label class="text-sm font-medium" { "Lifetime slots" } input name="lifetime_slots" type="number" min="0" max=(MAX_TIER_SLOTS) value=(values.lifetime_slots) class=(dashboard_input()); }
                                div class="space-y-2" { label class="text-sm font-medium" { "Early-adopter slots" } input name="early_adopter_slots" type="number" min="0" max=(MAX_TIER_SLOTS) value=(values.early_adopter_slots) class=(dashboard_input()); }
                                div class="space-y-2" { label class="text-sm font-medium" { "Early-adopter trial days" } input name="early_adopter_trial_days" type="number" min="0" max=(MAX_TRIAL_DAYS) value=(values.early_adopter_trial_days) class=(dashboard_input()); }
                                div class="space-y-2" { label class="text-sm font-medium" { "Standard trial days" } input name="standard_trial_days" type="number" min="0" max=(MAX_TRIAL_DAYS) value=(values.standard_trial_days) class=(dashboard_input()); }
                            }
                        },
                    ))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                },
            }
        }
    }
}

pub async fn tier_settings(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cfg = admin_api::tier_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let values = cfg
        .as_ref()
        .map(TierFormValues::from_config)
        .unwrap_or_else(|| TierFormValues {
            lifetime_slots: String::new(),
            early_adopter_slots: String::new(),
            early_adopter_trial_days: String::new(),
            standard_trial_days: String::new(),
            free_price_id: String::new(),
            early_adopter_price_id: String::new(),
            standard_price_id: String::new(),
            lifetime_product_id: String::new(),
            early_adopter_product_id: String::new(),
            standard_product_id: String::new(),
        });
    let content = tier_settings_content(cfg.as_ref(), &values, None);
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
    // BUNYIP-111: kept as raw strings so a non-integer submission can be
    // echoed back and re-validated inline instead of failing Form extraction
    // with a bare 422.
    #[serde(default)]
    pub lifetime_slots: String,
    #[serde(default)]
    pub early_adopter_slots: String,
    #[serde(default)]
    pub early_adopter_trial_days: String,
    #[serde(default)]
    pub standard_trial_days: String,
    // BUNYIP-122: Stripe price + product IDs. Optional - blank ("" after
    // form parse) leaves the persisted value untouched. We send the field
    // only when non-empty so the API's tri-state-by-omission semantics
    // line up.
    #[serde(default)]
    pub free_price_id: String,
    #[serde(default)]
    pub early_adopter_price_id: String,
    #[serde(default)]
    pub standard_price_id: String,
    #[serde(default)]
    pub lifetime_product_id: String,
    #[serde(default)]
    pub early_adopter_product_id: String,
    #[serde(default)]
    pub standard_product_id: String,
}
pub async fn tier_settings_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TierForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    // Echo back exactly what was submitted (trimmed) if we have to re-render.
    let values = TierFormValues {
        lifetime_slots: f.lifetime_slots.trim().to_string(),
        early_adopter_slots: f.early_adopter_slots.trim().to_string(),
        early_adopter_trial_days: f.early_adopter_trial_days.trim().to_string(),
        standard_trial_days: f.standard_trial_days.trim().to_string(),
        free_price_id: f.free_price_id.trim().to_string(),
        early_adopter_price_id: f.early_adopter_price_id.trim().to_string(),
        standard_price_id: f.standard_price_id.trim().to_string(),
        lifetime_product_id: f.lifetime_product_id.trim().to_string(),
        early_adopter_product_id: f.early_adopter_product_id.trim().to_string(),
        standard_product_id: f.standard_product_id.trim().to_string(),
    };

    // Validate the numeric fields and build the request body before calling the
    // API, then surface any API-side rejection instead of discarding it. `?`
    // short-circuits on the first bad field so the message names the offending
    // input. The Stripe catalog IDs (BUNYIP-122) are sent only when non-empty
    // and within the 255-char column limit, so an omitted field leaves the
    // persisted value untouched.
    let validated = (|| {
        let mut body = serde_json::Map::new();
        body.insert(
            "lifetime_slots".into(),
            json!(parse_tier_field(
                &f.lifetime_slots,
                "Lifetime slots",
                MAX_TIER_SLOTS
            )?),
        );
        body.insert(
            "early_adopter_slots".into(),
            json!(parse_tier_field(
                &f.early_adopter_slots,
                "Early-adopter slots",
                MAX_TIER_SLOTS
            )?),
        );
        body.insert(
            "early_adopter_trial_days".into(),
            json!(parse_tier_field(
                &f.early_adopter_trial_days,
                "Early-adopter trial days",
                MAX_TRIAL_DAYS
            )?),
        );
        body.insert(
            "standard_trial_days".into(),
            json!(parse_tier_field(
                &f.standard_trial_days,
                "Standard trial days",
                MAX_TRIAL_DAYS
            )?),
        );
        for (k, v) in [
            ("free_price_id", &f.free_price_id),
            ("early_adopter_price_id", &f.early_adopter_price_id),
            ("standard_price_id", &f.standard_price_id),
            ("lifetime_product_id", &f.lifetime_product_id),
            ("early_adopter_product_id", &f.early_adopter_product_id),
            ("standard_product_id", &f.standard_product_id),
        ] {
            let t = v.trim();
            if !t.is_empty() && t.len() <= 255 {
                body.insert(k.into(), json!(t));
            }
        }
        Ok::<_, String>(serde_json::Value::Object(body))
    })();

    let error = match validated {
        Ok(body) => {
            match admin_api::update_tier_config(&st.api, c.forward.as_deref(), body).await {
                Ok(()) => return redirect_cookies("/admin/tier-settings", &c.set_cookies),
                Err(e) => e.user_message(),
            }
        }
        Err(msg) => msg,
    };

    // Re-render the form inline with the error and the submitted values.
    let cfg = admin_api::tier_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = tier_settings_content(cfg.as_ref(), &values, Some(&error));
    admin_response(
        &c,
        &user,
        "/admin/tier-settings",
        "Tier settings · Bunyip",
        content,
    )
}

// ===========================================================================
// Email / SMTP config (BUNYIP-351)
// ===========================================================================

fn email_settings_content(cfg: Option<&crate::api::types::EmailConfigResponse>) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Email" } p class="mt-2 text-muted-foreground" { "Configure the SMTP relay for transactional email. Changes apply immediately without a restart." } }
            @match cfg {
                None => p class="text-muted-foreground" { "Could not load email config." },
                // BUNYIP-415: two-column block layout. The SMTP transport
                // settings and the sender/notification settings sit in
                // side-by-side blocks (one column below lg), inside one form so
                // a single Save persists everything.
                Some(e) => div class="space-y-6" {
                    form method="post" action="/admin/email" class="space-y-6" {
                    (admin_block_grid(vec![
                        admin_block(
                            "SMTP Connection",
                            Some(&format!("Source: {}. Leave a field blank to keep the existing value.", e.source)),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" {
                                        label class="text-sm font-medium" { "Sending" }
                                        select name="enabled" class=(dashboard_input()) {
                                            option value="true" selected[e.enabled] { "Enabled" }
                                            option value="false" selected[!e.enabled] { "Disabled" }
                                        }
                                    }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP host" } input name="smtp_host" value=(e.smtp_host) placeholder="smtp.example.com" class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP port" } input name="smtp_port" type="number" min="1" max="65535" value=(e.smtp_port) class=(dashboard_input()); }
                                    div class="space-y-2" {
                                        label class="text-sm font-medium" { "TLS mode" }
                                        select name="smtp_tls" class=(dashboard_input()) {
                                            option value="implicit" selected[e.smtp_tls == "implicit"] { "Implicit (port 465)" }
                                            option value="starttls" selected[e.smtp_tls == "starttls"] { "STARTTLS (port 587)" }
                                        }
                                    }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP username" } input name="smtp_username" value=(e.smtp_username) autocomplete="off" class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP password" } input name="smtp_password" type="password" autocomplete="new-password" placeholder=(if e.has_smtp_password { "••••••••" } else { "Not set" }) class=(dashboard_input()); p class="text-xs text-muted-foreground" {
                                        // BUNYIP-432: the placeholder is a fixed-length mask driven only
                                        // by has_smtp_password; the real password (and its length) never
                                        // reaches the browser. Leave blank to keep the current one.
                                        @if e.has_smtp_password { "A password is set (stored encrypted). Leave blank to keep it, or type a new one to replace it." } @else { "No password set. Stored encrypted when you save one." }
                                    } }
                                }
                            },
                        ),
                        admin_block(
                            "Sender & Notifications",
                            Some("Who transactional mail comes from, and where operational notices go."),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" { label class="text-sm font-medium" { "From email" } input name="from_email" type="email" value=(e.from_email) placeholder="noreply@example.com" class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "From name" } input name="from_name" value=(e.from_name) class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "Admin notification emails" } input name="admin_notification_emails" value=(e.admin_notification_emails.join(", ")) placeholder="ops@example.com, alerts@example.com" class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Comma-separated recipients for operational notices." } }
                                }
                            },
                        ),
                    ]))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    }
                    // BUNYIP-433: Test connection lives in its own form so it
                    // submits no fields - it always tests the SAVED settings,
                    // never the unsaved edits in the form above.
                    form method="post" action="/admin/email/test" class="flex flex-wrap items-center gap-3 border-t border-border/50 pt-4" {
                        button type="submit" class=(button_class("outline", "default", "")) { (icon("mail", "mr-2 h-4 w-4")) "Test connection" }
                        p class="text-xs text-muted-foreground" { "Opens a connection to the saved SMTP server and signs in, without sending an email. Save changes first to test them." }
                    }
                },
            }
        }
    }
}

// ===========================================================================
// Auto-ban settings (BUNYIP-351)
// ===========================================================================

/// Upper bounds for the auto-ban fields. Threshold is a strike count; the two
/// durations are seconds (window capped at 30 days, ban at 365 days) so a typo
/// cannot persist an absurd value.
const MAX_AUTO_BAN_THRESHOLD: i64 = 100_000;
const MAX_AUTO_BAN_WINDOW_SECS: i64 = 2_592_000; // 30 days
const MAX_AUTO_BAN_DURATION_SECS: i64 = 31_536_000; // 365 days

/// Auto-ban form values, kept as strings (numerics) so a failed save echoes
/// back exactly what the admin typed instead of failing extraction with a 422.
struct AutoBanFormValues {
    enabled: bool,
    threshold: String,
    window_secs: String,
    ban_duration_secs: String,
}

impl AutoBanFormValues {
    fn from_config(c: &crate::api::types::AutoBanConfigResponse) -> Self {
        AutoBanFormValues {
            enabled: c.enabled,
            threshold: c.threshold.to_string(),
            window_secs: c.window_secs.to_string(),
            ban_duration_secs: c.ban_duration_secs.to_string(),
        }
    }
}

/// Parse one auto-ban field: require a base-10 integer in `[1, max]`.
fn parse_auto_ban_field(raw: &str, label: &str, max: i64) -> Result<i64, String> {
    let n: i64 = raw
        .trim()
        .parse()
        .map_err(|_| format!("{label} must be a whole number."))?;
    if n < 1 {
        return Err(format!("{label} must be at least 1."));
    }
    if n > max {
        return Err(format!("{label} must be at most {max}."));
    }
    Ok(n)
}

fn auto_ban_settings_content(
    cfg: Option<&crate::api::types::AutoBanConfigResponse>,
    values: &AutoBanFormValues,
    error: Option<&str>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Auto-ban Settings" } p class="mt-2 text-muted-foreground" { "Tune the automatic IP-ban thresholds. Changes apply immediately without a restart." } }
            @match cfg {
                None => p class="text-muted-foreground" { "Could not load auto-ban config." },
                // BUNYIP-415: detection (when to strike/ban) and enforcement
                // (the on/off switch and how long a ban lasts) sit in two
                // side-by-side blocks, one column below lg, inside one form.
                Some(c) => form method="post" action="/admin/auto-ban-settings" class="space-y-6" {
                    @if let Some(e) = error { (error_box(e)) }
                    (admin_block_grid(vec![
                        admin_block(
                            "Detection",
                            Some(&format!("When a source IP earns a ban. Values sourced from {}.", c.source)),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" { label class="text-sm font-medium" { "Strike threshold" } input name="threshold" type="number" min="1" max=(MAX_AUTO_BAN_THRESHOLD) value=(values.threshold) class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Suspicious requests from one IP before it is banned." } }
                                    div class="space-y-2" { label class="text-sm font-medium" { "Strike window (seconds)" } input name="window_secs" type="number" min="1" max=(MAX_AUTO_BAN_WINDOW_SECS) value=(values.window_secs) class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Rolling window over which strikes accumulate." } }
                                }
                            },
                        ),
                        admin_block(
                            "Enforcement",
                            Some("Whether auto-ban is active, and how long a ban holds."),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" {
                                        label class="text-sm font-medium" { "Auto-ban" }
                                        select name="enabled" class=(dashboard_input()) {
                                            option value="true" selected[values.enabled] { "Enabled" }
                                            option value="false" selected[!values.enabled] { "Disabled" }
                                        }
                                    }
                                    div class="space-y-2" { label class="text-sm font-medium" { "Ban duration (seconds)" } input name="ban_duration_secs" type="number" min="1" max=(MAX_AUTO_BAN_DURATION_SECS) value=(values.ban_duration_secs) class=(dashboard_input()); p class="text-xs text-muted-foreground" { "How long a ban lasts before it expires." } }
                                }
                            },
                        ),
                    ]))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                },
            }
        }
    }
}

pub async fn email(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cfg = admin_api::email_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = email_settings_content(cfg.as_ref());
    admin_response(&c, &user, "/admin/email", "Email · Bunyip", content)
}

#[derive(Deserialize)]
pub struct EmailSettingsForm {
    #[serde(default)]
    pub enabled: String,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: String,
    #[serde(default)]
    pub smtp_tls: String,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub from_email: String,
    #[serde(default)]
    pub from_name: String,
    #[serde(default)]
    pub admin_notification_emails: String,
}

/// Build the PUT body from the submitted form. `enabled` and `smtp_tls` (both
/// from `<select>`s) are always sent; the SMTP port is validated when present;
/// every other field is sent only when non-blank so an untouched field leaves
/// the persisted value unchanged. Pure so it can be unit-tested.
fn email_update_body(f: &EmailSettingsForm) -> Result<serde_json::Value, String> {
    let mut body = serde_json::Map::new();
    body.insert("enabled".into(), json!(f.enabled.trim() == "true"));

    let port = f.smtp_port.trim();
    if !port.is_empty() {
        let n: i32 = port
            .parse()
            .map_err(|_| "SMTP port must be a whole number.".to_string())?;
        if !(1..=65535).contains(&n) {
            return Err("SMTP port must be between 1 and 65535.".to_string());
        }
        body.insert("smtp_port".into(), json!(n));
    }

    let tls = f.smtp_tls.trim();
    if tls == "implicit" || tls == "starttls" {
        body.insert("smtp_tls".into(), json!(tls));
    }

    let from_email = f.from_email.trim();
    if !from_email.is_empty() && !from_email.contains('@') {
        return Err("From email must be a valid address.".to_string());
    }

    for (key, raw) in [
        ("smtp_host", &f.smtp_host),
        ("smtp_username", &f.smtp_username),
        ("smtp_password", &f.smtp_password),
        ("from_email", &f.from_email),
        ("from_name", &f.from_name),
        ("admin_notification_emails", &f.admin_notification_emails),
    ] {
        let t = raw.trim();
        if !t.is_empty() {
            body.insert(key.into(), json!(t));
        }
    }

    Ok(serde_json::Value::Object(body))
}

pub async fn email_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<EmailSettingsForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let error = match email_update_body(&f) {
        Ok(body) => match admin_api::update_email_config(&st.api, c.forward.as_deref(), body).await
        {
            Ok(()) => return redirect_cookies("/admin/email", &c.set_cookies),
            Err(e) => e.user_message(),
        },
        Err(msg) => msg,
    };

    // Re-render with the persisted values plus the inline error.
    let cfg = admin_api::email_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = html! {
        (error_box(&error))
        (email_settings_content(cfg.as_ref()))
    };
    admin_response(&c, &user, "/admin/email", "Email · Bunyip", content)
}

/// POST /admin/email/test - BUNYIP-433. Run the SMTP "Test connection" probe
/// against the saved settings and re-render the email page with a banner naming
/// the outcome (and, on failure, the stage that failed). No mail is sent.
pub async fn email_test(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let banner = match admin_api::test_email_config(&st.api, c.forward.as_deref()).await {
        Ok(r) if r.ok => success_box(&r.message),
        // Reached the relay but a stage failed: name it (connect / tls / auth).
        Ok(r) => error_box(&format!(
            "SMTP test failed at the {} stage. {}",
            r.stage, r.message
        )),
        // Transport / rate-limit (429) error before the probe could report.
        Err(e) => error_box(&e.user_message()),
    };

    let cfg = admin_api::email_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = html! {
        (banner)
        (email_settings_content(cfg.as_ref()))
    };
    admin_response(&c, &user, "/admin/email", "Email · Bunyip", content)
}

pub async fn auto_ban_settings(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cfg = admin_api::auto_ban_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let values = cfg
        .as_ref()
        .map(AutoBanFormValues::from_config)
        .unwrap_or(AutoBanFormValues {
            enabled: false,
            threshold: String::new(),
            window_secs: String::new(),
            ban_duration_secs: String::new(),
        });
    let content = auto_ban_settings_content(cfg.as_ref(), &values, None);
    admin_response(
        &c,
        &user,
        "/admin/auto-ban-settings",
        "Auto-ban settings · Bunyip",
        content,
    )
}

#[derive(Deserialize)]
pub struct AutoBanForm {
    #[serde(default)]
    pub enabled: String,
    #[serde(default)]
    pub threshold: String,
    #[serde(default)]
    pub window_secs: String,
    #[serde(default)]
    pub ban_duration_secs: String,
}

pub async fn auto_ban_settings_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<AutoBanForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let enabled = f.enabled.trim() == "true";

    // Echo back exactly what was submitted (trimmed) if we have to re-render.
    let values = AutoBanFormValues {
        enabled,
        threshold: f.threshold.trim().to_string(),
        window_secs: f.window_secs.trim().to_string(),
        ban_duration_secs: f.ban_duration_secs.trim().to_string(),
    };

    // Validate the numeric fields and build the request body. `?` short-circuits
    // on the first bad field so the message names the offending input. `enabled`
    // is always sent explicitly (a full form submit represents the admin's
    // intent), the numerics likewise, so the API's COALESCE never re-reads a
    // stale value.
    let validated = (|| {
        let mut body = serde_json::Map::new();
        body.insert("enabled".into(), json!(enabled));
        body.insert(
            "threshold".into(),
            json!(parse_auto_ban_field(
                &f.threshold,
                "Strike threshold",
                MAX_AUTO_BAN_THRESHOLD
            )?),
        );
        body.insert(
            "window_secs".into(),
            json!(parse_auto_ban_field(
                &f.window_secs,
                "Strike window",
                MAX_AUTO_BAN_WINDOW_SECS
            )?),
        );
        body.insert(
            "ban_duration_secs".into(),
            json!(parse_auto_ban_field(
                &f.ban_duration_secs,
                "Ban duration",
                MAX_AUTO_BAN_DURATION_SECS
            )?),
        );
        Ok::<_, String>(serde_json::Value::Object(body))
    })();

    let error = match validated {
        Ok(body) => {
            match admin_api::update_auto_ban_config(&st.api, c.forward.as_deref(), body).await {
                Ok(()) => return redirect_cookies("/admin/auto-ban-settings", &c.set_cookies),
                Err(e) => e.user_message(),
            }
        }
        Err(msg) => msg,
    };

    // Re-render the form inline with the error and the submitted values.
    let cfg = admin_api::auto_ban_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = auto_ban_settings_content(cfg.as_ref(), &values, Some(&error));
    admin_response(
        &c,
        &user,
        "/admin/auto-ban-settings",
        "Auto-ban settings · Bunyip",
        content,
    )
}

// ===========================================================================
// Account backup & restore (BUNYIP-353)
// ===========================================================================

/// Upper bound on an uploaded backup file. The bundle embeds each entitled
/// app's backup, so it can be larger than a form post but is not unbounded.
/// Matches the API's restore body limit (8 MiB).
const BACKUP_MAX_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

/// The Integrations "Backup" surface: explains what an account backup contains,
/// offers a one-click download, and accepts an upload to restore. Reached from
/// the Backup add-on tile on `/applications`; admin-gated like the other
/// settings pages.
fn backup_settings_content(report: Option<&RestoreReport>, error: Option<&str>) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "Backup & Restore" }
                p class="mt-2 text-muted-foreground" { "Download a portable backup of this account, or restore one from a file. Account state is captured together with each entitled app's data." }
            }

            @if let Some(msg) = error { (error_box(msg)) }
            @if let Some(r) = report { (restore_report_card(r)) }

            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    h3 class="text-2xl font-semibold leading-none tracking-tight" { "What's included" }
                    p class="text-sm text-muted-foreground" { "One JSON bundle covering the account's Bunyip state plus each entitled app." }
                }
                div class="p-6 pt-0" {
                    ul class="list-disc space-y-2 pl-5 text-sm text-muted-foreground" {
                        li { "Account profile (name and phone)." }
                        li { "Entitlements: the apps this account can access." }
                        li { "Per-app data for each entitled app. " span class="text-foreground" { "Mokosh" } " is pending its backup API and is recorded as unavailable until then; unentitled apps are skipped." }
                    }
                }
            }

            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    h3 class="text-2xl font-semibold leading-none tracking-tight" { "Download backup" }
                    p class="text-sm text-muted-foreground" { "Generates and downloads the bundle now." }
                }
                div class="p-6 pt-0" {
                    a href="/integrations/backup/download" class=(button_class("default", "default", "")) {
                        (icon("download", "mr-2 h-4 w-4")) "Download backup"
                    }
                }
            }

            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    h3 class="text-2xl font-semibold leading-none tracking-tight" { "Restore from backup" }
                    p class="text-sm text-muted-foreground" { "Re-applies the account profile and re-grants the entitlements in the file, then dispatches each entitled app's data to that app. This overwrites the current profile." }
                }
                div class="p-6 pt-0" {
                    form method="post" action="/integrations/backup/restore" enctype="multipart/form-data" class="space-y-4 max-w-md" data-confirm="Restore from this backup file? This overwrites the current account profile and re-grants the entitlements in the file." {
                        div class="space-y-2" {
                            label class="text-sm font-medium" { "Backup file (.json)" }
                            input type="file" name="backup" accept="application/json,.json" required class=(dashboard_input());
                        }
                        button type="submit" class=(button_class("default", "default", "")) { (icon("upload", "mr-2 h-4 w-4")) "Restore" }
                    }
                }
            }
        }
    }
}

/// Render the outcome of a restore.
fn restore_report_card(r: &RestoreReport) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                h3 class="text-2xl font-semibold leading-none tracking-tight" { "Restore complete" }
            }
            div class="p-6 pt-0 space-y-3 text-sm" {
                p { "Profile: " @if r.profile_restored { span class="text-foreground" { "restored" } } @else { "unchanged" } }
                p {
                    "Entitlements granted: "
                    @if r.entitlements_granted.is_empty() { "none" }
                    @else { span class="text-foreground" { (r.entitlements_granted.join(", ")) } }
                }
                @if !r.apps.is_empty() {
                    div {
                        p class="font-medium text-foreground" { "Apps" }
                        ul class="mt-1 list-disc space-y-1 pl-5 text-muted-foreground" {
                            @for app in &r.apps {
                                li {
                                    span class="text-foreground" { (app.slug) } ": "
                                    @match &app.status {
                                        AppRestoreStatus::Restored => { "restored" }
                                        AppRestoreStatus::Skipped { reason } => { "skipped (" (reason) ")" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// GET /integrations/backup - the Backup add-on settings page.
pub async fn backup_settings(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let content = backup_settings_content(None, None);
    admin_response(
        &c,
        &user,
        "/integrations/backup",
        "Backup & Restore · Bunyip",
        content,
    )
}

/// GET /integrations/backup/download - stream the account bundle from the API
/// with its `Content-Disposition` so the browser saves the file. Mirrors
/// `feedback_export`.
pub async fn backup_download(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (_user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    match st.api.get_stream("/account/backup", fwd).await {
        Ok(resp) if resp.status().is_success() => {
            let content_type = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();
            let disposition = resp
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
                .unwrap_or_else(|| "attachment; filename=\"account-backup.json\"".to_string());
            let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
            let content_length = resp
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let mut builder = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::CONTENT_DISPOSITION, disposition);
            builder = with_attachment_hardening(builder);
            if let Some(len) = content_length {
                builder = builder.header(header::CONTENT_LENGTH, len);
            }
            builder
                .body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| redirect_cookies("/integrations/backup", &c.set_cookies))
        }
        Ok(resp) if resp.status().as_u16() == 401 => redirect_cookies("/login", &c.set_cookies),
        _ => redirect_cookies("/integrations/backup", &c.set_cookies),
    }
}

/// Read the single uploaded `backup` file from a multipart body and parse it as
/// JSON. Mirrors `read_feedback_multipart`'s field loop.
async fn read_backup_upload(multipart: &mut Multipart) -> Result<serde_json::Value, String> {
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => return Err("No backup file was uploaded.".into()),
            Err(e) => return Err(format!("Could not read upload: {e}")),
        };
        let is_backup = field.name() == Some("backup");
        // Always drain the field body before advancing to the next one.
        let bytes = match field.bytes().await {
            Ok(b) => b,
            Err(e) => return Err(format!("Could not read the file: {e}")),
        };
        if !is_backup {
            continue;
        }
        if bytes.is_empty() {
            return Err("The uploaded file is empty.".into());
        }
        if bytes.len() > BACKUP_MAX_UPLOAD_BYTES {
            return Err(format!(
                "The backup file must be {} MB or smaller.",
                BACKUP_MAX_UPLOAD_BYTES / (1024 * 1024)
            ));
        }
        return serde_json::from_slice(&bytes)
            .map_err(|_| "That file is not a valid backup (expected JSON).".to_string());
    }
}

/// POST /integrations/backup/restore - parse the uploaded bundle and forward it
/// to the API, then render the resulting report (or an inline error).
pub async fn backup_restore(
    State(st): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let (report, error) = match read_backup_upload(&mut multipart).await {
        Ok(bundle) => match admin_api::restore_account(&st.api, c.forward.as_deref(), bundle).await
        {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(e.user_message())),
        },
        Err(msg) => (None, Some(msg)),
    };

    let content = backup_settings_content(report.as_ref(), error.as_deref());
    admin_response(
        &c,
        &user,
        "/integrations/backup",
        "Backup & Restore · Bunyip",
        content,
    )
}

// ===========================================================================
// Stripe: config + setup docs + products + prices (BUNYIP-416)
// ===========================================================================

/// Setup guidance ported from the a8n-tools Stripe admin panel (BUNYIP-416):
/// how and where to create the restricted API key and how the app-tag scopes
/// what is shown. Rendered as a full-width intro card above the config form.
fn stripe_setup_docs() -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="p-6 space-y-3 text-sm text-muted-foreground" {
                div class="flex items-center gap-2 text-foreground" { (icon("help-circle", "h-5 w-5 text-primary")) h3 class="text-base font-semibold" { "Setting up Stripe" } }
                p {
                    "Your Stripe secret key authenticates API requests. Generate a "
                    a href="https://dashboard.stripe.com/apikeys" target="_blank" rel="noopener noreferrer" class="text-primary hover:underline" { "restricted key" }
                    " with these permissions set to " span class="font-medium text-foreground" { "Write" }
                    ": Products, Prices, Customers, Subscriptions, and Checkout Sessions; and " span class="font-medium text-foreground" { "Read" } " for Invoices."
                }
                p {
                    "Keys follow the format " code class="rounded bg-muted px-1 py-0.5 text-xs" { "rk_(live|test)_…" }
                    " - the prefix shows whether it is a live or test key. Leave a field blank to keep the existing value."
                }
                p {
                    "Products created here are tagged with your " span class="font-medium text-foreground" { "App tag" }
                    " in Stripe metadata, and only products matching that tag are shown. Add your API key, save, then manage Products and Prices below. A lifetime plan is simply a product with a "
                    span class="font-medium text-foreground" { "$0.00" } " price."
                }
            }
        }
    }
}

/// Format a Stripe price amount for display. A zero-amount lifetime price is
/// `Some(0)` -> "$0.00" (not "--"); a null amount -> "--".
fn format_stripe_amount(unit_amount: Option<i64>, currency: &str) -> String {
    match unit_amount {
        None => "--".to_string(),
        Some(cents) => {
            let whole = cents / 100;
            let frac = (cents % 100).abs();
            match currency.to_ascii_lowercase().as_str() {
                "usd" => format!("${whole}.{frac:02}"),
                "eur" => format!("€{whole}.{frac:02}"),
                "gbp" => format!("£{whole}.{frac:02}"),
                _ => format!("{whole}.{frac:02} {}", currency.to_uppercase()),
            }
        }
    }
}

/// The Products block: a create form plus the app-tagged product list, each
/// with an Archive action. `products == None` is the "could not load" state
/// (e.g. no valid API key yet).
fn stripe_products_block(products: Option<&[crate::api::types::StripeProduct]>) -> Markup {
    admin_block(
        "Products",
        Some("Stripe products for your subscription tiers."),
        html! {
            form method="post" action="/admin/stripe/products" class="flex flex-wrap items-end gap-3 mb-4" {
                div class="space-y-1 flex-1 min-w-[12rem]" { label class="text-xs font-medium" { "Name" } input name="name" required placeholder="Personal Plan" class=(dashboard_input()); }
                div class="space-y-1 flex-1 min-w-[12rem]" { label class="text-xs font-medium" { "Description" } input name="description" placeholder="Optional" class=(dashboard_input()); }
                button type="submit" class=(button_class("default", "sm", "")) { "Create product" }
            }
            @match products {
                None => (error_box("Could not load products from Stripe. Add a valid API key above and save, then reload.")),
                Some([]) => p class="py-6 text-center text-sm text-muted-foreground" { "No products yet. Create one to get started." },
                Some(list) => div class="divide-y" {
                    @for p in list {
                        div class="py-3 flex items-center justify-between gap-4" {
                            div class="min-w-0" {
                                p class="font-medium flex items-center gap-2" {
                                    (p.name)
                                    @if p.active { (badge("success", "Active")) } @else { (badge("secondary", "Archived")) }
                                }
                                @if let Some(d) = p.description.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
                                    p class="text-xs text-muted-foreground truncate" { (d) }
                                }
                                p class="text-xs text-muted-foreground font-mono truncate" { (p.id) }
                            }
                            @if p.active {
                                form method="post" action=(format!("/admin/stripe/products/{}/archive", p.id)) data-confirm="Archive this product? It will no longer be available for new subscriptions." {
                                    button type="submit" class=(button_class("outline", "sm", "")) { "Archive" }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// The Prices block: a create form (product dropdown limited to active
/// products; amount in dollars, zero allowed for a lifetime plan) plus the
/// price list, each active price with an Archive action. Prices are immutable
/// in Stripe, so there is no edit.
fn stripe_prices_block(
    prices: Option<&[crate::api::types::StripePrice]>,
    products: &[crate::api::types::StripeProduct],
) -> Markup {
    let name_of = |pid: &str| {
        products
            .iter()
            .find(|p| p.id == pid)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| pid.to_string())
    };
    admin_block(
        "Prices",
        Some("Pricing for your products. A lifetime plan is a $0.00 price."),
        html! {
            form method="post" action="/admin/stripe/prices" class="flex flex-wrap items-end gap-3 mb-4" {
                div class="space-y-1 min-w-[11rem]" {
                    label class="text-xs font-medium" { "Product" }
                    select name="product_id" required class=(dashboard_input()) {
                        option value="" disabled selected { "Select a product" }
                        @for p in products.iter().filter(|p| p.active) { option value=(p.id) { (p.name) } }
                    }
                }
                div class="space-y-1 w-28" { label class="text-xs font-medium" { "Amount" } input name="amount" type="number" step="0.01" min="0" required placeholder="9.99" class=(dashboard_input()); }
                div class="space-y-1 w-24" {
                    label class="text-xs font-medium" { "Currency" }
                    select name="currency" class=(dashboard_input()) { option value="usd" { "USD" } option value="eur" { "EUR" } option value="gbp" { "GBP" } }
                }
                div class="space-y-1 w-28" {
                    label class="text-xs font-medium" { "Interval" }
                    select name="interval" class=(dashboard_input()) { option value="month" { "Monthly" } option value="year" { "Yearly" } }
                }
                button type="submit" class=(button_class("default", "sm", "")) { "Create price" }
            }
            @match prices {
                None => (error_box("Could not load prices from Stripe. Add a valid API key above and save, then reload.")),
                Some([]) => p class="py-6 text-center text-sm text-muted-foreground" { "No prices yet. Create one to get started." },
                Some(list) => div class="divide-y" {
                    @for pr in list {
                        div class={ "py-3 flex items-center justify-between gap-4 " (if pr.active { "" } else { "opacity-50" }) } {
                            div class="min-w-0" {
                                p class="font-medium flex items-center gap-2" {
                                    (format_stripe_amount(pr.unit_amount, &pr.currency))
                                    span class="text-xs font-normal text-muted-foreground" { (pr.recurring_interval.clone().unwrap_or_else(|| "One-time".into())) }
                                    @if pr.active { (badge("success", "Active")) } @else { (badge("secondary", "Archived")) }
                                }
                                p class="text-xs text-muted-foreground truncate" { (name_of(&pr.product_id)) }
                                p class="text-xs text-muted-foreground font-mono truncate" { (pr.id) }
                            }
                            @if pr.active {
                                form method="post" action=(format!("/admin/stripe/prices/{}/archive", pr.id)) data-confirm="Archive this price? Existing subscriptions using it are not affected." {
                                    button type="submit" class=(button_class("outline", "sm", "")) { "Archive" }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// The tier -> Stripe catalog mapping (BUNYIP-417, moved here from Tier
/// Settings). Wires each tier to its Stripe price / product IDs. Its own form
/// (separate from the keys/checkout config) posting to `/admin/stripe/catalog`,
/// which partial-updates the tier config (blank = keep). `tier == None` renders
/// a load-error note.
fn stripe_catalog_section(tier: Option<&crate::api::types::TierConfigResponse>) -> Markup {
    let field = |label: &str, name: &str, ph: &str, value: &Option<String>| -> Markup {
        html! {
            div class="space-y-2" {
                label class="text-sm font-medium" { (label) }
                input name=(name) type="text" maxlength="255" placeholder=(ph) value=(value.clone().unwrap_or_default()) class=(dashboard_input());
            }
        }
    };
    html! {
        div class="space-y-3" {
            div { h3 class="text-xl font-semibold" { "Tier catalog mapping" } p class="text-sm text-muted-foreground" { "Wire each membership tier to the Stripe price / product it should use. Leave a field blank to keep the existing value." } }
            @match tier {
                None => (error_box("Could not load the tier catalog mapping.")),
                Some(t) => form method="post" action="/admin/stripe/catalog" class="space-y-6" {
                    (admin_block_grid(vec![
                        admin_block("Free / lifetime", None, html! {
                            div class="space-y-4" {
                                (field("Free price ID", "free_price_id", "price_...", &t.free_price_id))
                                (field("Lifetime product ID", "lifetime_product_id", "prod_...", &t.lifetime_product_id))
                            }
                        }),
                        admin_block("Early adopter", None, html! {
                            div class="space-y-4" {
                                (field("Early-adopter price ID", "early_adopter_price_id", "price_...", &t.early_adopter_price_id))
                                (field("Early-adopter product ID", "early_adopter_product_id", "prod_...", &t.early_adopter_product_id))
                            }
                        }),
                        admin_block("Standard", None, html! {
                            div class="space-y-4" {
                                (field("Standard price ID", "standard_price_id", "price_...", &t.standard_price_id))
                                (field("Standard product ID", "standard_product_id", "prod_...", &t.standard_product_id))
                            }
                        }),
                    ]))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save catalog mapping" }
                },
            }
        }
    }
}

pub async fn stripe(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let cfg = admin_api::stripe_config(&st.api, fwd).await.ok();
    // Products + prices come from Stripe via the API; an unconfigured / invalid
    // key surfaces as None and the blocks render a "could not load" note.
    let products = admin_api::list_stripe_products(&st.api, fwd).await.ok();
    let prices = admin_api::list_stripe_prices(&st.api, fwd).await.ok();
    // BUNYIP-417: the tier -> Stripe price/product mapping moved here from Tier
    // Settings, so all Stripe config lives under one nav entry.
    let tier = admin_api::tier_config(&st.api, fwd).await.ok();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Stripe" } p class="mt-2 text-muted-foreground" { "Connect and configure Stripe billing, products, and prices." } }
            @match cfg {
                None => p class="text-muted-foreground" { "Could not load Stripe config." },
                Some(s) => {
                    // BUNYIP-416: setup guidance ported from a8n-tools.
                    (stripe_setup_docs())
                    // BUNYIP-415: config in a responsive two-column block grid,
                    // both blocks in one form so a single Save persists all.
                    form method="post" action="/admin/stripe" class="space-y-6" {
                        (admin_block_grid(vec![
                            admin_block(
                                "Stripe Configuration",
                                Some(&format!("Source: {}. Leave a field blank to keep the existing value.", s.source)),
                                html! {
                                    div class="space-y-4" {
                                        div class="space-y-2" { label class="text-sm font-medium" { "Secret key" } input name="secret_key" type="password" placeholder=(s.secret_key_masked.clone().unwrap_or_else(|| "sk_live_…".into())) class=(dashboard_input()); }
                                        div class="space-y-2" { label class="text-sm font-medium" { "Webhook secret" } input name="webhook_secret" type="password" placeholder=(s.webhook_secret_masked.clone().unwrap_or_else(|| "whsec_…".into())) class=(dashboard_input()); }
                                        div class="space-y-2" { label class="text-sm font-medium" { "App tag" } input name="app_tag" value=(s.app_tag) class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Only Stripe products tagged with this value are shown below." } }
                                    }
                                },
                            ),
                            admin_block(
                                "Checkout",
                                Some("Where Stripe returns the customer after checkout, and the trial length."),
                                html! {
                                    div class="space-y-4" {
                                        div class="space-y-2" { label class="text-sm font-medium" { "Success URL" } input name="success_url" type="url" value=(s.success_url) placeholder="https://example.com/checkout/success" class=(dashboard_input()); }
                                        div class="space-y-2" { label class="text-sm font-medium" { "Cancel URL" } input name="cancel_url" type="url" value=(s.cancel_url) placeholder="https://example.com/pricing?checkout=canceled" class=(dashboard_input()); }
                                        div class="space-y-2" { label class="text-sm font-medium" { "Trial period (days)" } input name="trial_period_days" type="number" min="0" max="365" value=(s.trial_period_days) class=(dashboard_input()); }
                                    }
                                },
                            ),
                        ]))
                        button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    }
                    (stripe_products_block(products.as_deref()))
                    (stripe_prices_block(prices.as_deref(), products.as_deref().unwrap_or(&[])))
                    (stripe_catalog_section(tier.as_ref()))
                },
            }
        }
    };
    admin_response(&c, &user, "/admin/stripe", "Stripe · Bunyip", content)
}

#[derive(Deserialize)]
pub struct StripeProductForm {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// POST /admin/stripe/products - create a Stripe product, then redirect back.
pub async fn stripe_product_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<StripeProductForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = f.name.trim();
    if name.is_empty() {
        return redirect_cookies(
            "/admin/stripe?toast_err=Product%20name%20is%20required",
            &c.set_cookies,
        );
    }
    let mut body = json!({ "name": name });
    if !f.description.trim().is_empty() {
        body["description"] = json!(f.description.trim());
    }
    let target = match admin_api::create_stripe_product(&st.api, c.forward.as_deref(), body).await {
        Ok(()) => "/admin/stripe?toast_ok=Product%20created".to_string(),
        Err(e) => format!("/admin/stripe?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/stripe/products/{id}/archive
pub async fn stripe_product_archive(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::archive_stripe_product(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => "/admin/stripe?toast_ok=Product%20archived".to_string(),
        Err(e) => format!("/admin/stripe?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

#[derive(Deserialize)]
pub struct StripePriceForm {
    pub product_id: String,
    pub amount: String,
    pub currency: String,
    pub interval: String,
}

/// Parse a dollars-and-cents amount string into integer cents. Zero is allowed
/// (the lifetime-plan case); negatives and non-numbers are rejected. Pure so it
/// is unit-testable.
fn parse_price_cents(amount: &str) -> Result<i64, String> {
    match amount.trim().parse::<f64>() {
        Ok(a) if a >= 0.0 && a.is_finite() => Ok((a * 100.0).round() as i64),
        _ => Err("Amount must be a number of 0 or more.".to_string()),
    }
}

/// POST /admin/stripe/prices - create a Stripe price (dollars -> cents; 0 is a
/// valid lifetime price), then redirect back.
pub async fn stripe_price_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<StripePriceForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if f.product_id.trim().is_empty() {
        return redirect_cookies(
            "/admin/stripe?toast_err=Select%20a%20product",
            &c.set_cookies,
        );
    }
    let cents = match parse_price_cents(&f.amount) {
        Ok(v) => v,
        Err(msg) => {
            return redirect_cookies(
                &format!("/admin/stripe?toast_err={}", urlenc(&msg)),
                &c.set_cookies,
            )
        }
    };
    let body = json!({
        "product_id": f.product_id.trim(),
        "unit_amount": cents,
        "currency": f.currency.trim(),
        "interval": f.interval.trim(),
    });
    let target = match admin_api::create_stripe_price(&st.api, c.forward.as_deref(), body).await {
        Ok(()) => "/admin/stripe?toast_ok=Price%20created".to_string(),
        Err(e) => format!("/admin/stripe?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/stripe/prices/{id}/archive
pub async fn stripe_price_archive(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::archive_stripe_price(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => "/admin/stripe?toast_ok=Price%20archived".to_string(),
        Err(e) => format!("/admin/stripe?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// The tier -> Stripe catalog mapping form (BUNYIP-417). Same six price/product
/// ID fields the Tier Settings page used to carry; they persist to the tier
/// config via a partial update (blank = keep), so nothing is lost by the move.
#[derive(Deserialize)]
pub struct StripeCatalogForm {
    #[serde(default)]
    pub free_price_id: String,
    #[serde(default)]
    pub early_adopter_price_id: String,
    #[serde(default)]
    pub standard_price_id: String,
    #[serde(default)]
    pub lifetime_product_id: String,
    #[serde(default)]
    pub early_adopter_product_id: String,
    #[serde(default)]
    pub standard_product_id: String,
}

/// POST /admin/stripe/catalog - persist the tier -> Stripe price/product
/// mapping. Only non-blank, in-bounds (<=255) fields are sent, so an untouched
/// field keeps its stored value (matches the old Tier Settings behaviour).
pub async fn stripe_catalog_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<StripeCatalogForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut body = serde_json::Map::new();
    for (k, v) in [
        ("free_price_id", &f.free_price_id),
        ("early_adopter_price_id", &f.early_adopter_price_id),
        ("standard_price_id", &f.standard_price_id),
        ("lifetime_product_id", &f.lifetime_product_id),
        ("early_adopter_product_id", &f.early_adopter_product_id),
        ("standard_product_id", &f.standard_product_id),
    ] {
        let t = v.trim();
        if !t.is_empty() && t.len() <= 255 {
            body.insert(k.into(), json!(t));
        }
    }
    let target = match admin_api::update_tier_config(
        &st.api,
        c.forward.as_deref(),
        serde_json::Value::Object(body),
    )
    .await
    {
        Ok(()) => "/admin/stripe?toast_ok=Catalog%20mapping%20saved".to_string(),
        Err(e) => format!("/admin/stripe?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

#[derive(Deserialize)]
pub struct StripeForm {
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub webhook_secret: String,
    pub app_tag: String,
    #[serde(default)]
    pub success_url: String,
    #[serde(default)]
    pub cancel_url: String,
    #[serde(default)]
    pub trial_period_days: String,
}
pub async fn stripe_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<StripeForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // BUNYIP-117: validate at the edge. app_tag is bounded (200 chars
    // covers any sane Stripe metadata key); the two secrets are format-
    // checked against their Stripe-documented prefixes when present
    // (`sk_` / `rk_` for secret keys, `whsec_` for webhook secrets).
    // Empty inputs leave the persisted value untouched (the API treats
    // omission as "no change"). Replaces the prior `let _ = ...` that
    // swallowed API rejections so the operator now sees an inline error.
    use crate::handlers::validate;
    let render_error = |err: &str| -> Response { stripe_error_page(&c, &user, err) };
    let app_tag = match validate::trim_bounded_opt(&f.app_tag, "App tag", 200) {
        Ok(Some(t)) => t.to_string(),
        Ok(None) => String::new(),
        Err(msg) => return render_error(&msg),
    };
    let secret_key = f.secret_key.trim();
    if !secret_key.is_empty() {
        if !(secret_key.starts_with("sk_") || secret_key.starts_with("rk_")) {
            return render_error("Secret key must start with 'sk_' or 'rk_'");
        }
        if secret_key.len() > 255 {
            return render_error("Secret key must be 255 characters or fewer");
        }
    }
    let webhook_secret = f.webhook_secret.trim();
    if !webhook_secret.is_empty() {
        if !webhook_secret.starts_with("whsec_") {
            return render_error("Webhook secret must start with 'whsec_'");
        }
        if webhook_secret.len() > 255 {
            return render_error("Webhook secret must be 255 characters or fewer");
        }
    }
    // BUNYIP-351: checkout knobs. URLs are sent only when non-blank (blank =
    // keep existing); the trial length is validated to [0, 365] when present.
    let success_url = f.success_url.trim();
    let cancel_url = f.cancel_url.trim();
    let trial_days = match f.trial_period_days.trim() {
        "" => None,
        raw => match raw.parse::<i64>() {
            Ok(n) if (0..=365).contains(&n) => Some(n),
            _ => {
                return render_error(
                    "Trial period must be a whole number of days between 0 and 365",
                )
            }
        },
    };

    let mut body = json!({ "app_tag": app_tag });
    if !secret_key.is_empty() {
        body["secret_key"] = json!(secret_key);
    }
    if !webhook_secret.is_empty() {
        body["webhook_secret"] = json!(webhook_secret);
    }
    if !success_url.is_empty() {
        body["success_url"] = json!(success_url);
    }
    if !cancel_url.is_empty() {
        body["cancel_url"] = json!(cancel_url);
    }
    if let Some(days) = trial_days {
        body["trial_period_days"] = json!(days);
    }
    match admin_api::update_stripe_config(&st.api, c.forward.as_deref(), body).await {
        Ok(()) => redirect_cookies("/admin/stripe", &c.set_cookies),
        Err(e) => render_error(&e.user_message()),
    }
}

/// Re-render the Stripe settings page with the supplied inline error so a
/// failed save surfaces context instead of the prior silent 200 + redirect.
fn stripe_error_page(c: &AuthCtx, user: &User, err: &str) -> Response {
    // We deliberately do NOT re-fetch the upstream Stripe config here -
    // the failure path runs in a sync render context, mirroring the
    // posture other admin save handlers take for their error surface.
    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Stripe" } p class="mt-2 text-muted-foreground" { "Connect and configure Stripe billing." } }
            (error_box(err))
            p class="text-sm text-muted-foreground" { "Re-open the Stripe page to retry with the persisted values." }
            a href="/admin/stripe" class=(button_class("default", "default", "")) { "Back to Stripe" }
        }
    };
    admin_response(c, user, "/admin/stripe", "Stripe · Bunyip", content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_email_form() -> EmailSettingsForm {
        EmailSettingsForm {
            enabled: "false".into(),
            smtp_host: String::new(),
            smtp_port: String::new(),
            smtp_tls: "implicit".into(),
            smtp_username: String::new(),
            smtp_password: String::new(),
            from_email: String::new(),
            from_name: String::new(),
            admin_notification_emails: String::new(),
        }
    }

    #[test]
    fn email_body_always_sends_enabled_and_omits_blanks() {
        let mut f = blank_email_form();
        f.enabled = "true".into();
        f.smtp_host = "  smtp.example.com  ".into();
        f.smtp_port = "587".into();
        f.smtp_tls = "starttls".into();
        let body = email_update_body(&f).expect("valid");
        assert_eq!(body["enabled"], json!(true));
        assert_eq!(body["smtp_host"], json!("smtp.example.com")); // trimmed
        assert_eq!(body["smtp_port"], json!(587));
        assert_eq!(body["smtp_tls"], json!("starttls"));
        // Blank optional fields are omitted so the API keeps the existing value.
        assert!(body.get("smtp_username").is_none());
        assert!(body.get("smtp_password").is_none());
        assert!(body.get("from_email").is_none());
    }

    #[test]
    fn email_body_rejects_bad_port_and_email() {
        let mut f = blank_email_form();
        f.smtp_port = "70000".into();
        assert!(email_update_body(&f).is_err());

        let mut f = blank_email_form();
        f.from_email = "notanemail".into();
        assert!(email_update_body(&f).is_err());

        // enabled=false is still sent explicitly (the toggle works both ways).
        let body = email_update_body(&blank_email_form()).expect("valid");
        assert_eq!(body["enabled"], json!(false));
    }

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
        let body = create_app_body(&f).expect("create_app_body");
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
        let body = create_app_body(&f).expect("create_app_body");
        assert_eq!(body["forgejo_package"], json!("mokosh-cli"));
        assert_eq!(body["is_hosted"], json!(true));
    }

    #[test]
    fn create_body_rejects_junk_slug_and_oversize_name() {
        // BUNYIP-112: junk slug and over-length name surface as inline edge
        // errors, not raw 500s on a DB cap or silent acceptance.
        let mut f = CreateAppForm {
            name: "Mokosh".into(),
            slug: " $$$ ".into(),
            display_name: "Mokosh".into(),
            container_name: "mokosh".into(),
            ..Default::default()
        };
        assert!(create_app_body(&f).is_err());
        f.slug = "mokosh".into();
        f.name = "a".repeat(300);
        assert!(create_app_body(&f).is_err());
    }

    #[test]
    fn update_body_sends_detail_fields_trimmed_and_omits_empty() {
        // The descriptive fields are now editable from the admin form; set ones
        // are sent (trimmed) and blank ones are omitted so the backend keeps the
        // existing column value.
        let f = DistributionForm {
            description: "  A great app  ".into(),
            icon_url: "https://example.com/icon.png".into(),
            release_notes_url: "  https://dev.a8n.run/psa-systems/mokosh-server/releases  ".into(),
            maintenance_message: "Back at 5pm".into(),
            ..Default::default()
        };
        let body = distribution_update_body(&f);
        assert_eq!(body["description"], json!("A great app"));
        assert_eq!(body["icon_url"], json!("https://example.com/icon.png"));
        // BUNYIP-343: the release-notes URL is editable and sent trimmed.
        assert_eq!(
            body["release_notes_url"],
            json!("https://dev.a8n.run/psa-systems/mokosh-server/releases")
        );
        assert_eq!(body["maintenance_message"], json!("Back at 5pm"));
        assert!(body.get("subdomain").is_none());
        assert!(body.get("version").is_none());
        assert!(body.get("source_code_url").is_none());
    }

    #[test]
    fn create_body_sends_detail_fields() {
        let f = CreateAppForm {
            name: "Mokosh".into(),
            slug: "mokosh".into(),
            display_name: "Mokosh".into(),
            container_name: "mokosh".into(),
            description: "Identity platform".into(),
            version: "1.2.3".into(),
            source_code_url: "https://dev.a8n.run/psa-systems/mokosh".into(),
            ..Default::default()
        };
        let body = create_app_body(&f).expect("create_app_body");
        assert_eq!(body["description"], json!("Identity platform"));
        assert_eq!(body["version"], json!("1.2.3"));
        assert_eq!(
            body["source_code_url"],
            json!("https://dev.a8n.run/psa-systems/mokosh")
        );
        assert!(body.get("icon_url").is_none());
    }
}

#[cfg(test)]
mod error_log_tests {
    use super::log_row;
    use crate::api::types::AdminErrorLog;
    use std::collections::BTreeMap;

    fn entry() -> AdminErrorLog {
        let mut fields = BTreeMap::new();
        fields.insert("action".to_string(), "login".to_string());
        AdminErrorLog {
            timestamp: "2026-07-02T12:00:00Z".into(),
            level: "ERROR".into(),
            target: "bunyip_api::handlers".into(),
            message: "rate limit exceeded".into(),
            category: Some("rate_limit".into()),
            route: Some("/v1/auth/login".into()),
            client: Some("1.2.3.4".into()),
            fields,
        }
    }

    // BUNYIP-327 AC: an error event renders with its message, category and the
    // client it is attributable to, and is always tagged as an error.
    #[test]
    fn renders_message_category_client_and_fields() {
        let html = log_row(&entry()).into_string();
        assert!(html.contains("rate limit exceeded"), "message shown");
        assert!(html.contains("rate_limit"), "category shown");
        assert!(html.contains("1.2.3.4"), "client shown");
        assert!(html.contains("/v1/auth/login"), "route shown");
        assert!(html.contains("action=login"), "extra fields shown");
        assert!(html.contains("Error"), "tagged as an error");
    }
}

#[cfg(test)]
mod ip_ban_tests {
    use super::ip_ban_row;
    use crate::api::types::AdminIpBan;

    fn ban() -> AdminIpBan {
        AdminIpBan {
            ip: "203.0.113.7".into(),
            reason: "10 requests to suspicious paths in 60s".into(),
            strikes: 3,
            banned_at: "2026-07-03T11:00:00Z".into(),
            expires_at: "2026-07-03T12:00:00Z".into(),
        }
    }

    // BUNYIP-320 AC: a ban row shows the IP, reason and strike count, and
    // carries an Unban button that POSTs the IP to the lift endpoint.
    #[test]
    fn renders_ip_reason_strikes_and_unban_action() {
        let html = ip_ban_row(&ban()).into_string();
        assert!(html.contains("203.0.113.7"), "IP shown");
        assert!(
            html.contains("10 requests to suspicious paths in 60s"),
            "reason shown"
        );
        assert!(html.contains("3 strikes"), "strike count shown");
        assert!(html.contains("Unban"), "unban button present");
        assert!(
            html.contains(r#"action="/admin/ip-bans/unban""#),
            "unban form targets the lift endpoint"
        );
        assert!(
            html.contains(r#"name="ip" value="203.0.113.7""#),
            "ip carried in the form body"
        );
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use super::{fmt_retry_secs, rate_limit_row};
    use crate::api::types::AdminRateLimit;

    fn user_throttle() -> AdminRateLimit {
        AdminRateLimit {
            action: "login".into(),
            key: "user@example.com".into(),
            user_id: Some("11111111-1111-1111-1111-111111111111".into()),
            user_email: Some("user@example.com".into()),
            ip: None,
            count: 6,
            max_requests: 5,
            window_start: "2026-07-03T11:00:00Z".into(),
            retry_after: 125,
        }
    }

    fn ip_throttle() -> AdminRateLimit {
        AdminRateLimit {
            action: "registration".into(),
            key: "203.0.113.9".into(),
            user_id: None,
            user_email: None,
            ip: Some("203.0.113.9".into()),
            count: 3,
            max_requests: 3,
            window_start: "2026-07-03T11:00:00Z".into(),
            retry_after: 40,
        }
    }

    // BUNYIP-317 AC: a throttle row shows the subject, action, count/cap and a
    // Reset button that POSTs the (action, key) pair to the reset endpoint.
    #[test]
    fn renders_subject_action_countcap_and_reset_action() {
        let html = rate_limit_row(&user_throttle(), None).into_string();
        assert!(html.contains("user@example.com"), "subject email shown");
        assert!(html.contains("Login"), "action shown title-cased");
        assert!(html.contains("6/5"), "count vs cap shown");
        assert!(html.contains("retry in 2m 5s"), "retry-in shown");
        assert!(html.contains("Reset"), "reset button present");
        assert!(
            html.contains(r#"action="/admin/rate-limits/reset""#),
            "reset form targets the reset endpoint"
        );
        assert!(
            html.contains(r#"name="action" value="login""#),
            "action carried in the form body"
        );
        assert!(
            html.contains(r#"name="key" value="user@example.com""#),
            "key carried in the form body"
        );
        // No return context on the standalone list.
        assert!(
            !html.contains(r#"name="return_user""#),
            "list rows carry no return-user field"
        );
    }

    // On the user-detail page the row carries the return-user id so the reset
    // redirects back to that page.
    #[test]
    fn user_detail_row_carries_return_user() {
        let html = rate_limit_row(
            &user_throttle(),
            Some("11111111-1111-1111-1111-111111111111"),
        )
        .into_string();
        assert!(
            html.contains(r#"name="return_user" value="11111111-1111-1111-1111-111111111111""#),
            "return-user id carried so the reset redirects back to the user page"
        );
    }

    // An IP-keyed throttle exposes the IP as the subject and never a user.
    #[test]
    fn ip_keyed_row_shows_ip_subject() {
        let html = rate_limit_row(&ip_throttle(), None).into_string();
        assert!(html.contains("203.0.113.9"), "ip subject shown");
        assert!(html.contains("Registration"), "action shown title-cased");
        assert!(
            html.contains(r#"name="key" value="203.0.113.9""#),
            "ip key carried in the form body"
        );
    }

    #[test]
    fn retry_secs_formats_compactly() {
        assert_eq!(fmt_retry_secs(0), "any moment");
        assert_eq!(fmt_retry_secs(45), "45s");
        assert_eq!(fmt_retry_secs(60), "1m");
        assert_eq!(fmt_retry_secs(125), "2m 5s");
    }

    // -- BUNYIP-405: admin users list row --------------------------------------

    const ROW_UID: &str = "11111111-1111-1111-1111-111111111111";

    fn admin_user(email: &str, verified: bool, admin: bool) -> crate::api::types::AdminUser {
        serde_json::from_value(serde_json::json!({
            "id": ROW_UID,
            "email": email,
            "role": if admin { "admin" } else { "subscriber" },
            "email_verified": verified,
            "two_factor_enabled": false,
            "membership_status": "none",
            "subscription_tier": "standard",
            "lifetime_member": false,
            "created_at": "2026-01-01T00:00:00Z",
            "last_login_at": null,
            "grace_period_end": null,
        }))
        .expect("valid admin user json")
    }

    /// A suspended `AdminUser` (soft-deleted) built off the standard fixture.
    fn suspended_admin_user(email: &str) -> crate::api::types::AdminUser {
        let mut u = admin_user(email, true, false);
        u.suspended = true;
        u
    }

    #[test]
    fn active_user_row_links_to_detail_with_no_inline_actions() {
        let html = super::user_grid_row(&admin_user("ada@example.com", true, false)).into_string();
        // The whole row is a link into the per-user detail view.
        assert!(
            html.contains(&format!(r#"href="/admin/users/{ROW_UID}""#)),
            "active row links to the detail view"
        );
        assert!(html.contains("Verified"), "verified indicator shown");
        // Every management action lives on the detail view (BUNYIP-405): the list
        // row carries none of them, and no forms at all.
        for action in [
            "/role",
            "/reset-password",
            "/suspend",
            "/delete",
            "/lifetime",
            "/entitlements",
        ] {
            assert!(
                !html.contains(action),
                "active list row must not carry the {action} action"
            );
        }
        assert!(!html.contains("<form"), "active list row carries no forms");
    }

    #[test]
    fn unverified_user_row_shows_unverified_status() {
        let html = super::user_grid_row(&admin_user("new@example.com", false, false)).into_string();
        assert!(html.contains("Unverified"), "unverified status shown");
        assert!(!html.contains(">Verified<"));
    }

    #[test]
    fn suspended_user_row_keeps_reactivate_and_is_not_a_link() {
        let html = super::user_grid_row(&suspended_admin_user("gone@example.com")).into_string();
        assert!(
            html.contains(&format!(r#"action="/admin/users/{ROW_UID}/reactivate""#)),
            "suspended row keeps the inline Reactivate action"
        );
        assert!(html.contains("Suspended"), "suspended badge shown");
        // The detail view 404s for a soft-deleted user, so the suspended row is
        // intentionally not a link into it.
        assert!(
            !html.contains(&format!(r#"href="/admin/users/{ROW_UID}""#)),
            "suspended row is not a detail link"
        );
    }

    // -- BUNYIP-410: users + memberships consolidation --------------------------

    #[test]
    fn user_row_shows_membership_tier() {
        // The row carries the membership tier badge (the builder seeds "standard")
        // alongside the verification indicator.
        let html = super::user_grid_row(&admin_user("ada@example.com", true, false)).into_string();
        assert!(html.contains("Standard"), "tier badge shown on the row");
        assert!(html.contains("Verified"));
    }

    fn q(status: &str, tier: &str, verified: &str, search: &str) -> super::UsersQ {
        super::UsersQ::from_query(super::UserQuery {
            page: None,
            search: (!search.is_empty()).then(|| search.to_string()),
            status: (!status.is_empty()).then(|| status.to_string()),
            tier: (!tier.is_empty()).then(|| tier.to_string()),
            verified: (!verified.is_empty()).then(|| verified.to_string()),
            sort: None,
            dir: None,
            page_size: None,
        })
    }

    #[test]
    fn usersq_href_emits_only_nondefault_params() {
        // A clean, default state is a clean URL.
        assert_eq!(q("", "", "", "").href(), "/admin/users");
        // Filters appear; the default `active` status does not.
        let href = q("all", "lifetime", "verified", "ada").href();
        assert!(href.contains("status=all"));
        assert!(href.contains("tier=lifetime"));
        assert!(href.contains("verified=verified"));
        assert!(href.contains("search=ada"));
        // Default status is omitted.
        assert!(!q("active", "", "", "").href().contains("status="));
    }

    #[test]
    fn usersq_sort_toggles_then_switches_columns() {
        let base = q("", "", "", "");
        // First click on a column sorts ascending.
        let asc = base.with_sort("email");
        assert_eq!((asc.sort.as_str(), asc.dir.as_str()), ("email", "asc"));
        // Clicking the same column again flips to descending.
        let desc = asc.with_sort("email");
        assert_eq!(desc.dir, "desc");
        // Clicking a different column restarts ascending.
        let other = desc.with_sort("joined");
        assert_eq!((other.sort.as_str(), other.dir.as_str()), ("joined", "asc"));
    }

    #[test]
    fn usersq_is_filtered_only_when_narrowed() {
        assert!(!q("active", "", "", "").is_filtered(), "plain active view");
        assert!(q("all", "", "", "").is_filtered(), "non-default status");
        assert!(q("active", "lifetime", "", "").is_filtered(), "tier filter");
        assert!(
            q("active", "", "verified", "").is_filtered(),
            "verified filter"
        );
        assert!(q("active", "", "", "ada").is_filtered(), "search");
    }

    #[test]
    fn usersq_filter_change_resets_page() {
        let mut on_page_3 = q("", "", "", "");
        on_page_3.page = 3;
        assert_eq!(on_page_3.with_tier("lifetime").page, 1);
        assert_eq!(on_page_3.with_status("all").page, 1);
        assert_eq!(on_page_3.with_search("x").page, 1);
        // Paging itself does not reset the page.
        assert_eq!(on_page_3.with_page(4).page, 4);
    }

    #[test]
    fn users_panel_shows_count_filter_bar_and_sortable_headers() {
        let panel =
            super::users_panel(&q("active", "lifetime", "", ""), None, Some(13)).into_string();
        // Panel is the htmx swap target.
        assert!(panel.contains(r#"id="users-panel""#));
        // Segmented control + sortable headers present.
        assert!(panel.contains(r#"role="radiogroup""#));
        assert!(panel.contains("data-sort-header"));
        // An active tier filter renders a removable chip + Clear all.
        assert!(panel.contains("Tier: Lifetime"));
        assert!(panel.contains("Clear all"));
    }

    #[test]
    fn verified_filter_parses_tri_state() {
        assert_eq!(super::parse_verified_filter("verified"), Some(true));
        assert_eq!(super::parse_verified_filter("unverified"), Some(false));
        // Blank / absent / junk = no filter (both verified and unverified).
        assert_eq!(super::parse_verified_filter(""), None);
        assert_eq!(super::parse_verified_filter("anything"), None);
    }

    #[test]
    fn tier_label_maps_every_tier() {
        use crate::api::types::SubscriptionTier::*;
        assert_eq!(super::tier_label(&Lifetime), "Lifetime");
        assert_eq!(super::tier_label(&Free), "Free");
        assert_eq!(super::tier_label(&EarlyAdopter), "Early Adopter");
        assert_eq!(super::tier_label(&Standard), "Standard");
    }

    #[tokio::test]
    async fn memberships_redirects_to_filtered_users() {
        use axum::extract::Query;
        use axum::http::header::LOCATION;

        let loc = |resp: axum::response::Response| {
            assert!(resp.status().is_redirection(), "must be a redirect");
            resp.headers()
                .get(LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };

        // No tier -> the plain users list.
        let r = super::memberships(Query(super::PageQuery {
            page: None,
            tier: None,
        }))
        .await;
        assert_eq!(loc(r), "/admin/users");

        // A known tier is preserved as the users-list filter.
        let r = super::memberships(Query(super::PageQuery {
            page: None,
            tier: Some("lifetime".into()),
        }))
        .await;
        assert_eq!(loc(r), "/admin/users?tier=lifetime");

        // A junk tier falls back to the unfiltered list (matches the old page).
        let r = super::memberships(Query(super::PageQuery {
            page: None,
            tier: Some("not-a-tier".into()),
        }))
        .await;
        assert_eq!(loc(r), "/admin/users");
    }

    // -- BUNYIP-422: feedback list row + detail actions ------------------------

    const FB_ID: &str = "22222222-2222-2222-2222-222222222222";

    fn feedback_summary(status: &str) -> crate::api::types::AdminFeedbackSummary {
        serde_json::from_value(serde_json::json!({
            "id": FB_ID,
            "name": "Ada Lovelace",
            "email_masked": "a***@example.com",
            "subject": "A bug report",
            "message_excerpt": "Something went wrong when I clicked save.",
            "status": status,
            "created_at": "2026-01-01T00:00:00Z",
        }))
        .expect("feedback summary fixture")
    }

    #[test]
    fn feedback_row_links_to_detail_with_no_inline_actions() {
        let html =
            super::feedback_row(&feedback_summary("new"), super::FeedbackTab::Active).into_string();
        // The whole row is a link into the detail view, carrying the tab slug.
        assert!(
            html.contains(&format!(r#"href="/admin/feedback/{FB_ID}?from=active""#)),
            "row links to the detail view with the tab slug"
        );
        // Status chip is shown; the summary content is present.
        assert!(html.contains("New"), "status chip rendered");
        assert!(html.contains("A bug report"), "subject shown");
        // Every triage action lives on the detail view now: the list row
        // carries no forms and none of the action endpoints.
        assert!(!html.contains("<form"), "list row carries no forms");
        for action in [
            "/status",
            "/mark-spam",
            "/unmark-spam",
            "/archive",
            "/delete",
        ] {
            assert!(
                !html.contains(action),
                "list row must not carry the {action} action"
            );
        }
    }

    #[test]
    fn feedback_row_carries_originating_tab_slug() {
        let html =
            super::feedback_row(&feedback_summary("new"), super::FeedbackTab::Spam).into_string();
        assert!(
            html.contains(&format!(r#"href="/admin/feedback/{FB_ID}?from=spam""#)),
            "row from the Spam tab links back with ?from=spam"
        );
    }

    #[test]
    fn feedback_detail_actions_are_tab_aware() {
        use crate::api::types::FeedbackStatus;
        // Active: review + close + archive + spam + delete, all redirecting home.
        let active =
            super::feedback_detail_actions(FB_ID, &FeedbackStatus::New, super::FeedbackTab::Active)
                .into_string();
        assert!(active.contains(&format!(r#"action="/admin/feedback/{FB_ID}/status""#)));
        assert!(active.contains(&format!(r#"action="/admin/feedback/{FB_ID}/mark-spam""#)));
        assert!(active.contains(&format!(r#"action="/admin/feedback/{FB_ID}/delete""#)));
        assert!(active.contains("Close"));
        assert!(active.contains(r#"name="from" value="active""#));

        // A reviewed item offers Un-review rather than Reviewed.
        let reviewed = super::feedback_detail_actions(
            FB_ID,
            &FeedbackStatus::Reviewed,
            super::FeedbackTab::Active,
        )
        .into_string();
        assert!(reviewed.contains("Un-review"));

        // Spam tab: Not spam + archive + delete, redirecting back to Spam.
        let spam =
            super::feedback_detail_actions(FB_ID, &FeedbackStatus::New, super::FeedbackTab::Spam)
                .into_string();
        assert!(spam.contains("Not spam"));
        assert!(spam.contains(&format!(r#"action="/admin/feedback/{FB_ID}/unmark-spam""#)));
        assert!(spam.contains(r#"name="from" value="spam""#));
        assert!(!spam.contains("Close"), "spam tab has no Close action");

        // Closed tab: Re-open, redirecting back to Closed.
        let closed = super::feedback_detail_actions(
            FB_ID,
            &FeedbackStatus::Closed,
            super::FeedbackTab::Closed,
        )
        .into_string();
        assert!(closed.contains("Re-open"));
        assert!(closed.contains(r#"name="from" value="closed""#));
    }

    #[test]
    fn feedback_tab_from_query_round_trips() {
        for (slug, tab) in [
            ("active", super::FeedbackTab::Active),
            ("closed", super::FeedbackTab::Closed),
            ("spam", super::FeedbackTab::Spam),
            ("archive", super::FeedbackTab::Archive),
        ] {
            assert_eq!(super::FeedbackTab::from_query(Some(slug)), tab);
            assert_eq!(tab.query_slug(), slug);
        }
        // Absent / unknown falls back to Active.
        assert_eq!(
            super::FeedbackTab::from_query(None),
            super::FeedbackTab::Active
        );
        assert_eq!(
            super::FeedbackTab::from_query(Some("junk")),
            super::FeedbackTab::Active
        );
    }
}

// --- application documentation (BUNYIP-388) ---------------------------------

/// Add/edit form fields for one documentation page.
#[derive(Debug, Deserialize)]
pub struct DocForm {
    pub slug: String,
    pub title: String,
    pub body: String,
    // Parsed with `validate::parse_i32` (empty -> 0, non-numeric -> handled),
    // not deserialized as i32, so a cleared number input does not 400 the form.
    #[serde(default)]
    pub sort_order: String,
}

/// GET /admin/applications/{id}/docs - manage an app's documentation pages.
pub async fn application_docs(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let app_name = match admin_api::applications(&st.api, c.forward.as_deref()).await {
        Ok(apps) => apps
            .iter()
            .find(|a| a.id == id)
            .map(|a| a.display_name.clone())
            .unwrap_or_else(|| id.clone()),
        Err(e) => {
            let content = html! {
                div class="space-y-6" {
                    h1 class="text-3xl font-bold" { "Manage documentation" }
                    (error_box(&e.user_message()))
                }
            };
            return admin_response(
                &c,
                &user,
                "/admin/applications",
                "Manage documentation · Bunyip",
                content,
            );
        }
    };
    let docs = admin_api::app_docs(&st.api, c.forward.as_deref(), &id)
        .await
        .unwrap_or_default();
    let content = html! {
        div class="space-y-8" {
            div {
                a class="text-sm text-muted-foreground hover:underline" href="/admin/applications" { "← Applications" }
                h1 class="text-3xl font-bold mt-2" { "Documentation: " (app_name) }
                p class="text-muted-foreground" { "Public pages, rendered as markdown (raw HTML is stripped). Lower sort order shows first." }
            }
            div class="space-y-6" {
                @if docs.is_empty() {
                    p class="text-muted-foreground" { "No pages yet. Add one below." }
                }
                @for d in &docs {
                    div class="rounded-lg border p-4 space-y-3" {
                        form method="post" action=(format!("/admin/applications/{id}/docs/{}", d.id)) class="space-y-3" {
                            div class="grid gap-3 md:grid-cols-3" {
                                label class="text-sm block" { "Title" input class="mt-1 w-full rounded border px-2 py-1" name="title" value=(d.title) required; }
                                label class="text-sm block" { "Slug" input class="mt-1 w-full rounded border px-2 py-1" name="slug" value=(d.slug) required; }
                                label class="text-sm block" { "Sort order" input type="number" class="mt-1 w-full rounded border px-2 py-1" name="sort_order" value=(d.sort_order); }
                            }
                            label class="text-sm block" { "Body (markdown)" textarea class="mt-1 w-full rounded border px-2 py-1 font-mono text-sm" name="body" rows="10" { (d.body) } }
                            button type="submit" class=(button_class("default", "sm", "")) { "Save" }
                        }
                        form method="post" action=(format!("/admin/applications/{id}/docs/{}/delete", d.id)) data-confirm="Delete this documentation entry? This cannot be undone." {
                            button type="submit" class=(button_class("destructive", "sm", "")) { "Delete" }
                        }
                    }
                }
            }
            div class="rounded-lg border p-4 space-y-3" {
                h2 class="text-xl font-semibold" { "Add a page" }
                form method="post" action=(format!("/admin/applications/{id}/docs")) class="space-y-3" {
                    div class="grid gap-3 md:grid-cols-3" {
                        label class="text-sm block" { "Title" input class="mt-1 w-full rounded border px-2 py-1" name="title" required; }
                        label class="text-sm block" { "Slug" input class="mt-1 w-full rounded border px-2 py-1" name="slug" placeholder="getting-started" required; }
                        label class="text-sm block" { "Sort order" input type="number" class="mt-1 w-full rounded border px-2 py-1" name="sort_order" value="0"; }
                    }
                    label class="text-sm block" { "Body (markdown)" textarea class="mt-1 w-full rounded border px-2 py-1 font-mono text-sm" name="body" rows="10" {} }
                    button type="submit" class=(button_class("default", "sm", "")) { "Add page" }
                }
            }
        }
    };
    admin_response(
        &c,
        &user,
        "/admin/applications",
        "Manage documentation · Bunyip",
        content,
    )
}

/// POST /admin/applications/{id}/docs - create a page, then back to the manager.
pub async fn application_doc_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<DocForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let sort_order = crate::handlers::validate::parse_i32(&f.sort_order, "Sort order").unwrap_or(0);
    let target = match admin_api::create_app_doc(
        &st.api,
        c.forward.as_deref(),
        &id,
        &f.slug,
        &f.title,
        &f.body,
        sort_order,
    )
    .await
    {
        Ok(_) => format!("/admin/applications/{id}/docs"),
        Err(e) => {
            tracing::warn!(app_id = %id, slug = %f.slug, error = ?e, "admin create app doc failed");
            format!(
                "/admin/applications/{id}/docs?toast_err={}",
                urlenc("Could not create documentation page")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/applications/{id}/docs/{doc_id} - update a page.
pub async fn application_doc_update(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((id, doc_id)): Path<(String, String)>,
    Form(f): Form<DocForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let sort_order = crate::handlers::validate::parse_i32(&f.sort_order, "Sort order").unwrap_or(0);
    let target = match admin_api::update_app_doc(
        &st.api,
        c.forward.as_deref(),
        &doc_id,
        &f.slug,
        &f.title,
        &f.body,
        sort_order,
    )
    .await
    {
        Ok(_) => format!("/admin/applications/{id}/docs"),
        Err(e) => {
            tracing::warn!(app_id = %id, doc_id = %doc_id, error = ?e, "admin update app doc failed");
            format!(
                "/admin/applications/{id}/docs?toast_err={}",
                urlenc("Could not update documentation page")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/applications/{id}/docs/{doc_id}/delete - delete a page.
pub async fn application_doc_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((id, doc_id)): Path<(String, String)>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::delete_app_doc(&st.api, c.forward.as_deref(), &doc_id).await {
        Ok(_) => format!("/admin/applications/{id}/docs"),
        Err(e) => {
            tracing::warn!(app_id = %id, doc_id = %doc_id, error = ?e, "admin delete app doc failed");
            format!(
                "/admin/applications/{id}/docs?toast_err={}",
                urlenc("Could not delete documentation page")
            )
        }
    };
    redirect_cookies(&target, &c.set_cookies)
}

#[cfg(test)]
mod two_column_layout_tests {
    // BUNYIP-415: the SSR analog of a wide/narrow visual-regression check is to
    // assert the responsive two-column grid class (two columns at `lg`, one
    // below) is present and that no fields were dropped when regrouping into
    // blocks. The list-screen conversions (rate limits, IP bans, entitlements)
    // reuse the same `lg:grid-cols-2` wrapper and are verified via screenshots.
    use super::*;

    #[test]
    fn admin_block_grid_is_responsive_two_column() {
        let grid = admin_block_grid(vec![
            admin_block("Alpha", None, maud::html! { "a" }),
            admin_block("Beta", Some("sub"), maud::html! { "b" }),
        ])
        .into_string();
        assert!(grid.contains("grid"));
        assert!(
            grid.contains("lg:grid-cols-2"),
            "two columns at lg, one below"
        );
        assert!(
            grid.contains(">Alpha<") && grid.contains(">Beta<"),
            "both block titles present"
        );
        assert!(grid.contains("sub"), "subtitle rendered when provided");
    }

    fn email_cfg() -> crate::api::types::EmailConfigResponse {
        serde_json::from_value(json!({
            "enabled": true, "smtp_host": "smtp.example.com", "smtp_port": 587,
            "smtp_tls": "starttls", "smtp_username": "u", "has_smtp_password": true,
            "from_email": "no-reply@example.com",
            "from_name": "Bunyip", "admin_notification_emails": ["ops@example.com"],
            "source": "environment"
        }))
        .unwrap()
    }

    #[test]
    fn smtp_password_field_is_a_fixed_mask_never_the_secret() {
        // BUNYIP-432: the field is write-only. When a password is set the
        // placeholder is a fixed-length mask (no last-4, no length hint); the
        // real value is not in the type or the markup at all.
        let html = email_settings_content(Some(&email_cfg())).into_string();
        assert!(
            html.contains(r#"placeholder="••••••••""#),
            "a fixed-length mask is shown when a password is set: {html}"
        );
        assert!(
            !html.contains("****") && !html.contains("(unchanged)"),
            "no masked/last-4 or old placeholder leaks into the page"
        );
        // The empty-password variant shows a distinct, non-secret placeholder.
        let mut none = email_cfg();
        none.has_smtp_password = false;
        let html_none = email_settings_content(Some(&none)).into_string();
        assert!(html_none.contains(r#"placeholder="Not set""#));
    }

    #[test]
    fn email_screen_uses_two_column_blocks() {
        let html = email_settings_content(Some(&email_cfg())).into_string();
        assert!(
            html.contains("lg:grid-cols-2"),
            "email settings render as a responsive two-column grid"
        );
        assert!(html.contains("SMTP Connection") && html.contains("Notifications"));
        for f in [
            "smtp_host",
            "smtp_port",
            "from_email",
            "admin_notification_emails",
        ] {
            assert!(html.contains(f), "field {f} preserved after regrouping");
        }
    }

    /// BUNYIP-433: the email page carries a Test connection control that POSTs to
    /// its own endpoint (a separate form from Save, so it tests saved settings).
    #[test]
    fn email_screen_has_test_connection_button() {
        let html = email_settings_content(Some(&email_cfg())).into_string();
        assert!(
            html.contains(r#"action="/admin/email/test""#),
            "Test connection posts to /admin/email/test"
        );
        assert!(html.contains("Test connection"), "button label present");
        // Distinct from the Save form so it submits no unsaved fields.
        assert!(
            html.matches("<form").count() >= 2,
            "test control is its own form, separate from Save"
        );
    }

    fn auto_ban_cfg() -> crate::api::types::AutoBanConfigResponse {
        serde_json::from_value(json!({
            "enabled": true, "threshold": 10, "window_secs": 60,
            "ban_duration_secs": 3600, "source": "database"
        }))
        .unwrap()
    }

    #[test]
    fn auto_ban_screen_uses_two_column_blocks() {
        let cfg = auto_ban_cfg();
        let vals = AutoBanFormValues::from_config(&cfg);
        let html = auto_ban_settings_content(Some(&cfg), &vals, None).into_string();
        assert!(html.contains("lg:grid-cols-2"));
        assert!(html.contains("Detection") && html.contains("Enforcement"));
        for f in ["threshold", "window_secs", "ban_duration_secs"] {
            assert!(html.contains(f), "field {f} preserved after regrouping");
        }
    }

    fn tier_cfg() -> crate::api::types::TierConfigResponse {
        serde_json::from_value(json!({
            "lifetime_slots": 5, "early_adopter_slots": 5, "early_adopter_trial_days": 90,
            "standard_trial_days": 30, "free_price_id": null, "early_adopter_price_id": null,
            "standard_price_id": null, "source": "database",
            "lifetime_slots_used": 2, "early_adopter_slots_used": 1
        }))
        .unwrap()
    }

    #[test]
    fn tier_settings_shows_slots_and_no_stripe_catalog() {
        // BUNYIP-417: the Stripe catalog mapping moved to the Stripe page, so
        // Tier Settings keeps only slots + trial days and carries none of the
        // price/product-ID fields.
        let vals = TierFormValues {
            lifetime_slots: "5".into(),
            early_adopter_slots: "5".into(),
            early_adopter_trial_days: "90".into(),
            standard_trial_days: "30".into(),
            free_price_id: String::new(),
            early_adopter_price_id: String::new(),
            standard_price_id: String::new(),
            lifetime_product_id: String::new(),
            early_adopter_product_id: String::new(),
            standard_product_id: String::new(),
        };
        let html = tier_settings_content(Some(&tier_cfg()), &vals, None).into_string();
        for f in [
            "lifetime_slots",
            "early_adopter_slots",
            "standard_trial_days",
        ] {
            assert!(html.contains(f), "slots/trials field {f} present");
        }
        assert!(
            !html.contains("Stripe catalog"),
            "catalog blocks moved to the Stripe page"
        );
        for f in [
            "free_price_id",
            "standard_product_id",
            "early_adopter_price_id",
        ] {
            assert!(
                !html.contains(f),
                "catalog field {f} no longer on Tier Settings"
            );
        }
        // It links to where the mapping now lives.
        assert!(html.contains(r#"href="/admin/stripe""#));
    }
}

#[cfg(test)]
mod stripe_admin_tests {
    // BUNYIP-416: unit coverage for the ported Products/Prices sections. The
    // live product/price listing is exercised against Stripe by the bunyip-api
    // integration tests (this port calls those existing endpoints); here we
    // cover the rendering + the dollars->cents parsing, including the $0.00
    // lifetime-price case that must render as a real price, not "--".
    use super::{
        format_stripe_amount, parse_price_cents, stripe_prices_block, stripe_products_block,
    };
    use crate::api::types::{StripePrice, StripeProduct};

    fn product(id: &str, name: &str, active: bool) -> StripeProduct {
        StripeProduct {
            id: id.into(),
            name: name.into(),
            description: Some("desc".into()),
            active,
            created: 0,
        }
    }
    fn price(id: &str, product_id: &str, amount: Option<i64>, active: bool) -> StripePrice {
        StripePrice {
            id: id.into(),
            product_id: product_id.into(),
            unit_amount: amount,
            currency: "usd".into(),
            recurring_interval: Some("month".into()),
            active,
        }
    }

    #[test]
    fn format_stripe_amount_handles_zero_and_null() {
        assert_eq!(format_stripe_amount(Some(0), "usd"), "$0.00");
        assert_eq!(format_stripe_amount(Some(999), "usd"), "$9.99");
        assert_eq!(format_stripe_amount(Some(1000), "eur"), "€10.00");
        assert_eq!(format_stripe_amount(Some(500), "gbp"), "£5.00");
        assert_eq!(format_stripe_amount(Some(1234), "aud"), "12.34 AUD");
        assert_eq!(format_stripe_amount(None, "usd"), "--");
    }

    #[test]
    fn parse_price_cents_allows_zero_rejects_bad() {
        assert_eq!(parse_price_cents("0"), Ok(0)); // lifetime plan
        assert_eq!(parse_price_cents("9.99"), Ok(999));
        assert_eq!(parse_price_cents(" 10 "), Ok(1000));
        assert!(parse_price_cents("-1").is_err());
        assert!(parse_price_cents("").is_err());
        assert!(parse_price_cents("abc").is_err());
    }

    #[test]
    fn products_block_lists_and_gates_archive() {
        let list = [
            product("prod_a", "Personal Plan", true),
            product("prod_b", "Old Plan", false),
        ];
        let html = stripe_products_block(Some(&list)).into_string();
        assert!(html.contains("Personal Plan") && html.contains("Old Plan"));
        assert!(html.contains(">Active<") && html.contains(">Archived<"));
        // Create form present; archive only for the active product.
        assert!(html.contains(r#"action="/admin/stripe/products""#));
        assert!(html.contains(r#"action="/admin/stripe/products/prod_a/archive""#));
        assert!(
            !html.contains("prod_b/archive"),
            "archived product has no Archive action"
        );
    }

    #[test]
    fn products_block_renders_load_error_state() {
        let html = stripe_products_block(None).into_string();
        assert!(html.contains("Could not load products"));
    }

    #[test]
    fn prices_block_shows_zero_price_and_resolves_product_name() {
        let products = [product("prod_life", "Lifetime", true)];
        let prices = [price("price_free", "prod_life", Some(0), true)];
        let html = stripe_prices_block(Some(&prices), &products).into_string();
        assert!(
            html.contains("$0.00"),
            "zero lifetime price renders as $0.00, not --"
        );
        assert!(html.contains("Lifetime"), "product name resolved from id");
        assert!(
            html.contains(r#"action="/admin/stripe/prices""#),
            "create form present"
        );
        assert!(html.contains(r#"action="/admin/stripe/prices/price_free/archive""#));
    }

    #[test]
    fn catalog_section_renders_mapping_fields_prefilled() {
        // BUNYIP-417: the tier -> Stripe catalog mapping now lives on the Stripe
        // page, its own form posting to /admin/stripe/catalog, prefilled from the
        // tier config.
        let tier: crate::api::types::TierConfigResponse =
            serde_json::from_value(serde_json::json!({
                "lifetime_slots": 5, "early_adopter_slots": 5, "early_adopter_trial_days": 90,
                "standard_trial_days": 30,
                "free_price_id": "price_free123", "early_adopter_price_id": null,
                "standard_price_id": null, "lifetime_product_id": "prod_life123",
                "source": "database", "lifetime_slots_used": 0, "early_adopter_slots_used": 0
            }))
            .unwrap();
        let html = super::stripe_catalog_section(Some(&tier)).into_string();
        assert!(
            html.contains(r#"action="/admin/stripe/catalog""#),
            "catalog form present"
        );
        for f in ["free_price_id", "lifetime_product_id", "standard_price_id"] {
            assert!(html.contains(f), "mapping field {f} present");
        }
        // Existing values are prefilled.
        assert!(html.contains("price_free123") && html.contains("prod_life123"));
        // Load-error state when the tier config is unavailable.
        assert!(super::stripe_catalog_section(None)
            .into_string()
            .contains("Could not load the tier catalog mapping"));
    }
}

/// BUNYIP-421: the users-list identity cell must ellipsise a long email without
/// clipping the role/status badges that sit beside it.
#[cfg(test)]
mod identity_cell_clipping_tests {
    use crate::api::types::{AdminUser, MembershipStatus, SubscriptionTier, UserRole};
    use crate::views::ui::assert_no_truncating_flex_container;

    fn user(role: UserRole, suspended: bool) -> AdminUser {
        AdminUser {
            id: "u1".into(),
            email: "person.with.a.very.long.email.address@example.com".into(),
            role,
            email_verified: true,
            two_factor_enabled: false,
            membership_status: MembershipStatus::Active,
            subscription_tier: SubscriptionTier::EarlyAdopter,
            lifetime_member: false,
            created_at: "2026-03-04T10:00:00Z".into(),
            last_login_at: None,
            grace_period_end: None,
            suspended,
        }
    }

    #[test]
    fn badges_survive_a_long_email() {
        let row = super::user_grid_row(&user(UserRole::Admin, false)).into_string();
        // The clip was invisible in the markup: the badge WAS emitted, the row's
        // own `overflow:hidden` just painted none of it. Guard the CSS shape.
        assert_no_truncating_flex_container(&row);
        assert!(row.contains(">Admin<"), "admin badge is rendered");
        assert!(
            row.contains(
                r#"<span class="truncate">person.with.a.very.long.email.address@example.com</span>"#
            ),
            "the email, not the row, is what truncates: {row}"
        );

        let suspended = super::user_grid_row(&user(UserRole::Subscriber, true)).into_string();
        assert_no_truncating_flex_container(&suspended);
        assert!(
            suspended.contains(">Suspended<"),
            "suspended badge is rendered"
        );
    }
}

#[cfg(test)]
mod admin_action_confirm_tests {
    //! BUNYIP-430: every significant admin control routes through the one shared
    //! confirmation dialog (`data-confirm` + `assets/js/app.js`, which prompts
    //! on submit and cancels the POST when the admin declines), and each prompt
    //! names the action and the specific user (by email) it affects.
    use super::user_actions_card;
    use crate::api::types::{AdminUser, MembershipStatus, SubscriptionTier, UserRole};

    const UID: &str = "22222222-2222-2222-2222-222222222222";

    fn target(email: &str, lifetime_member: bool) -> AdminUser {
        AdminUser {
            id: UID.into(),
            email: email.into(),
            role: UserRole::Subscriber,
            email_verified: true,
            two_factor_enabled: false,
            membership_status: MembershipStatus::None,
            subscription_tier: SubscriptionTier::Free,
            lifetime_member,
            created_at: String::new(),
            last_login_at: None,
            grace_period_end: None,
            suspended: false,
        }
    }

    // BUNYIP-431 replaced the Grant/Revoke lifetime buttons in this card with the
    // 2FA-gated tier selector (`tier_change_card`, covered in `tier_change_tests`),
    // so the lifetime-specific confirm tests moved out with them.

    #[test]
    fn reset_password_confirms_and_names_the_user() {
        let html = user_actions_card(&target("jane@example.com", false), false).into_string();
        assert!(
            html.contains("Send a password reset email to jane@example.com?"),
            "reset-password confirms and names the user: {html}"
        );
    }

    #[test]
    fn role_change_shares_the_component_and_names_the_user() {
        // BUNYIP-109 control (Make Admin / Demote) now routes through the same
        // shared dialog and names the user, per BUNYIP-430 AC 3.
        let html = user_actions_card(&target("jane@example.com", false), false).into_string();
        assert!(
            html.contains("Change jane@example.com's role to admin?")
                || html.contains("Change jane@example.com&#39;s role to admin?"),
            "role change confirms and names the user: {html}"
        );
    }

    #[test]
    fn every_action_form_is_gated_by_the_shared_confirm() {
        // Cancelling the shared dialog (app.js) blocks the POST, so state is left
        // unchanged (AC 5). Guard that no state-changing control in the card
        // ships without data-confirm, for a lifetime and a non-lifetime user.
        for lifetime in [false, true] {
            let html = user_actions_card(&target("jane@example.com", lifetime), true).into_string();
            let forms = html.matches("<form").count();
            let confirms = html.matches("data-confirm=").count();
            assert!(
                forms > 0 && forms == confirms,
                "every action form ({forms}) carries data-confirm ({confirms}): {html}"
            );
        }
    }
}

#[cfg(test)]
mod tier_change_tests {
    //! BUNYIP-431: the tier selector offers every configured tier regardless of
    //! the member's current tier (any-to-any), and applying a change requires
    //! the acting admin's 2FA code.
    use super::tier_change_card;
    use crate::api::types::{AdminUser, MembershipStatus, SubscriptionTier, UserRole};

    const UID: &str = "33333333-3333-3333-3333-333333333333";

    fn target(tier: SubscriptionTier) -> AdminUser {
        AdminUser {
            id: UID.into(),
            email: "jane@example.com".into(),
            role: UserRole::Subscriber,
            email_verified: true,
            two_factor_enabled: false,
            membership_status: MembershipStatus::None,
            subscription_tier: tier,
            lifetime_member: false,
            created_at: String::new(),
            last_login_at: None,
            grace_period_end: None,
            suspended: false,
        }
    }

    #[test]
    fn offers_every_tier_regardless_of_current() {
        // AC3: the options do not vary with the member's current tier - whatever
        // they hold, all four destinations are offered (including downgrades).
        for current in [
            SubscriptionTier::Lifetime,
            SubscriptionTier::EarlyAdopter,
            SubscriptionTier::Standard,
            SubscriptionTier::Free,
        ] {
            let html = tier_change_card(&target(current)).into_string();
            for value in ["lifetime", "early_adopter", "standard", "free"] {
                assert!(
                    html.contains(&format!(r#"value="{value}""#)),
                    "tier option {value} is offered regardless of current tier"
                );
            }
        }
    }

    #[test]
    fn requires_a_2fa_code_and_posts_to_the_tier_route() {
        let html = tier_change_card(&target(SubscriptionTier::Standard)).into_string();
        assert!(html.contains(&format!(r#"action="/admin/users/{UID}/tier""#)));
        assert!(
            html.contains(r#"name="totp_code""#) && html.contains("required"),
            "the admin's 2FA code is a required field: {html}"
        );
    }

    #[test]
    fn preselects_the_current_tier() {
        let html = tier_change_card(&target(SubscriptionTier::EarlyAdopter)).into_string();
        assert!(
            html.contains(r#"value="early_adopter" selected"#),
            "the member's current tier is preselected: {html}"
        );
    }
}

#[cfg(test)]
mod rate_limit_management_tests {
    //! BUNYIP-413: the management controls are super-admin-only. The API
    //! enforces that too, so these assert the UI does not offer a control the
    //! caller's write would be refused for.
    use super::*;

    fn cfg(action: &str, overridden: bool) -> AdminRateLimitConfig {
        AdminRateLimitConfig {
            action: action.to_string(),
            max_requests: if overridden { 25 } else { 5 },
            window_seconds: 60,
            default_max_requests: 5,
            default_window_seconds: 60,
            overridden,
            updated_at: None,
        }
    }

    #[test]
    fn config_card_offers_edit_and_revert_to_the_super_admin() {
        let html = rate_limit_config_card(&[cfg("login", true)], true, true).into_string();
        assert!(
            html.contains(r#"action="/admin/rate-limits/config""#),
            "the save form is rendered"
        );
        assert!(
            html.contains(r#"action="/admin/rate-limits/config/reset""#),
            "an overridden limit offers a revert"
        );
        assert!(
            html.contains(r#"name="max_requests""#) && html.contains(r#"name="window_seconds""#)
        );
    }

    #[test]
    fn config_card_is_read_only_for_an_ordinary_admin() {
        let html = rate_limit_config_card(&[cfg("login", true)], true, false).into_string();
        assert!(
            !html.contains("/admin/rate-limits/config"),
            "no management form for a non-super-admin"
        );
        assert!(
            html.contains("Only the super admin can change them."),
            "the read-only card says why"
        );
        // The numbers are still visible, so the screen stays informative.
        assert!(html.contains("Login"));
    }

    #[test]
    fn a_limit_on_its_default_offers_no_revert() {
        let html = rate_limit_config_card(&[cfg("login", false)], true, true).into_string();
        assert!(html.contains(r#"action="/admin/rate-limits/config""#));
        assert!(
            !html.contains("/admin/rate-limits/config/reset"),
            "nothing to revert when no override is in force"
        );
    }

    #[test]
    fn ban_add_card_posts_ip_reason_and_duration() {
        let html = ip_ban_add_card(None).into_string();
        assert!(html.contains(r#"action="/admin/ip-bans/add""#));
        assert!(html.contains(r#"name="ip""#));
        assert!(html.contains(r#"name="reason""#));
        assert!(html.contains(r#"name="duration_secs""#));
    }

    /// BUNYIP-436: a "Ban this address" link carries the IP as `?ip=`, and the
    /// add-ban form seeds its address field from it so the admin lands ready to
    /// submit. An empty prefill leaves the field blank.
    #[test]
    fn ban_add_card_prefills_ip_from_query() {
        let html = ip_ban_add_card(Some("203.0.113.7")).into_string();
        assert!(
            html.contains(r#"name="ip""#) && html.contains(r#"value="203.0.113.7""#),
            "add-ban form seeds the address field from the prefill"
        );
        let blank = ip_ban_add_card(None).into_string();
        assert!(
            blank.contains(r#"value="""#) || !blank.contains("value="),
            "no prefill leaves the address field empty"
        );
    }

    /// BUNYIP-436: the captured IP on the feedback detail links into the ban
    /// flow (the ip-bans page prefills its add form from `?ip=`), while the
    /// user agent is shown as plain admin-only text. The address is
    /// URL-encoded into the query.
    #[test]
    fn feedback_detail_links_ip_into_ban_flow() {
        let detail = AdminFeedbackDetail {
            id: "22222222-2222-2222-2222-222222222222".to_string(),
            name: Some("Ada".to_string()),
            email: None,
            email_masked: None,
            subject: Some("Broken button".to_string()),
            tags: vec![],
            message: "It does not work".to_string(),
            page_path: None,
            status: FeedbackStatus::New,
            admin_response: None,
            created_at: "2026-08-01T00:00:00Z".to_string(),
            responded_at: None,
            attachments: vec![],
            submitter_ip: Some("203.0.113.7".to_string()),
            user_agent: Some("Mozilla/5.0 Firefox/121.0".to_string()),
        };
        let html = super::feedback_detail_view(&detail, super::FeedbackTab::Spam).into_string();
        assert!(
            html.contains(r#"href="/admin/ip-bans?ip=203.0.113.7""#),
            "the IP links into the ip-bans add flow"
        );
        assert!(
            html.contains("Mozilla/5.0 Firefox/121.0"),
            "user agent shown"
        );
    }

    #[test]
    fn window_labels_are_compact() {
        assert_eq!(fmt_window_secs(45), "45s");
        assert_eq!(fmt_window_secs(60), "1m");
        assert_eq!(fmt_window_secs(900), "15m");
        assert_eq!(fmt_window_secs(3600), "1h");
    }
}
