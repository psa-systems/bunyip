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
use crate::api::types::{AdminAuditLog, FeedbackStatus};
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::relative_time;
use crate::views::ui::{badge, button_class, icon};
use crate::web::{redirect, AppState};

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
    let (user, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let fwd = c.forward.as_deref();
    let stats = admin_api::stats(&st.api, fwd).await.ok();
    let logs = admin_api::audit_logs(&st.api, fwd, 1, 5, false).await.map(|p| p.items).unwrap_or_default();

    let stat = |label: &str, value: String, sub: &str, ic: &str| html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6 flex-row items-center justify-between pb-2" {
                h3 class="text-sm font-medium" { (label) } (icon(ic, "h-4 w-4 text-muted-foreground"))
            }
            div class="p-6 pt-0" { div class="text-2xl font-bold" { (value) } p class="text-xs text-muted-foreground" { (sub) } }
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
pub struct AuditQuery { pub page: Option<u32>, pub admin_only: Option<String> }

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

pub async fn audit_logs(State(st): State<AppState>, headers: HeaderMap, Query(q): Query<AuditQuery>) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let page = q.page.unwrap_or(1).max(1);
    let admin_only = q.admin_only.as_deref() == Some("true");
    let data = admin_api::audit_logs(&st.api, c.forward.as_deref(), page, 50, admin_only).await.ok();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);
    let base = if admin_only { "/admin/audit-logs?admin_only=true" } else { "/admin/audit-logs" };

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
    admin_response(&c, &user, "/admin/audit-logs", "Audit Logs · Bunyip", content)
}

// ===========================================================================
// Users
// ===========================================================================

#[derive(Deserialize)]
pub struct UserQuery { pub page: Option<u32>, pub search: Option<String> }

pub async fn users(State(st): State<AppState>, headers: HeaderMap, Query(q): Query<UserQuery>) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let page = q.page.unwrap_or(1).max(1);
    let search = q.search.unwrap_or_default();
    let data = admin_api::users(&st.api, c.forward.as_deref(), page, 20, &search).await.ok();
    let items = data.as_ref().map(|p| p.items.clone()).unwrap_or_default();
    let total_pages = data.as_ref().map(|p| p.total_pages).unwrap_or(1);
    let base = if search.is_empty() { "/admin/users".to_string() } else { format!("/admin/users?search={}", urlenc(&search)) };

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
                                div class="flex items-center gap-2" {
                                    form method="post" action=(format!("/admin/users/{}/role", u.id)) {
                                        input type="hidden" name="role" value=(if is_admin { "subscriber" } else { "admin" });
                                        button type="submit" class=(button_class("outline", "sm", "")) { @if is_admin { "Demote" } @else { "Make Admin" } }
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
pub struct RoleForm { pub role: String }
pub async fn user_role(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Form(f): Form<RoleForm>) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let _ = admin_api::update_user_role(&st.api, c.forward.as_deref(), &id, &f.role).await;
    redirect("/admin/users")
}
pub async fn user_delete(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let _ = admin_api::delete_user(&st.api, c.forward.as_deref(), &id).await;
    redirect("/admin/users")
}

// ===========================================================================
// Memberships
// ===========================================================================

#[derive(Deserialize)]
pub struct PageQuery { pub page: Option<u32> }

pub async fn memberships(State(st): State<AppState>, headers: HeaderMap, Query(q): Query<PageQuery>) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let page = q.page.unwrap_or(1).max(1);
    let data = admin_api::memberships(&st.api, c.forward.as_deref(), page, 20, "").await.ok();
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
    admin_response(&c, &user, "/admin/memberships", "Memberships · Bunyip", content)
}

// ===========================================================================
// Feedback
// ===========================================================================

pub async fn feedback(State(st): State<AppState>, headers: HeaderMap, Query(q): Query<PageQuery>) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let page = q.page.unwrap_or(1).max(1);
    let data = admin_api::feedback(&st.api, c.forward.as_deref(), page, 20).await.ok();
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
pub struct StatusForm { pub status: String }
pub async fn feedback_status(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Form(f): Form<StatusForm>) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let status = match f.status.as_str() {
        "reviewed" => FeedbackStatus::Reviewed,
        "responded" => FeedbackStatus::Responded,
        "closed" => FeedbackStatus::Closed,
        _ => FeedbackStatus::New,
    };
    let _ = admin_api::update_feedback_status(&st.api, c.forward.as_deref(), &id, status).await;
    redirect("/admin/feedback")
}

// ===========================================================================
// Applications
// ===========================================================================

pub async fn applications(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let apps = admin_api::applications(&st.api, c.forward.as_deref()).await.unwrap_or_default();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Applications" } p class="mt-2 text-muted-foreground" { "Configure available applications." } }
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
                                }
                            }
                        }
                        @if apps.is_empty() { p class="text-center text-muted-foreground py-8" { "No applications" } }
                    }
                }
            }
        }
    };
    admin_response(&c, &user, "/admin/applications", "Applications · Bunyip", content)
}

#[derive(Deserialize)]
pub struct AppFieldForm { pub field: String, pub value: String }
pub async fn application_field(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Form(f): Form<AppFieldForm>) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let val = f.value == "true";
    let mut map = serde_json::Map::new();
    map.insert(f.field.clone(), json!(val));
    let body = serde_json::Value::Object(map);
    let _ = admin_api::update_application(&st.api, c.forward.as_deref(), &id, body).await;
    redirect("/admin/applications")
}

// ===========================================================================
// Tier settings
// ===========================================================================

pub async fn tier_settings(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let cfg = admin_api::tier_config(&st.api, c.forward.as_deref()).await.ok();

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
    admin_response(&c, &user, "/admin/tier-settings", "Tier settings · Bunyip", content)
}

#[derive(Deserialize)]
pub struct TierForm { pub lifetime_slots: i64, pub early_adopter_slots: i64, pub early_adopter_trial_days: i64, pub standard_trial_days: i64 }
pub async fn tier_settings_save(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<TierForm>) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let body = json!({ "lifetime_slots": f.lifetime_slots, "early_adopter_slots": f.early_adopter_slots, "early_adopter_trial_days": f.early_adopter_trial_days, "standard_trial_days": f.standard_trial_days });
    let _ = admin_api::update_tier_config(&st.api, c.forward.as_deref(), body).await;
    redirect("/admin/tier-settings")
}

// ===========================================================================
// Stripe config (condensed: keys + app tag)
// ===========================================================================

pub async fn stripe(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let cfg = admin_api::stripe_config(&st.api, c.forward.as_deref()).await.ok();

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
pub struct StripeForm { #[serde(default)] pub secret_key: String, #[serde(default)] pub webhook_secret: String, pub app_tag: String }
pub async fn stripe_save(State(st): State<AppState>, headers: HeaderMap, Form(f): Form<StripeForm>) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await { Ok(v) => v, Err(r) => return r };
    let mut body = json!({ "app_tag": f.app_tag });
    if !f.secret_key.is_empty() { body["secret_key"] = json!(f.secret_key); }
    if !f.webhook_secret.is_empty() { body["webhook_secret"] = json!(f.webhook_secret); }
    let _ = admin_api::update_stripe_config(&st.api, c.forward.as_deref(), body).await;
    redirect("/admin/stripe")
}

fn urlenc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b { b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char), b' ' => out.push('+'), _ => out.push_str(&format!("%{b:02X}")) }
    }
    out
}
