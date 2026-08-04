//! Admin panel: Rate limits (BUNYIP-317).

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

use super::refuse_non_super_admin;
use super::PageQuery;
use super::{pager, title_case};

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
pub(super) fn rate_limit_row(rl: &AdminRateLimit, return_user: Option<&str>) -> Markup {
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
