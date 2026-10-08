//! Admin panel: Rate limits (BUNYIP-317).

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup, PreEscaped};
use serde::Deserialize;

use crate::api::admin as admin_api;
use crate::api::types::{
    AdminRateLimit, AdminRateLimitConfig, AdminRateLimitHistory, AdminRateLimitTraffic,
};
use crate::api::ApiError;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::{rel_time, urlenc};
use crate::views::ui::{badge, button_class, empty_state, error_box_for, icon, pager};
use crate::web::{redirect_cookies, AppState};

use super::refuse_non_super_admin;
use super::title_case;

/// Local query shape adding the sparkline time-range toggle (`1h | 6h | 1d`,
/// default `1h`). PageQuery stays as-is for the rest of the admin surface.
#[derive(Deserialize)]
pub struct RateLimitsQuery {
    pub page: Option<u32>,
    #[serde(default)]
    pub window: Option<String>,
}

fn normalize_window(raw: Option<&str>) -> &'static str {
    match raw.unwrap_or("1h") {
        "6h" => "6h",
        "1d" => "1d",
        _ => "1h",
    }
}

fn window_label(window: &str) -> &'static str {
    match window {
        "6h" => "6 hours",
        "1d" => "1 day",
        _ => "1 hour",
    }
}

/// Format a `retry_after` second count as a compact "retry in" label
/// (e.g. `2m 5s`, `45s`). Zero (or a window that has just elapsed) reads as
/// "any moment", since the throttle clears on the next request.
pub(super) fn fmt_retry_secs(secs: u64) -> String {
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
                        "Window started " (rel_time(&rl.window_start)) " · retry in " (fmt_retry_secs(rl.retry_after))
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
pub(super) fn fmt_window_secs(secs: i64) -> String {
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
    // BUNYIP-873: `@container` makes this row query its OWN rendered width
    // rather than the viewport, so the label/inputs split reflows correctly
    // whether the grid below is one or two columns wide and whatever the
    // admin sidebar is doing. `break-words` (not `break-all`) only breaks a
    // single word too long for the column; normal word-boundary wrapping
    // handles everything else, and `min-w-[11rem]` keeps the label from
    // being squeezed to a few characters per line beside the inputs.
    html! {
        div class="@container flex flex-col gap-3 py-4 border-b last:border-0 @md:flex-row @md:items-start @md:justify-between" {
            div class="min-w-0 @md:min-w-[11rem] @md:flex-1" {
                div class="flex items-center gap-2 flex-wrap" {
                    p class="font-medium break-words" { (title_case(&cfg.action)) }
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
                div class="flex items-end gap-2 flex-wrap @md:shrink-0 @md:flex-nowrap" {
                    form method="post" action="/admin/rate-limits/config" class="flex items-end gap-2 flex-wrap" {
                        input type="hidden" name="action" value=(cfg.action);
                        div class="space-y-1" { label for=(format!("max_requests-{}", cfg.action)) class="text-xs text-muted-foreground" { "Requests" } input id=(format!("max_requests-{}", cfg.action)) name="max_requests" type="number" min="1" max=(MAX_LIMIT_REQUESTS) value=(cfg.max_requests) class=(format!("{} w-28", dashboard_input())); }
                        div class="space-y-1" { label for=(format!("window_seconds-{}", cfg.action)) class="text-xs text-muted-foreground" { "Window (s)" } input id=(format!("window_seconds-{}", cfg.action)) name="window_seconds" type="number" min="1" max=(MAX_LIMIT_WINDOW_SECS) value=(cfg.window_seconds) class=(format!("{} w-28", dashboard_input())); }
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
pub(super) fn rate_limit_config_card(
    configs: &[AdminRateLimitConfig],
    error: Option<&ApiError>,
    editable: bool,
) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex items-center gap-3" { (icon("sliders-horizontal", "h-5 w-5 text-primary-text")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Limit Configuration" } }
                p class="text-sm text-muted-foreground" {
                    @if editable {
                        "The cap and window enforced for each action. A saved value is written to the database provider and takes effect on the next request; Revert deletes the override and falls back to the file/environment default."
                    } @else {
                        "The cap and window enforced for each action. Only the super admin can change them."
                    }
                }
            }
            div class="p-6 pt-0" {
                @if let Some(e) = error {
                    (error_box_for("Could not reach the API to load the limit configuration.", e))
                } @else {
                    // BUNYIP-873: `@5xl` queries the page's content-area container
                    // (declared in `rate_limits` below), not the viewport, so the
                    // column count follows the main area's actual width whether
                    // the admin sidebar is showing or not.
                    div class="grid gap-x-8 @5xl:grid-cols-2" { @for cfg in configs { (rate_limit_config_row(cfg, editable)) } }
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
    Query(q): Query<RateLimitsQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let page = q.page.unwrap_or(1).max(1);
    let window = normalize_window(q.window.as_deref());
    let cfg_data = admin_api::rate_limit_configs(&st.api, c.forward.as_deref()).await;
    let configs_error = cfg_data.as_ref().err().cloned();
    let configs = cfg_data.unwrap_or_default();
    let data = admin_api::rate_limits(&st.api, c.forward.as_deref(), page, 20).await;
    let error = data.as_ref().err().cloned();
    let (items, total, total_pages) = match data {
        Ok(p) => (p.items, p.total, p.total_pages),
        Err(_) => (Vec::new(), 0, 1),
    };

    // Past throttles (BUNYIP-891): the "has a rate limit fired recently"
    // question the active list cannot answer once the window has elapsed.
    let history_data =
        admin_api::rate_limit_history(&st.api, c.forward.as_deref(), None, Some(100)).await;
    let history_error = history_data.as_ref().err().cloned();
    let history = history_data.unwrap_or_default();

    // Traffic sparklines per configured action (BUNYIP-892). Sequential
    // fetch is fine while the configured action set is small (one row per
    // RateLimitConfig::ALL variant); if that grows the admin page can
    // move to `futures::join_all` without changing the render.
    let mut traffic: Vec<(String, Result<AdminRateLimitTraffic, ApiError>)> =
        Vec::with_capacity(configs.len());
    for cfg in &configs {
        let r =
            admin_api::rate_limit_traffic(&st.api, c.forward.as_deref(), &cfg.action, window).await;
        traffic.push((cfg.action.clone(), r));
    }

    let content = html! {
        // BUNYIP-873: `@container` turns this into the query context both
        // grids below size themselves against, so column counts follow the
        // admin main area's actual rendered width (sidebar open or
        // collapsed) rather than the raw viewport.
        div class="@container space-y-6" {
            div { h1 class="text-3xl font-bold" { "Rate Limits" } p class="mt-2 text-muted-foreground" { "Entities currently throttled by a rate limit. Resetting a throttle lets the affected user or IP act again immediately." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center gap-3" { (icon("gauge", "h-5 w-5 text-primary-text")) h3 class="text-2xl font-semibold leading-none tracking-tight" { "Active Throttles" } }
                    @if error.is_none() { p class="text-sm text-muted-foreground" { (total) " active." } }
                }
                div class="p-6 pt-0" {
                    @if let Some(e) = &error {
                        (error_box_for("Could not reach the API to load rate limits.", e))
                    } @else if items.is_empty() {
                        (empty_state("gauge", "No active rate limits.", None))
                    } @else {
                        // BUNYIP-415: flow throttle rows into two columns (one
                        // below the content area's width) so a long list uses the
                        // width. Each row keeps its own bottom-border separator.
                        // BUNYIP-873: `@5xl` queries the `@container` above, not
                        // the viewport.
                        div class="grid gap-x-8 @5xl:grid-cols-2" { @for rl in &items { (rate_limit_row(rl, None)) } }
                        (pager("/admin/rate-limits", "page", page, total_pages))
                    }
                }
            }
            // Past Throttles (BUNYIP-891): 24h of fired-and-expired events.
            (past_throttles_card(&history, history_error.as_ref()))
            // Traffic + sparkline per bucket (BUNYIP-892).
            (traffic_card(&traffic, window))
            (rate_limit_config_card(&configs, configs_error.as_ref(), user.is_super_admin))
        }
    };
    admin_response(&c, &user, "/admin/rate-limits", "Rate Limits", content)
}

/// Render one past-throttle row: subject, action, fired-at and expires-at
/// (as relative times), with the same icon vocabulary the active-list row
/// uses so one view's visual language carries into the next.
fn past_throttle_row(h: &AdminRateLimitHistory) -> Markup {
    let (subject, subject_sub, icon_name) = if let Some(email) = &h.user_email {
        (email.clone(), h.user_id.clone(), "user")
    } else if let Some(ip) = &h.ip {
        (ip.clone(), None, "globe")
    } else {
        (h.key.clone(), None, "help-circle")
    };
    html! {
        div class="flex items-start justify-between py-4 border-b last:border-0" {
            div class="flex items-start gap-4 min-w-0" {
                div class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-muted" {
                    (icon(icon_name, "h-5 w-5 text-muted-foreground"))
                }
                div class="min-w-0" {
                    div class="flex items-center gap-2 flex-wrap" {
                        p class="font-medium break-all" { (subject) }
                        (badge("secondary", &title_case(&h.action)))
                    }
                    @if let Some(sub) = &subject_sub {
                        p class="text-xs text-muted-foreground font-mono break-all" { (sub) }
                    }
                    p class="text-xs text-muted-foreground" {
                        "Fired " (rel_time(&h.fired_at))
                        " · released " (rel_time(&h.expires_at))
                    }
                }
            }
        }
    }
}

/// Past-throttles section: a 24h log of fired-and-expired events, so an
/// operator looking at the admin page an hour after a 429 can still
/// investigate what fired. Hidden entirely if the fetch failed with the
/// error rendered in its place.
fn past_throttles_card(history: &[AdminRateLimitHistory], error: Option<&ApiError>) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex items-center gap-3" {
                    (icon("history", "h-5 w-5 text-primary-text"))
                    h3 class="text-2xl font-semibold leading-none tracking-tight" { "Past Throttles" }
                }
                @if error.is_none() {
                    p class="text-sm text-muted-foreground" {
                        "The last 24 hours of fired-and-expired rate limits."
                    }
                }
            }
            div class="p-6 pt-0" {
                @if let Some(e) = error {
                    (error_box_for("Could not reach the API to load past throttles.", e))
                } @else if history.is_empty() {
                    (empty_state("history", "No rate limits have fired in the last 24 hours.", None))
                } @else {
                    div class="grid gap-x-8 @5xl:grid-cols-2" {
                        @for h in history { (past_throttle_row(h)) }
                    }
                }
            }
        }
    }
}

/// Server-rendered SVG sparkline. Draws one bar per bucket (status.claude.com
/// shape, not a line), colored "normal" by default and switching to the
/// warning tint when the bar's count crosses `limit`. Uses theme tokens via
/// Tailwind utility classes on the surrounding wrapper; the SVG itself
/// paints with `currentColor` so dark mode inherits.
fn sparkline(points: &[(String, i64)], limit: i32) -> Markup {
    const W: i64 = 240;
    const H: i64 = 32;
    const BAR_GAP: i64 = 1;
    let n = points.len().max(1) as i64;
    let bar_w = ((W - BAR_GAP * (n - 1)) / n).max(1);
    // The vertical scale is max(limit, observed): a short bar against a
    // high limit still reads as "nowhere near", a tall bar past the limit
    // reads as "over".
    let observed = points.iter().map(|p| p.1).max().unwrap_or(0);
    let scale = limit.max(1).max(observed as i32) as i64;

    let mut bars = String::new();
    // Buckets come back newest first; render oldest-left-to-newest-right.
    for (idx, (_bucket, count)) in points.iter().rev().enumerate() {
        let x = idx as i64 * (bar_w + BAR_GAP);
        let frac = (*count as f64 / scale as f64).clamp(0.0, 1.0);
        let bar_h = ((H as f64) * frac).round().max(1.0) as i64;
        let y = H - bar_h;
        let class = if *count as i32 > limit {
            "fill-amber-500 dark:fill-amber-400"
        } else {
            "fill-primary/60 dark:fill-primary/80"
        };
        bars.push_str(&format!(
            "<rect x=\"{x}\" y=\"{y}\" width=\"{bar_w}\" height=\"{bar_h}\" class=\"{class}\" />"
        ));
    }
    let threshold_y = if limit > 0 && (limit as i64) <= scale {
        H - (H * limit as i64 / scale)
    } else {
        0
    };
    let threshold = if limit > 0 {
        format!(
            "<line x1=\"0\" y1=\"{threshold_y}\" x2=\"{W}\" y2=\"{threshold_y}\" \
             class=\"stroke-amber-500/70\" stroke-dasharray=\"2 2\" stroke-width=\"1\" />"
        )
    } else {
        String::new()
    };
    let svg = format!(
        "<svg viewBox=\"0 0 {W} {H}\" width=\"{W}\" height=\"{H}\" \
         preserveAspectRatio=\"none\" aria-hidden=\"true\">{bars}{threshold}</svg>"
    );
    html! { (PreEscaped(svg)) }
}

/// Traffic card: configured limit + sparkline per bucket, with a 1h/6h/1d
/// time-range toggle at the top. One row per `RateLimitConfig::ALL` action
/// so the unauthenticated and authenticated API buckets are both visible.
fn traffic_card(
    traffic: &[(String, Result<AdminRateLimitTraffic, ApiError>)],
    window: &str,
) -> Markup {
    let toggles = ["1h", "6h", "1d"];
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex items-center justify-between flex-wrap gap-3" {
                    div class="flex items-center gap-3" {
                        (icon("activity", "h-5 w-5 text-primary-text"))
                        h3 class="text-2xl font-semibold leading-none tracking-tight" { "Traffic" }
                    }
                    div class="flex items-center gap-1 rounded-md border bg-muted/40 p-1" {
                        @for choice in toggles {
                            @let selected = *choice == *window;
                            a
                                href=(format!("/admin/rate-limits?window={}", urlenc(choice)))
                                class=({
                                    if selected {
                                        "px-3 py-1 text-sm rounded bg-background shadow-sm font-medium"
                                    } else {
                                        "px-3 py-1 text-sm rounded text-muted-foreground hover:bg-background/60"
                                    }
                                })
                                { (choice) }
                        }
                    }
                }
                p class="text-sm text-muted-foreground" {
                    "Requests per 15-minute bucket over the last " (window_label(window))
                    ", against each action's configured limit."
                }
            }
            div class="p-6 pt-0 space-y-4" {
                @if traffic.is_empty() {
                    (empty_state("activity", "No rate-limit actions are configured.", None))
                } @else {
                    @for (action, res) in traffic {
                        div class="flex items-center justify-between gap-4 flex-wrap border-b last:border-0 py-3" {
                            div class="min-w-0" {
                                p class="font-medium" { (title_case(action)) }
                                @match res {
                                    Ok(t) => {
                                        p class="text-xs text-muted-foreground" {
                                            "Limit: " (t.max_requests) " per "
                                            (fmt_window_seconds(t.window_seconds))
                                        }
                                    }
                                    Err(_) => {
                                        p class="text-xs text-muted-foreground" { "Limit unavailable." }
                                    }
                                }
                            }
                            div {
                                @match res {
                                    Ok(t) => {
                                        @let points: Vec<(String, i64)> = t
                                            .points
                                            .iter()
                                            .map(|p| (p.bucket_start.clone(), p.count))
                                            .collect();
                                        @if points.is_empty() {
                                            p class="text-xs text-muted-foreground italic" { "No traffic yet." }
                                        } @else {
                                            (sparkline(&points, t.max_requests))
                                        }
                                    }
                                    Err(_) => {
                                        p class="text-xs text-amber-600 dark:text-amber-400" {
                                            "Traffic unavailable."
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
}

/// Compact seconds-to-"5m" / "1h" / "1d" formatter for the configured
/// window beside each sparkline. One-line, read-left-to-right.
fn fmt_window_seconds(secs: i64) -> String {
    if secs <= 0 {
        return "0s".to_string();
    }
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    let mut parts: Vec<String> = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if mins > 0 {
        parts.push(format!("{mins}m"));
    }
    if s > 0 && parts.is_empty() {
        parts.push(format!("{s}s"));
    }
    parts.join(" ")
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
