//! Admin panel: Users.

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

use super::rate_limits::rate_limit_row;
use super::{pager, title_case};

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
