//! Authenticated dashboard. Ported from the Dioxus DashboardPage. Other
//! dashboard pages (applications, membership, billing, settings, ...) arrive in
//! phase 3.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Form;
use maud::{html, Markup, PreEscaped};
use serde::Deserialize;

use crate::api::auth as auth_api;
use crate::api::calls;
use crate::api::types::{
    AppDownloadGroup, Application, Membership, MembershipStatus, SubscriptionTier,
    TwoFactorSetupResponse, User,
};
use crate::handlers::{dashboard_response, guard, password_ok, rotating_index};
use crate::util::{app_gradient, days_until, has_active_membership, urlenc};
use crate::views::ui::{badge, button_class, error_box, icon};
use crate::web::{redirect_cookies, AppState};

const TAGLINES: [&str; 5] = [
    "All access. No clock.",
    "All in. All yours.",
    "No teardown. No sunset. Just tools.",
    "Price locked. Tools stocked.",
    "Zero TTL. Infinite access.",
];

pub async fn dashboard(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/dashboard").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();

    let apps = calls::applications(&st.api, fwd).await.unwrap_or_default();
    let stripe_enabled = auth_api::setup_status(&st.api)
        .await
        .map(|s| s.stripe_enabled)
        .unwrap_or(true);
    let is_member = has_active_membership(Some(&user));
    let tagline = TAGLINES[rotating_index(TAGLINES.len())];
    let base_domain = st.cfg.domain_or_localhost();

    let content = html! {
        div class="space-y-8" {
            div {
                h1 class="text-3xl font-bold" { "Welcome back!" }
                p class="mt-2 text-muted-foreground" { (tagline) }
            }

            // Membership status
            div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50 overflow-hidden" {
                div class="h-1 bg-gradient-to-r from-primary via-indigo-500 to-teal-500" {}
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center justify-between" {
                        div class="flex items-center gap-3" {
                            div class="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-indigo-500" {
                                (icon("credit-card", "h-4 w-4 text-white"))
                            }
                            h3 class="text-lg font-semibold leading-none tracking-tight" { "Membership" }
                        }
                        (membership_badge(&user))
                    }
                }
                div class="p-6 pt-0" {
                    @if is_member {
                        div class="flex items-center justify-between" {
                            div { (subscription_status(&user)) }
                            a href="/membership" class=(button_class("outline", "sm", "border-indigo-300/30 text-indigo-600 hover:bg-indigo-500/10 dark:border-indigo-500/30 dark:text-indigo-400")) { "Manage" }
                        }
                    } @else {
                        div class="flex items-center justify-between" {
                            p class="text-sm text-muted-foreground" { (membership_prompt(&user)) }
                            @if stripe_enabled {
                                a href="/membership" class=(button_class("default", "sm", "gap-2 bg-gradient-to-r from-primary to-indigo-500 text-white border-0 shadow-md shadow-primary/20")) {
                                    "Subscribe Now " (icon("arrow-right", "h-3.5 w-3.5"))
                                }
                            } @else {
                                button type="button" disabled title="Payment is not configured"
                                    class=(button_class("default", "sm", "gap-2 bg-gradient-to-r from-primary to-indigo-500 text-white border-0 shadow-md shadow-primary/20")) {
                                    "Subscribe Now " (icon("arrow-right", "h-3.5 w-3.5"))
                                }
                            }
                        }
                    }
                }
            }

            // Applications
            div {
                div class="flex items-center gap-3 mb-4" {
                    div class="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500 to-teal-500" {
                        (icon("app-window", "h-4 w-4 text-white"))
                    }
                    h2 class="text-xl font-semibold" { "Your Applications" }
                }
                div class="grid gap-4 lg:grid-cols-2" {
                    @for (i, app) in apps.iter().enumerate() {
                        @let subdomain = app.subdomain.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| app.slug.clone());
                        @let app_url = format!("{subdomain}.{base_domain}");
                        div class="rounded-lg border bg-card text-card-foreground shadow-sm flex h-full flex-col border-border/50 transition-all hover:shadow-lg hover:shadow-indigo-500/5" {
                            div class="flex flex-col space-y-1.5 p-6" {
                                div class="flex items-center justify-between" {
                                    h3 class="text-lg font-semibold leading-none tracking-tight" { (app.display_name) }
                                    @if app.maintenance_mode { (badge("warning", "Maintenance")) }
                                    @else if app.is_accessible { (badge("success", "Active")) }
                                    @else { (badge("secondary", "Locked")) }
                                }
                                p class="text-sm text-muted-foreground" { (app.description.clone().unwrap_or_default()) }
                            }
                            div class="p-6 pt-0 mt-auto" {
                                @if app.is_accessible {
                                    a href=(format!("https://{app_url}/dashboard")) target="_blank" rel="noopener noreferrer" {
                                        span class=(button_class("default", "default", &format!("w-full bg-gradient-to-r {} text-white border-0 shadow-md shadow-indigo-500/15 hover:shadow-lg hover:shadow-indigo-500/25 transition-shadow", app_gradient(i)))) {
                                            "Open " (app.display_name) (icon("external-link", "ml-2 h-4 w-4"))
                                        }
                                    }
                                } @else {
                                    button type="button" disabled class=(button_class("default", "default", "w-full")) {
                                        @if !is_member { "Membership Required" }
                                        @else if app.maintenance_mode { "Under Maintenance" }
                                        @else { "Not Available" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    dashboard_response(&c, &user, "/dashboard", "Dashboard · Bunyip", content)
}

pub fn membership_badge(user: &User) -> Markup {
    // Admins have all-access regardless of membership status (mirrors
    // `has_active_membership`, which treats role == Admin as access-granted).
    // Without this, an admin whose `membership_status` is None/Canceled/etc.
    // gets a "No Membership" pill next to "You have access to all
    // applications" - a direct contradiction (BUNYIP-108).
    if matches!(user.role, crate::api::types::UserRole::Admin) {
        return badge("default", "Admin");
    }
    if user.lifetime_member {
        return badge("success", "Lifetime");
    }
    if user.trial_ends_at.as_deref().and_then(days_until).is_some() {
        return badge("secondary", "Trial");
    }
    match user.membership_status {
        MembershipStatus::Active => badge("success", "Active"),
        MembershipStatus::GracePeriod => badge("warning", "Grace Period"),
        MembershipStatus::PastDue => badge("warning", "Past Due"),
        MembershipStatus::Canceled => badge("destructive", "Canceled"),
        MembershipStatus::Incomplete => badge("secondary", "Incomplete"),
        _ => badge("outline", "No Membership"),
    }
}

fn membership_prompt(user: &User) -> Markup {
    let ended =
        user.trial_ends_at.is_some() || user.membership_status == MembershipStatus::Canceled;
    html! {
        @if ended { "Your trial has ended - subscribe to continue." }
        @else { "Subscribe to get access to all applications." }
    }
}

fn subscription_status(user: &User) -> Markup {
    if user.lifetime_member {
        return html! { p class="text-sm font-medium text-teal-600 dark:text-teal-400" { "Lifetime member 🎉" } };
    }
    if let Some(days) = user.trial_ends_at.as_deref().and_then(days_until) {
        let plural = if days != 1 { "s" } else { "" };
        return html! { p class="text-sm text-muted-foreground" { "Trial ends in " (days) " day" (plural) } };
    }
    if user.membership_status == MembershipStatus::Active {
        return html! {
            p class="text-sm text-muted-foreground" {
                "You have access to all applications."
                @if user.price_locked {
                    span class="ml-2 text-teal-600 dark:text-teal-400 font-medium" { "Price locked at $3/month" }
                }
            }
        };
    }
    html! { p class="text-sm text-muted-foreground" { "You have access to all applications." } }
}

// ===========================================================================
// shared formatting
// ===========================================================================

fn fmt_ts(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|d| d.format("%B %-d, %Y").to_string())
        .unwrap_or_default()
}
fn fmt_date_iso(iso: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(iso)
        .map(|d| d.format("%B %-d, %Y").to_string())
        .unwrap_or_else(|_| iso.to_string())
}
fn fmt_currency(cents: i64, currency: &str) -> String {
    format!("{} {:.2}", currency.to_uppercase(), cents as f64 / 100.0)
}
fn format_size(bytes: i64) -> String {
    let mb = bytes as f64 / 1_048_576.0;
    if mb >= 1.0 {
        format!("{mb:.1} MB")
    } else {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    }
}

// ===========================================================================
// Applications
// ===========================================================================

/// One application card on the Applications page. `idx` only drives the
/// gradient accent so cards stay visually varied across groups.
fn app_card(
    idx: usize,
    app: &Application,
    domain: &str,
    is_member: bool,
    downloads: Option<&AppDownloadGroup>,
) -> Markup {
    let subdomain = app
        .subdomain
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| app.slug.clone());
    let app_url = format!("{subdomain}.{domain}");
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50 transition-all hover:shadow-lg" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex items-start justify-between" {
                    div class={ "flex h-12 w-12 items-center justify-center rounded-lg bg-gradient-to-br " (app_gradient(idx)) } {
                        @if let Some(ic) = &app.icon_url { img src=(ic) alt=(app.display_name) class="h-6 w-6"; } @else { (icon("link-2", "h-6 w-6 text-white")) }
                    }
                    @if app.maintenance_mode { (badge("warning", "Maintenance")) }
                }
                h3 class="text-2xl font-semibold leading-none tracking-tight mt-4" { (app.display_name) }
                p class="text-sm text-muted-foreground" { (app.description.clone().unwrap_or_default()) }
            }
            div class="p-6 pt-0" {
                p class="text-sm text-muted-foreground mb-4" { (app_url) }
                @if app.is_accessible {
                    // `/dashboard`, not `/`, so the child app's AuthGuard sees a
                    // protected route and kicks off the OIDC code flow against
                    // the user's existing OP session. Landing on the public
                    // homepage instead just shows the marketing page; the user
                    // has to click "Sign in" before the SSO bridge fires.
                    a href=(format!("https://{app_url}/dashboard")) target="_blank" rel="noopener noreferrer" {
                        span class=(button_class("default", "default", &format!("w-full bg-gradient-to-r {} text-white border-0 shadow-md", app_gradient(idx)))) { "Launch" (icon("external-link", "ml-2 h-4 w-4")) }
                    }
                } @else {
                    button type="button" disabled class=(button_class("default", "default", "w-full")) {
                        @if !is_member { "Membership Required" } @else if app.maintenance_mode { "Under Maintenance" } @else { "Not Available" }
                    }
                }
                @if let Some(g) = downloads { (download_affordance(g, is_member)) }
            }
        }
    }
}

pub async fn applications(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/applications").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let apps = calls::applications(&st.api, fwd).await.unwrap_or_default();
    // Groups (BUNYIP-100). A failed fetch degrades to a flat ungrouped list.
    let groups = calls::application_groups(&st.api, fwd)
        .await
        .unwrap_or_default();
    // Per-product downloads (BUNYIP-100), joined onto each card by slug so
    // downloads live on the Applications page (the standalone Downloads page is
    // retired). A failed fetch degrades to cards with no Download affordance.
    let download_groups = calls::downloads_all(&st.api, fwd).await.unwrap_or_default();
    let stripe = auth_api::setup_status(&st.api)
        .await
        .map(|s| s.stripe_enabled)
        .unwrap_or(true);
    let is_member = has_active_membership(Some(&user));
    let domain = st.cfg.domain_or_localhost();

    // Build display sections: each group (in API sort order) with its members,
    // then an "ungrouped" bucket. The global enumerate index is carried into
    // each card so gradient accents stay varied across sections. An app whose
    // group_id references a missing group falls into the ungrouped bucket.
    let indexed: Vec<(usize, &Application)> = apps.iter().enumerate().collect();
    let mut group_sections: Vec<(&str, Vec<(usize, &Application)>)> = Vec::new();
    for g in &groups {
        let members: Vec<(usize, &Application)> = indexed
            .iter()
            .filter(|(_, a)| a.group_id.as_deref() == Some(g.id.as_str()))
            .copied()
            .collect();
        if !members.is_empty() {
            group_sections.push((g.display_name.as_str(), members));
        }
    }
    let ungrouped: Vec<(usize, &Application)> = indexed
        .iter()
        .filter(|(_, a)| {
            !groups
                .iter()
                .any(|g| Some(g.id.as_str()) == a.group_id.as_deref())
        })
        .copied()
        .collect();
    let has_groups = !group_sections.is_empty();
    // Catalog-only products: download groups whose slug matches no hosted app.
    // These had only the Downloads page before; surface them here so retiring
    // that page loses nothing.
    let catalog_only: Vec<&AppDownloadGroup> = download_groups
        .iter()
        .filter(|g| !apps.iter().any(|a| a.slug == g.app_slug))
        .collect();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Applications" } p class="mt-2 text-muted-foreground" { "Access all your tools in one place." } }
            @if !is_member {
                div class="rounded-lg border bg-card text-card-foreground shadow-sm border-indigo-500/20 bg-gradient-to-r from-indigo-500/5 via-primary/5 to-teal-500/5 overflow-hidden" {
                    div class="h-1 bg-gradient-to-r from-indigo-500 via-primary to-teal-500" {}
                    div class="p-6 pt-0 flex items-center justify-between py-4" {
                        div { p class="font-medium" { "Membership required" } p class="text-sm text-muted-foreground" { "Subscribe to access all applications." } }
                        @if stripe {
                            a href="/membership" class=(button_class("default", "default", "gap-2 bg-gradient-to-r from-primary to-indigo-500 text-white border-0 shadow-md shadow-primary/20")) { "Subscribe Now " (icon("arrow-right", "h-3.5 w-3.5")) }
                        } @else {
                            button type="button" disabled title="Payment is not configured" class=(button_class("default", "default", "gap-2 bg-gradient-to-r from-primary to-indigo-500 text-white border-0")) { "Subscribe Now " (icon("arrow-right", "h-3.5 w-3.5")) }
                        }
                    }
                }
            }
            @for (name, members) in &group_sections {
                section class="space-y-3" {
                    h2 class="text-xl font-semibold tracking-tight" { (name) }
                    div class="grid gap-6 md:grid-cols-2 lg:grid-cols-3" {
                        @for &(idx, app) in members { (app_card(idx, app, &domain, is_member, download_groups.iter().find(|g| g.app_slug == app.slug))) }
                    }
                }
            }
            @if !ungrouped.is_empty() {
                section class="space-y-3" {
                    @if has_groups { h2 class="text-xl font-semibold tracking-tight" { "Other" } }
                    div class="grid gap-6 md:grid-cols-2 lg:grid-cols-3" {
                        @for &(idx, app) in &ungrouped { (app_card(idx, app, &domain, is_member, download_groups.iter().find(|g| g.app_slug == app.slug))) }
                    }
                }
            }
            @if !catalog_only.is_empty() {
                section class="space-y-3" {
                    h2 class="text-xl font-semibold tracking-tight" { "More downloads" }
                    div class="grid gap-6 md:grid-cols-2 lg:grid-cols-3" {
                        @for &g in &catalog_only { (download_only_card(g, is_member)) }
                    }
                }
            }
        }
    };
    dashboard_response(&c, &user, "/applications", "Applications · Bunyip", content)
}

// ===========================================================================
// Downloads
// ===========================================================================

/// The standalone Downloads page is retired (BUNYIP-100): downloads now live on
/// each application card via the per-card Download affordance. Old links and
/// bookmarks land on the Applications page. The `/downloads/{slug}/{asset}`
/// proxy below stays: the card download links still route through it.
pub async fn downloads(_: State<AppState>, _: HeaderMap) -> Response {
    axum::response::Redirect::permanent("/applications").into_response()
}

/// GET /downloads/{slug}/{asset_name}
///
/// BFF download proxy. The browser must never hit bunyip-api directly (separate
/// origin, the session cookie is scoped to this app), so the asset link points
/// here. We re-auth the session, forward the cookie to the API's
/// `/v1/applications/{slug}/downloads/{asset}`, and stream the bytes back with
/// the upstream Content-Type / Content-Disposition. Without this hop the anchor
/// resolved against the web origin, fell through to the HTML 404 fallback, and
/// the browser saved that HTML page under the asset's filename (BUNYIP-64).
pub async fn download_asset(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path((slug, asset_name)): Path<(String, String)>,
) -> Response {
    let (_user, c) = match guard(&st, &headers, "/downloads").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    match calls::download_asset(&st.api, &slug, &asset_name, fwd).await {
        Ok(resp) if resp.status().is_success() => {
            // Read the relay headers before consuming `resp` into a stream.
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
                // Fallback only: the API always sends Content-Disposition. Escape
                // backslash/quote so a stray char in the name can't break out of
                // the quoted filename (a newline is already rejected by
                // HeaderValue, which fails the build into the redirect below).
                .unwrap_or_else(|| {
                    let safe = asset_name.replace('\\', "\\\\").replace('"', "\\\"");
                    format!("attachment; filename=\"{safe}\"")
                });
            // Forward the upstream status (always 200 here) and Content-Length so
            // the browser can show download progress. When the CompressionLayer
            // compresses for the browser it drops the stale length itself; on the
            // identity path the forwarded length is correct.
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
            if let Some(len) = content_length {
                builder = builder.header(header::CONTENT_LENGTH, len);
            }
            builder
                .body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| redirect_cookies("/downloads", &c.set_cookies))
        }
        // Any non-2xx (expired session, lost entitlement, upstream outage) must
        // NOT be saved as the asset. The anchor carries no `download` attribute,
        // so navigating the browser back renders HTML instead of downloading it:
        // sign-in on 401, the downloads page otherwise.
        Ok(resp) if resp.status().as_u16() == 401 => redirect_cookies("/login", &c.set_cookies),
        _ => redirect_cookies("/downloads", &c.set_cookies),
    }
}

/// A single download option for a product, kept as a typed enum so the dialog
/// is data-driven: adding a new distribution channel is one new variant plus
/// one render arm in `download_option_row`, nothing else. BUNYIP-100.
enum DownloadOption {
    /// A binary asset fetchable in one click via the BFF proxy.
    DirectLink {
        name: String,
        size: String,
        href: String,
    },
    /// A copy-pasteable shell command (e.g. `docker login` / `docker pull`).
    CopyBlock { command: String },
}

/// Map a product's downloads to the ordered option list shown in its dialog:
/// every binary asset becomes a click-to-download link (via the BFF proxy on
/// this origin, not the API's `download_url` which the browser cannot reach);
/// an OCI image becomes the `docker login` + `docker pull` copy blocks.
fn download_options(g: &AppDownloadGroup) -> Vec<DownloadOption> {
    let mut opts = Vec::new();
    for a in &g.assets {
        opts.push(DownloadOption::DirectLink {
            name: a.asset_name.clone(),
            size: format_size(a.size_bytes),
            href: format!(
                "/downloads/{}/{}",
                urlencoding::encode(&g.app_slug),
                urlencoding::encode(&a.asset_name)
            ),
        });
    }
    if let Some(oci) = &g.oci {
        opts.push(DownloadOption::CopyBlock {
            command: format!("docker login {}", oci.registry),
        });
        opts.push(DownloadOption::CopyBlock {
            command: format!("docker pull {}", oci.reference),
        });
    }
    opts
}

/// Render one option inside the download dialog.
fn download_option_row(opt: &DownloadOption) -> Markup {
    match opt {
        // No `download` attribute: the proxy's Content-Disposition drives the
        // save, and an error response navigates rather than being saved as the
        // file (BUNYIP-64).
        DownloadOption::DirectLink { name, size, href } => html! {
            li class="flex items-center justify-between gap-3" {
                div { div class="font-mono text-sm break-all" { (name) } div class="text-xs text-muted-foreground" { (size) } }
                a href=(href) class="px-3 py-1 rounded bg-primary text-primary-foreground text-sm shrink-0" { "Download" }
            }
        },
        DownloadOption::CopyBlock { command } => html! { li { (command_block(command)) } },
    }
}

/// The Download affordance for an application card. With exactly one binary and
/// nothing else it is a one-click link; otherwise it is a button that opens a
/// `<dialog>` listing every option (binary links plus OCI copy blocks). Members
/// only; non-members get an upgrade prompt. Renders nothing when the product
/// has no downloads. BUNYIP-100.
fn download_affordance(g: &AppDownloadGroup, is_member: bool) -> Markup {
    let opts = download_options(g);
    if opts.is_empty() {
        return html! {};
    }
    if !is_member {
        return html! { div class="mt-2 text-center" { (upgrade_link()) } };
    }
    // One binary and nothing else: a direct download link, no dialog.
    if opts.len() == 1 {
        if let DownloadOption::DirectLink { href, .. } = &opts[0] {
            return html! {
                a href=(href) class=(button_class("outline", "default", "w-full mt-2")) { (icon("download", "mr-2 h-4 w-4")) "Download" }
            };
        }
    }
    // The slug is validated lowercase/digits/hyphens, so it is a safe element id
    // and a safe literal inside the inline open handler.
    let dialog_id = format!("dl-{}", g.app_slug);
    html! {
        button type="button" class=(button_class("outline", "default", "w-full mt-2"))
            onclick=(format!("document.getElementById('{dialog_id}').showModal()")) {
            (icon("download", "mr-2 h-4 w-4")) "Download"
        }
        dialog id=(dialog_id) class="rounded-lg border bg-card text-card-foreground p-0 w-full max-w-lg backdrop:bg-black/50" {
            div class="p-6 space-y-4" {
                div class="flex items-center justify-between gap-4" {
                    h3 class="text-lg font-semibold" { (g.app_display_name) " downloads" }
                    button type="button" aria-label="Close" class=(button_class("outline", "sm", "shrink-0")) onclick="this.closest('dialog').close()" { (icon("x", "h-4 w-4")) }
                }
                ul class="space-y-3" {
                    @for opt in &opts { (download_option_row(opt)) }
                }
            }
        }
    }
}

/// A download-only card for a catalog product that is not a hosted hub tile
/// (so it has no Launch action). Keeps catalog-only distribution products
/// visible on the Applications page now that the standalone Downloads page is
/// retired. BUNYIP-100.
fn download_only_card(g: &AppDownloadGroup, is_member: bool) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50 transition-all hover:shadow-lg" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex h-12 w-12 items-center justify-center rounded-lg bg-muted" {
                    @if let Some(ic) = &g.icon_url { img src=(ic) alt=(g.app_display_name) class="h-6 w-6"; } @else { (icon("package", "h-6 w-6 text-muted-foreground")) }
                }
                h3 class="text-2xl font-semibold leading-none tracking-tight mt-4" { (g.app_display_name) }
            }
            div class="p-6 pt-0" {
                (download_affordance(g, is_member))
            }
        }
    }
}

/// Membership-gate link shown in place of download/pull actions.
fn upgrade_link() -> Markup {
    html! {
        a href="/membership" class="text-sm text-primary underline" { "Upgrade to access" }
    }
}

/// Static click handler shared by every copy button. It reads the command
/// from the button's own `data-copy` attribute at click time; no value is ever
/// spliced into this string, so it is identical for every block.
///
/// Clipboard API needs a secure context (HTTPS / localhost). When it is
/// unavailable, select the command text so the user can copy manually;
/// otherwise report success/failure on the button label. The in-button label
/// swap ("Copy" -> "Copied") fires for the local feedback affordance, AND a
/// toast pops top-right via `window.bunyipToast`. The `if(window.bunyipToast)`
/// guard keeps the button usable if the toast script failed to load.
const COPY_CMD_JS: &str = "var b=this;var t=b.innerText;var c=b.dataset.copy;\
     if(navigator.clipboard){\
       navigator.clipboard.writeText(c).then(\
         function(){b.innerText='Copied';setTimeout(function(){b.innerText=t},1500);\
                      if(window.bunyipToast)window.bunyipToast('Copied to clipboard','success');},\
         function(){b.innerText='Copy failed';setTimeout(function(){b.innerText=t},1500);\
                      if(window.bunyipToast)window.bunyipToast('Copy failed','error');});\
     }else{\
       window.getSelection().selectAllChildren(b.previousElementSibling);\
       b.innerText='Press Ctrl+C';setTimeout(function(){b.innerText=t},3000);\
     }";

/// A copy-pasteable shell command with a copy-to-clipboard button.
///
/// Trust model: `cmd` may carry API-sourced values (the registry host and
/// image reference that bunyip-api returns for a product). Those values are
/// rendered ONLY as passive, Maud-escaped content: the visible `<code>` text
/// and the button's `data-copy` attribute. The click handler is the static
/// `COPY_CMD_JS` constant, which reads the command from `this.dataset.copy` at
/// click time and never has API data interpolated into executable JS. This
/// removes the prior BFF-trust pattern where the command was spliced into the
/// inline onclick (the earlier `serde_json::to_string` only blocked raw-string
/// injection; it still shipped API data as executable content).
fn command_block(cmd: &str) -> Markup {
    html! {
        div class="flex items-center gap-2" {
            code class="flex-1 rounded bg-muted px-3 py-2 font-mono text-sm overflow-x-auto whitespace-nowrap" { (cmd) }
            button type="button" aria-label="Copy command" data-copy=(cmd) class=(button_class("outline", "sm", "shrink-0 w-28")) onclick=(COPY_CMD_JS) {
                "Copy"
            }
        }
    }
}

// ===========================================================================
// Billing
// ===========================================================================

/// Permanent redirect to `/membership` (HTTP 308). The two pages used to be
/// separate but rendered the same "no payment history yet" empty state and
/// confused users navigating between them; the membership page now absorbs the
/// invoices table and the sidebar drops the standalone Billing entry. The
/// route stays mapped so existing bookmarks land somewhere sensible. See
/// `docs/bunyip-upgrade/01-membership-plan-data.md`.
pub async fn billing(_: State<AppState>, _: HeaderMap) -> Response {
    axum::response::Redirect::permanent("/membership").into_response()
}

// ===========================================================================
// Checkout success
// ===========================================================================

pub async fn checkout_success(State(st): State<AppState>, headers: HeaderMap) -> Response {
    // authenticate() already refreshed claims via /me; that picks up the new membership.
    let (user, c) = match guard(&st, &headers, "/checkout/success").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Route through the same canonical helper the Membership card uses so
    // the user sees the same plan label here, on /membership, and on /pricing.
    let tier = tier_name(&user.subscription_tier);
    let content = html! {
        div class="flex items-center justify-center min-h-[70vh]" {
            div class="rounded-lg border bg-card text-card-foreground shadow-sm max-w-lg w-full border-border/50 overflow-hidden" {
                div class="h-1 bg-gradient-to-r from-teal-500 via-indigo-500 to-primary" {}
                div class="p-6 pt-8 pb-8 text-center space-y-6" {
                    div class="flex justify-center" { div class="rounded-full bg-gradient-to-br from-teal-500/20 to-teal-500/5 p-4" { (icon("check-circle", "h-12 w-12 text-teal-500")) } }
                    div class="space-y-2" {
                        h1 class="text-3xl font-bold" { "Welcome aboard" span class="text-gradient bg-gradient-to-r from-primary to-indigo-500" { "!" } }
                        p class="text-muted-foreground text-lg" { "Your membership is now active. You have full access to all applications." }
                    }
                    div class="bg-gradient-to-r from-indigo-500/5 via-primary/5 to-teal-500/5 rounded-lg p-4 space-y-2 text-sm border border-border/50" {
                        div class="flex items-center justify-center gap-2" { (icon("credit-card", "h-4 w-4 text-indigo-500")) span class="font-medium" { (tier) " Plan" } }
                        p class="text-muted-foreground" { "Your price is locked in for life - it will never increase." }
                    }
                    div class="flex flex-col gap-3 pt-2" {
                        a href="/applications" class=(button_class("default", "lg", "gap-2 bg-gradient-to-r from-primary to-indigo-500 text-white border-0")) { (icon("app-window", "h-4 w-4")) "Browse Applications" (icon("arrow-right", "h-4 w-4")) }
                        a href="/membership" class=(button_class("outline", "default", "")) { "View Membership Details" }
                    }
                    p class="text-xs text-muted-foreground" { "Redirecting to applications shortly…" }
                    script { (PreEscaped("setTimeout(function(){location.href='/applications'},10000);")) }
                }
            }
        }
    };
    dashboard_response(&c, &user, "/membership", "Welcome · Bunyip", content)
}

// ===========================================================================
// Membership required (error page)
// ===========================================================================

pub async fn membership_required(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/membership-required").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let content = html! {
        div class="flex min-h-[60vh] items-center justify-center px-4" {
            div class="rounded-lg border bg-card text-card-foreground shadow-sm w-full max-w-md" {
                div class="flex flex-col space-y-1.5 p-6 text-center" {
                    div class="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/10" { (icon("credit-card", "h-8 w-8 text-primary")) }
                    h3 class="text-2xl font-semibold leading-none tracking-tight" { "Membership Required" }
                    p class="text-sm text-muted-foreground" { "You need an active membership to access this content." }
                }
                div class="p-6 pt-0 space-y-4" {
                    p class="text-center text-muted-foreground" { "Subscribe to get access to all applications for just $3/month." }
                    div class="flex flex-col gap-4" {
                        a href="/membership" class=(button_class("default", "default", "w-full")) { "Subscribe Now" }
                        a href="/dashboard" class=(button_class("outline", "default", "w-full")) { (icon("arrow-left", "mr-2 h-4 w-4")) "Back to Dashboard" }
                    }
                }
            }
        }
    };
    dashboard_response(
        &c,
        &user,
        "/dashboard",
        "Membership required · Bunyip",
        content,
    )
}

// ===========================================================================
// Membership (view + actions)
// ===========================================================================

/// Canonical plan-name helper. The Membership card, the Settings "Account
/// Type" cell, and the public Pricing card all route through this so the
/// in-app name and the marketing-facing name never disagree. Renaming a tier
/// is a one-line change here that updates every consumer. Closes audit
/// finding 1 (plan name inconsistency). See
/// `docs/bunyip-upgrade/01-membership-plan-data.md`.
pub fn tier_name(t: &SubscriptionTier) -> &'static str {
    match t {
        SubscriptionTier::Lifetime => "Lifetime",
        SubscriptionTier::Free => "Free",
        SubscriptionTier::EarlyAdopter => "Early Adopter",
        SubscriptionTier::Standard => "Standard",
    }
}
fn status_label(s: &MembershipStatus) -> &'static str {
    match s {
        MembershipStatus::None => "none",
        MembershipStatus::Active => "active",
        MembershipStatus::PastDue => "past_due",
        MembershipStatus::Canceled => "canceled",
        MembershipStatus::Incomplete => "incomplete",
        MembershipStatus::GracePeriod => "grace_period",
    }
}

pub async fn membership(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/membership").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let current: Option<Membership> = calls::membership(&st.api, fwd).await.unwrap_or(None);
    let payments = calls::payment_history(&st.api, fwd)
        .await
        .unwrap_or_default();
    // The page now absorbs the invoices table that used to live on /billing;
    // /billing is a 308 redirect into this page. See docs/bunyip-upgrade/
    // 01-membership-plan-data.md.
    let invoices = calls::invoices(&st.api, fwd).await.unwrap_or_default();
    let stripe = auth_api::setup_status(&st.api)
        .await
        .map(|s| s.stripe_enabled)
        .unwrap_or(true);
    let tier = user.subscription_tier.clone();
    let status = current.as_ref().map(|m| m.status.clone());
    // Lifetime members get a stripped-down card: plan name + an explanatory
    // line, NO price, NO next-billing field, NO cancel buttons. Subscribers
    // keep the existing card shape. The `has` guard explicitly excludes
    // lifetime so a lifetime user with a stray Active row from the legacy
    // billing flow never sees Cancel UI either (defense in depth).
    let lifetime = user.lifetime_member;
    let has = !lifetime
        && matches!(
            status,
            Some(MembershipStatus::Active)
                | Some(MembershipStatus::PastDue)
                | Some(MembershipStatus::GracePeriod)
        );
    let past_due = matches!(status, Some(MembershipStatus::PastDue));
    let will_cancel = current
        .as_ref()
        .map(|m| m.cancel_at_period_end)
        .unwrap_or(false);

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Membership & Billing" } p class="mt-2 text-muted-foreground" { "Your plan, status, and invoices." } }
            @if past_due {
                div class="rounded-lg border border-destructive/50 p-4 text-sm text-destructive flex items-center gap-2" {
                    (icon("alert-triangle", "h-4 w-4")) "Your payment failed. Update your payment method within 30 days to avoid losing access."
                }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50 overflow-hidden" {
                div class="h-1 bg-gradient-to-r from-primary via-indigo-500 to-teal-500" {}
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center justify-between" {
                        div class="flex items-center gap-3" {
                            div class="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-indigo-500" { (icon("credit-card", "h-4 w-4 text-white")) }
                            h3 class="text-2xl font-semibold leading-none tracking-tight" { "Current Plan" }
                        }
                        (membership_badge(&user))
                    }
                }
                div class="p-6 pt-0 space-y-4" {
                    @if lifetime {
                        // Lifetime members already see the "Lifetime" badge
                        // top-right of the card, so repeating it in a
                        // "Plan: Lifetime" and "Access: Lifetime - no billing"
                        // grid is a stutter. The badge carries the identity;
                        // the body just has to convey what makes lifetime
                        // different from a paid plan: no billing, no expiry.
                        // (BUNYIP-91.)
                        p class="text-sm text-muted-foreground" { "No billing. Access never expires." }
                    } @else if has {
                        // `has` is driven by membership_status (Active or
                        // PastDue) but `current` is loaded separately from
                        // the API. A successful status + missing current row
                        // is rare but representable, so the unwrap previously
                        // here was brittle: a future API hiccup could panic
                        // the Maud thread. Couple the field access to a
                        // matching guard; a missing `current` simply renders
                        // nothing in this branch.
                        @if let Some(m) = current.clone() {
                            div class="grid gap-4 md:grid-cols-2" {
                                div { p class="text-sm text-muted-foreground" { "Plan" } p class="font-medium" { (tier_name(&tier)) } }
                                div { p class="text-sm text-muted-foreground" { "Price" } p class="font-medium" { @if m.price_locked { @if let Some(a)=m.locked_price_amount { "$" (a/100) "/month" } @else { "$3/month" } } @else { "$3/month" } } }
                                div { p class="text-sm text-muted-foreground" { "Status" } p class="font-medium" { (status_label(&m.status)) } }
                                div { p class="text-sm text-muted-foreground" { "Next Billing" } p class="font-medium" {
                                    @let end = m.current_period_end.as_deref().map(fmt_date_iso).unwrap_or_else(|| "N/A".into());
                                    @if will_cancel { "Canceled - ends " (end) } @else { (end) } } }
                            }
                            div class="flex gap-4 pt-4" {
                                @if will_cancel {
                                    form method="post" action="/membership/reactivate" { button type="submit" class=(button_class("default", "default", "bg-gradient-to-r from-primary to-indigo-500 text-white border-0")) { "Reactivate Membership" } }
                                } @else {
                                    form method="post" action="/membership/cancel" { button type="submit" class=(button_class("outline", "default", "")) { "Cancel Membership" } }
                                    form method="post" action="/membership/cancel-now" onsubmit="return confirm('Cancel immediately? You will lose access right now.')" { button type="submit" class=(button_class("destructive", "default", "")) { "Cancel Now" } }
                                }
                            }
                        }
                    } @else {
                        div class="py-8" {
                            div class="text-center mb-8" {
                                div class="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-indigo-500/20 to-teal-500/20" { (icon("credit-card", "h-8 w-8 text-indigo-500")) }
                                h3 class="text-lg font-semibold mb-2" { "No Active Membership" }
                                p class="text-muted-foreground" { "Subscribe to access all applications." }
                            }
                            div class="text-center" {
                                @if stripe {
                                    form method="post" action="/membership/subscribe" { button type="submit" class=(button_class("default", "lg", "gap-2 bg-gradient-to-r from-primary to-indigo-500 text-white border-0")) { "Subscribe " (icon("arrow-right", "h-4 w-4")) } }
                                } @else {
                                    button type="button" disabled title="Payment is not configured" class=(button_class("default", "lg", "bg-gradient-to-r from-primary to-indigo-500 text-white border-0")) { "Subscribe" }
                                }
                            }
                        }
                    }
                }
            }
            // Invoices (lifted from the retired /billing page). Always
            // renders so a one-off charge or refund still surfaces;
            // empty-state copy covers the common lifetime-member case.
            div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Invoices" } p class="text-sm text-muted-foreground" { "Your billing history" } }
                div class="p-6 pt-0" {
                    @if invoices.is_empty() {
                        div class="flex flex-col items-center justify-center py-12 text-center" {
                            (icon("file-text", "h-10 w-10 text-muted-foreground mb-3"))
                            p class="text-muted-foreground" { "No invoices yet." }
                        }
                    } @else {
                        div class="divide-y" {
                            @for inv in &invoices {
                                div class="flex items-center justify-between py-4" {
                                    div class="space-y-1" {
                                        @if let Some(n) = &inv.number { p class="font-medium text-sm" { (n) } }
                                        @if let Some(d) = &inv.description { p class="text-sm text-muted-foreground" { (d) } }
                                        p class="text-xs text-muted-foreground" { (fmt_ts(inv.created)) }
                                    }
                                    div class="flex items-center gap-4" {
                                        span class="text-sm font-medium" { (fmt_currency(inv.amount_paid, &inv.currency)) }
                                        @if let Some(u) = inv.hosted_invoice_url.clone().or_else(|| inv.invoice_pdf.clone()) {
                                            a href=(u) target="_blank" rel="noopener noreferrer" class=(button_class("outline", "sm", "")) { (icon("external-link", "h-4 w-4 mr-1")) "View" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight" { "Payment History" } }
                div class="p-6 pt-0" {
                    @if payments.is_empty() { p class="text-center text-muted-foreground py-8" { "No payment history yet." } }
                    @else {
                        div class="space-y-4" {
                            @for p in &payments {
                                div class="flex items-center justify-between py-3 border-b border-border/50 last:border-0" {
                                    div class="flex items-center gap-4" {
                                        div class="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-teal-500/20 to-teal-500/5" { (icon("check-circle", "h-5 w-5 text-teal-600 dark:text-teal-400")) }
                                        div { p class="font-medium" { (fmt_currency(p.amount, &p.currency)) } p class="text-sm text-muted-foreground" { (fmt_ts(p.created)) } }
                                    }
                                    (badge("outline", p.status.clone().unwrap_or_default().as_str()))
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    dashboard_response(
        &c,
        &user,
        "/membership",
        "Membership & Billing · Bunyip",
        content,
    )
}

pub async fn membership_subscribe(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (_, c) = match guard(&st, &headers, "/membership").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match calls::checkout(&st.api, c.forward.as_deref(), None).await {
        Ok(s) if s.checkout_url.starts_with("https://checkout.stripe.com/") => {
            redirect_cookies(&s.checkout_url, &c.set_cookies)
        }
        _ => redirect_cookies("/membership", &c.set_cookies),
    }
}
pub async fn membership_cancel(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (_, c) = match guard(&st, &headers, "/membership").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let extra = calls::cancel(&st.api, c.forward.as_deref())
        .await
        .unwrap_or_default();
    let mut cookies = c.set_cookies.clone();
    cookies.extend(extra);
    redirect_cookies("/membership", &cookies)
}
pub async fn membership_cancel_now(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (_, c) = match guard(&st, &headers, "/membership").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let extra = calls::cancel_now(&st.api, c.forward.as_deref())
        .await
        .unwrap_or_default();
    let mut cookies = c.set_cookies.clone();
    cookies.extend(extra);
    redirect_cookies("/membership", &cookies)
}
pub async fn membership_reactivate(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (_, c) = match guard(&st, &headers, "/membership").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let extra = calls::reactivate(&st.api, c.forward.as_deref())
        .await
        .unwrap_or_default();
    let mut cookies = c.set_cookies.clone();
    cookies.extend(extra);
    redirect_cookies("/membership", &cookies)
}

// ===========================================================================
// Settings (view + actions)
// ===========================================================================

#[derive(Deserialize)]
pub struct SettingsQuery {
    pub ok: Option<String>,
    pub error: Option<String>,
}

pub async fn settings(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SettingsQuery>,
) -> Response {
    let (user, c) = match guard(&st, &headers, "/settings").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let twofa = auth_api::status_2fa(&st.api, fwd).await.ok();
    let twofa_enabled = twofa
        .as_ref()
        .map(|s| s.enabled)
        .unwrap_or(user.two_factor_enabled);
    let is_admin = matches!(user.role, crate::api::types::UserRole::Admin);

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Settings" } p class="mt-2 text-muted-foreground" { "Manage your account settings and preferences." } }
            @if let Some(ok) = &q.ok { div class="rounded-lg border p-3 text-sm flex items-center gap-2" { (icon("check", "h-4 w-4 text-teal-600 dark:text-teal-400")) (clamp_msg(ok)) } }
            @if let Some(e) = &q.error { (error_box(&clamp_msg(e))) }

            // Account info
            div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50 overflow-hidden" {
                div class="h-1 bg-gradient-to-r from-primary via-indigo-500 to-teal-500" {}
                div class="flex flex-col space-y-1.5 p-6" {
                    div class="flex items-center gap-3" { div class="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-indigo-500" { (icon("user", "h-4 w-4 text-white")) } h3 class="text-2xl font-semibold leading-none tracking-tight" { "Account Information" } }
                }
                div class="p-6 pt-0 space-y-4" {
                    div class="grid gap-4 md:grid-cols-2" {
                        div { p class="text-sm text-muted-foreground" { "Email" } p class="font-medium" { (user.email) } }
                        div { p class="text-sm text-muted-foreground" { "Account Type" } p class="font-medium flex items-center gap-2" { @if is_admin { "admin" (badge("default", "Admin")) } @else { (tier_name(&user.subscription_tier)) } } }
                        div { p class="text-sm text-muted-foreground" { "Email Verified" } p class="font-medium flex items-center gap-2" { @if user.email_verified { (icon("check", "h-4 w-4 text-teal-600 dark:text-teal-400")) "Verified" } @else { (icon("alert-circle", "h-4 w-4 text-yellow-600")) "Not Verified" } } }
                        div { p class="text-sm text-muted-foreground" { "Membership Status" } p class="font-medium" { (status_label(&user.membership_status)) } }
                    }
                }
            }

            // Change email. autocomplete="off" on the form + value="" on the
            // new-email input defeat the password-manager's "fill in the
            // saved username" heuristic that was leaving the field already
            // populated with the user's current email (audit finding 3).
            // current_password also takes autocomplete="off" here - this is
            // confirmation-of-identity, not a sign-in form, so we don't want
            // the manager filling it.
            (settings_card("mail", "from-primary to-teal-500", "Change Email", html! {
                form method="post" action="/settings/email" autocomplete="off" class="space-y-4 max-w-md" {
                    div class="space-y-2" { label class="text-sm font-medium" { "New Email Address" } input name="new_email" type="email" value="" autocomplete="off" placeholder="Enter your new email" class=(crate::handlers::dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "Current Password" } input name="current_password" type="password" autocomplete="off" placeholder="Enter your current password" class=(crate::handlers::dashboard_input()); }
                    button type="submit" class=(button_class("default", "default", "bg-gradient-to-r from-primary to-teal-500 text-white border-0")) { "Change Email" }
                }
            }))

            // Change password. This is the one Settings form where the
            // password manager SHOULD help: current-password lets it fill
            // the saved value, new-password lets it offer to save the
            // updated credential after submit.
            (settings_card("lock", "from-indigo-500 to-teal-500", "Change Password", html! {
                form method="post" action="/settings/password" class="space-y-4 max-w-md" {
                    div class="space-y-2" { label class="text-sm font-medium" { "Current Password" } input name="current_password" type="password" autocomplete="current-password" class=(crate::handlers::dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "New Password" } input name="new_password" type="password" autocomplete="new-password" class=(crate::handlers::dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "Confirm Password" } input name="confirm" type="password" autocomplete="new-password" class=(crate::handlers::dashboard_input()); }
                    button type="submit" class=(button_class("default", "default", "bg-gradient-to-r from-primary to-indigo-500 text-white border-0")) { "Update Password" }
                }
            }))

            // 2FA
            (settings_card("shield", "from-teal-500 to-indigo-500", "Two-Factor Authentication", html! {
                @if twofa_enabled {
                    div class="space-y-4" {
                        div class="flex items-center gap-2" { (icon("shield-check", "h-5 w-5 text-teal-600 dark:text-teal-400")) span class="font-medium" { "Enabled" } (badge("success", "Active")) }
                        @if !is_admin {
                            form method="post" action="/settings/2fa/disable" class="space-y-2 max-w-md" {
                                div class="space-y-2" { label class="text-sm font-medium" { "Password" } input name="password" type="password" class=(crate::handlers::dashboard_input()); }
                                button type="submit" class=(button_class("outline", "sm", "text-destructive hover:text-destructive")) { (icon("shield-off", "mr-2 h-4 w-4")) "Disable 2FA" }
                            }
                        } @else { p class="text-xs text-muted-foreground" { "Admin accounts cannot disable two-factor authentication." } }
                    }
                } @else {
                    div class="space-y-4" {
                        div class="flex items-center gap-2" { (icon("shield-off", "h-5 w-5 text-muted-foreground")) span class="font-medium text-muted-foreground" { "Not enabled" } }
                        a href="/settings/2fa/setup" class=(button_class("default", "default", "bg-gradient-to-r from-teal-500 to-indigo-500 text-white border-0")) { (icon("shield", "mr-2 h-4 w-4")) "Enable Two-Factor Authentication" }
                    }
                }
            }))

            // Danger zone
            div class="rounded-lg border bg-card text-card-foreground shadow-sm border-red-200 dark:border-red-900" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight text-red-600 dark:text-red-400 flex items-center gap-2" { (icon("alert-triangle", "h-5 w-5")) "Danger Zone" } p class="text-sm text-muted-foreground" { "Permanently delete your account and all associated data." } }
                div class="p-6 pt-0" {
                    // Delete account. autocomplete="off" on the form + on the
                    // password input together suppress the password-manager
                    // pre-fill that auditor finding 4 flagged on this danger-
                    // zone form. TOTP gets the spec-aligned one-time-code
                    // hint so the manager (or iOS / Chrome AutoFill) can
                    // surface a freshly-arrived SMS / TOTP code from a sibling
                    // tab WITHOUT pre-filling the password field.
                    form method="post" action="/settings/account/delete" autocomplete="off" class="space-y-3 max-w-md" onsubmit="return confirm('Permanently delete your account? This cannot be undone.')" {
                        div class="space-y-2" { label class="text-sm font-medium" { "Password" } input name="password" type="password" autocomplete="off" placeholder="Enter your password to confirm" class=(crate::handlers::dashboard_input()); }
                        @if user.two_factor_enabled { div class="space-y-2" { label class="text-sm font-medium" { "Two-Factor Code" } input name="totp_code" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code" class=(crate::handlers::dashboard_input()); } }
                        button type="submit" class=(button_class("destructive", "default", "")) { (icon("trash", "mr-2 h-4 w-4")) "Delete My Account" }
                    }
                }
            }
        }
    };
    dashboard_response(&c, &user, "/settings", "Settings · Bunyip", content)
}

fn settings_card(icon_name: &str, gradient: &str, title: &str, body: Markup) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50" {
            div class="flex flex-col space-y-1.5 p-6" {
                div class="flex items-center gap-3" { div class={ "flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br " (gradient) } { (icon(icon_name, "h-4 w-4 text-white")) } h3 class="text-2xl font-semibold leading-none tracking-tight" { (title) } }
            }
            div class="p-6 pt-0" { (body) }
        }
    }
}

#[derive(Deserialize)]
pub struct EmailChangeForm {
    pub new_email: String,
    #[serde(default)]
    pub current_password: String,
}
pub async fn settings_email(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<EmailChangeForm>,
) -> Response {
    let (_, c) = match guard(&st, &headers, "/settings").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match auth_api::request_email_change(
        &st.api,
        c.forward.as_deref(),
        f.new_email.trim(),
        &f.current_password,
    )
    .await
    {
        Ok((relogin, mut cookies)) => {
            let mut all = c.set_cookies.clone();
            all.append(&mut cookies);
            if relogin {
                redirect_cookies("/login", &all)
            } else {
                redirect_cookies("/settings?ok=Email+change+requested", &all)
            }
        }
        Err(e) => redirect_cookies(
            &format!("/settings?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

#[derive(Deserialize)]
pub struct PasswordChangeForm {
    pub current_password: String,
    pub new_password: String,
    pub confirm: String,
}
pub async fn settings_password(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<PasswordChangeForm>,
) -> Response {
    let (_, c) = match guard(&st, &headers, "/settings").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !password_ok(&f.new_password) || f.new_password != f.confirm {
        let e = if f.new_password != f.confirm {
            "Passwords don't match"
        } else {
            "Password does not meet the requirements"
        };
        return redirect_cookies(&format!("/settings?error={}", urlenc(e)), &c.set_cookies);
    }
    match auth_api::change_password(
        &st.api,
        c.forward.as_deref(),
        &f.current_password,
        &f.new_password,
    )
    .await
    {
        Ok(()) => redirect_cookies("/settings?ok=Password+updated", &c.set_cookies),
        Err(e) => redirect_cookies(
            &format!("/settings?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

#[derive(Deserialize)]
pub struct DisableForm {
    pub password: String,
}
pub async fn settings_disable_2fa(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<DisableForm>,
) -> Response {
    let (_, c) = match guard(&st, &headers, "/settings").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match auth_api::disable_2fa(&st.api, c.forward.as_deref(), &f.password).await {
        Ok(()) => redirect_cookies("/settings?ok=Two-factor+disabled", &c.set_cookies),
        Err(e) => redirect_cookies(
            &format!("/settings?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

#[derive(Deserialize)]
pub struct DeleteForm {
    pub password: String,
    #[serde(default)]
    pub totp_code: String,
}
pub async fn settings_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<DeleteForm>,
) -> Response {
    let (_, c) = match guard(&st, &headers, "/settings").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Account deletion is irreversible; require a non-empty password at the
    // edge instead of forwarding a blank credential to the API (BUNYIP-116).
    if f.password.trim().is_empty() {
        return redirect_cookies(
            &format!(
                "/settings?error={}",
                urlenc("Enter your current password to confirm account deletion.")
            ),
            &c.set_cookies,
        );
    }
    let totp = if f.totp_code.is_empty() {
        None
    } else {
        Some(f.totp_code.as_str())
    };
    match auth_api::delete_account(&st.api, c.forward.as_deref(), &f.password, totp).await {
        Ok(mut cookies) => {
            let mut all = c.set_cookies.clone();
            all.append(&mut cookies);
            redirect_cookies("/", &all)
        }
        Err(e) => redirect_cookies(
            &format!("/settings?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

/// Cap a user-supplied `?ok=`/`?error=` query-param message before it is
/// rendered. The value is already Maud-escaped (so this is not an XSS guard);
/// it bounds a hand-crafted link that stuffs the param with kilobytes of text
/// to blow up the page. ~256 bytes is ample for the short status strings these
/// params legitimately carry. Truncation lands on a char boundary.
fn clamp_msg(s: &str) -> String {
    const MAX: usize = 256;
    if s.len() <= MAX {
        return s.to_string();
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// ===========================================================================
// 2FA setup (QR + verify -> recovery codes)
// ===========================================================================

fn qr_svg(uri: &str) -> String {
    qrcode::QrCode::new(uri.as_bytes())
        .map(|code| {
            code.render::<qrcode::render::svg::Color>()
                .min_dimensions(200, 200)
                .quiet_zone(false)
                .build()
        })
        .unwrap_or_default()
}

/// Single Maud renderer for the 2FA enrollment view: QR + manual key + the
/// verification-code form. Used by BOTH the GET handler (no error) and the
/// POST error path (error banner above the code input). Keeping a single
/// renderer means the QR / manual key / submit button are guaranteed to
/// match across the entry render and any retry render, which is the whole
/// point of audit finding 6: a wrong code MUST NOT make the QR disappear.
///
/// Caller passes `setup` (the bunyip-api `/v1/auth/2fa/setup` response, which
/// the upstream handler MUST return the SAME in-progress secret for during
/// enrollment - see `docs/bunyip-upgrade/04-2fa-error-state-preserves-form.md`).
fn twofa_setup_view(setup: &TwoFactorSetupResponse, error: Option<&str>) -> Markup {
    html! {
        div class="mx-auto max-w-lg space-y-6" {
            div { h1 class="text-3xl font-bold" { "Set Up Two-Factor Authentication" } p class="mt-2 text-muted-foreground" { "Scan the QR code, then enter a code to confirm." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50" {
                div class="p-6 space-y-6" {
                    div class="flex justify-center rounded-lg bg-white p-4" { div class="[&_svg]:h-[200px] [&_svg]:w-[200px]" { (PreEscaped(qr_svg(&setup.otpauth_uri))) } }
                    div class="space-y-2" {
                        label class="text-sm text-muted-foreground" { "Or enter this key manually:" }
                        code class="block rounded bg-muted px-3 py-2 text-sm font-mono break-all" { (setup.secret) }
                    }
                    @if let Some(msg) = error {
                        (error_box(msg))
                    }
                    form method="post" action="/settings/2fa/setup" class="space-y-4" {
                        div class="space-y-2" { label class="text-sm font-medium" { "Verification Code" } input name="code" inputmode="numeric" placeholder="000000" autocomplete="one-time-code" class=(crate::handlers::dashboard_input()); }
                        button type="submit" class=(button_class("default", "default", "w-full")) { "Verify & Enable" }
                    }
                }
            }
        }
    }
}

pub async fn twofa_setup_get(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/settings/2fa/setup").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let content = match auth_api::setup_2fa(&st.api, fwd).await {
        Ok(setup) => twofa_setup_view(&setup, None),
        Err(e) => html! { div class="mx-auto max-w-lg" { (error_box(&e.user_message())) } },
    };
    dashboard_response(&c, &user, "/settings", "Two-factor setup · Bunyip", content)
}

#[derive(Deserialize)]
pub struct TwoFactorSetupForm {
    pub code: String,
}
pub async fn twofa_setup_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TwoFactorSetupForm>,
) -> Response {
    let (user, c) = match guard(&st, &headers, "/settings/2fa/setup").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let content = match auth_api::confirm_2fa(&st.api, fwd, f.code.trim()).await {
        Ok(codes) => html! {
            div class="mx-auto max-w-lg space-y-6" {
                div { h1 class="text-3xl font-bold" { "Two-Factor Authentication Enabled" } p class="mt-2 text-muted-foreground" { "Save your recovery codes in a safe place." } }
                div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50" {
                    div class="p-6 space-y-4" {
                        div class="rounded-lg border p-3 text-sm flex items-start gap-3" { (icon("alert-circle", "h-4 w-4 mt-0.5")) p class="text-sm" { "Save these codes now. You won't be able to see them again." } }
                        div class="grid grid-cols-2 gap-2 rounded-lg bg-muted p-4" { @for code in &codes.codes { code class="text-center font-mono text-sm py-1" { (code) } } }
                        a href="/settings" class=(button_class("default", "default", "w-full")) { "Done" }
                    }
                }
            }
        },
        Err(e) => {
            // Re-fetch the in-progress secret so the QR + manual key render
            // identically to what the user is currently scanning. bunyip-api
            // returns the SAME pending secret while an enrollment is in
            // flight (see the API-side note in
            // docs/bunyip-upgrade/04-2fa-error-state-preserves-form.md). If
            // that re-fetch itself fails (network blip, session timeout),
            // fall through to the legacy banner-only error so the user can
            // restart enrollment manually.
            let err_msg = e.user_message();
            match auth_api::setup_2fa(&st.api, fwd).await {
                Ok(setup) => twofa_setup_view(&setup, Some(&err_msg)),
                Err(_) => html! {
                    div class="mx-auto max-w-lg space-y-4" {
                        (error_box(&err_msg))
                        a href="/settings/2fa/setup" class=(button_class("outline", "default", "")) { "Try again" }
                    }
                },
            }
        }
    };
    dashboard_response(&c, &user, "/settings", "Two-factor setup · Bunyip", content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{MembershipStatus, SubscriptionTier, User, UserRole};

    fn user(role: UserRole, status: MembershipStatus) -> User {
        User {
            id: "u1".into(),
            email: "u@example.com".into(),
            role,
            email_verified: true,
            two_factor_enabled: false,
            membership_status: status,
            price_locked: false,
            locked_price_id: None,
            locked_price_amount: None,
            created_at: String::new(),
            updated_at: String::new(),
            subscription_tier: SubscriptionTier::Free,
            trial_ends_at: None,
            lifetime_member: false,
        }
    }

    #[test]
    fn admin_badge_shows_admin_not_no_membership() {
        // BUNYIP-108: an admin has all-access, so the badge must not read
        // "No Membership" (which contradicted "You have access to all
        // applications" on the dashboard).
        let markup = membership_badge(&user(UserRole::Admin, MembershipStatus::None)).into_string();
        assert!(markup.contains("Admin"));
        assert!(!markup.contains("No Membership"));
    }

    #[test]
    fn non_admin_without_membership_still_shows_no_membership() {
        let markup =
            membership_badge(&user(UserRole::Subscriber, MembershipStatus::None)).into_string();
        assert!(markup.contains("No Membership"));
    }

    #[test]
    fn non_admin_active_shows_active() {
        let markup =
            membership_badge(&user(UserRole::Subscriber, MembershipStatus::Active)).into_string();
        assert!(markup.contains("Active"));
    }
}
