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
    AppDownloadGroup, Application, Membership, MembershipStatus, OciImage, SubscriptionTier,
    TwoFactorSetupResponse, User,
};
use crate::handlers::{dashboard_response, guard, needs_onboarding, password_ok, rotating_index};
use crate::util::{app_gradient, days_until, has_active_membership, urlenc};
use crate::views::ui::{badge, button_class, error_box, icon, success_box};
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

    // BUNYIP-206: the passive "finish your profile" name banner was removed -
    // the forced /onboarding gate (handlers::mod::guard) now guarantees a name
    // is set before the dashboard is reachable, so the nudge is dead code.

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

/// BUNYIP-329: decide where `/community` sends the caller. A member with a
/// configured Let's Chat URL is redirected into it (authenticated via their
/// existing OP session); a non-member is sent to the membership upsell; and if
/// the feature is unconfigured there is nowhere to go, so fall back to the
/// dashboard. Pure so the routing decision is unit-testable without a request.
fn community_redirect_target(community_url: &str, is_member: bool) -> &str {
    match (is_member, community_url.is_empty()) {
        (true, false) => community_url,
        (false, _) => "/membership",
        (true, true) => "/dashboard",
    }
}

/// GET /community - drop an authenticated member into the team Let's Chat
/// ("Community") instance (BUNYIP-329). The target URL already runs Let's
/// Chat's OIDC client against bunyip-api, so the member's existing OP session
/// logs them in with no separate login (the same single-sign-in bridge the app
/// tiles use). Non-members are routed to the membership upsell instead.
pub async fn community(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/community").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let is_member = has_active_membership(Some(&user));
    let target = community_redirect_target(&st.cfg.community_url, is_member);
    redirect_cookies(target, &c.set_cookies)
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
                // BUNYIP-343: link to the app's release notes (its Forgejo
                // releases page) when the repo association is configured, so
                // users can see what changed. Opens in a new tab like Launch.
                @if let Some(notes) = app.release_notes_url.as_deref().filter(|s| !s.is_empty()) {
                    a href=(notes) target="_blank" rel="noopener noreferrer" {
                        span class=(button_class("outline", "default", "w-full mt-2")) { "Release notes" (icon("file-text", "ml-2 h-4 w-4")) }
                    }
                }
                // BUNYIP-388: public per-application documentation.
                a href=(format!("/apps/{}/docs", app.slug)) {
                    span class=(button_class("outline", "default", "w-full mt-2")) { "Documentation" (icon("file-text", "ml-2 h-4 w-4")) }
                }
                // BUNYIP-353: the Backup add-on is configured in-app rather than
                // launched to an external subdomain.
                @if app.slug == "backup" {
                    a href="/integrations/backup" {
                        span class=(button_class("outline", "default", "w-full")) { "Backup & Restore" (icon("settings", "ml-2 h-4 w-4")) }
                    }
                }
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

/// A numbered instruction step: a bold "N. Title" line above its body (a copy
/// block, a download button, or plain text). BUNYIP-358.
fn instruction_step(n: u32, title: &str, body: Markup) -> Markup {
    html! {
        li class="space-y-1" {
            div class="text-sm font-medium" { (n) ". " (title) }
            (body)
        }
    }
}

/// Docker pull-and-run instructions for a product's OCI image: a prerequisite
/// line plus numbered steps (sign in if the registry is private, pull, then
/// either a one-shot `docker run` or a copy-pasteable Docker Compose skeleton).
/// Docker only, per the BUNYIP-358 decision. No digest-verify step: `reference`
/// is tag-pinned and the API exposes no separate digest to check against. The
/// compose skeleton stays app-agnostic (image interpolated, ports/env/volumes
/// left as operator-filled placeholders), since this helper is shared across
/// every OCI-shipping app.
fn container_instructions(oci: &OciImage) -> Markup {
    let compose = format!(
        "services:\n  app:\n    image: {}\n    restart: unless-stopped\n    # Add the ports, environment, and volumes this app needs, e.g.:\n    # ports:\n    #   - \"8080:8080\"\n",
        oci.reference
    );
    html! {
        section class="space-y-3" {
            div class="flex items-center gap-2" {
                (icon("package", "h-4 w-4 text-muted-foreground"))
                h4 class="font-semibold" { "Container image" }
            }
            p class="text-sm text-muted-foreground" {
                "Requires Docker installed. Pulls " code class="font-mono" { (oci.reference) } "."
            }
            ol class="space-y-3" {
                (instruction_step(1, "Sign in to the registry (only if it is private)", command_block(&format!("docker login {}", oci.registry))))
                (instruction_step(2, "Pull the image", command_block(&format!("docker pull {}", oci.reference))))
                (instruction_step(3, "Run it (a starting point; add the ports, env, and volumes the app needs)", command_block(&format!("docker run --rm {}", oci.reference))))
                (instruction_step(4, "Or deploy with Docker Compose (save as compose.yml)", html! {
                    div class="space-y-2" {
                        (compose_block(&compose))
                        (command_block("docker compose up -d"))
                    }
                }))
            }
        }
    }
}

/// Download-and-run instructions for each binary asset. The download uses the
/// same-origin BFF proxy (`/downloads/...`); the API's `download_url` is not
/// browser-reachable. No checksum-verify step: the download API exposes no
/// per-asset checksum yet (a BUNYIP-358 follow-up would add one here).
fn binary_instructions(g: &AppDownloadGroup) -> Markup {
    html! {
        @for a in &g.assets {
            @let href = format!(
                "/downloads/{}/{}",
                urlencoding::encode(&g.app_slug),
                urlencoding::encode(&a.asset_name)
            );
            section class="space-y-3" {
                div class="flex flex-wrap items-center gap-2" {
                    (icon("download", "h-4 w-4 text-muted-foreground"))
                    h4 class="font-semibold" { "Binary" }
                    span class="font-mono text-xs text-muted-foreground break-all" { (a.asset_name) " (" (format_size(a.size_bytes)) ")" }
                }
                ol class="space-y-3" {
                    // No `download` attribute: the proxy's Content-Disposition drives
                    // the save, and an error response navigates rather than saving an
                    // error body as the file (BUNYIP-64).
                    (instruction_step(1, "Download the file", html! {
                        a href=(href) class=(button_class("default", "default", "")) {
                            (icon("download", "mr-2 h-4 w-4")) "Download " (a.asset_name)
                        }
                    }))
                    (instruction_step(2, "Make it executable and run", command_block(&format!("chmod +x {name} && ./{name} --help", name = a.asset_name))))
                }
            }
        }
    }
}

/// The Download affordance for an application card: a button that opens a
/// `<dialog>` of step-by-step download/pull instructions - a Docker section when
/// the product ships an OCI image, and a section per binary asset. Members only;
/// non-members get an upgrade prompt. Renders nothing when the product has no
/// downloads. BUNYIP-100 / BUNYIP-358.
fn download_affordance(g: &AppDownloadGroup, is_member: bool) -> Markup {
    let has_binary = !g.assets.is_empty();
    let has_oci = g.oci.is_some();
    if !has_binary && !has_oci {
        return html! {};
    }
    if !is_member {
        return html! { div class="mt-2 text-center" { (upgrade_link()) } };
    }
    // Label the affordance by the distribution surfaces this product offers:
    // binary assets only ("Download"), an OCI image only ("OCI"), or both
    // ("Download/OCI"). BUNYIP-289.
    let label = match (has_binary, has_oci) {
        (true, true) => "Download/OCI",
        (false, true) => "OCI",
        _ => "Download",
    };
    // The slug is validated lowercase/digits/hyphens, so it is a safe element id
    // and a safe literal inside the inline open handler. BUNYIP-358 always opens
    // the dialog (even for a lone binary) so the instructions are always shown.
    let dialog_id = format!("dl-{}", g.app_slug);
    html! {
        button type="button" class=(button_class("outline", "default", "w-full mt-2"))
            onclick=(format!("document.getElementById('{dialog_id}').showModal()")) {
            (icon("download", "mr-2 h-4 w-4")) (label)
        }
        // `m-auto` restores the native modal-dialog centering that Tailwind v4
        // Preflight removes (it resets `margin:0` on `*`, so the UA's
        // `dialog:modal { margin:auto }` no longer applies and the dialog pins
        // to the top-left). BUNYIP-289.
        dialog id=(dialog_id) class="m-auto rounded-lg border bg-card text-card-foreground p-0 w-full max-w-lg backdrop:bg-black/50" {
            div class="p-6 space-y-6 max-h-[80vh] overflow-y-auto" {
                div class="flex items-center justify-between gap-4" {
                    h3 class="text-lg font-semibold" { (g.app_display_name) " downloads" }
                    button type="button" aria-label="Close" class=(button_class("outline", "sm", "shrink-0")) onclick="this.closest('dialog').close()" { (icon("x", "h-4 w-4")) }
                }
                @if let Some(oci) = &g.oci { (container_instructions(oci)) }
                @if has_binary { (binary_instructions(g)) }
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

/// A copy-pasteable multi-line snippet (e.g. a `compose.yml`) with a copy
/// button. Like [`command_block`] but preserves newlines instead of forcing a
/// single line, for block content. Same trust model: the snippet is passive,
/// Maud-escaped `<code>` text plus the button's `data-copy` attribute; the
/// click handler is the static `COPY_CMD_JS` constant and never has API data
/// interpolated into executable JS.
fn compose_block(snippet: &str) -> Markup {
    html! {
        div class="flex items-start gap-2" {
            pre class="flex-1 rounded bg-muted px-3 py-2 font-mono text-sm overflow-x-auto" {
                code class="whitespace-pre" { (snippet) }
            }
            button type="button" aria-label="Copy compose file" data-copy=(snippet) class=(button_class("outline", "sm", "shrink-0 w-28")) onclick=(COPY_CMD_JS) {
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
    // BUNYIP-225: gate the "Welcome aboard" success copy on the user's
    // actual subscription_status, not just the tier string. The tier was
    // set at signup and stays "standard" forever for most users, so the
    // page used to confidently render success even when the webhook had
    // not flipped status to Active (e.g. signature-mismatch dropping the
    // delivery, or a 5-second race between the Stripe redirect and the
    // webhook landing). Read the live status; if it is not yet Active,
    // render a "Finalizing your subscription..." card that auto-refreshes
    // until the webhook lands. Lifetime members and any user already
    // Active see the celebration unchanged.
    let fwd = c.forward.as_deref();
    let membership = calls::membership(&st.api, fwd).await.unwrap_or(None);
    let is_active = user.lifetime_member
        || membership
            .as_ref()
            .map(|m| matches!(m.status, MembershipStatus::Active))
            .unwrap_or(false);
    let tier = tier_name(&user.subscription_tier);
    let content = if is_active {
        html! {
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
        }
    } else {
        // Stripe Checkout has redirected the user here, but the webhook that
        // flips subscription_status to Active has not landed yet. Two normal
        // causes: (a) network delay between the Stripe redirect and Stripe
        // firing the `checkout.session.completed` event (typically <5s); (b)
        // bunyip-api is rejecting Stripe deliveries (signature mismatch,
        // endpoint mis-config). The auto-refresh resolves (a) cleanly; (b)
        // also surfaces visibly to the user instead of hiding behind a
        // false "Welcome aboard" message. Operator follow-up: when this
        // page keeps refreshing for >30s on staging, check
        // `https://dashboard.stripe.com/test/webhooks` for 4xx/5xx deliveries.
        html! {
            div class="flex items-center justify-center min-h-[70vh]" {
                div class="rounded-lg border bg-card text-card-foreground shadow-sm max-w-lg w-full border-border/50 overflow-hidden" {
                    div class="h-1 bg-gradient-to-r from-primary via-indigo-500 to-teal-500" {}
                    div class="p-6 pt-8 pb-8 text-center space-y-6" {
                        div class="flex justify-center" {
                            div class="rounded-full bg-gradient-to-br from-primary/20 to-primary/5 p-4" {
                                (icon("loader", "h-12 w-12 text-primary animate-spin"))
                            }
                        }
                        div class="space-y-2" {
                            h1 class="text-3xl font-bold" { "Finalizing your subscription" }
                            p class="text-muted-foreground text-lg" {
                                "Stripe is confirming your payment. This page refreshes automatically."
                            }
                        }
                        p class="text-xs text-muted-foreground" {
                            "Still here after 30 seconds? Reload, or contact support if it persists."
                        }
                        // Refresh every 3s. As soon as the webhook lands and
                        // subscription_status flips to Active, the next
                        // refresh renders the success branch above.
                        script { (PreEscaped("setTimeout(function(){location.reload()},3000);")) }
                    }
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

/// BUNYIP-187: flash-banner query for the membership page. Mirrors
/// `SettingsQuery::{ok, error}`; the values are produced by
/// `membership_subscribe`, `membership_cancel`, etc., and rendered
/// in the page banner below.
#[derive(Deserialize)]
pub struct MembershipQuery {
    pub ok: Option<String>,
    pub error: Option<String>,
}

pub async fn membership(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<MembershipQuery>,
) -> Response {
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
            // BUNYIP-187: flash banners surface checkout failures (and any
            // other ?error= / ?ok= flash) at the top of the page so the
            // user sees why a click "did nothing".
            @if let Some(ok) = &q.ok { (success_box(ok)) }
            @if let Some(e) = &q.error { (error_box(e)) }
            @if past_due {
                div class="rounded-lg border border-destructive/50 p-4 text-sm text-destructive flex items-center gap-2" {
                    (icon("alert-triangle", "h-4 w-4")) "Your payment failed. Update your payment method within 30 days to avoid losing access."
                }
            }
            // BUNYIP-291 AC2: label the applied signup trial by tier
            // (early-adopter vs standard) so the member sees which trial they
            // received, not just an unlabeled "Trial" badge.
            @if !lifetime {
                @if let Some(days) = user.trial_ends_at.as_deref().and_then(days_until) {
                    div class="rounded-lg border border-primary/40 bg-primary/5 p-4 text-sm flex items-center gap-2" {
                        (icon("credit-card", "h-4 w-4 text-primary"))
                        span { b { (tier_name(&tier)) " trial" } " - " (days) " day" @if days != 1 { "s" } " remaining." }
                    }
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
                                    // BUNYIP-330: current_period_end is None until the
                                    // Stripe subscription webhook syncs it. Show the
                                    // concrete date when known; otherwise a plain-English
                                    // phrase, never the bare "N/A" it used to print.
                                    @let end = m.current_period_end.as_deref().map(fmt_date_iso);
                                    @if will_cancel {
                                        @if let Some(d) = end { "Canceled - ends " (d) } @else { "Canceled - ends at the end of the current billing period" }
                                    } @else {
                                        @if let Some(d) = end { (d) } @else { "End of the current billing period" }
                                    } } }
                            }
                            div class="flex gap-4 pt-4" {
                                @if will_cancel {
                                    form method="post" action="/membership/reactivate" { button type="submit" class=(button_class("default", "default", "bg-gradient-to-r from-primary to-indigo-500 text-white border-0")) { "Reactivate Membership" } }
                                } @else {
                                    // BUNYIP-291 AC3: a single cancel control that
                                    // offers the two distinct cancel modes (keep
                                    // access until period end vs cancel now) as a
                                    // choice, rather than two sibling buttons.
                                    // BUNYIP-330: see Next Billing above - fall back to a
                                    // readable phrase instead of "N/A" when the period end
                                    // has not synced from Stripe yet.
                                    @let end = m.current_period_end.as_deref().map(fmt_date_iso);
                                    details class="group" {
                                        summary class=(button_class("outline", "default", "cursor-pointer list-none")) { "Cancel Membership" }
                                        div class="mt-3 w-full max-w-md rounded-md border p-3 space-y-3 text-sm" {
                                            p class="text-muted-foreground" { "How would you like to cancel?" }
                                            form method="post" action="/membership/cancel" {
                                                button type="submit" class=(button_class("outline", "sm", "w-full justify-start")) { @if let Some(d) = end { "Cancel at period end - keep access until " (d) } @else { "Cancel at period end - keep access until the end of your current billing period" } }
                                            }
                                            form method="post" action="/membership/cancel-now" onsubmit="return confirm('Cancel immediately? You will lose access right now.')" {
                                                button type="submit" class=(button_class("destructive", "sm", "w-full justify-start")) { "Cancel immediately - lose access now" }
                                            }
                                        }
                                    }
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
    // BUNYIP-187: surface checkout failures as a flash banner on
    // `/membership` instead of silently redirecting. The api returns
    // a useful 400 (e.g. `price_id: No active price configured`)
    // when no app-tagged product is configured (gotcha 3 in
    // BUNYIP-A-5); the old `_ => redirect_cookies("/membership", ...)`
    // arm dropped that on the floor and left the operator wondering
    // why the Subscribe button "did nothing".
    match calls::checkout(&st.api, c.forward.as_deref(), None).await {
        Ok(s) if s.checkout_url.starts_with("https://checkout.stripe.com/") => {
            redirect_cookies(&s.checkout_url, &c.set_cookies)
        }
        Ok(_) => redirect_cookies(
            &format!(
                "/membership?error={}",
                urlenc(&humanise_checkout_error(
                    "Checkout returned an invalid URL. Please contact support."
                ))
            ),
            &c.set_cookies,
        ),
        Err(e) => redirect_cookies(
            &format!(
                "/membership?error={}",
                urlenc(&humanise_checkout_error(&e.user_message()))
            ),
            &c.set_cookies,
        ),
    }
}

/// BUNYIP-187: map the api's raw checkout-error message to operator-
/// friendly copy. The recognised messages come from
/// `bunyip-api/src/handlers/membership.rs` and the gotchas catalogued
/// in BUNYIP-A-5; anything we have not seen yet falls through to the
/// raw text so the operator still gets useful information instead of
/// a sanitised wall.
fn humanise_checkout_error(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.contains("No active price configured") {
        return "Stripe checkout is not configured. An admin must create at least one tagged product and recurring price before subscriptions can be opened. See docs/stripe-test-mode.md.".to_string();
    }
    if trimmed.contains("Stripe is not configured") || trimmed.contains("STRIPE_SECRET_KEY") {
        return "Stripe is not configured on this deployment. Set the Stripe keys in the admin Stripe page (or via env) before subscribing.".to_string();
    }
    // BUNYIP-191: dunite-core maps every `AppError::InternalError` /
    // `AppError::DatabaseError` to this single user-facing string,
    // which left the operator with no actionable hint (the real
    // cause is logged on the api side). Replace it with a message
    // that explicitly points at the api logs so an operator chasing
    // a Subscribe failure knows where to look.
    if trimmed == "An unexpected error occurred. Please try again later." {
        return "Checkout failed unexpectedly on the server. The api logged the cause - check `docker logs <bunyip-api>` for 'Failed to create Stripe checkout session' or similar, then contact support.".to_string();
    }
    if trimmed.is_empty() {
        return "Could not start checkout. Please try again or contact support.".to_string();
    }
    trimmed.to_string()
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
    /// 1-indexed page for the Active Sessions list (BUNYIP-177).
    pub session_page: Option<i64>,
    /// 1-indexed page for the Trusted Devices list (BUNYIP-177).
    pub device_page: Option<i64>,
}

/// Page size for the Settings sessions / trusted-device lists (BUNYIP-177).
const SETTINGS_PAGE_SIZE: i64 = 20;

/// Empty page fallback so a failed sessions/devices fetch does not break the
/// rest of /settings (BUNYIP-177).
fn empty_page<T>(page: i64) -> crate::api::types::PaginatedResponse<T> {
    crate::api::types::PaginatedResponse {
        items: Vec::new(),
        total: 0,
        page,
        page_size: Some(SETTINGS_PAGE_SIZE),
        total_pages: 0,
    }
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
    // Active sessions (BUNYIP-137), paginated (BUNYIP-177). A failure here must
    // not break the rest of the settings page, so fall back to an empty page.
    let session_page = q.session_page.unwrap_or(1).max(1);
    let device_page = q.device_page.unwrap_or(1).max(1);
    let sessions = calls::list_sessions(&st.api, fwd, session_page, SETTINGS_PAGE_SIZE)
        .await
        .unwrap_or_else(|_| empty_page(session_page));
    // Trusted devices (BUNYIP-138). Only 2FA users have any; fetch lazily.
    let trusted_devices = if twofa_enabled {
        auth_api::list_trusted_devices(&st.api, fwd, device_page, SETTINGS_PAGE_SIZE)
            .await
            .unwrap_or_else(|_| empty_page(device_page))
    } else {
        empty_page(device_page)
    };

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Settings" } p class="mt-2 text-muted-foreground" { "Manage your account settings and preferences." } }
            @if let Some(ok) = &q.ok { (success_box(ok)) }
            @if let Some(e) = &q.error { (error_box(e)) }

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
                        div { p class="text-sm text-muted-foreground" { "Email Verified" } p class="font-medium flex items-center gap-2" { @if user.email_verified { (icon("check", "h-4 w-4 text-teal-600 dark:text-teal-400")) "Verified" } @else { (icon("alert-circle", "h-4 w-4 text-yellow-600")) "Not Verified" } } @if !user.email_verified { form method="post" action="/settings/verify-email/resend" class="mt-2" { button type="submit" class=(button_class("outline", "sm", "")) { (icon("mail", "mr-2 h-4 w-4")) "Resend verification email" } } } }
                        div { p class="text-sm text-muted-foreground" { "Membership Status" } p class="font-medium" { (status_label(&user.membership_status)) } }
                    }
                }
            }

            // BUNYIP-139: Profile (first_name, last_name, phone). All three
            // are optional at the DB level; the Settings form trims input and
            // empty submission clears the column to NULL. Length is bounded
            // at 64 per the DB CHECK; the same limit is enforced at the API
            // edge. Persistence: PUT /v1/users/me/profile via
            // `auth_api::update_profile`.
            (settings_card("user-cog", "from-primary to-teal-500", "Profile", html! {
                form method="post" action="/settings/profile" class="space-y-4 max-w-md" {
                    div class="space-y-2" { label class="text-sm font-medium" { "First Name" } input name="first_name" type="text" maxlength="64" value=(user.first_name.as_deref().unwrap_or("")) class=(crate::handlers::dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "Last Name" } input name="last_name" type="text" maxlength="64" value=(user.last_name.as_deref().unwrap_or("")) class=(crate::handlers::dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "Phone " span class="text-xs text-muted-foreground" { "(optional)" } } input name="phone" type="tel" maxlength="64" value=(user.phone.as_deref().unwrap_or("")) class=(crate::handlers::dashboard_input()); }
                    p class="text-xs text-muted-foreground" { "Apps that connect to your Bunyip account can request these fields. You will be asked to confirm before any new app sees them." }
                    button type="submit" class=(button_class("default", "default", "bg-gradient-to-r from-primary to-teal-500 text-white border-0")) { "Save Profile" }
                }
            }))

            // Change email. autocomplete="off" on the form + value="" on the
            // new-email input defeat the password-manager's "fill in the
            // saved username" heuristic that was leaving the field already
            // populated with the user's current email (audit finding 3).
            // current_password also takes autocomplete="off" here - this is
            // confirmation-of-identity, not a sign-in form, so we don't want
            // the manager filling it.
            (settings_card("mail", "from-primary to-teal-500", "Change Email", html! {
                form method="post" action="/settings/email" autocomplete="off" class="space-y-4 max-w-md" {
                    // BUNYIP-117: bound the new-email at the edge (254
                    // chars / RFC 5321 max, required + type=email for the
                    // browser's own shape check). Authoritative validation
                    // is still in `services::auth::request_email_change`.
                    div class="space-y-2" { label class="text-sm font-medium" { "New Email Address" } input name="new_email" type="email" value="" autocomplete="off" maxlength="254" required placeholder="Enter your new email" class=(crate::handlers::dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "Current Password" } input name="current_password" type="password" autocomplete="off" required placeholder="Enter your current password" class=(crate::handlers::dashboard_input()); }
                    @if twofa_enabled { div class="space-y-2" { label class="text-sm font-medium" { "Two-Factor Code" } input name="totp_code" inputmode="numeric" autocomplete="one-time-code" required placeholder="6-digit code" class=(crate::handlers::dashboard_input()); } }
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
                    @if twofa_enabled { div class="space-y-2" { label class="text-sm font-medium" { "Two-Factor Code" } input name="totp_code" inputmode="numeric" autocomplete="one-time-code" required placeholder="6-digit code" class=(crate::handlers::dashboard_input()); } }
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
                                div class="space-y-2" { label class="text-sm font-medium" { "Two-Factor Code" } input name="totp_code" inputmode="numeric" autocomplete="one-time-code" required placeholder="6-digit code" class=(crate::handlers::dashboard_input()); }
                                button type="submit" class=(button_class("outline", "sm", "text-destructive hover:text-destructive")) { (icon("shield-off", "mr-2 h-4 w-4")) "Disable 2FA" }
                            }
                        } @else { p class="text-xs text-muted-foreground" { "Admin accounts cannot disable two-factor authentication." } }
                        // BUNYIP-355: recovery-code regeneration is available to
                        // every 2FA user, admins included - they cannot disable,
                        // so keeping working backup codes matters most for them.
                        div class="pt-2 border-t" {
                            p class="text-xs text-muted-foreground mb-2" { "Lost your recovery codes, or used some up? Generate a fresh set (this invalidates the old codes)." }
                            a href="/settings/2fa/recovery-codes" class=(button_class("outline", "sm", "")) { (icon("key", "mr-2 h-4 w-4")) "Regenerate recovery codes" }
                        }
                        // BUNYIP-355: re-key to a new authenticator (e.g. new
                        // phone). Available to admins too; the old authenticator
                        // keeps working until the new one is confirmed.
                        div class="pt-2 border-t" {
                            p class="text-xs text-muted-foreground mb-2" { "Switching to a new phone or authenticator app? Set up a new one - your current authenticator keeps working until you finish." }
                            a href="/settings/2fa/rekey" class=(button_class("outline", "sm", "")) { (icon("shield-check", "mr-2 h-4 w-4")) "Reset authenticator app" }
                        }
                    }
                } @else {
                    div class="space-y-4" {
                        div class="flex items-center gap-2" { (icon("shield-off", "h-5 w-5 text-muted-foreground")) span class="font-medium text-muted-foreground" { "Not enabled" } }
                        a href="/settings/2fa/setup" class=(button_class("default", "default", "bg-gradient-to-r from-teal-500 to-indigo-500 text-white border-0")) { (icon("shield", "mr-2 h-4 w-4")) "Enable Two-Factor Authentication" }
                    }
                }
            }))

            // Active sessions (BUNYIP-137)
            (settings_card("key", "from-indigo-500 to-primary", "Active Sessions", sessions_card_body(&sessions, device_page)))

            // Trusted devices (BUNYIP-138). Only meaningful with 2FA on.
            @if twofa_enabled {
                (settings_card("shield-check", "from-teal-500 to-primary", "Trusted Devices", trusted_devices_card_body(&trusted_devices, session_page)))
            }

            // Danger zone
            div class="rounded-lg border bg-card text-card-foreground shadow-sm border-red-200 dark:border-red-900" {
                div class="flex flex-col space-y-1.5 p-6" { h3 class="text-2xl font-semibold leading-none tracking-tight text-red-600 dark:text-red-400 flex items-center gap-2" { (icon("alert-triangle", "h-5 w-5")) "Danger Zone" } p class="text-sm text-muted-foreground" { "This permanently deletes your account AND all of your data in Mokosh and any other connected app. This cannot be undone." } }
                div class="p-6 pt-0" {
                    // Delete account. autocomplete="off" on the form + on the
                    // password input together suppress the password-manager
                    // pre-fill that auditor finding 4 flagged on this danger-
                    // zone form. TOTP gets the spec-aligned one-time-code
                    // hint so the manager (or iOS / Chrome AutoFill) can
                    // surface a freshly-arrived SMS / TOTP code from a sibling
                    // tab WITHOUT pre-filling the password field.
                    form method="post" action="/settings/account/delete" autocomplete="off" class="space-y-3 max-w-md" onsubmit="return confirm('Permanently delete your account AND all of your data in Mokosh and any other connected app? This cannot be undone.')" {
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

/// Human "time ago" from an ISO-8601 timestamp; falls back to the date prefix
/// if the value does not parse.
fn time_ago(iso: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(iso) {
        Ok(t) => {
            let secs = (chrono::Utc::now() - t.with_timezone(&chrono::Utc))
                .num_seconds()
                .max(0);
            if secs < 60 {
                "just now".to_string()
            } else if secs < 3600 {
                format!("{} min ago", secs / 60)
            } else if secs < 86_400 {
                format!("{} hr ago", secs / 3600)
            } else {
                format!("{} days ago", secs / 86_400)
            }
        }
        Err(_) => iso.chars().take(10).collect(),
    }
}

/// Prev/Next links for one of the two /settings lists (BUNYIP-177). `param` is
/// this list's page query key; `keep` carries the OTHER list's page so paging
/// one list does not reset the other. Plain links (no htmx), mirroring the only
/// existing pager in bunyip-web (the admin pager).
fn settings_pager(param: &str, page: i64, total_pages: i64, keep: &str) -> Markup {
    html! {
        @if total_pages > 1 {
            div class="flex justify-center gap-2 mt-4" {
                @if page > 1 { a href=(format!("/settings?{keep}&{param}={}", page - 1)) class=(button_class("outline", "sm", "")) { "Previous" } }
                span class="flex items-center px-3 text-sm text-muted-foreground" { "Page " (page) " of " (total_pages) }
                @if page < total_pages { a href=(format!("/settings?{keep}&{param}={}", page + 1)) class=(button_class("outline", "sm", "")) { "Next" } }
            }
        }
    }
}

/// Body of the "Active Sessions" card: one row per session with device, IP,
/// last-active time, a "This device" badge on the current session, a per-row
/// revoke action for non-current sessions, and a "log out all other devices"
/// action when there is at least one other session (BUNYIP-137).
fn sessions_card_body(
    page: &crate::api::types::PaginatedResponse<crate::api::types::SessionInfo>,
    device_page: i64,
) -> Markup {
    let sessions = &page.items;
    // "Log out all other devices" appears whenever the account has more than one
    // active session, even if the others are on a later page (BUNYIP-177).
    let has_others = page.total > 1;
    html! {
        @if sessions.is_empty() {
            p class="text-sm text-muted-foreground" { "No active sessions found." }
        } @else {
            ul class="space-y-3" {
                @for s in sessions {
                    li class="flex items-center justify-between gap-4 rounded-lg border border-border/50 p-4" {
                        div class="min-w-0" {
                            p class="font-medium truncate flex items-center gap-2" {
                                (s.device_info.as_deref().unwrap_or("Unknown device"))
                                @if s.current { (badge("success", "This device")) }
                            }
                            p class="text-sm text-muted-foreground" {
                                @if let Some(ip) = &s.ip_address { (ip) " · " }
                                "last active " (time_ago(s.last_used_at.as_deref().unwrap_or(&s.created_at)))
                            }
                        }
                        @if !s.current {
                            form method="post" action=(format!("/settings/sessions/{}/revoke", urlenc(&s.id))) {
                                button type="submit" class=(button_class("outline", "sm", "text-destructive hover:text-destructive")) { (icon("log-out", "mr-2 h-4 w-4")) "Revoke" }
                            }
                        }
                    }
                }
            }
            @if has_others {
                form method="post" action="/settings/sessions/revoke-others" class="mt-4" onsubmit="return confirm('Log out all other devices?')" {
                    button type="submit" class=(button_class("outline", "sm", "")) { (icon("log-out", "mr-2 h-4 w-4")) "Log out all other devices" }
                }
            }
        }
        (settings_pager("session_page", page.page, page.total_pages, &format!("device_page={device_page}")))
    }
}

/// POST /settings/sessions/{id}/revoke - revoke one of the user's sessions.
pub async fn settings_revoke_session(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match guard(&st, &headers, "/settings").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match calls::revoke_session(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => redirect_cookies("/settings?ok=Session+revoked", &c.set_cookies),
        Err(e) => redirect_cookies(
            &format!("/settings?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

/// POST /settings/sessions/revoke-others - log out all other devices.
pub async fn settings_revoke_other_sessions(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let (_, c) = match guard(&st, &headers, "/settings").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match calls::revoke_other_sessions(&st.api, c.forward.as_deref()).await {
        Ok(()) => redirect_cookies("/settings?ok=Logged+out+other+devices", &c.set_cookies),
        Err(e) => redirect_cookies(
            &format!("/settings?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

/// Body of the "Trusted Devices" card (BUNYIP-138): devices that skip the TOTP
/// prompt at login, each with a revoke action.
fn trusted_devices_card_body(
    page: &crate::api::types::PaginatedResponse<crate::api::types::TrustedDeviceInfo>,
    session_page: i64,
) -> Markup {
    let devices = &page.items;
    html! {
        p class="text-sm text-muted-foreground mb-4" { "Devices that skip the two-factor prompt when you sign in. Revoke any you do not recognize." }
        @if devices.is_empty() {
            p class="text-sm text-muted-foreground" { "No trusted devices." }
        } @else {
            ul class="space-y-3" {
                @for d in devices {
                    li class="flex items-center justify-between gap-4 rounded-lg border border-border/50 p-4" {
                        div class="min-w-0" {
                            p class="font-medium truncate" { (d.label.as_deref().unwrap_or("Unknown device")) }
                            p class="text-sm text-muted-foreground" {
                                @if let Some(ip) = &d.ip_address { (ip) " · " }
                                "added " (time_ago(&d.created_at))
                            }
                        }
                        form method="post" action=(format!("/settings/trusted-devices/{}/revoke", urlenc(&d.id))) {
                            button type="submit" class=(button_class("outline", "sm", "text-destructive hover:text-destructive")) { (icon("trash", "mr-2 h-4 w-4")) "Revoke" }
                        }
                    }
                }
            }
        }
        (settings_pager("device_page", page.page, page.total_pages, &format!("session_page={session_page}")))
    }
}

/// POST /settings/trusted-devices/{id}/revoke - forget a trusted device.
pub async fn settings_revoke_trusted_device(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match guard(&st, &headers, "/settings").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match auth_api::revoke_trusted_device(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => redirect_cookies("/settings?ok=Trusted+device+revoked", &c.set_cookies),
        Err(e) => redirect_cookies(
            &format!("/settings?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

#[derive(Deserialize)]
pub struct EmailChangeForm {
    pub new_email: String,
    #[serde(default)]
    pub current_password: String,
    /// TOTP/recovery code, required by the API when 2FA is on (BUNYIP-138).
    #[serde(default)]
    pub totp_code: String,
}

/// BUNYIP-139: Settings -> Profile form.
#[derive(Deserialize)]
pub struct ProfileForm {
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub phone: String,
}

/// BUNYIP-139: POST /settings/profile. Persists optional first_name /
/// last_name / phone via `auth_api::update_profile`. Every field is sent on
/// every submit (trimmed at the API edge) so a user can clear a value by
/// erasing the input and saving.
pub async fn settings_profile(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<ProfileForm>,
) -> Response {
    let (_, c) = match guard(&st, &headers, "/settings").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match auth_api::update_profile(
        &st.api,
        c.forward.as_deref(),
        Some(f.first_name.as_str()),
        Some(f.last_name.as_str()),
        Some(f.phone.as_str()),
    )
    .await
    {
        Ok(()) => redirect_cookies("/settings?ok=Profile+saved", &c.set_cookies),
        Err(e) => redirect_cookies(
            &format!("/settings?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
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
    // BUNYIP-117: web-edge shape + bound check on the email. Authoritative
    // shape-check still happens in `services::auth::request_email_change`,
    // but bouncing garbage / over-length values here means the bad-input
    // user error is "your email is malformed" rather than a generic
    // upstream rejection.
    if let Err(msg) = crate::handlers::validate::email(&f.new_email, "New email") {
        return redirect_cookies(&format!("/settings?error={}", urlenc(&msg)), &c.set_cookies);
    }
    if f.current_password.is_empty() {
        return redirect_cookies(
            &format!(
                "/settings?error={}",
                urlenc("Please enter your current password")
            ),
            &c.set_cookies,
        );
    }
    match auth_api::request_email_change(
        &st.api,
        c.forward.as_deref(),
        f.new_email.trim(),
        &f.current_password,
        f.totp_code.trim(),
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
    /// TOTP/recovery code, required by the API when 2FA is on (BUNYIP-138).
    #[serde(default)]
    pub totp_code: String,
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
        f.totp_code.trim(),
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
    #[serde(default)]
    pub totp_code: String,
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
    match auth_api::disable_2fa(&st.api, c.forward.as_deref(), &f.password, &f.totp_code).await {
        Ok(()) => redirect_cookies("/settings?ok=Two-factor+disabled", &c.set_cookies),
        Err(e) => redirect_cookies(
            &format!("/settings?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

/// Resend the email-verification message for the signed-in user. The domain
/// layer rate-limits issuance (3 per hour) and rejects an already-verified
/// account; both surface here as the API error message.
pub async fn settings_resend_verification(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Response {
    // BUNYIP-206: guard with the real route path so the onboarding allowlist
    // (handlers::mod::onboarding_allowed) admits it - a not-yet-onboarded user
    // must be able to resend the verification email from /onboarding.
    let (user, c) = match guard(&st, &headers, "/settings/verify-email/resend").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // BUNYIP-324: the resend control lives on BOTH /settings and /onboarding.
    // An onboarding-incomplete user is bounced off /settings by the onboarding
    // gate (handlers::mod::guard), which drops the ?ok / ?error feedback param,
    // so they saw nothing after a resend. Route the feedback back to the page
    // they were actually on: the two pages are mutually exclusive by onboarding
    // state, so `needs_onboarding` reconstructs the origin server-side without
    // trusting any client-supplied redirect target. Both pages render ?ok/?error.
    let dest = if needs_onboarding(&st, &user).await {
        "/onboarding"
    } else {
        "/settings"
    };
    match auth_api::request_email_verification(&st.api, c.forward.as_deref()).await {
        Ok(()) => redirect_cookies(
            &format!(
                "{dest}?ok={}",
                urlenc(&format!("Verification email sent to {}", user.email))
            ),
            &c.set_cookies,
        ),
        // BUNYIP-314: a throttled resend surfaces the standard verification
        // "try again in about N minutes" copy (from the real Retry-After);
        // other errors keep their generic message.
        Err(e) => redirect_cookies(
            &format!("{dest}?error={}", urlenc(&e.verification_message())),
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
/// QR + manual-key + verify-code page, shared by initial setup and the BUNYIP-355
/// re-key (which points the confirm form at a different action and relabels it).
fn twofa_qr_view(
    setup: &TwoFactorSetupResponse,
    error: Option<&str>,
    heading: &str,
    subtitle: &str,
    action: &str,
    button: &str,
) -> Markup {
    html! {
        div class="mx-auto max-w-lg space-y-6" {
            div { h1 class="text-3xl font-bold" { (heading) } p class="mt-2 text-muted-foreground" { (subtitle) } }
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
                    form method="post" action=(action) class="space-y-4" {
                        // BUNYIP-117: bound the TOTP edge before submit
                        // (maxlength + pattern). Authoritative check is
                        // still domain-side via `services::totp::verify_code`.
                        // BUNYIP-331: data-otp-autosubmit submits this
                        // single-field form once the six-digit code is complete.
                        div class="space-y-2" { label class="text-sm font-medium" { "Verification Code" } input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" minlength="6" required placeholder="000000" autocomplete="one-time-code" data-otp-autosubmit class=(crate::handlers::dashboard_input()); }
                        button type="submit" class=(button_class("default", "default", "w-full")) { (button) }
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
        Ok(setup) => twofa_qr_view(
            &setup,
            None,
            "Set Up Two-Factor Authentication",
            "Scan the QR code, then enter a code to confirm.",
            "/settings/2fa/setup",
            "Verify & Enable",
        ),
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
                Ok(setup) => twofa_qr_view(
                    &setup,
                    Some(&err_msg),
                    "Set Up Two-Factor Authentication",
                    "Scan the QR code, then enter a code to confirm.",
                    "/settings/2fa/setup",
                    "Verify & Enable",
                ),
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

/// Password-confirm form for regenerating recovery codes (BUNYIP-355). Mirrors
/// the API's password gate on `POST /auth/2fa/recovery-codes`.
fn twofa_recovery_form(err: Option<&str>) -> Markup {
    html! {
        div class="mx-auto max-w-lg space-y-6" {
            div { h1 class="text-3xl font-bold" { "Regenerate recovery codes" } p class="mt-2 text-muted-foreground" { "This invalidates your existing recovery codes and issues a fresh set. Confirm your password to continue." } }
            @if let Some(e) = err { (error_box(e)) }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="p-6" {
                    form method="post" action="/settings/2fa/recovery-codes" class="space-y-4 max-w-md" {
                        div class="space-y-2" { label class="text-sm font-medium" { "Password" } input name="password" type="password" autocomplete="current-password" required class=(crate::handlers::dashboard_input()); }
                        div class="flex gap-2" {
                            button type="submit" class=(button_class("default", "default", "")) { (icon("key", "mr-2 h-4 w-4")) "Regenerate codes" }
                            a href="/settings" class=(button_class("outline", "default", "")) { "Cancel" }
                        }
                    }
                }
            }
        }
    }
}

/// Show the freshly-generated recovery codes exactly once, matching the setup
/// flow's codes panel (BUNYIP-355).
fn twofa_recovery_result(codes: &[String]) -> Markup {
    html! {
        div class="mx-auto max-w-lg space-y-6" {
            div { h1 class="text-3xl font-bold" { "New recovery codes" } p class="mt-2 text-muted-foreground" { "Save these in a safe place. Your old recovery codes no longer work." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50" {
                div class="p-6 space-y-4" {
                    div class="rounded-lg border p-3 text-sm flex items-start gap-3" { (icon("alert-circle", "h-4 w-4 mt-0.5")) p class="text-sm" { "Save these codes now. You won't be able to see them again." } }
                    div class="grid grid-cols-2 gap-2 rounded-lg bg-muted p-4" { @for code in codes { code class="text-center font-mono text-sm py-1" { (code) } } }
                    a href="/settings" class=(button_class("default", "default", "w-full")) { "Done" }
                }
            }
        }
    }
}

/// GET /settings/2fa/recovery-codes - render the password-confirm form.
pub async fn twofa_recovery_get(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/settings/2fa/recovery-codes").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    dashboard_response(
        &c,
        &user,
        "/settings",
        "Recovery codes · Bunyip",
        twofa_recovery_form(None),
    )
}

#[derive(Deserialize)]
pub struct TwoFactorRecoveryForm {
    pub password: String,
}

/// POST /settings/2fa/recovery-codes - confirm the password, regenerate via the
/// API, and show the new codes once (or re-render the form on error).
pub async fn twofa_recovery_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TwoFactorRecoveryForm>,
) -> Response {
    let (user, c) = match guard(&st, &headers, "/settings/2fa/recovery-codes").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let content =
        match auth_api::regenerate_recovery_codes(&st.api, c.forward.as_deref(), &f.password).await
        {
            Ok(codes) => twofa_recovery_result(&codes.codes),
            Err(e) => twofa_recovery_form(Some(&e.user_message())),
        };
    dashboard_response(&c, &user, "/settings", "Recovery codes · Bunyip", content)
}

/// Step-up form that starts an authenticator re-key (BUNYIP-355): password + a
/// current code, matching the API gate on `POST /auth/2fa/rekey`.
fn twofa_rekey_stepup_form(err: Option<&str>) -> Markup {
    html! {
        div class="mx-auto max-w-lg space-y-6" {
            div { h1 class="text-3xl font-bold" { "Reset authenticator app" } p class="mt-2 text-muted-foreground" { "Set up a new authenticator (for example on a new phone). Confirm your password and a current code first; your existing authenticator keeps working until you finish." } }
            @if let Some(e) = err { (error_box(e)) }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="p-6" {
                    form method="post" action="/settings/2fa/rekey" class="space-y-4 max-w-md" {
                        div class="space-y-2" { label class="text-sm font-medium" { "Password" } input name="password" type="password" autocomplete="current-password" required class=(crate::handlers::dashboard_input()); }
                        div class="space-y-2" { label class="text-sm font-medium" { "Current two-factor code" } input name="totp_code" inputmode="numeric" autocomplete="one-time-code" required placeholder="6-digit or recovery code" class=(crate::handlers::dashboard_input()); }
                        div class="flex gap-2" {
                            button type="submit" class=(button_class("default", "default", "")) { (icon("shield", "mr-2 h-4 w-4")) "Continue" }
                            a href="/settings" class=(button_class("outline", "default", "")) { "Cancel" }
                        }
                    }
                }
            }
        }
    }
}

/// Bare code-entry form for finishing a re-key after the QR was already shown
/// (the pending secret is still staged, so no need to re-scan) (BUNYIP-355).
fn twofa_rekey_code_form(err: Option<&str>) -> Markup {
    html! {
        div class="mx-auto max-w-lg space-y-6" {
            div { h1 class="text-3xl font-bold" { "Reset authenticator app" } p class="mt-2 text-muted-foreground" { "Enter a fresh code from your new authenticator to finish." } }
            @if let Some(e) = err { (error_box(e)) }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50" {
                div class="p-6 space-y-4" {
                    form method="post" action="/settings/2fa/rekey/confirm" class="space-y-4" {
                        div class="space-y-2" { label class="text-sm font-medium" { "Verification Code" } input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" minlength="6" required placeholder="000000" autocomplete="one-time-code" data-otp-autosubmit class=(crate::handlers::dashboard_input()); }
                        button type="submit" class=(button_class("default", "default", "w-full")) { "Confirm new authenticator" }
                    }
                    p class="text-xs text-muted-foreground" { "Need the QR code again? " a href="/settings/2fa/rekey" class="underline" { "Restart the reset" } "." }
                }
            }
        }
    }
}

/// GET /settings/2fa/rekey - the re-key step-up form.
pub async fn twofa_rekey_get(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/settings/2fa/rekey").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    dashboard_response(
        &c,
        &user,
        "/settings",
        "Reset authenticator · Bunyip",
        twofa_rekey_stepup_form(None),
    )
}

#[derive(Deserialize)]
pub struct TwoFactorRekeyForm {
    pub password: String,
    #[serde(default)]
    pub totp_code: String,
}

/// POST /settings/2fa/rekey - step-up, then stage the new secret and show its QR.
pub async fn twofa_rekey_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TwoFactorRekeyForm>,
) -> Response {
    let (user, c) = match guard(&st, &headers, "/settings/2fa/rekey").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let content = match auth_api::begin_rekey(
        &st.api,
        c.forward.as_deref(),
        &f.password,
        f.totp_code.trim(),
    )
    .await
    {
        Ok(setup) => twofa_qr_view(
            &setup,
            None,
            "Reset authenticator app",
            "Scan this new QR code with your authenticator, then enter a code from it. Your old authenticator still works until you confirm.",
            "/settings/2fa/rekey/confirm",
            "Confirm new authenticator",
        ),
        Err(e) => twofa_rekey_stepup_form(Some(&e.user_message())),
    };
    dashboard_response(
        &c,
        &user,
        "/settings",
        "Reset authenticator · Bunyip",
        content,
    )
}

/// POST /settings/2fa/rekey/confirm - verify a code from the new authenticator,
/// promote it, and show the fresh recovery codes.
pub async fn twofa_rekey_confirm_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TwoFactorSetupForm>,
) -> Response {
    let (user, c) = match guard(&st, &headers, "/settings/2fa/rekey").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let content = match auth_api::confirm_rekey(&st.api, c.forward.as_deref(), f.code.trim()).await
    {
        Ok(codes) => twofa_recovery_result(&codes.codes),
        Err(e) => twofa_rekey_code_form(Some(&e.user_message())),
    };
    dashboard_response(
        &c,
        &user,
        "/settings",
        "Reset authenticator · Bunyip",
        content,
    )
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
            first_name: None,
            last_name: None,
            phone: None,
        }
    }

    fn app_with_release_notes(release_notes_url: Option<&str>) -> crate::api::types::Application {
        crate::api::types::Application {
            id: "a1".into(),
            slug: "mokosh".into(),
            display_name: "Mokosh".into(),
            description: Some("PSA".into()),
            icon_url: None,
            version: None,
            source_code_url: None,
            release_notes_url: release_notes_url.map(str::to_string),
            subdomain: Some("mokosh".into()),
            is_accessible: true,
            maintenance_mode: false,
            maintenance_message: None,
            group_id: None,
        }
    }

    #[test]
    fn app_card_links_release_notes_when_present() {
        // BUNYIP-343: the card links to the app's Forgejo releases page.
        let notes = "https://dev.a8n.run/psa-systems/mokosh-server/releases";
        let html = app_card(
            0,
            &app_with_release_notes(Some(notes)),
            "a8n.run",
            true,
            None,
        )
        .into_string();
        assert!(html.contains(notes), "release-notes URL must be linked");
        assert!(
            html.contains("Release notes"),
            "the link must carry the 'Release notes' label"
        );
    }

    #[test]
    fn app_card_omits_release_notes_when_absent() {
        // No repo association -> no link (not an empty/dead affordance).
        let html = app_card(0, &app_with_release_notes(None), "a8n.run", true, None).into_string();
        assert!(
            !html.contains("Release notes"),
            "no release-notes link when the URL is unset"
        );
    }

    #[test]
    fn community_sends_member_into_lets_chat() {
        // BUNYIP-329: a member with a configured Let's Chat URL is redirected
        // straight into it (authenticated via their existing OP session).
        let url = "https://chat.a8n.systems/auth/bunyip";
        assert_eq!(community_redirect_target(url, true), url);
    }

    #[test]
    fn community_upsells_non_members() {
        // A non-member hitting /community is sent to the membership upsell,
        // never into the members-only community.
        assert_eq!(
            community_redirect_target("https://chat.a8n.systems/auth/bunyip", false),
            "/membership"
        );
    }

    #[test]
    fn community_falls_back_to_dashboard_when_unconfigured() {
        // Feature off (empty URL): even a member has nowhere to go, so avoid a
        // dead external link and return to the dashboard.
        assert_eq!(community_redirect_target("", true), "/dashboard");
        assert_eq!(community_redirect_target("", false), "/membership");
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

    #[test]
    fn recovery_result_renders_every_code() {
        let codes = vec!["AAAA-1111".to_string(), "BBBB-2222".to_string()];
        let html = super::twofa_recovery_result(&codes).into_string();
        assert!(html.contains("AAAA-1111"));
        assert!(html.contains("BBBB-2222"));
        // The one-time / invalidation warning is present.
        assert!(html.contains("no longer work"));
    }

    #[test]
    fn recovery_form_surfaces_error_only_when_present() {
        assert!(super::twofa_recovery_form(Some("Invalid password"))
            .into_string()
            .contains("Invalid password"));
        assert!(!super::twofa_recovery_form(None)
            .into_string()
            .contains("Invalid password"));
    }

    #[test]
    fn rekey_stepup_form_requires_password_and_current_code() {
        let html = super::twofa_rekey_stepup_form(None).into_string();
        assert!(html.contains("Reset authenticator app"));
        assert!(html.contains(r#"name="password""#));
        assert!(html.contains(r#"name="totp_code""#));
        assert!(html.contains(r#"action="/settings/2fa/rekey""#));
    }

    #[test]
    fn rekey_qr_view_points_confirm_at_the_rekey_route() {
        let setup = crate::api::types::TwoFactorSetupResponse {
            otpauth_uri: "otpauth://totp/Bunyip:u@x?secret=ABCD".into(),
            secret: "ABCDABCDABCD".into(),
        };
        let html = super::twofa_qr_view(
            &setup,
            None,
            "Reset authenticator app",
            "sub",
            "/settings/2fa/rekey/confirm",
            "Confirm new authenticator",
        )
        .into_string();
        assert!(html.contains(r#"action="/settings/2fa/rekey/confirm""#));
        assert!(html.contains("Confirm new authenticator"));
        assert!(html.contains("ABCDABCDABCD")); // manual key rendered
    }

    #[test]
    fn rekey_code_form_offers_restart_and_surfaces_error() {
        let html = super::twofa_rekey_code_form(Some("Invalid verification code")).into_string();
        assert!(html.contains("Invalid verification code"));
        assert!(html.contains(r#"action="/settings/2fa/rekey/confirm""#));
        assert!(html.contains(r#"href="/settings/2fa/rekey""#)); // restart link
    }
}
