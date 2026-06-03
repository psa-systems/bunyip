//! Authenticated dashboard. Ported from the Dioxus DashboardPage. Other
//! dashboard pages (applications, membership, billing, settings, ...) arrive in
//! phase 3.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup, PreEscaped};
use serde::Deserialize;

use crate::api::auth as auth_api;
use crate::api::calls;
use crate::api::types::{AppDownloadGroup, Membership, MembershipStatus, SubscriptionTier, User};
use crate::handlers::{dashboard_response, guard, password_ok, rotating_index};
use crate::util::{app_gradient, days_until, has_active_membership};
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
    if user.lifetime_member {
        return badge("success", "Lifetime");
    }
    if user.trial_ends_at.as_deref().and_then(days_until).is_some() {
        return badge("secondary", "Trial");
    }
    match user.membership_status {
        MembershipStatus::Active => badge("success", "Active"),
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

fn base_domain(st: &AppState) -> String {
    st.cfg.domain_or_localhost()
}
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

pub async fn applications(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/applications").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let apps = calls::applications(&st.api, fwd).await.unwrap_or_default();
    let stripe = auth_api::setup_status(&st.api)
        .await
        .map(|s| s.stripe_enabled)
        .unwrap_or(true);
    let is_member = has_active_membership(Some(&user));
    let domain = base_domain(&st);

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
            div class="grid gap-6 md:grid-cols-2 lg:grid-cols-3" {
                @for (i, app) in apps.iter().enumerate() {
                    @let subdomain = app.subdomain.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| app.slug.clone());
                    @let app_url = format!("{subdomain}.{domain}");
                    div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50 transition-all hover:shadow-lg" {
                        div class="flex flex-col space-y-1.5 p-6" {
                            div class="flex items-start justify-between" {
                                div class={ "flex h-12 w-12 items-center justify-center rounded-lg bg-gradient-to-br " (app_gradient(i)) } {
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
                                a href=(format!("https://{app_url}")) target="_blank" rel="noopener noreferrer" {
                                    span class=(button_class("default", "default", &format!("w-full bg-gradient-to-r {} text-white border-0 shadow-md", app_gradient(i)))) { "Launch" (icon("external-link", "ml-2 h-4 w-4")) }
                                }
                            } @else {
                                button type="button" disabled class=(button_class("default", "default", "w-full")) {
                                    @if !is_member { "Membership Required" } @else if app.maintenance_mode { "Under Maintenance" } @else { "Not Available" }
                                }
                            }
                        }
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

pub async fn downloads(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/downloads").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let has_membership = has_active_membership(Some(&user));
    // Keep the error distinct from "genuinely empty catalog" so an API outage
    // doesn't masquerade as revoked entitlements.
    let groups_result = calls::downloads_all(&st.api, fwd).await;

    let content = html! {
        div class="space-y-6" {
            h1 class="text-2xl font-semibold" { "Downloads" }
            @match &groups_result {
                Err(_) => {
                    (error_box("Downloads are temporarily unavailable. Refresh the page to try again."))
                }
                Ok(groups) => {
                    @if groups.is_empty() {
                        p class="text-sm text-muted-foreground" { "No downloads available" }
                    } @else {
                        @for g in groups {
                            (download_group(g, has_membership))
                        }
                    }
                }
            }
        }
    };
    dashboard_response(&c, &user, "/downloads", "Downloads · Bunyip", content)
}

/// One product section on the downloads page: header with the (pinned, hence
/// latest) version, binary assets, and OCI pull instructions.
fn download_group(g: &AppDownloadGroup, has_membership: bool) -> Markup {
    // Pinned-version distribution model: exactly one version is available per
    // product, so the version shown is by definition the latest. release_tag
    // is empty (not absent) for OCI-only products; see api/types.rs.
    let version = if g.release_tag.is_empty() {
        g.oci.as_ref().map(|o| o.tag.as_str())
    } else {
        Some(g.release_tag.as_str())
    };
    html! {
        section class="border rounded p-4" {
            div class="flex items-center gap-2" {
                @if let Some(ic) = &g.icon_url { img src=(ic) alt="" class="w-6 h-6"; }
                h2 class="font-semibold" { (g.app_display_name) }
                @if let Some(v) = version {
                    span class="font-mono text-xs text-muted-foreground" { (v) }
                    (badge("success", "Latest"))
                }
            }

            // Binary downloads (Forgejo release / package assets)
            @if !g.assets.is_empty() {
                h3 class="text-sm font-medium mt-4 mb-2" { "Binary downloads" }
                ul class="space-y-2" {
                    @for a in &g.assets {
                        li class="flex items-center justify-between" {
                            div {
                                div class="font-mono text-sm" { (a.asset_name) }
                                div class="text-xs text-muted-foreground" { (format_size(a.size_bytes)) }
                            }
                            @if has_membership {
                                a href=(a.download_url) download=(a.asset_name) class="px-3 py-1 rounded bg-primary text-primary-foreground text-sm" { "Download" }
                            } @else {
                                (upgrade_link())
                            }
                        }
                    }
                }
            }

            // Container image (docker login / pull instructions)
            @if let Some(oci) = &g.oci {
                h3 class="text-sm font-medium mt-4 mb-2" { "Container image" }
                @if has_membership {
                    div class="space-y-2" {
                        p class="text-xs text-muted-foreground" {
                            "Log in to the registry with your account email and password, then pull the image:"
                        }
                        (command_block(&format!("docker login {}", oci.registry)))
                        (command_block(&format!("docker pull {}", oci.reference)))
                    }
                } @else {
                    (upgrade_link())
                }
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

/// A copy-pasteable shell command with a copy-to-clipboard button.
fn command_block(cmd: &str) -> Markup {
    // JSON-encode the command so it is a valid JS string literal inside the
    // onclick handler (Maud HTML-escapes the attribute value; the browser
    // un-escapes it before executing). Serializing a &str cannot fail.
    let cmd_js = serde_json::to_string(cmd).expect("serializing a string to JSON is infallible");
    // Clipboard API needs a secure context (HTTPS / localhost). When it is
    // unavailable, select the command text so the user can copy manually;
    // otherwise report success/failure on the button label.
    let copy_js = format!(
        "var b=this;var t=b.innerText;\
         if(navigator.clipboard){{\
           navigator.clipboard.writeText({cmd_js}).then(\
             function(){{b.innerText='Copied';setTimeout(function(){{b.innerText=t}},1500)}},\
             function(){{b.innerText='Copy failed';setTimeout(function(){{b.innerText=t}},1500)}});\
         }}else{{\
           window.getSelection().selectAllChildren(b.previousElementSibling);\
           b.innerText='Press Ctrl+C';setTimeout(function(){{b.innerText=t}},3000);\
         }}"
    );
    html! {
        div class="flex items-center gap-2" {
            code class="flex-1 rounded bg-muted px-3 py-2 font-mono text-sm overflow-x-auto whitespace-nowrap" { (cmd) }
            button type="button" aria-label="Copy command" class=(button_class("outline", "sm", "shrink-0 w-28")) onclick=(copy_js) {
                "Copy"
            }
        }
    }
}

// ===========================================================================
// Billing
// ===========================================================================

pub async fn billing(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/billing").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let invoices = calls::invoices(&st.api, fwd).await.unwrap_or_default();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-2xl font-bold" { "Billing" } p class="text-muted-foreground" { "View and download your invoices." } }
            div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
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
        }
    };
    dashboard_response(&c, &user, "/billing", "Billing · Bunyip", content)
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
    let tier = match user.subscription_tier {
        SubscriptionTier::EarlyAdopter => "Early Adopter",
        SubscriptionTier::Lifetime => "Lifetime",
        _ => "Standard",
    };
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

fn tier_name(t: &SubscriptionTier) -> &'static str {
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
    let stripe = auth_api::setup_status(&st.api)
        .await
        .map(|s| s.stripe_enabled)
        .unwrap_or(true);
    let tier = user.subscription_tier.clone();
    let status = current.as_ref().map(|m| m.status.clone());
    let has = matches!(
        status,
        Some(MembershipStatus::Active) | Some(MembershipStatus::PastDue)
    );
    let past_due = matches!(status, Some(MembershipStatus::PastDue));
    let will_cancel = current
        .as_ref()
        .map(|m| m.cancel_at_period_end)
        .unwrap_or(false);

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Membership" } p class="mt-2 text-muted-foreground" { "Manage your membership and billing." } }
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
                    @if has {
                        @let m = current.clone().unwrap();
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
    dashboard_response(&c, &user, "/membership", "Membership · Bunyip", content)
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
            @if let Some(ok) = &q.ok { div class="rounded-lg border p-3 text-sm flex items-center gap-2" { (icon("check", "h-4 w-4 text-teal-600 dark:text-teal-400")) (ok) } }
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
                        div { p class="text-sm text-muted-foreground" { "Account Type" } p class="font-medium flex items-center gap-2" { @if is_admin { "admin" (badge("default", "Admin")) } @else { "subscriber" } } }
                        div { p class="text-sm text-muted-foreground" { "Email Verified" } p class="font-medium flex items-center gap-2" { @if user.email_verified { (icon("check", "h-4 w-4 text-teal-600 dark:text-teal-400")) "Verified" } @else { (icon("alert-circle", "h-4 w-4 text-yellow-600")) "Not Verified" } } }
                        div { p class="text-sm text-muted-foreground" { "Membership Status" } p class="font-medium" { (status_label(&user.membership_status)) } }
                    }
                }
            }

            // Change email
            (settings_card("mail", "from-primary to-teal-500", "Change Email", html! {
                form method="post" action="/settings/email" class="space-y-4 max-w-md" {
                    div class="space-y-2" { label class="text-sm font-medium" { "New Email Address" } input name="new_email" type="email" placeholder="Enter your new email" class=(crate::handlers::dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "Current Password" } input name="current_password" type="password" placeholder="Enter your current password" class=(crate::handlers::dashboard_input()); }
                    button type="submit" class=(button_class("default", "default", "bg-gradient-to-r from-primary to-teal-500 text-white border-0")) { "Change Email" }
                }
            }))

            // Change password
            (settings_card("lock", "from-indigo-500 to-teal-500", "Change Password", html! {
                form method="post" action="/settings/password" class="space-y-4 max-w-md" {
                    div class="space-y-2" { label class="text-sm font-medium" { "Current Password" } input name="current_password" type="password" class=(crate::handlers::dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "New Password" } input name="new_password" type="password" class=(crate::handlers::dashboard_input()); }
                    div class="space-y-2" { label class="text-sm font-medium" { "Confirm Password" } input name="confirm" type="password" class=(crate::handlers::dashboard_input()); }
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
                    form method="post" action="/settings/account/delete" class="space-y-3 max-w-md" onsubmit="return confirm('Permanently delete your account? This cannot be undone.')" {
                        div class="space-y-2" { label class="text-sm font-medium" { "Password" } input name="password" type="password" placeholder="Enter your password to confirm" class=(crate::handlers::dashboard_input()); }
                        @if user.two_factor_enabled { div class="space-y-2" { label class="text-sm font-medium" { "Two-Factor Code" } input name="totp_code" placeholder="6-digit code" class=(crate::handlers::dashboard_input()); } }
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

pub async fn twofa_setup_get(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match guard(&st, &headers, "/settings/2fa/setup").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let content = match auth_api::setup_2fa(&st.api, fwd).await {
        Ok(s) => html! {
            div class="mx-auto max-w-lg space-y-6" {
                div { h1 class="text-3xl font-bold" { "Set Up Two-Factor Authentication" } p class="mt-2 text-muted-foreground" { "Scan the QR code, then enter a code to confirm." } }
                div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50" {
                    div class="p-6 space-y-6" {
                        div class="flex justify-center rounded-lg bg-white p-4" { div class="[&_svg]:h-[200px] [&_svg]:w-[200px]" { (PreEscaped(qr_svg(&s.otpauth_uri))) } }
                        div class="space-y-2" {
                            label class="text-sm text-muted-foreground" { "Or enter this key manually:" }
                            code class="block rounded bg-muted px-3 py-2 text-sm font-mono break-all" { (s.secret) }
                        }
                        form method="post" action="/settings/2fa/setup" class="space-y-4" {
                            div class="space-y-2" { label class="text-sm font-medium" { "Verification Code" } input name="code" inputmode="numeric" placeholder="000000" class=(crate::handlers::dashboard_input()); }
                            button type="submit" class=(button_class("default", "default", "w-full")) { "Verify & Enable" }
                        }
                    }
                }
            }
        },
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
            html! { div class="mx-auto max-w-lg space-y-4" { (error_box(&e.user_message())) a href="/settings/2fa/setup" class=(button_class("outline","default","")) { "Try again" } } }
        }
    };
    dashboard_response(&c, &user, "/settings", "Two-factor setup · Bunyip", content)
}
