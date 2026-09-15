//! BUNYIP-691 [BUNYIP-672 SSR half]: the Organizations & Teams admin page.
//!
//! One route (`GET /organizations`) that behaves as three progressive states
//! against BUNYIP-672's REST surface:
//!
//! 1. flag off (BUNYIP-493): serves the branded 404 BEFORE the auth guard;
//! 2. flag on, no org yet: renders the Create-your-organization form;
//! 3. flag on, org exists: renders the tabs the parent BUNYIP-626 epic
//!    asked for - a teams list with a create-team form, a Pricing card
//!    reading the BUNYIP-692 catalogue, a Subscription card reading the
//!    BUNYIP-693 snapshot, and a Grants card reading BUNYIP-673 (own + shared).
//!
//! Each POST target under this file writes through the same REST surface
//! and redirects back with a flash `?ok=` / `?error=` query so a page
//! reload never resubmits a form. Errors from the API (409 duplicate,
//! 422 validation, 502 upstream Stripe) surface as the flash text; the
//! wording is the raw API message trimmed to a reasonable length so an
//! operator reading a redirect URL still sees why the write refused.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::calls;
use crate::api::types::{
    MokoshGrant, OrgSubscription, OrgTier, Organization, PricingResponse, Team,
};
use crate::handlers::{dashboard_response, guard};
use crate::views::layout::orgs_enabled;
use crate::views::ui::empty_state;
use crate::web::{redirect_cookies, AppState};

fn urlenc(s: &str) -> String {
    urlencoding::encode(s).into_owned()
}

/// A flash payload delivered by `?ok=…` or `?error=…` on the redirect
/// target. Kept as a struct so `Query<Flash>` deserialises the search
/// string into either half; either being absent is the common case, so
/// both fields are `#[serde(default)]`.
#[derive(Debug, Default, Deserialize)]
pub struct Flash {
    #[serde(default)]
    pub ok: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

fn flash_banner(flash: &Flash) -> Markup {
    html! {
        @if let Some(msg) = &flash.ok {
            div class="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-800 dark:text-emerald-300" {
                (msg)
            }
        }
        @if let Some(msg) = &flash.error {
            div class="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-800 dark:text-red-300" {
                (msg)
            }
        }
    }
}

/// `GET /organizations`.
///
/// With the flag off the caller gets the same 404 the router fallback
/// renders, BEFORE the auth guard runs: a redirect to `/login` would
/// confirm the route exists, which is exactly what "dark in production"
/// must not do. With the flag on and no org yet, the page renders the
/// create form; with an org, it renders the full dashboard.
pub async fn organizations(
    State(st): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(flash): axum::extract::Query<Flash>,
) -> Response {
    if !orgs_enabled() {
        return crate::skin::public::not_found(State(st), headers).await;
    }
    let (user, c) = match guard(&st, &headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cookie = c.forward.as_deref();
    let org = calls::get_own_organization(&st.api, cookie)
        .await
        .unwrap_or_default();
    let content = match org {
        None => no_org_content(&flash),
        Some(org) => {
            // Fetch the four cards' data in parallel: teams, org tiers,
            // subscription snapshot, received + issued grants. Each is
            // resilient - a failed fetch renders the card's fallback rather
            // than failing the whole page.
            let (teams, pricing, subscription, received, issued) = tokio::join!(
                calls::list_teams(&st.api, cookie),
                calls::pricing(&st.api),
                calls::get_org_subscription(&st.api, cookie),
                calls::list_received_grants(&st.api, cookie),
                calls::list_issued_grants(&st.api, cookie),
            );
            with_org_content(
                &org,
                &flash,
                teams.ok(),
                pricing.ok(),
                subscription.ok(),
                received.ok(),
                issued.ok(),
            )
        }
    };
    dashboard_response(&c, &user, "/organizations", "Organizations", content)
}

fn no_org_content(flash: &Flash) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "Organizations & Teams" }
                p class="mt-2 text-muted-foreground" {
                    "Create an organization to collect teams under one billing and identity plane."
                }
            }
            (flash_banner(flash))
            form method="post" action="/organizations/create" class="rounded-lg border bg-card p-6 space-y-4 max-w-lg" {
                div {
                    label for="org-name" class="block text-sm font-medium mb-1" { "Organization name" }
                    input
                        id="org-name"
                        name="name"
                        type="text"
                        required
                        maxlength="100"
                        placeholder="e.g. Acme MSP"
                        class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" {}
                }
                button
                    type="submit"
                    class="inline-flex items-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90"
                    { "Create organization" }
            }
        }
    }
}

fn with_org_content(
    org: &Organization,
    flash: &Flash,
    teams: Option<Vec<Team>>,
    pricing: Option<PricingResponse>,
    subscription: Option<OrgSubscription>,
    received: Option<Vec<MokoshGrant>>,
    issued: Option<Vec<MokoshGrant>>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div class="flex items-baseline justify-between" {
                div {
                    h1 class="text-3xl font-bold" { (org.name) }
                    p class="mt-1 text-sm text-muted-foreground" { "Organizations & Teams" }
                }
            }
            (flash_banner(flash))
            div class="grid grid-cols-1 lg:grid-cols-2 gap-6" {
                (teams_card(teams.as_deref()))
                (subscription_card(pricing.as_ref(), subscription.as_ref(), org))
            }
            div class="grid grid-cols-1 lg:grid-cols-2 gap-6" {
                (received_grants_card(received.as_deref()))
                (issued_grants_card(issued.as_deref()))
            }
        }
    }
}

fn teams_card(teams: Option<&[Team]>) -> Markup {
    html! {
        div class="rounded-lg border bg-card p-6" {
            div class="flex items-center justify-between mb-4" {
                h2 class="text-lg font-semibold" { "Teams" }
            }
            @match teams {
                None => div class="text-sm text-muted-foreground" {
                    "Could not load teams. Try refreshing the page."
                },
                Some([]) => (empty_state("users", "No teams yet.", None)),
                Some(list) => ul class="divide-y divide-border" {
                    @for team in list {
                        li class="py-3" {
                            div class="text-sm font-medium" { (team.name) }
                            @if let Some(d) = &team.description {
                                @if !d.is_empty() {
                                    div class="text-xs text-muted-foreground" { (d) }
                                }
                            }
                        }
                    }
                },
            }
            form method="post" action="/organizations/teams/create" class="mt-4 space-y-3" {
                div {
                    label for="team-name" class="block text-xs font-medium mb-1" { "Team name" }
                    input
                        id="team-name"
                        name="name"
                        type="text"
                        required
                        maxlength="100"
                        placeholder="e.g. On-call"
                        class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" {}
                }
                div {
                    label for="team-description" class="block text-xs font-medium mb-1" { "Description (optional)" }
                    input
                        id="team-description"
                        name="description"
                        type="text"
                        maxlength="500"
                        class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" {}
                }
                button
                    type="submit"
                    class="inline-flex items-center rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90"
                    { "Create team" }
            }
        }
    }
}

fn subscription_card(
    pricing: Option<&PricingResponse>,
    subscription: Option<&OrgSubscription>,
    org: &Organization,
) -> Markup {
    let tiers: &[OrgTier] = pricing.map(|p| p.org_tiers.as_slice()).unwrap_or(&[]);
    html! {
        div class="rounded-lg border bg-card p-6" {
            h2 class="text-lg font-semibold mb-4" { "Billing" }
            @if tiers.is_empty() {
                div class="text-sm text-muted-foreground mb-3" {
                    "No org tiers are published. An admin can add one on the Pricing page."
                }
            } @else {
                form method="post" action="/organizations/tier" class="mb-4 space-y-2" {
                    label for="org-tier-id" class="block text-xs font-medium" { "Tier" }
                    div class="flex gap-2" {
                        select
                            id="org-tier-id"
                            name="org_tier_id"
                            class="flex-1 rounded-md border border-input bg-background px-3 py-2 text-sm"
                        {
                            @for tier in tiers {
                                option
                                    value=(tier.id)
                                    selected[org.org_tier_id.as_deref() == Some(&tier.id)]
                                {
                                    (tier.name)
                                    @if tier.included_seats > 0 {
                                        " · " (tier.included_seats) " seats included"
                                    }
                                    @if let Some(cap) = tier.seat_cap {
                                        " · cap " (cap)
                                    }
                                }
                            }
                        }
                        button
                            type="submit"
                            class="rounded-md bg-secondary px-3 py-1.5 text-xs font-medium text-secondary-foreground hover:opacity-90"
                            { "Save" }
                    }
                }
            }
            @match subscription {
                None => div class="text-sm text-muted-foreground" {
                    "Could not load subscription state. Try refreshing the page."
                },
                Some(snap) => (subscription_status(snap, org)),
            }
        }
    }
}

fn subscription_status(snap: &OrgSubscription, org: &Organization) -> Markup {
    let status = snap.subscription_status.as_deref().unwrap_or("");
    let has_tier = org.org_tier_id.is_some();
    let is_active = matches!(status, "active" | "trialing" | "past_due");
    html! {
        div class="space-y-2 text-sm" {
            @if snap.stripe_subscription_id.is_some() {
                div {
                    span class="font-medium" { "Status: " }
                    span class="text-muted-foreground" { (status) }
                }
                div {
                    span class="font-medium" { "Seats billed: " }
                    span class="text-muted-foreground" { (snap.seat_count) }
                }
                @if is_active {
                    div class="flex gap-2 pt-2" {
                        form method="post" action="/organizations/subscription/change" {
                            button
                                type="submit"
                                class="rounded-md bg-secondary px-3 py-1.5 text-xs font-medium text-secondary-foreground hover:opacity-90"
                                { "Apply current tier" }
                        }
                        form method="post" action="/organizations/subscription/cancel" {
                            button
                                type="submit"
                                class="rounded-md border border-red-500/40 px-3 py-1.5 text-xs font-medium text-red-700 dark:text-red-400 hover:bg-red-500/10"
                                onclick="return confirm('Cancel the org subscription at period end?')"
                                { "Cancel at period end" }
                        }
                    }
                }
            } @else if has_tier {
                form method="post" action="/organizations/subscription/subscribe" {
                    button
                        type="submit"
                        class="inline-flex items-center rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90"
                        { "Subscribe to the selected tier" }
                }
            } @else {
                div class="text-sm text-muted-foreground" {
                    "Pick a tier above, then subscribe."
                }
            }
        }
    }
}

fn received_grants_card(grants: Option<&[MokoshGrant]>) -> Markup {
    html! {
        div class="rounded-lg border bg-card p-6" {
            h2 class="text-lg font-semibold mb-4" { "Shared with you" }
            @match grants {
                None => div class="text-sm text-muted-foreground" {
                    "Could not load received grants."
                },
                Some([]) => div class="text-sm text-muted-foreground" {
                    "Nobody has shared a Mokosh account with you."
                },
                Some(list) => ul class="divide-y divide-border text-sm" {
                    @for g in list {
                        li class="py-3" {
                            div class="font-medium" { (g.mokosh_account_id) }
                            div class="text-xs text-muted-foreground" {
                                "Role: " (g.role)
                            }
                        }
                    }
                },
            }
        }
    }
}

fn issued_grants_card(grants: Option<&[MokoshGrant]>) -> Markup {
    html! {
        div class="rounded-lg border bg-card p-6" {
            h2 class="text-lg font-semibold mb-4" { "Grants you have issued" }
            @match grants {
                None => div class="text-sm text-muted-foreground" {
                    "Could not load issued grants."
                },
                Some([]) => div class="text-sm text-muted-foreground" {
                    "You have not shared any Mokosh account yet."
                },
                Some(list) => ul class="divide-y divide-border text-sm mb-4" {
                    @for g in list {
                        li class="py-3 flex items-center justify-between" {
                            div {
                                div class="font-medium" { (g.mokosh_account_id) }
                                div class="text-xs text-muted-foreground" {
                                    "Role: " (g.role)
                                }
                            }
                            form method="post" action=(format!("/organizations/grants/{}/revoke", urlenc(&g.id))) {
                                button
                                    type="submit"
                                    class="rounded-md border border-red-500/40 px-2.5 py-1 text-xs text-red-700 dark:text-red-400 hover:bg-red-500/10"
                                    onclick="return confirm('Revoke this grant? The grantee will lose access within 30 seconds.')"
                                    { "Revoke" }
                            }
                        }
                    }
                },
            }
            form method="post" action="/organizations/grants/create" class="space-y-3" {
                div {
                    label for="grantee-email" class="block text-xs font-medium mb-1" { "Grantee email" }
                    input
                        id="grantee-email"
                        name="grantee_email"
                        type="email"
                        required
                        class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" {}
                }
                div {
                    label for="mokosh-account-id" class="block text-xs font-medium mb-1" { "Mokosh account" }
                    input
                        id="mokosh-account-id"
                        name="mokosh_account_id"
                        type="text"
                        required
                        placeholder="tenant slug"
                        class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" {}
                }
                div {
                    label for="grant-role" class="block text-xs font-medium mb-1" { "Role" }
                    select
                        id="grant-role"
                        name="role"
                        class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    {
                        option value="read_only" { "Read only" }
                        option value="technician" { "Technician" }
                        option value="finance" { "Finance" }
                        option value="manager" { "Manager" }
                        option value="admin" { "Admin" }
                    }
                }
                button
                    type="submit"
                    class="inline-flex items-center rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90"
                    { "Share access" }
            }
        }
    }
}

// -- POST targets -----------------------------------------------------------
//
// Every POST redirects back to `/organizations` with a `?ok=` or
// `?error=` flash. A `303 See Other` from `redirect_cookies` means a
// reload of the target page does not resubmit the form.

fn require_flag_and_guard(_st: &AppState) -> Option<Response> {
    if orgs_enabled() {
        None
    } else {
        // Off means invisible: a caller poking a POST directly gets 404,
        // not "success" and not "unauthorized". Kept BEFORE the auth
        // guard for the same "off means invisible" reason `GET
        // /organizations` uses.
        Some(axum::response::IntoResponse::into_response((
            axum::http::StatusCode::NOT_FOUND,
            "",
        )))
    }
}

fn redirect_ok(msg: &str, set_cookies: &[String]) -> Response {
    redirect_cookies(&format!("/organizations?ok={}", urlenc(msg)), set_cookies)
}

fn redirect_err(msg: &str, set_cookies: &[String]) -> Response {
    redirect_cookies(
        &format!("/organizations?error={}", urlenc(msg)),
        set_cookies,
    )
}

#[derive(Debug, Deserialize)]
pub struct CreateOrgForm {
    pub name: String,
}

pub async fn post_create_org(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateOrgForm>,
) -> Response {
    if let Some(r) = require_flag_and_guard(&st) {
        return r;
    }
    let (_, c) = match guard(&st, &headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match calls::create_organization(&st.api, c.forward.as_deref(), form.name.trim()).await {
        Ok(_) => redirect_ok("Organization created.", &c.set_cookies),
        Err(e) => redirect_err(&e.user_message(), &c.set_cookies),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateTeamForm {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

pub async fn post_create_team(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateTeamForm>,
) -> Response {
    if let Some(r) = require_flag_and_guard(&st) {
        return r;
    }
    let (_, c) = match guard(&st, &headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let description = form
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match calls::create_team(&st.api, c.forward.as_deref(), form.name.trim(), description).await {
        Ok(_) => redirect_ok("Team created.", &c.set_cookies),
        Err(e) => redirect_err(&e.user_message(), &c.set_cookies),
    }
}

#[derive(Debug, Deserialize)]
pub struct SetTierForm {
    pub org_tier_id: String,
}

pub async fn post_set_tier(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SetTierForm>,
) -> Response {
    if let Some(r) = require_flag_and_guard(&st) {
        return r;
    }
    let (_, c) = match guard(&st, &headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match calls::set_organization_tier(&st.api, c.forward.as_deref(), form.org_tier_id.trim()).await
    {
        Ok(()) => redirect_ok("Tier updated.", &c.set_cookies),
        Err(e) => redirect_err(&e.user_message(), &c.set_cookies),
    }
}

pub async fn post_subscribe(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(r) = require_flag_and_guard(&st) {
        return r;
    }
    let (_, c) = match guard(&st, &headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match calls::subscribe_org(&st.api, c.forward.as_deref()).await {
        Ok(_) => redirect_ok("Subscribed.", &c.set_cookies),
        Err(e) => redirect_err(&e.user_message(), &c.set_cookies),
    }
}

pub async fn post_change_tier(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(r) = require_flag_and_guard(&st) {
        return r;
    }
    let (_, c) = match guard(&st, &headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match calls::change_org_tier(&st.api, c.forward.as_deref()).await {
        Ok(_) => redirect_ok("Subscription tier changed.", &c.set_cookies),
        Err(e) => redirect_err(&e.user_message(), &c.set_cookies),
    }
}

pub async fn post_cancel(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(r) = require_flag_and_guard(&st) {
        return r;
    }
    let (_, c) = match guard(&st, &headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match calls::cancel_org_subscription(&st.api, c.forward.as_deref()).await {
        Ok(_) => redirect_ok("Subscription cancelled at period end.", &c.set_cookies),
        Err(e) => redirect_err(&e.user_message(), &c.set_cookies),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateGrantForm {
    pub grantee_email: String,
    pub mokosh_account_id: String,
    pub role: String,
}

pub async fn post_create_grant(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CreateGrantForm>,
) -> Response {
    if let Some(r) = require_flag_and_guard(&st) {
        return r;
    }
    let (_, c) = match guard(&st, &headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match calls::create_grant(
        &st.api,
        c.forward.as_deref(),
        form.grantee_email.trim(),
        form.mokosh_account_id.trim(),
        &form.role,
    )
    .await
    {
        Ok(_) => redirect_ok("Access shared.", &c.set_cookies),
        Err(e) => redirect_err(&e.user_message(), &c.set_cookies),
    }
}

pub async fn post_revoke_grant(
    State(st): State<AppState>,
    axum::extract::Path(grant_id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(r) = require_flag_and_guard(&st) {
        return r;
    }
    let (_, c) = match guard(&st, &headers, "/organizations").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match calls::revoke_grant(&st.api, c.forward.as_deref(), &grant_id).await {
        Ok(()) => redirect_ok("Grant revoked.", &c.set_cookies),
        Err(e) => redirect_err(&e.user_message(), &c.set_cookies),
    }
}
