//! Admin panel: Stripe: config + setup docs + products + prices (BUNYIP-416).

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::api::types::User;
use crate::api::ApiError;
use crate::auth::AuthCtx;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::{format_stripe_amount, urlenc};
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{
    badge, button_class, empty_state, error_box, error_box_detailed, icon, success_box,
};
use crate::web::{redirect_cookies, AppState};

/// BUNYIP-516: the result of loading one of the Stripe-backed lists on this
/// page. `Ok` is the real list, which may legitimately be empty; `Err` means
/// bunyip could not read it from Stripe and must SAY so, because rendering the
/// empty state instead tells the admin "none exist" as though it were a fact.
/// Before DUNITE-10 a 403 on the webhook listing came back as `Ok(vec![])`, so
/// the page confidently reported "No webhook endpoints yet" to an admin whose
/// key simply could not see them.
pub(super) type Loaded<'a, T> = Result<&'a [T], &'a ApiError>;

/// The cause line under a "could not read" box.
///
/// bunyip-api answers a permission or key failure with a 4xx whose message is
/// bunyip-authored and names the exact permission (`stripe_err_for`, BUNYIP-516),
/// so it is shown as-is. Anything else collapses to a generic line at
/// `ApiError::user_message` (BUNYIP-477), and the static hint names the
/// permission that is the usual cause instead of leaving the admin guessing.
fn load_failure_cause(e: &ApiError, permission_hint: &str) -> String {
    match e.status {
        400..=499 if !e.message.is_empty() => e.user_message(),
        _ => permission_hint.to_string(),
    }
}

/// The "could not read this list" box: what bunyip does not know, why it
/// probably happened, and the request id that finds it in the api log.
fn load_failure_box(headline: &str, e: &ApiError, permission_hint: &str) -> Markup {
    error_box_detailed(
        headline,
        Some(&load_failure_cause(e, permission_hint)),
        e.request_id.as_deref(),
    )
}

/// Setup guidance ported from the a8n-tools Stripe admin panel (BUNYIP-416):
/// how and where to create the restricted API key and how the app-tag scopes
/// what is shown. Rendered as a full-width intro card above the config form.
pub(super) fn stripe_setup_docs() -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="p-6 space-y-3 text-sm text-muted-foreground" {
                div class="flex items-center gap-2 text-foreground" { (icon("help-circle", "h-5 w-5 text-primary-text")) h3 class="text-base font-semibold" { "Setting up Stripe" } }
                p {
                    "Your Stripe secret key authenticates API requests. Generate a "
                    a href="https://dashboard.stripe.com/apikeys" target="_blank" rel="noopener noreferrer" class="text-primary-text hover:underline" { "restricted key" }
                    " with these permissions set to " span class="font-medium text-foreground" { "Write" }
                    ": Products, Prices, Customers, Subscriptions, Checkout Sessions, and "
                    span class="font-medium text-foreground" { "Webhook Endpoints" }
                    "; and " span class="font-medium text-foreground" { "Read" } " for Invoices."
                }
                // BUNYIP-516: the page offers a Create endpoint button that
                // fails with a 403 without this permission, so the list that
                // grants it has to say which button needs it.
                p {
                    "Webhook Endpoints is what the " span class="font-medium text-foreground" { "Create endpoint" }
                    " button further down needs. Without it Stripe answers 403 and bunyip can neither create an endpoint nor read the ones that already exist."
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

/// The Products block: a create form plus the app-tagged product list, each with
/// an Edit disclosure (BUNYIP-511, name/description in place) and an
/// Archive/Unarchive action. `Err` is the "could not read" state (BUNYIP-516) and
/// is rendered as such, never as the empty state.
pub(super) fn stripe_products_block(
    products: Loaded<'_, crate::api::types::StripeProduct>,
    prices: Loaded<'_, crate::api::types::StripePrice>,
) -> Markup {
    // BUNYIP-512: an active product with no active price is unsellable (the
    // state an archive-then-unarchive can leave behind); flag it so it is not
    // silently broken. A price-list read failure (`Err`, BUNYIP-516) makes no
    // claim: this is true ONLY when the list loaded and holds no active price.
    let flag_no_active_price = |product_id: &str| match prices {
        Ok(list) => !list
            .iter()
            .any(|pr| pr.product_id == product_id && pr.active),
        Err(_) => false,
    };
    admin_block(
        "Products",
        Some("Stripe products for your subscription tiers."),
        html! {
            form method="post" action="/admin/stripe/products" class="flex flex-wrap items-end gap-3 mb-4" {
                div class="space-y-1 flex-1 min-w-[12rem]" { label for="name" class="text-xs font-medium" { "Name" } input id="name" name="name" required placeholder="Personal Plan" class=(dashboard_input()); }
                div class="space-y-1 flex-1 min-w-[12rem]" { label for="description" class="text-xs font-medium" { "Description" } input id="description" name="description" placeholder="Optional" class=(dashboard_input()); }
                button type="submit" class=(button_class("default", "sm", "")) { "Create product" }
            }
            @match products {
                Err(e) => (load_failure_box(
                    "Could not read the products from Stripe, so bunyip cannot tell whether any exist.",
                    e,
                    "This usually means the restricted key lacks the Products permission, or no valid key is saved above.",
                )),
                Ok([]) => (empty_state("package", "No products yet. Create one to get started.", None)),
                Ok(list) => div class="divide-y" {
                    @for p in list {
                        div class="py-3 space-y-3" {
                            div class="flex items-center justify-between gap-4" {
                                div class="min-w-0" {
                                    p class="font-medium flex items-center gap-2" {
                                        (p.name)
                                        @if p.active { (badge("success", "Active")) } @else { (badge("secondary", "Archived")) }
                                        @if p.active && flag_no_active_price(&p.id) { (badge("warning", "No active price")) }
                                    }
                                    @if let Some(d) = p.description.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
                                        p class="text-xs text-muted-foreground truncate" { (d) }
                                    }
                                    p class="text-xs text-muted-foreground font-mono truncate" { (p.id) }
                                }
                                @if p.active {
                                    @if p.member_count > 0 {
                                        (archive_blocked_by_members(p.member_count))
                                    } @else {
                                        form method="post" action=(format!("/admin/stripe/products/{}/archive", p.id)) data-confirm="Archive this product? Its prices are archived too, and it will no longer be available for new subscriptions." {
                                            button type="submit" class=(button_class("outline", "sm", "")) { "Archive" }
                                        }
                                    }
                                } @else {
                                    // BUNYIP-513: an archived product can be restored. No cascade to
                                    // prices - each archived price is restored on its own row.
                                    form method="post" action=(format!("/admin/stripe/products/{}/unarchive", p.id)) data-confirm="Restore this product? It becomes purchasable again. Its prices stay as they are; restore any archived price on its own row." {
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Unarchive" }
                                    }
                                }
                            }
                            // BUNYIP-511: correct the name/description in place.
                            (product_edit_details(p))
                        }
                    }
                }
            }
        },
    )
}

/// BUNYIP-512: the courtesy control shown in place of a live Archive button when
/// a plan still has members: a disabled button plus the member count. The server
/// guard is authoritative (a direct POST is refused with 409); this only spares
/// the admin a click that would fail.
fn archive_blocked_by_members(member_count: i64) -> Markup {
    let label = if member_count == 1 {
        "1 member".to_string()
    } else {
        format!("{member_count} members")
    };
    html! {
        div class="flex items-center gap-2 shrink-0" {
            span class="text-xs text-muted-foreground" { (label) }
            button type="button" disabled title="Move members to another plan before archiving" class=(button_class("outline", "sm", "opacity-50 cursor-not-allowed")) { "Archive" }
        }
    }
}

/// BUNYIP-511: the inline "edit name / description" disclosure for one product
/// row. A native `<details>` (no JS, matching the app's other disclosures) whose
/// form posts to `/admin/stripe/products/{id}`. The request carries name +
/// description only, so an edit cannot change lifecycle (BUNYIP-512/513 own
/// archive/restore) and the Stripe `app_tag` metadata survives.
fn product_edit_details(p: &crate::api::types::StripeProduct) -> Markup {
    let desc = p.description.as_deref().unwrap_or_default();
    html! {
        details {
            summary class=(button_class("outline", "sm", "cursor-pointer list-none [&::-webkit-details-marker]:hidden")) { "Edit" }
            form method="post" action=(format!("/admin/stripe/products/{}", p.id)) class="mt-3 w-full max-w-md rounded-md border p-3 space-y-3 text-sm" {
                div class="space-y-1" {
                    label for=(format!("name-{}", p.id)) class="text-xs font-medium" { "Name" }
                    input id=(format!("name-{}", p.id)) name="name" value=(p.name) required maxlength="250" class=(dashboard_input());
                }
                div class="space-y-1" {
                    label for=(format!("desc-{}", p.id)) class="text-xs font-medium" { "Description" }
                    input id=(format!("desc-{}", p.id)) name="description" value=(desc) maxlength="500" placeholder="Optional - leave blank to clear" class=(dashboard_input());
                }
                button type="submit" class=(button_class("default", "sm", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
            }
        }
    }
}

/// BUNYIP-511: the inline "replace" disclosure for one active price row. Stripe
/// prices are immutable, so this posts the NEW amount/currency/interval to
/// `/admin/stripe/prices/{id}/replace`, which creates a new price on the same
/// product, repoints bunyip's references, and archives this one. The confirm
/// names what is NOT migrated (existing subscriptions, locked-in prices).
fn price_replace_details(pr: &crate::api::types::StripePrice) -> Markup {
    let amount = format!("{:.2}", pr.unit_amount.unwrap_or(0) as f64 / 100.0);
    let cur = pr.currency.to_lowercase();
    let interval = pr.recurring_interval.as_deref().unwrap_or("month");
    html! {
        details {
            summary class=(button_class("outline", "sm", "cursor-pointer list-none [&::-webkit-details-marker]:hidden")) { "Replace" }
            form method="post" action=(format!("/admin/stripe/prices/{}/replace", pr.id)) data-confirm="Replace this price? A new price is created and this one is archived. The catalog mapping and product entitlements move to the new price. Existing subscriptions keep billing on the old price, and anyone on a grandfathered price stays on theirs." class="mt-3 w-full max-w-xl rounded-md border p-3 space-y-3 text-sm" {
                // BUNYIP-511: explain WHY this is a replace, not an edit, so the
                // create-then-archive is understood rather than surprising.
                div class="space-y-1 text-xs text-muted-foreground" {
                    p {
                        span class="font-medium text-foreground" { "Why replace instead of edit? " }
                        "A Stripe price is immutable: its amount, currency and interval are fixed the moment it is created. Live subscriptions and past invoices reference that exact price object, so letting you change its amount would retroactively alter what existing customers agreed to pay and what their invoices say. Stripe only permits changing a price's active state, nickname or metadata - never its amount."
                    }
                    p { "So changing what a plan costs means creating a NEW price at the new amount and archiving this one. bunyip moves the catalog mapping and product entitlements onto the new price for you. Existing subscriptions keep billing on the old price until migrated in Stripe, and anyone on a grandfathered (locked) price stays on theirs." }
                }
                div class="flex flex-wrap items-end gap-3" {
                    div class="space-y-1 w-28" { label for=(format!("amount-{}", pr.id)) class="text-xs font-medium" { "Amount" } input id=(format!("amount-{}", pr.id)) name="amount" type="number" step="0.01" min="0" required value=(amount) class=(dashboard_input()); }
                    div class="space-y-1 w-24" {
                        label for=(format!("currency-{}", pr.id)) class="text-xs font-medium" { "Currency" }
                        select id=(format!("currency-{}", pr.id)) name="currency" class=(dashboard_input()) {
                            option value="usd" selected[cur == "usd"] { "USD" }
                            option value="eur" selected[cur == "eur"] { "EUR" }
                            option value="gbp" selected[cur == "gbp"] { "GBP" }
                        }
                    }
                    div class="space-y-1 w-28" {
                        label for=(format!("interval-{}", pr.id)) class="text-xs font-medium" { "Interval" }
                        select id=(format!("interval-{}", pr.id)) name="interval" class=(dashboard_input()) {
                            option value="month" selected[interval == "month"] { "Monthly" }
                            option value="year" selected[interval == "year"] { "Yearly" }
                        }
                    }
                    button type="submit" class=(button_class("default", "sm", "")) { "Replace price" }
                }
            }
        }
    }
}

/// The Prices block: a create form (product dropdown limited to active
/// products; amount in dollars, zero allowed for a lifetime plan) plus the
/// price list, each active price with a Replace and an Archive action.
///
/// BUNYIP-511: a Stripe price is immutable in amount, currency and interval, so
/// changing what a plan costs is a REPLACE, not an edit: the Replace control
/// creates a new price on the same product, moves the catalog mapping and the
/// product entitlements onto it, and archives the old price. Existing Stripe
/// subscriptions and grandfathered (locked) prices are deliberately left on the
/// old price; the control's confirm and the block caption say so.
pub(super) fn stripe_prices_block(
    prices: Loaded<'_, crate::api::types::StripePrice>,
    products: Loaded<'_, crate::api::types::StripeProduct>,
) -> Markup {
    // BUNYIP-516: an unreadable product list would otherwise leave the dropdown
    // with nothing in it, which reads as "this account has no products". The
    // Products block states the cause; the caption below says why the picker is
    // empty so the form is not silently unusable.
    let product_list = products.unwrap_or(&[]);
    let name_of = |pid: &str| {
        product_list
            .iter()
            .find(|p| p.id == pid)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| pid.to_string())
    };
    admin_block(
        "Prices",
        Some("Pricing for your products. A lifetime plan is a $0.00 price. Prices cannot be edited in Stripe, so Replace creates a new price and archives the old one, moving the catalog mapping and entitlements across; existing subscriptions and locked-in prices stay on the old price."),
        html! {
            form method="post" action="/admin/stripe/prices" class="flex flex-wrap items-end gap-3 mb-4" {
                div class="space-y-1 min-w-[11rem]" {
                    label for="product_id" class="text-xs font-medium" { "Product" }
                    select id="product_id" name="product_id" required class=(dashboard_input()) {
                        option value="" disabled selected { "Select a product" }
                        @for p in product_list.iter().filter(|p| p.active) { option value=(p.id) { (p.name) } }
                    }
                    @if products.is_err() {
                        p class="text-xs text-destructive-text" { "Empty because the products could not be read from Stripe, not because there are none. See the Products block above." }
                    }
                }
                div class="space-y-1 w-28" { label for="amount" class="text-xs font-medium" { "Amount" } input id="amount" name="amount" type="number" step="0.01" min="0" required placeholder="9.99" class=(dashboard_input()); }
                div class="space-y-1 w-24" {
                    label for="currency" class="text-xs font-medium" { "Currency" }
                    select id="currency" name="currency" class=(dashboard_input()) { option value="usd" { "USD" } option value="eur" { "EUR" } option value="gbp" { "GBP" } }
                }
                div class="space-y-1 w-28" {
                    label for="interval" class="text-xs font-medium" { "Interval" }
                    select id="interval" name="interval" class=(dashboard_input()) { option value="month" { "Monthly" } option value="year" { "Yearly" } }
                }
                button type="submit" class=(button_class("default", "sm", "")) { "Create price" }
            }
            @match prices {
                Err(e) => (load_failure_box(
                    "Could not read the prices from Stripe, so bunyip cannot tell whether any exist.",
                    e,
                    "This usually means the restricted key lacks the Prices permission, or no valid key is saved above.",
                )),
                Ok([]) => (empty_state("banknote", "No prices yet. Create one to get started.", None)),
                Ok(list) => div class="divide-y" {
                    @for pr in list {
                        div class={ "py-3 space-y-3 " (if pr.active { "" } else { "opacity-50" }) } {
                            div class="flex items-center justify-between gap-4" {
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
                                    @if pr.member_count > 0 {
                                        (archive_blocked_by_members(pr.member_count))
                                    } @else {
                                        form method="post" action=(format!("/admin/stripe/prices/{}/archive", pr.id)) data-confirm="Archive this price? Existing subscriptions using it are not affected." {
                                            button type="submit" class=(button_class("outline", "sm", "")) { "Archive" }
                                        }
                                    }
                                } @else {
                                    // BUNYIP-513: restore an archived price.
                                    form method="post" action=(format!("/admin/stripe/prices/{}/unarchive", pr.id)) data-confirm="Restore this price? It becomes purchasable again." {
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Unarchive" }
                                    }
                                }
                            }
                            // BUNYIP-511: change what this plan costs. A replace, not
                            // an edit (Stripe prices are immutable), so it is offered
                            // only on an active price.
                            @if pr.active { (price_replace_details(pr)) }
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
/// DEV-518: events pre-filled into the create-endpoint form - the set bunyip's
/// webhook processor actually handles. The admin can edit them before creating.
const RECOMMENDED_WEBHOOK_EVENTS: &[&str] = &[
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.payment_succeeded",
    "invoice.payment_failed",
];

/// BUNYIP-510: the webhook URL an admin must register in Stripe.
/// `webhook::configure` mounts `/webhooks/stripe` INSIDE the `/v1` scope
/// (`bunyip-api/src/routes/mod.rs`), so the path is `/v1/webhooks/stripe`; a
/// registration without `/v1` 404s in Stripe and every event is lost.
pub(super) fn stripe_webhook_url(api_public_origin: &str) -> String {
    format!(
        "{}/v1/webhooks/stripe",
        api_public_origin.trim_end_matches('/')
    )
}

/// BUNYIP-510: whether the derived origin is one Stripe can actually reach.
/// `Config::api_public_origin` falls back to the internal `api_url` when
/// `BUNYIP_API_PUBLIC_ORIGIN` is unset, which prefills an unreachable Docker
/// hostname; the caption warns instead of presenting that value as correct.
pub(super) fn is_public_https_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => authority,
    };
    !host.is_empty() && !matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// DEV-518: the Webhook Endpoints block - a create form (endpoint URL + enabled
/// events, pre-filled with the events bunyip processes) plus the list of
/// registered endpoints, each with a Delete action. Fills the admin-UI gap the
/// backend already had (list / create / delete_webhook_endpoint); the a8n-tools
/// React admin already exposed this.
/// BUNYIP-510: the URL is prefilled from the deployment's public API origin and
/// the block states whether processing is live (`has_webhook_secret`).
/// BUNYIP-516: what a failed create hands back to the form, so fixing the key
/// and pressing the button again does not mean retyping the URL and the event
/// list. All-`None` on a normal page load.
#[derive(Default)]
pub(super) struct WebhookRetry<'a> {
    /// The user-facing reason the create failed.
    pub error: Option<&'a str>,
    /// The endpoint URL that was submitted.
    pub url: Option<&'a str>,
    /// The enabled-events text that was submitted, verbatim.
    pub events: Option<&'a str>,
    /// bunyip-api's request id for the failed create.
    pub reference: Option<&'a str>,
}

pub(super) fn stripe_webhooks_block(
    webhooks: Loaded<'_, crate::api::types::StripeWebhookEndpoint>,
    api_public_origin: &str,
    has_webhook_secret: bool,
    retry: &WebhookRetry<'_>,
) -> Markup {
    let derived_url = stripe_webhook_url(api_public_origin);
    // BUNYIP-516: a failed attempt keeps what the admin typed; otherwise the
    // form falls back to the derived URL and the recommended event set.
    let url = retry.url.unwrap_or(&derived_url);
    let default_events = RECOMMENDED_WEBHOOK_EVENTS.join(", ");
    let events = retry.events.unwrap_or(&default_events);
    let origin_ok = is_public_https_origin(api_public_origin);
    admin_block(
        "Webhook endpoints",
        Some("Receives information from Stripe about checkout, subscription, and payment events. bunyip uses it to activate a membership after checkout, keep subscription status and tier in step with the subscription, grant or revoke product entitlements, and send payment receipt and failure emails. Create the endpoint here and bunyip saves its signing secret for you."),
        html! {
            // BUNYIP-510 / BUNYIP-203: `stripe_webhook` rejects every delivery
            // until a real signing secret is stored, so say so on the page
            // rather than only in the api log.
            div class="mb-4" {
                @if has_webhook_secret {
                    (success_box("Webhook processing is active: a signing secret is saved, so bunyip verifies and processes incoming Stripe events."))
                } @else {
                    (error_box("Webhook processing is not active: bunyip rejects every incoming Stripe event until a signing secret is saved. Creating an endpoint below saves one automatically."))
                }
            }
            // BUNYIP-516: a failed create is reported here, next to the button
            // that failed and the values it was given, rather than as a toast
            // that has faded by the time the admin looks.
            @if let Some(err) = retry.error {
                div class="mb-4" {
                    (error_box_detailed("Creating the webhook endpoint failed. Your entries are kept below, so fix the cause and press Create endpoint again.", Some(err), retry.reference))
                }
            }
            form method="post" action="/admin/stripe/webhooks" class="space-y-3 mb-4" {
                div class="space-y-1" {
                    label for="url" class="text-xs font-medium" { "Endpoint URL" }
                    input id="url" name="url" type="url" required value=(url) placeholder="https://api.example.com/v1/webhooks/stripe" class=(dashboard_input());
                    @if origin_ok {
                        p class="text-xs text-muted-foreground" { "Built from BUNYIP_API_PUBLIC_ORIGIN. Edit it if bunyip-api is published on a different public path." }
                    } @else {
                        p class="text-xs text-destructive-text" { "Built from BUNYIP_API_PUBLIC_ORIGIN, which is not set to a public https:// origin, so Stripe cannot reach this address. Set BUNYIP_API_PUBLIC_ORIGIN to the browser-facing origin of bunyip-api, or enter the public URL here." }
                    }
                }
                div class="space-y-1" {
                    label for="enabled_events" class="text-xs font-medium" { "Enabled events" }
                    textarea id="enabled_events" name="enabled_events" rows="2" class=(dashboard_input()) { (events) }
                    p class="text-xs text-muted-foreground" { "Comma- or whitespace-separated. Defaults to the events bunyip handles." }
                }
                button type="submit" class=(button_class("default", "sm", "")) { "Create endpoint" }
            }
            @match webhooks {
                Err(e) => (load_failure_box(
                    "Could not read the webhook endpoints from Stripe, so bunyip cannot tell whether one already exists.",
                    e,
                    "This usually means the restricted key lacks the Webhook Endpoints permission, or no valid key is saved above.",
                )),
                Ok([]) => (empty_state("link-2", "No webhook endpoints yet. Create one so Stripe can send checkout, subscription, and payment events to bunyip.", None)),
                Ok(list) => div class="divide-y" {
                    @for w in list {
                        div class="py-3 flex items-center justify-between gap-4" {
                            div class="min-w-0" {
                                p class="font-medium flex items-center gap-2" {
                                    span class="truncate" { (w.url) }
                                    @if w.status == "enabled" { (badge("success", "Enabled")) } @else { (badge("secondary", w.status.as_str())) }
                                }
                                p class="text-xs text-muted-foreground truncate" { (format!("{} event{}: ", w.enabled_events.len(), if w.enabled_events.len() == 1 { "" } else { "s" })) (w.enabled_events.join(", ")) }
                                p class="text-xs text-muted-foreground font-mono truncate" { (w.id) }
                            }
                            form method="post" action=(format!("/admin/stripe/webhooks/{}/delete", w.id)) data-confirm="Delete this webhook endpoint? Stripe will stop sending events to it." {
                                button type="submit" class=(button_class("outline", "sm", "")) { "Delete" }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// BUNYIP-524: what `/pricing` is doing right now, in plain words, next to the
/// switch that controls it. Published tiers in a success box; every reason it is
/// not publishing in its own error box, quoting the tier, the price id and (for
/// the app-tag filter) the fix. Without this the admin has several causes that
/// all look like a 404. Moved here from the Pricing tiers page (BUNYIP-515) so
/// the switch and its feedback sit together.
fn pricing_status_block(status: Result<&crate::api::types::PricingStatus, &str>) -> Markup {
    let s = match status {
        Err(msg) => {
            return error_box(&format!(
                "Could not load the pricing status, so this page cannot say what /pricing is \
                 serving: {msg}"
            ))
        }
        Ok(s) => s,
    };
    let names = s
        .tiers
        .iter()
        .map(|t| crate::handlers::dashboard::tier_name(&t.tier))
        .collect::<Vec<_>>()
        .join(", ");
    html! {
        div class="space-y-2" {
            @if s.published {
                (success_box(&format!("/pricing is live and advertising: {names}.")))
            }
            @for r in &s.reasons { (error_box(&r.message)) }
            @if !s.published && s.reasons.is_empty() {
                (error_box("/pricing returns 404 and the API gave no reason. Check the bunyip-api logs."))
            }
        }
    }
}

/// BUNYIP-517: the tier catalog mapping. The admin picks the Stripe PRICE per
/// tier; bunyip derives and stores the product it needs for webhook tier
/// classification from that price on save, so the two can never disagree. Only
/// price fields are asked for; the derived product is shown read-only.
/// BUNYIP-524: the publish switch for the public `/pricing` page lives here too,
/// in the same form, so one Save maps the prices and decides whether the page is
/// live. `status` is the live diagnosis shown under the switch.
pub(super) fn stripe_catalog_section(
    tier: Result<&crate::api::types::TierConfigResponse, &ApiError>,
    prices: Option<&[crate::api::types::StripePrice]>,
    status: Result<&crate::api::types::PricingStatus, &str>,
) -> Markup {
    // A price <select> populated from the active prices, with the stored value
    // preserved as a selected option even when it is no longer in the list
    // (archived or invisible), so a save does not silently drop it.
    let price_select = |name: &str, current: &Option<String>| -> Markup {
        let cur = current.as_deref().unwrap_or("").to_string();
        let active: Vec<&crate::api::types::StripePrice> = prices
            .map(|l| l.iter().filter(|p| p.active).collect())
            .unwrap_or_default();
        let current_listed = active.iter().any(|p| p.id == cur);
        html! {
            label for=(name) class="text-sm font-medium" { "Price" }
            select id=(name) name=(name) class=(dashboard_input()) {
                option value="" selected[cur.is_empty()] { "(none)" }
                @for p in &active {
                    option value=(&p.id) selected[p.id == cur] { (format!("{} - {}", format_stripe_amount(p.unit_amount, &p.currency), p.id)) }
                }
                @if !cur.is_empty() && !current_listed {
                    option value=(&cur) selected { (format!("{} (not in the active list)", cur)) }
                }
            }
        }
    };
    // The product of the currently-mapped price, looked up in the loaded list.
    let derived_product = |price_id: &Option<String>| -> Option<String> {
        let pid = price_id.as_deref()?;
        prices?
            .iter()
            .find(|p| p.id == pid)
            .map(|p| p.product_id.clone())
    };
    let tier_card = |price_name: &str,
                     price_val: &Option<String>,
                     stored_product: &Option<String>,
                     visible_name: &str,
                     visible: bool|
     -> Markup {
        let derived = derived_product(price_val);
        let disagrees =
            matches!((stored_product.as_deref(), derived.as_deref()), (Some(s), Some(d)) if s != d);
        html! {
            div class="space-y-2" {
                (price_select(price_name, price_val))
                p class="text-xs text-muted-foreground" {
                    "Webhook events for this tier are classified by its product: "
                    @match &derived {
                        Some(p) => span class="font-mono" { (p) },
                        None => span { "derived from the price on save" },
                    }
                }
                @if disagrees {
                    (badge("warning", "Stored product differs from the price"))
                    p class="text-xs text-destructive-text" {
                        "The stored product "
                        @if let Some(sp) = stored_product.as_deref() { span class="font-mono" { (sp) } }
                        " no longer matches the mapped price's product. Save to re-derive it."
                    }
                }
                // BUNYIP-527: per-tier visibility. Hidden tiers are dropped from
                // the public page even when mapped, under the global switch above.
                label class="flex items-center gap-2 pt-1 text-sm font-medium" {
                    input name=(visible_name) type="checkbox" value="true" checked[visible] class="h-4 w-4 rounded border-input";
                    "Show this tier on the pricing page"
                }
            }
        }
    };
    html! {
        div class="space-y-3" {
            div {
                h3 class="text-xl font-semibold" { "Tier catalog mapping" }
                p class="text-sm text-muted-foreground" {
                    "Stripe has no concept of a bunyip membership tier, so each tier is bound to the Stripe price that represents it. The binding is read forwards, to advertise pricing and to open the $0 subscription behind a free or lifetime grant, and backwards, to classify incoming subscription events onto the right tier. Pick the price; bunyip derives and stores the product it needs for that classification, so the two halves cannot disagree."
                }
            }
            @match tier {
                Err(e) => (error_box_detailed("Could not load the tier catalog mapping.", Some(&e.user_message()), e.request_id.as_deref())),
                Ok(t) => form method="post" action="/admin/tier-settings/catalog" class="space-y-6" {
                    // BUNYIP-524: the publish switch sits with the price mapping
                    // it depends on. Ticking it advertises these prices; the
                    // status line says whether /pricing actually publishes and,
                    // if not, which tier's price is the reason.
                    (admin_block(
                        "Public pricing page",
                        Some("Off by default. While this is off (or no tier resolves to a usable Stripe price) /pricing returns 404 and every link to it stays hidden."),
                        html! {
                            div class="space-y-4" {
                                (pricing_status_block(status))
                                label class="flex items-center gap-3 text-sm font-medium" {
                                    input id="pricing_enabled" name="pricing_enabled" type="checkbox" value="true" checked[t.pricing_enabled] class="h-4 w-4 rounded border-input";
                                    "Show pricing on the public page"
                                }
                            }
                        },
                    ))
                    (admin_block_grid(vec![
                        admin_block("Free / lifetime", Some("A $0 price. Free and lifetime grants both open a subscription on it."), html! {
                            div class="space-y-4" { (tier_card("free_price_id", &t.free_price_id, &t.lifetime_product_id, "lifetime_visible", t.lifetime_visible)) }
                        }),
                        admin_block("Early adopter", None, html! {
                            div class="space-y-4" { (tier_card("early_adopter_price_id", &t.early_adopter_price_id, &t.early_adopter_product_id, "early_adopter_visible", t.early_adopter_visible)) }
                        }),
                        admin_block("Standard", None, html! {
                            div class="space-y-4" { (tier_card("standard_price_id", &t.standard_price_id, &t.standard_product_id, "standard_visible", t.standard_visible)) }
                        }),
                    ]))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save catalog mapping" }
                },
            }
        }
    }
}

/// BUNYIP-516: the query a failed webhook create redirects back with, so the
/// Webhook endpoints block can restate the failure and redisplay the submitted
/// values. Every field is optional; a plain page load leaves them empty.
#[derive(Debug, Default, Deserialize)]
pub struct StripePageQuery {
    #[serde(default)]
    pub webhook_error: String,
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub webhook_events: String,
    #[serde(default)]
    pub webhook_ref: String,
}

/// Non-empty `&str`, or `None`, so a blank query parameter does not blank out
/// the form default it is meant to override.
fn present(s: &str) -> Option<&str> {
    Some(s.trim()).filter(|v| !v.is_empty())
}

pub async fn stripe(
    State(st): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<StripePageQuery>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let cfg = admin_api::stripe_config(&st.api, fwd).await;
    // BUNYIP-516: keep the `Result`. These lists come from Stripe via the API,
    // and an unreadable list is NOT an empty one: the blocks say which of the
    // two happened, and name the api request id when it is the former.
    let products = admin_api::list_stripe_products(&st.api, fwd).await;
    let prices = admin_api::list_stripe_prices(&st.api, fwd).await;
    // DEV-518: webhook endpoints, same load-or-report posture as products/prices.
    let webhooks = admin_api::list_stripe_webhooks(&st.api, fwd).await;
    // BUNYIP-527: the tier -> Stripe price/product catalog mapping (and the
    // publish switch + status) moved back to the Pricing tiers page, so the
    // Stripe page no longer fetches or renders them.

    let products_loaded: Loaded<'_, _> = products.as_ref().map(Vec::as_slice);
    let prices_loaded: Loaded<'_, _> = prices.as_ref().map(Vec::as_slice);
    let webhooks_loaded: Loaded<'_, _> = webhooks.as_ref().map(Vec::as_slice);
    let retry = WebhookRetry {
        error: present(&q.webhook_error),
        url: present(&q.webhook_url),
        events: present(&q.webhook_events),
        reference: present(&q.webhook_ref),
    };

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Stripe" } p class="mt-2 text-muted-foreground" { "Connect and configure Stripe billing, products, and prices." } }
            @match &cfg {
                Err(e) => (error_box_detailed("Could not load Stripe config.", Some(&e.user_message()), e.request_id.as_deref())),
                Ok(s) => {
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
                                        div class="space-y-2" { label for="secret_key" class="text-sm font-medium" { "Secret key" } input id="secret_key" name="secret_key" type="password" placeholder=(s.secret_key_masked.clone().unwrap_or_else(|| "sk_live_…".into())) class=(dashboard_input()); }
                                        div class="space-y-2" { label for="webhook_secret" class="text-sm font-medium" { "Webhook secret" } input id="webhook_secret" name="webhook_secret" type="password" placeholder=(s.webhook_secret_masked.clone().unwrap_or_else(|| "whsec_…".into())) class=(dashboard_input()); }
                                        div class="space-y-2" { label for="app_tag" class="text-sm font-medium" { "App tag" } input id="app_tag" name="app_tag" value=(s.app_tag) class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Only Stripe products tagged with this value are shown below." } }
                                    }
                                },
                            ),
                            admin_block(
                                "Checkout",
                                Some("Where Stripe returns the customer after checkout. The trial length moved to the Pricing tiers page (BUNYIP-527)."),
                                html! {
                                    div class="space-y-4" {
                                        div class="space-y-2" { label for="success_url" class="text-sm font-medium" { "Success URL" } input id="success_url" name="success_url" type="url" value=(s.success_url) placeholder="https://example.com/checkout/success" class=(dashboard_input()); }
                                        div class="space-y-2" { label for="cancel_url" class="text-sm font-medium" { "Cancel URL" } input id="cancel_url" name="cancel_url" type="url" value=(s.cancel_url) placeholder="https://example.com/pricing?checkout=canceled" class=(dashboard_input()); }
                                    }
                                },
                            ),
                        ]))
                        button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    }
                    (stripe_products_block(products_loaded, prices_loaded))
                    (stripe_prices_block(prices_loaded, products_loaded))
                    (stripe_webhooks_block(webhooks_loaded, &st.cfg.api_public_origin, s.has_webhook_secret, &retry))
                },
            }
        }
    };
    admin_response(&c, &user, "/admin/stripe", "Stripe", content)
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
        Err(e) => format!(
            "/admin/stripe?toast_err={}",
            urlenc(&e.user_message_with_reference())
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

#[derive(Deserialize)]
pub struct StripeProductEditForm {
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// BUNYIP-511: name validation for a product edit - trimmed, required, 1 to 250
/// chars. A blank name is an error (never sent upstream); this is the check the
/// edit handler runs before building the request body.
pub(super) fn validate_product_name(raw: &str) -> Result<String, String> {
    match crate::handlers::validate::trim_bounded_opt(raw, "Product name", 250)? {
        Some(t) => Ok(t.to_string()),
        None => Err("Product name is required".to_string()),
    }
}

/// BUNYIP-511: the body of a product edit. Name + description ONLY. It must never
/// carry an `active` key (lifecycle is owned by archive/unarchive, BUNYIP-512/513)
/// nor a `metadata` key (Stripe replaces the whole metadata map on update, so
/// sending it would drop the `app_tag` and vanish the product from the list). A
/// blank description is sent as `""` so Stripe clears the field.
pub(super) fn product_edit_body(name: &str, description: &str) -> serde_json::Value {
    json!({ "name": name, "description": description })
}

/// POST /admin/stripe/products/{id} - edit a product's name/description in place
/// (BUNYIP-511), then redirect back.
pub async fn stripe_product_edit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<StripeProductEditForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let name = match validate_product_name(&f.name) {
        Ok(n) => n,
        Err(msg) => {
            return redirect_cookies(
                &format!("/admin/stripe?toast_err={}", urlenc(&msg)),
                &c.set_cookies,
            )
        }
    };
    let description = f.description.trim();
    if description.len() > 500 {
        return redirect_cookies(
            &format!(
                "/admin/stripe?toast_err={}",
                urlenc("Description must be 500 characters or fewer")
            ),
            &c.set_cookies,
        );
    }
    let body = product_edit_body(&name, description);
    let target =
        match admin_api::update_stripe_product(&st.api, c.forward.as_deref(), &id, body).await {
            Ok(()) => "/admin/stripe?toast_ok=Product%20updated".to_string(),
            Err(e) => format!(
                "/admin/stripe?toast_err={}",
                urlenc(&e.user_message_with_reference())
            ),
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
        Err(e) => format!(
            "/admin/stripe?toast_err={}",
            urlenc(&e.user_message_with_reference())
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/stripe/products/{id}/unarchive (BUNYIP-513)
pub async fn stripe_product_unarchive(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::unarchive_stripe_product(&st.api, c.forward.as_deref(), &id).await
    {
        Ok(()) => "/admin/stripe?toast_ok=Product%20restored".to_string(),
        Err(e) => format!("/admin/stripe?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

#[derive(Deserialize)]
pub struct StripeWebhookForm {
    pub url: String,
    #[serde(default)]
    pub enabled_events: String,
}

/// POST /admin/stripe/webhooks - create a Stripe webhook endpoint (DEV-518). On
/// success renders a one-time page showing the signing secret (Stripe returns it
/// only at creation); on error redirects back with a toast.
pub async fn stripe_webhook_create(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<StripeWebhookForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let url = f.url.trim();
    if url.is_empty() {
        return redirect_cookies(
            "/admin/stripe?toast_err=Endpoint%20URL%20is%20required",
            &c.set_cookies,
        );
    }
    // Split on commas + whitespace, drop blanks and duplicates (order-preserving).
    let mut seen = std::collections::HashSet::new();
    let mut events: Vec<String> = f
        .enabled_events
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .map(str::trim)
        .filter(|e| !e.is_empty() && seen.insert(e.to_string()))
        .map(str::to_string)
        .collect();
    if events.is_empty() {
        events = RECOMMENDED_WEBHOOK_EVENTS
            .iter()
            .map(|e| e.to_string())
            .collect();
    }
    // Kept for the failure redirect below, which redisplays what was submitted.
    let events_text = events.join(", ");
    let body = json!({ "url": url, "enabled_events": events });
    match admin_api::create_stripe_webhook(&st.api, c.forward.as_deref(), body).await {
        Ok(w) => {
            let content = webhook_created_page(&w);
            admin_response(&c, &user, "/admin/stripe", "Webhook created", content)
        }
        // BUNYIP-516: hand the reason, the submitted URL and the submitted event
        // text back to the page. A toast would fade in 2.5 seconds and the form
        // would come back blank, so the admin retyped everything to retry.
        Err(e) => {
            let mut target = format!(
                "/admin/stripe?webhook_error={}&webhook_url={}&webhook_events={}",
                urlenc(&e.user_message_with_reference()),
                urlenc(url),
                urlenc(&events_text),
            );
            if let Some(id) = &e.request_id {
                target.push_str(&format!("&webhook_ref={}", urlenc(id)));
            }
            redirect_cookies(&target, &c.set_cookies)
        }
    }
}

/// BUNYIP-510: the post-create confirmation page. `create_stripe_webhook`
/// (`bunyip-api/src/handlers/admin_stripe.rs`) already encrypts and stores the
/// signing secret Stripe returns and hot-reloads `StripeService`, so the
/// success branch records the value instead of asking for a paste. Only the
/// `secret == None` branch (nothing was saved) keeps a manual instruction.
pub(super) fn webhook_created_page(w: &crate::api::types::StripeWebhookEndpoint) -> Markup {
    html! {
        div class="space-y-6 max-w-2xl" {
            div {
                h1 class="text-3xl font-bold" { "Webhook endpoint created" }
                @match w.secret {
                    Some(_) => p class="mt-2 text-muted-foreground" { "bunyip saved the signing secret automatically, so webhook processing is now active. Stripe shows the secret only once - keep the value below for your own records." },
                    None => p class="mt-2 text-muted-foreground" { "Stripe did not return a signing secret, so none was saved." },
                }
            }
            (admin_block(
                "Signing secret",
                Some(&format!("Endpoint: {}", w.url)),
                html! {
                    @match w.secret.as_deref() {
                        Some(secret) => div class="space-y-2" {
                            code class="block break-all rounded bg-muted p-3 font-mono text-sm" { (secret) }
                            p class="text-xs text-muted-foreground" { "Saved automatically - there is nothing to enter by hand." }
                        },
                        None => p class="text-sm text-muted-foreground" { "Stripe did not return a signing secret. bunyip rejects every incoming Stripe event until one is saved: retrieve the secret from the Stripe dashboard for this endpoint, paste it into Webhook secret on the Stripe page, then Save." },
                    }
                    div class="mt-4" { a href="/admin/stripe" class=(button_class("default", "default", "")) { "Back to Stripe" } }
                },
            ))
        }
    }
}

/// POST /admin/stripe/webhooks/{id}/delete (DEV-518).
pub async fn stripe_webhook_delete(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::delete_stripe_webhook(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => "/admin/stripe?toast_ok=Webhook%20endpoint%20deleted".to_string(),
        Err(e) => format!(
            "/admin/stripe?toast_err={}",
            urlenc(&e.user_message_with_reference())
        ),
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
pub(super) fn parse_price_cents(amount: &str) -> Result<i64, String> {
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
        Err(e) => format!(
            "/admin/stripe?toast_err={}",
            urlenc(&e.user_message_with_reference())
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

#[derive(Deserialize)]
pub struct StripePriceReplaceForm {
    pub amount: String,
    pub currency: String,
    pub interval: String,
}

/// BUNYIP-511: the body of a price replace - the new amount (cents), currency and
/// interval. Reuses [`parse_price_cents`] for the amount, exactly like create.
pub(super) fn price_replace_body(cents: i64, currency: &str, interval: &str) -> serde_json::Value {
    json!({ "unit_amount": cents, "currency": currency, "interval": interval })
}

/// POST /admin/stripe/prices/{id}/replace - replace a price (BUNYIP-511). The API
/// creates the new price, repoints bunyip's references, and archives this one; a
/// partial failure comes back as an error the toast shows verbatim.
pub async fn stripe_price_replace(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(f): Form<StripePriceReplaceForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cents = match parse_price_cents(&f.amount) {
        Ok(v) => v,
        Err(msg) => {
            return redirect_cookies(
                &format!("/admin/stripe?toast_err={}", urlenc(&msg)),
                &c.set_cookies,
            )
        }
    };
    let body = price_replace_body(cents, f.currency.trim(), f.interval.trim());
    let target =
        match admin_api::replace_stripe_price(&st.api, c.forward.as_deref(), &id, body).await {
            Ok(()) => "/admin/stripe?toast_ok=Price%20replaced".to_string(),
            Err(e) => format!(
                "/admin/stripe?toast_err={}",
                urlenc(&e.user_message_with_reference())
            ),
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
        Err(e) => format!(
            "/admin/stripe?toast_err={}",
            urlenc(&e.user_message_with_reference())
        ),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// POST /admin/stripe/prices/{id}/unarchive (BUNYIP-513)
pub async fn stripe_price_unarchive(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target = match admin_api::unarchive_stripe_price(&st.api, c.forward.as_deref(), &id).await {
        Ok(()) => "/admin/stripe?toast_ok=Price%20restored".to_string(),
        Err(e) => format!("/admin/stripe?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}

/// The tier -> Stripe catalog mapping form. BUNYIP-527: moved back onto the
/// Pricing tiers page (`/admin/tier-settings/catalog`), it carries the three
/// price selects plus the publish switch; the api derives the product per tier.
#[derive(Deserialize)]
pub struct StripeCatalogForm {
    #[serde(default)]
    pub free_price_id: String,
    #[serde(default)]
    pub early_adopter_price_id: String,
    #[serde(default)]
    pub standard_price_id: String,
    // BUNYIP-524: the publish switch. An unchecked checkbox submits no field at
    // all, so absence is "off"; it is always sent to the API (never omitted, as
    // omission means "leave unchanged" there and could never turn it off).
    #[serde(default)]
    pub pricing_enabled: Option<String>,
    // BUNYIP-527: per-tier visibility checkboxes, same absent-means-off semantics.
    #[serde(default)]
    pub lifetime_visible: Option<String>,
    #[serde(default)]
    pub early_adopter_visible: Option<String>,
    #[serde(default)]
    pub standard_visible: Option<String>,
}

/// Build the catalog-save body. BUNYIP-527: each price select ALWAYS submits its
/// value, and "(none)" submits `""`, so the price fields are always sent - an
/// empty one as an explicit `""` that the API reads as "clear this mapping"
/// (distinct from omitting the field, which keeps it). This is what makes
/// "(none)" actually unmap a tier instead of silently keeping the old price. The
/// publish switch is authoritative (absent checkbox = off), so it is always sent.
pub(super) fn catalog_save_body(f: &StripeCatalogForm) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    for (k, v) in [
        ("free_price_id", &f.free_price_id),
        ("early_adopter_price_id", &f.early_adopter_price_id),
        ("standard_price_id", &f.standard_price_id),
    ] {
        let t = v.trim();
        // Over-long junk is dropped (kept, not set); "" and valid ids pass.
        if t.len() <= 255 {
            body.insert(k.into(), json!(t));
        }
    }
    body.insert("pricing_enabled".into(), json!(f.pricing_enabled.is_some()));
    // BUNYIP-527: per-tier visibility, always sent (absent checkbox = hidden).
    body.insert(
        "lifetime_visible".into(),
        json!(f.lifetime_visible.is_some()),
    );
    body.insert(
        "early_adopter_visible".into(),
        json!(f.early_adopter_visible.is_some()),
    );
    body.insert(
        "standard_visible".into(),
        json!(f.standard_visible.is_some()),
    );
    serde_json::Value::Object(body)
}

/// POST /admin/tier-settings/catalog - persist the tier -> Stripe price mapping
/// and the publish switch (BUNYIP-527, moved from the Stripe page).
pub async fn stripe_catalog_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<StripeCatalogForm>,
) -> Response {
    let (_, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let target =
        match admin_api::update_tier_config(&st.api, c.forward.as_deref(), catalog_save_body(&f))
            .await
        {
            Ok(()) => "/admin/tier-settings?toast_ok=Catalog%20mapping%20saved".to_string(),
            Err(e) => format!(
                "/admin/tier-settings?toast_err={}",
                urlenc(&e.user_message_with_reference())
            ),
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
    // BUNYIP-351: checkout URLs are sent only when non-blank (blank = keep
    // existing). BUNYIP-527: the trial length moved to the Pricing tiers page.
    let success_url = f.success_url.trim();
    let cancel_url = f.cancel_url.trim();

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
    match admin_api::update_stripe_config(&st.api, c.forward.as_deref(), body).await {
        Ok(()) => redirect_cookies("/admin/stripe", &c.set_cookies),
        // BUNYIP-516: the api's request id rides along so a save that still
        // reports a generic line can be found in the api log.
        Err(e) => render_error(&e.user_message_with_reference()),
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
    admin_response(c, user, "/admin/stripe", "Stripe", content)
}
