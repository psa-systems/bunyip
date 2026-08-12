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
use crate::auth::AuthCtx;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::{format_stripe_amount, urlenc};
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{badge, button_class, empty_state, error_box, icon, success_box};
use crate::web::{redirect_cookies, AppState};

/// Setup guidance ported from the a8n-tools Stripe admin panel (BUNYIP-416):
/// how and where to create the restricted API key and how the app-tag scopes
/// what is shown. Rendered as a full-width intro card above the config form.
fn stripe_setup_docs() -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm" {
            div class="p-6 space-y-3 text-sm text-muted-foreground" {
                div class="flex items-center gap-2 text-foreground" { (icon("help-circle", "h-5 w-5 text-primary-text")) h3 class="text-base font-semibold" { "Setting up Stripe" } }
                p {
                    "Your Stripe secret key authenticates API requests. Generate a "
                    a href="https://dashboard.stripe.com/apikeys" target="_blank" rel="noopener noreferrer" class="text-primary-text hover:underline" { "restricted key" }
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

/// The Products block: a create form plus the app-tagged product list, each
/// with an Archive action. `products == None` is the "could not load" state
/// (e.g. no valid API key yet).
pub(super) fn stripe_products_block(
    products: Option<&[crate::api::types::StripeProduct]>,
    prices: Option<&[crate::api::types::StripePrice]>,
) -> Markup {
    // BUNYIP-512: an active product with no active price is unsellable (the
    // state an archive-then-unarchive can leave behind); flag it so it is not
    // silently broken. `None` prices = "could not load", so make no claim:
    // this is true ONLY when the price list loaded and holds no active price.
    let flag_no_active_price = |product_id: &str| {
        prices.is_some_and(|list| {
            !list
                .iter()
                .any(|pr| pr.product_id == product_id && pr.active)
        })
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
                None => (error_box("Could not load products from Stripe. Add a valid API key above and save, then reload.")),
                Some([]) => (empty_state("package", "No products yet. Create one to get started.", None)),
                Some(list) => div class="divide-y" {
                    @for p in list {
                        div class="py-3 flex items-center justify-between gap-4" {
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
                            }
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

/// The Prices block: a create form (product dropdown limited to active
/// products; amount in dollars, zero allowed for a lifetime plan) plus the
/// price list, each active price with an Archive action. Prices are immutable
/// in Stripe, so there is no edit.
pub(super) fn stripe_prices_block(
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
                    label for="product_id" class="text-xs font-medium" { "Product" }
                    select id="product_id" name="product_id" required class=(dashboard_input()) {
                        option value="" disabled selected { "Select a product" }
                        @for p in products.iter().filter(|p| p.active) { option value=(p.id) { (p.name) } }
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
                None => (error_box("Could not load prices from Stripe. Add a valid API key above and save, then reload.")),
                Some([]) => (empty_state("banknote", "No prices yet. Create one to get started.", None)),
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
                                @if pr.member_count > 0 {
                                    (archive_blocked_by_members(pr.member_count))
                                } @else {
                                    form method="post" action=(format!("/admin/stripe/prices/{}/archive", pr.id)) data-confirm="Archive this price? Existing subscriptions using it are not affected." {
                                        button type="submit" class=(button_class("outline", "sm", "")) { "Archive" }
                                    }
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
pub(super) fn stripe_webhooks_block(
    webhooks: Option<&[crate::api::types::StripeWebhookEndpoint]>,
    api_public_origin: &str,
    has_webhook_secret: bool,
) -> Markup {
    let url = stripe_webhook_url(api_public_origin);
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
                    textarea id="enabled_events" name="enabled_events" rows="2" class=(dashboard_input()) { (RECOMMENDED_WEBHOOK_EVENTS.join(", ")) }
                    p class="text-xs text-muted-foreground" { "Comma- or whitespace-separated. Defaults to the events bunyip handles." }
                }
                button type="submit" class=(button_class("default", "sm", "")) { "Create endpoint" }
            }
            @match webhooks {
                None => (error_box("Could not load webhook endpoints from Stripe. Add a valid API key above and save, then reload.")),
                Some([]) => (empty_state("link-2", "No webhook endpoints yet. Create one so Stripe can send checkout, subscription, and payment events to bunyip.", None)),
                Some(list) => div class="divide-y" {
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

/// BUNYIP-517: the tier catalog mapping. The admin picks the Stripe PRICE per
/// tier; bunyip derives and stores the product it needs for webhook tier
/// classification from that price on save, so the two can never disagree. Only
/// price fields are asked for; the derived product is shown read-only.
pub(super) fn stripe_catalog_section(
    tier: Option<&crate::api::types::TierConfigResponse>,
    prices: Option<&[crate::api::types::StripePrice]>,
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
                     stored_product: &Option<String>|
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
                None => (error_box("Could not load the tier catalog mapping.")),
                Some(t) => form method="post" action="/admin/stripe/catalog" class="space-y-6" {
                    (admin_block_grid(vec![
                        admin_block("Free / lifetime", Some("A $0 price. Free and lifetime grants both open a subscription on it."), html! {
                            div class="space-y-4" { (tier_card("free_price_id", &t.free_price_id, &t.lifetime_product_id)) }
                        }),
                        admin_block("Early adopter", None, html! {
                            div class="space-y-4" { (tier_card("early_adopter_price_id", &t.early_adopter_price_id, &t.early_adopter_product_id)) }
                        }),
                        admin_block("Standard", None, html! {
                            div class="space-y-4" { (tier_card("standard_price_id", &t.standard_price_id, &t.standard_product_id)) }
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
    // DEV-518: webhook endpoints, same load-or-None posture as products/prices.
    let webhooks = admin_api::list_stripe_webhooks(&st.api, fwd).await.ok();
    // BUNYIP-417: the tier -> Stripe price/product mapping moved here from Tier
    // Settings, so all Stripe config lives under one nav entry.
    let tier = admin_api::tier_config(&st.api, fwd).await.ok();

    let content = html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Stripe" } p class="mt-2 text-muted-foreground" { "Connect and configure Stripe billing, products, and prices." } }
            @match cfg {
                None => (error_box("Could not load Stripe config.")),
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
                                        div class="space-y-2" { label for="secret_key" class="text-sm font-medium" { "Secret key" } input id="secret_key" name="secret_key" type="password" placeholder=(s.secret_key_masked.clone().unwrap_or_else(|| "sk_live_…".into())) class=(dashboard_input()); }
                                        div class="space-y-2" { label for="webhook_secret" class="text-sm font-medium" { "Webhook secret" } input id="webhook_secret" name="webhook_secret" type="password" placeholder=(s.webhook_secret_masked.clone().unwrap_or_else(|| "whsec_…".into())) class=(dashboard_input()); }
                                        div class="space-y-2" { label for="app_tag" class="text-sm font-medium" { "App tag" } input id="app_tag" name="app_tag" value=(s.app_tag) class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Only Stripe products tagged with this value are shown below." } }
                                    }
                                },
                            ),
                            admin_block(
                                "Checkout",
                                Some("Where Stripe returns the customer after checkout, and the trial length."),
                                html! {
                                    div class="space-y-4" {
                                        div class="space-y-2" { label for="success_url" class="text-sm font-medium" { "Success URL" } input id="success_url" name="success_url" type="url" value=(s.success_url) placeholder="https://example.com/checkout/success" class=(dashboard_input()); }
                                        div class="space-y-2" { label for="cancel_url" class="text-sm font-medium" { "Cancel URL" } input id="cancel_url" name="cancel_url" type="url" value=(s.cancel_url) placeholder="https://example.com/pricing?checkout=canceled" class=(dashboard_input()); }
                                        div class="space-y-2" { label for="trial_period_days" class="text-sm font-medium" { "Trial period (days)" } input id="trial_period_days" name="trial_period_days" type="number" min="0" max="365" value=(s.trial_period_days) class=(dashboard_input()); }
                                    }
                                },
                            ),
                        ]))
                        button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    }
                    (stripe_products_block(products.as_deref(), prices.as_deref()))
                    (stripe_prices_block(prices.as_deref(), products.as_deref().unwrap_or(&[])))
                    (stripe_webhooks_block(webhooks.as_deref(), &st.cfg.api_public_origin, s.has_webhook_secret))
                    (stripe_catalog_section(tier.as_ref(), prices.as_deref()))
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
    let body = json!({ "url": url, "enabled_events": events });
    match admin_api::create_stripe_webhook(&st.api, c.forward.as_deref(), body).await {
        Ok(w) => {
            let content = webhook_created_page(&w);
            admin_response(&c, &user, "/admin/stripe", "Webhook created", content)
        }
        Err(e) => redirect_cookies(
            &format!("/admin/stripe?toast_err={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
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
/// ID fields the Pricing tiers page used to carry; they persist to the tier
/// config via a partial update (blank = keep), so nothing is lost by the move.
#[derive(Deserialize)]
pub struct StripeCatalogForm {
    #[serde(default)]
    pub free_price_id: String,
    #[serde(default)]
    pub early_adopter_price_id: String,
    #[serde(default)]
    pub standard_price_id: String,
}

/// POST /admin/stripe/catalog - persist the tier -> Stripe price mapping
/// (BUNYIP-517). Only a price per tier is submitted; the api derives the product
/// bunyip stores for webhook classification. A blank field is sent as an
/// explicit empty string so the admin can clear a mapping, distinct from the
/// tri-state-by-omission the price ids used to rely on.
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
    admin_response(c, user, "/admin/stripe", "Stripe", content)
}
