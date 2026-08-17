//! Admin panel: Pricing tiers (route stays /admin/tier-settings).
//!
//! BUNYIP-527: this page owns everything about bunyip's own tiers - slot limits,
//! trial lengths, the checkout trial actually applied, the tier -> Stripe price
//! catalog mapping (with per-tier visibility), and the public pricing publish
//! switch. The Stripe page keeps only raw Stripe (connection, products, prices,
//! webhooks). The catalog mapping is its own form (posting to
//! `/admin/tier-settings/catalog`, handled by `stripe_catalog_save`).

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::api::types::{PricingStatus, StripePrice, TierConfigResponse};
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::views::layout::admin_block;
use crate::views::ui::{button_class, error_box, icon};
use crate::web::{redirect_cookies, AppState};

/// Upper bounds for tier-settings fields. Slots and trial days are i64 with no
/// business meaning beyond these caps; rejecting larger input keeps obvious
/// typos and overflow probes out of the config.
const MAX_TIER_SLOTS: i64 = 1_000_000;
const MAX_TRIAL_DAYS: i64 = 3_650;

/// Field values shown in the Tiers & Slots form. Kept as strings so a failed save
/// can echo back exactly what the admin typed, including junk that did not parse.
pub(super) struct TierFormValues {
    pub(super) lifetime_slots: String,
    pub(super) early_adopter_slots: String,
    pub(super) early_adopter_trial_days: String,
    pub(super) standard_trial_days: String,
    /// BUNYIP-527: the single trial Stripe actually grants at checkout, relocated
    /// here from the Stripe page. It persists to `stripe_config`, not tier config.
    pub(super) trial_period_days: String,
}

impl TierFormValues {
    pub(super) fn from_config(c: &TierConfigResponse, trial_period_days: &str) -> Self {
        TierFormValues {
            lifetime_slots: c.lifetime_slots.to_string(),
            early_adopter_slots: c.early_adopter_slots.to_string(),
            early_adopter_trial_days: c.early_adopter_trial_days.to_string(),
            standard_trial_days: c.standard_trial_days.to_string(),
            trial_period_days: trial_period_days.to_string(),
        }
    }

    fn empty() -> Self {
        TierFormValues {
            lifetime_slots: String::new(),
            early_adopter_slots: String::new(),
            early_adopter_trial_days: String::new(),
            standard_trial_days: String::new(),
            trial_period_days: String::new(),
        }
    }
}

/// Parse one tier-settings field: require a base-10 integer in `[0, max]`.
/// Returns a user-facing message naming the field on failure.
fn parse_tier_field(raw: &str, label: &str, max: i64) -> Result<i64, String> {
    let n: i64 = raw
        .trim()
        .parse()
        .map_err(|_| format!("{label} must be a whole number."))?;
    if n < 0 {
        return Err(format!("{label} must be zero or greater."));
    }
    if n > max {
        return Err(format!("{label} must be at most {max}."));
    }
    Ok(n)
}

pub(super) fn tier_settings_content(
    cfg: Option<&TierConfigResponse>,
    prices: Option<&[StripePrice]>,
    status: Result<&PricingStatus, &str>,
    values: &TierFormValues,
    error: Option<&str>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Pricing Tiers" } p class="mt-2 text-muted-foreground" { "Slot limits, trial lengths, the tier -> Stripe price mapping, and the public pricing switch. Raw Stripe products, prices and webhooks live on the " a href="/admin/stripe" class="text-primary-text hover:underline" { "Stripe" } " page." } }
            @match cfg {
                None => (error_box("Could not load tier config.")),
                Some(c) => {
                    form method="post" action="/admin/tier-settings" class="space-y-6" {
                        @if let Some(e) = error { (error_box(e)) }
                        (admin_block(
                            "Tiers & Slots",
                            Some(&format!("{} lifetime and {} early-adopter slots used.", c.lifetime_slots_used, c.early_adopter_slots_used)),
                            html! {
                                div class="space-y-4 max-w-md" {
                                    div class="space-y-2" { label for="lifetime_slots" class="text-sm font-medium" { "Lifetime slots" } input id="lifetime_slots" name="lifetime_slots" type="number" min="0" max=(MAX_TIER_SLOTS) value=(values.lifetime_slots) class=(dashboard_input()); }
                                    div class="space-y-2" { label for="early_adopter_slots" class="text-sm font-medium" { "Early-adopter slots" } input id="early_adopter_slots" name="early_adopter_slots" type="number" min="0" max=(MAX_TIER_SLOTS) value=(values.early_adopter_slots) class=(dashboard_input()); }
                                    div class="space-y-2" { label for="early_adopter_trial_days" class="text-sm font-medium" { "Early-adopter trial days" } input id="early_adopter_trial_days" name="early_adopter_trial_days" type="number" min="0" max=(MAX_TRIAL_DAYS) value=(values.early_adopter_trial_days) class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Advertised on /pricing for this tier." } }
                                    div class="space-y-2" { label for="standard_trial_days" class="text-sm font-medium" { "Standard trial days" } input id="standard_trial_days" name="standard_trial_days" type="number" min="0" max=(MAX_TRIAL_DAYS) value=(values.standard_trial_days) class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Advertised on /pricing for this tier." } }
                                }
                            },
                        ))
                        // BUNYIP-527: the ONE trial Stripe grants at checkout, moved here
                        // from the Stripe page and labelled to say what it does versus the
                        // per-tier advertised lengths above.
                        (admin_block(
                            "Trial applied at checkout",
                            Some("The single trial length Stripe grants a new subscription at checkout, for every tier. The per-tier trial days above are what /pricing advertises; making checkout honour them per tier is tracked separately."),
                            html! {
                                div class="space-y-2 max-w-md" {
                                    label for="trial_period_days" class="text-sm font-medium" { "Checkout trial (days)" }
                                    input id="trial_period_days" name="trial_period_days" type="number" min="0" max="365" value=(values.trial_period_days) class=(dashboard_input());
                                }
                            },
                        ))
                        button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    }
                    // BUNYIP-527: the catalog mapping (price selects + per-tier
                    // visibility + publish switch + live status), its own form
                    // posting to /admin/tier-settings/catalog.
                    (super::stripe_catalog_section(Ok(c), prices, status))
                }
            }
        }
    }
}

/// Tier config for the page. `None` renders "Could not load tier config.", so
/// the admin sees the failure; the log is what names its cause.
async fn tier_config(st: &AppState, cookie: Option<&str>) -> Option<TierConfigResponse> {
    match admin_api::tier_config(&st.api, cookie).await {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(
                endpoint = "/v1/admin/tier-config",
                error = %e.message,
                code = %e.code,
                "tier config unavailable on the Pricing tiers page"
            );
            None
        }
    }
}

/// Stripe prices for the catalog selects. `None` on an unreadable list, which the
/// catalog section renders as "derived from the price on save" placeholders.
async fn stripe_prices(st: &AppState, cookie: Option<&str>) -> Option<Vec<StripePrice>> {
    admin_api::list_stripe_prices(&st.api, cookie)
        .await
        .map_err(|e| {
            tracing::warn!(
                endpoint = "/v1/admin/stripe/prices",
                error = %e.message,
                code = %e.code,
                "Stripe price list unavailable on the Pricing tiers page"
            );
        })
        .ok()
}

/// Live /pricing diagnosis for the publish block. A failed fetch is reported to
/// the admin (and logged), never rendered as "nothing to report".
async fn pricing_status(st: &AppState, cookie: Option<&str>) -> Result<PricingStatus, String> {
    admin_api::pricing_status(&st.api, cookie)
        .await
        .map_err(|e| {
            tracing::warn!(
                endpoint = "/v1/admin/pricing/status",
                error = %e.message,
                code = %e.code,
                "pricing status unavailable on the Pricing tiers page"
            );
            e.user_message()
        })
}

/// The checkout trial length (`stripe_config.trial_period_days`), as a string for
/// the form. An unreadable config leaves the field blank rather than inventing 0.
async fn checkout_trial_days(st: &AppState, cookie: Option<&str>) -> String {
    match admin_api::stripe_config(&st.api, cookie).await {
        Ok(s) => s.trial_period_days.to_string(),
        Err(e) => {
            tracing::warn!(
                endpoint = "/v1/admin/stripe",
                error = %e.message,
                code = %e.code,
                "Stripe config unavailable on the Pricing tiers page"
            );
            String::new()
        }
    }
}

pub async fn tier_settings(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();
    let cfg = tier_config(&st, fwd).await;
    let prices = stripe_prices(&st, fwd).await;
    let status = pricing_status(&st, fwd).await;
    let trial = checkout_trial_days(&st, fwd).await;
    let values = cfg
        .as_ref()
        .map(|c| TierFormValues::from_config(c, &trial))
        .unwrap_or_else(TierFormValues::empty);
    let content = tier_settings_content(
        cfg.as_ref(),
        prices.as_deref(),
        status.as_ref().map_err(String::as_str),
        &values,
        None,
    );
    admin_response(&c, &user, "/admin/tier-settings", "Pricing Tiers", content)
}

#[derive(Deserialize)]
pub struct TierForm {
    // BUNYIP-111: kept as raw strings so a non-integer submission can be echoed
    // back and re-validated inline instead of failing Form extraction with a 422.
    #[serde(default)]
    pub lifetime_slots: String,
    #[serde(default)]
    pub early_adopter_slots: String,
    #[serde(default)]
    pub early_adopter_trial_days: String,
    #[serde(default)]
    pub standard_trial_days: String,
    // BUNYIP-527: the checkout trial length, persisted to stripe_config.
    #[serde(default)]
    pub trial_period_days: String,
}

pub async fn tier_settings_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TierForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let fwd = c.forward.as_deref();

    // Validate everything up front so a bad field names itself and nothing is
    // persisted on a partial failure. The two backends (tier config + the single
    // stripe-config trial) are only called once every field parses.
    let outcome = (|| {
        let mut tier_body = serde_json::Map::new();
        tier_body.insert(
            "lifetime_slots".into(),
            json!(parse_tier_field(
                &f.lifetime_slots,
                "Lifetime slots",
                MAX_TIER_SLOTS
            )?),
        );
        tier_body.insert(
            "early_adopter_slots".into(),
            json!(parse_tier_field(
                &f.early_adopter_slots,
                "Early-adopter slots",
                MAX_TIER_SLOTS
            )?),
        );
        tier_body.insert(
            "early_adopter_trial_days".into(),
            json!(parse_tier_field(
                &f.early_adopter_trial_days,
                "Early-adopter trial days",
                MAX_TRIAL_DAYS
            )?),
        );
        tier_body.insert(
            "standard_trial_days".into(),
            json!(parse_tier_field(
                &f.standard_trial_days,
                "Standard trial days",
                MAX_TRIAL_DAYS
            )?),
        );
        // BUNYIP-527: the checkout trial is a stripe_config value, bounded [0,365].
        let checkout_trial = parse_tier_field(&f.trial_period_days, "Checkout trial (days)", 365)?;
        Ok::<_, String>((serde_json::Value::Object(tier_body), checkout_trial))
    })();

    let error = match outcome {
        Ok((tier_body, checkout_trial)) => {
            // Persist the tier config, then the stripe-config trial. Either error
            // surfaces inline; the tier body is slots/trials only, so it never
            // touches the price mapping the catalog form owns.
            match admin_api::update_tier_config(&st.api, fwd, tier_body).await {
                Ok(()) => match admin_api::update_stripe_config(
                    &st.api,
                    fwd,
                    json!({ "trial_period_days": checkout_trial }),
                )
                .await
                {
                    Ok(()) => return redirect_cookies("/admin/tier-settings", &c.set_cookies),
                    Err(e) => e.user_message(),
                },
                Err(e) => e.user_message(),
            }
        }
        Err(msg) => msg,
    };

    // Re-render inline with the error and the submitted values.
    let cfg = tier_config(&st, fwd).await;
    let prices = stripe_prices(&st, fwd).await;
    let status = pricing_status(&st, fwd).await;
    let values = TierFormValues {
        lifetime_slots: f.lifetime_slots.trim().to_string(),
        early_adopter_slots: f.early_adopter_slots.trim().to_string(),
        early_adopter_trial_days: f.early_adopter_trial_days.trim().to_string(),
        standard_trial_days: f.standard_trial_days.trim().to_string(),
        trial_period_days: f.trial_period_days.trim().to_string(),
    };
    let content = tier_settings_content(
        cfg.as_ref(),
        prices.as_deref(),
        status.as_ref().map_err(String::as_str),
        &values,
        Some(&error),
    );
    admin_response(&c, &user, "/admin/tier-settings", "Pricing Tiers", content)
}
