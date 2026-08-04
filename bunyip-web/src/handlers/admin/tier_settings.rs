//! Admin panel: Tier settings.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::views::layout::admin_block;
use crate::views::ui::{button_class, error_box, icon};
use crate::web::{redirect_cookies, AppState};

/// Upper bounds for tier-settings fields. Slots and trial days are i64 with no
/// business meaning beyond these caps; rejecting larger input keeps obvious
/// typos and overflow probes out of the config.
const MAX_TIER_SLOTS: i64 = 1_000_000;
const MAX_TRIAL_DAYS: i64 = 3_650;

/// Field values shown in the tier-settings form. Kept as strings so a failed
/// save can echo back exactly what the admin typed, including junk that did not
/// parse as an integer.
pub(super) struct TierFormValues {
    pub(super) lifetime_slots: String,
    pub(super) early_adopter_slots: String,
    pub(super) early_adopter_trial_days: String,
    pub(super) standard_trial_days: String,
    // BUNYIP-122: Stripe catalog IDs echoed back on a failed save so the admin
    // does not lose what they typed when a numeric field fails validation.
    pub(super) free_price_id: String,
    pub(super) early_adopter_price_id: String,
    pub(super) standard_price_id: String,
    pub(super) lifetime_product_id: String,
    pub(super) early_adopter_product_id: String,
    pub(super) standard_product_id: String,
}

impl TierFormValues {
    pub(super) fn from_config(c: &crate::api::types::TierConfigResponse) -> Self {
        TierFormValues {
            lifetime_slots: c.lifetime_slots.to_string(),
            early_adopter_slots: c.early_adopter_slots.to_string(),
            early_adopter_trial_days: c.early_adopter_trial_days.to_string(),
            standard_trial_days: c.standard_trial_days.to_string(),
            free_price_id: c.free_price_id.clone().unwrap_or_default(),
            early_adopter_price_id: c.early_adopter_price_id.clone().unwrap_or_default(),
            standard_price_id: c.standard_price_id.clone().unwrap_or_default(),
            lifetime_product_id: c.lifetime_product_id.clone().unwrap_or_default(),
            early_adopter_product_id: c.early_adopter_product_id.clone().unwrap_or_default(),
            standard_product_id: c.standard_product_id.clone().unwrap_or_default(),
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
    cfg: Option<&crate::api::types::TierConfigResponse>,
    values: &TierFormValues,
    error: Option<&str>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Tier Settings" } p class="mt-2 text-muted-foreground" { "Trial lengths and membership slot limits. Stripe price / product mapping now lives on the " a href="/admin/stripe" class="text-primary hover:underline" { "Stripe" } " page." } }
            @match cfg {
                None => (error_box("Could not load tier config.")),
                // BUNYIP-417: the Stripe catalog price/product mappings moved to
                // the Stripe page to consolidate all Stripe config under one nav
                // entry. Tier Settings keeps only its non-Stripe concerns (slots
                // + trial lengths).
                Some(c) => form method="post" action="/admin/tier-settings" class="space-y-6" {
                    @if let Some(e) = error { (error_box(e)) }
                    (admin_block(
                        "Tiers & Slots",
                        Some(&format!("{} lifetime and {} early-adopter slots used.", c.lifetime_slots_used, c.early_adopter_slots_used)),
                        html! {
                            div class="space-y-4 max-w-md" {
                                div class="space-y-2" { label for="lifetime_slots" class="text-sm font-medium" { "Lifetime slots" } input id="lifetime_slots" name="lifetime_slots" type="number" min="0" max=(MAX_TIER_SLOTS) value=(values.lifetime_slots) class=(dashboard_input()); }
                                div class="space-y-2" { label for="early_adopter_slots" class="text-sm font-medium" { "Early-adopter slots" } input id="early_adopter_slots" name="early_adopter_slots" type="number" min="0" max=(MAX_TIER_SLOTS) value=(values.early_adopter_slots) class=(dashboard_input()); }
                                div class="space-y-2" { label for="early_adopter_trial_days" class="text-sm font-medium" { "Early-adopter trial days" } input id="early_adopter_trial_days" name="early_adopter_trial_days" type="number" min="0" max=(MAX_TRIAL_DAYS) value=(values.early_adopter_trial_days) class=(dashboard_input()); }
                                div class="space-y-2" { label for="standard_trial_days" class="text-sm font-medium" { "Standard trial days" } input id="standard_trial_days" name="standard_trial_days" type="number" min="0" max=(MAX_TRIAL_DAYS) value=(values.standard_trial_days) class=(dashboard_input()); }
                            }
                        },
                    ))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                },
            }
        }
    }
}

pub async fn tier_settings(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cfg = admin_api::tier_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let values = cfg
        .as_ref()
        .map(TierFormValues::from_config)
        .unwrap_or_else(|| TierFormValues {
            lifetime_slots: String::new(),
            early_adopter_slots: String::new(),
            early_adopter_trial_days: String::new(),
            standard_trial_days: String::new(),
            free_price_id: String::new(),
            early_adopter_price_id: String::new(),
            standard_price_id: String::new(),
            lifetime_product_id: String::new(),
            early_adopter_product_id: String::new(),
            standard_product_id: String::new(),
        });
    let content = tier_settings_content(cfg.as_ref(), &values, None);
    admin_response(
        &c,
        &user,
        "/admin/tier-settings",
        "Tier Settings · Bunyip",
        content,
    )
}

#[derive(Deserialize)]
pub struct TierForm {
    // BUNYIP-111: kept as raw strings so a non-integer submission can be
    // echoed back and re-validated inline instead of failing Form extraction
    // with a bare 422.
    #[serde(default)]
    pub lifetime_slots: String,
    #[serde(default)]
    pub early_adopter_slots: String,
    #[serde(default)]
    pub early_adopter_trial_days: String,
    #[serde(default)]
    pub standard_trial_days: String,
    // BUNYIP-122: Stripe price + product IDs. Optional - blank ("" after
    // form parse) leaves the persisted value untouched. We send the field
    // only when non-empty so the API's tri-state-by-omission semantics
    // line up.
    #[serde(default)]
    pub free_price_id: String,
    #[serde(default)]
    pub early_adopter_price_id: String,
    #[serde(default)]
    pub standard_price_id: String,
    #[serde(default)]
    pub lifetime_product_id: String,
    #[serde(default)]
    pub early_adopter_product_id: String,
    #[serde(default)]
    pub standard_product_id: String,
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

    // Echo back exactly what was submitted (trimmed) if we have to re-render.
    let values = TierFormValues {
        lifetime_slots: f.lifetime_slots.trim().to_string(),
        early_adopter_slots: f.early_adopter_slots.trim().to_string(),
        early_adopter_trial_days: f.early_adopter_trial_days.trim().to_string(),
        standard_trial_days: f.standard_trial_days.trim().to_string(),
        free_price_id: f.free_price_id.trim().to_string(),
        early_adopter_price_id: f.early_adopter_price_id.trim().to_string(),
        standard_price_id: f.standard_price_id.trim().to_string(),
        lifetime_product_id: f.lifetime_product_id.trim().to_string(),
        early_adopter_product_id: f.early_adopter_product_id.trim().to_string(),
        standard_product_id: f.standard_product_id.trim().to_string(),
    };

    // Validate the numeric fields and build the request body before calling the
    // API, then surface any API-side rejection instead of discarding it. `?`
    // short-circuits on the first bad field so the message names the offending
    // input. The Stripe catalog IDs (BUNYIP-122) are sent only when non-empty
    // and within the 255-char column limit, so an omitted field leaves the
    // persisted value untouched.
    let validated = (|| {
        let mut body = serde_json::Map::new();
        body.insert(
            "lifetime_slots".into(),
            json!(parse_tier_field(
                &f.lifetime_slots,
                "Lifetime slots",
                MAX_TIER_SLOTS
            )?),
        );
        body.insert(
            "early_adopter_slots".into(),
            json!(parse_tier_field(
                &f.early_adopter_slots,
                "Early-adopter slots",
                MAX_TIER_SLOTS
            )?),
        );
        body.insert(
            "early_adopter_trial_days".into(),
            json!(parse_tier_field(
                &f.early_adopter_trial_days,
                "Early-adopter trial days",
                MAX_TRIAL_DAYS
            )?),
        );
        body.insert(
            "standard_trial_days".into(),
            json!(parse_tier_field(
                &f.standard_trial_days,
                "Standard trial days",
                MAX_TRIAL_DAYS
            )?),
        );
        for (k, v) in [
            ("free_price_id", &f.free_price_id),
            ("early_adopter_price_id", &f.early_adopter_price_id),
            ("standard_price_id", &f.standard_price_id),
            ("lifetime_product_id", &f.lifetime_product_id),
            ("early_adopter_product_id", &f.early_adopter_product_id),
            ("standard_product_id", &f.standard_product_id),
        ] {
            let t = v.trim();
            if !t.is_empty() && t.len() <= 255 {
                body.insert(k.into(), json!(t));
            }
        }
        Ok::<_, String>(serde_json::Value::Object(body))
    })();

    let error = match validated {
        Ok(body) => {
            match admin_api::update_tier_config(&st.api, c.forward.as_deref(), body).await {
                Ok(()) => return redirect_cookies("/admin/tier-settings", &c.set_cookies),
                Err(e) => e.user_message(),
            }
        }
        Err(msg) => msg,
    };

    // Re-render the form inline with the error and the submitted values.
    let cfg = admin_api::tier_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = tier_settings_content(cfg.as_ref(), &values, Some(&error));
    admin_response(
        &c,
        &user,
        "/admin/tier-settings",
        "Tier Settings · Bunyip",
        content,
    )
}
