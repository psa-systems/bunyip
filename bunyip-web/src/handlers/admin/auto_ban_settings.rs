//! Admin panel: Auto-ban settings (BUNYIP-351).

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{button_class, error_box, icon};
use crate::web::{redirect_cookies, AppState};

/// Upper bounds for the auto-ban fields. Threshold is a strike count; the two
/// durations are seconds (window capped at 30 days, ban at 365 days) so a typo
/// cannot persist an absurd value.
const MAX_AUTO_BAN_THRESHOLD: i64 = 100_000;
const MAX_AUTO_BAN_WINDOW_SECS: i64 = 2_592_000; // 30 days
const MAX_AUTO_BAN_DURATION_SECS: i64 = 31_536_000; // 365 days

/// Auto-ban form values, kept as strings (numerics) so a failed save echoes
/// back exactly what the admin typed instead of failing extraction with a 422.
pub(super) struct AutoBanFormValues {
    enabled: bool,
    threshold: String,
    window_secs: String,
    ban_duration_secs: String,
}

impl AutoBanFormValues {
    pub(super) fn from_config(c: &crate::api::types::AutoBanConfigResponse) -> Self {
        AutoBanFormValues {
            enabled: c.enabled,
            threshold: c.threshold.to_string(),
            window_secs: c.window_secs.to_string(),
            ban_duration_secs: c.ban_duration_secs.to_string(),
        }
    }
}

/// Parse one auto-ban field: require a base-10 integer in `[1, max]`.
fn parse_auto_ban_field(raw: &str, label: &str, max: i64) -> Result<i64, String> {
    let n: i64 = raw
        .trim()
        .parse()
        .map_err(|_| format!("{label} must be a whole number."))?;
    if n < 1 {
        return Err(format!("{label} must be at least 1."));
    }
    if n > max {
        return Err(format!("{label} must be at most {max}."));
    }
    Ok(n)
}

pub(super) fn auto_ban_settings_content(
    cfg: Option<&crate::api::types::AutoBanConfigResponse>,
    values: &AutoBanFormValues,
    error: Option<&str>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Auto-ban Settings" } p class="mt-2 text-muted-foreground" { "Tune the automatic IP-ban thresholds. Changes apply immediately without a restart." } }
            @match cfg {
                None => p class="text-muted-foreground" { "Could not load auto-ban config." },
                // BUNYIP-415: detection (when to strike/ban) and enforcement
                // (the on/off switch and how long a ban lasts) sit in two
                // side-by-side blocks, one column below lg, inside one form.
                Some(c) => form method="post" action="/admin/auto-ban-settings" class="space-y-6" {
                    @if let Some(e) = error { (error_box(e)) }
                    (admin_block_grid(vec![
                        admin_block(
                            "Detection",
                            Some(&format!("When a source IP earns a ban. Values sourced from {}.", c.source)),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" { label class="text-sm font-medium" { "Strike threshold" } input name="threshold" type="number" min="1" max=(MAX_AUTO_BAN_THRESHOLD) value=(values.threshold) class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Suspicious requests from one IP before it is banned." } }
                                    div class="space-y-2" { label class="text-sm font-medium" { "Strike window (seconds)" } input name="window_secs" type="number" min="1" max=(MAX_AUTO_BAN_WINDOW_SECS) value=(values.window_secs) class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Rolling window over which strikes accumulate." } }
                                }
                            },
                        ),
                        admin_block(
                            "Enforcement",
                            Some("Whether auto-ban is active, and how long a ban holds."),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" {
                                        label class="text-sm font-medium" { "Auto-ban" }
                                        select name="enabled" class=(dashboard_input()) {
                                            option value="true" selected[values.enabled] { "Enabled" }
                                            option value="false" selected[!values.enabled] { "Disabled" }
                                        }
                                    }
                                    div class="space-y-2" { label class="text-sm font-medium" { "Ban duration (seconds)" } input name="ban_duration_secs" type="number" min="1" max=(MAX_AUTO_BAN_DURATION_SECS) value=(values.ban_duration_secs) class=(dashboard_input()); p class="text-xs text-muted-foreground" { "How long a ban lasts before it expires." } }
                                }
                            },
                        ),
                    ]))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                },
            }
        }
    }
}

pub async fn auto_ban_settings(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cfg = admin_api::auto_ban_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let values = cfg
        .as_ref()
        .map(AutoBanFormValues::from_config)
        .unwrap_or(AutoBanFormValues {
            enabled: false,
            threshold: String::new(),
            window_secs: String::new(),
            ban_duration_secs: String::new(),
        });
    let content = auto_ban_settings_content(cfg.as_ref(), &values, None);
    admin_response(
        &c,
        &user,
        "/admin/auto-ban-settings",
        "Auto-ban settings · Bunyip",
        content,
    )
}

#[derive(Deserialize)]
pub struct AutoBanForm {
    #[serde(default)]
    pub enabled: String,
    #[serde(default)]
    pub threshold: String,
    #[serde(default)]
    pub window_secs: String,
    #[serde(default)]
    pub ban_duration_secs: String,
}

pub async fn auto_ban_settings_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<AutoBanForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let enabled = f.enabled.trim() == "true";

    // Echo back exactly what was submitted (trimmed) if we have to re-render.
    let values = AutoBanFormValues {
        enabled,
        threshold: f.threshold.trim().to_string(),
        window_secs: f.window_secs.trim().to_string(),
        ban_duration_secs: f.ban_duration_secs.trim().to_string(),
    };

    // Validate the numeric fields and build the request body. `?` short-circuits
    // on the first bad field so the message names the offending input. `enabled`
    // is always sent explicitly (a full form submit represents the admin's
    // intent), the numerics likewise, so the API's COALESCE never re-reads a
    // stale value.
    let validated = (|| {
        let mut body = serde_json::Map::new();
        body.insert("enabled".into(), json!(enabled));
        body.insert(
            "threshold".into(),
            json!(parse_auto_ban_field(
                &f.threshold,
                "Strike threshold",
                MAX_AUTO_BAN_THRESHOLD
            )?),
        );
        body.insert(
            "window_secs".into(),
            json!(parse_auto_ban_field(
                &f.window_secs,
                "Strike window",
                MAX_AUTO_BAN_WINDOW_SECS
            )?),
        );
        body.insert(
            "ban_duration_secs".into(),
            json!(parse_auto_ban_field(
                &f.ban_duration_secs,
                "Ban duration",
                MAX_AUTO_BAN_DURATION_SECS
            )?),
        );
        Ok::<_, String>(serde_json::Value::Object(body))
    })();

    let error = match validated {
        Ok(body) => {
            match admin_api::update_auto_ban_config(&st.api, c.forward.as_deref(), body).await {
                Ok(()) => return redirect_cookies("/admin/auto-ban-settings", &c.set_cookies),
                Err(e) => e.user_message(),
            }
        }
        Err(msg) => msg,
    };

    // Re-render the form inline with the error and the submitted values.
    let cfg = admin_api::auto_ban_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = auto_ban_settings_content(cfg.as_ref(), &values, Some(&error));
    admin_response(
        &c,
        &user,
        "/admin/auto-ban-settings",
        "Auto-ban settings · Bunyip",
        content,
    )
}
