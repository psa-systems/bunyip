//! Admin panel: Mirzam newsletter integration (BUNYIP-997).
//!
//! The Mirzam site address, the product-updates and notices list slugs, the
//! on/off switch and the write-only API token, plus a Check connection button
//! that reads both saved lists from Mirzam.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::api::types::{MirzamCheckResult, MirzamConfigResponse};
use crate::api::ApiError;
use crate::handlers::admin::secret_field_note;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::util::relative_time;
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::password::{password_field, PwField, PwRole};
use crate::views::ui::{
    button_class, error_box, error_box_detailed, error_box_for, icon, success_box,
    toggle_switch_field,
};
use crate::web::{redirect_cookies, AppState};

/// The page path, the topbar title and the sidebar label all agree (BUNYIP-551).
const PAGE: &str = "/admin/mirzam";
const TITLE: &str = "Mirzam";

/// Form values kept as typed, so a failed save echoes back what the admin
/// entered rather than the stored record (BUNYIP-731). The token is the
/// deliberate exception: it is re-rendered empty whatever was submitted.
#[derive(Default)]
pub(super) struct MirzamValues {
    enabled: bool,
    base_url: String,
    updates_list: String,
    notices_list: String,
}

impl MirzamValues {
    pub(super) fn from_form(f: &MirzamForm) -> Self {
        MirzamValues {
            enabled: f.enabled.trim() == "true",
            base_url: f.base_url.trim().to_string(),
            updates_list: f.updates_list.trim().to_string(),
            notices_list: f.notices_list.trim().to_string(),
        }
    }

    pub(super) fn from_config(c: &MirzamConfigResponse) -> Self {
        MirzamValues {
            enabled: c.enabled,
            base_url: c.base_url.clone(),
            updates_list: c.updates_list.clone(),
            notices_list: c.notices_list.clone(),
        }
    }
}

pub(super) fn mirzam_content(
    cfg: Result<&MirzamConfigResponse, &ApiError>,
    values: &MirzamValues,
    error: Option<&str>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { (TITLE) }
                p class="mt-2 text-muted-foreground" { "Connect to Mirzam, the newsletter service, so account holders are kept on its product-updates and notices lists." }
            }
            @match cfg {
                Err(e) => (error_box_for("Could not reach the API to load the Mirzam settings.", e)),
                Ok(c) => div class="space-y-6" {
                    form method="post" action=(PAGE) class="space-y-6" {
                        @if let Some(err) = error { (error_box(err)) }
                        (admin_block_grid(vec![
                            admin_block(
                                "Connection",
                                Some("The Mirzam site and the API token bunyip calls it with."),
                                html! {
                                    div class="space-y-4" {
                                        div class="flex items-center gap-3" {
                                            (toggle_switch_field("enabled", "enabled", values.enabled, "Enabled"))
                                            label for="enabled" class="text-sm font-medium" { "Enabled" }
                                        }
                                        div class="space-y-2" {
                                            label for="base_url" class="text-sm font-medium" { "Mirzam address" }
                                            input id="base_url" name="base_url" type="url" value=(values.base_url) placeholder="https://news.example.com" class=(dashboard_input());
                                        }
                                        // Write-only, like the SMTP password (BUNYIP-432/542): the
                                        // placeholder is a fixed mask driven by has_api_token, and in
                                        // SECRETS_STORAGE=environment the field is read-only.
                                        @if c.api_token_editable {
                                            (password_field("api_token", "api_token", "API token", PwRole::New, PwField {
                                                autocomplete: Some("new-password"),
                                                placeholder: Some(if c.has_api_token { "••••••••" } else { "Not set" }),
                                                ..Default::default()
                                            }))
                                        } @else {
                                            div class="space-y-2" {
                                                label for="api_token" class="text-sm font-medium" { "API token" }
                                                input id="api_token" name="api_token" type="password" autocomplete="new-password" readonly disabled placeholder=(if c.has_api_token { "••••••••" } else { "Not set" }) class=(dashboard_input());
                                            }
                                        }
                                        p class="text-xs text-muted-foreground" {
                                            (secret_field_note(c.api_token_editable, &c.secrets_storage, c.has_api_token, "MIRZAM_API_TOKEN", "mirzam_api_token"))
                                            " A Mirzam administrator makes the token on Mirzam's API page, with read and write access."
                                        }
                                    }
                                },
                            ),
                            admin_block(
                                "Lists",
                                Some("The slugs of the two Mirzam lists account holders are kept on."),
                                html! {
                                    div class="space-y-4" {
                                        div class="space-y-2" {
                                            label for="updates_list" class="text-sm font-medium" { "Product updates list" }
                                            input id="updates_list" name="updates_list" value=(values.updates_list) placeholder="product-updates" autocomplete="off" class=(dashboard_input());
                                            p class="text-xs text-muted-foreground" { "A newsletter list. Account holders are on it unless they leave it." }
                                        }
                                        div class="space-y-2" {
                                            label for="notices_list" class="text-sm font-medium" { "Notices list" }
                                            input id="notices_list" name="notices_list" value=(values.notices_list) placeholder="notices" autocomplete="off" class=(dashboard_input());
                                            p class="text-xs text-muted-foreground" { "A notices list, for required account notices nobody leaves while they have an account." }
                                        }
                                    }
                                },
                            ),
                        ]))
                        button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    }
                    // Its own form so it submits no fields: it always checks the
                    // SAVED settings, never the unsaved edits above.
                    form method="post" action="/admin/mirzam/check" class="flex flex-wrap items-center gap-3 border-t border-border/50 pt-4" {
                        button type="submit" class=(button_class("outline", "default", "")) { (icon("check-circle", "mr-2 h-4 w-4")) "Check connection" }
                        p class="text-xs text-muted-foreground" { "Reads both saved lists from Mirzam with the saved token. Save changes first to check them." }
                    }
                    (sync_block(c))
                    (crate::views::password::script())
                },
            }
        }
    }
}

/// The last failed sync call (BUNYIP-998), or that none is recorded. The api
/// clears it when a later call succeeds.
pub(super) fn sync_block(c: &MirzamConfigResponse) -> Markup {
    admin_block(
        "Sync",
        Some("While the integration is on, bunyip adds verified account holders to both lists, moves them when their address changes and removes them when the account is deleted, in the background."),
        html! {
            @match &c.last_error {
                Some(err) => {
                    @let when = c.last_error_at.as_deref().map(relative_time);
                    @let headline = match &when {
                        Some(when) => format!("The last call to Mirzam failed {when}."),
                        None => "The last call to Mirzam failed.".to_string(),
                    };
                    (error_box_detailed(&headline, Some(err), None))
                }
                None => p class="text-sm text-muted-foreground" { "No failed calls." },
            }
        },
    )
}

pub async fn mirzam(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cfg = admin_api::mirzam_config(&st.api, c.forward.as_deref()).await;
    let values = cfg
        .as_ref()
        .map(MirzamValues::from_config)
        .unwrap_or_default();
    admin_response(
        &c,
        &user,
        PAGE,
        TITLE,
        mirzam_content(cfg.as_ref(), &values, None),
    )
}

#[derive(Deserialize)]
pub struct MirzamForm {
    #[serde(default)]
    pub enabled: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub updates_list: String,
    #[serde(default)]
    pub notices_list: String,
    #[serde(default)]
    pub api_token: String,
}

/// The PUT body. The four settings are always sent, because the API replaces
/// them whole (a blank address or slug is a deliberate clear); the token is
/// sent only when typed, since a blank token means "keep the stored one". Pure
/// so it can be unit-tested; the API does the validation.
pub(super) fn mirzam_update_body(f: &MirzamForm) -> serde_json::Value {
    let mut body = json!({
        "enabled": f.enabled.trim() == "true",
        "base_url": f.base_url.trim(),
        "updates_list": f.updates_list.trim(),
        "notices_list": f.notices_list.trim(),
    });
    let token = f.api_token.trim();
    if !token.is_empty() {
        body["api_token"] = json!(token);
    }
    body
}

pub async fn mirzam_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<MirzamForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let error = match admin_api::update_mirzam_config(
        &st.api,
        c.forward.as_deref(),
        mirzam_update_body(&f),
    )
    .await
    {
        Ok(()) => return redirect_cookies(PAGE, &c.set_cookies),
        Err(e) => e.user_message(),
    };
    // Re-render the submitted values with the error; only the record's
    // non-form facts (the token flags) need a re-fetch.
    let cfg = admin_api::mirzam_config(&st.api, c.forward.as_deref()).await;
    let values = MirzamValues::from_form(&f);
    admin_response(
        &c,
        &user,
        PAGE,
        TITLE,
        mirzam_content(cfg.as_ref(), &values, Some(&error)),
    )
}

fn list_label(list: &str) -> &'static str {
    match list {
        "updates_list" => "Product updates list",
        "notices_list" => "Notices list",
        _ => "List",
    }
}

/// The banners for a Check connection click: one per list, green when Mirzam
/// answered with a list of the right kind and red otherwise, each naming the
/// slug and what was found or what is wrong. Pure, so every outcome is
/// testable without an API.
pub(super) fn check_banners(result: Result<MirzamCheckResult, ApiError>) -> Markup {
    match result {
        Ok(r) if r.lists.is_empty() => {
            error_box("The connection check returned no result. Try again.")
        }
        Ok(r) => html! {
            div class="space-y-2" {
                @for list in &r.lists {
                    @let line = format!("{} ({}): {}", list_label(&list.list), list.slug, list.message);
                    @if list.ok { (success_box(&line)) } @else { (error_box(&line)) }
                }
            }
        },
        // Missing settings (400), a rate limit or a transport error before the
        // check could report.
        Err(e) => error_box(&e.user_message()),
    }
}

/// POST /admin/mirzam/check: check the saved settings against Mirzam and
/// re-render the page with the outcome above it.
pub async fn mirzam_check(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let (check_result, cfg) = tokio::join!(
        admin_api::check_mirzam_connection(&st.api, c.forward.as_deref()),
        admin_api::mirzam_config(&st.api, c.forward.as_deref())
    );
    let banners = check_banners(check_result);
    let values = cfg
        .as_ref()
        .map(MirzamValues::from_config)
        .unwrap_or_default();
    let content = html! {
        (banners)
        (mirzam_content(cfg.as_ref(), &values, None))
    };
    admin_response(&c, &user, PAGE, TITLE, content)
}
