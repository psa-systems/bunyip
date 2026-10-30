//! Admin panel: the Mokosh host settings (BUNYIP-983).
//!
//! The Google OAuth client a hosted Mokosh reads over
//! `GET /v1/host/secrets/mokosh/google_oauth_client`. The id is public and is
//! shown; the secret is write-only, like every other governed secret on these
//! pages.
//!
//! One thing is unlike the other config pages. Changing the id stops contact
//! sync for every Mokosh tenant until each reconnects, so the first save of a
//! changed id comes back as a warning and the page then offers "Save anyway",
//! which is the same request with `confirm_client_id_change` set (BUNYIP-855
//! D10). The confirmation lives in a hidden field rather than in a session,
//! because the thing being confirmed is the value in front of the admin.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::api::types::MokoshConfigResponse;
use crate::api::ApiError;
use crate::handlers::admin::secret_field_note;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::password::{password_field, PwField, PwRole};
use crate::views::ui::{button_class, error_box, error_box_for, icon, warning_box};
use crate::web::{redirect_cookies, AppState};

/// The page path, the topbar title and the sidebar label all agree
/// (BUNYIP-551).
const PAGE: &str = "/admin/mokosh";
const TITLE: &str = "Mokosh";
/// Where a successful save lands: the page, with the confirmation toast the
/// other admin pages show (BUNYIP-1014).
pub(super) const SAVED: &str = "/admin/mokosh?toast_ok=Mokosh%20settings%20saved";

/// Form values kept as typed, so a failed save echoes back what the admin
/// entered rather than the stored record (BUNYIP-731). The secret is the
/// deliberate exception: it is re-rendered empty whatever was submitted.
#[derive(Default)]
pub(super) struct MokoshValues {
    google_client_id: String,
}

impl MokoshValues {
    pub(super) fn from_form(f: &MokoshForm) -> Self {
        MokoshValues {
            google_client_id: f.google_client_id.trim().to_string(),
        }
    }

    pub(super) fn from_config(c: &MokoshConfigResponse) -> Self {
        MokoshValues {
            google_client_id: c.google_client_id.clone(),
        }
    }
}

pub(super) fn mokosh_content(
    cfg: Result<&MokoshConfigResponse, &ApiError>,
    values: &MokoshValues,
    error: Option<&str>,
    confirm_change: Option<&str>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { (TITLE) }
                p class="mt-2 text-muted-foreground" { "The Google OAuth client the hosted Mokosh deployments use to sync a customer's contacts. Set it here once and every hosted Mokosh reads it on its next restart." }
            }
            @match cfg {
                Err(e) => (error_box_for("Could not reach the API to load the Mokosh settings.", e)),
                Ok(c) => div class="space-y-6" {
                    form method="post" action=(PAGE) class="space-y-6" {
                        @if let Some(err) = error { (error_box(err)) }
                        @if let Some(warning) = confirm_change { (warning_box(warning)) }
                        (admin_block_grid(vec![
                            admin_block(
                                "Google OAuth client",
                                Some("From the Google Cloud project that owns the suite's OAuth consent screen."),
                                html! {
                                    div class="space-y-4" {
                                        div class="space-y-2" {
                                            label for="google_client_id" class="text-sm font-medium" { "Client id" }
                                            input id="google_client_id" name="google_client_id" value=(values.google_client_id) placeholder="123456789012-abc123def456.apps.googleusercontent.com" autocomplete="off" class=(dashboard_input());
                                            p class="text-xs text-muted-foreground" { "Public: it travels in every sign-in redirect, so it is shown here rather than masked." }
                                        }
                                        // Write-only, like the SMTP password and
                                        // the Mirzam token (BUNYIP-432/542/997).
                                        @if c.google_client_secret_editable {
                                            (password_field("google_client_secret", "google_client_secret", "Client secret", PwRole::New, PwField {
                                                autocomplete: Some("new-password"),
                                                placeholder: Some(if c.has_google_client_secret { "••••••••" } else { "Not set" }),
                                                ..Default::default()
                                            }))
                                        } @else {
                                            div class="space-y-2" {
                                                label for="google_client_secret" class="text-sm font-medium" { "Client secret" }
                                                input id="google_client_secret" name="google_client_secret" type="password" autocomplete="new-password" readonly disabled placeholder=(if c.has_google_client_secret { "••••••••" } else { "Not set" }) class=(dashboard_input());
                                            }
                                        }
                                        p class="text-xs text-muted-foreground" {
                                            (secret_field_note(c.google_client_secret_editable, &c.secrets_storage, c.has_google_client_secret, "MOKOSH_GOOGLE_CLIENT_SECRET", "mokosh_google_client_secret"))
                                            " Rotating the secret alone is safe: nobody has to reconnect."
                                        }
                                    }
                                },
                            ),
                        ]))
                        // Set only on the second attempt, so the admin confirms
                        // the value they can see rather than one held in a
                        // session.
                        @if confirm_change.is_some() {
                            input type="hidden" name="confirm_client_id_change" value="true";
                        }
                        button type="submit" class=(button_class("default", "default", "")) {
                            (icon("save", "mr-2 h-4 w-4"))
                            @if confirm_change.is_some() { "Save anyway" } @else { "Save" }
                        }
                    }
                    (crate::views::password::script())
                },
            }
        }
    }
}

pub async fn mokosh(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cfg = admin_api::mokosh_config(&st.api, c.forward.as_deref()).await;
    let values = cfg
        .as_ref()
        .map(MokoshValues::from_config)
        .unwrap_or_default();
    admin_response(
        &c,
        &user,
        PAGE,
        TITLE,
        mokosh_content(cfg.as_ref(), &values, None, None),
    )
}

#[derive(Deserialize)]
pub struct MokoshForm {
    #[serde(default)]
    pub google_client_id: String,
    #[serde(default)]
    pub google_client_secret: String,
    #[serde(default)]
    pub confirm_client_id_change: String,
}

/// The PUT body. The id is always sent, because the API replaces it whole (a
/// blank id is a deliberate clear); the secret is sent only when typed, since a
/// blank one means "keep the stored one". Pure so it can be unit-tested; the
/// API does the validation.
pub(super) fn mokosh_update_body(f: &MokoshForm) -> serde_json::Value {
    let mut body = json!({
        "google_client_id": f.google_client_id.trim(),
        "confirm_client_id_change": f.confirm_client_id_change.trim() == "true",
    });
    let secret = f.google_client_secret.trim();
    if !secret.is_empty() {
        body["google_client_secret"] = json!(secret);
    }
    body
}

/// Whether an API refusal is the changed-id warning rather than a plain error.
///
/// Matched on the status and the sentence the API sends, not on a code of our
/// own: the 409 is what the API answers for a read-only secrets provider too,
/// and that one is an error with nothing to confirm.
pub(super) fn is_client_id_warning(e: &ApiError) -> bool {
    e.user_message().contains("confirm_client_id_change")
}

/// What the admin reads above the form on the first attempt. The API's sentence
/// minus the machine instruction, which the "Save anyway" button now is.
pub(super) fn warning_text(e: &ApiError) -> String {
    e.user_message()
        .split(" Send the same change again")
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub async fn mokosh_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<MokoshForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let (error, confirm) = match admin_api::update_mokosh_config(
        &st.api,
        c.forward.as_deref(),
        mokosh_update_body(&f),
    )
    .await
    {
        Ok(()) => return redirect_cookies(SAVED, &c.set_cookies),
        Err(e) if is_client_id_warning(&e) => (None, Some(warning_text(&e))),
        Err(e) => (Some(e.user_message()), None),
    };
    // Re-render the submitted values with the error or the warning; only the
    // record's non-form facts (the secret flags) need a re-fetch.
    let cfg = admin_api::mokosh_config(&st.api, c.forward.as_deref()).await;
    let values = MokoshValues::from_form(&f);
    admin_response(
        &c,
        &user,
        PAGE,
        TITLE,
        mokosh_content(cfg.as_ref(), &values, error.as_deref(), confirm.as_deref()),
    )
}
