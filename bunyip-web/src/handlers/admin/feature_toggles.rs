//! Admin panel: Feature Toggles (BUNYIP-840).
//!
//! One row per entry in bunyip-api's feature-toggle registry, each its own form
//! posting to `/admin/features`. Any admin sees the states; only the super admin
//! can flip one, which the API enforces again.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::admin as admin_api;
use crate::api::types::AdminFeatureToggle;
use crate::handlers::{admin_guard, admin_response};
use crate::util::{rel_time, urlenc};
use crate::views::layout::admin_block;
use crate::views::ui::{badge, button_class, empty_state, error_box, icon, toggle_switch_field};
use crate::web::{redirect_cookies, AppState};

use super::refuse_non_super_admin;

/// Who changed the toggle and when, or that nobody has.
fn last_changed(t: &AdminFeatureToggle) -> Markup {
    html! {
        p class="text-xs text-muted-foreground" {
            @match (&t.updated_at, &t.updated_by_email) {
                (Some(at), Some(by)) => { "Last changed by " (by) " " (rel_time(at)) }
                (Some(at), None) => { "Last changed " (rel_time(at)) }
                _ => { "Never changed. Off by default." }
            }
        }
    }
}

fn feature_toggle_row(t: &AdminFeatureToggle, editable: bool) -> Markup {
    let id = format!("feature-{}", t.key);
    admin_block(
        &t.label,
        Some(&t.help),
        html! {
            div class="flex flex-wrap items-center justify-between gap-4" {
                @if editable {
                    form method="post" action="/admin/features" class="flex items-center gap-3" {
                        input type="hidden" name="key" value=(t.key);
                        (toggle_switch_field(&id, "enabled", t.enabled, &t.label))
                        label for=(id) class="text-sm font-medium" { "Enabled" }
                        button type="submit" class=(button_class("default", "sm", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    }
                } @else {
                    div class="flex items-center gap-2" {
                        @if t.enabled { (badge("success", "On")) } @else { (badge("secondary", "Off")) }
                        span class="text-xs text-muted-foreground" { "Only the super admin can change this." }
                    }
                }
                (last_changed(t))
            }
        },
    )
}

pub(super) fn feature_toggles_content(
    toggles: &[AdminFeatureToggle],
    reachable: bool,
    editable: bool,
) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "Feature Toggles" }
                p class="mt-2 text-muted-foreground" { "Switch a whole feature on or off for this deployment. Off means hidden: its pages return 404 and its links are not shown. A change is live everywhere within a minute, with no restart." }
            }
            @if !reachable {
                (error_box("Could not reach the API to load the feature toggles."))
            } @else if toggles.is_empty() {
                (empty_state("sliders-horizontal", "No feature toggles.", None))
            } @else {
                @for t in toggles { (feature_toggle_row(t, editable)) }
            }
        }
    }
}

pub async fn feature_toggles(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let data = admin_api::feature_toggles(&st.api, c.forward.as_deref()).await;
    if let Err(e) = &data {
        tracing::warn!(
            endpoint = "/v1/admin/feature-toggles",
            error = %e.message,
            code = %e.code,
            "feature toggles unavailable on the Feature Toggles page"
        );
    }
    let reachable = data.is_ok();
    let toggles = data.unwrap_or_default();
    let content = feature_toggles_content(&toggles, reachable, user.is_super_admin);
    admin_response(&c, &user, "/admin/features", "Feature Toggles", content)
}

/// One row's submission. An unticked switch is absent from the body, which is
/// a real "off" because every row form renders the control.
#[derive(Deserialize)]
pub struct FeatureToggleForm {
    pub key: String,
    #[serde(default)]
    pub enabled: Option<String>,
}

pub async fn feature_toggle_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<FeatureToggleForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(refusal) = refuse_non_super_admin(&user, &c, "/admin/features") {
        return refusal;
    }
    let target = match admin_api::set_feature_toggle(
        &st.api,
        c.forward.as_deref(),
        f.key.trim(),
        f.enabled.is_some(),
    )
    .await
    {
        Ok(()) => "/admin/features?toast_ok=Feature%20toggle%20saved".to_string(),
        Err(e) => format!("/admin/features?toast_err={}", urlenc(&e.user_message())),
    };
    redirect_cookies(&target, &c.set_cookies)
}
