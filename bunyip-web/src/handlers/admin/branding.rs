//! Admin panel: product branding (BUNYIP-561).
//!
//! The one place the product name, tagline, meta description and Open Graph
//! image are set. Modelled on the Email config page: one form, one Save, the
//! persisted values re-read after a failed save so the admin never loses what
//! is actually stored.
//!
//! Every field is a full replacement, not a "blank keeps the current value":
//! clearing a field is how an admin removes a tagline, description or share
//! image, and an empty value omits the corresponding markup rather than
//! substituting anything.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::types::Branding;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{button_class, error_box, icon};
use crate::web::{redirect_cookies, AppState};

pub(super) fn branding_content(cfg: Option<&Branding>, reachable: bool) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "Branding" }
                p class="mt-2 text-muted-foreground" { "The product name, tagline and sharing metadata. Saved here, not compiled in; changes reach every page within a minute." }
            }
            @if !reachable {
                (error_box("Could not reach the API to load branding."))
            } @else if let Some(b) = cfg {
                form method="post" action="/admin/branding" class="space-y-6" {
                    (admin_block_grid(vec![
                        admin_block(
                            "Identity",
                            Some("Shown in the navigation, the browser title and every email subject. Clear a field to remove it."),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" {
                                        label for="brand_name" class="text-sm font-medium" { "Product name" }
                                        input id="brand_name" name="brand_name" maxlength="120" value=(b.brand_name) class=(dashboard_input());
                                        p class="text-xs text-muted-foreground" { "Left blank, the deployment falls back to the APP_NAME the api was started with." }
                                    }
                                    div class="space-y-2" {
                                        label for="tagline" class="text-sm font-medium" { "Tagline" }
                                        input id="tagline" name="tagline" maxlength="200" value=(b.tagline) class=(dashboard_input());
                                        p class="text-xs text-muted-foreground" { "One line under the mark. Omitted entirely when blank." }
                                    }
                                }
                            },
                        ),
                        admin_block(
                            "Sharing",
                            Some("What a link to this site previews as in a chat client, a search result or a social card."),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" {
                                        label for="meta_description" class="text-sm font-medium" { "Description" }
                                        textarea id="meta_description" name="meta_description" rows="3" maxlength="320" class=(dashboard_input()) { (b.meta_description) }
                                        p class="text-xs text-muted-foreground" { "The meta description and the Open Graph description. Omitted when blank." }
                                    }
                                    div class="space-y-2" {
                                        label for="og_image_url" class="text-sm font-medium" { "Share image URL" }
                                        input id="og_image_url" name="og_image_url" type="url" maxlength="2048" value=(b.og_image_url) placeholder="https://example.com/card.png" class=(dashboard_input());
                                        p class="text-xs text-muted-foreground" { "Absolute https:// URL. A card previews as a large image when this is set and a small one when it is blank." }
                                    }
                                }
                            },
                        ),
                    ]))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                }
            } @else {
                (error_box("Could not load branding."))
            }
        }
    }
}

pub async fn branding(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // BUNYIP-461/546: a failed fetch is told apart from an empty record, so
    // "could not load" never reads as "nothing configured".
    let data = crate::branding::admin_get(&st.api, c.forward.as_deref()).await;
    let reachable = data.is_ok();
    let cfg = data.ok();
    let content = branding_content(cfg.as_ref(), reachable);
    admin_response(&c, &user, "/admin/branding", "Branding", content)
}

#[derive(Deserialize)]
pub struct BrandingForm {
    #[serde(default)]
    pub brand_name: String,
    #[serde(default)]
    pub tagline: String,
    #[serde(default)]
    pub meta_description: String,
    #[serde(default)]
    pub og_image_url: String,
}

/// The PUT body. Every field is sent every time, blank included: the record has
/// no "leave it alone" semantics, because clearing a field is the way to remove
/// its markup. Pure, so it is unit-testable.
pub(super) fn branding_update_body(f: &BrandingForm) -> serde_json::Value {
    json!({
        "brand_name": f.brand_name.trim(),
        "tagline": f.tagline.trim(),
        "meta_description": f.meta_description.trim(),
        "og_image_url": f.og_image_url.trim(),
    })
}

pub async fn branding_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<BrandingForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let error = match crate::branding::admin_update(
        &st.api,
        c.forward.as_deref(),
        branding_update_body(&f),
    )
    .await
    {
        Ok(()) => return redirect_cookies("/admin/branding", &c.set_cookies),
        // A rejected save is a 4xx carrying the api's per-field message, which
        // passes through `user_message` verbatim (BUNYIP-506 only collapses
        // 5xx and transport failures).
        Err(e) => e.user_message(),
    };

    // Re-render with the PERSISTED values plus the inline error: the save wrote
    // nothing, so showing the rejected input back would misreport the state.
    let data = crate::branding::admin_get(&st.api, c.forward.as_deref()).await;
    let reachable = data.is_ok();
    let cfg = data.ok();
    let content = html! {
        (error_box(&error))
        (branding_content(cfg.as_ref(), reachable))
    };
    admin_response(&c, &user, "/admin/branding", "Branding", content)
}
