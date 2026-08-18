//! Admin panel: product branding (BUNYIP-561, BUNYIP-560).
//!
//! The one place the product name, tagline, meta description, Open Graph image,
//! palette and brand images are set. Modelled on the Email config page: one
//! form, one Save, the persisted values re-read after a failed save so the admin
//! never loses what is actually stored.
//!
//! Every field is a full replacement, not a "blank keeps the current value":
//! clearing a field is how an admin removes a tagline, description, share image
//! or palette entry, and an empty value omits the corresponding markup rather
//! than substituting anything.
//!
//! BUNYIP-560: the three image slots (mark, favicon source, mascot) are their
//! OWN small forms rather than file inputs on the text form. An upload is a
//! multipart request whose failure has to be reported on its own terms, and one
//! combined submit would make "the palette saved but the logo did not" a state
//! the page could reach.

use axum::extract::{Multipart, Path, State};
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

/// BUNYIP-560: 2 MiB upload ceiling on the BFF, matching `ImagePolicy::avatar()`
/// api-side and the `branding_assets` size CHECK. The API re-validates type,
/// size and dimensions; rejecting an oversized body here avoids relaying it.
const MAX_ASSET_UPLOAD_BYTES: usize = 2 * 1024 * 1024;

/// One uploadable brand image, as the page renders it.
struct AssetSlot {
    /// Path segment: the api's slot name and this page's sub-route.
    slot: &'static str,
    title: &'static str,
    help: &'static str,
    /// What the preview `<img>` loads when the slot is filled.
    preview_src: fn(&Branding) -> Option<String>,
    /// What the page says when it is not.
    empty: &'static str,
}

const ASSET_SLOTS: &[AssetSlot] = &[
    AssetSlot {
        slot: "mark",
        title: "Brand mark",
        help: "Shown beside the product name in the header. Square works best. Left unset, a plain glyph is drawn in the theme colour.",
        preview_src: Branding::mark_src,
        empty: "No mark uploaded. The header draws the built-in glyph.",
    },
    AssetSlot {
        slot: "favicon",
        title: "Favicon source",
        help: "One square image; the browser-tab icons (16, 32, 48, 192, 512), the iOS home-screen icon and favicon.ico are all derived from it. Left unset, the icons that ship with the build are served.",
        preview_src: |b| b.favicon_src("favicon-192"),
        empty: "No source uploaded. The icons that ship with the build are served.",
    },
    AssetSlot {
        slot: "mascot",
        title: "Hero illustration",
        help: "The picture beside the headline on the landing page. Left unset, the hero renders without one.",
        preview_src: Branding::mascot_src,
        empty: "No illustration uploaded. The hero renders without one.",
    },
];

/// The upload / clear / preview card for one slot.
fn asset_card(s: &AssetSlot, b: &Branding) -> Markup {
    let current = (s.preview_src)(b);
    html! {
        div class="space-y-4" {
            p class="text-xs text-muted-foreground" { (s.help) }
            @if let Some(src) = &current {
                // `alt` is empty: the card's heading already names the slot, and
                // the image is a preview of it, not information of its own.
                img src=(src) alt="" class="h-20 w-20 rounded-md border border-border object-contain bg-card p-1";
            } @else {
                p class="text-sm text-muted-foreground" { (s.empty) }
            }
            form method="post" action=(format!("/admin/branding/assets/{}", s.slot)) enctype="multipart/form-data" class="space-y-3" {
                input type="file" name="asset" accept="image/png,image/jpeg,image/webp,image/gif" required class=(dashboard_input());
                div class="flex flex-wrap items-center gap-2" {
                    button type="submit" class=(button_class("default", "sm", "")) { (icon("upload", "mr-2 h-4 w-4")) "Upload" }
                }
            }
            @if current.is_some() {
                form method="post" action=(format!("/admin/branding/assets/{}/clear", s.slot)) {
                    button type="submit" class=(button_class("outline", "sm", "")) { (icon("trash", "mr-2 h-4 w-4")) "Remove" }
                }
            }
        }
    }
}

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
                        // BUNYIP-560: the palette rides on the same Save as the
                        // copy. Both are text on one record, and splitting them
                        // would make "the name saved but the colour did not" a
                        // reachable state.
                        admin_block(
                            "Palette",
                            Some("The brand ramp and the colour the browser paints its own chrome. Clear a field to fall back to the default palette."),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" {
                                        label for="theme_css" class="text-sm font-medium" { "Theme CSS" }
                                        textarea id="theme_css" name="theme_css" rows="4" maxlength="4096" placeholder="--skin-primary-500: #336699; --skin-accent-500: #993366;" class=(dashboard_input()) { (b.theme_css) }
                                        p class="text-xs text-muted-foreground" { "CSS custom properties, emitted into :root. No angle brackets." }
                                    }
                                    div class="grid gap-4 sm:grid-cols-2" {
                                        div class="space-y-2" {
                                            label for="theme_color_light" class="text-sm font-medium" { "Browser chrome, light" }
                                            input id="theme_color_light" name="theme_color_light" maxlength="9" value=(b.theme_color_light) placeholder="#336699" class=(dashboard_input());
                                        }
                                        div class="space-y-2" {
                                            label for="theme_color_dark" class="text-sm font-medium" { "Browser chrome, dark" }
                                            input id="theme_color_dark" name="theme_color_dark" maxlength="9" value=(b.theme_color_dark) placeholder="#112233" class=(dashboard_input());
                                        }
                                    }
                                    p class="text-xs text-muted-foreground" { "Hex colours. Blank omits the meta tag rather than guessing one." }
                                }
                            },
                        ),
                    ]))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                }
                // BUNYIP-560: the images, each its own upload. Outside the form
                // above, because a file upload is a separate request.
                (admin_block_grid(ASSET_SLOTS.iter().map(|s| admin_block(s.title, None, asset_card(s, b))).collect()))
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
    #[serde(default)]
    pub theme_css: String,
    #[serde(default)]
    pub theme_color_light: String,
    #[serde(default)]
    pub theme_color_dark: String,
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
        "theme_css": f.theme_css.trim(),
        "theme_color_light": f.theme_color_light.trim(),
        "theme_color_dark": f.theme_color_dark.trim(),
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

/// BUNYIP-560: read the single uploaded `asset` file (filename, declared
/// content-type, bytes). Mirrors `dashboard::read_avatar_upload`'s field loop;
/// the declared MIME is advisory, since bunyip-api sniffs the real type from
/// the bytes.
async fn read_asset_upload(multipart: &mut Multipart) -> Result<(String, String, Vec<u8>), String> {
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => return Err("No image was selected.".into()),
            Err(e) => return Err(format!("Could not read upload: {e}")),
        };
        let is_asset = field.name() == Some("asset");
        let filename = field.file_name().unwrap_or("asset").to_string();
        let mime = field
            .content_type()
            .map(str::to_string)
            .unwrap_or_else(|| "application/octet-stream".to_string());
        // Always drain the field body before advancing to the next one.
        let bytes = match field.bytes().await {
            Ok(b) => b,
            Err(e) => return Err(format!("Could not read the image: {e}")),
        };
        if !is_asset {
            continue;
        }
        if bytes.is_empty() {
            return Err("The selected file is empty.".into());
        }
        if bytes.len() > MAX_ASSET_UPLOAD_BYTES {
            return Err("The image must be 2 MB or smaller.".into());
        }
        return Ok((filename, mime, bytes.to_vec()));
    }
}

/// Re-render the Branding page with an inline error above it, showing the
/// PERSISTED record: the failed write changed nothing, so anything else would
/// misreport the state.
async fn branding_error_page(
    st: &AppState,
    c: &crate::auth::AuthCtx,
    user: &crate::api::types::User,
    error: &str,
) -> Response {
    let data = crate::branding::admin_get(&st.api, c.forward.as_deref()).await;
    let reachable = data.is_ok();
    let cfg = data.ok();
    let content = html! {
        (error_box(error))
        (branding_content(cfg.as_ref(), reachable))
    };
    admin_response(c, user, "/admin/branding", "Branding", content)
}

/// POST /admin/branding/assets/{slot} - upload (or replace) one brand image.
///
/// A failure at either hop (an unreadable body here, a rejected image there)
/// re-renders the page with the cause above the form and writes nothing: the
/// api replaces a slot in one transaction, so a rejected upload leaves the
/// previous brand exactly as it was.
pub async fn branding_asset_upload(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(slot): Path<String>,
    mut multipart: Multipart,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !ASSET_SLOTS.iter().any(|s| s.slot == slot) {
        return branding_error_page(&st, &c, &user, "Unknown brand asset.").await;
    }

    let (filename, mime, bytes) = match read_asset_upload(&mut multipart).await {
        Ok(v) => v,
        Err(message) => return branding_error_page(&st, &c, &user, &message).await,
    };

    match crate::branding::admin_upload_asset(
        &st.api,
        c.forward.as_deref(),
        &slot,
        &filename,
        &mime,
        bytes,
    )
    .await
    {
        Ok(()) => redirect_cookies("/admin/branding", &c.set_cookies),
        // A rejected upload is a 4xx carrying the api's message, which passes
        // through `user_message` verbatim (BUNYIP-506 only collapses 5xx and
        // transport failures).
        Err(e) => branding_error_page(&st, &c, &user, &e.user_message()).await,
    }
}

/// POST /admin/branding/assets/{slot}/clear - remove one brand image.
pub async fn branding_asset_clear(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(slot): Path<String>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !ASSET_SLOTS.iter().any(|s| s.slot == slot) {
        return branding_error_page(&st, &c, &user, "Unknown brand asset.").await;
    }

    match crate::branding::admin_clear_asset(&st.api, c.forward.as_deref(), &slot).await {
        Ok(()) => redirect_cookies("/admin/branding", &c.set_cookies),
        Err(e) => branding_error_page(&st, &c, &user, &e.user_message()).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BUNYIP-560: every slot the page renders is a slot the api accepts, and
    /// every slot has an upload form, a preview and a way back to unset.
    #[test]
    fn every_asset_slot_uploads_previews_and_clears() {
        let filled = Branding {
            mark_version: "1".into(),
            favicon_version: "2".into(),
            mascot_version: "3".into(),
            ..Branding::default()
        };
        for s in ASSET_SLOTS {
            assert!(
                ["mark", "favicon", "mascot"].contains(&s.slot),
                "`{}` is not a slot the api accepts",
                s.slot
            );

            let empty = asset_card(s, &Branding::default()).into_string();
            assert!(
                empty.contains(&format!(r#"action="/admin/branding/assets/{}""#, s.slot)),
                "{} has no upload form: {empty}",
                s.slot
            );
            assert!(empty.contains(r#"type="file" name="asset""#), "{empty}");
            assert!(
                empty.contains(s.empty),
                "an unset slot says so rather than showing a broken image: {empty}"
            );
            assert!(
                !empty.contains("/clear"),
                "there is nothing to clear when the slot is unset: {empty}"
            );

            let set = asset_card(s, &filled).into_string();
            assert!(
                set.contains("<img src=\"/brand/"),
                "{} previews the current image: {set}",
                s.slot
            );
            assert!(
                set.contains(&format!(
                    r#"action="/admin/branding/assets/{}/clear""#,
                    s.slot
                )),
                "{} cannot be cleared: {set}",
                s.slot
            );
        }
    }

    /// BUNYIP-560: the palette is part of the same record and the same Save, and
    /// every field is sent every time so clearing one actually clears it.
    #[test]
    fn the_save_body_carries_the_palette_and_clears_by_omission_of_nothing() {
        let body = branding_update_body(&BrandingForm {
            brand_name: " Acme ".into(),
            tagline: String::new(),
            meta_description: String::new(),
            og_image_url: String::new(),
            theme_css: "  --skin-primary-500: #123456;  ".into(),
            theme_color_light: " #abcdef ".into(),
            theme_color_dark: String::new(),
        });
        assert_eq!(body["brand_name"], "Acme");
        assert_eq!(body["theme_css"], "--skin-primary-500: #123456;");
        assert_eq!(body["theme_color_light"], "#abcdef");
        assert_eq!(
            body["theme_color_dark"], "",
            "a cleared colour is sent as empty, not omitted: omission would leave the old value"
        );
    }

    /// The form renders what is stored, so an admin can see and edit the
    /// palette rather than guessing at it.
    #[test]
    fn the_form_renders_the_stored_palette() {
        let markup = branding_content(
            Some(&Branding {
                theme_css: "--skin-primary-500: #123456;".into(),
                theme_color_light: "#abcdef".into(),
                ..Branding::default()
            }),
            true,
        )
        .into_string();
        assert!(markup.contains("--skin-primary-500: #123456;"), "{markup}");
        assert!(markup.contains(r##"value="#abcdef""##), "{markup}");
        assert!(markup.contains(r#"name="theme_color_dark""#), "{markup}");
    }
}
