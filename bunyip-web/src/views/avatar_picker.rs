//! BUNYIP-408: reusable avatar picker component.
//!
//! One component, mounted anywhere an image upload is needed. The markup
//! ([`avatar_picker`]) is progressive-enhancement friendly: without JS it is a
//! plain multipart `<form>` (choose a file, submit) plus a remove form; with JS,
//! `assets/js/avatar-picker.js` takes over and delivers the rich behaviour - the circle
//! is the primary click/drop target, selection previews instantly, the image is
//! validated (magic-byte MIME + 2 MB cap) and downscaled to a 512px square on a
//! canvas before it ever leaves the browser, and the upload fires automatically
//! with a progress ring. Component styling lives in `input.css`
//! (`.avatar-picker*`); the controller is `assets/js/avatar-picker.js`, mounted
//! once from the base document head.
//!
//! Every avatar surface in the app renders a `[data-avatar-slot]` (see
//! `layout::avatar_badge`), so a successful upload/removal repaints the header
//! menu avatar too, with no full-page reload.

use maud::{html, Markup};

use crate::api::types::User;
use crate::views::ui::{button_class, icon};

/// Component CSS, mounted INLINE in the document head (see `layout::document`)
/// rather than compiled into `assets/styles.css`.
///
/// Why inline: `styles.css` is a separately-built, browser-cached file. A deploy
/// that ships fresh SSR HTML + inline JS but a stale/cached stylesheet would
/// leave every structural rule below undefined - the `absolute inset-0` fallback
/// initial then escaped its container and filled the whole card (BUNYIP-408 bug
/// report). Shipping these rules inline in the always-fresh SSR head removes the
/// stale-stylesheet failure mode entirely and needs no Tailwind rebuild. Keyed
/// on the theme tokens so light / dark / high-contrast all adapt. The markup
/// leans only on utilities that already exist in `styles.css`; everything novel
/// and structural lives here.
///
/// BUNYIP-554: split in two. `AVATAR_SLOT_CSS` is the one rule the shared shell
/// needs (the avatar image in the topbar / profile menu, on every page);
/// `AVATAR_PICKER_CSS` is the rest, which only `/settings` renders and which
/// therefore only that page ships.
pub const AVATAR_SLOT_CSS: &str = ".avatar-slot__img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;border-radius:9999px}";

/// The picker's own rules. Shipped by `layout::document_with_avatar_picker`
/// only, alongside `assets/js/avatar-picker.js`. See `AVATAR_SLOT_CSS`.
pub const AVATAR_PICKER_CSS: &str = r#".avatar-picker{display:flex;align-items:center;gap:1rem}
.avatar-picker__form{margin:0}
.avatar-picker__trigger{position:relative;display:inline-flex;align-items:center;justify-content:center;width:4rem;height:4rem;border-radius:9999px;cursor:pointer;flex:none}
.avatar-picker__input{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0 0 0 0);clip-path:inset(50%);white-space:nowrap;border:0}
.avatar-picker__circle{position:relative;width:100%;height:100%;border-radius:9999px;overflow:hidden;border:1px solid hsl(var(--border));background:hsl(var(--muted));display:flex;align-items:center;justify-content:center}
.avatar-picker__circle [data-avatar-initial]{user-select:none;-webkit-user-select:none}
.avatar-picker__overlay{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;border-radius:9999px;color:#fff;background:rgba(0,0,0,.55);font-size:.7rem;font-weight:600;opacity:0;transition:opacity .15s ease;pointer-events:none}
.avatar-picker__trigger:hover .avatar-picker__overlay,.avatar-picker__trigger:focus-within .avatar-picker__overlay,.avatar-picker.is-dragging .avatar-picker__overlay,.avatar-picker.is-uploading .avatar-picker__overlay{opacity:1}
.avatar-picker__trigger:focus-within .avatar-picker__circle{outline:2px solid var(--color-brand-primary-600);outline-offset:2px}
.avatar-picker.is-dragging .avatar-picker__circle{outline:2px dashed var(--color-brand-primary-500);outline-offset:2px;border-color:var(--color-brand-primary-500)}
.avatar-picker__progress{position:absolute;inset:-3px;border-radius:9999px;opacity:0;transition:opacity .15s ease;background:conic-gradient(var(--color-brand-primary-500) calc(var(--avatar-progress,0)*1%),transparent 0);-webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 3px));mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 3px));pointer-events:none}
.avatar-picker.is-uploading .avatar-picker__progress{opacity:1}
.avatar-picker.is-uploading .avatar-picker__trigger{pointer-events:none;cursor:default}
.avatar-picker__side{display:flex;flex-direction:column;gap:.25rem;min-width:0}
.avatar-picker__actions{display:flex;flex-wrap:wrap;gap:.5rem}
.avatar-picker__help{font-size:.75rem;color:hsl(var(--muted-foreground));margin:0}
.avatar-picker__error{font-size:.75rem;color:hsl(var(--destructive-text));margin:0;min-height:1rem}
.avatar-picker__enhanced{display:none}
.avatar-picker[data-enhanced] .avatar-picker__enhanced{display:inline-flex}
.avatar-picker[data-enhanced] .avatar-picker__nojs{display:none}"#;

/// Render the avatar picker for `user`. Reusable: it carries its own endpoints
/// and limits via `data-*` attributes, so the controller wires it with no
/// per-instance config. The letter fallback (initial over a reed/water gradient)
/// shows when no avatar is set.
pub fn avatar_picker(user: &User) -> Markup {
    let src = user.avatar_src();
    let initial = user.avatar_initial();
    let has = src.is_some();
    html! {
        div class="avatar-picker"
            data-avatar-picker
            data-upload-url="/settings/avatar"
            data-remove-url="/settings/avatar/remove"
            data-max-bytes="2097152"
            data-max-edge="512" {
            // No-JS baseline: a real multipart form. JS hides its submit button
            // (`.avatar-picker__nojs`) and drives the upload instead.
            form class="avatar-picker__form" method="post" action="/settings/avatar" enctype="multipart/form-data" {
                label class="avatar-picker__trigger" data-avatar-trigger {
                    input type="file" name="avatar"
                          accept="image/png,image/jpeg,image/webp,image/gif"
                          class="avatar-picker__input" data-avatar-input
                          aria-label="Upload a profile photo (PNG, JPEG, WebP, or GIF, up to 2 MB)"
                          aria-describedby="avatar-picker-help avatar-picker-error";
                    span class="avatar-picker__circle" data-avatar-slot data-initial=(initial) {
                        @if let Some(s) = &src {
                            img src=(s) alt="Your profile photo" class="avatar-slot__img" data-avatar-image;
                        }
                        // `h-full w-full` (not `absolute inset-0`) so the letter
                        // fallback can never escape its circle even if this
                        // component's CSS is somehow missing.
                        span data-avatar-initial aria-hidden="true"
                             class="flex h-full w-full items-center justify-center rounded-full bg-gradient-to-br from-primary to-indigo-500 text-white text-xl font-semibold"
                             style=[has.then_some("display:none")] {
                            (initial)
                        }
                    }
                    span class="avatar-picker__overlay" aria-hidden="true" {
                        (icon("upload", "h-5 w-5"))
                        span { "Change" }
                    }
                    span class="avatar-picker__progress" data-avatar-progress aria-hidden="true" {}
                }
                // No-JS submit (hidden once enhanced).
                button type="submit" class=(button_class("outline", "sm", "avatar-picker__nojs mt-2")) {
                    (icon("upload", "mr-2 h-4 w-4")) "Upload"
                }
            }
            div class="avatar-picker__side" {
                div class="avatar-picker__actions" {
                    // JS-enhanced trigger (opens the same dialog).
                    button type="button" class=(button_class("outline", "sm", "avatar-picker__enhanced")) data-avatar-change {
                        (icon("upload", "mr-2 h-4 w-4")) "Change photo"
                    }
                    // JS remove (confirm + delete without reload); hidden until
                    // an avatar exists.
                    button type="button"
                           class=(button_class("ghost", "sm", "avatar-picker__enhanced text-destructive-text hover:text-destructive-text"))
                           data-avatar-remove data-has-avatar=(if has { "1" } else { "0" }) {
                        (icon("trash", "mr-2 h-4 w-4")) "Remove photo"
                    }
                    // No-JS remove form (hidden once enhanced), only when set.
                    @if has {
                        form method="post" action="/settings/avatar/remove" class="avatar-picker__nojs" {
                            button type="submit" class=(button_class("ghost", "sm", "text-destructive-text hover:text-destructive-text")) {
                                (icon("trash", "mr-2 h-4 w-4")) "Remove photo"
                            }
                        }
                    }
                }
                p id="avatar-picker-help" class="avatar-picker__help" { "PNG, JPEG, WebP, or GIF up to 2 MB." }
                p id="avatar-picker-error" class="avatar-picker__error" data-avatar-error role="status" aria-live="polite" {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::avatar_picker;
    use crate::api::types::User;

    fn user(avatar: Option<&str>) -> User {
        serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "ada@example.com",
            "role": "subscriber",
            "email_verified": true,
            "two_factor_enabled": false,
            "membership_status": "none",
            "price_locked": false,
            "created_at": "2026-01-01T00:00:00Z",
            "membership_tier": "standard",
            "lifetime_member": false,
            "first_name": "Ada",
            "avatar_updated_at": avatar,
        }))
        .expect("valid user json")
    }

    #[test]
    fn renders_picker_scaffolding_and_endpoints() {
        let html = avatar_picker(&user(None)).into_string();
        assert!(html.contains("data-avatar-picker"));
        assert!(html.contains(r#"data-upload-url="/settings/avatar""#));
        assert!(html.contains(r#"data-remove-url="/settings/avatar/remove""#));
        // A live region for errors + a hidden focusable input for a11y.
        assert!(html.contains(r#"aria-live="polite""#));
        assert!(html.contains(r#"type="file""#));
    }

    #[test]
    fn empty_state_shows_initial_and_hides_no_remove() {
        // No avatar -> letter fallback visible, remove button flagged empty, and
        // no no-JS remove form (nothing to remove).
        let html = avatar_picker(&user(None)).into_string();
        assert!(html.contains(">A</span>") || html.contains(">A<"));
        assert!(html.contains(r#"data-has-avatar="0""#));
        assert!(!html.contains(r#"action="/settings/avatar/remove""#));
    }

    /// BUNYIP-554: the picker's stylesheet and controller no longer ship in the
    /// shared head, so a page that renders `avatar_picker` through the plain
    /// `dashboard_response` gets an unstyled, inert component. Every handler
    /// file that renders it must also reach for the picker-carrying response.
    #[test]
    fn every_handler_that_renders_the_picker_asks_for_its_assets() {
        let handlers = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers");
        let mut stack = vec![handlers];
        let (mut renderers, mut offenders) = (0, Vec::new());
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable handler dir") {
                let path = entry.expect("readable dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let body = std::fs::read_to_string(&path).expect("readable source file");
                if !body.contains("avatar_picker::avatar_picker(") {
                    continue;
                }
                renderers += 1;
                if !body.contains("dashboard_response_with_avatar_picker(") {
                    offenders.push(path.display().to_string());
                }
            }
        }
        assert_eq!(
            renderers, 1,
            "expected exactly one page to render the picker"
        );
        assert!(
            offenders.is_empty(),
            "these render the avatar picker without shipping its CSS / JS: {offenders:?}"
        );
    }

    #[test]
    fn set_state_renders_image_and_remove_affordances() {
        let html = avatar_picker(&user(Some("2026-07-28T10:00:00Z"))).into_string();
        assert!(html.contains("data-avatar-image"));
        assert!(html.contains("/me/avatar?v="));
        assert!(html.contains(r#"data-has-avatar="1""#));
        // No-JS remove form present when an avatar exists.
        assert!(html.contains(r#"action="/settings/avatar/remove""#));
    }
}
