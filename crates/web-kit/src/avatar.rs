//! Reusable avatar picker component (BUNYIP-408; lifted to web-kit in
//! BUNYIP-589).
//!
//! One component, mounted anywhere an image upload is needed. The markup
//! ([`avatar_picker`]) is progressive-enhancement friendly: without JS it is a
//! plain multipart `<form>` (choose a file, submit) plus a remove form; with JS,
//! the consumer's avatar-picker controller takes over and delivers the rich
//! behaviour - the circle is the primary click/drop target, selection previews
//! instantly, the image is validated (magic-byte MIME + 2 MB cap) and downscaled
//! to a 512px square on a canvas before it ever leaves the browser, and the
//! upload fires automatically with a progress ring.
//!
//! The component is consumer-agnostic: the caller passes the upload and remove
//! endpoints, and the avatar image src / letter fallback come from the [`Avatar`]
//! trait, so nothing here names a product route or user type.

use maud::{html, Markup};

use crate::ui::{button_class, icon};

/// The two values the picker needs from whatever the consumer calls a user: the
/// current avatar image URL (if any) and the letter fallback shown when none is
/// set.
pub trait Avatar {
    /// The avatar image URL, or `None` when no avatar is set.
    fn avatar_src(&self) -> Option<String>;
    /// The single-letter fallback (e.g. the uppercased first name initial).
    fn avatar_initial(&self) -> String;
}

/// Component CSS, mounted INLINE in the document head rather than compiled into
/// the built stylesheet.
///
/// Why inline: the built stylesheet is a separately-cached file. A deploy that
/// ships fresh SSR HTML + inline JS but a stale/cached stylesheet would leave
/// every structural rule below undefined - the `absolute inset-0` fallback
/// initial then escaped its container and filled the whole card (BUNYIP-408 bug
/// report). Shipping these rules inline in the always-fresh SSR head removes the
/// stale-stylesheet failure mode entirely and needs no stylesheet rebuild. Keyed
/// on the theme tokens so light / dark / high-contrast all adapt.
///
/// BUNYIP-554: split in two. `AVATAR_SLOT_CSS` is the one rule the shared shell
/// needs (the avatar image in the topbar / profile menu, on every page);
/// `AVATAR_PICKER_CSS` is the rest, which only the settings page renders and
/// which therefore only that page ships.
pub const AVATAR_SLOT_CSS: &str = ".avatar-slot__img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;border-radius:9999px}";

/// The picker's own rules. Shipped by the consumer's avatar-picker-carrying page
/// response only, alongside its controller. See `AVATAR_SLOT_CSS`.
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
/// (`upload_action` / `remove_action`) and limits via `data-*` attributes, so
/// the controller wires it with no per-instance config. The letter fallback
/// (initial over a gradient) shows when no avatar is set.
pub fn avatar_picker(user: &impl Avatar, upload_action: &str, remove_action: &str) -> Markup {
    let src = user.avatar_src();
    let initial = user.avatar_initial();
    let has = src.is_some();
    html! {
        div class="avatar-picker"
            data-avatar-picker
            data-upload-url=(upload_action)
            data-remove-url=(remove_action)
            data-max-bytes="2097152"
            data-max-edge="512" {
            // No-JS baseline: a real multipart form. JS hides its submit button
            // (`.avatar-picker__nojs`) and drives the upload instead.
            form class="avatar-picker__form" method="post" action=(upload_action) enctype="multipart/form-data" {
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
                        form method="post" action=(remove_action) class="avatar-picker__nojs" {
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
    use super::{avatar_picker, Avatar};

    struct TestUser {
        src: Option<String>,
        initial: String,
    }
    impl Avatar for TestUser {
        fn avatar_src(&self) -> Option<String> {
            self.src.clone()
        }
        fn avatar_initial(&self) -> String {
            self.initial.clone()
        }
    }
    fn user(avatar: Option<&str>) -> TestUser {
        TestUser {
            src: avatar.map(|_| "/me/avatar?v=2026-07-28T10:00:00Z".to_string()),
            initial: "A".to_string(),
        }
    }

    #[test]
    fn renders_picker_scaffolding_and_endpoints() {
        let html =
            avatar_picker(&user(None), "/settings/avatar", "/settings/avatar/remove").into_string();
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
        let html =
            avatar_picker(&user(None), "/settings/avatar", "/settings/avatar/remove").into_string();
        assert!(html.contains(">A</span>") || html.contains(">A<"));
        assert!(html.contains(r#"data-has-avatar="0""#));
        assert!(!html.contains(r#"action="/settings/avatar/remove""#));
    }

    #[test]
    fn set_state_renders_image_and_remove_affordances() {
        let html = avatar_picker(
            &user(Some("2026-07-28T10:00:00Z")),
            "/settings/avatar",
            "/settings/avatar/remove",
        )
        .into_string();
        assert!(html.contains("data-avatar-image"));
        assert!(html.contains("/me/avatar?v="));
        assert!(html.contains(r#"data-has-avatar="1""#));
        // No-JS remove form present when an avatar exists.
        assert!(html.contains(r#"action="/settings/avatar/remove""#));
    }
}
