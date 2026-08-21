//! The password input every form shares: an inline show/hide eye toggle
//! (BUNYIP-282) and the submit guard that stops a validation failure wiping
//! what the user typed (BUNYIP-575).
//!
//! Both halves are driven by `assets/js/password-field.js`, which is loaded by
//! `script()` and is inert on a page that renders neither marker. The live
//! per-rule indicators and the HaveIBeenPwned lookup stay in the separate
//! `assets/js/password.js`, so a form can take the toggle and the guard without
//! also taking a submit button gated on an external service.
//!
//! Why the guard exists: a rejected password change answers with a redirect,
//! and a redirect necessarily re-renders every `type=password` input empty
//! (a server-known password is never written back into HTML). So the only way
//! to keep the typed characters through a failure the browser can evaluate
//! itself is to not make the round trip. `handlers::password_ok` stays the
//! backstop: with JS off the form posts exactly as it did before.

use maud::{html, Markup};

use crate::handlers::dashboard_input;
use crate::views::layout::asset;
use crate::views::ui::icon;

/// Which password an input holds. Decides the `autocomplete` hint and, for the
/// new/confirm pair, the marker `assets/js/password-field.js` looks for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PwRole {
    /// The existing password, re-entered to confirm identity.
    Current,
    /// The password being chosen.
    New,
    /// The re-typed copy of the password being chosen.
    Confirm,
}

/// BUNYIP-554: both eye states, pre-rendered. `input.css` shows exactly one per
/// the button's `aria-pressed`, so the script never builds markup - SVG
/// generation stays in Rust and the script only flips the ARIA state.
fn toggle_glyphs() -> Markup {
    html! {
        span data-pw-icon="eye" aria-hidden="true" { (icon("eye", "h-4 w-4")) }
        span data-pw-icon="eye-off" aria-hidden="true" { (icon("eye-off", "h-4 w-4")) }
    }
}

/// A labelled password input with the inline show/hide eye toggle.
///
/// Default state is hidden (`type=password`, eye glyph, `aria-pressed=false`,
/// `aria-label="Show password"`); the script flips `type`, `aria-pressed` and
/// `aria-label` on click. The `pr-10` padding keeps the typed text from running
/// under the button. `id` and `name` are separate because the dashboard form
/// namespaces its ids (`password-current_password`) while posting the plain
/// field name.
pub fn password_field(id: &str, name: &str, label: &str, role: PwRole, autofocus: bool) -> Markup {
    let input_class = format!("{} pr-10", dashboard_input());
    let autocomplete = match role {
        PwRole::Current => "current-password",
        PwRole::New | PwRole::Confirm => "new-password",
    };
    html! {
        div class="space-y-2" {
            label for=(id) class="text-sm font-medium leading-none" { (label) }
            div class="relative" {
                input id=(id) name=(name) type="password" autocomplete=(autocomplete)
                    autofocus[autofocus]
                    data-pw-new[role == PwRole::New]
                    data-pw-confirm[role == PwRole::Confirm]
                    class=(input_class);
                button type="button"
                    data-pw-toggle=(id)
                    aria-label="Show password"
                    aria-pressed="false"
                    class="absolute right-2 top-1/2 -translate-y-1/2 inline-flex items-center justify-center w-7 h-7 rounded text-muted-foreground hover:text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring" {
                    (toggle_glyphs())
                }
            }
        }
    }
}

/// Where the guard writes the rule the typed password broke. Rendered empty and
/// hidden; the script fills it, reveals it, and clears it again on the next
/// keystroke. `role=alert` so the message is announced, not just painted.
pub fn guard_message() -> Markup {
    html! { p data-pw-guard-msg role="alert" hidden class="text-sm text-destructive-text" {} }
}

/// The toggle + guard controller. Separate from `password.js` so a form can
/// take these two behaviours alone.
pub fn script() -> Markup {
    html! { script src=(asset("/assets/js/password-field.js")) defer {} }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTROLLER: &str = include_str!("../../assets/js/password-field.js");

    /// Every marker the markup emits has to be the one the controller queries:
    /// a rename on either side silently turns the toggle or the guard off, and
    /// a dead guard is invisible (the form just wipes again).
    #[test]
    fn the_controller_reads_every_marker_the_markup_emits() {
        let field =
            password_field("new_password", "new_password", "New", PwRole::New, false).into_string();
        let confirm =
            password_field("confirm", "confirm", "Confirm", PwRole::Confirm, false).into_string();
        assert!(
            field.contains(r#"data-pw-toggle="new_password""#),
            "{field}"
        );
        assert!(field.contains("data-pw-new"), "{field}");
        assert!(confirm.contains("data-pw-confirm"), "{confirm}");
        assert!(guard_message().into_string().contains("data-pw-guard-msg"));
        for marker in [
            "[data-pw-toggle]",
            "form[data-pw-guard]",
            "[data-pw-new]",
            "[data-pw-confirm]",
            "[data-pw-guard-msg]",
        ] {
            assert!(
                CONTROLLER.contains(marker),
                "assets/js/password-field.js no longer queries {marker}"
            );
        }
    }

    /// BUNYIP-575: the guard's whole job is to stop the submit that wipes the
    /// form. Without `preventDefault` it renders a message and posts anyway.
    #[test]
    fn the_guard_blocks_the_wiping_submit() {
        assert!(
            CONTROLLER.contains("preventDefault"),
            "the [data-pw-guard] submit handler must cancel the submit, else the \
             failed POST redirects and clears every password input"
        );
    }

    /// A password the user cannot reveal is a password they cannot check, which
    /// is the half of BUNYIP-575 that drives weaker choices.
    #[test]
    fn every_role_renders_a_reveal_toggle() {
        for role in [PwRole::Current, PwRole::New, PwRole::Confirm] {
            let html = password_field("f", "f", "Field", role, false).into_string();
            assert!(html.contains("data-pw-toggle=\"f\""), "{html}");
            assert!(html.contains(r#"aria-label="Show password""#), "{html}");
            assert!(html.contains(r#"type="password""#), "{html}");
        }
    }
}
