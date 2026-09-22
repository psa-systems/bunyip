//! The per-field inline-error a11y pattern (BUNYIP-541), named and extracted
//! here (BUNYIP-813) so a future form with more than one required field wires
//! it once through this helper rather than copy-pasting the feedback form's
//! block a third time. Themed inline errors read `aria-invalid` /
//! `aria-describedby` / `aria-required` instead of relying on the browser's
//! unthemed, inconsistent-across-browsers native validation bubbles, which is
//! why every such form also renders its `<form>` with `novalidate`.
//!
//! `bunyip-web/src/views/password.rs`'s `data-pw-guard` idiom is the
//! INTENTIONAL lighter second tier for a form with a single guard condition
//! (a password re-entry, not a set of independently required fields): one
//! `role="alert"` message node with a submit-cancel guard, no per-field
//! wiring. It is not an ad hoc pattern awaiting this helper; the two are
//! meant to coexist. A new form with more than one required field should use
//! this module; a new form with a single guard condition may reach for
//! `password.rs`'s guard instead.

use maud::{html, Markup};

/// `"true"` / `"false"` for an `aria-invalid` attribute. Rendering the literal
/// value (not a valueless boolean attribute) lets an `aria-[invalid=true]:`
/// Tailwind variant paint the invalid-state border, and lets client-side JS
/// flip it in place.
pub fn aria_invalid(is_invalid: bool) -> &'static str {
    if is_invalid {
        "true"
    } else {
        "false"
    }
}

/// The shared class for a text field, plus the invalid-state border/ring
/// driven by `aria-invalid="true"`, so marking a field invalid is a single
/// attribute flip on both the server redraw and the client path. `base` is
/// the caller's own input class (e.g. `dashboard_input()`); `extra` is any
/// additional class the caller's field needs.
pub fn field_invalid_class(base: &str, extra: &str) -> String {
    format!(
        "{base} aria-[invalid=true]:border-destructive aria-[invalid=true]:ring-1 aria-[invalid=true]:ring-destructive {extra}"
    )
}

/// The inline error slot rendered under a field. It always exists (so the
/// input's `aria-describedby` target is real and client-side JS has a stable
/// node to fill), and is hidden until it carries a message. `data-field-error`
/// is the one marker name every caller shares (maud attribute names must be
/// static, so it cannot be parameterized per form); a caller's own script
/// scopes its `querySelector` to its own `<form>`, so sharing the marker name
/// across forms causes no collision.
pub fn field_error_slot(field: &str, msg: Option<&str>) -> Markup {
    let hidden = if msg.is_some() { "" } else { " hidden" };
    html! {
        p id=(format!("{field}-error")) data-field-error=(field) role="alert"
          class={ "mt-1 text-sm text-destructive-text" (hidden) } {
            @if let Some(m) = msg { (m) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aria_invalid_renders_the_literal_string() {
        assert_eq!(aria_invalid(true), "true");
        assert_eq!(aria_invalid(false), "false");
    }

    #[test]
    fn field_invalid_class_carries_the_base_and_the_invalid_state_variant() {
        let class = field_invalid_class("base-input", "extra-class");
        assert!(class.contains("base-input"));
        assert!(class.contains("extra-class"));
        assert!(class.contains("aria-[invalid=true]:border-destructive"));
    }

    #[test]
    fn field_error_slot_is_present_but_hidden_with_no_message() {
        let html = field_error_slot("name", None).into_string();
        assert!(html.contains(r#"id="name-error""#));
        assert!(html.contains(r#"data-field-error="name""#));
        assert!(html.contains(r#"role="alert""#));
        assert!(html.contains("hidden"));
    }

    #[test]
    fn field_error_slot_shows_the_message_and_drops_hidden() {
        let html = field_error_slot("email", Some("Email must contain an @")).into_string();
        assert!(html.contains("Email must contain an @"));
        assert!(!html.contains("hidden"));
    }
}
