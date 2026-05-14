//! Reactive password rule checklist. Mirrors the server policy in
//! `mokosh-auth-core::policy::validate_password_strength` so users can
//! see which rule is failing before they submit. Server-side validation
//! is still the source of truth; this is a UX wrapper.

use dioxus::prelude::*;

/// Server policy: 12-128 chars, at least one upper, lower, digit, and
/// symbol, must not equal the email local-part.
const MIN_PASSWORD_LEN: usize = 12;

/// One rule and whether the supplied (password, email) pair satisfies it.
fn evaluate(password: &str, email: &str) -> [(&'static str, bool); 6] {
    let local_part = email.split('@').next().unwrap_or("");
    [
        ("At least 12 characters", password.len() >= MIN_PASSWORD_LEN),
        (
            "An uppercase letter (A-Z)",
            password.chars().any(|c| c.is_ascii_uppercase()),
        ),
        (
            "A lowercase letter (a-z)",
            password.chars().any(|c| c.is_ascii_lowercase()),
        ),
        (
            "A number (0-9)",
            password.chars().any(|c| c.is_ascii_digit()),
        ),
        (
            "A symbol (e.g. ! @ # $)",
            password.chars().any(|c| !c.is_ascii_alphanumeric()),
        ),
        (
            "Different from the email username",
            !password.is_empty()
                && !local_part.is_empty()
                && !password.eq_ignore_ascii_case(local_part),
        ),
    ]
}

/// True iff the password satisfies every server-side rule. Callers can
/// gate submit-button enablement on this without duplicating the rules.
pub fn password_meets_policy(password: &str, email: &str) -> bool {
    evaluate(password, email).iter().all(|(_, ok)| *ok)
}

#[component]
pub fn PasswordChecklist(password: String, email: String) -> Element {
    let rules = evaluate(&password, &email);
    rsx! {
        ul { class: "mt-2 space-y-1 text-xs",
            for (label, ok) in rules.iter() {
                li { class: "flex items-center gap-2",
                    if *ok {
                        // Green check
                        svg {
                            class: "w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0",
                            view_box: "0 0 16 16",
                            fill: "none",
                            path {
                                stroke: "currentColor",
                                "stroke-width": "2",
                                "stroke-linecap": "round",
                                "stroke-linejoin": "round",
                                d: "M3 8.5l3.5 3.5L13 5",
                            }
                        }
                        span { class: "text-emerald-700 dark:text-emerald-300", "{label}" }
                    } else {
                        // Neutral circle
                        svg {
                            class: "w-3.5 h-3.5 text-bunyip-reed-400 dark:text-bunyip-reed-500 shrink-0",
                            view_box: "0 0 16 16",
                            fill: "none",
                            circle {
                                cx: "8",
                                cy: "8",
                                r: "5",
                                stroke: "currentColor",
                                "stroke-width": "2",
                            }
                        }
                        span { class: "text-bunyip-reed-600 dark:text-bunyip-reed-300", "{label}" }
                    }
                }
            }
        }
    }
}
