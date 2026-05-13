//! Floating feedback launcher. Mirrors the saas FeedbackLauncher pattern:
//! a tiny pill on the bottom-right that expands on hover and links to
//! `/feedback`. Hidden on `/feedback` and `/admin/*` (the feedback page
//! itself, and the admin viewer).

use dioxus::prelude::*;

// Rendered outside the Router (at App root) so we can't use `<Link>` —
// it would panic with "Link must have access to a parent router". Plain
// anchor with href is fine since /feedback is a top-level route.

#[component]
pub fn FeedbackLauncher() -> Element {
    // Don't show the launcher if we're already on /feedback or in /admin.
    let pathname = web_sys::window()
        .and_then(|w| w.location().pathname().ok())
        .unwrap_or_default();
    if pathname == "/feedback" || pathname.starts_with("/admin") {
        return rsx! {};
    }

    rsx! {
        div { class: "pointer-events-none fixed bottom-4 right-4 z-40 sm:bottom-6 sm:right-6",
            a {
                href: "/feedback",
                class: "pointer-events-auto group flex h-14 items-center overflow-hidden rounded-2xl border border-bunyip-reed-200 bg-white/90 text-bunyip-reed-700 shadow-xl backdrop-blur-md transition-all duration-300 hover:border-bunyip-reed-400 hover:bg-white",
                span { class: "relative inline-flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl",
                    span { class: "absolute inset-0 rounded-2xl bg-gradient-to-br from-bunyip-reed-100 to-bunyip-water-100 opacity-80" }
                    SmileIcon {}
                }
                span { class: "max-w-0 whitespace-nowrap pl-0 pr-0 text-sm font-medium text-bunyip-reed-900 opacity-0 transition-all duration-300 group-hover:max-w-[160px] group-hover:pl-3 group-hover:pr-4 group-hover:opacity-100",
                    "Have feedback?"
                }
            }
        }
    }
}

#[component]
fn SmileIcon() -> Element {
    rsx! {
        svg {
            class: "relative z-10 h-7 w-7 text-bunyip-reed-700",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            "stroke-width": "1.8",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            circle { cx: "12", cy: "12", r: "9" }
            path { d: "M8 14c1 1.3 2.4 2 4 2s3-0.7 4-2" }
            circle { cx: "9", cy: "10", r: "0.8", fill: "currentColor" }
            circle { cx: "15", cy: "10", r: "0.8", fill: "currentColor" }
            path { d: "M19 8h3 M20.5 6.5v3" }
        }
    }
}
