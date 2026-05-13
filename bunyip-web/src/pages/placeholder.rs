use dioxus::prelude::*;

use crate::routes::Route;

/// Catch-all "coming soon" placeholder for routes that Phases 3-6 will wire up.
/// Renders the segments the user navigated to so it's clear what was expected.
#[component]
pub fn PlaceholderPage(segments: Vec<String>) -> Element {
    let path = format!("/{}", segments.join("/"));
    rsx! {
        div { class: "min-h-screen flex items-center justify-center px-6",
            div { class: "max-w-lg text-center",
                p { class: "text-sm uppercase tracking-wide text-bunyip-reed-600 dark:text-bunyip-reed-300 font-semibold",
                    "Coming soon"
                }
                h1 { class: "mt-2 text-3xl font-bold",
                    "{path}"
                }
                p { class: "mt-4 text-bunyip-reed-700 dark:text-bunyip-reed-200",
                    "This route is scaffolded and will be wired up in a later phase. See ",
                    span { class: "font-mono",
                        "For AI/bunyip-progress.md"
                    },
                    " for status."
                }
                div { class: "mt-8",
                    Link { to: Route::LandingPage {}, class: "px-4 py-2 rounded border border-bunyip-reed-300 hover:bg-bunyip-reed-100",
                        "Back to home"
                    }
                }
            }
        }
    }
}
