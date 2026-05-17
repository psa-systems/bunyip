use dioxus::prelude::*;

use crate::routes::Route;

#[component]
pub fn NotFoundPage() -> Element {
    rsx! {
        div { class: "min-h-screen flex items-center justify-center px-6",
            div { class: "max-w-md text-center",
                p { class: "text-sm uppercase tracking-wide text-bunyip-reed-600 dark:text-bunyip-reed-300 font-semibold",
                    "404"
                }
                h1 { class: "mt-2 text-3xl font-bold",
                    "Page not found"
                }
                p { class: "mt-3 text-bunyip-reed-700 dark:text-bunyip-reed-200",
                    "Either it never existed or it's still being built."
                }
                Link { to: Route::LandingPage {}, class: "mt-6 inline-block px-4 py-2 rounded bg-bunyip-reed-700 text-white hover:bg-bunyip-reed-800",
                    "Go home"
                }
            }
        }
    }
}
