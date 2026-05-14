use dioxus::prelude::*;

use crate::components::theme::ThemeToggle;
use crate::routes::Route;

/// Top-of-page nav shown on public marketing pages (landing, pricing).
#[component]
pub fn PublicNav() -> Element {
    rsx! {
        header { class: "px-6 py-4 backdrop-blur supports-backdrop-blur:bg-white/70 dark:supports-backdrop-blur:bg-bunyip-reed-900/70 border-b border-bunyip-reed-100/50 dark:border-bunyip-reed-800/60",
            div { class: "max-w-6xl mx-auto flex items-center justify-between",
                Link { to: Route::LandingPage {}, class: "flex items-center gap-2 group",
                    BrandMark {}
                    span { class: "text-xl font-semibold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50 group-hover:text-bunyip-reed-700 dark:group-hover:text-bunyip-reed-200 transition-colors",
                        "Bunyip"
                    }
                }
                nav { class: "flex items-center gap-1 text-sm",
                    Link {
                        to: Route::PricingPage {},
                        class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:text-bunyip-reed-900 hover:bg-bunyip-reed-50 dark:hover:text-white dark:hover:bg-bunyip-reed-800 transition-colors",
                        "Pricing"
                    }
                    Link {
                        to: Route::LoginPage {},
                        class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:text-bunyip-reed-900 hover:bg-bunyip-reed-50 dark:hover:text-white dark:hover:bg-bunyip-reed-800 transition-colors",
                        "Sign in"
                    }
                    Link {
                        to: Route::SignupPage {},
                        class: "ml-1 px-3.5 py-1.5 rounded-md bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 shadow-sm transition-colors",
                        "Sign up"
                    }
                    ThemeToggle {}
                }
            }
        }
    }
}

/// Small reed-and-eyes mark used in navs and the footer.
#[component]
pub fn BrandMark() -> Element {
    rsx! {
        svg {
            // Dark variant added so the reed icon doesn't disappear
            // against dark backgrounds in AuthShell / AppShell.
            class: "w-7 h-7 text-bunyip-reed-700 dark:text-bunyip-reed-200",
            view_box: "0 0 32 32",
            fill: "none",
            path {
                stroke: "currentColor",
                "stroke-width": "2",
                "stroke-linecap": "round",
                d: "M8 28 V14 M16 28 V8 M24 28 V14",
            }
            circle { cx: "12.5", cy: "18", r: "2", fill: "currentColor" }
            circle { cx: "19.5", cy: "18", r: "2", fill: "currentColor" }
        }
    }
}

/// Centered shell for auth pages (signup, login, etc.).
#[component]
pub fn AuthShell(title: String, subtitle: String, children: Element) -> Element {
    rsx! {
        div { class: "min-h-screen flex flex-col bg-gradient-to-b from-bunyip-reed-50 to-white dark:from-bunyip-reed-900 dark:to-bunyip-reed-900",
            header { class: "px-6 py-4 flex items-center justify-between",
                div { class: "max-w-6xl mx-auto w-full flex items-center justify-between",
                    Link { to: Route::LandingPage {}, class: "flex items-center gap-2 group w-fit",
                        BrandMark {}
                        span { class: "text-xl font-semibold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50 group-hover:text-bunyip-reed-700 dark:group-hover:text-bunyip-reed-200 transition-colors",
                            "Bunyip"
                        }
                    }
                    ThemeToggle {}
                }
            }
            main { class: "flex-1 flex items-start justify-center px-6 py-10",
                div { class: "w-full max-w-md",
                    h1 { class: "text-3xl font-bold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50",
                        "{title}"
                    }
                    p { class: "mt-2 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-300",
                        "{subtitle}"
                    }
                    div { class: "mt-8 p-7 rounded-2xl border border-bunyip-reed-100 dark:border-bunyip-reed-800 bg-white dark:bg-bunyip-reed-800 shadow-sm",
                        {children}
                    }
                }
            }
        }
    }
}

/// Authenticated app shell: header with org badge + sign-out, page body padded.
///
/// `back_to` (optional): renders a "← Back" link in the title bar that
/// navigates to the supplied parent route. Use it on nested pages
/// (everything under /settings/* and /admin/*) so users aren't trapped
/// when entering a sub-page directly. The link is a real `<Link>`, so
/// browser back/forward keeps working.
#[component]
pub fn AppShell(
    title: String,
    children: Element,
    #[props(default = None)] back_to: Option<Route>,
    #[props(default = String::new())] back_label: String,
) -> Element {
    use crate::stores::auth::{use_auth, AuthState};

    let auth = use_auth();
    let state = auth.read().clone();
    let nav = navigator();

    // All sign-out paths converge on /logout (pages/logout.rs) so the
    // OP cookie + localStorage tokens + auth signal die in one place.
    let sign_out = move |_| {
        nav.replace(Route::LogoutPage {});
    };

    let (user_name, org_name) = match &state {
        AuthState::SignedIn(me) => (
            me.user.name.clone(),
            me.memberships
                .first()
                .map(|m| m.org.name.clone())
                .unwrap_or_else(|| "Personal".to_string()),
        ),
        _ => (String::new(), String::new()),
    };

    rsx! {
        div { class: "min-h-screen bg-bunyip-reed-50 dark:bg-bunyip-reed-900",
            header { class: "px-6 py-3 bg-white dark:bg-bunyip-reed-800 border-b border-bunyip-reed-100 dark:border-bunyip-reed-700 sticky top-0 z-10",
                div { class: "max-w-7xl mx-auto flex items-center justify-between",
                    div { class: "flex items-center gap-4",
                        Link { to: Route::DashboardPage {}, class: "flex items-center gap-2",
                            BrandMark {}
                            span { class: "text-lg font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50", "Bunyip" }
                        }
                        if !org_name.is_empty() {
                            span { class: "h-5 w-px bg-bunyip-reed-200 dark:bg-bunyip-reed-700" }
                            div { class: "flex items-center gap-2 px-3 py-1.5 rounded-md bg-bunyip-reed-50 dark:bg-bunyip-reed-900",
                                span { class: "w-2 h-2 rounded-full bg-bunyip-reed-600 dark:bg-bunyip-reed-400" }
                                span { class: "text-sm font-medium text-bunyip-reed-900 dark:text-bunyip-reed-100", "{org_name}" }
                            }
                        }
                    }
                    nav { class: "flex items-center gap-2 text-sm",
                        Link {
                            to: Route::SettingsPage {},
                            class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                            "Settings"
                        }
                        Link {
                            to: Route::OrgListPage {},
                            class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                            "Orgs"
                        }
                        if !user_name.is_empty() {
                            span { class: "px-2 text-bunyip-reed-700 dark:text-bunyip-reed-200", "{user_name}" }
                            button {
                                class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:text-bunyip-reed-900 hover:bg-bunyip-reed-50 dark:hover:text-white dark:hover:bg-bunyip-reed-900 transition-colors",
                                onclick: sign_out,
                                "Sign out"
                            }
                        }
                        ThemeToggle {}
                    }
                }
            }
            main { class: "px-6 py-10",
                if let Some(parent) = back_to.clone() {
                    div { class: "max-w-7xl mx-auto mb-4",
                        Link {
                            to: parent,
                            class: "inline-flex items-center gap-1 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:text-bunyip-reed-900 dark:hover:text-white hover:underline focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600 dark:focus:ring-bunyip-reed-400 rounded",
                            aria_label: if back_label.is_empty() { "Back".to_string() } else { format!("Back to {back_label}") },
                            span { aria_hidden: "true", "←" }
                            if !back_label.is_empty() {
                                span { "Back to {back_label}" }
                            } else {
                                span { "Back" }
                            }
                        }
                    }
                }
                if !title.is_empty() {
                    // Title slot reserved for future breadcrumbs / utility nav.
                    div { class: "sr-only", "{title}" }
                }
                {children}
            }
        }
    }
}
