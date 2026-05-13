use dioxus::prelude::*;

use crate::routes::Route;

/// Top-of-page nav shown on public marketing pages (landing, pricing).
#[component]
pub fn PublicNav() -> Element {
    rsx! {
        header { class: "px-6 py-4 backdrop-blur supports-backdrop-blur:bg-white/70 border-b border-bunyip-reed-100/50",
            div { class: "max-w-6xl mx-auto flex items-center justify-between",
                Link { to: Route::LandingPage {}, class: "flex items-center gap-2 group",
                    BrandMark {}
                    span { class: "text-xl font-semibold tracking-tight text-bunyip-reed-900 group-hover:text-bunyip-reed-700 transition-colors",
                        "Bunyip"
                    }
                }
                nav { class: "flex items-center gap-1 text-sm",
                    Link {
                        to: Route::PricingPage {},
                        class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 hover:text-bunyip-reed-900 hover:bg-bunyip-reed-50 transition-colors",
                        "Pricing"
                    }
                    Link {
                        to: Route::LoginPage {},
                        class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 hover:text-bunyip-reed-900 hover:bg-bunyip-reed-50 transition-colors",
                        "Sign in"
                    }
                    Link {
                        to: Route::SignupPage {},
                        class: "ml-1 px-3.5 py-1.5 rounded-md bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 shadow-sm transition-colors",
                        "Sign up"
                    }
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
            class: "w-7 h-7 text-bunyip-reed-700",
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
pub fn AuthShell(title: &'static str, subtitle: &'static str, children: Element) -> Element {
    rsx! {
        div { class: "min-h-screen flex flex-col bg-gradient-to-b from-bunyip-reed-50 to-white",
            header { class: "px-6 py-4",
                div { class: "max-w-6xl mx-auto",
                    Link { to: Route::LandingPage {}, class: "flex items-center gap-2 group w-fit",
                        BrandMark {}
                        span { class: "text-xl font-semibold tracking-tight text-bunyip-reed-900 group-hover:text-bunyip-reed-700 transition-colors",
                            "Bunyip"
                        }
                    }
                }
            }
            main { class: "flex-1 flex items-start justify-center px-6 py-10",
                div { class: "w-full max-w-md",
                    h1 { class: "text-3xl font-bold tracking-tight text-bunyip-reed-900",
                        "{title}"
                    }
                    p { class: "mt-2 text-sm text-bunyip-reed-700",
                        "{subtitle}"
                    }
                    div { class: "mt-8 p-7 rounded-2xl border border-bunyip-reed-100 bg-white shadow-sm",
                        {children}
                    }
                }
            }
        }
    }
}

/// Authenticated app shell: header with org badge + sign-out, page body padded.
#[component]
pub fn AppShell(title: String, children: Element) -> Element {
    use crate::api;
    use crate::stores::auth::{refresh_auth, use_auth, AuthState};
    use crate::stores::toast::use_toast;

    let auth = use_auth();
    let state = auth.read().clone();
    let toast = use_toast();
    let nav = navigator();

    let sign_out = move |_| {
        spawn(async move {
            let _ = api::auth::logout().await;
            refresh_auth(auth).await;
            toast.info("Signed out.");
            nav.replace(Route::LoginPage {});
        });
    };

    let (user_name, org_name) = match &state {
        AuthState::SignedIn(me) => (
            me.user.name.clone(),
            me.memberships.first().map(|m| m.org.name.clone()).unwrap_or_else(|| "Personal".to_string()),
        ),
        _ => (String::new(), String::new()),
    };

    rsx! {
        div { class: "min-h-screen bg-bunyip-reed-50",
            header { class: "px-6 py-3 bg-white border-b border-bunyip-reed-100 sticky top-0 z-10",
                div { class: "max-w-7xl mx-auto flex items-center justify-between",
                    div { class: "flex items-center gap-4",
                        Link { to: Route::DashboardPage {}, class: "flex items-center gap-2",
                            BrandMark {}
                            span { class: "text-lg font-semibold text-bunyip-reed-900", "Bunyip" }
                        }
                        if !org_name.is_empty() {
                            span { class: "h-5 w-px bg-bunyip-reed-200" }
                            div { class: "flex items-center gap-2 px-3 py-1.5 rounded-md bg-bunyip-reed-50",
                                span { class: "w-2 h-2 rounded-full bg-bunyip-reed-600" }
                                span { class: "text-sm font-medium text-bunyip-reed-900", "{org_name}" }
                            }
                        }
                    }
                    nav { class: "flex items-center gap-2 text-sm",
                        Link {
                            to: Route::OrgListPage {},
                            class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 hover:bg-bunyip-reed-50",
                            "Orgs"
                        }
                        if !user_name.is_empty() {
                            span { class: "px-2 text-bunyip-reed-700", "{user_name}" }
                            button {
                                class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 hover:text-bunyip-reed-900 hover:bg-bunyip-reed-50 transition-colors",
                                onclick: sign_out,
                                "Sign out"
                            }
                        }
                    }
                }
            }
            main { class: "px-6 py-10",
                if !title.is_empty() {
                    div { class: "max-w-7xl mx-auto",
                        // Title is set in the page itself for now - this slot is
                        // available for future breadcrumbs / utility nav.
                    }
                }
                {children}
            }
        }
    }
}

/// Header used by authenticated app pages.
#[component]
pub fn AppHeader(current_org: &'static str) -> Element {
    rsx! {
        header { class: "px-6 py-3 bg-white border-b border-bunyip-reed-100 sticky top-0 z-10",
            div { class: "max-w-7xl mx-auto flex items-center justify-between",
                div { class: "flex items-center gap-4",
                    Link { to: Route::DashboardPage {}, class: "flex items-center gap-2 group",
                        BrandMark {}
                        span { class: "text-lg font-semibold text-bunyip-reed-900",
                            "Bunyip"
                        }
                    }
                    span { class: "h-5 w-px bg-bunyip-reed-200" }
                    button { class: "flex items-center gap-2 px-3 py-1.5 rounded-md hover:bg-bunyip-reed-50 transition-colors",
                        span { class: "w-2 h-2 rounded-full bg-bunyip-reed-600" }
                        span { class: "text-sm font-medium text-bunyip-reed-900",
                            "{current_org}"
                        }
                        svg {
                            class: "w-3.5 h-3.5 text-bunyip-reed-600",
                            view_box: "0 0 12 12",
                            fill: "currentColor",
                            path { d: "M6 8L2.5 4h7L6 8z" }
                        }
                    }
                }
                nav { class: "flex items-center gap-1 text-sm",
                    button { class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 hover:text-bunyip-reed-900 hover:bg-bunyip-reed-50 transition-colors",
                        "Settings"
                    }
                    button { class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 hover:text-bunyip-reed-900 hover:bg-bunyip-reed-50 transition-colors",
                        "Sign out"
                    }
                }
            }
        }
    }
}
