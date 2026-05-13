use dioxus::prelude::*;

use crate::api;
use crate::api::types::MeResponse;
use crate::components::layout::BrandMark;
use crate::components::theme::ThemeToggle;
use crate::routes::Route;
use crate::stores::auth::{refresh_auth, use_auth, AuthState};
use crate::stores::toast::use_toast;

#[component]
pub fn DashboardPage() -> Element {
    let auth = use_auth();
    let state = auth.read().clone();

    match state {
        AuthState::Loading => rsx! { Splash { message: "Loading your dashboard…" } },
        AuthState::SignedOut => rsx! { SignedOutNotice {} },
        AuthState::SignedIn(me) => rsx! { Authenticated { me: me } },
    }
}

#[component]
fn Splash(message: &'static str) -> Element {
    rsx! {
        div { class: "min-h-screen flex items-center justify-center text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
            "{message}"
        }
    }
}

#[component]
fn SignedOutNotice() -> Element {
    rsx! {
        div { class: "min-h-screen flex items-center justify-center px-6",
            div { class: "max-w-md text-center",
                h1 { class: "text-2xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50", "You're signed out" }
                p { class: "mt-2 text-bunyip-reed-700 dark:text-bunyip-reed-200", "Sign in to see your dashboard." }
                Link {
                    to: Route::LoginPage {},
                    class: "mt-6 inline-block px-4 py-2 rounded bg-bunyip-reed-700 text-white hover:bg-bunyip-reed-800",
                    "Go to sign in"
                }
            }
        }
    }
}

#[component]
fn Authenticated(me: MeResponse) -> Element {
    let primary_org = me.memberships.first().cloned();
    let org_name = primary_org
        .as_ref()
        .map(|m| m.org.name.clone())
        .unwrap_or_else(|| "Personal".to_string());

    rsx! {
        div { class: "min-h-screen flex flex-col bg-bunyip-reed-50 dark:bg-bunyip-reed-900",
            DashboardHeader { user_name: me.user.name.clone(), org_name: org_name.clone() }

            main { class: "flex-1 px-6 py-10",
                div { class: "max-w-6xl mx-auto",
                    div { class: "rounded-2xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-gradient-to-br from-white via-bunyip-reed-50 to-bunyip-reed-100 dark:from-bunyip-reed-800 dark:via-bunyip-reed-800 dark:to-bunyip-reed-700 p-8 md:p-10 shadow-sm",
                        div { class: "flex flex-col md:flex-row gap-6 md:items-center md:justify-between",
                            div {
                                p { class: "text-sm uppercase tracking-wide text-bunyip-reed-600 dark:text-bunyip-reed-300 font-semibold",
                                    "Welcome back, {me.user.name}"
                                }
                                h2 { class: "mt-2 text-3xl font-bold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50",
                                    "Bunyip handles the business. Mokosh does the work."
                                }
                                p { class: "mt-3 text-bunyip-reed-700 dark:text-bunyip-reed-200 max-w-2xl",
                                    "Account, billing, members, and identity live here. Tickets, calendar, and contacts live in Mokosh."
                                }
                            }
                            div { class: "flex flex-wrap gap-3",
                                a {
                                    class: "px-5 py-2.5 rounded-lg bg-bunyip-reed-700 text-white font-medium shadow-sm hover:bg-bunyip-reed-800 transition-colors whitespace-nowrap",
                                    href: "https://msp.a8n.systems",
                                    "Open Mokosh →"
                                }
                                {
                                    let invite_target: Option<String> = primary_org.as_ref().map(|m| m.org.slug.clone());
                                    rsx! {
                                        if let Some(slug) = invite_target {
                                            Link {
                                                to: Route::OrgMembersPage { slug: slug.clone() },
                                                class: "px-5 py-2.5 rounded-lg border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-bunyip-reed-800 dark:text-bunyip-reed-100 hover:bg-bunyip-reed-100 dark:hover:bg-bunyip-reed-700 transition-colors",
                                                "Invite a teammate"
                                            }
                                        } else {
                                            Link {
                                                to: Route::OrgListPage {},
                                                class: "px-5 py-2.5 rounded-lg border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-bunyip-reed-800 dark:text-bunyip-reed-100 hover:bg-bunyip-reed-100 dark:hover:bg-bunyip-reed-700 transition-colors",
                                                "Manage orgs"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    div { class: "mt-6 grid md:grid-cols-3 gap-4",
                        StatCard {
                            label: "Email",
                            value: me.user.email.clone(),
                            sub: if me.user.email_verified_at.is_some() { "Verified".to_string() } else { "Pending verification".to_string() },
                            accent: "reed",
                        }
                        StatCard {
                            label: "Organizations",
                            value: me.memberships.len().to_string(),
                            sub: org_name.clone(),
                            accent: "water",
                        }
                        StatCard {
                            label: "MFA",
                            value: if me.user.mfa_enabled { "Enabled".to_string() } else { "Off".to_string() },
                            sub: if me.user.mfa_enabled { "Sign-ins require a code".to_string() } else { "Add TOTP from Settings".to_string() },
                            accent: "reed",
                        }
                    }

                    if !me.memberships.is_empty() {
                        div { class: "mt-8 p-6 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 shadow-sm",
                            h3 { class: "font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50", "Your organizations" }
                            ul { class: "mt-4 divide-y divide-bunyip-reed-50 dark:divide-bunyip-reed-700",
                                for m in me.memberships.iter() {
                                    li { class: "py-3 flex items-center justify-between",
                                        div {
                                            p { class: "font-medium text-bunyip-reed-900 dark:text-bunyip-reed-50", "{m.org.name}" }
                                            p { class: "text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300", "{m.org.slug}" }
                                        }
                                        span { class: "px-2 py-0.5 rounded-full bg-bunyip-reed-50 dark:bg-bunyip-reed-900 border border-bunyip-reed-100 dark:border-bunyip-reed-700 text-xs uppercase tracking-wide text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                            "{role_label(&m.role)}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn role_label(role: &crate::api::types::MembershipRole) -> &'static str {
    use crate::api::types::MembershipRole::*;
    match role {
        Owner => "Owner",
        Admin => "Admin",
        Member => "Member",
    }
}

#[component]
fn DashboardHeader(user_name: String, org_name: String) -> Element {
    let auth = use_auth();
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

    rsx! {
        header { class: "px-6 py-3 bg-white dark:bg-bunyip-reed-800 border-b border-bunyip-reed-100 dark:border-bunyip-reed-700 sticky top-0 z-10",
            div { class: "max-w-7xl mx-auto flex items-center justify-between",
                div { class: "flex items-center gap-4",
                    Link { to: Route::DashboardPage {}, class: "flex items-center gap-2",
                        BrandMark {}
                        span { class: "text-lg font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50", "Bunyip" }
                    }
                    span { class: "h-5 w-px bg-bunyip-reed-200 dark:bg-bunyip-reed-700" }
                    div { class: "flex items-center gap-2 px-3 py-1.5 rounded-md bg-bunyip-reed-50 dark:bg-bunyip-reed-900",
                        span { class: "w-2 h-2 rounded-full bg-bunyip-reed-600 dark:bg-bunyip-reed-400" }
                        span { class: "text-sm font-medium text-bunyip-reed-900 dark:text-bunyip-reed-100", "{org_name}" }
                    }
                }
                nav { class: "flex items-center gap-2 text-sm",
                    span { class: "text-bunyip-reed-700 dark:text-bunyip-reed-200", "{user_name}" }
                    button {
                        class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:text-bunyip-reed-900 hover:bg-bunyip-reed-50 dark:hover:text-white dark:hover:bg-bunyip-reed-900 transition-colors",
                        onclick: sign_out,
                        "Sign out"
                    }
                    ThemeToggle {}
                }
            }
        }
    }
}

#[component]
fn StatCard(label: &'static str, value: String, sub: String, accent: &'static str) -> Element {
    let bar = match accent {
        "water" => "bg-bunyip-water-500",
        _ => "bg-bunyip-reed-600",
    };
    rsx! {
        div { class: "relative p-5 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 shadow-sm overflow-hidden",
            span { class: "absolute left-0 top-0 bottom-0 w-1 {bar}" }
            div { class: "pl-2",
                div { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "{label}" }
                div { class: "mt-1 text-2xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50 tracking-tight",
                    "{value}"
                }
                div { class: "mt-1 text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300", "{sub}" }
            }
        }
    }
}
