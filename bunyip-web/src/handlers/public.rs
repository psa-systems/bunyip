//! Public marketing pages (landing for now; the rest land in phase 2).

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup};

use crate::api::calls;
use crate::config::Config;
use crate::handlers::ctx;
use crate::util::{app_gradient, app_link};
use crate::views::layout::{document, public_shell};
use crate::views::ui::{button_class, icon};
use crate::web::{html, html_cookies, AppState};

struct Feature {
    icon: &'static str,
    title: &'static str,
    desc: &'static str,
}

const FEATURES: [Feature; 6] = [
    Feature { icon: "fa-solid fa-key", title: "Single sign-on", desc: "Bunyip is the OIDC entry point. Your team logs in once and lands in Mokosh." },
    Feature { icon: "fa-solid fa-credit-card", title: "Stripe-ready billing", desc: "Multi-tier subscriptions, trials, dunning, and an admin override for the cases that don't fit." },
    Feature { icon: "fa-solid fa-users", title: "Orgs and members", desc: "Invite teammates, manage roles, switch between orgs without leaving the dashboard." },
    Feature { icon: "fa-solid fa-shield", title: "MFA, magic links, trusted devices", desc: "All the SSO niceties out of the box - TOTP, recovery codes, password reset, magic links." },
    Feature { icon: "fa-solid fa-chart-line", title: "Admin console", desc: "Audit logs, rate limits, tier config, manual subscription overrides. The bits you only need but really need." },
    Feature { icon: "fa-solid fa-comment-dots", title: "In-app feedback", desc: "A floating widget lets your team report bugs and ideas without leaving the app. Optionally pipes to Forgejo." },
];

/// The Bunyip mascot: a stylized creature peering through reeds over a water
/// disc, with the "Surfaces what matters." caption. Ported from the original
/// Dioxus frontend's hero illustration.
fn bunyip_mascot() -> maud::Markup {
    maud::html! {
        div class="relative aspect-square w-full max-w-md mx-auto" {
            div class="absolute inset-0 rounded-full bg-gradient-to-b from-bunyip-water-100 via-bunyip-water-500 to-bunyip-water-900 shadow-xl" {}
            svg class="relative w-full h-full" viewBox="0 0 400 400" fill="none" {
                ellipse cx="200" cy="240" rx="120" ry="8" fill="#ffffff" opacity="0.35" {}
                ellipse cx="200" cy="270" rx="150" ry="6" fill="#ffffff" opacity="0.25" {}
                ellipse cx="200" cy="290" rx="100" ry="5" fill="#ffffff" opacity="0.20" {}
                ellipse cx="200" cy="190" rx="75" ry="55" fill="#1f311f" {}
                ellipse cx="200" cy="230" rx="85" ry="20" fill="#1f311f" {}
                circle cx="172" cy="180" r="16" fill="#ffffff" {}
                circle cx="228" cy="180" r="16" fill="#ffffff" {}
                circle cx="175" cy="182" r="8" fill="#1f311f" {}
                circle cx="231" cy="182" r="8" fill="#1f311f" {}
                circle cx="177" cy="180" r="2.5" fill="#ffffff" {}
                circle cx="233" cy="180" r="2.5" fill="#ffffff" {}
                path fill="#3c6438" d="M60 400 Q56 240 78 180 Q86 240 90 400 Z" {}
                path fill="#2f4e2e" d="M100 400 Q96 200 120 140 Q128 220 130 400 Z" {}
                path fill="#2f4e2e" d="M280 400 Q276 220 296 160 Q306 220 310 400 Z" {}
                path fill="#3c6438" d="M330 400 Q326 250 348 200 Q356 260 358 400 Z" {}
                ellipse cx="78" cy="180" rx="5" ry="12" fill="#283e27" {}
                ellipse cx="120" cy="140" rx="5" ry="14" fill="#283e27" {}
                ellipse cx="296" cy="160" rx="5" ry="14" fill="#283e27" {}
                ellipse cx="348" cy="200" rx="5" ry="12" fill="#283e27" {}
            }
            p class="absolute -bottom-2 left-1/2 -translate-x-1/2 px-3 py-1 rounded-full bg-white dark:bg-bunyip-reed-800 border border-bunyip-reed-100 dark:border-bunyip-reed-700 text-xs italic text-bunyip-reed-700 dark:text-bunyip-reed-200 shadow-sm whitespace-nowrap" {
                "Surfaces what matters."
            }
        }
    }
}

pub async fn landing(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, fwd) = ctx(&st, &headers).await;
    let apps = calls::applications(&st.api, fwd.as_deref()).await.unwrap_or_default();
    let signed_in = c.is_signed_in();
    let (cta_href, cta_label) = if signed_in { ("/membership", "Go to Membership") } else { ("/register", "Start free trial") };

    let content = html! {
        div {
            // Hero
            section class="relative overflow-hidden py-20 md:py-32" {
                div class="container relative grid items-center gap-12 md:grid-cols-2" {
                  div class="flex flex-col items-center text-center md:items-start md:text-left" {
                    span class="mb-6 inline-flex items-center gap-2 rounded-full bg-bunyip-reed-100 dark:bg-bunyip-reed-800 px-3 py-1 text-xs font-medium uppercase tracking-wide text-bunyip-reed-800 dark:text-bunyip-reed-100 hero-fade-up" {
                        span class="h-1.5 w-1.5 rounded-full bg-bunyip-reed-600 dark:bg-bunyip-reed-300" {}
                        "Now in early access"
                    }
                    h1 class="mt-2 text-4xl font-bold tracking-tight sm:text-5xl md:text-6xl text-bunyip-reed-900 dark:text-bunyip-reed-50 leading-[1.05] hero-fade-up-1" {
                        "The SaaS layer for your "
                        span class="relative inline-block" {
                            span class="relative z-10 text-bunyip-water-700 dark:text-bunyip-water-100" { "PSA" }
                            span class="absolute left-0 right-0 bottom-1 h-3 -z-0 bg-bunyip-water-100 dark:bg-bunyip-water-700/60" {}
                        }
                        "."
                    }
                    p class="mt-6 max-w-2xl text-lg text-bunyip-reed-700 dark:text-bunyip-reed-200 leading-relaxed hero-fade-up-2" {
                        "Bunyip handles the business-y bits - signup, billing, members, invitations - so Mokosh can focus on what makes your MSP tick."
                    }
                    div class="mt-10 flex flex-col gap-4 sm:flex-row hero-fade-up-3" {
                        a href=(cta_href) class=(button_class("default", "lg", "w-full sm:w-auto gap-2 bg-bunyip-reed-700 hover:bg-bunyip-reed-800 border-0 text-white shadow-lg shadow-primary/25")) {
                            (cta_label) " " i class="fa-solid fa-arrow-right text-[1rem]" {}
                        }
                        a href="/pricing" class=(button_class("outline", "lg", "w-full sm:w-auto")) { "See pricing" }
                    }
                    div class="mt-10 flex flex-wrap items-center justify-center md:justify-start gap-x-8 gap-y-2 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-300" {
                        @for t in ["No credit card required", "14-day trial", "Cancel anytime"] {
                            span class="flex items-center gap-2" { (icon("check", "h-4 w-4 text-bunyip-reed-600 dark:text-bunyip-reed-300")) (t) }
                        }
                    }
                  }
                  (bunyip_mascot())
                }
            }
            // Features
            section class="relative border-t border-border/50 py-20" {
                div class="container relative scroll-fade-up in-view" {
                    div class="max-w-2xl" {
                        p class="text-sm uppercase tracking-wide font-semibold text-bunyip-reed-600 dark:text-bunyip-reed-300" { "What you get" }
                        h2 class="mt-2 text-3xl md:text-4xl font-bold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50" { "Everything around the product. Nothing in it." }
                        p class="mt-4 text-muted-foreground" { "Bunyip is the business shell that wraps Mokosh. We do the boring infrastructure so you can ship the PSA." }
                    }
                    div class="mt-12 grid gap-6 md:grid-cols-3 auto-rows-fr scroll-fade-up-child in-view" {
                        @for f in &FEATURES {
                            div class="h-full flex flex-col rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-bunyip-reed-50 dark:bg-bunyip-reed-900 p-6 transition-colors hover:border-bunyip-reed-300 dark:hover:border-bunyip-reed-500 hover:bg-white dark:hover:bg-bunyip-reed-800" {
                                div class="flex h-10 w-10 items-center justify-center rounded-lg border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 text-bunyip-reed-700 dark:text-bunyip-reed-100" {
                                    i class={ (f.icon) " text-base" } {}
                                }
                                h3 class="mt-4 text-lg font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50" { (f.title) }
                                p class="mt-2 text-sm leading-relaxed text-bunyip-reed-700 dark:text-bunyip-reed-200" { (f.desc) }
                            }
                        }
                    }
                }
            }
            // Apps wired through Bunyip
            @if !apps.is_empty() {
                section class="relative py-20" {
                    div class="container relative scroll-fade-up in-view" {
                        h2 class="text-center text-3xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50" { "Wired into your stack" }
                        p class="mx-auto mt-4 max-w-2xl text-center text-muted-foreground" { "Bunyip is the front door to the products your team already runs." }
                        div class="mt-12 grid gap-8 md:grid-cols-2 max-w-3xl mx-auto scroll-fade-up-child in-view" {
                            @for (i, app) in apps.iter().enumerate() {
                                div class="rounded-lg border bg-card text-card-foreground shadow-sm transition-all hover:shadow-lg border-border/50" {
                                    div class="flex flex-col space-y-1.5 p-6" {
                                        div class="flex items-center gap-4" {
                                            div class={ "flex h-12 w-12 items-center justify-center rounded-lg bg-gradient-to-br " (app_gradient(i)) } {
                                                @if let Some(icon) = &app.icon_url { img src=(icon) alt=(app.display_name) class="h-6 w-6"; }
                                                @else { i class="fa-solid fa-cube text-xl text-white" {} }
                                            }
                                            div { h3 class="text-2xl font-semibold leading-none tracking-tight" { (app.display_name) } }
                                        }
                                    }
                                    div class="p-6 pt-0" {
                                        p class="text-base text-muted-foreground" { (app.description.clone().unwrap_or_default()) }
                                        a href=(app_link(app, &st.cfg.app_domain)) target="_blank" rel="noopener noreferrer"
                                          class="mt-4 inline-flex items-center gap-1 text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:underline" {
                                            "Learn more " i class="fa-solid fa-arrow-right text-xs" {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // CTA
            section class="relative overflow-hidden border-t border-border/50 py-20" {
                div class="container relative" {
                    div class="mx-auto max-w-4xl rounded-2xl border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-gradient-to-br from-bunyip-reed-700 to-bunyip-water-700 p-10 md:p-12 text-white shadow-lg" {
                        div class="flex flex-col gap-6 md:flex-row md:items-center md:justify-between" {
                            div {
                                h3 class="text-2xl md:text-3xl font-bold tracking-tight" { "Ready to wire up your business layer?" }
                                p class="mt-2 text-bunyip-reed-100" { "Try Bunyip free for 14 days. Bring your team along." }
                            }
                            a href=(cta_href) class="whitespace-nowrap rounded-lg bg-white px-6 py-3 font-medium text-bunyip-reed-800 shadow-sm transition-shadow hover:shadow-md" {
                                (if signed_in { "Go to Membership" } else { "Create your account" }) " →"
                            }
                        }
                    }
                }
            }
        }
    };

    let body = public_shell(&st.cfg, c.user.as_ref(), &apps, true, content);
    html_cookies(document("Bunyip · Surfaces what matters.", body), &c.set_cookies)
}

/// Static legal/marketing copy block shared shape.
pub fn simple_page(cfg: &Config, title: &str, body: Markup) -> Markup {
    let _ = cfg;
    html! {
        div class="container max-w-4xl py-12" {
            h1 class="text-4xl font-bold mb-8" { (title) }
            (body)
        }
    }
}

pub async fn not_found(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, fwd) = ctx(&st, &headers).await;
    let apps = calls::applications(&st.api, fwd.as_deref()).await.unwrap_or_default();
    let content = html! {
        div class="flex min-h-[60vh] flex-col items-center justify-center text-center px-6" {
            p class="text-6xl font-bold text-gradient bg-gradient-to-r from-primary to-indigo-500" { "404" }
            h1 class="mt-4 text-2xl font-semibold" { "Page not found" }
            a href="/" class=(button_class("default", "default", "mt-8")) { "Back home" }
        }
    };
    let body = public_shell(&st.cfg, c.user.as_ref(), &apps, false, content);
    html(document("Not found · Bunyip", body))
}
