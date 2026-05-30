//! Public marketing pages (landing for now; the rest land in phase 2).

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use maud::{html, Markup};

use crate::api::calls;
use crate::config::Config;
use crate::handlers::{ctx, rotating_index};
use crate::util::{app_gradient, app_link};
use crate::views::layout::{document, public_shell};
use crate::views::ui::button_class;
use crate::web::{html, html_cookies, AppState};

const HERO: [(&str, &str); 7] = [
    ("All access.", "No clock."),
    ("All in.", "All yours."),
    ("Price locked.", "Tools stocked."),
    ("Locked in.", "Lights on."),
    ("Subscribed once", "Sorted Forever."),
    ("One Price", "For life."),
    ("Open source", "For life."),
];

struct Feature {
    icon: &'static str,
    title: &'static str,
    desc: &'static str,
    gradient: &'static str,
    border: &'static str,
}

const FEATURES: [Feature; 3] = [
    Feature { icon: "fa-solid fa-bolt", title: "Blazing Fast", desc: "Written in Rust. No garbage collector, no runtime overhead. Just raw speed.", gradient: "from-primary to-primary/60", border: "from-primary/50 via-primary/20 to-transparent" },
    Feature { icon: "fa-solid fa-shield", title: "Secure by Default", desc: "Memory-safe, type-safe, battle-tested. Sleep well at night.", gradient: "from-indigo-500 to-indigo-500/60", border: "from-indigo-500/50 via-indigo-500/20 to-transparent" },
    Feature { icon: "fa-solid fa-dollar-sign", title: "$3/month. Forever.", desc: "One price, locked for life. No tiers. No surprises. No \"enterprise\" upsells.", gradient: "from-teal-500 to-teal-500/60", border: "from-teal-500/50 via-teal-500/20 to-transparent" },
];

pub async fn landing(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, fwd) = ctx(&st, &headers).await;
    let apps = calls::applications(&st.api, fwd.as_deref()).await.unwrap_or_default();
    let signed_in = c.is_signed_in();
    let hero = HERO[rotating_index(HERO.len())];
    let (cta_href, cta_label) = if signed_in { ("/membership", "Go to Membership") } else { ("/register", "Get Started") };

    let content = html! {
        div {
            // Hero
            section class="relative overflow-hidden py-20 md:py-32" {
                div class="container relative flex flex-col items-center text-center" {
                    div class="mb-6 inline-flex items-center gap-2 rounded-full bg-zinc-800 px-4 py-1.5 text-sm text-zinc-300 hero-fade-up" {
                        i class="fa-solid fa-terminal text-[0.875rem]" {}
                        "Open source. Rust-powered. Fully managed."
                    }
                    h1 class="text-4xl font-bold tracking-tight sm:text-5xl md:text-6xl lg:text-7xl hero-fade-up-1" {
                        (hero.0) " "
                        span class="text-gradient bg-gradient-to-r from-primary via-indigo-500 to-teal-400 hero-gradient-shift" { (hero.1) }
                    }
                    p class="mt-6 max-w-2xl text-lg text-muted-foreground md:text-xl hero-fade-up-2" {
                        "Tools that run themselves so you can focus on what you're actually building. One subscription. "
                        span class="font-semibold text-foreground" { "$3/month" } ", locked forever."
                    }
                    div class="mt-10 flex flex-col gap-4 sm:flex-row hero-fade-up-3" {
                        a href=(cta_href) class=(button_class("default", "lg", "w-full sm:w-auto gap-2 bg-gradient-to-r from-primary to-indigo-500 hover:from-primary/90 hover:to-indigo-500/90 border-0 text-white shadow-lg shadow-primary/25")) {
                            (cta_label) " " i class="fa-solid fa-arrow-right text-[1rem]" {}
                        }
                        a href="/pricing" class=(button_class("outline", "lg", "w-full sm:w-auto border-indigo-300/30 text-indigo-600 hover:bg-indigo-500/10 dark:border-indigo-500/30 dark:text-indigo-400 dark:hover:bg-indigo-500/10")) { "View Pricing" }
                    }
                }
            }
            // Features
            section class="relative border-t border-border/50 py-20" {
                div class="pointer-events-none absolute inset-0 bg-gradient-to-b from-indigo-500/[0.03] via-transparent to-teal-500/[0.03]" {}
                div class="container relative scroll-fade-up in-view" {
                    h2 class="text-center text-3xl font-bold" { "No ops. No overhead. No nonsense." }
                    p class="mx-auto mt-4 max-w-2xl text-center text-muted-foreground" { "We handle hosting, updates, and uptime. You get tools that just work." }
                    div class="mt-12 grid gap-8 md:grid-cols-3 scroll-fade-up-child in-view" {
                        @for f in &FEATURES {
                            div class="group relative rounded-xl" {
                                div class={ "absolute -inset-px rounded-xl bg-gradient-to-b " (f.border) " opacity-0 transition-opacity group-hover:opacity-100" } {}
                                div class="relative rounded-lg border bg-card/80 text-card-foreground shadow-sm border-0 backdrop-blur-sm" {
                                    div class="flex flex-col space-y-1.5 p-6" {
                                        div class={ "flex h-12 w-12 items-center justify-center rounded-lg bg-gradient-to-br " (f.gradient) } {
                                            i class={ (f.icon) " text-xl text-white" } {}
                                        }
                                        h3 class="text-2xl font-semibold leading-none tracking-tight mt-4" { (f.title) }
                                    }
                                    div class="p-6 pt-0" { p class="text-base text-muted-foreground" { (f.desc) } }
                                }
                            }
                        }
                    }
                }
            }
            // Apps
            section class="relative py-20" {
                div class="container relative scroll-fade-up in-view" {
                    h2 class="text-center text-3xl font-bold" { "The toolkit" }
                    p class="mx-auto mt-4 max-w-2xl text-center text-muted-foreground" { "All included. More shipping soon." }
                    div class="mt-12 grid gap-8 md:grid-cols-2 max-w-3xl mx-auto scroll-fade-up-child in-view" {
                        @for (i, app) in apps.iter().enumerate() {
                            div class="rounded-lg border bg-card text-card-foreground shadow-sm transition-all hover:shadow-lg hover:shadow-indigo-500/5 border-border/50" {
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
                                      class={ "mt-4 inline-flex items-center gap-1 text-sm text-gradient bg-gradient-to-r " (app_gradient(i)) " font-medium hover:underline" } {
                                        "Learn more " i class="fa-solid fa-arrow-right text-xs text-indigo-500" {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // CTA
            section class="relative overflow-hidden border-t border-border/50 py-20" {
                div class="absolute inset-0 bg-gradient-to-br from-indigo-600 via-primary to-teal-500" {}
                div class="container relative text-center scroll-fade-up in-view" {
                    h2 class="text-3xl font-bold text-white" { "Stop configuring. Start building." }
                    p class="mx-auto mt-4 max-w-2xl text-white/80" { "Lock in $3/month. Get every tool, current and future. Cancel anytime." }
                    div class="mt-10 flex justify-center gap-4" {
                        a href=(cta_href) class=(button_class("secondary", "lg", "gap-2 shadow-lg")) {
                            (if signed_in { "Go to Membership" } else { "Create Account" }) " "
                            i class="fa-solid fa-arrow-right text-[1rem]" {}
                        }
                    }
                }
            }
        }
    };

    let body = public_shell(&st.cfg, c.user.as_ref(), &apps, true, content);
    html_cookies(document("PSA Systems · Managed tools for service providers.", body), &c.set_cookies)
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
    html(document("Not found · PSA Systems", body))
}
