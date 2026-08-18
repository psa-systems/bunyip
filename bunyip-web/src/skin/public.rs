//! Public marketing pages (landing for now; the rest land in phase 2).

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use maud::html;

use crate::handlers::public_ctx;
use crate::util::{app_gradient, app_link};
use crate::views::layout::{document, public_shell};
use crate::views::ui::{button_class, icon};
use crate::web::{html_cookies, html_status, AppState};

/// Hero trust-chip for the trial length, from `tier_config.standard_trial_days`.
/// Drops the number when the length is unknown rather than printing "0-day".
fn trial_chip(days: i64) -> String {
    if days > 0 {
        format!("{days}-day trial")
    } else {
        "Free trial".to_string()
    }
}

struct Feature {
    icon: &'static str,
    title: &'static str,
    desc: String,
}

/// BUNYIP-561: the subject of a marketing sentence. The admin-managed brand
/// name, or a neutral noun when nothing is branded, so the copy never falls
/// back to a product name compiled into the binary.
fn brand_or_platform(brand_name: &str) -> &str {
    if brand_name.is_empty() {
        "The platform"
    } else {
        brand_name
    }
}

/// BUNYIP-561: the CTA's "Try X" line. Unbranded, there is nothing to name.
fn try_phrase(brand_name: &str) -> String {
    if brand_name.is_empty() {
        "Try it".to_string()
    } else {
        format!("Try {brand_name}")
    }
}

/// BUNYIP-561: the feature cards name the product from the admin-managed brand
/// record, so they are built per render rather than being a `const` of
/// `&'static str`.
fn features(brand_name: &str) -> Vec<Feature> {
    let brand = brand_or_platform(brand_name);
    vec![
        Feature { icon: "fa-solid fa-key", title: "Single sign-on", desc: format!("{brand} is the OIDC entry point. Your team logs in once and lands in Mokosh.") },
        Feature { icon: "fa-solid fa-credit-card", title: "Stripe-ready billing", desc: "Multi-tier memberships, trials, dunning, and an admin override for the cases that don't fit.".to_string() },
        // BUNYIP-487: replaced the "Orgs and members" card. The product has no
        // orgs table, no invitations, and no role switching, so the old copy
        // advertised three features that do not exist.
        Feature { icon: "fa-solid fa-users", title: "Membership and entitlements", desc: format!("Tier, trial, and per-application entitlements resolved in one place and honored everywhere {brand} signs you in.") },
        Feature { icon: "fa-solid fa-shield", title: "MFA, magic links, trusted devices", desc: "All the SSO niceties out of the box - TOTP, recovery codes, password reset, magic links.".to_string() },
        Feature { icon: "fa-solid fa-chart-line", title: "Admin console", desc: "Audit logs, rate limits, tier config, manual membership overrides. The bits you only need but really need.".to_string() },
        Feature { icon: "fa-solid fa-comment-dots", title: "In-app feedback", desc: "A floating widget lets your team report bugs and ideas without leaving the app. Optionally pipes to Forgejo.".to_string() },
    ]
}

/// The hero mascot: a stylized creature peering through reeds over a water
/// disc, captioned with the admin-managed tagline. Ported from the original
/// Dioxus frontend's hero illustration.
///
/// BUNYIP-561: the `alt` text describes the illustration and does not name the
/// product (the artwork itself is BUNYIP-560's problem), and the caption is the
/// branding record's tagline, omitted entirely when it is unset.
fn hero_mascot(tagline: &str) -> maud::Markup {
    maud::html! {
        div class="relative aspect-square w-full max-w-md mx-auto" {
            // BUNYIP-216: the illustration is self-contained (creature, reeds,
            // and water on a transparent background), so it replaces both the
            // old inline-SVG creature and the separate water-gradient disc.
            img src="/assets/bunyip-hero.png"
                alt="A shaggy creature with wide, friendly eyes peering through the reeds over a pond"
                class="relative w-full h-full object-contain drop-shadow-2xl" {}
            @if !tagline.is_empty() {
                p class="absolute bottom-16 left-1/2 -translate-x-1/2 px-3 py-1 rounded-full bg-white dark:bg-brand-primary-800 border border-brand-primary-100 dark:border-brand-primary-700 text-xs italic text-brand-primary-700 dark:text-brand-primary-200 shadow-lg whitespace-nowrap" {
                    "\"" (tagline) "\""
                }
            }
        }
    }
}

pub async fn landing(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
    let signed_in = c.is_signed_in();
    // BUNYIP-487: the advertised trial length comes from
    // `tier_config.standard_trial_days`, never a literal.
    let trial_days = pricing.trial_days;
    let (cta_href, cta_label) = if signed_in {
        ("/membership", "Go to Membership")
    } else {
        ("/register", "Start free trial")
    };
    // BUNYIP-561: every occurrence of the product name on this page comes from
    // the admin-managed branding record, never from a literal.
    let branding = crate::views::layout::branding();
    let brand = brand_or_platform(&branding.brand_name);
    let features = features(&branding.brand_name);

    let content = html! {
        div {
            // Hero
            section class="relative overflow-hidden py-20 md:py-32" {
                div class="container relative grid items-center gap-12 md:grid-cols-2" {
                  div class="flex flex-col items-center text-center md:items-start md:text-left" {
                    span class="mb-6 inline-flex items-center gap-2 rounded-full bg-brand-primary-100 dark:bg-brand-primary-800 px-3 py-1 text-xs font-medium uppercase tracking-wide text-brand-primary-800 dark:text-brand-primary-100 hero-fade-up" {
                        span class="h-1.5 w-1.5 rounded-full bg-brand-primary-600 dark:bg-brand-primary-300" {}
                        "Now in early access"
                    }
                    h1 class="mt-2 text-4xl font-bold tracking-tight sm:text-5xl md:text-6xl text-brand-primary-900 dark:text-brand-primary-50 leading-[1.05] hero-fade-up-1" {
                        "The SaaS layer for your "
                        span class="relative inline-block" {
                            span class="relative z-10 text-brand-accent-700 dark:text-brand-accent-100" { "PSA" }
                            span class="absolute left-0 right-0 bottom-1 h-3 -z-0 bg-brand-accent-100 dark:bg-brand-accent-700/60" {}
                        }
                        "."
                    }
                    p class="mt-6 max-w-2xl text-lg text-brand-primary-700 dark:text-brand-primary-200 leading-relaxed hero-fade-up-2" {
                        (format!("{brand} handles the business-y bits - signup, billing, members, invitations - so Mokosh can focus on what makes your MSP tick."))
                    }
                    div class="mt-10 flex flex-col gap-4 sm:flex-row hero-fade-up-3" {
                        a href=(cta_href) class=(button_class("default", "lg", "w-full sm:w-auto gap-2 bg-brand-primary-700 hover:bg-brand-primary-800 border-0 text-white shadow-lg shadow-primary/25")) {
                            (cta_label) " " i class="fa-solid fa-arrow-right text-[1rem]" {}
                        }
                        // BUNYIP-487: /pricing 404s when pricing is unpublished,
                        // so the hero button follows the same condition as the
                        // nav and footer links.
                        @if pricing.published() { a href="/pricing" class=(button_class("outline", "lg", "w-full sm:w-auto")) { "See pricing" } }
                    }
                    div class="mt-10 flex flex-wrap items-center justify-center md:justify-start gap-x-8 gap-y-2 text-sm text-brand-primary-700 dark:text-brand-primary-300" {
                        @for t in ["No credit card required".to_string(), trial_chip(trial_days), "Cancel anytime".to_string()] {
                            span class="flex items-center gap-2" { (icon("check", "h-4 w-4 text-brand-primary-600 dark:text-brand-primary-300")) (t) }
                        }
                    }
                  }
                  (hero_mascot(&branding.tagline))
                }
            }
            // Features
            section class="relative border-t border-border/50 py-20" {
                div class="container relative scroll-fade-up in-view" {
                    div class="max-w-2xl" {
                        p class="text-sm uppercase tracking-wide font-semibold text-brand-primary-600 dark:text-brand-primary-300" { "What you get" }
                        h2 class="mt-2 text-3xl md:text-4xl font-bold tracking-tight text-brand-primary-900 dark:text-brand-primary-50" { "Everything around the product. Nothing in it." }
                        p class="mt-4 text-muted-foreground" { (format!("{brand} is the business shell that wraps Mokosh. We do the boring infrastructure so you can ship the PSA.")) }
                    }
                    div class="mt-12 grid gap-6 md:grid-cols-3 auto-rows-fr scroll-fade-up-child in-view" {
                        @for f in &features {
                            div class="h-full flex flex-col rounded-xl border border-brand-primary-100 dark:border-brand-primary-700 bg-brand-primary-50 dark:bg-brand-primary-900 p-6 transition-colors hover:border-brand-primary-300 dark:hover:border-brand-primary-500 hover:bg-white dark:hover:bg-brand-primary-800" {
                                div class="flex h-10 w-10 items-center justify-center rounded-lg border border-brand-primary-200 dark:border-brand-primary-700 bg-white dark:bg-brand-primary-800 text-brand-primary-700 dark:text-brand-primary-100" {
                                    i class={ (f.icon) " text-base" } {}
                                }
                                h3 class="mt-4 text-lg font-semibold text-brand-primary-900 dark:text-brand-primary-50" { (f.title) }
                                p class="mt-2 text-sm leading-relaxed text-brand-primary-700 dark:text-brand-primary-200" { (f.desc) }
                            }
                        }
                    }
                }
            }
            // Apps wired through the platform
            @if !apps.is_empty() {
                section class="relative py-20" {
                    div class="container relative scroll-fade-up in-view" {
                        h2 class="text-center text-3xl font-bold text-brand-primary-900 dark:text-brand-primary-50" { "Wired into your stack" }
                        p class="mx-auto mt-4 max-w-2xl text-center text-muted-foreground" { (format!("{brand} is the front door to the products your team already runs.")) }
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
                                          class="mt-4 inline-flex items-center gap-1 text-sm font-medium text-brand-primary-700 dark:text-brand-primary-200 hover:underline" {
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
                    div class="mx-auto max-w-4xl rounded-2xl border border-brand-primary-200 dark:border-brand-primary-700 bg-gradient-to-br from-brand-primary-700 to-brand-accent-700 p-10 md:p-12 text-white shadow-lg" {
                        div class="flex flex-col gap-6 md:flex-row md:items-center md:justify-between" {
                            div {
                                h3 class="text-2xl md:text-3xl font-bold tracking-tight" { "Ready to wire up your business layer?" }
                                p class="mt-2 text-brand-primary-100" { (try_phrase(&branding.brand_name)) " " (crate::skin::content::trial_phrase(trial_days)) ". Bring your team along." }
                            }
                            // Same size and shape as the hero CTA; only the
                            // inverted-on-gradient colouring is bespoke.
                            a href=(cta_href) class=(button_class("default", "lg", "whitespace-nowrap gap-2 bg-white hover:bg-white text-brand-primary-800 border-0 shadow-sm hover:shadow-md")) {
                                (if signed_in { "Go to Membership" } else { "Create your account" })
                                i class="fa-solid fa-arrow-right text-[1rem]" {}
                            }
                        }
                    }
                }
            }
        }
    };

    let body = public_shell(
        &st.cfg,
        c.user.as_ref(),
        &apps,
        pricing.published(),
        true,
        content,
    );
    html_cookies(document("Surfaces what matters.", body), &c.set_cookies)
}

/// The branded 404 body. Shared so a route that decides it has nothing to serve
/// (BUNYIP-487: `/pricing` when pricing is unpublished) renders the same page as
/// the router fallback rather than a bespoke near-miss.
pub fn not_found_content() -> maud::Markup {
    html! {
        div class="flex min-h-[60vh] flex-col items-center justify-center text-center px-6" {
            p class="text-5xl font-bold text-gradient bg-gradient-to-r from-primary to-indigo-500" { "404" }
            h1 class="mt-4 text-4xl font-bold" { "Page not found" }
            a href="/" class=(button_class("default", "default", "mt-8")) { "Back home" }
        }
    }
}

pub async fn not_found(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, apps, pricing) = public_ctx(&st, &headers).await;
    let body = public_shell(
        &st.cfg,
        c.user.as_ref(),
        &apps,
        pricing.published(),
        false,
        not_found_content(),
    );
    // BUNYIP-186: a real 404, not a soft-404 200, while still rendering the
    // branded page.
    html_status(document("Not found", body), StatusCode::NOT_FOUND)
}

#[cfg(test)]
mod copy_tests {
    use super::{brand_or_platform, features, hero_mascot, trial_chip, try_phrase};

    /// BUNYIP-487: the homepage no longer advertises org switching, role
    /// management, or inviting teammates. None of the three exist.
    #[test]
    fn no_feature_card_claims_orgs_or_invitations() {
        // Whole words, not substrings: "Forgejo" contains "org".
        const BANNED_WORDS: &[&str] = &[
            "org",
            "orgs",
            "organisation",
            "organisations",
            "organization",
            "organizations",
            "teammate",
            "teammates",
            "invite",
            "inviting",
            "invitations",
        ];
        for f in &features("Acme") {
            let text = format!("{} {}", f.title, f.desc).to_lowercase();
            for word in text.split(|c: char| !c.is_ascii_alphanumeric()) {
                assert!(
                    !BANNED_WORDS.contains(&word),
                    "feature card {:?} claims {word:?}, which the product does not do",
                    f.title
                );
            }
            assert!(
                !text.contains("switch between"),
                "feature card {:?} claims switching, which the product does not do",
                f.title
            );
        }
    }

    /// The hero trust-chip reads its length from `tier_config`, and says
    /// nothing specific when the length is unknown.
    #[test]
    fn trial_chip_reads_the_configured_length() {
        assert_eq!(trial_chip(30), "30-day trial");
        assert_eq!(trial_chip(7), "7-day trial");
        assert_eq!(trial_chip(0), "Free trial");
    }

    /// BUNYIP-561: the landing copy names the admin-managed brand, and names no
    /// product at all when the record is empty. The old codename literals were
    /// the whole reason the codename leaked into every shared link.
    #[test]
    fn marketing_copy_follows_the_brand_and_never_falls_back_to_a_product_name() {
        for f in features("Acme") {
            assert!(
                !f.desc.contains("Bunyip"), // brand-literal-ok: the assertion that the codename is gone
                "feature card {:?} still names the codename",
                f.title
            );
        }
        assert!(features("Acme")[0].desc.starts_with("Acme is the OIDC"));
        assert!(features("")[0].desc.starts_with("The platform is the OIDC"));

        assert_eq!(brand_or_platform("Acme"), "Acme");
        assert_eq!(brand_or_platform(""), "The platform");
        assert_eq!(try_phrase("Acme"), "Try Acme");
        assert_eq!(try_phrase(""), "Try it");
    }

    /// BUNYIP-561: the hero caption is the record's tagline, dropped entirely
    /// when unset, and the mascot `alt` describes the picture without naming
    /// the product.
    #[test]
    fn the_hero_caption_is_the_tagline_and_the_alt_names_no_product() {
        let with = hero_mascot("Surfaces what matters.").into_string();
        assert!(with.contains("Surfaces what matters."));
        let without = hero_mascot("").into_string();
        assert!(
            !without.contains("<p"),
            "an unset tagline omits the caption entirely: {without}"
        );
        for markup in [&with, &without] {
            assert!(markup.contains("alt=\"A shaggy creature"));
            assert!(
                !markup.contains("Bunyip"), // brand-literal-ok: the assertion that the codename is gone
                "the alt text describes the illustration only: {markup}"
            );
        }
    }
}
