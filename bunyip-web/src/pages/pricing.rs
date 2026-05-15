use dioxus::prelude::*;

use crate::api::billing::{self, TierConfig};
use crate::components::layout::PublicNav;
use crate::routes::Route;

#[component]
pub fn PricingPage() -> Element {
    let tiers = use_resource(|| async { billing::list_tiers().await });

    rsx! {
        div { class: "min-h-screen flex flex-col bg-gradient-to-b from-bunyip-reed-50 to-white dark:from-bunyip-reed-900 dark:to-bunyip-reed-800",
            PublicNav {}

            section { class: "px-6 pt-16 pb-20",
                div { class: "max-w-5xl mx-auto",
                    div { class: "text-center max-w-2xl mx-auto",
                        span { class: "inline-flex items-center gap-2 px-3 py-1 rounded-full bg-bunyip-reed-100 dark:bg-bunyip-reed-800 text-bunyip-reed-800 dark:text-bunyip-reed-100 text-xs font-medium tracking-wide uppercase",
                            "Pricing"
                        }
                        h1 { class: "mt-4 text-4xl md:text-5xl font-bold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50",
                            "Simple. Honest. Done."
                        }
                        p { class: "mt-4 text-bunyip-reed-700 dark:text-bunyip-reed-200",
                            "All plans include unlimited members, every SSO feature, and the admin console."
                        }
                    }

                    div { class: "mt-12",
                        match &*tiers.read_unchecked() {
                            None => rsx! {
                                p { class: "text-center text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                    "Loading plans..."
                                }
                            },
                            Some(Err(_)) => rsx! {
                                // Fall back to a compact "talk to us" card if
                                // the catalogue endpoint is unreachable. Pricing
                                // is informational; a 5xx shouldn't block the
                                // page entirely.
                                div { class: "max-w-md mx-auto p-6 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 text-center",
                                    p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                        "Our pricing page is taking a moment. In the meantime, "
                                        Link { to: Route::SignupPage {}, class: "underline font-medium",
                                            "sign up"
                                        }
                                        " and we'll match you to the right plan."
                                    }
                                }
                            },
                            Some(Ok(list)) if list.is_empty() => rsx! {
                                p { class: "text-center text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                    "Plans are being finalised. Check back soon."
                                }
                            },
                            Some(Ok(list)) => {
                                // Highlight a "middle" tier so the eye lands
                                // somewhere. Picks the tier closest to (but
                                // not past) the middle index; for 4 tiers
                                // that's index 1 (Starter), for 3 it's the
                                // middle one, for 1 it's the only card.
                                let highlight_idx = list.len() / 2;
                                let cols_class = if list.len() >= 4 {
                                    "grid md:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-6"
                                } else if list.len() == 3 {
                                    "grid md:grid-cols-3 gap-4 md:gap-6"
                                } else if list.len() == 2 {
                                    "grid md:grid-cols-2 gap-4 md:gap-6 max-w-3xl mx-auto"
                                } else {
                                    "max-w-md mx-auto"
                                };
                                rsx! {
                                    div { class: "{cols_class}",
                                        for (i, tier) in list.iter().enumerate() {
                                            PricingCard {
                                                tier: tier.clone(),
                                                highlighted: i == highlight_idx && list.len() > 1,
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    div { class: "mt-16",
                        h2 { class: "text-2xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                            "Questions"
                        }
                        div { class: "mt-6 divide-y divide-bunyip-reed-100 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800",
                            Faq {
                                q: "Can I bring my own Stripe?",
                                a: "Yes - in the admin console, point Bunyip at your Stripe account and Bunyip will create the customer / subscription on your behalf.",
                            }
                            Faq {
                                q: "How does the trial end?",
                                a: "You're never auto-charged. We email you a few days before the end of the trial. If you don't add a payment method, the account simply moves to read-only until you do.",
                            }
                            Faq {
                                q: "Is the early-adopter pricing really locked in?",
                                a: "Yes. The price you sign up at is the price you renew at, forever. We may add new tiers above but never above your locked-in price.",
                            }
                        }
                    }
                }
            }

            footer { class: "px-6 py-10 border-t border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800",
                div { class: "max-w-6xl mx-auto text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                    Link { to: Route::LandingPage {}, class: "underline",
                        "← Back to home"
                    }
                }
            }
        }
    }
}

/// Bucket a tier's monthly price into a (display, period) pair.
/// 0 cents -> ("Free", "forever"); huge -> ("Contact us", "for select partners");
/// everything else -> ("$N", "per month").
fn price_and_period(tier: &TierConfig) -> (String, &'static str) {
    if tier.monthly_price_cents == 0 {
        ("Free".to_string(), "forever")
    } else {
        let dollars = tier.monthly_price_cents / 100;
        (format!("${dollars}"), "per month")
    }
}

fn cta_for(tier: &TierConfig) -> &'static str {
    if tier.monthly_price_cents == 0 {
        "Start free"
    } else if tier.tier_key == "enterprise" {
        "Talk to us"
    } else {
        "Start free trial"
    }
}

#[component]
fn PricingCard(tier: TierConfig, highlighted: bool) -> Element {
    let card_class = if highlighted {
        "relative p-7 rounded-2xl border-2 border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 shadow-lg"
    } else {
        "relative p-7 rounded-2xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800"
    };
    let button_class = if highlighted {
        "w-full px-4 py-2.5 rounded-lg bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 transition-colors"
    } else {
        "w-full px-4 py-2.5 rounded-lg border border-bunyip-reed-300 text-bunyip-reed-800 dark:text-bunyip-reed-100 font-medium hover:bg-bunyip-reed-50 transition-colors"
    };
    let (price, period) = price_and_period(&tier);
    let cta = cta_for(&tier);

    rsx! {
        div { class: "{card_class}",
            if highlighted {
                span { class: "absolute -top-3 left-7 px-2.5 py-0.5 rounded-full bg-bunyip-reed-700 text-white text-xs font-semibold tracking-wide uppercase",
                    "Popular"
                }
            }
            h3 { class: "text-lg font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                "{tier.display_name}"
            }
            div { class: "mt-4 flex items-baseline gap-2",
                span { class: "text-4xl font-bold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50",
                    "{price}"
                }
                span { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                    "{period}"
                }
            }
            if tier.trial_days > 0 && tier.monthly_price_cents > 0 {
                p { class: "mt-1 text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300",
                    "Includes a {tier.trial_days}-day free trial"
                }
            }
            ul { class: "mt-6 space-y-2.5 text-sm",
                for feature in tier.features.iter() {
                    li { class: "flex items-start gap-2",
                        svg {
                            class: "w-4 h-4 mt-0.5 text-bunyip-reed-600 dark:text-bunyip-reed-300 shrink-0",
                            view_box: "0 0 20 20",
                            fill: "currentColor",
                            path {
                                "fill-rule": "evenodd",
                                "clip-rule": "evenodd",
                                d: "M16.7 5.3a1 1 0 010 1.4l-7.3 7.3a1 1 0 01-1.4 0L3.3 9.3a1 1 0 011.4-1.4l3.6 3.6 6.6-6.6a1 1 0 011.4 0z",
                            }
                        }
                        span { class: "text-bunyip-reed-800 dark:text-bunyip-reed-100", "{feature}" }
                    }
                }
            }
            Link {
                to: Route::SignupPage {},
                class: "mt-7 inline-block text-center {button_class}",
                "{cta}"
            }
        }
    }
}

#[component]
fn Faq(q: &'static str, a: &'static str) -> Element {
    rsx! {
        div { class: "p-5",
            p { class: "font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                "{q}"
            }
            p { class: "mt-2 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 leading-relaxed",
                "{a}"
            }
        }
    }
}
