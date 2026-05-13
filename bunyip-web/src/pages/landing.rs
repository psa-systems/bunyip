use dioxus::prelude::*;

use crate::components::layout::PublicNav;
use crate::routes::Route;

#[component]
pub fn LandingPage() -> Element {
    rsx! {
        div { class: "min-h-screen flex flex-col bg-gradient-to-b from-bunyip-reed-50 via-bunyip-reed-50 to-white",
            PublicNav {}

            // Hero
            section { class: "flex-1 px-6 pt-12 pb-20",
                div { class: "max-w-6xl mx-auto grid md:grid-cols-2 gap-12 items-center",
                    div {
                        span { class: "inline-flex items-center gap-2 px-3 py-1 rounded-full bg-bunyip-reed-100 text-bunyip-reed-800 text-xs font-medium tracking-wide uppercase",
                            span { class: "w-1.5 h-1.5 rounded-full bg-bunyip-reed-600" }
                            "Now in early access"
                        }
                        h1 { class: "mt-6 text-4xl md:text-6xl font-bold tracking-tight text-bunyip-reed-900 leading-[1.05]",
                            "The SaaS layer for your "
                            span { class: "relative inline-block",
                                span { class: "relative z-10 text-bunyip-water-500",
                                    "PSA"
                                }
                                span { class: "absolute left-0 right-0 bottom-1 h-3 bg-bunyip-water-100 -z-0" }
                            }
                            "."
                        }
                        p { class: "mt-6 text-lg text-bunyip-reed-700 leading-relaxed max-w-xl",
                            "Bunyip handles the business-y bits - signup, billing, members, invitations - so Mokosh can focus on what makes your MSP tick."
                        }
                        div { class: "mt-10 flex flex-wrap gap-3",
                            Link {
                                to: Route::SignupPage {},
                                class: "px-6 py-3 rounded-lg bg-bunyip-reed-700 text-white font-medium shadow-sm hover:bg-bunyip-reed-800 hover:shadow-md transition-all",
                                "Start free trial"
                            }
                            Link {
                                to: Route::PricingPage {},
                                class: "px-6 py-3 rounded-lg border border-bunyip-reed-300 text-bunyip-reed-800 font-medium hover:bg-bunyip-reed-100 transition-colors",
                                "See pricing"
                            }
                        }
                        div { class: "mt-10 flex flex-wrap items-center gap-x-8 gap-y-2 text-sm text-bunyip-reed-700",
                            Bullet { text: "No credit card required" }
                            Bullet { text: "14-day trial" }
                            Bullet { text: "Cancel anytime" }
                        }
                    }

                    BunyipMascot {}
                }
            }

            // Features
            section { class: "px-6 py-20 bg-white border-y border-bunyip-reed-100",
                div { class: "max-w-6xl mx-auto",
                    div { class: "max-w-2xl",
                        p { class: "text-sm uppercase tracking-wide text-bunyip-reed-600 font-semibold",
                            "What you get"
                        }
                        h2 { class: "mt-2 text-3xl md:text-4xl font-bold tracking-tight",
                            "Everything around the product. Nothing in it."
                        }
                        p { class: "mt-4 text-bunyip-reed-700",
                            "Bunyip is the business shell that wraps Mokosh. We do the boring infrastructure so you can ship the PSA."
                        }
                    }
                    div { class: "mt-12 grid md:grid-cols-3 gap-6",
                        FeatureCard {
                            icon: rsx! { IconKey {} },
                            title: "Single sign-on",
                            body: "Bunyip is the OIDC entry point. Your team logs in once and lands in Mokosh."
                        }
                        FeatureCard {
                            icon: rsx! { IconCard {} },
                            title: "Stripe-ready billing",
                            body: "Multi-tier subscriptions, trials, dunning, and an admin override for the cases that don't fit."
                        }
                        FeatureCard {
                            icon: rsx! { IconPeople {} },
                            title: "Orgs and members",
                            body: "Invite teammates, manage roles, switch between orgs without leaving the dashboard."
                        }
                        FeatureCard {
                            icon: rsx! { IconShield {} },
                            title: "MFA, magic links, trusted devices",
                            body: "All the SSO niceties out of the box - TOTP, recovery codes, password reset, magic links."
                        }
                        FeatureCard {
                            icon: rsx! { IconChart {} },
                            title: "Admin console",
                            body: "Audit logs, rate limits, tier config, manual subscription overrides. The bits you only need but really need."
                        }
                        FeatureCard {
                            icon: rsx! { IconChat {} },
                            title: "In-app feedback",
                            body: "A floating widget lets your team report bugs and ideas without leaving the app. Optionally pipes to Forgejo."
                        }
                    }
                }
            }

            // CTA strip
            section { class: "px-6 py-16",
                div { class: "max-w-4xl mx-auto rounded-2xl border border-bunyip-reed-200 bg-gradient-to-br from-bunyip-reed-700 to-bunyip-water-700 p-10 md:p-12 text-white shadow-lg",
                    div { class: "flex flex-col md:flex-row gap-6 md:items-center md:justify-between",
                        div {
                            h3 { class: "text-2xl md:text-3xl font-bold tracking-tight",
                                "Ready to wire up your business layer?"
                            }
                            p { class: "mt-2 text-bunyip-reed-100",
                                "Try Bunyip free for 14 days. Bring your team along."
                            }
                        }
                        Link {
                            to: Route::SignupPage {},
                            class: "px-6 py-3 rounded-lg bg-white text-bunyip-reed-800 font-medium shadow-sm hover:shadow-md transition-shadow whitespace-nowrap",
                            "Create your account →"
                        }
                    }
                }
            }

            Footer {}
        }
    }
}

#[component]
fn FeatureCard(icon: Element, title: &'static str, body: &'static str) -> Element {
    rsx! {
        div { class: "p-6 rounded-xl border border-bunyip-reed-100 bg-bunyip-reed-50 hover:border-bunyip-reed-300 hover:bg-white transition-colors",
            div { class: "w-10 h-10 rounded-lg bg-white border border-bunyip-reed-200 flex items-center justify-center text-bunyip-reed-700",
                {icon}
            }
            h3 { class: "mt-4 font-semibold text-lg text-bunyip-reed-900",
                "{title}"
            }
            p { class: "mt-2 text-sm text-bunyip-reed-700 leading-relaxed",
                "{body}"
            }
        }
    }
}

#[component]
fn Bullet(text: &'static str) -> Element {
    rsx! {
        div { class: "flex items-center gap-2",
            svg {
                class: "w-4 h-4 text-bunyip-reed-600",
                view_box: "0 0 20 20",
                fill: "currentColor",
                path {
                    "fill-rule": "evenodd",
                    "clip-rule": "evenodd",
                    d: "M16.7 5.3a1 1 0 010 1.4l-7.3 7.3a1 1 0 01-1.4 0L3.3 9.3a1 1 0 011.4-1.4l3.6 3.6 6.6-6.6a1 1 0 011.4 0z",
                }
            }
            "{text}"
        }
    }
}

#[component]
fn Footer() -> Element {
    rsx! {
        footer { class: "px-6 py-10 border-t border-bunyip-reed-100 bg-white",
            div { class: "max-w-6xl mx-auto flex flex-col md:flex-row gap-4 md:items-center md:justify-between text-sm text-bunyip-reed-700",
                div { class: "flex items-center gap-3",
                    BunyipMark {}
                    div { "Bunyip · a8n.systems" }
                }
                div { class: "flex gap-6",
                    Link { to: Route::PricingPage {}, class: "hover:text-bunyip-reed-900",
                        "Pricing"
                    }
                    Link { to: Route::LoginPage {}, class: "hover:text-bunyip-reed-900",
                        "Sign in"
                    }
                    a { href: "https://msp.a8n.systems", class: "hover:text-bunyip-reed-900",
                        "Open Mokosh"
                    }
                }
            }
        }
    }
}

#[component]
fn BunyipMark() -> Element {
    rsx! {
        svg {
            class: "w-7 h-7 text-bunyip-reed-700",
            view_box: "0 0 32 32",
            fill: "none",
            // Stylized reed-and-eyes mark.
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

#[component]
fn BunyipMascot() -> Element {
    // Stylized illustration: reeds in front of a body of water, with two friendly
    // eyes peering through. Matches the README tagline (Surfaces what matters).
    // Tailwind-based backgrounds give us the "gradient" effect without needing
    // SVG <linearGradient> children, which the rsx! macro doesn't parse cleanly.
    rsx! {
        div { class: "relative aspect-square w-full max-w-md mx-auto",
            // Water disc backdrop, drawn via a Tailwind-gradient div behind the SVG.
            div { class: "absolute inset-0 rounded-full bg-gradient-to-b from-bunyip-water-100 via-bunyip-water-500 to-bunyip-water-900 shadow-xl" }
            svg {
                class: "relative w-full h-full",
                view_box: "0 0 400 400",
                fill: "none",
                // Water ripples on top of the disc.
                ellipse { cx: "200", cy: "270", rx: "120", ry: "8", fill: "#ffffff", opacity: "0.35" }
                ellipse { cx: "200", cy: "300", rx: "150", ry: "6", fill: "#ffffff", opacity: "0.25" }
                ellipse { cx: "200", cy: "320", rx: "100", ry: "5", fill: "#ffffff", opacity: "0.20" }
                // Bunyip head silhouette (peeking out of the water).
                ellipse { cx: "200", cy: "220", rx: "75", ry: "55", fill: "#1f311f" }
                ellipse { cx: "200", cy: "260", rx: "85", ry: "20", fill: "#1f311f" }
                // Friendly eyes.
                circle { cx: "172", cy: "210", r: "16", fill: "#ffffff" }
                circle { cx: "228", cy: "210", r: "16", fill: "#ffffff" }
                circle { cx: "175", cy: "212", r: "8", fill: "#1f311f" }
                circle { cx: "231", cy: "212", r: "8", fill: "#1f311f" }
                circle { cx: "177", cy: "210", r: "2.5", fill: "#ffffff" }
                circle { cx: "233", cy: "210", r: "2.5", fill: "#ffffff" }
                // Reeds in the foreground.
                path { fill: "#3c6438", d: "M60 400 Q56 240 78 180 Q86 240 90 400 Z" }
                path { fill: "#2f4e2e", d: "M100 400 Q96 200 120 140 Q128 220 130 400 Z" }
                path { fill: "#2f4e2e", d: "M280 400 Q276 220 296 160 Q306 220 310 400 Z" }
                path { fill: "#3c6438", d: "M330 400 Q326 250 348 200 Q356 260 358 400 Z" }
                // Reed seed-heads.
                ellipse { cx: "78", cy: "180", rx: "5", ry: "12", fill: "#283e27" }
                ellipse { cx: "120", cy: "140", rx: "5", ry: "14", fill: "#283e27" }
                ellipse { cx: "296", cy: "160", rx: "5", ry: "14", fill: "#283e27" }
                ellipse { cx: "348", cy: "200", rx: "5", ry: "12", fill: "#283e27" }
            }
            p { class: "absolute -bottom-2 right-2 px-3 py-1 rounded-full bg-white border border-bunyip-reed-100 text-xs italic text-bunyip-reed-700 shadow-sm",
                "Surfaces what matters."
            }
        }
    }
}

// --- Icons (heroicons-style outline, 24px) ---

#[component]
fn IconKey() -> Element {
    rsx! {
        svg {
            class: "w-5 h-5",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            "stroke-width": "1.8",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            path { d: "M15.5 7.5a4 4 0 11-3.74 5.45L8 17l-2 .5L5 21l-2-1 0.5-3L8 13.24A4 4 0 1115.5 7.5z" }
            circle { cx: "16", cy: "8", r: "1.2", fill: "currentColor" }
        }
    }
}

#[component]
fn IconCard() -> Element {
    rsx! {
        svg {
            class: "w-5 h-5",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            "stroke-width": "1.8",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            rect { x: "3", y: "5", width: "18", height: "14", rx: "2" }
            path { d: "M3 10h18" }
            path { d: "M7 15h3" }
        }
    }
}

#[component]
fn IconPeople() -> Element {
    rsx! {
        svg {
            class: "w-5 h-5",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            "stroke-width": "1.8",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            circle { cx: "9", cy: "8", r: "3.2" }
            circle { cx: "17", cy: "9", r: "2.5" }
            path { d: "M3 19c0-3 3-5 6-5s6 2 6 5" }
            path { d: "M14 19c0-2 2-3.5 4-3.5s3 1.2 3 3" }
        }
    }
}

#[component]
fn IconShield() -> Element {
    rsx! {
        svg {
            class: "w-5 h-5",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            "stroke-width": "1.8",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            path { d: "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z" }
            path { d: "M9 12l2 2 4-4" }
        }
    }
}

#[component]
fn IconChart() -> Element {
    rsx! {
        svg {
            class: "w-5 h-5",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            "stroke-width": "1.8",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            path { d: "M3 3v18h18" }
            path { d: "M7 15l4-4 3 3 5-6" }
        }
    }
}

#[component]
fn IconChat() -> Element {
    rsx! {
        svg {
            class: "w-5 h-5",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            "stroke-width": "1.8",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            path { d: "M4 6h16v10H8l-4 3z" }
            path { d: "M8 10h8" }
            path { d: "M8 13h5" }
        }
    }
}
