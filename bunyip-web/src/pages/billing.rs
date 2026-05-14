//! Org billing page. Shows current plan, lets owners change/cancel/restart.

use dioxus::prelude::*;

use crate::api::billing::{self, BillingView, SubscriptionStatus, TierConfig};
use crate::components::error_card::{ErrorCard, ErrorVariant};
use crate::components::layout::AppShell;
use crate::routes::Route;
use crate::stores::toast::use_toast;

#[component]
pub fn OrgBillingPage(slug: String) -> Element {
    let toast = use_toast();
    let mut refresh_key = use_signal(|| 0u64);

    let slug_for_view = slug.clone();
    let mut view = use_resource(move || {
        let slug = slug_for_view.clone();
        let _ = refresh_key.read();
        async move { billing::get_billing(&slug).await }
    });
    let tiers = use_resource(|| async { billing::list_tiers().await });

    rsx! {
        AppShell {
            title: format!("Billing · {slug}"),
            back_to: Some(Route::OrgListPage {}),
            back_label: "Organizations".to_string(),
            div { class: "max-w-4xl mx-auto",
                h1 { class: "text-2xl font-bold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50",
                    "Billing"
                }

                match &*view.read_unchecked() {
                    None => rsx! { div { class: "mt-6 p-6 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "Loading…" } },
                    Some(Err(e)) => {
                        let variant = e.variant();
                        let (title, message) = match variant {
                            ErrorVariant::ComingSoon => (
                                "Billing is on the roadmap".to_string(),
                                "Subscription management isn't wired up yet. We'll surface plan + invoices here when it ships.".to_string(),
                            ),
                            ErrorVariant::Retryable => (
                                "We hit a snag".to_string(),
                                "We couldn't load your billing info. The server might be having a momentary issue.".to_string(),
                            ),
                            ErrorVariant::HardError => ("Something's not right".to_string(), e.user_message()),
                        };
                        let retry = matches!(variant, ErrorVariant::Retryable)
                            .then(|| EventHandler::new(move |_| view.restart()));
                        rsx! {
                            div { class: "mt-6",
                                ErrorCard { variant, title, message, on_retry: retry }
                            }
                        }
                    },
                    Some(Ok(view)) => rsx! { CurrentPlan { view: view.clone(), slug: slug.clone(), refresh_key: refresh_key, toast: toast } },
                }

                match &*tiers.read_unchecked() {
                    None => rsx! { div { class: "mt-6 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "Loading tiers…" } },
                    Some(Err(_)) => rsx! { },
                    Some(Ok(list)) => rsx! { TierPicker { tiers: list.clone(), slug: slug.clone(), refresh_key: refresh_key, toast: toast } },
                }
            }
        }
    }
}

#[component]
fn CurrentPlan(
    view: BillingView,
    slug: String,
    refresh_key: Signal<u64>,
    toast: crate::stores::toast::ToastStore,
) -> Element {
    let _ = (slug.clone(), toast);
    let refresh_key = refresh_key;
    // Stripe write integration is deferred (see docs/mokosh-fixes/05-billing.md).
    // The cancel / uncancel handlers were here; they'll be rewritten
    // against the new endpoints when that surface ships. Today the
    // buttons render as disabled-with-tooltip.

    let (status_label, status_class) = view
        .subscription
        .as_ref()
        .map(|s| status_pill(&s.status))
        .unwrap_or((
        "No subscription",
        "bg-bunyip-reed-50 dark:bg-bunyip-reed-900 text-bunyip-reed-700 dark:text-bunyip-reed-200",
    ));

    rsx! {
        div { class: "mt-6 p-6 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800",
            div { class: "flex items-center justify-between",
                div {
                    p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "Current plan" }
                    p { class: "mt-1 text-3xl font-bold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50",
                        if let Some(t) = &view.tier { "{t.display_name}" } else { "None" }
                    }
                    if let Some(t) = &view.tier {
                        p { class: "mt-1 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                            "{price_label(t)}"
                        }
                    }
                }
                span { class: "px-3 py-1 rounded-full text-xs uppercase tracking-wide font-semibold {status_class}",
                    "{status_label}"
                }
            }

            if let Some(sub) = &view.subscription {
                div { class: "mt-6 grid sm:grid-cols-2 gap-4 text-sm",
                    InfoRow { label: "Renews".to_string(), value: format_or_dash(sub.current_period_end.as_deref()) }
                    InfoRow { label: "Trial ends".to_string(), value: format_or_dash(sub.trial_end.as_deref()) }
                    if sub.cancel_at_period_end {
                        InfoRow { label: "Cancellation".to_string(), value: "Scheduled at period end".to_string() }
                    }
                    if let Some(gp) = &sub.grace_period_end {
                        InfoRow { label: "Grace period ends".to_string(), value: format_or_dash(Some(gp)) }
                    }
                }

                // Stripe write integration is deferred; the cancel /
                // uncancel handlers exist on the SPA but the server
                // endpoints stay 404 today. Render the buttons as
                // disabled with a tooltip so the surface looks complete
                // without misleading users.
                div { class: "mt-6 flex flex-wrap gap-3",
                    if sub.cancel_at_period_end {
                        button {
                            r#type: "button",
                            disabled: true,
                            title: "Coming soon - Stripe integration not wired yet",
                            class: "px-4 py-2 rounded-lg bg-bunyip-reed-700 text-white text-sm disabled:opacity-50 disabled:cursor-not-allowed",
                            "Keep my plan"
                        }
                    } else if !matches!(sub.status, SubscriptionStatus::Lifetime) {
                        button {
                            r#type: "button",
                            disabled: true,
                            title: "Coming soon - Stripe integration not wired yet",
                            class: "px-4 py-2 rounded-lg border border-red-200 text-red-700 text-sm disabled:opacity-50 disabled:cursor-not-allowed",
                            "Cancel subscription"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn InfoRow(label: String, value: String) -> Element {
    rsx! {
        div {
            p { class: "text-xs uppercase tracking-wide text-bunyip-reed-600 dark:text-bunyip-reed-300 font-semibold", "{label}" }
            p { class: "mt-1 text-bunyip-reed-900 dark:text-bunyip-reed-50", "{value}" }
        }
    }
}

fn status_pill(status: &SubscriptionStatus) -> (&'static str, &'static str) {
    match status {
        SubscriptionStatus::Trialing => ("Trial", "bg-bunyip-water-50 text-bunyip-water-700"),
        SubscriptionStatus::Active => ("Active", "bg-bunyip-reed-50 dark:bg-bunyip-reed-900 text-bunyip-reed-700 dark:text-bunyip-reed-200"),
        SubscriptionStatus::PastDue => ("Past due", "bg-red-50 text-red-700"),
        SubscriptionStatus::Canceled => ("Canceled", "bg-bunyip-reed-50 dark:bg-bunyip-reed-900 text-bunyip-reed-700 dark:text-bunyip-reed-200"),
        SubscriptionStatus::Lifetime => ("Lifetime", "bg-bunyip-reed-700 text-white"),
    }
}

fn price_label(tier: &TierConfig) -> String {
    if tier.monthly_price_cents == 0 {
        "Free".to_string()
    } else {
        format!("${}/month", tier.monthly_price_cents / 100)
    }
}

fn format_or_dash(ts: Option<&str>) -> String {
    match ts {
        Some(s) if !s.is_empty() => s.split('T').next().unwrap_or(s).to_string(),
        _ => "—".to_string(),
    }
}

#[component]
fn TierPicker(
    tiers: Vec<TierConfig>,
    slug: String,
    refresh_key: Signal<u64>,
    toast: crate::stores::toast::ToastStore,
) -> Element {
    let mut refresh_key = refresh_key;
    let slug = std::rc::Rc::new(slug);

    rsx! {
        h2 { class: "mt-10 text-lg font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50", "Change plan" }
        div { class: "mt-3 grid md:grid-cols-3 gap-4",
            for tier in tiers.iter() {
                {
                    let tier_key = tier.tier_key.clone();
                    let slug = slug.clone();
                    rsx! {
                        div { class: "p-5 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800",
                            p { class: "font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50", "{tier.display_name}" }
                            p { class: "mt-1 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "{price_label(tier)}" }
                            ul { class: "mt-3 space-y-1 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                for f in tier.features.iter() {
                                    li { class: "flex gap-2",
                                        span { class: "text-bunyip-reed-600 dark:text-bunyip-reed-300", "✓" }
                                        span { "{f}" }
                                    }
                                }
                            }
                            button {
                                r#type: "button",
                                disabled: true,
                                title: "Coming soon - Stripe integration not wired yet",
                                class: "mt-4 w-full px-3 py-2 rounded-lg border border-bunyip-reed-300 text-sm disabled:opacity-50 disabled:cursor-not-allowed",
                                onclick: move |_| {
                                    let tier_key = tier_key.clone();
                                    let slug = (*slug).clone();
                                    spawn(async move {
                                        match billing::create_checkout(&slug, tier_key).await {
                                            Ok(_) => {
                                                toast.success("Plan updated.");
                                                refresh_key.set(refresh_key() + 1);
                                            }
                                            Err(e) => toast.error(e.user_message()),
                                        }
                                    });
                                },
                                "Select"
                            }
                        }
                    }
                }
            }
        }
    }
}
