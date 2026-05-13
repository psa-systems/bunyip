//! `/settings/active-tenant` - tenant switcher.
//!
//! Lists every tenant the user has an active membership in, marks the
//! current one, and lets them switch. Switching POSTs to
//! `/v1/auth/active-tenant`; the server reissues a fresh token bundle
//! with the new `mokosh_active_tenant` claim, the API helper replaces
//! the stored tokens, and we reload so every page (and every running
//! relying party that depends on /v1/auth/me) refetches under the new
//! tenant scope.
//!
//! Ported from mokosh-clients's pages/active_tenant.rs per
//! docs/migration/settings-split.md.

use dioxus::prelude::*;

use crate::api::tenants::{self, MembershipView};
use crate::components::layout::AppShell;
use crate::routes::Route;
use crate::stores::auth::{use_auth, AuthState};
use crate::stores::config::OidcConfig;

#[component]
pub fn ActiveTenantPage() -> Element {
    let nav = navigator();
    let auth = use_auth();
    use_effect(move || {
        if matches!(*auth.read(), AuthState::SignedOut) {
            nav.replace(Route::LoginPage {});
        }
    });

    let mut memberships: Signal<Option<Result<Vec<MembershipView>, String>>> = use_signal(|| None);
    let mut busy: Signal<Option<String>> = use_signal(|| None);
    let mut error: Signal<Option<String>> = use_signal(|| None);
    let mut bump = use_signal(|| 0u32);

    use_future(move || async move {
        let _ = bump.read();
        memberships.set(None);
        let r = tenants::list_memberships()
            .await
            .map_err(|e| e.user_message());
        memberships.set(Some(r));
    });

    let switch = use_callback(move |tenant_id: String| {
        busy.set(Some(tenant_id.clone()));
        error.set(None);
        spawn(async move {
            let cfg = OidcConfig::from_env();
            match tenants::switch_active_tenant(&tenant_id, &cfg.client_id).await {
                Ok(_) => {
                    // Hard reload: every page should refetch its data
                    // under the new active tenant. Cleaner than
                    // surgically invalidating individual fetches.
                    if let Some(win) = web_sys::window() {
                        let _ = win.location().reload();
                    }
                }
                Err(e) => {
                    error.set(Some(e.user_message()));
                    busy.set(None);
                }
            }
        });
    });

    rsx! {
        AppShell { title: "Switch tenant".to_string(),
            div { class: "max-w-2xl mx-auto px-6 space-y-6",
                div {
                    h1 { class: "text-3xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                        "Switch tenant"
                    }
                    p { class: "mt-1 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                        "Pick which tenant you want to act under. Switching reissues your tokens with the new active-tenant claim; every page refetches under the new scope."
                    }
                }

                if let Some(msg) = error.read().as_ref() {
                    div { class: "rounded-md bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-3",
                        p { class: "text-sm text-red-700 dark:text-red-300", "Could not switch tenant: {msg}" }
                    }
                }

                div { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 overflow-hidden",
                    match memberships.read().clone() {
                        None => rsx! {
                            div { class: "p-8 text-center text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                "Loading..."
                            }
                        },
                        Some(Err(msg)) => rsx! {
                            div { class: "p-4 bg-red-50 dark:bg-red-900/20 border-b border-red-200 dark:border-red-800",
                                p { class: "text-sm text-red-700 dark:text-red-300", "{msg}" }
                            }
                        },
                        Some(Ok(rows)) if rows.is_empty() => rsx! {
                            div { class: "p-8 text-center text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                "You only belong to one tenant. There is nothing to switch to."
                            }
                        },
                        Some(Ok(rows)) => rsx! {
                            div { class: "divide-y divide-bunyip-reed-100 dark:divide-bunyip-reed-700",
                                for m in rows {
                                    TenantRow {
                                        key: "{m.tenant_id}",
                                        membership: m.clone(),
                                        busy_id: busy.read().clone(),
                                        on_switch: {
                                            let id = m.tenant_id.clone();
                                            move |_| switch.call(id.clone())
                                        },
                                    }
                                }
                            }
                        },
                    }
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct TenantRowProps {
    membership: MembershipView,
    busy_id: Option<String>,
    on_switch: EventHandler<()>,
}

fn role_label(role: &str) -> &'static str {
    match role {
        "admin" => "Admin",
        "manager" => "Manager",
        "finance" => "Finance",
        "member" => "Member",
        "readonly" => "Read only",
        _ => "Other",
    }
}

fn kind_badge_class(kind: &str) -> &'static str {
    match kind {
        "personal" => "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300",
        _ => "bg-bunyip-reed-100 text-bunyip-reed-800 dark:bg-bunyip-reed-700 dark:text-bunyip-reed-200",
    }
}

#[component]
fn TenantRow(props: TenantRowProps) -> Element {
    let m = &props.membership;
    let busy = props.busy_id.as_deref() == Some(m.tenant_id.as_str());

    rsx! {
        div { class: "flex items-center justify-between gap-4 px-6 py-4",
            div { class: "min-w-0 flex-1 space-y-1",
                div { class: "flex items-center gap-2 flex-wrap",
                    p { class: "text-sm font-medium text-bunyip-reed-900 dark:text-bunyip-reed-50",
                        "{m.tenant_name}"
                    }
                    span { class: "inline-flex px-2 py-0.5 rounded-full text-xs font-medium {kind_badge_class(&m.tenant_kind)}",
                        "{m.tenant_kind}"
                    }
                    if m.is_active {
                        span { class: "inline-flex px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300",
                            "Current"
                        }
                    }
                }
                p { class: "text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                    "Your role: {role_label(&m.role)}"
                }
            }
            if m.is_active {
                span { class: "text-sm text-bunyip-reed-500 dark:text-bunyip-reed-400", "active" }
            } else {
                button {
                    r#type: "button",
                    class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-60",
                    disabled: busy,
                    onclick: move |_| props.on_switch.call(()),
                    if busy { "Switching..." } else { "Switch" }
                }
            }
        }
    }
}
