//! Header org-switcher dropdown. Replaces the static "[Personal | User]"
//! pill in the AppShell + Dashboard header. Picking a tenant POSTs
//! `/v1/auth/active-tenant` (which reissues a fresh token bundle with
//! `mokosh_active_tenant` updated) and reloads the page so every
//! downstream resource refetches under the new scope.

use dioxus::prelude::*;

use crate::api::tenants::{self, MembershipView};
use crate::routes::Route;
use crate::stores::config::OidcConfig;
use crate::stores::toast::use_toast;

#[derive(Props, Clone, PartialEq)]
pub struct OrgSwitcherProps {
    /// What to display before the user opens the dropdown - typically
    /// the current tenant's display name.
    pub current_label: String,
    /// Trailing user name shown after a thin divider inside the pill
    /// (the "where am I + who am I" pattern from the static version).
    #[props(default)]
    pub user_name: Option<String>,
}

#[component]
pub fn OrgSwitcher(props: OrgSwitcherProps) -> Element {
    let toast = use_toast();
    let mut open = use_signal(|| false);
    let memberships = use_resource(|| async { tenants::list_memberships().await });

    let switch = move |tenant_id: String| {
        spawn(async move {
            let client_id = OidcConfig::from_env().client_id.clone();
            match tenants::switch_active_tenant(&tenant_id, &client_id).await {
                Ok(_) => {
                    if let Some(win) = web_sys::window() {
                        let _ = win.location().reload();
                    }
                }
                Err(e) => toast.error(e.user_message()),
            }
        });
    };

    rsx! {
        div { class: "relative",
            button {
                r#type: "button",
                "aria-haspopup": "menu",
                "aria-expanded": "{open()}",
                class: "flex items-center gap-2 px-3 py-1.5 rounded-md bg-bunyip-reed-50 dark:bg-bunyip-reed-900 hover:bg-bunyip-reed-100 dark:hover:bg-bunyip-reed-800",
                onclick: move |_| open.set(!open()),
                span { class: "w-2 h-2 rounded-full bg-bunyip-reed-600 dark:bg-bunyip-reed-400" }
                span { class: "text-sm font-medium text-bunyip-reed-900 dark:text-bunyip-reed-100",
                    "{props.current_label}"
                }
                if let Some(name) = &props.user_name {
                    if !name.is_empty() {
                        span { class: "h-3 w-px bg-bunyip-reed-200 dark:bg-bunyip-reed-700" }
                        span { class: "text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300", "{name}" }
                    }
                }
                span { class: "text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400", "▾" }
            }
            if open() {
                // Backdrop closes the dropdown when clicked.
                div {
                    class: "fixed inset-0 z-10",
                    onclick: move |_| open.set(false),
                }
                div {
                    role: "menu",
                    class: "absolute left-0 mt-2 w-72 z-20 rounded-lg border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 shadow-lg",
                    match &*memberships.read_unchecked() {
                        None => rsx! { p { class: "p-3 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "Loading…" } },
                        Some(Err(e)) => rsx! { p { class: "p-3 text-sm text-red-700", "{e.user_message()}" } },
                        Some(Ok(list)) if list.is_empty() => rsx! { p { class: "p-3 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300", "No memberships." } },
                        Some(Ok(list)) => rsx! {
                            ul { class: "py-1 max-h-72 overflow-y-auto",
                                for m in list.iter() {
                                    {
                                        let m = m.clone();
                                        rsx! { TenantRow { membership: m, on_pick: switch.clone() } }
                                    }
                                }
                            }
                        }
                    }
                    div { class: "border-t border-bunyip-reed-50 dark:border-bunyip-reed-700",
                        Link {
                            to: Route::OrgListPage {},
                            class: "block px-3 py-2 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                            onclick: move |_| open.set(false),
                            "Manage organizations →"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn TenantRow(membership: MembershipView, on_pick: Callback<String>) -> Element {
    let active = membership.is_active;
    let kind = membership.tenant_kind.clone();
    let tenant_id = membership.tenant_id.clone();
    let pill = if kind == "personal" {
        "Personal"
    } else {
        "Org"
    };
    rsx! {
        li {
            button {
                r#type: "button",
                class: "w-full flex items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                onclick: move |_| {
                    if !active {
                        on_pick.call(tenant_id.clone());
                    }
                },
                div { class: "min-w-0 flex-1",
                    p { class: "truncate text-bunyip-reed-900 dark:text-bunyip-reed-50",
                        "{membership.tenant_name}"
                    }
                    p { class: "text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300",
                        "{pill} · {membership.role}"
                    }
                }
                if active {
                    span { class: "text-xs text-bunyip-reed-600 dark:text-bunyip-reed-400", "✓" }
                }
            }
        }
    }
}
