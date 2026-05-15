//! `/settings` - account-management hub.
//!
//! Card grid that catalogs every account-management surface bunyip
//! owns. Reaches every page the user could otherwise only find by
//! typing the URL. Grouped into:
//!   - Your account (profile, security, sessions, tenant switcher)
//!   - Organizations
//!   - Admin (admin-only)
//!
//! See docs/migration/settings-split.md for the partition this hub
//! reflects.

use dioxus::prelude::*;

use crate::api::orgs::{self as orgs_api, OrgMembershipBrief};
use crate::api::tenants::{self, MembershipView};
use crate::api::types::UserRole;
use crate::components::layout::AppShell;
use crate::routes::Route;
use crate::stores::auth::{use_auth, AuthState};

#[component]
pub fn SettingsPage() -> Element {
    let nav = navigator();
    let auth = use_auth();
    use_effect(move || {
        if matches!(*auth.read(), AuthState::SignedOut) {
            nav.replace(Route::LoginPage {});
        }
    });

    let is_admin = matches!(
        &*auth.read(),
        AuthState::SignedIn(me) if me.user.role == UserRole::Admin
    );

    // Show the "Switch tenant" card only when the user actually has
    // 2+ memberships. A single-membership account has nothing to
    // switch to; the card would just lead to an empty page.
    let mut memberships: Signal<Option<Vec<MembershipView>>> = use_signal(|| None);
    use_future(move || async move {
        memberships.set(tenants::list_memberships().await.ok());
    });
    let show_switcher = memberships
        .read()
        .as_ref()
        .map(|m| m.len() >= 2)
        .unwrap_or(false);

    // Org memberships drive the Billing card: pick the org matching
    // the active tenant if possible, otherwise the first org the
    // user belongs to. Personal-tenant-only users don't see the card.
    let mut my_orgs: Signal<Option<Vec<OrgMembershipBrief>>> = use_signal(|| None);
    use_future(move || async move {
        my_orgs.set(orgs_api::list_my_orgs().await.ok());
    });
    let billing_slug: Option<String> = {
        let orgs = my_orgs.read();
        let mems = memberships.read();
        orgs.as_ref().and_then(|orgs| {
            if orgs.is_empty() {
                return None;
            }
            // Prefer the org matching the user's active tenant id.
            let active_id = mems
                .as_ref()
                .and_then(|m| m.iter().find(|x| x.is_active).map(|x| x.tenant_id.clone()));
            let preferred = active_id
                .as_ref()
                .and_then(|id| orgs.iter().find(|o| &o.org.id == id))
                .or_else(|| orgs.first());
            preferred.map(|o| o.org.slug.clone())
        })
    };

    rsx! {
        AppShell { title: "Settings".to_string(),
            div { class: "max-w-5xl mx-auto px-6 space-y-10",
                div {
                    h1 { class: "text-3xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                        "Settings"
                    }
                    p { class: "mt-1 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                        "Your account, your organizations, and (if you're an admin) the platform."
                    }
                }

                HubSection { title: "Your account",
                    HubCard {
                        title: "Profile",
                        description: "Your name, timezone, avatar, and password.",
                        to: Route::ProfilePage {},
                    }
                    HubCard {
                        title: "Security",
                        description: "Two-factor authentication and recovery codes.",
                        to: Route::SecurityPage {},
                    }
                    HubCard {
                        title: "Active sessions",
                        description: "Devices currently signed in to your account.",
                        to: Route::SessionsPage {},
                    }
                    if show_switcher {
                        HubCard {
                            title: "Switch tenant",
                            description: "Pick which tenant you want to act under.",
                            to: Route::ActiveTenantPage {},
                        }
                    }
                }

                HubSection { title: "Organizations",
                    HubCard {
                        title: "Organizations",
                        description: "Members, roles, and billing for each org you belong to.",
                        to: Route::OrgListPage {},
                    }
                    if let Some(slug) = billing_slug.clone() {
                        HubCard {
                            title: "Billing",
                            description: "Plan, trial countdown, and invoices for your active organization.",
                            to: Route::OrgBillingPage { slug },
                        }
                    }
                }

                if is_admin {
                    HubSection { title: "Admin",
                        HubCard {
                            title: "User management",
                            description: "Suspend, reactivate, and force-disenroll MFA on users.",
                            to: Route::UserManagementPage {},
                        }
                        HubCard {
                            title: "Audit logs",
                            description: "Security events recorded by the auth subsystem.",
                            to: Route::AuditLogsPage {},
                        }
                        HubCard {
                            title: "Feedback inbox",
                            description: "Triage in-app feedback submissions.",
                            to: Route::AdminFeedbackPage {},
                        }
                    }
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct HubSectionProps {
    title: &'static str,
    children: Element,
}

#[component]
fn HubSection(props: HubSectionProps) -> Element {
    rsx! {
        section {
            h2 { class: "text-sm font-semibold uppercase tracking-wide text-bunyip-reed-600 dark:text-bunyip-reed-300",
                "{props.title}"
            }
            // auto-rows-fr makes every grid row sized identically to the
            // tallest card across the whole grid. Combined with h-full on
            // each card, all cards match the tallest card's height even
            // when descriptions differ in length.
            div { class: "mt-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 auto-rows-fr",
                {props.children}
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct HubCardProps {
    title: &'static str,
    description: &'static str,
    to: Route,
}

#[component]
fn HubCard(props: HubCardProps) -> Element {
    rsx! {
        Link {
            to: props.to,
            class: "group h-full flex flex-col p-5 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 hover:border-bunyip-reed-300 dark:hover:border-bunyip-reed-500 hover:shadow-md transition-all",
            h3 { class: "text-base font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                "{props.title}"
            }
            p { class: "mt-1 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                "{props.description}"
            }
            // Pinned to the bottom regardless of description length so the
            // affordance lines up across cards in the same row.
            span { class: "mt-auto pt-3 text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400 group-hover:text-bunyip-reed-700 dark:group-hover:text-bunyip-reed-200",
                "Open →"
            }
        }
    }
}
