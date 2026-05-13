//! Invitation accept flow. Reads `?token=...` from the URL, calls /v1/invitations/lookup
//! to show context, then accepts via /v1/invitations/accept.

use dioxus::prelude::*;

use crate::api::orgs::{self, InvitationLookup};
use crate::components::layout::AuthShell;
use crate::routes::Route;
use crate::stores::auth::{refresh_auth, use_auth};
use crate::stores::toast::use_toast;

#[component]
pub fn AcceptInvitationPage() -> Element {
    let nav = navigator();
    let toast = use_toast();
    let auth = use_auth();

    let token = use_memo(|| {
        web_sys::window()
            .and_then(|w| w.location().search().ok())
            .and_then(|s| {
                let qs = s.trim_start_matches('?').to_string();
                qs.split('&').find_map(|p| p.strip_prefix("token=").map(|t| t.to_string()))
            })
    });

    let lookup = use_resource(move || async move {
        let t = token()?;
        Some(orgs::lookup_invitation(&t).await)
    });

    let mut submitting = use_signal(|| false);

    let accept = move |_| {
        let Some(t) = token() else { return; };
        if submitting() {
            return;
        }
        spawn(async move {
            submitting.set(true);
            match orgs::accept_invitation(t).await {
                Ok(org) => {
                    toast.success(format!("Joined {}.", org.name));
                    refresh_auth(auth).await;
                    nav.replace(Route::DashboardPage {});
                }
                Err(e) => toast.error(e.user_message()),
            }
            submitting.set(false);
        });
    };

    rsx! {
        AuthShell {
            title: "Join an organization",
            subtitle: "Review the invitation, then accept to join the org.",
            match &*lookup.read_unchecked() {
                None => rsx! { p { class: "text-sm text-bunyip-reed-700", "Loading invitation…" } },
                Some(None) => rsx! { p { class: "text-sm text-red-700", "Missing or invalid invitation link." } },
                Some(Some(Err(e))) => rsx! { p { class: "text-sm text-red-700", "{e.user_message()}" } },
                Some(Some(Ok(lookup))) => rsx! { LookupCard { lookup: lookup.clone(), submitting: submitting(), onaccept: accept } },
            }
        }
    }
}

#[component]
fn LookupCard(lookup: InvitationLookup, submitting: bool, onaccept: EventHandler<MouseEvent>) -> Element {
    let role_text = match lookup.role {
        crate::api::types::MembershipRole::Owner => "Owner",
        crate::api::types::MembershipRole::Admin => "Admin",
        crate::api::types::MembershipRole::Member => "Member",
    };
    rsx! {
        div {
            p { class: "text-sm text-bunyip-reed-700",
                if let Some(name) = &lookup.inviter_name {
                    "{name} invited you to join"
                } else {
                    "You've been invited to join"
                }
            }
            p { class: "mt-1 text-2xl font-bold text-bunyip-reed-900",
                "{lookup.org.name}"
            }
            p { class: "mt-1 text-xs text-bunyip-reed-600 font-mono",
                "{lookup.org.slug}"
            }
            p { class: "mt-4 text-sm text-bunyip-reed-700",
                "Email: ",
                span { class: "text-bunyip-reed-900", "{lookup.email}" }
                br {}
                "Role: ",
                span { class: "text-bunyip-reed-900", "{role_text}" }
            }
            if lookup.expired {
                p { class: "mt-4 text-sm text-red-700",
                    "This invitation has expired or was already used."
                }
            } else {
                button {
                    class: "mt-6 w-full px-4 py-2.5 rounded-lg bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 disabled:opacity-60",
                    onclick: move |evt| onaccept.call(evt),
                    disabled: submitting,
                    if submitting { "Joining…" } else { "Accept invitation" }
                }
                p { class: "mt-3 text-xs text-bunyip-reed-600",
                    "You must be signed in for this to work. If you aren't, the request will fail."
                }
            }
        }
    }
}
