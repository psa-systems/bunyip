//! Org list + member-management pages.

use dioxus::prelude::*;

use crate::api::orgs::{self, MemberBrief, OrgMembershipBrief};
use crate::api::types::MembershipRole;
use crate::components::layout::AppShell;
use crate::routes::Route;
use crate::stores::toast::use_toast;

#[component]
pub fn OrgListPage() -> Element {
    let orgs = use_resource(|| async { orgs::list_my_orgs().await });

    rsx! {
        AppShell { title: "Organizations".to_string(),
            div { class: "max-w-4xl mx-auto",
                div { class: "flex items-center justify-between",
                    div {
                        h1 { class: "text-2xl font-bold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50", "Your organizations" }
                        p { class: "mt-1 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                            "Switch between orgs and manage members."
                        }
                    }
                    button { class: "px-4 py-2 rounded-lg bg-bunyip-reed-700 text-white text-sm font-medium hover:bg-bunyip-reed-800",
                        "+ New org"
                    }
                }
                div { class: "mt-6 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 divide-y divide-bunyip-reed-50 dark:divide-bunyip-reed-700",
                    match &*orgs.read_unchecked() {
                        None => rsx! { p { class: "p-6 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "Loading…" } },
                        Some(Err(e)) => rsx! { p { class: "p-6 text-sm text-red-700", "{e.user_message()}" } },
                        Some(Ok(list)) if list.is_empty() => rsx! { p { class: "p-6 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "You're not in any organizations yet." } },
                        Some(Ok(list)) => rsx! {
                            for membership in list.iter() {
                                OrgRow { membership: membership.clone() }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn OrgRow(membership: OrgMembershipBrief) -> Element {
    let slug = membership.org.slug.clone();
    rsx! {
        div { class: "p-5 flex items-center justify-between gap-4",
            div {
                p { class: "font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50", "{membership.org.name}" }
                p { class: "text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300 font-mono", "{membership.org.slug}" }
            }
            div { class: "flex items-center gap-3",
                span { class: "px-2 py-0.5 rounded-full bg-bunyip-reed-50 dark:bg-bunyip-reed-900 border border-bunyip-reed-100 dark:border-bunyip-reed-700 text-xs uppercase tracking-wide text-bunyip-reed-700 dark:text-bunyip-reed-200",
                    "{role_label(&membership.role)}"
                }
                Link {
                    to: Route::OrgMembersPage { slug: slug.clone() },
                    class: "px-3 py-1.5 rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 text-sm hover:bg-bunyip-reed-50",
                    "Members"
                }
                Link {
                    to: Route::OrgBillingPage { slug: slug.clone() },
                    class: "px-3 py-1.5 rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 text-sm hover:bg-bunyip-reed-50",
                    "Billing"
                }
            }
        }
    }
}

fn role_label(role: &MembershipRole) -> &'static str {
    match role {
        MembershipRole::Owner => "Owner",
        MembershipRole::Admin => "Admin",
        MembershipRole::Member => "Member",
    }
}

#[component]
pub fn OrgMembersPage(slug: String) -> Element {
    let toast = use_toast();
    let slug_for_resource = slug.clone();
    let mut refresh_key = use_signal(|| 0u64);

    let members = use_resource(move || {
        let slug = slug_for_resource.clone();
        let _ = refresh_key.read(); // re-fetch when refresh_key changes
        async move { orgs::list_members(&slug).await }
    });
    let invites_slug = slug.clone();
    let invites = use_resource(move || {
        let slug = invites_slug.clone();
        let _ = refresh_key.read();
        async move { orgs::list_invitations(&slug).await }
    });

    let mut invite_email = use_signal(String::new);
    let mut invite_role = use_signal(|| MembershipRole::Member);
    let mut submitting = use_signal(|| false);

    let slug_for_submit = slug.clone();
    let submit_invite = move |evt: Event<FormData>| {
        evt.prevent_default();
        if submitting() || invite_email().is_empty() {
            return;
        }
        let slug = slug_for_submit.clone();
        let req = orgs::CreateInvitationRequest {
            email: invite_email(),
            role: invite_role(),
        };
        spawn(async move {
            submitting.set(true);
            match orgs::create_invitation(&slug, &req).await {
                Ok(_) => {
                    toast.success("Invitation sent. The accept link is in the dev log.");
                    invite_email.set(String::new());
                    refresh_key.set(refresh_key() + 1);
                }
                Err(e) => toast.error(e.user_message()),
            }
            submitting.set(false);
        });
    };

    rsx! {
        AppShell { title: format!("Members · {slug}"),
            div { class: "max-w-4xl mx-auto",
                Link { to: Route::OrgListPage {}, class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 underline",
                    "← All organizations"
                }
                h1 { class: "mt-3 text-2xl font-bold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50",
                    "Members"
                }
                p { class: "mt-1 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                    "Invite teammates and manage their roles."
                }

                section { class: "mt-6 p-6 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800",
                    h2 { class: "font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50", "Invite a teammate" }
                    form { class: "mt-4 grid md:grid-cols-[1fr_140px_auto] gap-3 items-end", onsubmit: submit_invite,
                        label { class: "block",
                            span { class: "text-xs font-medium text-bunyip-reed-800 dark:text-bunyip-reed-100", "Email" }
                            input {
                                class: "mt-1 w-full px-3 py-2 rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                r#type: "email",
                                placeholder: "teammate@example.com",
                                value: "{invite_email()}",
                                oninput: move |e| invite_email.set(e.value()),
                            }
                        }
                        label { class: "block",
                            span { class: "text-xs font-medium text-bunyip-reed-800 dark:text-bunyip-reed-100", "Role" }
                            select {
                                class: "mt-1 w-full px-3 py-2 rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800",
                                value: "{role_to_str(&invite_role())}",
                                onchange: move |e| invite_role.set(str_to_role(&e.value())),
                                option { value: "member", "Member" }
                                option { value: "admin", "Admin" }
                                option { value: "owner", "Owner" }
                            }
                        }
                        button {
                            class: "px-4 py-2 rounded-lg bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 disabled:opacity-60",
                            r#type: "submit",
                            disabled: submitting(),
                            if submitting() { "Sending…" } else { "Invite" }
                        }
                    }
                }

                section { class: "mt-6 p-6 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800",
                    h2 { class: "font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50", "Pending invitations" }
                    div { class: "mt-4 divide-y divide-bunyip-reed-50 dark:divide-bunyip-reed-700",
                        match &*invites.read_unchecked() {
                            None => rsx! { p { class: "py-3 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "Loading…" } },
                            Some(Err(e)) => rsx! { p { class: "py-3 text-sm text-red-700", "{e.user_message()}" } },
                            Some(Ok(list)) if list.is_empty() => rsx! { p { class: "py-3 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300", "None pending." } },
                            Some(Ok(list)) => {
                                let slug = slug.clone();
                                rsx! {
                                    for inv in list.iter() {
                                        InvitationRow { invite: inv.clone(), slug: slug.clone(), refresh_key: refresh_key, toast: toast }
                                    }
                                }
                            }
                        }
                    }
                }

                section { class: "mt-6 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800",
                    h2 { class: "p-6 pb-3 font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50", "All members" }
                    div { class: "divide-y divide-bunyip-reed-50 dark:divide-bunyip-reed-700",
                        match &*members.read_unchecked() {
                            None => rsx! { p { class: "p-6 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "Loading…" } },
                            Some(Err(e)) => rsx! { p { class: "p-6 text-sm text-red-700", "{e.user_message()}" } },
                            Some(Ok(list)) if list.is_empty() => rsx! { p { class: "p-6 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300", "No members yet." } },
                            Some(Ok(list)) => {
                                let slug = slug.clone();
                                rsx! {
                                    for m in list.iter() {
                                        MemberRow { member: m.clone(), slug: slug.clone(), refresh_key: refresh_key, toast: toast }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn InvitationRow(
    invite: crate::api::orgs::Invitation,
    slug: String,
    refresh_key: Signal<u64>,
    toast: crate::stores::toast::ToastStore,
) -> Element {
    let invite_id = invite.id.clone();
    let slug_for_revoke = slug.clone();
    let mut refresh_key = refresh_key;

    let revoke = move |_| {
        let id = invite_id.clone();
        let slug = slug_for_revoke.clone();
        spawn(async move {
            match orgs::revoke_invitation(&slug, &id).await {
                Ok(()) => {
                    toast.info("Invitation revoked.");
                    refresh_key.set(refresh_key() + 1);
                }
                Err(e) => toast.error(e.user_message()),
            }
        });
    };

    rsx! {
        div { class: "py-3 flex items-center justify-between gap-4",
            div {
                p { class: "text-sm text-bunyip-reed-900 dark:text-bunyip-reed-50", "{invite.email}" }
                p { class: "text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300",
                    "Role: {role_label(&invite.role)} · token "
                    span { class: "font-mono", "{short_token(&invite.token)}" }
                }
            }
            button {
                class: "px-3 py-1.5 rounded border border-red-200 text-red-700 text-sm hover:bg-red-50",
                onclick: revoke,
                "Revoke"
            }
        }
    }
}

fn short_token(token: &str) -> String {
    if token.len() > 14 {
        format!("{}…{}", &token[..6], &token[token.len() - 4..])
    } else {
        token.to_string()
    }
}

#[component]
fn MemberRow(
    member: MemberBrief,
    slug: String,
    refresh_key: Signal<u64>,
    toast: crate::stores::toast::ToastStore,
) -> Element {
    let user_id = member.user.id.clone();
    let slug_for_remove = slug.clone();
    let slug_for_role = slug.clone();
    let mut refresh_key = refresh_key;
    let role = member.role;
    let user_id_for_role = user_id.clone();

    let remove = move |_| {
        let id = user_id.clone();
        let slug = slug_for_remove.clone();
        spawn(async move {
            match orgs::remove_member(&slug, &id).await {
                Ok(()) => {
                    toast.info("Member removed.");
                    refresh_key.set(refresh_key() + 1);
                }
                Err(e) => toast.error(e.user_message()),
            }
        });
    };

    let change_role = move |evt: Event<FormData>| {
        let value = evt.value();
        let new_role = str_to_role(&value);
        let id = user_id_for_role.clone();
        let slug = slug_for_role.clone();
        spawn(async move {
            match orgs::change_member_role(&slug, &id, new_role).await {
                Ok(()) => {
                    toast.success("Role updated.");
                    refresh_key.set(refresh_key() + 1);
                }
                Err(e) => toast.error(e.user_message()),
            }
        });
    };

    let is_owner_row = matches!(role, MembershipRole::Owner);

    rsx! {
        div { class: "px-6 py-4 flex items-center justify-between gap-4",
            div { class: "min-w-0",
                p { class: "text-sm font-medium text-bunyip-reed-900 dark:text-bunyip-reed-50 truncate", "{member.user.name}" }
                p { class: "text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300 truncate", "{member.user.email}" }
            }
            div { class: "flex items-center gap-3",
                if is_owner_row {
                    span { class: "px-2 py-0.5 rounded-full bg-bunyip-reed-50 dark:bg-bunyip-reed-900 border border-bunyip-reed-100 dark:border-bunyip-reed-700 text-xs uppercase tracking-wide text-bunyip-reed-700 dark:text-bunyip-reed-200",
                        "Owner"
                    }
                } else {
                    select {
                        class: "px-2 py-1.5 rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 text-sm",
                        value: "{role_to_str(&role)}",
                        onchange: change_role,
                        option { value: "member", "Member" }
                        option { value: "admin", "Admin" }
                    }
                    button {
                        class: "px-3 py-1.5 rounded border border-red-200 text-red-700 text-sm hover:bg-red-50",
                        onclick: remove,
                        "Remove"
                    }
                }
            }
        }
    }
}

fn role_to_str(r: &MembershipRole) -> &'static str {
    match r {
        MembershipRole::Owner => "owner",
        MembershipRole::Admin => "admin",
        MembershipRole::Member => "member",
    }
}

fn str_to_role(s: &str) -> MembershipRole {
    match s {
        "owner" => MembershipRole::Owner,
        "admin" => MembershipRole::Admin,
        _ => MembershipRole::Member,
    }
}
