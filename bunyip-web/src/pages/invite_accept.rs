//! `/invite/:token` - admin-invite accept (the link in invitation emails).
//!
//! Two branches based on the preview's `kind`:
//!   * `new_account` - no Mokosh user owns this email yet. Show a
//!     password + name form; POST creates the user in the inviter's
//!     tenant under SERIALIZABLE.
//!   * `join_tenant` - the email already belongs to an existing user.
//!     Show a confirmation card; POST adds the membership. The user
//!     keeps their existing password.
//!
//! Distinct from `pages/invitations.rs` (`AcceptInvitationPage`), which
//! handles org-scoped invitations (mokosh-server's `/v1/invitations`
//! surface). This page is the *admin-invite* flow that mints fresh
//! user accounts.

use dioxus::prelude::*;

use crate::api;
use crate::api::auth::{InviteAcceptRequest, InvitePreview};
use crate::components::layout::AuthShell;
use crate::components::password_checklist::{password_meets_policy, PasswordChecklist};
use crate::routes::Route;
use crate::stores::toast::use_toast;

#[derive(Default, Clone, PartialEq)]
struct State {
    first_name: String,
    last_name: String,
    password: String,
    submitting: bool,
    preview_loaded: bool,
    preview: Option<InvitePreview>,
    error: Option<String>,
}

#[component]
pub fn InviteAcceptPage(token: String) -> Element {
    let nav = navigator();
    let toast = use_toast();
    let mut state = use_signal(State::default);

    let preview_token = token.clone();
    use_future(move || {
        let token = preview_token.clone();
        async move {
            match api::auth::invite_preview(&token).await {
                Ok(p) => state.with_mut(|s| {
                    s.preview_loaded = true;
                    s.preview = Some(p);
                }),
                Err(_) => state.with_mut(|s| {
                    s.preview_loaded = true;
                    s.error = Some("This invite link is invalid or has expired.".into());
                }),
            }
        }
    });

    let submit_token = token.clone();
    let submit = move |evt: Event<FormData>| {
        evt.prevent_default();
        if state.read().submitting {
            return;
        }
        let preview = match state.read().preview.clone() {
            Some(p) => p,
            None => return,
        };
        let req = InviteAcceptRequest {
            password: if preview.kind == "new_account" {
                Some(state.read().password.clone())
            } else {
                None
            },
            first_name: Some(state.read().first_name.clone()).filter(|s| !s.trim().is_empty()),
            last_name: Some(state.read().last_name.clone()).filter(|s| !s.trim().is_empty()),
        };
        let token = submit_token.clone();
        spawn(async move {
            state.with_mut(|s| {
                s.submitting = true;
                s.error = None;
            });
            match api::auth::invite_accept(&token, &req).await {
                Ok(_) => {
                    toast.success("Invite accepted. Sign in to continue.");
                    nav.replace(Route::LoginPage {});
                }
                Err(e) => state.with_mut(|s| {
                    s.submitting = false;
                    s.error = Some(e.user_message());
                }),
            }
        });
    };

    let preview = state.read().preview.clone();
    let subtitle = preview
        .as_ref()
        .map(|p| {
            format!(
                "{} ({}) invited you to join {} as {}.",
                p.invited_by_name, p.invited_by_email, p.tenant_name, p.role
            )
        })
        .unwrap_or_default();

    rsx! {
        AuthShell {
            title: "Accept your invite",
            subtitle: subtitle,
            match (state.read().preview_loaded, state.read().error.clone(), preview.clone()) {
                (false, _, _) => rsx! {
                    p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "Checking your invite link..." }
                },
                (true, None, None) => rsx! {
                    p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200", "Checking your invite link..." }
                },
                (true, Some(err), None) => rsx! {
                    div { class: "p-4 rounded-lg border border-red-200 bg-red-50 text-sm text-red-800",
                        "{err}"
                    }
                    div { class: "mt-4 text-center text-sm",
                        Link { to: Route::LoginPage {}, class: "underline text-bunyip-reed-700 dark:text-bunyip-reed-200",
                            "Back to sign in"
                        }
                    }
                },
                (_, _, Some(p)) => {
                    let kind = p.kind.clone();
                    let email = p.email.clone();
                    let password = state.read().password.clone();
                    let policy_ok = kind != "new_account" || password_meets_policy(&password, &email);
                    let submitting = state.read().submitting;
                    rsx! {
                        form { class: "space-y-4", onsubmit: submit,
                            if let Some(err) = state.read().error.clone() {
                                div { class: "p-3 rounded-lg border border-red-200 bg-red-50 text-sm text-red-800",
                                    "{err}"
                                }
                            }
                            div { class: "p-3 rounded-lg border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-bunyip-reed-50 dark:bg-bunyip-reed-900 text-sm",
                                p { class: "text-bunyip-reed-900 dark:text-bunyip-reed-50",
                                    "You're accepting as "
                                    span { class: "font-mono", "{email}" }
                                }
                            }
                            if kind == "new_account" {
                                label { class: "block",
                                    span { class: "text-xs font-medium text-bunyip-reed-800 dark:text-bunyip-reed-100", "First name" }
                                    input {
                                        class: "mt-1 w-full px-3 py-2 rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                        r#type: "text",
                                        value: "{state.read().first_name}",
                                        oninput: move |e| { state.write().first_name = e.value(); },
                                    }
                                }
                                label { class: "block",
                                    span { class: "text-xs font-medium text-bunyip-reed-800 dark:text-bunyip-reed-100", "Last name" }
                                    input {
                                        class: "mt-1 w-full px-3 py-2 rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                        r#type: "text",
                                        value: "{state.read().last_name}",
                                        oninput: move |e| { state.write().last_name = e.value(); },
                                    }
                                }
                                label { class: "block",
                                    span { class: "text-xs font-medium text-bunyip-reed-800 dark:text-bunyip-reed-100", "Password" }
                                    input {
                                        class: "mt-1 w-full px-3 py-2 rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                        r#type: "password",
                                        value: "{password}",
                                        oninput: move |e| { state.write().password = e.value(); },
                                    }
                                }
                                PasswordChecklist { password: password.clone(), email: email.clone() }
                            } else {
                                p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                    "You already have an account with this email. Accepting will add you to "
                                    span { class: "font-medium", "{p.tenant_name}" }
                                    " and keep your existing password."
                                }
                            }
                            button {
                                r#type: "submit",
                                disabled: submitting || !policy_ok,
                                class: "w-full px-4 py-2 rounded-lg bg-bunyip-reed-700 text-white text-sm font-medium hover:bg-bunyip-reed-800 disabled:opacity-60",
                                if submitting { "Accepting..." } else if kind == "new_account" { "Create account" } else { "Accept invite" }
                            }
                        }
                    }
                }
            }
        }
    }
}
