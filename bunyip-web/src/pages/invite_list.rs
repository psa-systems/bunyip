//! `/admin/users/invites` - pending invites with resend + revoke (admin-only).

use chrono::{DateTime, Utc};
use dioxus::prelude::*;

use crate::api::admin::{self, InviteView};
use crate::components::layout::AppShell;
use crate::routes::Route;
use crate::stores::auth::use_require_role;
use crate::stores::toast::use_toast;

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

fn role_badge_class(role: &str) -> &'static str {
    match role {
        "admin" => "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300",
        "manager" => "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300",
        "finance" => "bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300",
        _ => "bg-bunyip-reed-100 text-bunyip-reed-800 dark:bg-bunyip-reed-700 dark:text-bunyip-reed-200",
    }
}

fn relative(ts: DateTime<Utc>) -> String {
    let now = Utc::now();
    if ts > now {
        let d = ts - now;
        if d < chrono::Duration::minutes(1) {
            "<1 min".into()
        } else if d < chrono::Duration::hours(1) {
            format!("in {} min", d.num_minutes())
        } else if d < chrono::Duration::days(1) {
            format!("in {}h", d.num_hours())
        } else {
            format!("in {}d", d.num_days())
        }
    } else {
        let d = now - ts;
        if d < chrono::Duration::minutes(1) {
            "just now".into()
        } else if d < chrono::Duration::hours(1) {
            format!("{} min ago", d.num_minutes())
        } else if d < chrono::Duration::days(1) {
            format!("{}h ago", d.num_hours())
        } else {
            format!("{}d ago", d.num_days())
        }
    }
}

#[component]
pub fn InviteListPage() -> Element {
    use_require_role("admin");
    let nav = navigator();
    let mut invites: Signal<Option<Result<Vec<InviteView>, String>>> = use_signal(|| None);
    let mut bump = use_signal(|| 0u32);

    use_future(move || async move {
        let _ = bump.read();
        invites.set(None);
        let r = admin::list_invites().await.map_err(|e| e.user_message());
        invites.set(Some(r));
    });

    let refetch = use_callback(move |_| {
        bump.with_mut(|n| *n += 1);
    });

    rsx! {
        AppShell { title: "Pending invites".to_string(),
            div { class: "max-w-5xl mx-auto px-6 space-y-6",
                div {
                    Link {
                        to: Route::UserManagementPage {},
                        class: "text-sm text-bunyip-reed-600 hover:text-bunyip-reed-900 dark:text-bunyip-reed-300 dark:hover:text-bunyip-reed-50",
                        "← Back to user management"
                    }
                }
                div { class: "flex items-start justify-between gap-4",
                    div {
                        h1 { class: "text-3xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                            "Pending invites"
                        }
                        p { class: "mt-1 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                            "Outstanding invitations that have not yet been accepted."
                        }
                    }
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-md bg-bunyip-reed-700 text-white text-sm font-medium hover:bg-bunyip-reed-800",
                        onclick: move |_| { nav.push(Route::InviteCreatePage {}); },
                        "Invite a teammate"
                    }
                }

                match invites.read().clone() {
                    None => rsx! {
                        div { class: "p-8 text-center text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                            "Loading..."
                        }
                    },
                    Some(Err(msg)) => rsx! {
                        div { class: "rounded-md bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4",
                            p { class: "text-sm text-red-700 dark:text-red-300", "{msg}" }
                        }
                    },
                    Some(Ok(rows)) if rows.is_empty() => rsx! {
                        div { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 p-8 text-center space-y-3",
                            p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                "No pending invites."
                            }
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 rounded-md bg-bunyip-reed-700 text-white text-sm font-medium hover:bg-bunyip-reed-800",
                                onclick: move |_| { nav.push(Route::InviteCreatePage {}); },
                                "Invite the first teammate"
                            }
                        }
                    },
                    Some(Ok(rows)) => rsx! {
                        div { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 overflow-hidden",
                            table { class: "min-w-full divide-y divide-bunyip-reed-100 dark:divide-bunyip-reed-700",
                                thead { class: "bg-bunyip-reed-50 dark:bg-bunyip-reed-900",
                                    tr {
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Email" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Role" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Invited by" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Issued" }
                                        th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Expires" }
                                        th { class: "px-6 py-3" }
                                    }
                                }
                                tbody { class: "bg-white dark:bg-bunyip-reed-800 divide-y divide-bunyip-reed-100 dark:divide-bunyip-reed-700",
                                    for invite in rows {
                                        InviteRow {
                                            key: "{invite.id}",
                                            invite: invite.clone(),
                                            on_changed: move |_| refetch.call(()),
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct InviteRowProps {
    invite: InviteView,
    on_changed: EventHandler<()>,
}

#[component]
fn InviteRow(props: InviteRowProps) -> Element {
    let toast = use_toast();
    let mut busy = use_signal(|| false);
    let invite = props.invite.clone();
    let id_resend = invite.id.clone();
    let id_revoke = invite.id.clone();

    let resend = move |_| {
        let id = id_resend.clone();
        spawn(async move {
            busy.set(true);
            let r = admin::resend_invite(&id).await;
            busy.set(false);
            match r {
                Ok(_) => {
                    toast.success("Invite resent.");
                    props.on_changed.call(());
                }
                Err(e) => toast.error(e.user_message()),
            }
        });
    };

    let revoke = move |_| {
        let id = id_revoke.clone();
        spawn(async move {
            busy.set(true);
            let r = admin::revoke_invite(&id).await;
            busy.set(false);
            match r {
                Ok(()) => {
                    toast.success("Invite revoked.");
                    props.on_changed.call(());
                }
                Err(e) => toast.error(e.user_message()),
            }
        });
    };

    let issued = relative(invite.issued_at);
    let expires = if invite.expires_at < Utc::now() {
        "expired".to_string()
    } else {
        relative(invite.expires_at)
    };

    rsx! {
        tr {
            td { class: "px-6 py-4 whitespace-nowrap text-sm text-bunyip-reed-900 dark:text-bunyip-reed-50",
                "{invite.email}"
            }
            td { class: "px-6 py-4 whitespace-nowrap",
                span { class: "inline-flex px-2 py-0.5 rounded-full text-xs font-medium {role_badge_class(&invite.role)}",
                    "{role_label(&invite.role)}"
                }
            }
            td { class: "px-6 py-4 whitespace-nowrap text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                "{invite.invited_by.email}"
            }
            td { class: "px-6 py-4 whitespace-nowrap text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                "{issued}"
            }
            td { class: "px-6 py-4 whitespace-nowrap text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                "{expires}"
            }
            td { class: "px-6 py-4 whitespace-nowrap text-right",
                div { class: "flex gap-2 justify-end",
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-xs text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-60",
                        disabled: *busy.read(),
                        onclick: resend,
                        "Resend"
                    }
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-md border border-red-300 dark:border-red-700 text-xs text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30 disabled:opacity-60",
                        disabled: *busy.read(),
                        onclick: revoke,
                        "Revoke"
                    }
                }
            }
        }
    }
}
