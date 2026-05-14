//! `/admin/users` - list users with search + filters + pagination,
//! suspend/reactivate, admin-force MFA disenroll. Click a row to open
//! the detail page (`/admin/users/:id`).
//!
//! See docs/bunyip-settings/04-ui.md for the design.

use chrono::{DateTime, Utc};
use dioxus::prelude::*;

use crate::api::admin::{self, UserListFilter, UserView};
use crate::components::layout::AppShell;
use crate::routes::Route;
use crate::stores::auth::{use_auth, use_require_role};
use crate::stores::toast::use_toast;

const PAGE_SIZE: u32 = 50;

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

fn status_label(s: &str) -> &'static str {
    match s {
        "active" => "Active",
        "suspended" => "Suspended",
        "pending" => "Pending",
        "deleted" => "Deleted",
        _ => "Unknown",
    }
}

fn status_badge_class(s: &str) -> &'static str {
    match s {
        "active" => "bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300",
        "suspended" => {
            "bg-bunyip-reed-100 text-bunyip-reed-800 dark:bg-bunyip-reed-700 dark:text-bunyip-reed-200"
        }
        "pending" => "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300",
        "deleted" => "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300",
        _ => "bg-bunyip-reed-100 text-bunyip-reed-800 dark:bg-bunyip-reed-700 dark:text-bunyip-reed-200",
    }
}

fn display_name(u: &UserView) -> String {
    match (u.first_name.as_deref(), u.last_name.as_deref()) {
        (Some(f), Some(l)) if !f.is_empty() && !l.is_empty() => format!("{f} {l}"),
        (Some(f), _) if !f.is_empty() => f.to_string(),
        (_, Some(l)) if !l.is_empty() => l.to_string(),
        _ => u.email.clone(),
    }
}

fn relative_time(ts: DateTime<Utc>) -> String {
    let d = Utc::now() - ts;
    if d < chrono::Duration::minutes(1) {
        "just now".into()
    } else if d < chrono::Duration::hours(1) {
        format!("{} min ago", d.num_minutes())
    } else if d < chrono::Duration::days(1) {
        format!("{}h ago", d.num_hours())
    } else if d < chrono::Duration::days(30) {
        format!("{}d ago", d.num_days())
    } else {
        ts.format("%Y-%m-%d").to_string()
    }
}

#[component]
pub fn UserManagementPage() -> Element {
    use_require_role("admin");
    let nav = navigator();
    let auth = use_auth();
    let toast = use_toast();
    let my_id: String = auth
        .read()
        .me()
        .map(|me| me.user.id.clone())
        .unwrap_or_default();

    let mut search = use_signal(String::new);
    let mut role_filter = use_signal(String::new);
    let mut status_filter = use_signal(String::new);
    let mut mfa_filter = use_signal(String::new);
    let mut offset = use_signal(|| 0u32);

    let mut invites_count: Signal<Option<usize>> = use_signal(|| None);
    let mut busy: Signal<Option<String>> = use_signal(|| None);
    let mut disenroll_for: Signal<Option<UserView>> = use_signal(|| None);

    // `use_resource` is the reactive variant of `use_future`: it tracks
    // every signal read inside its closure via a ReactiveContext and
    // re-runs the future whenever any of them changes. `use_future`
    // would run ONCE on mount and never react to filter input - that's
    // the bug we hit pre-refactor where the search box did nothing.
    let mut page = use_resource(move || async move {
        let filter = UserListFilter {
            search: Some(search.read().trim().to_string()).filter(|s| !s.is_empty()),
            role: Some(role_filter.read().trim().to_string()).filter(|s| !s.is_empty()),
            status: Some(status_filter.read().trim().to_string()).filter(|s| !s.is_empty()),
            mfa_enrolled: match mfa_filter.read().as_str() {
                "yes" => Some(true),
                "no" => Some(false),
                _ => None,
            },
            limit: PAGE_SIZE,
            offset: *offset.read(),
        };
        let r = admin::list_users(&filter)
            .await
            .map_err(|e| e.user_message());
        // Side-fetch the pending-invites count; failures are
        // non-fatal and we just leave the badge blank.
        invites_count.set(admin::list_invites().await.ok().map(|v| v.len()));
        r
    });

    let refetch = use_callback(move |_| {
        // restart() re-fires the resource's future with the current
        // signal values. Used by mutation handlers (suspend, etc.)
        // that need a fresh list AFTER they wrote to the server.
        page.restart();
    });
    let reset_offset = use_callback(move |_| {
        offset.set(0);
    });

    let toggle_status = use_callback(move |(id, currently_active): (String, bool)| {
        busy.set(Some(id.clone()));
        spawn(async move {
            let r = if currently_active {
                admin::suspend_user(&id).await
            } else {
                admin::reactivate_user(&id).await
            };
            busy.set(None);
            match r {
                Ok(()) => {
                    toast.success(if currently_active {
                        "User suspended."
                    } else {
                        "User reactivated."
                    });
                    refetch.call(());
                }
                Err(e) => toast.error(e.user_message()),
            }
        });
    });

    rsx! {
        AppShell {
            title: "User management".to_string(),
            back_to: Some(Route::SettingsPage {}),
            back_label: "Settings".to_string(),
            div { class: "max-w-6xl mx-auto px-6 space-y-6",
                div { class: "flex items-start justify-between gap-4 flex-wrap",
                    div {
                        h1 { class: "text-3xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                            "User management"
                        }
                        p { class: "mt-1 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                            "Click a row to open the user's detail page."
                        }
                    }
                    div { class: "flex gap-2",
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                            onclick: move |_| { nav.push(Route::InviteListPage {}); },
                            if let Some(n) = *invites_count.read() {
                                "Pending invites ({n})"
                            } else {
                                "Pending invites"
                            }
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 rounded-md bg-bunyip-reed-700 text-white text-sm font-medium hover:bg-bunyip-reed-800",
                            onclick: move |_| { nav.push(Route::InviteCreatePage {}); },
                            "Invite user"
                        }
                    }
                }

                div { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 p-4",
                    div { class: "flex gap-2 items-end flex-wrap",
                        div { class: "flex-1 min-w-[16rem]",
                            label { class: "block text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 mb-1",
                                "Search"
                            }
                            input {
                                r#type: "text",
                                placeholder: "name or email",
                                class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{search.read()}",
                                oninput: move |e: Event<FormData>| {
                                    search.set(e.value());
                                    reset_offset.call(());
                                },
                            }
                        }
                        div {
                            label { class: "block text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 mb-1",
                                "Role"
                            }
                            select {
                                class: "block rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{role_filter.read()}",
                                onchange: move |e: Event<FormData>| {
                                    role_filter.set(e.value());
                                    reset_offset.call(());
                                },
                                option { value: "", "All roles" }
                                option { value: "admin", "Admin" }
                                option { value: "manager", "Manager" }
                                option { value: "finance", "Finance" }
                                option { value: "member", "Member" }
                                option { value: "readonly", "Read only" }
                            }
                        }
                        div {
                            label { class: "block text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 mb-1",
                                "Status"
                            }
                            select {
                                class: "block rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{status_filter.read()}",
                                onchange: move |e: Event<FormData>| {
                                    status_filter.set(e.value());
                                    reset_offset.call(());
                                },
                                option { value: "", "All statuses" }
                                option { value: "active", "Active" }
                                option { value: "suspended", "Suspended" }
                                option { value: "pending", "Pending" }
                            }
                        }
                        div {
                            label { class: "block text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 mb-1",
                                "MFA"
                            }
                            select {
                                class: "block rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{mfa_filter.read()}",
                                onchange: move |e: Event<FormData>| {
                                    mfa_filter.set(e.value());
                                    reset_offset.call(());
                                },
                                option { value: "", "Any" }
                                option { value: "yes", "Enrolled" }
                                option { value: "no", "Not enrolled" }
                            }
                        }
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                            onclick: move |_| {
                                search.set(String::new());
                                role_filter.set(String::new());
                                status_filter.set(String::new());
                                mfa_filter.set(String::new());
                                reset_offset.call(());
                            },
                            "Reset"
                        }
                    }
                }

                div { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 overflow-hidden",
                    match page.read().clone() {
                        None => rsx! {
                            div { class: "p-8 text-center text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                "Loading..."
                            }
                        },
                        Some(Err(msg)) => rsx! {
                            div { class: "p-4 bg-red-50 dark:bg-red-900/20 border-b border-red-200 dark:border-red-800",
                                p { class: "text-sm text-red-700 dark:text-red-300", "Could not load users: {msg}" }
                            }
                        },
                        Some(Ok(body)) if body.users.is_empty() => rsx! {
                            div { class: "p-8 text-center text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                "No users match the current filters."
                            }
                        },
                        Some(Ok(body)) => {
                            let total = body.total;
                            let limit = body.limit.max(1) as u64;
                            let off = body.offset as u64;
                            let shown = body.users.len() as u64;
                            rsx! {
                                table { class: "min-w-full divide-y divide-bunyip-reed-100 dark:divide-bunyip-reed-700",
                                    thead { class: "bg-bunyip-reed-50 dark:bg-bunyip-reed-900",
                                        tr {
                                            th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "User" }
                                            th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Role" }
                                            th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Status" }
                                            th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "MFA" }
                                            th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Last login" }
                                            th { class: "px-6 py-3" }
                                        }
                                    }
                                    tbody { class: "bg-white dark:bg-bunyip-reed-800 divide-y divide-bunyip-reed-100 dark:divide-bunyip-reed-700",
                                        for u in body.users.iter().cloned() {
                                            UserRow {
                                                key: "{u.id}",
                                                user: u.clone(),
                                                is_self: u.id == my_id,
                                                busy_id: busy.read().clone(),
                                                on_toggle: {
                                                    let id = u.id.clone();
                                                    let active = u.status == "active";
                                                    move |_| toggle_status.call((id.clone(), active))
                                                },
                                                on_disenroll: {
                                                    let user = u.clone();
                                                    move |_| disenroll_for.set(Some(user.clone()))
                                                },
                                            }
                                        }
                                    }
                                }
                                div { class: "flex items-center justify-between gap-2 px-4 py-3 border-t border-bunyip-reed-100 dark:border-bunyip-reed-700",
                                    span { class: "text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                                        if total == 0 {
                                            "No rows"
                                        } else {
                                            "Showing {off + 1}-{off + shown} of {total}"
                                        }
                                    }
                                    div { class: "flex gap-2",
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-50",
                                            disabled: off == 0,
                                            onclick: move |_| {
                                                let cur = *offset.read();
                                                offset.set(cur.saturating_sub(PAGE_SIZE));
                                            },
                                            "Previous"
                                        }
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-50",
                                            disabled: off + shown >= total,
                                            onclick: move |_| {
                                                offset.with_mut(|o| *o += limit as u32);
                                            },
                                            "Next"
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }

            if let Some(target) = disenroll_for.read().clone() {
                DisenrollMfaModal {
                    user: target,
                    on_close: move |_| disenroll_for.set(None),
                    on_done: move |_| {
                        disenroll_for.set(None);
                        refetch.call(());
                    },
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct UserRowProps {
    user: UserView,
    is_self: bool,
    busy_id: Option<String>,
    on_toggle: EventHandler<()>,
    on_disenroll: EventHandler<()>,
}

#[component]
fn UserRow(props: UserRowProps) -> Element {
    let u = &props.user;
    let name = display_name(u);
    let initial = name
        .chars()
        .next()
        .unwrap_or('?')
        .to_string()
        .to_uppercase();
    let active = u.status == "active";
    let busy = props.busy_id.as_deref() == Some(u.id.as_str());
    let last = u
        .last_login_at
        .map(relative_time)
        .unwrap_or_else(|| "never".to_string());
    let row_link = Route::UserDetailPage {
        user_id: u.id.clone(),
    };

    rsx! {
        tr {
            td { class: "px-6 py-4 whitespace-nowrap",
                Link {
                    to: row_link.clone(),
                    class: "flex items-center gap-3 group",
                    div { class: "w-10 h-10 rounded-full bg-bunyip-reed-100 dark:bg-bunyip-reed-700 flex items-center justify-center",
                        span { class: "text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200",
                            "{initial}"
                        }
                    }
                    div { class: "ml-1",
                        div { class: "text-sm font-medium text-bunyip-reed-900 dark:text-bunyip-reed-50 group-hover:text-bunyip-reed-700 dark:group-hover:text-white",
                            "{name}"
                            if props.is_self {
                                span { class: "ml-2 text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400", "(you)" }
                            }
                        }
                        div { class: "text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400", "{u.email}" }
                    }
                }
            }
            td { class: "px-6 py-4 whitespace-nowrap",
                span { class: "inline-flex px-2 py-0.5 rounded-full text-xs font-medium {role_badge_class(&u.role)}",
                    "{role_label(&u.role)}"
                }
            }
            td { class: "px-6 py-4 whitespace-nowrap",
                span { class: "inline-flex px-2 py-0.5 rounded-full text-xs font-medium {status_badge_class(&u.status)}",
                    "{status_label(&u.status)}"
                }
            }
            td { class: "px-6 py-4 whitespace-nowrap text-sm",
                if u.mfa_enrolled {
                    span { class: "text-bunyip-reed-700 dark:text-bunyip-reed-200", "Enrolled" }
                } else {
                    span { class: "text-bunyip-reed-400", "Not enrolled" }
                }
            }
            td { class: "px-6 py-4 whitespace-nowrap text-sm text-bunyip-reed-500 dark:text-bunyip-reed-400",
                "{last}"
            }
            td { class: "px-6 py-4 whitespace-nowrap text-right text-sm",
                div { class: "flex gap-2 justify-end",
                    if u.mfa_enrolled && !props.is_self {
                        button {
                            r#type: "button",
                            class: "px-3 py-1.5 rounded-md border border-red-300 dark:border-red-700 text-xs text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30",
                            onclick: move |_| props.on_disenroll.call(()),
                            "Disenroll MFA"
                        }
                    }
                    if !props.is_self {
                        button {
                            r#type: "button",
                            class: if active {
                                "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-xs text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-60"
                            } else {
                                "px-3 py-1.5 rounded-md bg-bunyip-reed-700 text-white text-xs font-medium hover:bg-bunyip-reed-800 disabled:opacity-60"
                            },
                            disabled: busy,
                            onclick: move |_| props.on_toggle.call(()),
                            if busy { "..." } else if active { "Suspend" } else { "Reactivate" }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct DisenrollMfaModalProps {
    user: UserView,
    on_close: EventHandler<()>,
    on_done: EventHandler<()>,
}

#[component]
fn DisenrollMfaModal(props: DisenrollMfaModalProps) -> Element {
    let toast = use_toast();
    let mut reason = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error: Signal<Option<String>> = use_signal(|| None);

    let user_id = props.user.id.clone();
    let user_email = props.user.email.clone();

    let submit = use_callback(move |_| {
        let id = user_id.clone();
        let r = reason.read().trim().to_string();
        if r.is_empty() {
            error.set(Some("A reason is required.".into()));
            return;
        }
        spawn(async move {
            submitting.set(true);
            error.set(None);
            let result = admin::force_disenroll_mfa(&id, &r).await;
            submitting.set(false);
            match result {
                Ok(()) => {
                    toast.success("MFA disenrolled.");
                    props.on_done.call(());
                }
                Err(e) => error.set(Some(e.user_message())),
            }
        });
    });

    rsx! {
        div { class: "fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4",
            div { class: "w-full max-w-md rounded-xl bg-white dark:bg-bunyip-reed-800 border border-bunyip-reed-100 dark:border-bunyip-reed-700 shadow-xl p-6 space-y-4",
                h2 { class: "text-lg font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                    "Disenroll MFA"
                }
                p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                    "This will remove MFA from "
                    span { class: "font-mono", "{user_email}" }
                    ". They will be prompted to re-enroll on next sign-in. The user will be notified by email."
                }
                if let Some(msg) = error.read().as_ref() {
                    p { class: "text-sm text-red-700 dark:text-red-300", "{msg}" }
                }
                div {
                    label {
                        class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                        r#for: "disenroll-reason",
                        "Reason (required)"
                    }
                    textarea {
                        id: "disenroll-reason",
                        rows: "3",
                        class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-sm text-bunyip-reed-900 dark:text-bunyip-reed-50 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                        placeholder: "User lost their device; verified identity by phone.",
                        value: "{reason.read()}",
                        oninput: move |e: Event<FormData>| reason.set(e.value()),
                    }
                }
                div { class: "flex justify-end gap-2 pt-2",
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                        onclick: move |_| props.on_close.call(()),
                        "Cancel"
                    }
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-md bg-red-600 text-white text-sm font-medium hover:bg-red-700 disabled:opacity-60",
                        disabled: *submitting.read(),
                        onclick: move |_| submit.call(()),
                        if *submitting.read() { "Disenrolling..." } else { "Disenroll MFA" }
                    }
                }
            }
        }
    }
}
