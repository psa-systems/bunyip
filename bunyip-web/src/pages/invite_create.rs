//! `/admin/users/invite` - issue a new invite (admin-only).

use dioxus::prelude::*;
use wasm_bindgen::JsCast;

use crate::api::admin::{self, IssueInviteBody, IssueInviteSuccess};
use crate::api::ApiError;
use crate::components::layout::AppShell;
use crate::routes::Route;
use crate::stores::auth::use_require_role;

/// Cheap client-side check that mirrors mokosh-server's `looks_like_email`
/// (one `@`, at least one char on each side, at least one `.` in the
/// host). The browser's `type=email` is more permissive than the
/// server, so we pre-validate to avoid round-tripping a clearly-bad
/// address.
fn looks_like_email(s: &str) -> bool {
    let s = s.trim();
    let Some(at) = s.find('@') else {
        return false;
    };
    if at == 0 || at == s.len() - 1 {
        return false;
    }
    let (_local, host) = s.split_at(at);
    host[1..].contains('.')
}

fn parse_error_message(err: &ApiError) -> String {
    if let ApiError::Status { message, .. } = err {
        match message.as_str() {
            "invite_already_open" => {
                return "An invite already exists for this email. Use Resend or Revoke first."
                    .to_string();
            }
            "forbidden" => return "Only admins may issue invites.".into(),
            "rate_limited" => {
                return "Too many invites issued recently. Please wait a moment.".into();
            }
            _ => {}
        }
    }
    err.user_message()
}

#[component]
pub fn InviteCreatePage() -> Element {
    use_require_role("admin");
    let nav = navigator();

    let mut email = use_signal(String::new);
    let mut role = use_signal(|| "member".to_string());
    let mut note = use_signal(String::new);
    let mut error: Signal<Option<String>> = use_signal(|| None);
    let mut warning: Signal<Option<String>> = use_signal(|| None);
    let mut submitting = use_signal(|| false);
    let mut success: Signal<Option<IssueInviteSuccess>> = use_signal(|| None);

    let submit = use_callback(move |_| {
        let raw_email = email.read().trim().to_string();
        if !looks_like_email(&raw_email) {
            error.set(Some(
                "That does not look like a valid email address.".into(),
            ));
            return;
        }
        let body = IssueInviteBody {
            email: raw_email,
            role: role.read().clone(),
            note: {
                let n = note.read().trim().to_string();
                if n.is_empty() {
                    None
                } else {
                    Some(n)
                }
            },
        };
        spawn(async move {
            error.set(None);
            warning.set(None);
            submitting.set(true);
            match admin::issue_invite(&body).await {
                Ok(resp) => {
                    if let Some(w) = resp.warning.as_deref() {
                        warning.set(Some(format!(
                            "Invite created but the email failed to send ({w}). Copy the link below and share it manually."
                        )));
                    }
                    success.set(Some(resp));
                    submitting.set(false);
                }
                Err(e) => {
                    error.set(Some(parse_error_message(&e)));
                    submitting.set(false);
                }
            }
        });
    });

    rsx! {
        AppShell {
            title: "Invite user".to_string(),
            back_to: Some(Route::UserManagementPage {}),
            back_label: "User management".to_string(),
            div { class: "max-w-2xl mx-auto px-6 space-y-6",
                if let Some(s) = success.read().clone() {
                    InviteSuccessCard {
                        invite_email: s.invite.email.clone(),
                        accept_url: s.accept_url.clone().unwrap_or_default(),
                        warning: s.warning.clone(),
                        on_invite_another: move |_| {
                            success.set(None);
                            email.set(String::new());
                            note.set(String::new());
                            error.set(None);
                            warning.set(None);
                        },
                        on_done: move |_| { nav.push(Route::InviteListPage {}); },
                    }
                }
                div { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 p-6 space-y-4",
                    div {
                        h1 { class: "text-2xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                            "Invite a teammate"
                        }
                        p { class: "mt-1 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                            "They'll receive a one-time link. Copy it from the success card if you'd rather share it manually."
                        }
                    }

                    form {
                        class: "space-y-4",
                        onsubmit: move |e: Event<FormData>| {
                            e.prevent_default();
                            submit.call(());
                        },

                        if let Some(msg) = error.read().as_ref() {
                            div { class: "rounded-md bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-3",
                                p { class: "text-sm text-red-700 dark:text-red-300", "{msg}" }
                            }
                        }
                        if let Some(msg) = warning.read().as_ref() {
                            div { class: "rounded-md bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 p-3",
                                p { class: "text-sm text-yellow-800 dark:text-yellow-300", "{msg}" }
                            }
                        }

                        div {
                            label { class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                                r#for: "email",
                                "Email"
                            }
                            input {
                                id: "email",
                                r#type: "email",
                                required: true,
                                placeholder: "alice@example.com",
                                class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{email.read()}",
                                oninput: move |e: Event<FormData>| email.set(e.value()),
                            }
                        }

                        div {
                            label { class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                                r#for: "role",
                                "Role"
                            }
                            select {
                                id: "role",
                                class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{role.read()}",
                                onchange: move |e: Event<FormData>| role.set(e.value()),
                                option { value: "member", "Member" }
                                option { value: "manager", "Manager" }
                                option { value: "finance", "Finance" }
                                option { value: "admin", "Admin" }
                                option { value: "readonly", "Read only" }
                            }
                        }

                        div {
                            label { class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                                r#for: "note",
                                "Note (optional)"
                            }
                            input {
                                id: "note",
                                r#type: "text",
                                placeholder: "Welcome aboard!",
                                class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{note.read()}",
                                oninput: move |e: Event<FormData>| note.set(e.value()),
                            }
                            p { class: "mt-1 text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                                "Shown to the invitee on the accept page. Max 200 chars."
                            }
                        }

                        div { class: "flex justify-end gap-2 pt-2",
                            button {
                                r#type: "button",
                                class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                                onclick: move |_| { nav.push(Route::InviteListPage {}); },
                                "Cancel"
                            }
                            button {
                                r#type: "submit",
                                class: "px-3 py-1.5 rounded-md bg-bunyip-reed-700 text-white text-sm font-medium hover:bg-bunyip-reed-800 disabled:opacity-60",
                                disabled: *submitting.read(),
                                if *submitting.read() { "Sending..." } else { "Send invite" }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct InviteSuccessCardProps {
    invite_email: String,
    accept_url: String,
    warning: Option<String>,
    on_invite_another: EventHandler<()>,
    on_done: EventHandler<()>,
}

#[component]
fn InviteSuccessCard(props: InviteSuccessCardProps) -> Element {
    let url = props.accept_url.clone();
    let copy = move |_| {
        if let Some(win) = web_sys::window() {
            let navigator_js: wasm_bindgen::JsValue = win.navigator().into();
            if let Ok(clipboard) =
                js_sys::Reflect::get(&navigator_js, &wasm_bindgen::JsValue::from_str("clipboard"))
            {
                if let Ok(write_fn) =
                    js_sys::Reflect::get(&clipboard, &wasm_bindgen::JsValue::from_str("writeText"))
                {
                    if let Ok(write_fn) = write_fn.dyn_into::<js_sys::Function>() {
                        let _ = write_fn.call1(&clipboard, &wasm_bindgen::JsValue::from_str(&url));
                    }
                }
            }
        }
    };

    rsx! {
        div { class: "rounded-md border border-green-300 dark:border-green-800 bg-green-50 dark:bg-green-900/20 p-4 space-y-3",
            div {
                p { class: "text-sm font-medium text-green-800 dark:text-green-300",
                    "Invite sent to {props.invite_email}"
                }
                if let Some(w) = props.warning.as_deref() {
                    p { class: "mt-1 text-xs text-yellow-700 dark:text-yellow-400",
                        "Warning: {w}"
                    }
                }
            }
            div {
                label { class: "block text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 mb-1",
                    "Shareable link"
                }
                div { class: "flex gap-2",
                    input {
                        r#type: "text",
                        readonly: true,
                        value: "{props.accept_url}",
                        class: "flex-1 rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 px-3 py-2 text-xs font-mono text-bunyip-reed-900 dark:text-bunyip-reed-50",
                    }
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                        onclick: copy,
                        "Copy"
                    }
                }
                p { class: "mt-1 text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                    "Send this link to the invitee. It expires in 7 days and can only be used once."
                }
            }
            div { class: "flex justify-end gap-2 pt-2",
                button {
                    r#type: "button",
                    class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                    onclick: move |_| props.on_invite_another.call(()),
                    "Invite another"
                }
                button {
                    r#type: "button",
                    class: "px-3 py-1.5 rounded-md bg-bunyip-reed-700 text-white text-sm font-medium hover:bg-bunyip-reed-800",
                    onclick: move |_| props.on_done.call(()),
                    "Done"
                }
            }
        }
    }
}
