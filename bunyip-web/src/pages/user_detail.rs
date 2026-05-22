//! `/admin/users/:id` - per-user drill-down.
//!
//! Five sections + a danger zone:
//!
//!   1. Profile        - identity + status/role badges, read-only
//!   2. Role           - role dropdown with confirm + step-up-on-promote
//!   3. Status         - suspend / reactivate
//!   4. Security       - MFA force-disenroll, resend verification,
//!                       admin-trigger password reset
//!   5. Audit timeline - link out to /admin/audit-logs filtered to this user
//!   6. Danger zone    - delete (typed-email + step-up gated)
//!
//! See docs/bunyip-settings/04-ui.md.

use chrono::{DateTime, Utc};
use dioxus::prelude::*;

use crate::api::admin::{self, UserDetail, UserView};
use crate::components::layout::AppShell;
use crate::modules::oidc::{self, OidcConfig};
use crate::routes::Route;
use crate::stores::auth::{use_auth, use_require_role};
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

fn status_badge_class(s: &str) -> &'static str {
    match s {
        "active" => "bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300",
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

fn fmt_ts(ts: DateTime<Utc>) -> String {
    // Render in the browser's local timezone via chrono+wasmbind.
    ts.with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M")
        .to_string()
}

#[component]
pub fn UserDetailPage(user_id: String) -> Element {
    use_require_role("admin");
    let auth = use_auth();
    let toast = use_toast();
    let nav = navigator();

    let my_id: String = auth
        .read()
        .me()
        .map(|me| me.user.id.clone())
        .unwrap_or_default();
    let is_self = my_id == user_id;

    // `use_resource` is reactive: rerun on signal change AND via
    // explicit `.restart()` after mutations. `use_future` would only
    // fire on first mount, so a role change wouldn't refresh the
    // page without a hard reload.
    let id_for_fetch = user_id.clone();
    let mut detail = use_resource(move || {
        let id = id_for_fetch.clone();
        async move { admin::get_user(&id).await.map_err(|e| e.user_message()) }
    });

    let mut role_modal: Signal<Option<String>> = use_signal(|| None);
    let mut disenroll_modal = use_signal(|| false);
    let mut delete_modal = use_signal(|| false);
    let mut busy_action: Signal<Option<&'static str>> = use_signal(|| None);

    let id_for_actions = user_id.clone();
    let refetch = use_callback(move |_| detail.restart());

    let toggle_status = {
        let id = id_for_actions.clone();
        use_callback(move |currently_active: bool| {
            let id = id.clone();
            busy_action.set(Some(if currently_active {
                "suspend"
            } else {
                "reactivate"
            }));
            spawn(async move {
                let r = if currently_active {
                    admin::suspend_user(&id).await
                } else {
                    admin::reactivate_user(&id).await
                };
                busy_action.set(None);
                match r {
                    Ok(()) => {
                        toast.success(if currently_active {
                            "Suspended."
                        } else {
                            "Reactivated."
                        });
                        refetch.call(());
                    }
                    Err(e) => toast.error(e.user_message()),
                }
            });
        })
    };

    let id_for_resend = id_for_actions.clone();
    let resend_verify = move |_| {
        let id = id_for_resend.clone();
        busy_action.set(Some("resend_verify"));
        spawn(async move {
            let r = admin::resend_verify(&id).await;
            busy_action.set(None);
            match r {
                Ok(()) => {
                    toast.success("Verification email queued.");
                    refetch.call(());
                }
                Err(e) => toast.error(e.user_message()),
            }
        });
    };

    let id_for_reset = id_for_actions.clone();
    let trigger_reset = move |_| {
        let id = id_for_reset.clone();
        busy_action.set(Some("password_reset"));
        spawn(async move {
            let r = admin::admin_trigger_password_reset(&id).await;
            busy_action.set(None);
            match r {
                Ok(()) => toast.success("Password-reset email queued."),
                Err(e) => toast.error(e.user_message()),
            }
        });
    };

    rsx! {
        AppShell { title: "User detail".to_string(),
            div { class: "max-w-3xl mx-auto px-6 space-y-6",
                Link {
                    to: Route::UserManagementPage {},
                    class: "text-sm text-bunyip-reed-600 hover:text-bunyip-reed-900 dark:text-bunyip-reed-300 dark:hover:text-bunyip-reed-50",
                    "← Back to user management"
                }

                match detail.read().clone() {
                    None => rsx! {
                        p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                            "Loading..."
                        }
                    },
                    Some(Err(msg)) => rsx! {
                        div { class: "rounded-md bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4",
                            p { class: "text-sm text-red-700 dark:text-red-300", "{msg}" }
                        }
                    },
                    Some(Ok(d)) => {
                        let u = d.user.clone();
                        let name = display_name(&u);
                        let initial = name.chars().next().unwrap_or('?').to_string().to_uppercase();
                        let active = u.status == "active";
                        let pending = u.status == "pending";
                        let busy_label = busy_action.read().clone();
                        let available_roles = d.available_role_transitions.clone();
                        let target_email_for_delete = u.email.clone();
                        rsx! {
                            // --- Profile -----------------------------
                            section { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 p-6",
                                div { class: "flex items-start gap-4",
                                    div { class: "shrink-0 w-14 h-14 rounded-full bg-bunyip-reed-100 dark:bg-bunyip-reed-700 flex items-center justify-center",
                                        span { class: "text-lg font-semibold text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                            "{initial}"
                                        }
                                    }
                                    div { class: "min-w-0 flex-1",
                                        div { class: "flex items-center gap-2 flex-wrap",
                                            h1 { class: "text-2xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50 truncate",
                                                "{name}"
                                                if is_self {
                                                    span { class: "ml-2 text-sm font-normal text-bunyip-reed-500 dark:text-bunyip-reed-400", "(you)" }
                                                }
                                            }
                                            span { class: "inline-flex px-2 py-0.5 rounded-full text-xs font-medium {role_badge_class(&u.role)}",
                                                "{role_label(&u.role)}"
                                            }
                                            span { class: "inline-flex px-2 py-0.5 rounded-full text-xs font-medium {status_badge_class(&u.status)}",
                                                "{u.status}"
                                            }
                                            if u.is_owner {
                                                span {
                                                    class: "inline-flex px-2 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200",
                                                    title: "Tenant owner - immutable by other admins",
                                                    "Owner"
                                                }
                                            }
                                        }
                                        p { class: "mt-1 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                            "{u.email}"
                                        }
                                        p { class: "mt-1 text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                                            "Joined {fmt_ts(u.created_at)}"
                                            if let Some(t) = u.last_login_at {
                                                " · Last login {fmt_ts(t)}"
                                            } else {
                                                " · Never signed in"
                                            }
                                        }
                                    }
                                }
                            }

                            // --- Role + status -----------------------
                            // Hidden when viewing own profile (admins
                            // can't mutate themselves here) or when the
                            // target is the Owner (server refuses; UI
                            // hides to keep state honest).
                            if !is_self && !u.is_owner {
                                section { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 p-6 space-y-4",
                                    h2 { class: "text-base font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                                        "Role and status"
                                    }
                                    div { class: "flex items-center gap-2 flex-wrap",
                                        p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 mr-2",
                                            "Change role:"
                                        }
                                        for r in available_roles.iter().cloned() {
                                            {
                                                let r_clone = r.clone();
                                                rsx! {
                                                    button {
                                                        r#type: "button",
                                                        class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-xs text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                                                        onclick: move |_| role_modal.set(Some(r_clone.clone())),
                                                        "{role_label(&r)}"
                                                    }
                                                }
                                            }
                                        }
                                        if available_roles.is_empty() {
                                            span { class: "text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                                                "No legal role transitions for this user."
                                            }
                                        }
                                    }
                                    div { class: "flex items-center gap-2 flex-wrap pt-2",
                                        p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 mr-2",
                                            "Status:"
                                        }
                                        if active {
                                            button {
                                                r#type: "button",
                                                class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-xs text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-60",
                                                disabled: busy_label == Some("suspend"),
                                                onclick: move |_| toggle_status.call(true),
                                                if busy_label == Some("suspend") { "Suspending..." } else { "Suspend" }
                                            }
                                        } else {
                                            button {
                                                r#type: "button",
                                                class: "px-3 py-1.5 rounded-md bg-bunyip-reed-700 text-white text-xs font-medium hover:bg-bunyip-reed-800 disabled:opacity-60",
                                                disabled: busy_label == Some("reactivate"),
                                                onclick: move |_| toggle_status.call(false),
                                                if busy_label == Some("reactivate") { "Reactivating..." } else { "Reactivate" }
                                            }
                                        }
                                    }
                                }
                            }

                            // --- Security ----------------------------
                            section { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 p-6 space-y-3",
                                h2 { class: "text-base font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                                    "Security"
                                }
                                div { class: "flex items-center justify-between gap-4",
                                    div {
                                        p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                            "MFA: " span { class: "font-medium",
                                                if u.mfa_enrolled { "Enrolled" } else { "Not enrolled" }
                                            }
                                        }
                                    }
                                    if u.mfa_enrolled && !is_self && !u.is_owner {
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1.5 rounded-md border border-red-300 dark:border-red-700 text-xs text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30",
                                            onclick: move |_| disenroll_modal.set(true),
                                            "Force disenroll"
                                        }
                                    }
                                }
                                div { class: "flex items-center justify-between gap-4",
                                    div {
                                        p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                            "Email verified: " span { class: "font-medium",
                                                if u.email_verified { "yes" } else { "no" }
                                            }
                                        }
                                    }
                                    if !u.email_verified && pending {
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-xs text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-60",
                                            disabled: busy_label == Some("resend_verify"),
                                            onclick: resend_verify,
                                            if busy_label == Some("resend_verify") { "Sending..." } else { "Resend verification" }
                                        }
                                    } else if u.email_verified {
                                        span { class: "text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                                            title: "Email already verified.",
                                            "—"
                                        }
                                    }
                                }
                                if u.email_verified && !is_self && !matches!(u.status.as_str(), "deleted") {
                                    div { class: "flex items-center justify-between gap-4",
                                        p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                            "Password reset"
                                        }
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-xs text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-60",
                                            disabled: busy_label == Some("password_reset"),
                                            onclick: trigger_reset,
                                            if busy_label == Some("password_reset") { "Sending..." } else { "Send reset email" }
                                        }
                                    }
                                }
                            }

                            // --- Sessions ----------------------------
                            if !is_self {
                                UserSessionsSection { user_id: user_id.clone() }
                            }

                            // --- Audit cross-link --------------------
                            section { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 p-6 space-y-2",
                                h2 { class: "text-base font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                                    "Audit timeline"
                                }
                                p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                    "All admin actions taken on this user are recorded. Open the audit log to see the full history."
                                }
                                Link {
                                    to: Route::AuditLogsPage {},
                                    class: "inline-block px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-xs text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                                    "Open audit logs →"
                                }
                            }

                            // --- Danger zone -------------------------
                            // Hidden for self (you can't delete yourself
                            // from this surface) and for Owners (immovable).
                            if !is_self && !u.is_owner {
                                section { class: "rounded-xl border-2 border-red-300 dark:border-red-800 bg-white dark:bg-bunyip-reed-800 p-6 space-y-3",
                                    h2 { class: "text-base font-semibold text-red-700 dark:text-red-300",
                                        "Danger zone"
                                    }
                                    p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                        "Deleting marks the account as deleted and frees the email address for re-use. Sessions are revoked. The audit row is preserved. This cannot be undone."
                                    }
                                    button {
                                        r#type: "button",
                                        class: "px-3 py-1.5 rounded-md bg-red-600 text-white text-xs font-medium hover:bg-red-700",
                                        onclick: move |_| delete_modal.set(true),
                                        "Delete user"
                                    }
                                }
                            }

                            // --- Modals ------------------------------
                            if let Some(new_role) = role_modal.read().clone() {
                                ChangeRoleModal {
                                    user: u.clone(),
                                    new_role: new_role.clone(),
                                    on_close: move |_| role_modal.set(None),
                                    on_done: move |_| {
                                        role_modal.set(None);
                                        toast.success("Role updated.");
                                        refetch.call(());
                                    },
                                }
                            }
                            if *disenroll_modal.read() {
                                DisenrollMfaConfirm {
                                    user: u.clone(),
                                    on_close: move |_| disenroll_modal.set(false),
                                    on_done: move |_| {
                                        disenroll_modal.set(false);
                                        toast.success("MFA disenrolled.");
                                        refetch.call(());
                                    },
                                }
                            }
                            if *delete_modal.read() {
                                DeleteUserConfirm {
                                    user: u.clone(),
                                    target_email: target_email_for_delete.clone(),
                                    on_close: move |_| delete_modal.set(false),
                                    on_done: move |_| {
                                        delete_modal.set(false);
                                        toast.success("User deleted.");
                                        nav.replace(Route::UserManagementPage {});
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

// --- Modals -------------------------------------------------------------

#[derive(Props, Clone, PartialEq)]
struct ChangeRoleModalProps {
    user: UserView,
    new_role: String,
    on_close: EventHandler<()>,
    on_done: EventHandler<()>,
}

#[component]
fn ChangeRoleModal(props: ChangeRoleModalProps) -> Element {
    let mut reason = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error: Signal<Option<String>> = use_signal(|| None);
    let mut step_up_token: Signal<Option<String>> = use_signal(|| None);
    let mut step_up_in_progress = use_signal(|| false);

    let needs_step_up = props.new_role == "admin" && props.user.role != "admin";

    let id_for_submit = props.user.id.clone();
    let new_role_for_submit = props.new_role.clone();
    let submit = use_callback(move |_| {
        let id = id_for_submit.clone();
        let role = new_role_for_submit.clone();
        let reason_s = reason.read().trim().to_string();
        let reason_opt = if reason_s.is_empty() {
            None
        } else {
            Some(reason_s)
        };
        let tok = step_up_token.read().clone();
        if needs_step_up && tok.is_none() {
            error.set(Some(
                "MFA step-up required to promote a user to admin.".into(),
            ));
            return;
        }
        spawn(async move {
            submitting.set(true);
            error.set(None);
            let r = admin::change_user_role(&id, &role, reason_opt, tok).await;
            submitting.set(false);
            match r {
                Ok(()) => props.on_done.call(()),
                Err(e) => error.set(Some(e.user_message())),
            }
        });
    });

    let _ = step_up_in_progress; // kept for future spinner-state wiring.

    rsx! {
        div { class: "fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4",
            div { class: "w-full max-w-md rounded-xl bg-white dark:bg-bunyip-reed-800 border border-bunyip-reed-100 dark:border-bunyip-reed-700 shadow-xl p-6 space-y-4",
                h2 { class: "text-lg font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                    "Change role"
                }
                p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                    "Change " span { class: "font-mono", "{props.user.email}" }
                    " from " strong { "{props.user.role}" }
                    " to " strong { "{props.new_role}" } "."
                }
                if let Some(msg) = error.read().as_ref() {
                    p { class: "text-sm text-red-700 dark:text-red-300", "{msg}" }
                }
                if needs_step_up {
                    StepUpVerifyForm {
                        on_token: move |t: String| step_up_token.set(Some(t)),
                        on_error: move |e: String| error.set(Some(e)),
                    }
                    if step_up_token.read().is_some() {
                        p { class: "text-xs text-green-700 dark:text-green-300",
                            "MFA step-up verified."
                        }
                    }
                }
                div {
                    label { class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                        "Reason (optional)"
                    }
                    textarea {
                        rows: "2",
                        class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-sm text-bunyip-reed-900 dark:text-bunyip-reed-50 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
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
                        class: "px-3 py-1.5 rounded-md bg-bunyip-reed-700 text-white text-sm font-medium hover:bg-bunyip-reed-800 disabled:opacity-60",
                        disabled: *submitting.read() || (needs_step_up && step_up_token.read().is_none()),
                        onclick: move |_| submit.call(()),
                        if *submitting.read() { "Saving..." } else { "Change role" }
                    }
                }
            }
        }
    }
}

#[derive(serde::Deserialize)]
struct StepUpStartResp {
    challenge: String,
    #[allow(dead_code)]
    expires_in: i64,
}

#[derive(serde::Deserialize)]
struct StepUpVerifyResp {
    step_up_token: String,
}

#[derive(Props, Clone, PartialEq)]
struct StepUpVerifyFormProps {
    on_token: EventHandler<String>,
    on_error: EventHandler<String>,
}

#[component]
fn StepUpVerifyForm(props: StepUpVerifyFormProps) -> Element {
    let mut code = use_signal(String::new);
    let mut challenge: Signal<Option<String>> = use_signal(|| None);
    let mut submitting = use_signal(|| false);

    let start = use_callback(move |_| {
        spawn(async move {
            submitting.set(true);
            let cfg = OidcConfig::from_env();
            match oidc::issuer_post_authed::<StepUpStartResp, _>(
                &cfg,
                "/v1/auth/mfa/step-up/start",
                &serde_json::json!({}),
            )
            .await
            {
                Ok(r) => {
                    challenge.set(Some(r.challenge));
                    submitting.set(false);
                }
                Err(e) => {
                    submitting.set(false);
                    let msg = e.to_string();
                    // The server returns `{"error": "not_enrolled"}` when
                    // the calling admin doesn't have MFA on their own
                    // account; without translating, that body shows up
                    // verbatim. Surface the actual problem.
                    let friendly = if msg.contains("not_enrolled") {
                        "You need to enable MFA on your own account before performing this action. Set it up under Settings -> Security."
                            .to_string()
                    } else if msg.contains("rate_limited") {
                        "Too many attempts. Wait a moment and try again.".to_string()
                    } else {
                        format!("Could not start step-up: {e}")
                    };
                    props.on_error.call(friendly);
                }
            }
        });
    });

    let verify = use_callback(move |_| {
        let ch = match challenge.read().clone() {
            Some(c) => c,
            None => {
                props
                    .on_error
                    .call("No step-up challenge issued yet. Click 'Send code'.".into());
                return;
            }
        };
        let c = code.read().trim().to_string();
        if c.is_empty() {
            props.on_error.call("Enter your authenticator code.".into());
            return;
        }
        spawn(async move {
            submitting.set(true);
            let cfg = OidcConfig::from_env();
            let body = serde_json::json!({"challenge": ch, "code": c});
            match oidc::issuer_post_authed::<StepUpVerifyResp, _>(
                &cfg,
                "/v1/auth/mfa/step-up/verify",
                &body,
            )
            .await
            {
                Ok(r) => {
                    props.on_token.call(r.step_up_token);
                    submitting.set(false);
                }
                Err(e) => {
                    submitting.set(false);
                    props.on_error.call(format!("step-up verify: {e}"));
                }
            }
        });
    });

    rsx! {
        div { class: "rounded-md bg-bunyip-reed-50 dark:bg-bunyip-reed-900 p-3 space-y-2",
            p { class: "text-xs text-bunyip-reed-700 dark:text-bunyip-reed-200",
                "Promoting a user to admin requires MFA step-up."
            }
            div { class: "flex gap-2 items-end",
                div { class: "flex-1",
                    label { class: "block text-xs font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                        "Authenticator code"
                    }
                    input {
                        r#type: "text",
                        placeholder: "123456",
                        class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                        value: "{code.read()}",
                        oninput: move |e: Event<FormData>| code.set(e.value()),
                    }
                }
                if challenge.read().is_none() {
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-xs text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-60",
                        disabled: *submitting.read(),
                        onclick: move |_| start.call(()),
                        "Start"
                    }
                } else {
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-md bg-bunyip-reed-700 text-white text-xs font-medium hover:bg-bunyip-reed-800 disabled:opacity-60",
                        disabled: *submitting.read(),
                        onclick: move |_| verify.call(()),
                        "Verify"
                    }
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct DisenrollMfaConfirmProps {
    user: UserView,
    on_close: EventHandler<()>,
    on_done: EventHandler<()>,
}

#[component]
fn DisenrollMfaConfirm(props: DisenrollMfaConfirmProps) -> Element {
    let mut reason = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut error: Signal<Option<String>> = use_signal(|| None);
    let id = props.user.id.clone();
    let submit = use_callback(move |_| {
        let id = id.clone();
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
                Ok(()) => props.on_done.call(()),
                Err(e) => error.set(Some(e.user_message())),
            }
        });
    });
    rsx! {
        div { class: "fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4",
            div { class: "w-full max-w-md rounded-xl bg-white dark:bg-bunyip-reed-800 border border-bunyip-reed-100 dark:border-bunyip-reed-700 shadow-xl p-6 space-y-4",
                h2 { class: "text-lg font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50", "Force disenroll MFA" }
                p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                    "Remove MFA from " span { class: "font-mono", "{props.user.email}" } ". The user will re-enroll on next sign-in and be notified by email."
                }
                if let Some(msg) = error.read().as_ref() {
                    p { class: "text-sm text-red-700 dark:text-red-300", "{msg}" }
                }
                textarea {
                    rows: "3",
                    placeholder: "Reason (required)",
                    class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-sm text-bunyip-reed-900 dark:text-bunyip-reed-50 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                    value: "{reason.read()}",
                    oninput: move |e: Event<FormData>| reason.set(e.value()),
                }
                div { class: "flex justify-end gap-2",
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
                        if *submitting.read() { "Disenrolling..." } else { "Disenroll" }
                    }
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct DeleteUserConfirmProps {
    user: UserView,
    target_email: String,
    on_close: EventHandler<()>,
    on_done: EventHandler<()>,
}

#[component]
fn DeleteUserConfirm(props: DeleteUserConfirmProps) -> Element {
    let mut reason = use_signal(String::new);
    let mut typed_email = use_signal(String::new);
    let mut step_up_token: Signal<Option<String>> = use_signal(|| None);
    let mut submitting = use_signal(|| false);
    let mut error: Signal<Option<String>> = use_signal(|| None);
    let id = props.user.id.clone();
    let target = props.target_email.clone();
    let target_for_check = props.target_email.clone();
    let typed_matches = *typed_email.read() == target_for_check;

    let submit = use_callback(move |_| {
        let id = id.clone();
        let r = reason.read().trim().to_string();
        let tok = match step_up_token.read().clone() {
            Some(t) => t,
            None => {
                error.set(Some("Complete the step-up first.".into()));
                return;
            }
        };
        if r.is_empty() {
            error.set(Some("A reason is required.".into()));
            return;
        }
        spawn(async move {
            submitting.set(true);
            error.set(None);
            let result = admin::delete_user(&id, &r, &tok).await;
            submitting.set(false);
            match result {
                Ok(()) => props.on_done.call(()),
                Err(e) => error.set(Some(e.user_message())),
            }
        });
    });

    rsx! {
        div { class: "fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4",
            div { class: "w-full max-w-md rounded-xl bg-white dark:bg-bunyip-reed-800 border-2 border-red-300 dark:border-red-800 shadow-xl p-6 space-y-4",
                h2 { class: "text-lg font-semibold text-red-700 dark:text-red-300",
                    "Delete user"
                }
                p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                    "This will mark " span { class: "font-mono", "{target}" }
                    " as deleted and revoke all their sessions. The email is freed for re-use. The audit row is preserved. This cannot be undone."
                }
                if let Some(msg) = error.read().as_ref() {
                    p { class: "text-sm text-red-700 dark:text-red-300", "{msg}" }
                }
                StepUpVerifyForm {
                    on_token: move |t: String| step_up_token.set(Some(t)),
                    on_error: move |e: String| error.set(Some(e)),
                }
                if step_up_token.read().is_some() {
                    p { class: "text-xs text-green-700 dark:text-green-300",
                        "MFA step-up verified."
                    }
                }
                textarea {
                    rows: "2",
                    placeholder: "Reason (required)",
                    class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-sm text-bunyip-reed-900 dark:text-bunyip-reed-50 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                    value: "{reason.read()}",
                    oninput: move |e: Event<FormData>| reason.set(e.value()),
                }
                div {
                    label { class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                        "Type " span { class: "font-mono", "{target}" } " to confirm"
                    }
                    input {
                        r#type: "text",
                        class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-sm text-bunyip-reed-900 dark:text-bunyip-reed-50 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-red-600 font-mono",
                        value: "{typed_email.read()}",
                        oninput: move |e: Event<FormData>| typed_email.set(e.value()),
                    }
                }
                div { class: "flex justify-end gap-2",
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                        onclick: move |_| props.on_close.call(()),
                        "Cancel"
                    }
                    button {
                        r#type: "button",
                        class: "px-3 py-1.5 rounded-md bg-red-600 text-white text-sm font-medium hover:bg-red-700 disabled:opacity-50",
                        disabled: !typed_matches || step_up_token.read().is_none() || *submitting.read(),
                        onclick: move |_| submit.call(()),
                        if *submitting.read() { "Deleting..." } else { "Delete user" }
                    }
                }
            }
        }
    }
}

#[component]
fn UserSessionsSection(user_id: String) -> Element {
    let toast = use_toast();
    let id_for_fetch = user_id.clone();
    let mut sessions = use_resource(move || {
        let id = id_for_fetch.clone();
        async move {
            admin::list_user_sessions(&id)
                .await
                .map_err(|e| e.user_message())
        }
    });

    let mut revoking: Signal<Option<String>> = use_signal(|| None);

    rsx! {
        section { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 p-6 space-y-3",
            h2 { class: "text-base font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                "Active sessions"
            }
            p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                "Devices currently signed in as this user. Force-revoking kills the session and any refresh tokens issued from it."
            }
            match &*sessions.read_unchecked() {
                None => rsx! {
                    p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300", "Loading..." }
                },
                Some(Err(e)) => rsx! {
                    p { class: "text-sm text-red-700 dark:text-red-300", "{e}" }
                },
                Some(Ok(list)) if list.is_empty() => rsx! {
                    p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300", "No active sessions." }
                },
                Some(Ok(list)) => rsx! {
                    ul { class: "divide-y divide-bunyip-reed-100 dark:divide-bunyip-reed-700",
                        for s in list.iter() {
                            {
                                let s = s.clone();
                                let device = ua_short_label(s.user_agent.as_deref());
                                let ip = s.ip.clone().unwrap_or_else(|| "unknown".into());
                                let last = format_dt(&s.last_active_at);
                                let busy = revoking.read().as_deref() == Some(s.id.as_str());
                                let sid = s.id.clone();
                                let user_id_for_revoke = user_id.clone();
                                let on_revoke = move |_| {
                                    if busy { return; }
                                    let sid = sid.clone();
                                    let user_id = user_id_for_revoke.clone();
                                    revoking.set(Some(sid.clone()));
                                    spawn(async move {
                                        match admin::revoke_user_session(&user_id, &sid).await {
                                            Ok(()) => {
                                                toast.info("Session revoked.");
                                                sessions.restart();
                                            }
                                            Err(e) => toast.error(e.user_message()),
                                        }
                                        revoking.set(None);
                                    });
                                };
                                rsx! {
                                    li { class: "py-3 flex items-center justify-between gap-3",
                                        div { class: "min-w-0",
                                            p { class: "text-sm font-medium text-bunyip-reed-900 dark:text-bunyip-reed-50 truncate",
                                                "{device}"
                                            }
                                            p { class: "text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                                                "{ip} - last active {last}"
                                            }
                                        }
                                        button {
                                            r#type: "button",
                                            class: "px-3 py-1.5 rounded-md border border-red-300 dark:border-red-700 text-xs text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30 disabled:opacity-60",
                                            disabled: busy,
                                            onclick: on_revoke,
                                            if busy { "Revoking..." } else { "Revoke" }
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
}

/// Best-effort UA -> "Browser on OS" label. Mirror of the helper in
/// pages/sessions.rs so the detail page can render the same shape
/// without coupling the two modules.
fn ua_short_label(ua: Option<&str>) -> String {
    let Some(ua) = ua else {
        return "Unknown device".into();
    };
    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("Chrome/") && !ua.contains("Chromium/") {
        "Chrome"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else if ua.contains("Safari/") && !ua.contains("Chrome/") {
        "Safari"
    } else {
        "Browser"
    };
    let os = if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "device"
    };
    format!("{browser} on {os}")
}

fn format_dt(s: &str) -> String {
    // ISO-8601 (e.g. "2026-05-15T13:42:01.123456Z"); trim subseconds + 'Z'.
    s.split('.').next().unwrap_or(s).replace('T', " ")
}
