//! `/admin/audit-logs` - paginated audit log viewer (admin-only).

use dioxus::prelude::*;

use crate::api::admin::{self, AuditListBody, AUDIT_EVENT_KINDS};
use crate::components::layout::AppShell;
use crate::routes::Route;
use crate::stores::auth::use_require_role;

fn severity_class(s: &str) -> &'static str {
    match s {
        "critical" => "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300",
        "warning" => "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300",
        _ => "bg-bunyip-reed-100 text-bunyip-reed-800 dark:bg-bunyip-reed-700 dark:text-bunyip-reed-200",
    }
}

/// Map `event_kind` (snake_case canonical string from
/// `mokosh-auth-storage::audit::event_kind`) to a human-readable label.
/// Falls back to a title-cased version of the raw kind when unknown so
/// new event kinds are still readable while we wait for the table to
/// catch up.
fn event_label(kind: &str) -> String {
    match kind {
        "login_success" => "Signed in".into(),
        "login_failed" => "Sign-in failed".into(),
        "logout_success" => "Signed out".into(),
        "password_changed" => "Password changed".into(),
        "password_reset_requested" => "Password-reset requested".into(),
        "password_reset_completed" => "Password reset".into(),
        "password_reset_attempt_failed" => "Password-reset failed".into(),
        "magic_link_requested" => "Magic-link requested".into(),
        "magic_link_used" => "Magic-link used".into(),
        "token_issued" => "Token issued".into(),
        "token_refreshed" => "Token refreshed".into(),
        "refresh_reuse_detected" => "Refresh token reuse detected".into(),
        "session_revoked" => "Session revoked".into(),
        "client_created" => "OAuth client created".into(),
        "client_disabled" => "OAuth client disabled".into(),
        "key_rotated" => "Signing key rotated".into(),
        "suspicious_activity" => "Suspicious activity".into(),
        "admin_action" => "Admin action".into(),
        "invite_issued" => "Invite issued".into(),
        "invite_revoked" => "Invite revoked".into(),
        "invite_accepted" => "Invite accepted".into(),
        "invite_attempt_failed" => "Invite acceptance failed".into(),
        "signup_requested" => "Signup requested".into(),
        "signup_completed" => "Account created".into(),
        "signup_attempt_failed" => "Signup failed".into(),
        "totp_enrollment_started" => "MFA setup started".into(),
        "totp_enrolled" => "MFA enabled".into(),
        "totp_disenrolled" => "MFA disabled".into(),
        "mfa_challenge_issued" => "MFA code requested".into(),
        "mfa_challenge_consumed" => "MFA code verified".into(),
        "mfa_verify_failed" => "MFA code failed".into(),
        "step_up_issued" => "Step-up challenge issued".into(),
        "step_up_consumed" => "Step-up challenge passed".into(),
        "recovery_codes_issued" => "Recovery codes issued".into(),
        "recovery_codes_regenerated" => "Recovery codes regenerated".into(),
        "recovery_code_used" => "Recovery code used".into(),
        "account_lockout_hit" => "Account-lockout threshold hit".into(),
        "account_locked" => "Account locked".into(),
        other => {
            // Title-case the snake_case form so unknown kinds still read
            // as English. e.g. "new_thing_happened" -> "New thing happened".
            let mut s = String::with_capacity(other.len());
            let mut first = true;
            for ch in other.chars() {
                if ch == '_' {
                    s.push(' ');
                } else if first {
                    s.extend(ch.to_uppercase());
                    first = false;
                } else {
                    s.push(ch);
                }
            }
            s
        }
    }
}

/// Extract a one-line "details" string from the event's metadata. Each
/// event_kind tucks different fields in here; this helper pulls the
/// ones a human cares about and joins them with " · ". Empty when the
/// metadata is null or no relevant fields are present.
fn event_details(kind: &str, metadata: &serde_json::Value) -> String {
    let s = |k: &str| -> Option<String> {
        metadata
            .get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    let n = |k: &str| -> Option<String> {
        metadata
            .get(k)
            .and_then(|v| v.as_i64())
            .map(|n| n.to_string())
    };

    let mut parts: Vec<String> = Vec::new();
    match kind {
        "login_failed" => {
            if let Some(r) = s("reason") {
                parts.push(format!("reason: {r}"));
            }
            if let Some(e) = s("email") {
                parts.push(format!("email: {e}"));
            }
        }
        "login_success" => {
            if let Some(method) = s("amr").or_else(|| s("method")) {
                parts.push(format!("method: {method}"));
            }
        }
        "signup_requested" | "password_reset_requested" => {
            if let Some(e) = s("email") {
                parts.push(format!("email: {e}"));
            }
        }
        "invite_issued" | "invite_accepted" | "invite_revoked" => {
            if let Some(e) = s("email") {
                parts.push(format!("email: {e}"));
            }
            if let Some(r) = s("role") {
                parts.push(format!("role: {r}"));
            }
        }
        "mfa_verify_failed" => {
            if let Some(r) = s("reason") {
                parts.push(format!("reason: {r}"));
            }
        }
        "mfa_challenge_consumed" => {
            if let Some(m) = s("method") {
                parts.push(format!("method: {m}"));
            }
        }
        "totp_disenrolled" => {
            if let Some(by) = s("disenrolled_by") {
                parts.push(format!("by: {by}"));
            }
            if let Some(reason) = s("reason") {
                parts.push(format!("reason: {reason}"));
            }
        }
        "session_revoked" => {
            if let Some(reason) = s("reason") {
                parts.push(format!("reason: {reason}"));
            }
        }
        "recovery_codes_issued" | "recovery_codes_regenerated" => {
            if let Some(c) = n("count") {
                parts.push(format!("count: {c}"));
            }
        }
        _ => {}
    }

    parts.join(" · ")
}

/// Render an actor UUID as the first 8 characters in monospace; the
/// full UUID is in the `title` attribute for hover-to-reveal. Empty
/// string when no actor (the dash is rendered by the caller).
fn short_actor(actor_id: &str) -> String {
    actor_id.chars().take(8).collect()
}

const PAGE_SIZE: i64 = 50;

#[component]
pub fn AuditLogsPage() -> Element {
    use_require_role("admin");
    let mut data: Signal<Option<Result<AuditListBody, String>>> = use_signal(|| None);
    let mut offset = use_signal(|| 0i64);
    // Dropdown selection: "" = "All kinds", or one of AUDIT_EVENT_KINDS,
    // or "__custom__" to enable the free-text fallback.
    let mut kind_select = use_signal(String::new);
    let mut kind_custom = use_signal(String::new);
    let mut bump = use_signal(|| 0u32);

    use_future(move || async move {
        let _ = bump.read();
        data.set(None);
        let off = *offset.read();
        let sel = kind_select.read().clone();
        let kind: Option<String> = if sel == "__custom__" {
            let v = kind_custom.read().trim().to_string();
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        } else if sel.is_empty() {
            None
        } else {
            Some(sel)
        };
        let r = admin::list_audit_logs(PAGE_SIZE, off, kind.as_deref())
            .await
            .map_err(|e| e.user_message());
        data.set(Some(r));
    });

    let on_filter = use_callback(move |_| {
        offset.set(0);
        bump.with_mut(|n| *n += 1);
    });
    let prev = use_callback(move |_| {
        let off = *offset.read();
        offset.set((off - PAGE_SIZE).max(0));
        bump.with_mut(|n| *n += 1);
    });
    let next = use_callback(move |_| {
        let off = *offset.read();
        offset.set(off + PAGE_SIZE);
        bump.with_mut(|n| *n += 1);
    });

    rsx! {
        AppShell {
            title: "Audit logs".to_string(),
            back_to: Some(Route::SettingsPage {}),
            back_label: "Settings".to_string(),
            div { class: "max-w-6xl mx-auto px-6 space-y-6",
                div {
                    h1 { class: "text-3xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                        "Audit logs"
                    }
                    p { class: "mt-1 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                        "Security-relevant events recorded by the auth subsystem."
                    }
                }

                div { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 p-4",
                    form {
                        class: "flex gap-2 items-end flex-wrap",
                        onsubmit: move |e: Event<FormData>| {
                            e.prevent_default();
                            on_filter.call(());
                        },
                        div { class: "flex-1 min-w-[16rem]",
                            label { class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                                "Event kind"
                            }
                            select {
                                class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{kind_select.read()}",
                                onchange: move |e: Event<FormData>| kind_select.set(e.value()),
                                option { value: "", "All kinds" }
                                for k in AUDIT_EVENT_KINDS {
                                    option { value: "{k}", "{k}" }
                                }
                                option { value: "__custom__", "Custom..." }
                            }
                        }
                        if &*kind_select.read() == "__custom__" {
                            div { class: "flex-1 min-w-[16rem]",
                                label { class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                                    "Custom kind"
                                }
                                input {
                                    r#type: "text",
                                    placeholder: "e.g. some_new_event_kind",
                                    class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                    value: "{kind_custom.read()}",
                                    oninput: move |e: Event<FormData>| kind_custom.set(e.value()),
                                }
                            }
                        }
                        button {
                            r#type: "submit",
                            class: "px-4 py-2 rounded-md bg-bunyip-reed-700 text-white text-sm font-medium hover:bg-bunyip-reed-800",
                            "Filter"
                        }
                    }
                }

                div { class: "rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 overflow-hidden",
                    match &*data.read() {
                        None => rsx! {
                            div { class: "p-8 text-center text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                "Loading..."
                            }
                        },
                        Some(Err(e)) => rsx! {
                            div { class: "p-4 bg-red-50 dark:bg-red-900/20 border-b border-red-200 dark:border-red-800",
                                p { class: "text-sm text-red-700 dark:text-red-300", "Failed to load: {e}" }
                            }
                        },
                        Some(Ok(body)) => rsx! {
                            div { class: "overflow-x-auto",
                                table { class: "min-w-full divide-y divide-bunyip-reed-100 dark:divide-bunyip-reed-700",
                                    thead { class: "bg-bunyip-reed-50 dark:bg-bunyip-reed-900",
                                        tr {
                                            th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "When" }
                                            th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Event" }
                                            th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Severity" }
                                            th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Details" }
                                            th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "Actor" }
                                            th { class: "px-6 py-3 text-left text-xs font-medium text-bunyip-reed-600 dark:text-bunyip-reed-300 uppercase tracking-wide", "IP" }
                                        }
                                    }
                                    tbody { class: "bg-white dark:bg-bunyip-reed-800 divide-y divide-bunyip-reed-100 dark:divide-bunyip-reed-700",
                                        if body.entries.is_empty() {
                                            tr {
                                                td { colspan: "6", class: "px-6 py-8 text-center text-sm text-bunyip-reed-500 dark:text-bunyip-reed-400",
                                                    "No entries"
                                                }
                                            }
                                        } else {
                                            for row in body.entries.iter() {
                                                {
                                                    let ts = row.created_at.format("%Y-%m-%d %H:%M:%S").to_string();
                                                    let label = event_label(&row.event_kind);
                                                    let details = event_details(&row.event_kind, &row.metadata);
                                                    rsx! {
                                                tr { key: "{row.id}",
                                                    td { class: "px-6 py-3 whitespace-nowrap text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300 font-mono",
                                                        "{ts}"
                                                    }
                                                    td { class: "px-6 py-3 whitespace-nowrap text-sm text-bunyip-reed-900 dark:text-bunyip-reed-50",
                                                        // Human-readable label, with the raw event_kind
                                                        // tucked into the title attribute for engineers
                                                        // who want the canonical string.
                                                        span { title: "{row.event_kind}", "{label}" }
                                                    }
                                                    td { class: "px-6 py-3 whitespace-nowrap",
                                                        span { class: "inline-flex px-2 py-0.5 rounded-full text-xs font-medium {severity_class(&row.severity)}",
                                                            "{row.severity}"
                                                        }
                                                    }
                                                    td { class: "px-6 py-3 text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                                        if details.is_empty() {
                                                            span { class: "text-bunyip-reed-400", "-" }
                                                        } else {
                                                            "{details}"
                                                        }
                                                    }
                                                    td { class: "px-6 py-3 whitespace-nowrap text-xs font-mono text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                                        match &row.actor_id {
                                                            // Show the first 8 hex chars; full UUID is
                                                            // in the title attribute on hover. Saves
                                                            // a column-of-noise in the table.
                                                            Some(a) => {
                                                                let short = short_actor(a);
                                                                rsx! { span { title: "{a}", "{short}" } }
                                                            },
                                                            None => rsx! { span { class: "text-bunyip-reed-400", "-" } },
                                                        }
                                                    }
                                                    td { class: "px-6 py-3 whitespace-nowrap text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                                        match &row.ip {
                                                            Some(ip) => rsx! { "{ip}" },
                                                            None => rsx! { span { class: "text-bunyip-reed-400", "-" } },
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
                            div { class: "flex gap-2 mt-2 px-4 py-3 justify-end items-center border-t border-bunyip-reed-100 dark:border-bunyip-reed-700",
                                span { class: "text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                                    if body.entries.is_empty() {
                                        "No rows"
                                    } else {
                                        "Showing rows {body.offset + 1}-{body.offset + body.entries.len() as i64}"
                                    }
                                }
                                button {
                                    r#type: "button",
                                    class: "px-3 py-1 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-50",
                                    disabled: *offset.read() == 0,
                                    onclick: move |_| prev.call(()),
                                    "Previous"
                                }
                                button {
                                    r#type: "button",
                                    class: "px-3 py-1 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-50",
                                    disabled: body.entries.len() < body.limit as usize,
                                    onclick: move |_| next.call(()),
                                    "Next"
                                }
                            }
                        },
                    }
                }
            }
        }
    }
}
