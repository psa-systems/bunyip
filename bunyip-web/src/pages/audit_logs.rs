//! `/admin/audit-logs` - paginated audit log viewer (admin-only).

use dioxus::prelude::*;

use crate::api::admin::{self, AUDIT_EVENT_KINDS};
use crate::api::issuer_url;
use crate::components::layout::AppShell;
use crate::routes::Route;
use crate::stores::auth::use_require_role;
use crate::stores::toast::use_toast;
use crate::stores::tokens::current_access_token;

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
    let toast = use_toast();
    let mut offset = use_signal(|| 0i64);
    // Dropdown selection: "" = "All kinds", or one of AUDIT_EVENT_KINDS,
    // or "__custom__" to enable the free-text fallback.
    let mut kind_select = use_signal(String::new);
    let mut kind_custom = use_signal(String::new);
    let mut search = use_signal(String::new);
    let mut severity = use_signal(String::new);
    let mut date_from = use_signal(String::new);
    let mut date_to = use_signal(String::new);
    let mut downloading = use_signal(|| false);

    fn build_filter(
        kind_select: &Signal<String>,
        kind_custom: &Signal<String>,
        search: &Signal<String>,
        severity: &Signal<String>,
        date_from: &Signal<String>,
        date_to: &Signal<String>,
    ) -> admin::AuditFilter {
        let sel = kind_select.read().clone();
        let kind: Option<String> = if sel == "__custom__" {
            let v = kind_custom.read().trim().to_string();
            (!v.is_empty()).then_some(v)
        } else if sel.is_empty() {
            None
        } else {
            Some(sel)
        };
        // <input type="date"> emits `YYYY-MM-DD`; widen to a full-day
        // bound so the server sees it as RFC 3339. From-date floors to
        // 00:00:00Z, to-date ceils to 23:59:59Z.
        let from = date_from
            .read()
            .trim()
            .to_string()
            .as_str()
            .strip_prefix("")
            .map(|s| {
                if s.is_empty() {
                    String::new()
                } else {
                    format!("{s}T00:00:00Z")
                }
            })
            .unwrap_or_default();
        let to = {
            let v = date_to.read().trim().to_string();
            if v.is_empty() {
                String::new()
            } else {
                format!("{v}T23:59:59Z")
            }
        };
        admin::AuditFilter {
            kind,
            search: Some(search.read().trim().to_string()).filter(|s| !s.is_empty()),
            severity: Some(severity.read().clone()).filter(|s| !s.is_empty()),
            from: Some(from).filter(|s| !s.is_empty()),
            to: Some(to).filter(|s| !s.is_empty()),
        }
    }

    // `use_resource` is the reactive variant of `use_future`:
    // signals read inside its closure auto-subscribe via a
    // ReactiveContext and re-run the future on any change.
    let data = use_resource(move || async move {
        let off = *offset.read();
        let filter = build_filter(
            &kind_select,
            &kind_custom,
            &search,
            &severity,
            &date_from,
            &date_to,
        );
        admin::list_audit_logs(PAGE_SIZE, off, &filter)
            .await
            .map_err(|e| e.user_message())
    });

    // Reset to the first page when any filter changes.
    let on_filter = use_callback(move |_| {
        offset.set(0);
    });
    let prev = use_callback(move |_| {
        let off = *offset.read();
        offset.set((off - PAGE_SIZE).max(0));
    });
    let next = use_callback(move |_| {
        let off = *offset.read();
        offset.set(off + PAGE_SIZE);
    });

    let on_csv = use_callback(move |_| {
        if downloading() {
            return;
        }
        downloading.set(true);
        let filter = build_filter(
            &kind_select,
            &kind_custom,
            &search,
            &severity,
            &date_from,
            &date_to,
        );
        spawn(async move {
            match download_audit_csv(&filter).await {
                Ok(()) => {}
                Err(e) => toast.error(format!("CSV download failed: {e}")),
            }
            downloading.set(false);
        });
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
                        div { class: "flex-1 min-w-[14rem]",
                            label { class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                                "Search"
                            }
                            input {
                                r#type: "text",
                                placeholder: "Metadata substring (case-insensitive)",
                                class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{search.read()}",
                                oninput: move |e: Event<FormData>| search.set(e.value()),
                            }
                        }
                        div { class: "min-w-[10rem]",
                            label { class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                                "Severity"
                            }
                            select {
                                class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{severity.read()}",
                                onchange: move |e: Event<FormData>| severity.set(e.value()),
                                option { value: "", "Any" }
                                option { value: "info", "info" }
                                option { value: "warning", "warning" }
                                option { value: "critical", "critical" }
                            }
                        }
                        div { class: "min-w-[10rem]",
                            label { class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                                "From"
                            }
                            input {
                                r#type: "date",
                                class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{date_from.read()}",
                                oninput: move |e: Event<FormData>| date_from.set(e.value()),
                            }
                        }
                        div { class: "min-w-[10rem]",
                            label { class: "block text-sm font-medium text-bunyip-reed-700 dark:text-bunyip-reed-200 mb-1",
                                "To"
                            }
                            input {
                                r#type: "date",
                                class: "block w-full rounded-md border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600",
                                value: "{date_to.read()}",
                                oninput: move |e: Event<FormData>| date_to.set(e.value()),
                            }
                        }
                        button {
                            r#type: "submit",
                            class: "px-4 py-2 rounded-md bg-bunyip-reed-700 text-white text-sm font-medium hover:bg-bunyip-reed-800",
                            "Filter"
                        }
                        button {
                            r#type: "button",
                            class: "px-4 py-2 rounded-md border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-60",
                            disabled: downloading(),
                            onclick: move |_| on_csv.call(()),
                            if downloading() { "Downloading..." } else { "Download CSV" }
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
                                                    td { class: "px-6 py-3 whitespace-nowrap text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                                        match (&row.actor_email, &row.actor_id) {
                                                            // Server-side LEFT JOIN populates actor_email
                                                            // when the actor row still exists. Fall back
                                                            // to a short UUID with the full id in the
                                                            // title attribute for engineers.
                                                            (Some(email), _) => rsx! { span { title: row.actor_id.clone().unwrap_or_default(), "{email}" } },
                                                            (None, Some(a)) => {
                                                                let short = short_actor(a);
                                                                rsx! { span { class: "font-mono", title: "{a}", "{short}" } }
                                                            },
                                                            (None, None) => rsx! { span { class: "text-bunyip-reed-400", "-" } },
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

/// Fetch the CSV from mokosh-server with the caller's Bearer token,
/// then trigger a Blob-based browser download. Bearer can't be set on
/// a plain `<a download>` so we route through fetch + Blob URL.
async fn download_audit_csv(filter: &admin::AuditFilter) -> Result<(), String> {
    use wasm_bindgen::JsCast;

    let path = admin::audit_csv_path(filter);
    let url = issuer_url(&path);
    let token = current_access_token().ok_or_else(|| "not signed in".to_string())?;

    let resp = gloo_net::http::Request::get(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Accept", "text/csv")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.ok() {
        return Err(format!("server returned {}", resp.status()));
    }
    let text = resp.text().await.map_err(|e| e.to_string())?;

    // Wrap the CSV body in a Blob and trigger a download by clicking a
    // synthesized anchor with the `download` attribute set. Standard
    // SPA pattern; no library involved beyond web-sys.
    let win = web_sys::window().ok_or("no window")?;
    let doc = win.document().ok_or("no document")?;
    let array = js_sys::Array::new();
    array.push(&wasm_bindgen::JsValue::from_str(&text));
    let mut opts = web_sys::BlobPropertyBag::new();
    opts.type_("text/csv;charset=utf-8");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&array, &opts)
        .map_err(|_| "blob construction failed".to_string())?;
    let blob_url = web_sys::Url::create_object_url_with_blob(&blob)
        .map_err(|_| "blob url failed".to_string())?;

    let anchor = doc
        .create_element("a")
        .map_err(|_| "create_element failed".to_string())?;
    let anchor: web_sys::HtmlAnchorElement = anchor
        .dyn_into()
        .map_err(|_| "dyn_into HtmlAnchorElement failed".to_string())?;
    anchor.set_href(&blob_url);
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    anchor.set_download(&format!("audit-logs-{stamp}.csv"));
    anchor.click();
    let _ = web_sys::Url::revoke_object_url(&blob_url);
    Ok(())
}
