//! Admin panel: Email / SMTP config (BUNYIP-351).

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::json;

use crate::api::admin as admin_api;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{button_class, error_box, icon, success_box};
use crate::web::{redirect_cookies, AppState};

pub(super) fn email_settings_content(
    cfg: Option<&crate::api::types::EmailConfigResponse>,
) -> Markup {
    html! {
        div class="space-y-6" {
            div { h1 class="text-3xl font-bold" { "Email" } p class="mt-2 text-muted-foreground" { "Configure the SMTP relay for transactional email. Changes apply immediately without a restart." } }
            @match cfg {
                None => p class="text-muted-foreground" { "Could not load email config." },
                // BUNYIP-415: two-column block layout. The SMTP transport
                // settings and the sender/notification settings sit in
                // side-by-side blocks (one column below lg), inside one form so
                // a single Save persists everything.
                Some(e) => div class="space-y-6" {
                    form method="post" action="/admin/email" class="space-y-6" {
                    (admin_block_grid(vec![
                        admin_block(
                            "SMTP Connection",
                            Some(&format!("Source: {}. Leave a field blank to keep the existing value.", e.source)),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" {
                                        label class="text-sm font-medium" { "Sending" }
                                        select name="enabled" class=(dashboard_input()) {
                                            option value="true" selected[e.enabled] { "Enabled" }
                                            option value="false" selected[!e.enabled] { "Disabled" }
                                        }
                                    }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP host" } input name="smtp_host" value=(e.smtp_host) placeholder="smtp.example.com" class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP port" } input name="smtp_port" type="number" min="1" max="65535" value=(e.smtp_port) class=(dashboard_input()); }
                                    div class="space-y-2" {
                                        label class="text-sm font-medium" { "TLS mode" }
                                        select name="smtp_tls" class=(dashboard_input()) {
                                            option value="implicit" selected[e.smtp_tls == "implicit"] { "Implicit (port 465)" }
                                            option value="starttls" selected[e.smtp_tls == "starttls"] { "STARTTLS (port 587)" }
                                        }
                                    }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP username" } input name="smtp_username" value=(e.smtp_username) autocomplete="off" class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "SMTP password" } input name="smtp_password" type="password" autocomplete="new-password" placeholder=(if e.has_smtp_password { "••••••••" } else { "Not set" }) class=(dashboard_input()); p class="text-xs text-muted-foreground" {
                                        // BUNYIP-432: the placeholder is a fixed-length mask driven only
                                        // by has_smtp_password; the real password (and its length) never
                                        // reaches the browser. Leave blank to keep the current one.
                                        @if e.has_smtp_password { "A password is set (stored encrypted). Leave blank to keep it, or type a new one to replace it." } @else { "No password set. Stored encrypted when you save one." }
                                    } }
                                }
                            },
                        ),
                        admin_block(
                            "Sender & Notifications",
                            Some("Who transactional mail comes from, and where operational notices go."),
                            html! {
                                div class="space-y-4" {
                                    div class="space-y-2" { label class="text-sm font-medium" { "From email" } input name="from_email" type="email" value=(e.from_email) placeholder="noreply@example.com" class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "From name" } input name="from_name" value=(e.from_name) class=(dashboard_input()); }
                                    div class="space-y-2" { label class="text-sm font-medium" { "Admin notification emails" } input name="admin_notification_emails" value=(e.admin_notification_emails.join(", ")) placeholder="ops@example.com, alerts@example.com" class=(dashboard_input()); p class="text-xs text-muted-foreground" { "Comma-separated recipients for operational notices." } }
                                }
                            },
                        ),
                    ]))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    }
                    // BUNYIP-433: Test connection lives in its own form so it
                    // submits no fields - it always tests the SAVED settings,
                    // never the unsaved edits in the form above.
                    form method="post" action="/admin/email/test" class="flex flex-wrap items-center gap-3 border-t border-border/50 pt-4" {
                        button type="submit" class=(button_class("outline", "default", "")) { (icon("mail", "mr-2 h-4 w-4")) "Test connection" }
                        p class="text-xs text-muted-foreground" { "Opens a connection to the saved SMTP server and signs in, without sending an email. Save changes first to test them." }
                    }
                },
            }
        }
    }
}

pub async fn email(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cfg = admin_api::email_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = email_settings_content(cfg.as_ref());
    admin_response(&c, &user, "/admin/email", "Email · Bunyip", content)
}

#[derive(Deserialize)]
pub struct EmailSettingsForm {
    #[serde(default)]
    pub enabled: String,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: String,
    #[serde(default)]
    pub smtp_tls: String,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub from_email: String,
    #[serde(default)]
    pub from_name: String,
    #[serde(default)]
    pub admin_notification_emails: String,
}

/// Build the PUT body from the submitted form. `enabled` and `smtp_tls` (both
/// from `<select>`s) are always sent; the SMTP port is validated when present;
/// every other field is sent only when non-blank so an untouched field leaves
/// the persisted value unchanged. Pure so it can be unit-tested.
pub(super) fn email_update_body(f: &EmailSettingsForm) -> Result<serde_json::Value, String> {
    let mut body = serde_json::Map::new();
    body.insert("enabled".into(), json!(f.enabled.trim() == "true"));

    let port = f.smtp_port.trim();
    if !port.is_empty() {
        let n: i32 = port
            .parse()
            .map_err(|_| "SMTP port must be a whole number.".to_string())?;
        if !(1..=65535).contains(&n) {
            return Err("SMTP port must be between 1 and 65535.".to_string());
        }
        body.insert("smtp_port".into(), json!(n));
    }

    let tls = f.smtp_tls.trim();
    if tls == "implicit" || tls == "starttls" {
        body.insert("smtp_tls".into(), json!(tls));
    }

    let from_email = f.from_email.trim();
    if !from_email.is_empty() && !from_email.contains('@') {
        return Err("From email must be a valid address.".to_string());
    }

    for (key, raw) in [
        ("smtp_host", &f.smtp_host),
        ("smtp_username", &f.smtp_username),
        ("smtp_password", &f.smtp_password),
        ("from_email", &f.from_email),
        ("from_name", &f.from_name),
        ("admin_notification_emails", &f.admin_notification_emails),
    ] {
        let t = raw.trim();
        if !t.is_empty() {
            body.insert(key.into(), json!(t));
        }
    }

    Ok(serde_json::Value::Object(body))
}

pub async fn email_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<EmailSettingsForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let error = match email_update_body(&f) {
        Ok(body) => match admin_api::update_email_config(&st.api, c.forward.as_deref(), body).await
        {
            Ok(()) => return redirect_cookies("/admin/email", &c.set_cookies),
            Err(e) => e.user_message(),
        },
        Err(msg) => msg,
    };

    // Re-render with the persisted values plus the inline error.
    let cfg = admin_api::email_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = html! {
        (error_box(&error))
        (email_settings_content(cfg.as_ref()))
    };
    admin_response(&c, &user, "/admin/email", "Email · Bunyip", content)
}

/// POST /admin/email/test - BUNYIP-433. Run the SMTP "Test connection" probe
/// against the saved settings and re-render the email page with a banner naming
/// the outcome (and, on failure, the stage that failed). No mail is sent.
pub async fn email_test(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let banner = match admin_api::test_email_config(&st.api, c.forward.as_deref()).await {
        Ok(r) if r.ok => success_box(&r.message),
        // Reached the relay but a stage failed: name it (connect / tls / auth).
        Ok(r) => error_box(&format!(
            "SMTP test failed at the {} stage. {}",
            r.stage, r.message
        )),
        // Transport / rate-limit (429) error before the probe could report.
        Err(e) => error_box(&e.user_message()),
    };

    let cfg = admin_api::email_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = html! {
        (banner)
        (email_settings_content(cfg.as_ref()))
    };
    admin_response(&c, &user, "/admin/email", "Email · Bunyip", content)
}
