//! Admin panel: System settings backed by the YAML config file (BUNYIP-580).
//!
//! A web form over the BUNYIP-579 system-config file. Saving writes the whole
//! file (validated api-side before the write); every change applies on the next
//! restart, and an environment variable still overrides the file.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::admin as admin_api;
use crate::api::types::SystemConfigResponse;
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{button_class, error_box, icon};
use crate::web::{redirect_cookies, AppState};

fn toggle(id: &str, label: &str, on: bool) -> Markup {
    html! {
        div class="space-y-2" {
            label for=(id) class="text-sm font-medium" { (label) }
            select id=(id) name=(id) class=(dashboard_input()) {
                option value="true" selected[on] { "Enabled" }
                option value="false" selected[!on] { "Disabled" }
            }
        }
    }
}

fn text_field(id: &str, label: &str, value: &str, placeholder: &str, help: &str) -> Markup {
    html! {
        div class="space-y-2" {
            label for=(id) class="text-sm font-medium" { (label) }
            input id=(id) name=(id) value=(value) placeholder=(placeholder) class=(dashboard_input());
            @if !help.is_empty() { p class="text-xs text-muted-foreground" { (help) } }
        }
    }
}

pub(super) fn system_settings_content(cfg: Option<&SystemConfigResponse>) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "System" }
                p class="mt-2 text-muted-foreground" {
                    "Deployment-level settings, stored in the config file rather than the database. "
                    "Every change here applies on the next restart, and an environment variable still overrides the file. See "
                    a href="/docs" class="text-primary-text hover:underline" { "the documentation" } " for the full reference."
                }
            }
            @match cfg {
                None => (error_box("Could not load the system config.")),
                Some(e) => div class="space-y-6" {
                    div class="rounded-md border border-border/60 bg-muted/40 px-4 py-3 text-sm text-muted-foreground" {
                        "File: " code { (e.path) } ". Changes take effect after the next restart."
                    }
                    form method="post" action="/admin/system-config" class="space-y-6" {
                    (admin_block_grid(vec![
                        admin_block(
                            "Hostnames",
                            Some("Public origins the API trusts and links to. Restart required."),
                            html! {
                                div class="space-y-4" {
                                    (text_field("cors_origin", "CORS origin(s)", &e.cors_origin, "https://app.example.com", "Comma-separated allowed browser origins."))
                                    (text_field("web_origin", "Web origin", &e.web_origin, "https://app.example.com", "Absolute URL of the login UI; blank uses the first CORS origin."))
                                    (text_field("cookie_domain", "Cookie domain", &e.cookie_domain, ".example.com", "Blank scopes cookies to the exact host."))
                                }
                            },
                        ),
                        admin_block(
                            "Features",
                            Some("Opt-in switches. Restart required."),
                            html! {
                                div class="space-y-4" {
                                    (toggle("login_approval_enabled", "Suspicious-login approval gate", e.login_approval_enabled))
                                    (toggle("signup_bot_guard_enabled", "Signup bot guard", e.signup_bot_guard_enabled))
                                }
                            },
                        ),
                        admin_block(
                            "Country access",
                            Some("Country allow/deny for sign-in (BUNYIP-581). Restart required."),
                            html! {
                                div class="space-y-4" {
                                    (text_field("country_allow", "Allow list", &e.country_allow, "US, GB", "ISO alpha-2 codes; blank allows all."))
                                    (text_field("country_deny", "Deny list", &e.country_deny, "RU, KP", "ISO alpha-2 codes refused sign-in; applied after allow."))
                                }
                            },
                        ),
                    ]))
                    button type="submit" class=(button_class("default", "default", "")) { (icon("save", "mr-2 h-4 w-4")) "Save" }
                    }
                },
            }
        }
    }
}

pub async fn system_config(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let cfg = admin_api::system_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = system_settings_content(cfg.as_ref());
    admin_response(&c, &user, "/admin/system-config", "System", content)
}

#[derive(Deserialize)]
pub struct SystemSettingsForm {
    #[serde(default)]
    pub cors_origin: String,
    #[serde(default)]
    pub web_origin: String,
    #[serde(default)]
    pub cookie_domain: String,
    #[serde(default)]
    pub login_approval_enabled: String,
    #[serde(default)]
    pub signup_bot_guard_enabled: String,
    #[serde(default)]
    pub country_allow: String,
    #[serde(default)]
    pub country_deny: String,
}

/// The full PUT body. The whole file is rewritten from the form, so a cleared
/// field clears the setting. The API validates before writing (BUNYIP-580 AC4).
pub(super) fn system_config_update_body(f: &SystemSettingsForm) -> Value {
    json!({
        "cors_origin": f.cors_origin.trim(),
        "web_origin": f.web_origin.trim(),
        "cookie_domain": f.cookie_domain.trim(),
        "login_approval_enabled": f.login_approval_enabled.trim() == "true",
        "signup_bot_guard_enabled": f.signup_bot_guard_enabled.trim() == "true",
        "country_allow": f.country_allow.trim(),
        "country_deny": f.country_deny.trim(),
    })
}

pub async fn system_config_save(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<SystemSettingsForm>,
) -> Response {
    let (user, c) = match admin_guard(&st, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };

    let error = match admin_api::update_system_config(
        &st.api,
        c.forward.as_deref(),
        system_config_update_body(&f),
    )
    .await
    {
        Ok(()) => return redirect_cookies("/admin/system-config", &c.set_cookies),
        Err(e) => e.user_message(),
    };

    // Re-render with the persisted values plus the inline error.
    let cfg = admin_api::system_config(&st.api, c.forward.as_deref())
        .await
        .ok();
    let content = html! {
        (error_box(&error))
        (system_settings_content(cfg.as_ref()))
    };
    admin_response(&c, &user, "/admin/system-config", "System", content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_body_sends_the_full_config() {
        let f = SystemSettingsForm {
            cors_origin: "  https://app.example  ".into(),
            web_origin: String::new(),
            cookie_domain: ".example.com".into(),
            login_approval_enabled: "true".into(),
            signup_bot_guard_enabled: "false".into(),
            country_allow: "US, GB".into(),
            country_deny: String::new(),
        };
        let body = system_config_update_body(&f);
        assert_eq!(body["cors_origin"], json!("https://app.example"));
        assert_eq!(body["login_approval_enabled"], json!(true));
        assert_eq!(body["signup_bot_guard_enabled"], json!(false));
        assert_eq!(body["country_allow"], json!("US, GB"));
    }
}
