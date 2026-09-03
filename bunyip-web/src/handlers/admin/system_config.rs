//! Admin panel: System settings backed by the file configuration layer
//! (BUNYIP-580/644).
//!
//! A web form over the application-level deployment settings. Saving writes one
//! file per setting into the file layer directory (validated api-side before the
//! write); every change applies on the next restart, and the file layer
//! outranks the environment.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::admin as admin_api;
use crate::api::types::{SettingProvenance, SystemConfigResponse};
use crate::handlers::{admin_guard, admin_response, dashboard_input};
use crate::views::layout::{admin_block, admin_block_grid};
use crate::views::ui::{button_class, error_box, icon};
use crate::web::{redirect_cookies, AppState};

fn toggle(id: &str, label: &str, on: bool, provenance: Markup) -> Markup {
    html! {
        div class="space-y-2" {
            label for=(id) class="text-sm font-medium" { (label) }
            select id=(id) name=(id) class=(dashboard_input()) {
                option value="true" selected[on] { "Enabled" }
                option value="false" selected[!on] { "Disabled" }
            }
            (provenance)
        }
    }
}

fn text_field(
    id: &str,
    label: &str,
    value: &str,
    placeholder: &str,
    help: &str,
    provenance: Markup,
) -> Markup {
    html! {
        div class="space-y-2" {
            label for=(id) class="text-sm font-medium" { (label) }
            input id=(id) name=(id) value=(value) placeholder=(placeholder) class=(dashboard_input());
            @if !help.is_empty() { p class="text-xs text-muted-foreground" { (help) } }
            (provenance)
        }
    }
}

/// BUNYIP-648: the one line under each field naming the provider that serves it,
/// and what saving here does to the other providers holding it. The api reports
/// the same facts `config-status` does and never a value, so this sentence is
/// built here rather than relayed.
fn provenance_text(entry: Option<&SettingProvenance>, field: &str) -> String {
    let var = field.to_uppercase();
    // An older api sends no provenance. Saying so beats rendering a guess: the
    // page must not claim the built-in default is serving a value it never asked
    // about.
    let Some(entry) = entry else {
        return "This deployment's API did not report which provider serves this setting."
            .to_string();
    };
    let held_by_environment = entry.providers.iter().any(|p| p == "environment");
    match entry.serving.as_deref() {
        Some("environment") => format!(
            "Served by the {var} environment variable. Saving here writes the file layer, which \
             overrides that variable from the next restart."
        ),
        Some("file") if held_by_environment => format!(
            "Served by the file layer, which this form writes. The {var} environment variable also \
             sets it and is ignored; it becomes live again if the file value is cleared."
        ),
        Some("file") => "Served by the file layer, which this form writes.".to_string(),
        Some(other) => format!("Served by the {other} provider."),
        None => {
            "No provider sets it, so the built-in default applies. Saving here writes the file \
                 layer."
                .to_string()
        }
    }
}

/// The provenance line for one form field. Every field on this page renders one;
/// `every_rendered_setting_carries_its_provenance` fails the build otherwise.
fn provenance_line(cfg: &SystemConfigResponse, field: &str) -> Markup {
    let entry = cfg
        .provenance
        .iter()
        .find(|p| p.key.eq_ignore_ascii_case(field));
    html! {
        p class="text-xs text-muted-foreground" data-provenance=(field) {
            (provenance_text(entry, field))
        }
    }
}

pub(super) fn system_settings_content(cfg: Option<&SystemConfigResponse>) -> Markup {
    html! {
        div class="space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "System" }
                p class="mt-2 text-muted-foreground" {
                    "Application-level deployment settings, stored in the file configuration layer rather than the database. "
                    "System-level origins and domains are set through the environment, not here. "
                    "Every change here applies on the next restart, and these values override the matching environment variables. See "
                    a href="/docs" class="text-primary-text hover:underline" { "the documentation" } " for the full reference."
                }
            }
            @match cfg {
                None => (error_box("Could not load the system config.")),
                Some(e) => div class="space-y-6" {
                    div class="rounded-md border border-border/60 bg-muted/40 px-4 py-3 text-sm text-muted-foreground" {
                        "Directory: " code { (e.path) } ". Changes take effect after the next restart."
                    }
                    form method="post" action="/admin/system-config" class="space-y-6" {
                    (admin_block_grid(vec![
                        admin_block(
                            "Features",
                            Some("Opt-in switches. Restart required."),
                            html! {
                                div class="space-y-4" {
                                    (toggle("login_approval_enabled", "Suspicious-login approval gate", e.login_approval_enabled, provenance_line(e, "login_approval_enabled")))
                                    (toggle("signup_bot_guard_enabled", "Signup bot guard", e.signup_bot_guard_enabled, provenance_line(e, "signup_bot_guard_enabled")))
                                }
                            },
                        ),
                        admin_block(
                            "Country access",
                            Some("Country allow/deny for sign-in. Restart required."),
                            html! {
                                div class="space-y-4" {
                                    (text_field("country_allow", "Allow list", &e.country_allow, "US, GB", "ISO alpha-2 codes; blank allows all.", provenance_line(e, "country_allow")))
                                    (text_field("country_deny", "Deny list", &e.country_deny, "RU, KP", "ISO alpha-2 codes refused sign-in; applied after allow.", provenance_line(e, "country_deny")))
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
    pub login_approval_enabled: String,
    #[serde(default)]
    pub signup_bot_guard_enabled: String,
    #[serde(default)]
    pub country_allow: String,
    #[serde(default)]
    pub country_deny: String,
}

/// The full PUT body. Every setting is rewritten from the form, so a cleared
/// field clears the setting. The API validates before writing (BUNYIP-580 AC4).
pub(super) fn system_config_update_body(f: &SystemSettingsForm) -> Value {
    json!({
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

    fn provenance(key: &str, serving: Option<&str>, providers: &[&str]) -> SettingProvenance {
        SettingProvenance {
            key: key.to_string(),
            serving: serving.map(str::to_string),
            condition: match (serving, providers.len()) {
                (None, _) => "default",
                (Some(_), 0 | 1) => "use",
                _ => "overridden",
            }
            .to_string(),
            providers: providers.iter().map(|p| (*p).to_string()).collect(),
        }
    }

    fn config(provenance: Vec<SettingProvenance>) -> SystemConfigResponse {
        SystemConfigResponse {
            path: "/app/config".into(),
            login_approval_enabled: true,
            signup_bot_guard_enabled: false,
            country_allow: "US".into(),
            country_deny: String::new(),
            provenance,
        }
    }

    /// Every `name="..."` control the page renders, so the guard below sees the
    /// fields as the browser does rather than as a list someone remembered to
    /// keep current.
    fn rendered_fields(html: &str) -> Vec<String> {
        html.match_indices("name=\"")
            .map(|(i, m)| {
                let rest = &html[i + m.len()..];
                rest[..rest.find('"').expect("a closed attribute")].to_string()
            })
            .collect()
    }

    /// BUNYIP-648 AC3: a setting rendered with no provenance line fails the
    /// build. The fields are read out of the markup, so a new one added to the
    /// form without a line is caught too.
    #[test]
    fn every_rendered_setting_carries_its_provenance() {
        let cfg = config(vec![
            provenance("LOGIN_APPROVAL_ENABLED", Some("file"), &["file"]),
            provenance(
                "SIGNUP_BOT_GUARD_ENABLED",
                Some("environment"),
                &["environment"],
            ),
            provenance("COUNTRY_ALLOW", None, &[]),
            provenance("COUNTRY_DENY", Some("file"), &["file", "environment"]),
        ]);
        let html = system_settings_content(Some(&cfg)).into_string();
        let fields = rendered_fields(&html);
        assert!(!fields.is_empty(), "the form renders its settings");
        for field in fields {
            assert!(
                html.contains(&format!("data-provenance=\"{field}\"")),
                "{field} is rendered with no provenance line"
            );
        }
    }

    /// AC2: the environment case says which variable serves the setting and what
    /// saving does to it, and a shadowed environment copy is named as ignored.
    #[test]
    fn the_provenance_line_names_the_provider_and_what_saving_does() {
        let env = provenance(
            "SIGNUP_BOT_GUARD_ENABLED",
            Some("environment"),
            &["environment"],
        );
        let line = provenance_text(Some(&env), "signup_bot_guard_enabled");
        assert!(line.contains("SIGNUP_BOT_GUARD_ENABLED environment variable"));
        assert!(line.contains("overrides that variable from the next restart"));

        let overridden = provenance("COUNTRY_DENY", Some("file"), &["file", "environment"]);
        let line = provenance_text(Some(&overridden), "country_deny");
        assert!(line.starts_with("Served by the file layer"));
        assert!(line.contains("COUNTRY_DENY environment variable also sets it and is ignored"));

        let default = provenance("COUNTRY_ALLOW", None, &[]);
        assert!(provenance_text(Some(&default), "country_allow").contains("built-in default"));

        // An api that reports nothing says so rather than reading as a default.
        assert!(provenance_text(None, "country_allow").contains("did not report"));
    }

    #[test]
    fn update_body_sends_only_application_level_keys() {
        let f = SystemSettingsForm {
            login_approval_enabled: "true".into(),
            signup_bot_guard_enabled: "false".into(),
            country_allow: "US, GB".into(),
            country_deny: String::new(),
        };
        let body = system_config_update_body(&f);
        assert_eq!(body["login_approval_enabled"], json!(true));
        assert_eq!(body["signup_bot_guard_enabled"], json!(false));
        assert_eq!(body["country_allow"], json!("US, GB"));
        // BUNYIP-622: the form and its body cannot carry a system-level origin.
        assert!(body.get("cors_origin").is_none());
        assert!(body.get("cookie_domain").is_none());
    }
}
