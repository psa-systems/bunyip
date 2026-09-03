//! Admin system-config screen (BUNYIP-580): view and edit the application-level
//! deployment settings from the admin UI. Reads and writes the ONE file-based
//! configuration layer (BUNYIP-644), the directory the file provider serves;
//! changes apply on the next restart. Gated behind the existing admin check.
//!
//! BUNYIP-622: this endpoint writes a `SystemSettings`, which by type carries
//! only application-level keys, and `SystemSettings::entries` is the only
//! mapping it has from a field to a file. The system-level origins and domains
//! (`CORS_ORIGIN`, `BUNYIP_WEB_ORIGIN`, `COOKIE_DOMAIN`) are environment-only
//! and have no field here, so there is no code path through which this endpoint
//! could persist one. The absence of those fields IS the enforcement.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::responses::{get_request_id, success};
use bunyip_domain::config_providers::{ConfigStack, SYSTEM_SETTINGS_KEYS};
use bunyip_domain::sys_config::SystemSettings;

/// The current values, shaped for the admin form. Country lists are comma-joined
/// for a text input.
#[derive(Debug, Serialize)]
pub struct SystemConfigResponse {
    /// The file layer directory these values are read from and written to. The
    /// wire key is unchanged from the YAML layer it replaced (BUNYIP-644).
    pub path: String,
    pub login_approval_enabled: bool,
    pub signup_bot_guard_enabled: bool,
    pub country_allow: String,
    pub country_deny: String,
    /// BUNYIP-648: where each of the four settings above comes from, one entry
    /// per `SYSTEM_SETTINGS_KEYS` key.
    pub provenance: Vec<SettingProvenance>,
}

/// One setting's provenance, the same three facts `config-status` reports per
/// key and nothing more: which providers hold it, which one serves it, and the
/// condition. It carries no configuration VALUE, for the reason the status
/// report carries none (BUNYIP-643) - the values on this page are the four
/// fields above, and a provider's ignored copy is not one of them.
#[derive(Debug, Serialize)]
pub struct SettingProvenance {
    /// The declared configuration key, which is the form field's name in upper
    /// case and the environment variable that carries it.
    pub key: String,
    /// The provider serving it: `database` / `file` / `environment`. `None` is
    /// the built-in default.
    pub serving: Option<String>,
    /// `use` / `default` / `overridden` / `shadowed`.
    pub condition: String,
    /// Every provider holding a value, highest priority first. This is what
    /// tells the page that saving will shadow another provider.
    pub providers: Vec<String>,
}

/// Resolve each system setting's provenance through `stack`. Pure over the
/// stack, so the caller decides which one (and reads it once).
fn provenance_from(stack: &ConfigStack) -> Vec<SettingProvenance> {
    SYSTEM_SETTINGS_KEYS
        .iter()
        .map(|key| {
            let verdict = stack.resolve(key);
            SettingProvenance {
                key: (*key).to_string(),
                serving: verdict.serving().map(|kind| kind.to_string()),
                condition: verdict.condition().to_string(),
                providers: stack
                    .holders(key)
                    .iter()
                    .map(|kind| kind.to_string())
                    .collect(),
            }
        })
        .collect()
}

fn response_from(settings: &SystemSettings, stack: &ConfigStack) -> SystemConfigResponse {
    SystemConfigResponse {
        path: SystemSettings::directory().display().to_string(),
        login_approval_enabled: settings.login_approval_enabled,
        signup_bot_guard_enabled: settings.signup_bot_guard_enabled,
        country_allow: settings.country_allow.join(", "),
        country_deny: settings.country_deny.join(", "),
        provenance: provenance_from(stack),
    }
}

/// BUNYIP-622: the writable fields are application-level ONLY. There is
/// deliberately no `cors_origin` / `web_origin` / `cookie_domain` field: those
/// are system-level and environment-only, so the request cannot carry them and
/// the handler has nothing to write. Any such key an old client sends is dropped
/// by serde as an unknown field, never persisted.
#[derive(Debug, Deserialize)]
pub struct UpdateSystemConfigRequest {
    pub login_approval_enabled: Option<bool>,
    pub signup_bot_guard_enabled: Option<bool>,
    pub country_allow: Option<String>,
    pub country_deny: Option<String>,
}

/// Parse a comma/space separated list of ISO 3166-1 alpha-2 codes, validating
/// each is two ASCII letters, so an invalid list is rejected before anything is
/// written (BUNYIP-580 AC4).
fn parse_country_list(raw: &str) -> Result<Vec<String>, AppError> {
    let mut out = Vec::new();
    for token in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        if t.len() != 2 || !t.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(AppError::validation(
                "country",
                format!("'{t}' is not a 2-letter ISO country code"),
            ));
        }
        out.push(t.to_uppercase());
    }
    Ok(out)
}

/// GET /v1/admin/system-config
pub async fn get_system_config(
    req: HttpRequest,
    _admin: AdminUser,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    // One stack for both halves: the effective values and where each came from
    // are read from the same providers, so the page cannot show a value from one
    // reading and a provenance from another.
    let stack = ConfigStack::deployment();
    Ok(success(
        response_from(&SystemSettings::resolve(&stack), &stack),
        request_id,
    ))
}

/// PUT /v1/admin/system-config
pub async fn update_system_config(
    req: HttpRequest,
    _admin: AdminUser,
    body: web::Json<UpdateSystemConfigRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Validate everything BEFORE writing, so an invalid submit never leaves the
    // layer half-updated (AC4).
    let country_allow = match &body.country_allow {
        Some(raw) => Some(parse_country_list(raw)?),
        None => None,
    };
    let country_deny = match &body.country_deny {
        Some(raw) => Some(parse_country_list(raw)?),
        None => None,
    };

    // Apply the submitted values onto the current effective ones, then write one
    // file per key. BUNYIP-622: only application-level keys are writable here;
    // the system-level origins have no field on the request and no field on
    // `SystemSettings`.
    let mut settings = SystemSettings::current();
    if let Some(v) = body.login_approval_enabled {
        settings.login_approval_enabled = v;
    }
    if let Some(v) = body.signup_bot_guard_enabled {
        settings.signup_bot_guard_enabled = v;
    }
    if let Some(a) = country_allow {
        settings.country_allow = a;
    }
    if let Some(d) = country_deny {
        settings.country_deny = d;
    }

    settings.save().map_err(|e| {
        AppError::internal(format!(
            "could not write the system settings to {}: {e}",
            SystemSettings::directory().display()
        ))
    })?;

    // The file provider snapshots its directory when it is built, so the
    // provenance the save produced is only visible through a stack loaded AFTER
    // the write.
    let stack = ConfigStack::deployment();
    Ok(success(response_from(&settings, &stack), request_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_system_level_key_in_the_request_body_is_dropped_not_persisted() {
        // BUNYIP-622 AC3/AC5: the settings API has no path to write a system-level
        // key. A body that tries to set an origin deserializes fine, but the
        // origin field does not exist on the request, so serde drops it as an
        // unknown field and only the application-level toggle survives to be
        // written. The enforcement is structural: there is no field to route it.
        let body: UpdateSystemConfigRequest = serde_json::from_value(serde_json::json!({
            "cors_origin": "https://attacker.example",
            "web_origin": "https://attacker.example",
            "cookie_domain": ".attacker.example",
            "login_approval_enabled": true,
        }))
        .expect("unknown fields are ignored");
        assert_eq!(body.login_approval_enabled, Some(true));
        assert_eq!(body.country_allow, None);
        // The settings this handler writes have no field for a system-level key
        // either; `sys_config::system_level_keys_never_enter_the_file_layer`
        // pins that half.
    }

    /// BUNYIP-648 AC1: every setting the page renders reports its provider and
    /// condition, and the provenance carries no configuration value.
    #[test]
    fn every_system_setting_reports_its_provider_and_condition() {
        let stack = ConfigStack::environment_only();
        let entries = provenance_from(&stack);

        let keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(
            keys, SYSTEM_SETTINGS_KEYS,
            "the page reports provenance for exactly the settings it renders"
        );
        for entry in &entries {
            assert!(
                ["use", "default", "overridden", "shadowed"].contains(&entry.condition.as_str()),
                "{} reported an unknown condition {}",
                entry.key,
                entry.condition
            );
            if let Some(serving) = &entry.serving {
                assert!(
                    entry.providers.contains(serving),
                    "{} is served by {serving}, which must be one of its holders",
                    entry.key
                );
            }
        }

        // No value reaches the wire: the serialized provenance names providers,
        // conditions and keys only.
        let json = serde_json::to_value(&entries).expect("provenance serializes");
        let fields: Vec<String> = json[0]
            .as_object()
            .expect("an object per setting")
            .keys()
            .cloned()
            .collect();
        assert_eq!(fields, ["condition", "key", "providers", "serving"]);
    }

    #[test]
    fn rejects_bad_country_codes_and_normalises_good_ones() {
        assert_eq!(
            parse_country_list("us, gb  fr").unwrap(),
            vec!["US", "GB", "FR"]
        );
        assert!(parse_country_list("usa").is_err(), "3-letter is rejected");
        assert!(parse_country_list("u1").is_err(), "non-alpha is rejected");
        assert!(parse_country_list("").unwrap().is_empty());
    }
}
