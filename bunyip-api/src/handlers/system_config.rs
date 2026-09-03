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
}

fn response_from(settings: &SystemSettings) -> SystemConfigResponse {
    SystemConfigResponse {
        path: SystemSettings::directory().display().to_string(),
        login_approval_enabled: settings.login_approval_enabled,
        signup_bot_guard_enabled: settings.signup_bot_guard_enabled,
        country_allow: settings.country_allow.join(", "),
        country_deny: settings.country_deny.join(", "),
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
    Ok(success(
        response_from(&SystemSettings::current()),
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

    Ok(success(response_from(&settings), request_id))
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
