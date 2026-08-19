//! Admin system-config screen (BUNYIP-580): view and edit the BUNYIP-579 YAML
//! config layer from the admin UI. Reads/writes the file `SysConfig` loads at
//! startup; changes apply on the next restart (environment variables still
//! override the file). Gated behind the existing admin check.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::responses::{get_request_id, success};
use bunyip_domain::sys_config::{SysConfig, SysConfigFile};

/// The current file values, shaped for the admin form. Country lists are
/// comma-joined for a text input.
#[derive(Debug, Serialize)]
pub struct SystemConfigResponse {
    /// The file these values are read from and written to.
    pub path: String,
    pub cors_origin: String,
    pub web_origin: String,
    pub cookie_domain: String,
    pub login_approval_enabled: bool,
    pub signup_bot_guard_enabled: bool,
    pub country_allow: String,
    pub country_deny: String,
}

fn response_from_file(file: &SysConfigFile) -> SystemConfigResponse {
    SystemConfigResponse {
        path: SysConfig::file_path().display().to_string(),
        cors_origin: file.hostnames.cors_origin.clone().unwrap_or_default(),
        web_origin: file.hostnames.web_origin.clone().unwrap_or_default(),
        cookie_domain: file.hostnames.cookie_domain.clone().unwrap_or_default(),
        login_approval_enabled: file.features.login_approval_enabled.unwrap_or(false),
        signup_bot_guard_enabled: file.features.signup_bot_guard_enabled.unwrap_or(false),
        country_allow: file.country_access.allow.join(", "),
        country_deny: file.country_access.deny.join(", "),
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateSystemConfigRequest {
    pub cors_origin: Option<String>,
    pub web_origin: Option<String>,
    pub cookie_domain: Option<String>,
    pub login_approval_enabled: Option<bool>,
    pub signup_bot_guard_enabled: Option<bool>,
    pub country_allow: Option<String>,
    pub country_deny: Option<String>,
}

/// Parse a comma/space separated list of ISO 3166-1 alpha-2 codes, validating
/// each is two ASCII letters, so an invalid list is rejected before the file is
/// touched (BUNYIP-580 AC4).
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

fn nonempty(v: &Option<String>) -> Option<String> {
    v.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// GET /v1/admin/system-config
pub async fn get_system_config(
    req: HttpRequest,
    _admin: AdminUser,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    Ok(success(
        response_from_file(&SysConfig::read_file()),
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

    // Validate everything BEFORE touching the file, so an invalid submit never
    // leaves it broken (AC4).
    for (field, url) in [
        ("cors_origin", nonempty(&body.cors_origin)),
        ("web_origin", nonempty(&body.web_origin)),
    ] {
        if let Some(url) = url {
            if !url.contains("://") {
                return Err(AppError::validation(field, "must be an absolute URL"));
            }
        }
    }
    let country_allow = match &body.country_allow {
        Some(raw) => Some(parse_country_list(raw)?),
        None => None,
    };
    let country_deny = match &body.country_deny {
        Some(raw) => Some(parse_country_list(raw)?),
        None => None,
    };

    // Apply the submitted values onto the current file, then write atomically.
    let mut file = SysConfig::read_file();
    if body.cors_origin.is_some() {
        file.hostnames.cors_origin = nonempty(&body.cors_origin);
    }
    if body.web_origin.is_some() {
        file.hostnames.web_origin = nonempty(&body.web_origin);
    }
    if body.cookie_domain.is_some() {
        file.hostnames.cookie_domain = nonempty(&body.cookie_domain);
    }
    if let Some(v) = body.login_approval_enabled {
        file.features.login_approval_enabled = Some(v);
    }
    if let Some(v) = body.signup_bot_guard_enabled {
        file.features.signup_bot_guard_enabled = Some(v);
    }
    if let Some(a) = country_allow {
        file.country_access.allow = a;
    }
    if let Some(d) = country_deny {
        file.country_access.deny = d;
    }

    SysConfig::write_file(&file)
        .map_err(|e| AppError::internal(format!("could not write the config file: {e}")))?;

    Ok(success(response_from_file(&file), request_id))
}

#[cfg(test)]
mod tests {
    use super::*;

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
