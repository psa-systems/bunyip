//! The Mirzam newsletter integration settings (BUNYIP-997).
//!
//! Mirzam is the suite's newsletter service. bunyip keeps its account holders
//! on two Mirzam lists (product updates and required account notices) by
//! calling Mirzam's REST API, so the integration needs the Mirzam site address,
//! the two list slugs, an on/off switch and an API token. The first four are the
//! singleton `mirzam_config` row; the token is the governed secret
//! [`GovernedSecret::MirzamApiToken`], whose `database` provider is the row's
//! ciphertext columns.
//!
//! [`GovernedSecret::MirzamApiToken`]: crate::config::GovernedSecret::MirzamApiToken

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MirzamConfigRow {
    pub id: i32,
    pub enabled: bool,
    pub base_url: String,
    pub updates_list: String,
    pub notices_list: String,
    pub api_token: Option<Vec<u8>>,
    pub api_token_nonce: Option<Vec<u8>>,
    pub key_version: i16,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

impl MirzamConfigRow {
    /// Decrypt the API token held by the `database` provider, mirroring
    /// `EmailConfig::db_imap_password`. A ciphertext no key decrypts is
    /// reported at `error` and treated as no token, so a stale row never blocks
    /// boot.
    pub fn db_api_token(&self, key_set: &crate::services::AppKeySet) -> Option<String> {
        let (ciphertext, nonce) = match (&self.api_token, &self.api_token_nonce) {
            (Some(ct), Some(nonce)) => (ct, nonce),
            _ => return None,
        };
        match crate::models::stripe::decrypt_secret(key_set, ciphertext, nonce, self.key_version) {
            Ok(token) => Some(token),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    key_version = self.key_version,
                    "mirzam_config.api_token does not decrypt with APP_ENCRYPTION_KEY or any \
                     APP_ENCRYPTION_KEY_PREV entry; treating the database provider as holding \
                     no Mirzam API token"
                );
                None
            }
        }
    }
}

/// `PUT /v1/admin/mirzam`. The four settings are replaced whole; `api_token`
/// empty or absent leaves the stored token unchanged.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateMirzamConfigRequest {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub updates_list: String,
    #[serde(default)]
    pub notices_list: String,
    #[serde(default)]
    pub api_token: Option<String>,
}

/// The admin read model. The token is never sent back, not even masked:
/// `has_api_token` is the only fact about it that leaves the server.
#[derive(Debug, Clone, Serialize)]
pub struct MirzamConfigResponse {
    pub enabled: bool,
    pub base_url: String,
    pub updates_list: String,
    pub notices_list: String,
    pub has_api_token: bool,
    /// False in `SECRETS_STORAGE=environment`, the one read-only provider.
    pub api_token_editable: bool,
    /// The declared provider of the token. The wire key keeps the
    /// `secrets_storage` spelling of the variable it reports (BUNYIP-642).
    pub secrets_storage: String,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

impl MirzamConfigResponse {
    pub fn new(
        row: &MirzamConfigRow,
        provider: crate::config::SecretsProvider,
        has_api_token: bool,
    ) -> Self {
        Self {
            enabled: row.enabled,
            base_url: row.base_url.clone(),
            updates_list: row.updates_list.clone(),
            notices_list: row.notices_list.clone(),
            has_api_token,
            api_token_editable: provider.is_writable(),
            secrets_storage: provider.as_str().to_string(),
            updated_at: row.updated_at,
            updated_by: row.updated_by,
        }
    }
}

/// The four non-secret settings, validated and normalised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirzamSettings {
    pub enabled: bool,
    /// Trimmed, with no trailing `/`, so `{base_url}/api/v1/...` is one join.
    pub base_url: String,
    pub updates_list: String,
    pub notices_list: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirzamFieldError {
    pub field: &'static str,
    pub message: String,
}

impl MirzamFieldError {
    fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }
}

pub const MAX_MIRZAM_BASE_URL_LEN: usize = 2048;
/// Mirzam's own limit on a list slug.
pub const MAX_MIRZAM_SLUG_LEN: usize = 64;

/// Mirzam's list-slug rule: lowercase words of letters and digits joined by
/// single dashes, at most 64 characters (the `lists.slug` CHECK in Mirzam).
pub fn valid_list_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= MAX_MIRZAM_SLUG_LEN
        && slug.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// Validate the four settings and return them normalised.
///
/// A blank field is allowed only while the integration is off, so a half-typed
/// configuration can be saved, but switching it on needs the address and both
/// slugs. The API token is checked by the caller, which knows the declared
/// provider.
pub fn validate_mirzam_settings(
    enabled: bool,
    base_url: &str,
    updates_list: &str,
    notices_list: &str,
) -> Result<MirzamSettings, MirzamFieldError> {
    let base_url = base_url.trim().trim_end_matches('/');
    let updates_list = updates_list.trim();
    let notices_list = notices_list.trim();

    if base_url.is_empty() {
        if enabled {
            return Err(MirzamFieldError::new(
                "base_url",
                "Enter the Mirzam site address before switching the integration on.",
            ));
        }
    } else {
        if base_url.len() > MAX_MIRZAM_BASE_URL_LEN {
            return Err(MirzamFieldError::new(
                "base_url",
                format!("Must be at most {MAX_MIRZAM_BASE_URL_LEN} characters."),
            ));
        }
        let parsed = url::Url::parse(base_url).map_err(|_| {
            MirzamFieldError::new(
                "base_url",
                "Must be an absolute address such as https://news.example.com.",
            )
        })?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(MirzamFieldError::new(
                "base_url",
                "Must be an http:// or https:// address with a host name.",
            ));
        }
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(MirzamFieldError::new(
                "base_url",
                "Must be the site address alone, with no sign-in details, query or fragment.",
            ));
        }
    }

    for (field, slug, label) in [
        ("updates_list", updates_list, "product-updates"),
        ("notices_list", notices_list, "notices"),
    ] {
        if slug.is_empty() {
            if enabled {
                return Err(MirzamFieldError::new(
                    field,
                    format!("Enter the {label} list's slug before switching the integration on."),
                ));
            }
        } else if !valid_list_slug(slug) {
            return Err(MirzamFieldError::new(
                field,
                format!(
                    "Must be a Mirzam list slug: lowercase letters and digits, words joined by \
                     single dashes, at most {MAX_MIRZAM_SLUG_LEN} characters."
                ),
            ));
        }
    }
    if !updates_list.is_empty() && updates_list == notices_list {
        return Err(MirzamFieldError::new(
            "notices_list",
            "Must be a different list from the product-updates list.",
        ));
    }

    Ok(MirzamSettings {
        enabled,
        base_url: base_url.to_string(),
        updates_list: updates_list.to_string(),
        notices_list: notices_list.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_follow_mirzams_rule() {
        for ok in ["product-updates", "notices", "a1-b2", "x"] {
            assert!(valid_list_slug(ok), "{ok}");
        }
        for bad in [
            "",
            "Product-Updates",
            "product--updates",
            "-updates",
            "updates-",
            "product_updates",
            "product updates",
            &"a".repeat(65),
        ] {
            assert!(!valid_list_slug(bad), "{bad}");
        }
    }

    #[test]
    fn a_complete_configuration_is_normalised() {
        let s = validate_mirzam_settings(
            true,
            "  https://news.psa.systems/ ",
            " product-updates ",
            "notices",
        )
        .unwrap();
        assert_eq!(s.base_url, "https://news.psa.systems");
        assert_eq!(s.updates_list, "product-updates");
        assert_eq!(s.notices_list, "notices");
        assert!(s.enabled);
    }

    #[test]
    fn blanks_are_allowed_only_while_switched_off() {
        assert!(validate_mirzam_settings(false, "", "", "").is_ok());
        assert_eq!(
            validate_mirzam_settings(true, "", "updates", "notices")
                .unwrap_err()
                .field,
            "base_url"
        );
        assert_eq!(
            validate_mirzam_settings(true, "https://news.example.com", "", "notices")
                .unwrap_err()
                .field,
            "updates_list"
        );
        assert_eq!(
            validate_mirzam_settings(true, "https://news.example.com", "updates", "")
                .unwrap_err()
                .field,
            "notices_list"
        );
    }

    #[test]
    fn the_address_must_be_an_absolute_http_site_address() {
        for bad in [
            "news.example.com",
            "ftp://news.example.com",
            "https://user:pw@news.example.com",
            "https://news.example.com/?x=1",
            "https://news.example.com/#top",
            "/api/v1",
        ] {
            let err = validate_mirzam_settings(false, bad, "", "").unwrap_err();
            assert_eq!(err.field, "base_url", "{bad}");
        }
        assert!(validate_mirzam_settings(false, "http://127.0.0.1:8080", "", "").is_ok());
    }

    #[test]
    fn the_two_lists_must_differ() {
        let err = validate_mirzam_settings(false, "", "updates", "updates").unwrap_err();
        assert_eq!(err.field, "notices_list");
    }

    #[test]
    fn a_bad_slug_names_its_field() {
        let err = validate_mirzam_settings(false, "", "Updates", "").unwrap_err();
        assert_eq!(err.field, "updates_list");
        let err = validate_mirzam_settings(false, "", "", "no tices").unwrap_err();
        assert_eq!(err.field, "notices_list");
    }
}
