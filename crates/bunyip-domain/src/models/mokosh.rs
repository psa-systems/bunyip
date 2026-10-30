//! The Mokosh host settings bunyip keeps on the suite's behalf (BUNYIP-983).
//!
//! A hosted Mokosh needs the suite's Google OAuth client to sync a customer's
//! contacts. Before this it was set in Mokosh's own secret store by hand, once
//! per deployment (PMS-1430), which is the cross-management BUNYIP-855's design
//! removes: bunyip already holds the suite's shared facts, so the pair is set
//! here and read over `GET /v1/host/secrets/{KEY}`.
//!
//! The pair is split by what each half IS. `google_client_id` is public by
//! nature, travelling in every OAuth redirect the browser makes, so it is an
//! ordinary setting on the singleton `mokosh_config` row and the admin page
//! shows it. The secret half is the governed secret
//! [`GovernedSecret::MokoshGoogleClientSecret`], whose `database` provider is
//! this row's ciphertext columns and which no admin read ever returns.
//!
//! [`GovernedSecret::MokoshGoogleClientSecret`]: crate::config::GovernedSecret::MokoshGoogleClientSecret

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MokoshConfigRow {
    pub id: i32,
    pub google_client_id: String,
    pub google_client_secret: Option<Vec<u8>>,
    pub google_client_secret_nonce: Option<Vec<u8>>,
    pub key_version: i16,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

impl MokoshConfigRow {
    /// Decrypt the client secret held by the `database` provider, mirroring
    /// [`MirzamConfigRow::db_api_token`]. A ciphertext no key decrypts is
    /// reported at `error` and treated as absent, so a stale row never blocks
    /// boot: the secrets route then answers "not set", which is the honest
    /// answer and the one an operator can act on.
    ///
    /// [`MirzamConfigRow::db_api_token`]: crate::models::mirzam::MirzamConfigRow::db_api_token
    pub fn db_google_client_secret(&self, key_set: &crate::services::EncryptionKeySet) -> Option<String> {
        let (ciphertext, nonce) =
            match (&self.google_client_secret, &self.google_client_secret_nonce) {
                (Some(ct), Some(nonce)) => (ct, nonce),
                _ => return None,
            };
        match crate::models::stripe::decrypt_secret(key_set, ciphertext, nonce, self.key_version) {
            Ok(secret) => Some(secret),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    key_version = self.key_version,
                    "mokosh_config.google_client_secret does not decrypt with \
                     APP_ENCRYPTION_KEY or any APP_ENCRYPTION_KEY_PREV entry; treating the \
                     database provider as holding no Mokosh Google client secret"
                );
                None
            }
        }
    }
}

/// `PUT /v1/admin/mokosh`. The client id is replaced whole; `client_secret`
/// empty or absent leaves the stored secret unchanged, so an admin correcting
/// a mistyped id does not have to re-enter the secret.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateMokoshConfigRequest {
    #[serde(default)]
    pub google_client_id: String,
    #[serde(default)]
    pub google_client_secret: Option<String>,
    /// BUNYIP-855 D10: changing the client id invalidates every Google grant
    /// a tenant has already given, so the admin page asks again and sends this
    /// with the second attempt. Absent or false with a changed id is refused.
    #[serde(default)]
    pub confirm_client_id_change: bool,
}

/// The admin read model. The secret is never sent back, not even masked:
/// `has_google_client_secret` is the only fact about it that leaves the server.
#[derive(Debug, Clone, Serialize)]
pub struct MokoshConfigResponse {
    pub google_client_id: String,
    pub has_google_client_secret: bool,
    /// False in `SECRETS_STORAGE=environment`, the one read-only provider.
    pub google_client_secret_editable: bool,
    /// The declared provider of the secret. The wire key keeps the
    /// `secrets_storage` spelling of the variable it reports (BUNYIP-642).
    pub secrets_storage: String,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

impl MokoshConfigResponse {
    pub fn new(
        row: &MokoshConfigRow,
        provider: crate::config::SecretsProvider,
        has_google_client_secret: bool,
    ) -> Self {
        Self {
            google_client_id: row.google_client_id.clone(),
            has_google_client_secret,
            google_client_secret_editable: provider.is_writable(),
            secrets_storage: provider.as_str().to_string(),
            updated_at: row.updated_at,
            updated_by: row.updated_by,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MokoshFieldError {
    pub field: &'static str,
    pub message: String,
}

/// Google's own shape for an OAuth client id, which is what a mistyped value
/// fails on: `<digits>-<token>.apps.googleusercontent.com`.
///
/// Validated here rather than left to Google because the failure otherwise
/// surfaces as a tenant's contact sync refusing to connect, days later, in
/// another product. The pattern is deliberately loose about the middle token's
/// length: Google has changed it before and a tightened rule would reject a
/// client that works.
pub fn validate_google_client_id(raw: &str) -> Result<String, MokoshFieldError> {
    let id = raw.trim();
    if id.is_empty() {
        return Ok(String::new());
    }
    if id.len() > MAX_GOOGLE_CLIENT_ID_LEN {
        return Err(MokoshFieldError {
            field: "google_client_id",
            message: format!("must be at most {MAX_GOOGLE_CLIENT_ID_LEN} characters"),
        });
    }
    let shaped = id
        .strip_suffix(".apps.googleusercontent.com")
        .and_then(|head| head.split_once('-'))
        .is_some_and(|(digits, token)| {
            !digits.is_empty()
                && digits.chars().all(|c| c.is_ascii_digit())
                && !token.is_empty()
                && token
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        });
    if !shaped {
        return Err(MokoshFieldError {
            field: "google_client_id",
            message: "must be a Google OAuth client id, which looks like \
                      123456789012-abc123def456.apps.googleusercontent.com"
                .to_string(),
        });
    }
    Ok(id.to_string())
}

/// Length only, like every other secret field: a client secret has no shape
/// worth asserting and a rule invented here would reject a value Google issued.
pub fn validate_google_client_secret(raw: &str) -> Result<String, MokoshFieldError> {
    let secret = raw.trim();
    if secret.is_empty() {
        return Err(MokoshFieldError {
            field: "google_client_secret",
            message: "must not be empty".to_string(),
        });
    }
    if secret.len() > MAX_GOOGLE_CLIENT_SECRET_LEN {
        return Err(MokoshFieldError {
            field: "google_client_secret",
            message: format!("must be at most {MAX_GOOGLE_CLIENT_SECRET_LEN} characters"),
        });
    }
    Ok(secret.to_string())
}

pub const MAX_GOOGLE_CLIENT_ID_LEN: usize = 256;
/// A kilobyte, the ceiling BUNYIP-983 named. Google's secrets are far shorter;
/// this is the guard against a paste of the whole credentials JSON file.
pub const MAX_GOOGLE_CLIENT_SECRET_LEN: usize = 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_google_client_id_is_recognised_by_its_shape() {
        assert_eq!(
            validate_google_client_id("  123456789012-abc123def456.apps.googleusercontent.com  ")
                .expect("a well-shaped id"),
            "123456789012-abc123def456.apps.googleusercontent.com",
            "trimmed, because a pasted value carries whitespace"
        );
        assert_eq!(
            validate_google_client_id("").expect("blank is how an admin clears it"),
            ""
        );
    }

    /// Each of these fails in a way that would otherwise surface as a tenant's
    /// contact sync refusing to connect, in another product, days later.
    #[test]
    fn a_value_that_is_not_a_google_client_id_is_refused_by_shape() {
        for wrong in [
            "not-a-client-id",
            "123456789012-abc123def456.apps.google.com",
            "123456789012-abc123def456",
            "-abc123def456.apps.googleusercontent.com",
            "123456789012-.apps.googleusercontent.com",
            "123456789012-ABC123.apps.googleusercontent.com",
            "abc-abc123def456.apps.googleusercontent.com",
        ] {
            let error =
                validate_google_client_id(wrong).expect_err(&format!("{wrong} should not pass"));
            assert_eq!(error.field, "google_client_id");
            assert!(
                error.message.contains("apps.googleusercontent.com"),
                "the message shows the shape: {}",
                error.message
            );
        }
    }

    #[test]
    fn a_client_secret_is_checked_for_length_and_nothing_else() {
        assert_eq!(
            validate_google_client_secret(" fixture-client-secret ").expect("any non-empty value"),
            "fixture-client-secret"
        );
        assert_eq!(
            validate_google_client_secret("   ").unwrap_err().field,
            "google_client_secret"
        );
        let long = "x".repeat(MAX_GOOGLE_CLIENT_SECRET_LEN + 1);
        assert!(validate_google_client_secret(&long).is_err());
    }
}
