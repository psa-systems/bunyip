use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

use crate::errors::AppError;
use crate::services::AppKeySet;

// DEV-515: the async-stripe response DTOs moved to the shared `dunite-stripe`
// crate (consumed by a8n-tools too) and are re-exported here, so every
// `crate::models::stripe::*` / `crate::models::*` path is unchanged across
// bunyip-domain and bunyip-api. The DB `StripeConfig` model, the secret
// encryption helpers, and `StripeConfigResponse` stay here (app-specific).
pub use dunite_stripe::models::{
    StripeCheckoutPrice, StripeInvoiceResponse, StripePriceResponse, StripeProductResponse,
    StripeSubscriptionItemResponse, StripeSubscriptionResponse, StripeWebhookEndpointResponse,
};

#[derive(Debug, Clone, FromRow)]
pub struct StripeConfig {
    pub id: i32,
    pub secret_key: Option<Vec<u8>>,
    pub secret_key_nonce: Option<Vec<u8>>,
    pub webhook_secret: Option<Vec<u8>>,
    pub webhook_secret_nonce: Option<Vec<u8>>,
    pub key_version: i16,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
    /// Application tag used to filter products/prices in shared Stripe accounts.
    pub app_tag: Option<String>,
    /// BUNYIP-351: checkout redirect URLs + trial length. NULL falls back to the
    /// derived defaults (URLs from `CORS_ORIGIN`, trial from
    /// `BUNYIP_BILLING_TRIAL_PERIOD_DAYS`) in `stripe_config_from_db_model`.
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
    pub trial_period_days: Option<i32>,
}

/// Encrypt plaintext with the current key. Returns (ciphertext, nonce, key_version).
pub fn encrypt_secret(
    key_set: &AppKeySet,
    plaintext: &str,
) -> Result<(Vec<u8>, Vec<u8>, i16), AppError> {
    key_set.encrypt(plaintext.as_bytes())
}

/// Decrypt ciphertext using the key set (with fallback). Returns plaintext string.
pub fn decrypt_secret(
    key_set: &AppKeySet,
    ciphertext: &[u8],
    nonce: &[u8],
    key_version: i16,
) -> Result<String, AppError> {
    let decrypted = key_set.decrypt(ciphertext, nonce, key_version)?;
    String::from_utf8(decrypted)
        .map_err(|e| AppError::internal(format!("Invalid UTF-8 in decrypted secret: {e}")))
}

/// Returns a masked version of a secret showing the prefix (e.g. `sk_live_`)
/// and the last 4 characters, so admins can identify the key type and mode.
pub fn mask_secret(s: &str) -> String {
    if s.len() <= 4 {
        return "***".to_string();
    }
    // For Stripe-style keys like "sk_live_abc...xyz" or "whsec_abc...xyz",
    // show prefix through the last underscore plus *** plus last 4 chars.
    let prefix_end = s.rfind('_').map(|i| i + 1).unwrap_or(0);
    let suffix = &s[s.len() - 4..];
    if prefix_end > 0 && prefix_end + 4 <= s.len() {
        format!("{}***{}", &s[..prefix_end], suffix)
    } else {
        format!("***{}", suffix)
    }
}

#[derive(Debug, Serialize)]
pub struct StripeConfigResponse {
    /// BUNYIP-443: the Stripe secret key and webhook secret are returned to the
    /// browser as a `mask_secret` hint (prefix + `***` + last 4), NOT the full
    /// value. This is a deliberate posture, reviewed and kept under BUNYIP-443:
    /// PMS-342 chose the last-4 hint for operator convenience in identifying
    /// which credential is set, and BUNYIP-443 decided to retain it here rather
    /// than take the write-only posture BUNYIP-432 chose for the SMTP password.
    /// The ceiling is intentional and enforced by
    /// `masked_response_never_carries_the_full_secret`: at most the last 4
    /// characters ever leave the server, never the middle of the secret. If this
    /// is ever revisited toward write-only, drop these two fields and render a
    /// fixed-length mask from the `has_*` booleans (mirroring `has_smtp_password`).
    pub secret_key_masked: Option<String>,
    pub webhook_secret_masked: Option<String>,
    pub has_secret_key: bool,
    pub has_webhook_secret: bool,
    pub app_tag: String,
    /// BUNYIP-351: resolved (DB-over-default) checkout knobs, surfaced so the
    /// admin Stripe page can render + edit them.
    pub success_url: String,
    pub cancel_url: String,
    pub trial_period_days: u32,
    pub updated_at: Option<DateTime<Utc>>,
    /// "database" or "unconfigured" - indicates where the config came from
    /// (BUNYIP-482: env is no longer a source).
    pub source: String,
}

impl StripeConfigResponse {
    pub fn from_db(config: &StripeConfig, key_set: &AppKeySet) -> Result<Self, AppError> {
        let secret_key_plain = match (&config.secret_key, &config.secret_key_nonce) {
            (Some(ct), Some(nonce)) => {
                Some(decrypt_secret(key_set, ct, nonce, config.key_version)?)
            }
            _ => None,
        };
        let webhook_secret_plain = match (&config.webhook_secret, &config.webhook_secret_nonce) {
            (Some(ct), Some(nonce)) => {
                Some(decrypt_secret(key_set, ct, nonce, config.key_version)?)
            }
            _ => None,
        };

        let app_tag = config.app_tag.clone().unwrap_or_else(Self::default_app_tag);

        Ok(Self {
            secret_key_masked: secret_key_plain.as_deref().map(mask_secret),
            webhook_secret_masked: webhook_secret_plain.as_deref().map(mask_secret),
            has_secret_key: config.secret_key.is_some(),
            has_webhook_secret: config.webhook_secret.is_some(),
            app_tag,
            // BUNYIP-351: resolved (DB-over-default) checkout knobs.
            success_url: config
                .success_url
                .clone()
                .unwrap_or_else(crate::services::stripe::default_success_url),
            cancel_url: config
                .cancel_url
                .clone()
                .unwrap_or_else(crate::services::stripe::default_cancel_url),
            trial_period_days: config
                .trial_period_days
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or_else(crate::services::stripe::trial_period_days_from_env),
            updated_at: Some(config.updated_at),
            source: "database".to_string(),
        })
    }

    /// BUNYIP-482: the admin read model for a deployment with nothing saved in
    /// `stripe_config`. No secret is set and the checkout knobs show the derived
    /// defaults the runtime would use.
    pub fn unconfigured() -> Self {
        Self {
            secret_key_masked: None,
            webhook_secret_masked: None,
            has_secret_key: false,
            has_webhook_secret: false,
            app_tag: Self::default_app_tag(),
            success_url: crate::services::stripe::default_success_url(),
            cancel_url: crate::services::stripe::default_cancel_url(),
            trial_period_days: crate::services::stripe::trial_period_days_from_env(),
            updated_at: None,
            source: "unconfigured".to_string(),
        }
    }

    fn default_app_tag() -> String {
        crate::services::stripe::DEFAULT_APP_TAG.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key_set() -> AppKeySet {
        AppKeySet {
            current: [0xAA; 32],
            current_version: 1,
            previous: Vec::new(),
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let ks = test_key_set();
        let plaintext = "sk_live_abc123xyz";
        let (ciphertext, nonce, version) = encrypt_secret(&ks, plaintext).unwrap();
        assert_eq!(version, 1);
        let decrypted = decrypt_secret(&ks, &ciphertext, &nonce, 1).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_unique_nonces() {
        let ks = test_key_set();
        let (_, nonce1, _) = encrypt_secret(&ks, "secret").unwrap();
        let (_, nonce2, _) = encrypt_secret(&ks, "secret").unwrap();
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let ks = test_key_set();
        let (ciphertext, nonce, _) = encrypt_secret(&ks, "secret").unwrap();
        let wrong_ks = AppKeySet {
            current: [0xBB; 32],
            current_version: 1,
            previous: Vec::new(),
        };
        assert!(decrypt_secret(&wrong_ks, &ciphertext, &nonce, 1).is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let ks = test_key_set();
        let (mut ciphertext, nonce, _) = encrypt_secret(&ks, "secret").unwrap();
        ciphertext[0] ^= 0xFF;
        assert!(decrypt_secret(&ks, &ciphertext, &nonce, 1).is_err());
    }

    #[test]
    fn mask_secret_stripe_live_key() {
        assert_eq!(mask_secret("sk_live_abcdefgh1234"), "sk_live_***1234");
    }

    #[test]
    fn mask_secret_stripe_test_key() {
        assert_eq!(mask_secret("sk_test_abcdefgh5678"), "sk_test_***5678");
    }

    #[test]
    fn mask_secret_restricted_key() {
        assert_eq!(mask_secret("rk_live_abcdefgh1234"), "rk_live_***1234");
        assert_eq!(mask_secret("rk_test_abcdefgh5678"), "rk_test_***5678");
    }

    #[test]
    fn mask_secret_webhook_secret() {
        assert_eq!(mask_secret("whsec_abcdefgh1234"), "whsec_***1234");
    }

    #[test]
    fn mask_secret_short_strings() {
        assert_eq!(mask_secret(""), "***");
        assert_eq!(mask_secret("abc"), "***");
        assert_eq!(mask_secret("abcd"), "***");
    }

    #[test]
    fn mask_secret_no_prefix() {
        assert_eq!(mask_secret("abcdefghij"), "***ghij");
    }

    #[test]
    fn from_db_decrypts_and_masks() {
        let ks = test_key_set();
        let (sk_ct, sk_nonce, _) = encrypt_secret(&ks, "sk_live_test1234").unwrap();
        let (wh_ct, wh_nonce, _) = encrypt_secret(&ks, "whsec_abcdef5678").unwrap();

        let config = StripeConfig {
            id: 1,
            secret_key: Some(sk_ct),
            secret_key_nonce: Some(sk_nonce),
            webhook_secret: Some(wh_ct),
            webhook_secret_nonce: Some(wh_nonce),
            key_version: 1,
            updated_at: Utc::now(),
            updated_by: None,
            app_tag: None,
            success_url: None,
            cancel_url: None,
            trial_period_days: None,
        };

        let resp = StripeConfigResponse::from_db(&config, &ks).unwrap();
        assert_eq!(resp.secret_key_masked.as_deref(), Some("sk_live_***1234"));
        assert_eq!(resp.webhook_secret_masked.as_deref(), Some("whsec_***5678"));
        assert!(resp.has_secret_key);
        assert!(resp.has_webhook_secret);
        assert_eq!(resp.source, "database");
    }

    /// BUNYIP-443: keeping the last-4 hint is deliberate, but the ceiling is a
    /// hard invariant: the serialized response must never carry the full secret
    /// or its middle - only the prefix and last 4. This locks that ceiling so a
    /// future change to `mask_secret` or the response cannot silently widen the
    /// exposure back toward the full value.
    #[test]
    fn masked_response_never_carries_the_full_secret() {
        let ks = test_key_set();
        // Distinctive middles that must never appear in the payload.
        let full_sk = "sk_live_MIDDLEsecretMATERIAL1234";
        let full_wh = "whsec_MIDDLEsigningMATERIAL5678";
        let (sk_ct, sk_nonce, _) = encrypt_secret(&ks, full_sk).unwrap();
        let (wh_ct, wh_nonce, _) = encrypt_secret(&ks, full_wh).unwrap();

        let config = StripeConfig {
            id: 1,
            secret_key: Some(sk_ct),
            secret_key_nonce: Some(sk_nonce),
            webhook_secret: Some(wh_ct),
            webhook_secret_nonce: Some(wh_nonce),
            key_version: 1,
            updated_at: Utc::now(),
            updated_by: None,
            app_tag: None,
            success_url: None,
            cancel_url: None,
            trial_period_days: None,
        };

        let resp = StripeConfigResponse::from_db(&config, &ks).unwrap();
        let body = serde_json::to_string(&resp).unwrap();

        // The full secrets and their sensitive middles are absent from the wire.
        for leaked in [
            full_sk,
            full_wh,
            "MIDDLEsecretMATERIAL",
            "MIDDLEsigningMATERIAL",
        ] {
            assert!(
                !body.contains(leaked),
                "the full secret or its middle leaked into the response: {body}"
            );
        }
        // Only the deliberate prefix + last-4 hint is present (BUNYIP-443).
        assert!(body.contains("sk_live_***1234"));
        assert!(body.contains("whsec_***5678"));
    }

    #[test]
    fn from_db_handles_missing_secrets() {
        let ks = test_key_set();
        let config = StripeConfig {
            id: 1,
            secret_key: None,
            secret_key_nonce: None,
            webhook_secret: None,
            webhook_secret_nonce: None,
            key_version: 1,
            updated_at: Utc::now(),
            updated_by: None,
            app_tag: None,
            success_url: None,
            cancel_url: None,
            trial_period_days: None,
        };

        let resp = StripeConfigResponse::from_db(&config, &ks).unwrap();
        assert!(resp.secret_key_masked.is_none());
        assert!(resp.webhook_secret_masked.is_none());
        assert!(!resp.has_secret_key);
        assert!(!resp.has_webhook_secret);
    }

    // ---- Key rotation scenarios ----

    #[test]
    fn decrypt_with_previous_key_fallback() {
        // Encrypt with key v1
        let ks_v1 = test_key_set();
        let (ct, nonce, _) = encrypt_secret(&ks_v1, "sk_live_old").unwrap();

        // Rotate: new key is current, old key is previous
        let ks_v2 = AppKeySet {
            current: [0xBB; 32],
            current_version: 2,
            previous: vec![[0xAA; 32]],
        };
        let decrypted = decrypt_secret(&ks_v2, &ct, &nonce, 1).unwrap();
        assert_eq!(decrypted, "sk_live_old");
    }

    #[test]
    fn reencrypt_stripe_secret_roundtrip() {
        // Encrypt with v1
        let ks_v1 = test_key_set();
        let (ct_old, nonce_old, _) = encrypt_secret(&ks_v1, "whsec_original").unwrap();

        // Rotate to v2
        let ks_v2 = AppKeySet {
            current: [0xBB; 32],
            current_version: 2,
            previous: vec![[0xAA; 32]],
        };

        // Decrypt old, re-encrypt with new
        let plain = decrypt_secret(&ks_v2, &ct_old, &nonce_old, 1).unwrap();
        let (ct_new, nonce_new, ver_new) = encrypt_secret(&ks_v2, &plain).unwrap();
        assert_eq!(ver_new, 2);

        // New ciphertext decryptable with v2 key only
        let ks_v2_only = AppKeySet {
            current: [0xBB; 32],
            current_version: 2,
            previous: Vec::new(),
        };
        let final_plain = decrypt_secret(&ks_v2_only, &ct_new, &nonce_new, 2).unwrap();
        assert_eq!(final_plain, "whsec_original");
    }

    #[test]
    fn from_db_decrypts_with_rotated_key() {
        // Encrypt secrets with v1 key
        let ks_v1 = test_key_set();
        let (sk_ct, sk_nonce, _) = encrypt_secret(&ks_v1, "sk_live_rotated").unwrap();

        let config = StripeConfig {
            id: 1,
            secret_key: Some(sk_ct),
            secret_key_nonce: Some(sk_nonce),
            webhook_secret: None,
            webhook_secret_nonce: None,
            key_version: 1,
            updated_at: Utc::now(),
            updated_by: None,
            app_tag: None,
            success_url: None,
            cancel_url: None,
            trial_period_days: None,
        };

        // Decrypt with v2 key set (v1 as previous)
        let ks_v2 = AppKeySet {
            current: [0xBB; 32],
            current_version: 2,
            previous: vec![[0xAA; 32]],
        };
        let resp = StripeConfigResponse::from_db(&config, &ks_v2).unwrap();
        assert_eq!(resp.secret_key_masked.as_deref(), Some("sk_live_***ated"));
        assert!(resp.has_secret_key);
    }

    #[test]
    fn from_db_fails_without_previous_key_after_rotation() {
        // Encrypt with v1 key
        let ks_v1 = test_key_set();
        let (sk_ct, sk_nonce, _) = encrypt_secret(&ks_v1, "sk_live_lost").unwrap();

        let config = StripeConfig {
            id: 1,
            secret_key: Some(sk_ct),
            secret_key_nonce: Some(sk_nonce),
            webhook_secret: None,
            webhook_secret_nonce: None,
            key_version: 1,
            updated_at: Utc::now(),
            updated_by: None,
            app_tag: None,
            success_url: None,
            cancel_url: None,
            trial_period_days: None,
        };

        // v2 key only, no previous — cannot decrypt v1 data
        let ks_v2_no_prev = AppKeySet {
            current: [0xBB; 32],
            current_version: 2,
            previous: Vec::new(),
        };
        assert!(StripeConfigResponse::from_db(&config, &ks_v2_no_prev).is_err());
    }
}
