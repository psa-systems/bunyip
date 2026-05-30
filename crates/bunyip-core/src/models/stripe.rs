use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use uuid::Uuid;

use crate::errors::AppError;
use crate::services::encryption::EncryptionKeySet;

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
}

// --- Stripe API response structs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeProductResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub active: bool,
    pub metadata: HashMap<String, String>,
    pub created: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripePriceResponse {
    pub id: String,
    pub product_id: String,
    pub unit_amount: Option<i64>,
    pub currency: String,
    pub recurring_interval: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSubscriptionItemResponse {
    pub price_id: String,
    pub product_id: String,
    pub quantity: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSubscriptionResponse {
    pub id: String,
    pub status: String,
    pub current_period_start: i64,
    pub current_period_end: i64,
    pub cancel_at_period_end: bool,
    pub items: Vec<StripeSubscriptionItemResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeInvoiceResponse {
    pub id: String,
    pub customer_id: Option<String>,
    pub amount_paid: i64,
    pub currency: String,
    pub status: Option<String>,
    pub invoice_pdf: Option<String>,
    pub hosted_invoice_url: Option<String>,
    pub created: i64,
    pub description: Option<String>,
    pub number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeWebhookEndpointResponse {
    pub id: String,
    pub url: String,
    pub enabled_events: Vec<String>,
    pub status: String,
    /// Only present on creation
    pub secret: Option<String>,
}

/// Encrypt plaintext with the current key. Returns (ciphertext, nonce, key_version).
pub fn encrypt_secret(
    key_set: &EncryptionKeySet,
    plaintext: &str,
) -> Result<(Vec<u8>, Vec<u8>, i16), AppError> {
    key_set.encrypt(plaintext.as_bytes())
}

/// Decrypt ciphertext using the key set (with fallback). Returns plaintext string.
pub fn decrypt_secret(
    key_set: &EncryptionKeySet,
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
    if prefix_end > 0 && prefix_end + 4 < s.len() {
        format!("{}***{}", &s[..prefix_end], suffix)
    } else {
        format!("***{}", suffix)
    }
}

#[derive(Debug, Serialize)]
pub struct StripeConfigResponse {
    pub secret_key_masked: Option<String>,
    pub webhook_secret_masked: Option<String>,
    pub has_secret_key: bool,
    pub has_webhook_secret: bool,
    pub app_tag: String,
    pub updated_at: Option<DateTime<Utc>>,
    /// "database" or "environment" — indicates where the config came from
    pub source: String,
}

impl StripeConfigResponse {
    pub fn from_db(config: &StripeConfig, key_set: &EncryptionKeySet) -> Result<Self, AppError> {
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
            updated_at: Some(config.updated_at),
            source: "database".to_string(),
        })
    }

    /// Reads env vars and returns a response showing what's currently configured there.
    /// Used as a fallback when no DB config has been saved yet.
    pub fn from_env() -> Self {
        use std::env;
        let secret_key = env::var("STRIPE_SECRET_KEY").ok().filter(|s| !s.is_empty());
        let webhook_secret = env::var("STRIPE_WEBHOOK_SECRET")
            .ok()
            .filter(|s| !s.is_empty());

        Self {
            secret_key_masked: secret_key.as_deref().map(mask_secret),
            webhook_secret_masked: webhook_secret.as_deref().map(mask_secret),
            has_secret_key: secret_key.is_some(),
            has_webhook_secret: webhook_secret.is_some(),
            app_tag: Self::default_app_tag(),
            updated_at: None,
            source: "environment".to_string(),
        }
    }

    fn default_app_tag() -> String {
        std::env::var("STRIPE_APP_TAG")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "a8n-tools".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key_set() -> EncryptionKeySet {
        EncryptionKeySet {
            current: [0xAA; 32],
            current_version: 1,
            previous: None,
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
        let wrong_ks = EncryptionKeySet {
            current: [0xBB; 32],
            current_version: 1,
            previous: None,
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
        };

        let resp = StripeConfigResponse::from_db(&config, &ks).unwrap();
        assert_eq!(resp.secret_key_masked.as_deref(), Some("sk_live_***1234"));
        assert_eq!(resp.webhook_secret_masked.as_deref(), Some("whsec_***5678"));
        assert!(resp.has_secret_key);
        assert!(resp.has_webhook_secret);
        assert_eq!(resp.source, "database");
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
        let ks_v2 = EncryptionKeySet {
            current: [0xBB; 32],
            current_version: 2,
            previous: Some([0xAA; 32]),
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
        let ks_v2 = EncryptionKeySet {
            current: [0xBB; 32],
            current_version: 2,
            previous: Some([0xAA; 32]),
        };

        // Decrypt old, re-encrypt with new
        let plain = decrypt_secret(&ks_v2, &ct_old, &nonce_old, 1).unwrap();
        let (ct_new, nonce_new, ver_new) = encrypt_secret(&ks_v2, &plain).unwrap();
        assert_eq!(ver_new, 2);

        // New ciphertext decryptable with v2 key only
        let ks_v2_only = EncryptionKeySet {
            current: [0xBB; 32],
            current_version: 2,
            previous: None,
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
        };

        // Decrypt with v2 key set (v1 as previous)
        let ks_v2 = EncryptionKeySet {
            current: [0xBB; 32],
            current_version: 2,
            previous: Some([0xAA; 32]),
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
        };

        // v2 key only, no previous — cannot decrypt v1 data
        let ks_v2_no_prev = EncryptionKeySet {
            current: [0xBB; 32],
            current_version: 2,
            previous: None,
        };
        assert!(StripeConfigResponse::from_db(&config, &ks_v2_no_prev).is_err());
    }
}
