//! Stripe config construction + the shared Stripe service (DEV-515).
//!
//! The async-stripe `StripeService`, runtime `StripeConfig`, and response DTOs
//! now live in the shared `dunite-stripe` crate (consumed by a8n-tools too) and
//! are re-exported here, so `crate::services::stripe::*` paths are unchanged.
//!
//! The crate's methods return a neutral `StripeServiceError`; [`stripe_err`]
//! maps it to bunyip's `AppError` at the call sites (the orphan rule forbids a
//! blanket `From` impl between the two foreign types). What else stays
//! bunyip-specific: building a `StripeConfig` from env / the DB row (uses
//! bunyip's secret encryption + env conventions and the "bunyip" app-tag
//! default), and the checkout-URL env defaults shared with the admin read model.

pub use dunite_stripe::{StripeConfig, StripeService, StripeServiceError};
use dunite_stripe::{SECRET_KEY_PLACEHOLDER, WEBHOOK_SECRET_PLACEHOLDER};

use crate::errors::AppError;
use crate::models::stripe::decrypt_secret;
use crate::services::encryption::EncryptionKeySet;

/// Map the shared crate's neutral [`StripeServiceError`] to bunyip's `AppError`.
/// Used as `.map_err(stripe_err)?` at every `StripeService` call site: a blanket
/// `From<StripeServiceError> for AppError` is impossible (both are foreign types,
/// so the impl would violate the orphan rule).
pub fn stripe_err(e: StripeServiceError) -> AppError {
    match e {
        StripeServiceError::Internal(message) => AppError::internal(message),
        StripeServiceError::Validation { field, message } => AppError::validation(field, message),
        StripeServiceError::NotFound(resource) => AppError::not_found(resource),
        StripeServiceError::Unauthorized => AppError::Unauthorized,
    }
}

/// BUNYIP-209: default length of the signup free trial, in days. Overridable
/// via `BUNYIP_BILLING_TRIAL_PERIOD_DAYS` so ops can dial it without a redeploy.
const DEFAULT_TRIAL_PERIOD_DAYS: u32 = 30;

/// BUNYIP-188: pull the first non-empty origin out of a (possibly
/// comma-separated) `CORS_ORIGIN`-style value. Returns `None` when every entry
/// is empty so the caller can apply its own default. Trims surrounding
/// whitespace per entry so `"a, b"` -> `Some("a")`.
fn first_origin(raw: &str) -> Option<&str> {
    raw.split(',').map(str::trim).find(|s| !s.is_empty())
}

/// The single frontend origin used to derive the default checkout URLs: the
/// first non-empty entry of `CORS_ORIGIN` (a comma-list on multi-RP
/// deployments), trailing slash trimmed (BUNYIP-188).
fn checkout_base_from_env() -> String {
    let frontend_origin =
        std::env::var("CORS_ORIGIN").unwrap_or_else(|_| "http://localhost:5173".to_string());
    first_origin(&frontend_origin)
        .unwrap_or("http://localhost:5173")
        .trim_end_matches('/')
        .to_string()
}

/// BUNYIP-351: env default for the Stripe Checkout success URL. `STRIPE_SUCCESS_URL`
/// when set, else derived from the first `CORS_ORIGIN`. Shared by the runtime
/// config and the admin read model so the DB NULL fallback can never diverge.
pub fn success_url_from_env() -> String {
    std::env::var("STRIPE_SUCCESS_URL")
        .unwrap_or_else(|_| format!("{}/checkout/success", checkout_base_from_env()))
}

/// BUNYIP-351: env default for the Stripe Checkout cancel URL.
pub fn cancel_url_from_env() -> String {
    std::env::var("STRIPE_CANCEL_URL")
        .unwrap_or_else(|_| format!("{}/pricing?checkout=canceled", checkout_base_from_env()))
}

/// BUNYIP-351: env default for the signup free-trial length (days). A blank or
/// unparseable `BUNYIP_BILLING_TRIAL_PERIOD_DAYS` falls back to the 30-day
/// default rather than disabling the trial.
pub fn trial_period_days_from_env() -> u32 {
    std::env::var("BUNYIP_BILLING_TRIAL_PERIOD_DAYS")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_TRIAL_PERIOD_DAYS)
}

/// Build a runtime [`StripeConfig`] from env (was `StripeConfig::from_env`).
/// Kept bunyip-side because it uses bunyip's `{NAME}_FILE` secret convention,
/// the `bunyip` app-tag default, and the checkout-URL env helpers above.
pub fn stripe_config_from_env() -> Result<StripeConfig, AppError> {
    // BUNYIP-188: the checkout success/cancel URLs derive from a SINGLE origin
    // (the first non-empty `CORS_ORIGIN` entry), not the whole comma-list;
    // explicit `STRIPE_SUCCESS_URL` / `STRIPE_CANCEL_URL` still win.
    Ok(StripeConfig {
        // secret_env supports the {NAME}_FILE compose-secret convention,
        // falling back to the plain env var.
        secret_key: crate::config::secret_env("STRIPE_SECRET_KEY")
            .unwrap_or_else(|| SECRET_KEY_PLACEHOLDER.to_string()),
        webhook_secret: crate::config::secret_env("STRIPE_WEBHOOK_SECRET")
            .unwrap_or_else(|| WEBHOOK_SECRET_PLACEHOLDER.to_string()),
        success_url: success_url_from_env(),
        cancel_url: cancel_url_from_env(),
        // Single source shared with `TierConfig` so the two cannot diverge.
        free_price_id: crate::config::free_price_id_from_env(),
        app_tag: std::env::var("STRIPE_APP_TAG")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "bunyip".to_string()),
        trial_period_days: trial_period_days_from_env(),
    })
}

/// Build a runtime [`StripeConfig`] from the DB model, decrypting secrets and
/// falling back to env for any field not set in the DB (was
/// `StripeConfig::from_db_model`). Bunyip-side because it decrypts with bunyip's
/// [`EncryptionKeySet`].
pub fn stripe_config_from_db_model(
    db: &crate::models::stripe::StripeConfig,
    key_set: &EncryptionKeySet,
) -> Result<StripeConfig, AppError> {
    let env_config = stripe_config_from_env()?;

    let secret_key = match (&db.secret_key, &db.secret_key_nonce) {
        (Some(ct), Some(nonce)) => decrypt_secret(key_set, ct, nonce, db.key_version)?,
        _ => env_config.secret_key,
    };
    let webhook_secret = match (&db.webhook_secret, &db.webhook_secret_nonce) {
        (Some(ct), Some(nonce)) => decrypt_secret(key_set, ct, nonce, db.key_version)?,
        _ => env_config.webhook_secret,
    };

    let app_tag = db.app_tag.clone().unwrap_or(env_config.app_tag);

    // BUNYIP-351: checkout knobs live in the DB row too; NULL falls back to the
    // env value already resolved in `env_config`.
    let success_url = db.success_url.clone().unwrap_or(env_config.success_url);
    let cancel_url = db.cancel_url.clone().unwrap_or(env_config.cancel_url);
    let trial_period_days = db
        .trial_period_days
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(env_config.trial_period_days);

    Ok(StripeConfig {
        secret_key,
        webhook_secret,
        success_url,
        cancel_url,
        free_price_id: env_config.free_price_id,
        app_tag,
        trial_period_days,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> StripeConfig {
        StripeConfig {
            secret_key: "sk_test_xxx".to_string(),
            webhook_secret: "whsec_test_secret".to_string(),
            success_url: "http://localhost/checkout/success".to_string(),
            cancel_url: "http://localhost/cancel".to_string(),
            free_price_id: None,
            app_tag: "bunyip".to_string(),
            trial_period_days: 30,
        }
    }

    // -- BUNYIP-351: checkout knobs resolve DB-over-env --

    #[test]
    fn from_db_model_prefers_db_checkout_knobs_then_env() {
        let _env = crate::test_support::env_lock();
        std::env::set_var("STRIPE_SUCCESS_URL", "https://env.example/ok");
        std::env::set_var("STRIPE_CANCEL_URL", "https://env.example/no");
        std::env::set_var("BUNYIP_BILLING_TRIAL_PERIOD_DAYS", "14");

        let ks = EncryptionKeySet {
            current: [0u8; 32],
            current_version: 1,
            previous: None,
        };

        // success_url + trial overridden in DB; cancel_url NULL -> env fallback.
        let db = crate::models::stripe::StripeConfig {
            id: 1,
            secret_key: None,
            secret_key_nonce: None,
            webhook_secret: None,
            webhook_secret_nonce: None,
            key_version: 1,
            updated_at: chrono::Utc::now(),
            updated_by: None,
            app_tag: None,
            success_url: Some("https://db.example/ok".to_string()),
            cancel_url: None,
            trial_period_days: Some(7),
        };

        let cfg = stripe_config_from_db_model(&db, &ks).unwrap();
        assert_eq!(cfg.success_url, "https://db.example/ok");
        assert_eq!(cfg.cancel_url, "https://env.example/no");
        assert_eq!(cfg.trial_period_days, 7);

        std::env::remove_var("STRIPE_SUCCESS_URL");
        std::env::remove_var("STRIPE_CANCEL_URL");
        std::env::remove_var("BUNYIP_BILLING_TRIAL_PERIOD_DAYS");
    }

    // -- BUNYIP-188: first_origin helper --

    #[test]
    fn first_origin_single_value_passthrough() {
        assert_eq!(
            first_origin("https://example.com"),
            Some("https://example.com")
        );
    }

    #[test]
    fn first_origin_picks_first_of_comma_list() {
        assert_eq!(
            first_origin("https://a.example.com,https://b.example.com"),
            Some("https://a.example.com")
        );
    }

    #[test]
    fn first_origin_trims_whitespace() {
        assert_eq!(
            first_origin("  https://a.example.com  ,  https://b.example.com"),
            Some("https://a.example.com")
        );
    }

    #[test]
    fn first_origin_skips_empty_entries() {
        assert_eq!(
            first_origin(",https://a.example.com"),
            Some("https://a.example.com")
        );
    }

    #[test]
    fn first_origin_all_empty_returns_none() {
        assert_eq!(first_origin(""), None);
        assert_eq!(first_origin(",,"), None);
    }

    // -- BUNYIP-209: signup free trial --

    #[test]
    fn default_trial_period_days_is_30() {
        assert_eq!(DEFAULT_TRIAL_PERIOD_DAYS, 30);
        assert_eq!(test_config().trial_period_days, 30);
    }

    // -- error mapping --

    #[test]
    fn stripe_err_maps_variants() {
        assert!(matches!(
            stripe_err(StripeServiceError::internal("x")),
            AppError::InternalError { .. }
        ));
        assert!(matches!(
            stripe_err(StripeServiceError::validation("secret_key", "missing")),
            AppError::ValidationError { .. }
        ));
        assert!(matches!(
            stripe_err(StripeServiceError::not_found("Product")),
            AppError::NotFound { .. }
        ));
        assert!(matches!(
            stripe_err(StripeServiceError::Unauthorized),
            AppError::Unauthorized
        ));
    }
}
