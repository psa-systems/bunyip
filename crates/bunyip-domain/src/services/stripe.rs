//! Stripe config construction + the shared Stripe service (DEV-515).
//!
//! The async-stripe `StripeService`, runtime `StripeConfig`, and response DTOs
//! now live in the shared `dunite-stripe` crate (consumed by a8n-tools too) and
//! are re-exported here, so `crate::services::stripe::*` paths are unchanged.
//!
//! The crate's methods return a neutral `StripeServiceError`; [`stripe_err`]
//! maps it to bunyip's `AppError` at the call sites (the orphan rule forbids a
//! blanket `From` impl between the two foreign types). What else stays
//! bunyip-specific: building a `StripeConfig` from the DB row (uses bunyip's
//! secret encryption and the "bunyip" app-tag default), and the checkout-URL
//! defaults shared with the admin read model.
//!
//! BUNYIP-482: the `stripe_config` DB row is the ONLY source of Stripe
//! configuration. No Stripe-prefixed environment variable is read here; the
//! at-rest key material for that row is the application key set
//! (`APP_ENCRYPTION_KEY`, BUNYIP-483) and lives in `config.rs`.

pub use dunite_stripe::{StripeConfig, StripeService, StripeServiceError};
use dunite_stripe::{SECRET_KEY_PLACEHOLDER, WEBHOOK_SECRET_PLACEHOLDER};

use crate::errors::AppError;
use crate::models::stripe::decrypt_secret;
use crate::services::AppKeySet;

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
        // DUNITE-10: the classified Stripe-call failure. When Stripe said the
        // object does not exist, surface bunyip's own 404 (e.g. unarchiving a
        // price id Stripe no longer knows) rather than a blanket 500; any other
        // classification keeps the neutral 500 the plain message carried before.
        StripeServiceError::Stripe { message, details } => {
            if details.is_resource_missing() {
                AppError::not_found("Stripe resource")
            } else {
                AppError::internal(message)
            }
        }
    }
}

/// BUNYIP-209: default length of the signup free trial, in days. Overridable
/// via `BUNYIP_BILLING_TRIAL_PERIOD_DAYS` so ops can dial it without a redeploy.
const DEFAULT_TRIAL_PERIOD_DAYS: u32 = 30;

/// BUNYIP-482: app tag used to filter products/prices in a shared Stripe
/// account when the `stripe_config.app_tag` column is NULL. Admins override it
/// from the admin Stripe page.
pub const DEFAULT_APP_TAG: &str = "bunyip";

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

/// BUNYIP-351/482: default Stripe Checkout success URL, derived from the first
/// `CORS_ORIGIN` entry. Shared by the runtime config and the admin read model so
/// the DB NULL fallback can never diverge. Admins override it from the admin
/// Stripe page.
pub fn default_success_url() -> String {
    format!("{}/checkout/success", checkout_base_from_env())
}

/// BUNYIP-351/482: default Stripe Checkout cancel URL (see [`default_success_url`]).
pub fn default_cancel_url() -> String {
    format!("{}/pricing?checkout=canceled", checkout_base_from_env())
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

/// BUNYIP-482: the runtime [`StripeConfig`] for a deployment with no saved
/// Stripe config. The placeholder secrets keep `StripeService::is_configured()`
/// reporting false, so the api boots with payment disabled until an admin saves
/// real keys on the admin Stripe page.
pub fn unconfigured_stripe_config() -> StripeConfig {
    StripeConfig {
        secret_key: SECRET_KEY_PLACEHOLDER.to_string(),
        webhook_secret: WEBHOOK_SECRET_PLACEHOLDER.to_string(),
        success_url: default_success_url(),
        cancel_url: default_cancel_url(),
        // BUNYIP-482: the $0 price id lives in `tier_config` and is read from
        // the live `TierConfig` at the call site, never baked in here.
        free_price_id: None,
        app_tag: DEFAULT_APP_TAG.to_string(),
        trial_period_days: trial_period_days_from_env(),
    }
}

/// Build a runtime [`StripeConfig`] from the DB model, decrypting secrets and
/// falling back to the derived defaults for any field that is NULL (was
/// `StripeConfig::from_db_model`). Bunyip-side because it decrypts with bunyip's
/// [`AppKeySet`].
pub fn stripe_config_from_db_model(
    db: &crate::models::stripe::StripeConfig,
    key_set: &AppKeySet,
) -> Result<StripeConfig, AppError> {
    let defaults = unconfigured_stripe_config();

    let secret_key = match (&db.secret_key, &db.secret_key_nonce) {
        (Some(ct), Some(nonce)) => decrypt_secret(key_set, ct, nonce, db.key_version)?,
        _ => defaults.secret_key,
    };
    let webhook_secret = match (&db.webhook_secret, &db.webhook_secret_nonce) {
        (Some(ct), Some(nonce)) => decrypt_secret(key_set, ct, nonce, db.key_version)?,
        _ => defaults.webhook_secret,
    };

    let app_tag = db.app_tag.clone().unwrap_or(defaults.app_tag);

    // BUNYIP-351: checkout knobs live in the DB row too; NULL falls back to the
    // derived default.
    let success_url = db.success_url.clone().unwrap_or(defaults.success_url);
    let cancel_url = db.cancel_url.clone().unwrap_or(defaults.cancel_url);
    let trial_period_days = db
        .trial_period_days
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(defaults.trial_period_days);

    Ok(StripeConfig {
        secret_key,
        webhook_secret,
        success_url,
        cancel_url,
        free_price_id: None,
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

    // -- BUNYIP-351/482: checkout knobs resolve DB-over-derived-default --

    fn empty_db_row() -> crate::models::stripe::StripeConfig {
        crate::models::stripe::StripeConfig {
            id: 1,
            secret_key: None,
            secret_key_nonce: None,
            webhook_secret: None,
            webhook_secret_nonce: None,
            key_version: 1,
            updated_at: chrono::Utc::now(),
            updated_by: None,
            app_tag: None,
            success_url: None,
            cancel_url: None,
            trial_period_days: None,
        }
    }

    fn test_key_set() -> AppKeySet {
        AppKeySet {
            current: [0u8; 32],
            current_version: 1,
            previous: Vec::new(),
        }
    }

    #[test]
    fn from_db_model_prefers_db_checkout_knobs_then_derived_defaults() {
        let _env = crate::test_support::env_lock();
        std::env::set_var("CORS_ORIGIN", "https://cors.example");

        // success_url + trial overridden in DB; cancel_url NULL -> derived default.
        let db = crate::models::stripe::StripeConfig {
            success_url: Some("https://db.example/ok".to_string()),
            trial_period_days: Some(7),
            ..empty_db_row()
        };

        let cfg = stripe_config_from_db_model(&db, &test_key_set()).unwrap();
        assert_eq!(cfg.success_url, "https://db.example/ok");
        assert_eq!(
            cfg.cancel_url,
            "https://cors.example/pricing?checkout=canceled"
        );
        assert_eq!(cfg.trial_period_days, 7);

        std::env::remove_var("CORS_ORIGIN");
    }

    /// BUNYIP-482: an empty DB row resolves to placeholder secrets (so
    /// `is_configured()` stays false) and derived checkout URLs, identically to
    /// the unconfigured constructor. `scripts/check-no-stripe-env.nu` is the
    /// gate that keeps env out of this path; this asserts the resulting state.
    #[test]
    fn empty_db_row_resolves_to_the_unconfigured_state() {
        let _env = crate::test_support::env_lock();
        std::env::set_var("CORS_ORIGIN", "https://cors.example");

        for cfg in [
            unconfigured_stripe_config(),
            stripe_config_from_db_model(&empty_db_row(), &test_key_set()).unwrap(),
        ] {
            assert_eq!(cfg.secret_key, SECRET_KEY_PLACEHOLDER);
            assert_eq!(cfg.webhook_secret, WEBHOOK_SECRET_PLACEHOLDER);
            assert_eq!(cfg.success_url, "https://cors.example/checkout/success");
            assert_eq!(
                cfg.cancel_url,
                "https://cors.example/pricing?checkout=canceled"
            );
            assert_eq!(cfg.app_tag, DEFAULT_APP_TAG);
            assert_eq!(cfg.free_price_id, None);
        }

        std::env::remove_var("CORS_ORIGIN");
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

    /// DUNITE-10: the classified Stripe-call failure maps to a 404 when Stripe
    /// said the object is missing, and to a 500 otherwise.
    #[test]
    fn stripe_err_maps_the_classified_stripe_variant() {
        use dunite_stripe::StripeErrorDetails;

        let missing = StripeErrorDetails {
            code: Some("resource_missing".into()),
            ..Default::default()
        };
        assert!(matches!(
            stripe_err(StripeServiceError::stripe("gone", missing)),
            AppError::NotFound { .. }
        ));

        let other = StripeErrorDetails {
            http_status: Some(402),
            ..Default::default()
        };
        assert!(matches!(
            stripe_err(StripeServiceError::stripe("declined", other)),
            AppError::InternalError { .. }
        ));
    }
}
