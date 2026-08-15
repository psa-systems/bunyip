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

pub use dunite_stripe::{StripeConfig, StripeErrorDetails, StripeService, StripeServiceError};
use dunite_stripe::{SECRET_KEY_PLACEHOLDER, WEBHOOK_SECRET_PLACEHOLDER};

use crate::errors::AppError;
use crate::models::stripe::decrypt_secret;
use crate::services::AppKeySet;

/// BUNYIP-516: a Stripe restricted-key permission, spelled the way Stripe's own
/// key editor spells it. The variants are the complete set bunyip's Stripe calls
/// need, and their labels are the only permission names that reach a user: a
/// permission failure is explained with bunyip-authored copy built from these,
/// never with Stripe's own `error.message` (BUNYIP-265).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripePermission {
    Products,
    Prices,
    Subscriptions,
    Customers,
    CheckoutSessions,
    Invoices,
    WebhookEndpoints,
}

impl StripePermission {
    /// The label Stripe's restricted-key editor shows for this permission, so
    /// the message names the checkbox the admin has to find.
    pub fn label(self) -> &'static str {
        match self {
            Self::Products => "Products",
            Self::Prices => "Prices",
            Self::Subscriptions => "Subscriptions",
            Self::Customers => "Customers",
            Self::CheckoutSessions => "Checkout Sessions",
            Self::Invoices => "Invoices",
            Self::WebhookEndpoints => "Webhook Endpoints",
        }
    }

    /// BUNYIP-532: the stable machine name used on the wire (JSON key / test id),
    /// so the web panel keys off an identifier rather than the display label.
    pub fn key(self) -> &'static str {
        match self {
            Self::Products => "products",
            Self::Prices => "prices",
            Self::Subscriptions => "subscriptions",
            Self::Customers => "customers",
            Self::CheckoutSessions => "checkout_sessions",
            Self::Invoices => "invoices",
            Self::WebhookEndpoints => "webhook_endpoints",
        }
    }
}

/// BUNYIP-532: the outcome of probing one restricted-key permission by making a
/// harmless read against that resource. `Untested` is not a probe result: it
/// marks a permission bunyip needs but cannot classify from a bunyip-only call
/// today (the checkout-time resources, whose dunite-stripe methods collapse
/// Stripe's error), so the panel lists it as required without claiming a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    /// The read succeeded: the key can at least read this resource.
    Granted,
    /// Stripe returned 403 / `more_permissions_required`: the key lacks it.
    Missing,
    /// Stripe rejected the key itself (401 / expired / invalid).
    KeyRejected,
    /// Some other failure; the probe could not decide.
    Unknown,
    /// bunyip needs this permission but does not live-test it here.
    Untested,
}

/// BUNYIP-532: classify a probe read into a [`ProbeStatus`]. Reuses the same
/// key-rejected / permission-denied predicates BUNYIP-516 uses to build the
/// reactive error copy, so the proactive test and the reactive message agree on
/// what a given Stripe failure means. Only the classified `Stripe { details }`
/// variant can be a permission verdict; every other error is inconclusive.
pub fn classify_probe<T>(res: &Result<T, StripeServiceError>) -> ProbeStatus {
    match res {
        Ok(_) => ProbeStatus::Granted,
        Err(StripeServiceError::Unauthorized) => ProbeStatus::KeyRejected,
        Err(StripeServiceError::Stripe { details, .. }) => {
            if is_key_rejected(details) {
                ProbeStatus::KeyRejected
            } else if is_permission_denied(details) {
                ProbeStatus::Missing
            } else {
                ProbeStatus::Unknown
            }
        }
        Err(_) => ProbeStatus::Unknown,
    }
}

/// The tail every restricted-key message ends with: where to fix it and what to
/// do afterwards, phrased against the admin Stripe page's own field names.
const KEY_FIX_STEPS: &str =
    "in the Stripe dashboard, paste the key into Secret key above, and save.";

/// BUNYIP-516: Stripe rejected the key itself (401, or one of the key-specific
/// codes) rather than the operation.
const KEY_REJECTED_MESSAGE: &str = "Stripe rejected your secret key: it is invalid, expired or revoked. Create a new restricted key in the Stripe dashboard, paste it into Secret key above, and save.";

/// Stripe refused the call for lack of permission on a restricted key. `403` is
/// the status a restricted key gets, and `more_permissions_required` is the code
/// Stripe pairs with it.
fn is_permission_denied(details: &StripeErrorDetails) -> bool {
    details.code.as_deref() == Some("more_permissions_required") || details.http_status == Some(403)
}

/// Stripe refused the key itself: a 401, or an explicit expired / invalid code.
fn is_key_rejected(details: &StripeErrorDetails) -> bool {
    details.http_status == Some(401)
        || matches!(
            details.code.as_deref(),
            Some("api_key_expired") | Some("invalid_api_key")
        )
}

/// The user-facing copy for a permission failure. Naming the permission needs
/// the call site's context, so an unattributed failure falls back to the generic
/// phrasing rather than guessing a permission.
fn permission_message(permission: Option<StripePermission>) -> String {
    match permission {
        Some(p) => format!(
            "Your Stripe restricted key does not have the {label} permission. Add Write access for {label} to the key {KEY_FIX_STEPS}",
            label = p.label()
        ),
        None => format!(
            "Your Stripe restricted key does not have permission for this action. Add the missing Write access to the key {KEY_FIX_STEPS}"
        ),
    }
}

/// Map the shared crate's neutral [`StripeServiceError`] to bunyip's `AppError`.
/// Used as `.map_err(stripe_err)?` at every `StripeService` call site: a blanket
/// `From<StripeServiceError> for AppError` is impossible (both are foreign types,
/// so the impl would violate the orphan rule).
pub fn stripe_err(e: StripeServiceError) -> AppError {
    map_stripe_err(e, None)
}

/// BUNYIP-516: [`stripe_err`] for a call site that knows which restricted-key
/// permission it needs, so a 403 is answered with the permission's name instead
/// of a generic "an unexpected error occurred". Used as
/// `.map_err(stripe_err_for(StripePermission::WebhookEndpoints))?`.
pub fn stripe_err_for(permission: StripePermission) -> impl Fn(StripeServiceError) -> AppError {
    move |e| map_stripe_err(e, Some(permission))
}

fn map_stripe_err(e: StripeServiceError, permission: Option<StripePermission>) -> AppError {
    match e {
        StripeServiceError::Internal(message) => AppError::internal(message),
        StripeServiceError::Validation { field, message } => AppError::validation(field, message),
        StripeServiceError::NotFound(resource) => AppError::not_found(resource),
        StripeServiceError::Unauthorized => AppError::Unauthorized,
        // DUNITE-10 carries Stripe's own classification out of the service.
        StripeServiceError::Stripe { message, details } => {
            // BUNYIP-513: a missing object is bunyip's own 404 (e.g. unarchiving
            // a price id Stripe no longer knows), not a 500. Otherwise fall to
            // BUNYIP-516's permission/key mapping, which keeps the 500 for codes
            // bunyip cannot explain.
            if details.is_resource_missing() {
                AppError::not_found("Stripe resource")
            } else {
                stripe_upstream_err(&message, &details, permission)
            }
        }
    }
}

/// BUNYIP-516: turn Stripe's error code into an answer the admin can act on.
///
/// The two causes bunyip can actually explain answer `400`, which is what makes
/// the copy survive: `ApiError::user_message` in bunyip-web collapses every 5xx
/// to a generic line by design (BUNYIP-477), so a message attached to a 500
/// could never reach the page. Every other code keeps the 500, so the only
/// user-facing strings remain the enumerated, bunyip-authored ones above; Stripe's
/// `error.message` is not carried by [`StripeErrorDetails`] at all (BUNYIP-265).
fn stripe_upstream_err(
    message: &str,
    details: &StripeErrorDetails,
    permission: Option<StripePermission>,
) -> AppError {
    if is_permission_denied(details) {
        tracing::warn!(
            stripe_details = %details,
            permission = permission.map(StripePermission::label).unwrap_or("unattributed"),
            "Stripe refused the call: the restricted key is missing a permission"
        );
        return AppError::validation("secret_key", permission_message(permission));
    }
    if is_key_rejected(details) {
        tracing::warn!(stripe_details = %details, "Stripe rejected the secret key");
        return AppError::validation("secret_key", KEY_REJECTED_MESSAGE);
    }
    // Unmapped: stays a 500. The details are machine-readable and PII-free, so
    // they ride along in the internal message for the operator log; the browser
    // sees the generic line either way.
    AppError::internal(format!("{message} ({details})"))
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

/// Build a runtime [`StripeConfig`] from the DB row's NON-SECRET columns only
/// (app tag, checkout URLs, trial length), leaving the two secrets on their
/// unconfigured placeholders (BUNYIP-542).
///
/// Those columns are configuration, not secrets: they stay editable and
/// readable in every `SECRETS_STORAGE` mode. The caller overlays the secret key
/// and webhook secret from whichever store the deployment declared.
pub fn stripe_settings_from_db_model(db: &crate::models::stripe::StripeConfig) -> StripeConfig {
    let defaults = unconfigured_stripe_config();
    StripeConfig {
        secret_key: defaults.secret_key,
        webhook_secret: defaults.webhook_secret,
        success_url: db.success_url.clone().unwrap_or(defaults.success_url),
        cancel_url: db.cancel_url.clone().unwrap_or(defaults.cancel_url),
        free_price_id: None,
        app_tag: db.app_tag.clone().unwrap_or(defaults.app_tag),
        trial_period_days: db
            .trial_period_days
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(defaults.trial_period_days),
    }
}

/// Build a runtime [`StripeConfig`] from the DB model, decrypting secrets and
/// falling back to the derived defaults for any field that is NULL (was
/// `StripeConfig::from_db_model`). Bunyip-side because it decrypts with bunyip's
/// [`AppKeySet`].
///
/// This is the `SECRETS_STORAGE=database` form of the secret resolution; the
/// other two modes overlay their own values onto
/// [`stripe_settings_from_db_model`].
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

    /// BUNYIP-513: the classified Stripe-call failure maps to a 404 when Stripe
    /// said the object is missing, and (for a code bunyip cannot explain) to 500.
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

    // -- BUNYIP-516: Stripe's error code becomes an answer, at a 4xx --

    use actix_web::ResponseError;

    fn stripe_failure(status: u16, code: Option<&str>) -> StripeServiceError {
        StripeServiceError::stripe(
            "Failed to create webhook endpoint",
            StripeErrorDetails {
                http_status: Some(status),
                error_type: Some("invalid_request_error".to_string()),
                code: code.map(str::to_string),
                decline_code: None,
                request_id: Some("req_stripe_1".to_string()),
            },
        )
    }

    /// The incident: a restricted key without the Webhook Endpoints permission.
    /// The admin has to be told which permission and what to do about it.
    #[test]
    fn more_permissions_required_names_the_permission_and_the_fix() {
        let err = stripe_err_for(StripePermission::WebhookEndpoints)(stripe_failure(
            403,
            Some("more_permissions_required"),
        ));
        let AppError::ValidationError { field, message } = &err else {
            panic!("expected a validation error, got {err:?}");
        };
        assert_eq!(field, "secret_key");
        assert!(
            message.contains("Webhook Endpoints permission"),
            "names the missing permission: {message}"
        );
        assert!(
            message.contains("Add Write access for Webhook Endpoints"),
            "names the change to make: {message}"
        );
        assert!(
            message.contains("paste the key into Secret key above, and save"),
            "names where to apply it: {message}"
        );
    }

    /// The mapping is worthless unless it answers a 4xx: bunyip-web collapses
    /// every 5xx to a generic line (BUNYIP-477), so a 500 could not carry this
    /// text to the page no matter how good the text was.
    #[test]
    fn the_permission_mapping_answers_4xx_so_the_message_survives() {
        let err = stripe_err_for(StripePermission::WebhookEndpoints)(stripe_failure(
            403,
            Some("more_permissions_required"),
        ));
        let status = err.status_code().as_u16();
        assert!(
            (400..500).contains(&status),
            "must be a 4xx to survive user_message(), got {status}"
        );
        assert_eq!(status, 400);
    }

    /// A bare 403 with no code is the same failure; a rejected key is its own
    /// message; every other code keeps the 500 so no new backend text leaks.
    #[test]
    fn only_the_two_explainable_causes_become_4xx() {
        // 403 without a code still reads as a permission problem.
        assert!(matches!(
            stripe_err(stripe_failure(403, None)),
            AppError::ValidationError { .. }
        ));
        // A rejected / expired key gets key-specific copy.
        for e in [
            stripe_failure(401, None),
            stripe_failure(400, Some("api_key_expired")),
        ] {
            let mapped = stripe_err(e);
            let AppError::ValidationError { message, .. } = &mapped else {
                panic!("expected a validation error, got {mapped:?}");
            };
            assert!(
                message.contains("Stripe rejected your secret key"),
                "key-specific copy: {message}"
            );
        }
        // Anything else stays a 500 and keeps the generic client message.
        for e in [
            stripe_failure(429, Some("rate_limit")),
            stripe_failure(500, None),
            stripe_failure(402, Some("card_declined")),
        ] {
            let mapped = stripe_err(e);
            assert!(
                matches!(mapped, AppError::InternalError { .. }),
                "unmapped codes keep the 500: {mapped:?}"
            );
            assert_eq!(mapped.status_code().as_u16(), 500);
        }
    }

    /// An unattributed call site still explains the class of failure rather than
    /// inventing a permission it cannot know.
    #[test]
    fn an_unattributed_permission_failure_does_not_guess_a_permission() {
        let mapped = stripe_err(stripe_failure(403, Some("more_permissions_required")));
        let AppError::ValidationError { message, .. } = &mapped else {
            panic!("expected a validation error, got {mapped:?}");
        };
        assert!(message.contains("does not have permission for this action"));
        for p in [
            StripePermission::Products,
            StripePermission::WebhookEndpoints,
            StripePermission::Invoices,
        ] {
            assert!(
                !message.contains(p.label()),
                "no permission is named when the call site did not say: {message}"
            );
        }
    }

    /// BUNYIP-265: only bunyip-authored strings are user-facing. Stripe's own
    /// `error.message` is not even carried by `StripeErrorDetails`, and the
    /// mapping must not start echoing the machine-readable fields at the user.
    #[test]
    fn no_stripe_supplied_text_reaches_the_user_facing_message() {
        for permission in [None, Some(StripePermission::WebhookEndpoints)] {
            let e = stripe_failure(403, Some("more_permissions_required"));
            let mapped = match permission {
                Some(p) => stripe_err_for(p)(e),
                None => stripe_err(e),
            };
            let AppError::ValidationError { message, .. } = &mapped else {
                panic!("expected a validation error, got {mapped:?}");
            };
            for leaked in [
                "more_permissions_required",
                "invalid_request_error",
                "req_stripe_1",
                "Failed to create webhook endpoint",
            ] {
                assert!(
                    !message.contains(leaked),
                    "user copy must not carry Stripe's own {leaked}: {message}"
                );
            }
        }
    }

    /// Every permission label is the string Stripe's key editor shows, because
    /// the message tells the admin which checkbox to look for.
    #[test]
    fn permission_labels_match_stripes_own_wording() {
        assert_eq!(
            StripePermission::WebhookEndpoints.label(),
            "Webhook Endpoints"
        );
        assert_eq!(
            StripePermission::CheckoutSessions.label(),
            "Checkout Sessions"
        );
        assert_eq!(StripePermission::Products.label(), "Products");
        assert_eq!(StripePermission::Prices.label(), "Prices");
        assert_eq!(StripePermission::Customers.label(), "Customers");
        assert_eq!(StripePermission::Subscriptions.label(), "Subscriptions");
        assert_eq!(StripePermission::Invoices.label(), "Invoices");
    }

    // -- BUNYIP-532: probe classification (the proactive self-test) --

    /// A successful read means the key can at least see the resource.
    #[test]
    fn classify_probe_ok_is_granted() {
        let ok: Result<(), StripeServiceError> = Ok(());
        assert_eq!(classify_probe(&ok), ProbeStatus::Granted);
    }

    /// The reported incident: a 403 / `more_permissions_required` on a probe read
    /// is the permission being missing, the same failure BUNYIP-516 maps
    /// reactively.
    #[test]
    fn classify_probe_403_is_missing() {
        let denied: Result<(), _> = Err(stripe_failure(403, Some("more_permissions_required")));
        assert_eq!(classify_probe(&denied), ProbeStatus::Missing);
        // A bare 403 with no code reads the same way.
        let bare: Result<(), _> = Err(stripe_failure(403, None));
        assert_eq!(classify_probe(&bare), ProbeStatus::Missing);
    }

    /// A rejected / expired key is the key's fault, not a single permission's, so
    /// the panel can say so once instead of flagging every permission as missing.
    #[test]
    fn classify_probe_key_rejected_takes_precedence() {
        for e in [
            stripe_failure(401, None),
            stripe_failure(400, Some("api_key_expired")),
            stripe_failure(400, Some("invalid_api_key")),
        ] {
            let res: Result<(), _> = Err(e);
            assert_eq!(classify_probe(&res), ProbeStatus::KeyRejected);
        }
        let unauthorized: Result<(), _> = Err(StripeServiceError::Unauthorized);
        assert_eq!(classify_probe(&unauthorized), ProbeStatus::KeyRejected);
    }

    /// Anything bunyip cannot explain stays inconclusive rather than being
    /// reported as a definite pass or fail.
    #[test]
    fn classify_probe_other_errors_are_unknown() {
        for e in [
            stripe_failure(429, Some("rate_limit")),
            stripe_failure(500, None),
            StripeServiceError::internal("boom"),
        ] {
            let res: Result<(), _> = Err(e);
            assert_eq!(classify_probe(&res), ProbeStatus::Unknown);
        }
    }

    /// The wire key is stable and distinct per permission (the panel keys off it).
    #[test]
    fn permission_keys_are_stable_and_unique() {
        let all = [
            StripePermission::Products,
            StripePermission::Prices,
            StripePermission::Subscriptions,
            StripePermission::Customers,
            StripePermission::CheckoutSessions,
            StripePermission::Invoices,
            StripePermission::WebhookEndpoints,
        ];
        let keys: Vec<&str> = all.iter().map(|p| p.key()).collect();
        assert_eq!(keys.len(), 7);
        let unique: std::collections::HashSet<&str> = keys.iter().copied().collect();
        assert_eq!(unique.len(), 7, "keys must be unique: {keys:?}");
        assert_eq!(
            StripePermission::WebhookEndpoints.key(),
            "webhook_endpoints"
        );
        assert_eq!(
            StripePermission::CheckoutSessions.key(),
            "checkout_sessions"
        );
    }
}
