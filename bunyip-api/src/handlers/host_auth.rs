//! BUNYIP-1011: the machine-caller preamble both host routes share.
//!
//! BUNYIP-983 shipped it inside the host-secrets handler, and the config route
//! needs the same five steps in the same order. Two copies of an
//! authentication sequence is two places for the order to drift, and the order
//! is the security property: credential, then entitlement, then existence, so a
//! caller who cannot authenticate learns nothing about which keys exist and one
//! who can learns nothing about the keys it may not read.
//!
//! The mailer relay keeps its own copy (BUNYIP-602). It is deliberately not
//! folded in here: its caps, its log text and its 429 shape are its own, and
//! rewriting a live mail path to share four lines is a change with no upside.

use actix_web::{HttpRequest, HttpResponse};
use sqlx::PgPool;

use bunyip_oidc::machine_client;
use bunyip_oidc::services::oidc_provider::OAuthClient;

use crate::errors::AppError;
use crate::middleware::extract_client_ip;
use crate::models::RateLimitConfig;
use crate::repositories::{RateLimitConfigRepository, RateLimitRepository};

/// The caps and the log label one host route authenticates under.
///
/// Per route rather than shared, because a burst against one route must not
/// spend the other's budget: a Mokosh reading its configuration every boot and
/// one reading a secret every boot are different callers with different volumes.
pub struct HostRouteCaps {
    /// Per-registration throughput, charged after the credential is verified.
    pub read: &'static RateLimitConfig,
    /// Per-IP FAILED authentications, charged before the Argon2 work is done
    /// on behalf of an unauthenticated caller.
    pub auth_failures: &'static RateLimitConfig,
    /// What the refusal lines call this route, e.g. `"host secrets"`.
    pub label: &'static str,
}

/// Whether failed authentications from this address are already at the cap.
async fn at_cap(pool: &PgPool, ip_key: &str, caps: &HostRouteCaps) -> Result<bool, AppError> {
    let config = RateLimitConfigRepository::effective(pool, caps.auth_failures).await?;
    let (count, _) = RateLimitRepository::check(pool, ip_key, &config).await?;
    Ok(count >= config.max_requests)
}

/// Count one failed authentication. A failure to RECORD a failure is logged and
/// swallowed: the request is already being refused, and turning a counter
/// problem into a different status code would hide the real answer.
async fn record_failure(pool: &PgPool, ip_key: Option<&str>, caps: &HostRouteCaps) {
    let Some(ip_key) = ip_key else { return };
    if let Err(e) = RateLimitRepository::check_and_increment(pool, ip_key, caps.auth_failures).await
    {
        tracing::error!(
            error = %e,
            route = caps.label,
            "could not record a failed client authentication"
        );
    }
}

/// Authenticate a machine caller and charge its throughput budget.
///
/// Returns the registration, which the caller then checks its own allow-list
/// against: the entitlement differs per route and this function deliberately
/// does not know which column to read.
///
/// Failure modes, in the order they are reached: too many failed
/// authentications from this address (429), no Basic header (401), an unknown
/// or disabled registration (401), a wrong secret or a registration without the
/// machine grant (401 or 403 from `verify_machine_client`), and the route's own
/// throughput cap (429).
pub async fn authenticate_machine_caller(
    req: &HttpRequest,
    pool: &PgPool,
    caps: &HostRouteCaps,
) -> Result<OAuthClient, AppError> {
    let ip_key = extract_client_ip(req).map(|ip| ip.to_string());

    if let Some(ip) = ip_key.as_deref() {
        if at_cap(pool, ip, caps).await? {
            let retry_after =
                match RateLimitConfigRepository::effective(pool, caps.auth_failures).await {
                    Ok(config) => config.window_seconds.max(0) as u64,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            route = caps.label,
                            "could not read the failure window; reporting the full window"
                        );
                        caps.auth_failures.window_seconds.max(0) as u64
                    }
                };
            tracing::error!(
                category = "rate_limit",
                client = %ip,
                action = caps.auth_failures.action,
                route = caps.label,
                "too many failed client authentications from this address"
            );
            return Err(AppError::RateLimited { retry_after });
        }
    }

    let Some((client_id, secret)) = machine_client::basic_credentials(req) else {
        record_failure(pool, ip_key.as_deref(), caps).await;
        tracing::warn!(
            ip = ip_key.as_deref().unwrap_or("unknown"),
            route = caps.label,
            "rejected: no HTTP Basic client credential was presented"
        );
        return Err(AppError::OidcInvalidClient(
            "HTTP Basic client credentials are required".into(),
        ));
    };

    let client = match machine_client::load_machine_client(pool, &client_id).await {
        Ok(client) => client,
        Err(e) => {
            record_failure(pool, ip_key.as_deref(), caps).await;
            tracing::warn!(
                ip = ip_key.as_deref().unwrap_or("unknown"),
                client_id = %client_id,
                route = caps.label,
                error = %e,
                "rejected: unknown or disabled client"
            );
            return Err(e);
        }
    };

    if let Err(e) = machine_client::verify_machine_client(&client, &secret).await {
        record_failure(pool, ip_key.as_deref(), caps).await;
        tracing::warn!(
            ip = ip_key.as_deref().unwrap_or("unknown"),
            client_id = %client.client_id,
            client = %client.name,
            route = caps.label,
            error = %e,
            "rejected: client authentication failed"
        );
        return Err(e);
    }

    super::check_rate_limit(pool, &client.client_id.to_string(), caps.read).await?;

    Ok(client)
}

/// The 403 a registration without the key gets, logged with what it asked for.
///
/// Checked by each route against its own column, and refused before the key is
/// looked up at all: an unentitled key answers the same whether or not it
/// exists, so this route cannot be walked to enumerate what the host holds.
pub fn refuse_unentitled(client: &OAuthClient, key: &str, caps: &HostRouteCaps) -> AppError {
    tracing::warn!(
        client_id = %client.client_id,
        client = %client.name,
        key = %key,
        route = caps.label,
        "refused: this registration does not list the key"
    );
    AppError::Forbidden
}

/// Typed 200 body for both routes: the key echoed, and the value.
///
/// Echoing the key means a caller reading several can tell the answers apart
/// without tracking its own requests.
#[derive(Debug, serde::Serialize)]
pub struct HostValueResponse {
    pub key: String,
    pub value: String,
}

/// Nothing here ever logs a value; `HttpResponse` is imported for the type
/// alias the handlers return.
pub type HostResult = Result<HttpResponse, AppError>;
