//! BUNYIP-983: `GET /v1/host/secrets/{KEY}`, read-only, for a registered
//! calling app.
//!
//! The authentication is the mailer relay's (BUNYIP-602/604): HTTP Basic
//! machine-client credentials, verified against the Argon2id hash on
//! `oauth_clients`, with the `client_credentials` grant required and
//! `disabled_at` honoured by the lookup. That is the only machine-to-machine
//! credential this deployment issues, and reusing it means revoking a calling
//! app's access stays one `machine-client disable` for every machine endpoint
//! it can reach.
//!
//! ## The order of the checks is the design
//!
//! 1. Credentials, before anything about the key is looked at. A caller who
//!    cannot authenticate learns nothing about which keys exist.
//! 2. The allow-list on the caller's own registration. A key the caller is not
//!    entitled to is a 403 whether or not it exists, so this endpoint cannot
//!    be walked to enumerate the host's secrets.
//! 3. Whether the key is one this build serves, and then whether a value is
//!    set for it. Both are 404s, and the detail says which: an operator with a
//!    typo in `allowed_secret_keys` and an operator who has not filled the
//!    admin form in yet need different sentences.
//!
//! Nothing here logs a value, and the 200 body is the only place one appears.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Serialize;
use sqlx::PgPool;

use bunyip_oidc::machine_client;

use crate::errors::AppError;
use crate::host_secrets::HostSecret;
use crate::middleware::extract_client_ip;
use crate::models::RateLimitConfig;
use crate::repositories::{RateLimitConfigRepository, RateLimitRepository};
use crate::responses::{get_request_id, success};
use bunyip_domain::config::Config;
use bunyip_domain::services::AppKeySet;

/// The 200 body. `key` is echoed so a caller reading several keys can tell the
/// answers apart without tracking its own requests.
#[derive(Debug, Serialize)]
pub struct HostSecretResponse {
    pub key: String,
    pub value: String,
}

/// Whether failed authentications from this address are already at the cap.
async fn auth_failures_at_cap(pool: &PgPool, ip_key: &str) -> Result<bool, AppError> {
    let config =
        RateLimitConfigRepository::effective(pool, &RateLimitConfig::HOST_SECRET_AUTH_FAILURES)
            .await?;
    let (count, _) = RateLimitRepository::check(pool, ip_key, &config).await?;
    Ok(count >= config.max_requests)
}

/// Count one failed authentication. A failure to RECORD a failure is logged and
/// swallowed: the request is already being refused, and turning a counter
/// problem into a different status code would hide the real answer.
async fn record_auth_failure(pool: &PgPool, ip_key: Option<&str>) {
    let Some(ip_key) = ip_key else { return };
    if let Err(e) = RateLimitRepository::check_and_increment(
        pool,
        ip_key,
        &RateLimitConfig::HOST_SECRET_AUTH_FAILURES,
    )
    .await
    {
        tracing::error!(
            error = %e,
            "host secrets could not record a failed client authentication"
        );
    }
}

/// GET /v1/host/secrets/{key}
pub async fn get_host_secret(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let key = path.into_inner();
    let ip_key = extract_client_ip(&req).map(|ip| ip.to_string());

    if let Some(ip) = ip_key.as_deref() {
        if auth_failures_at_cap(&pool, ip).await? {
            let retry_after = match RateLimitConfigRepository::effective(
                &pool,
                &RateLimitConfig::HOST_SECRET_AUTH_FAILURES,
            )
            .await
            {
                Ok(config) => config.window_seconds.max(0) as u64,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "host secrets could not read the failure window; reporting the full window"
                    );
                    RateLimitConfig::HOST_SECRET_AUTH_FAILURES
                        .window_seconds
                        .max(0) as u64
                }
            };
            tracing::error!(
                category = "rate_limit",
                client = %ip,
                action = RateLimitConfig::HOST_SECRET_AUTH_FAILURES.action,
                "host secrets: too many failed client authentications from this address"
            );
            return Err(AppError::RateLimited { retry_after });
        }
    }

    let Some((client_id, secret)) = machine_client::basic_credentials(&req) else {
        record_auth_failure(&pool, ip_key.as_deref()).await;
        tracing::warn!(
            ip = ip_key.as_deref().unwrap_or("unknown"),
            "host secrets rejected: no HTTP Basic client credential was presented"
        );
        return Err(AppError::OidcInvalidClient(
            "HTTP Basic client credentials are required".into(),
        ));
    };

    let client = match machine_client::load_machine_client(&pool, &client_id).await {
        Ok(client) => client,
        Err(e) => {
            record_auth_failure(&pool, ip_key.as_deref()).await;
            tracing::warn!(
                ip = ip_key.as_deref().unwrap_or("unknown"),
                client_id = %client_id,
                error = %e,
                "host secrets rejected: unknown or disabled client"
            );
            return Err(e);
        }
    };

    if let Err(e) = machine_client::verify_machine_client(&client, &secret).await {
        record_auth_failure(&pool, ip_key.as_deref()).await;
        tracing::warn!(
            ip = ip_key.as_deref().unwrap_or("unknown"),
            client_id = %client.client_id,
            client = %client.name,
            error = %e,
            "host secrets rejected: client authentication failed"
        );
        return Err(e);
    }

    super::check_rate_limit(
        &pool,
        &client.client_id.to_string(),
        &RateLimitConfig::HOST_SECRET_READ,
    )
    .await?;

    // The entitlement before the existence, so a caller cannot learn which
    // keys this host holds by asking for them one at a time.
    if !client.allowed_secret_keys.iter().any(|k| k == &key) {
        tracing::warn!(
            client_id = %client.client_id,
            client = %client.name,
            key = %key,
            "host secrets refused: this registration does not list the key"
        );
        return Err(AppError::Forbidden);
    }

    let Some(secret) = HostSecret::parse(&key) else {
        // Allow-listed and unservable, which is an operator's typo in
        // `allowed_secret_keys` rather than a caller's mistake, so the message
        // says where to look.
        tracing::error!(
            client_id = %client.client_id,
            client = %client.name,
            key = %key,
            "host secrets: the registration lists a key this build does not serve"
        );
        return Err(AppError::not_found(format!(
            "{key} is not a host secret this deployment serves"
        )));
    };

    let Some(value) = secret.resolve(&pool, &config, &app_key_set).await? else {
        return Err(AppError::not_found(format!(
            "{key} is not set; an administrator sets it under Host configuration"
        )));
    };

    tracing::info!(
        client_id = %client.client_id,
        client = %client.name,
        key = %key,
        "served a host secret"
    );

    Ok(success(
        HostSecretResponse {
            key: key.clone(),
            value,
        },
        request_id,
    ))
}

#[cfg(test)]
mod tests {
    /// The handler must not grow a logging call that takes the value. The
    /// value reaches exactly one place, the response body, and a `tracing`
    /// line carrying it would copy a host secret into the log shipper.
    #[test]
    fn the_handler_never_logs_a_value() {
        let src = include_str!("host_secrets.rs");
        let head = &src[..src.find("mod tests").expect("this module")];
        for forbidden in [
            "value = %",
            "value = ?",
            "{value}",
            "value,\n            \"served",
        ] {
            assert!(
                !head.contains(forbidden),
                "a diagnostic carries the secret value: {forbidden}"
            );
        }
    }

    /// The order of the three refusals is load-bearing (see the module doc), so
    /// it is asserted on the source rather than left to a reviewer.
    #[test]
    fn the_entitlement_is_checked_before_the_key_exists() {
        let src = include_str!("host_secrets.rs");
        let head = &src[..src.find("mod tests").expect("this module")];
        let verify = head
            .find("verify_machine_client(&client, &secret)")
            .expect("the credential check");
        let allow_list = head
            .find("client.allowed_secret_keys")
            .expect("the allow-list check");
        let parse = head
            .find("HostSecret::parse(&key)")
            .expect("the key lookup");
        assert!(
            verify < allow_list && allow_list < parse,
            "credentials, then entitlement, then existence"
        );
    }
}
