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

use actix_web::{web, HttpRequest};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::host_secrets::HostSecret;
use crate::models::RateLimitConfig;
use crate::responses::{get_request_id, success};
use bunyip_domain::config::Config;
use bunyip_domain::services::AppKeySet;

use super::host_auth::{
    authenticate_machine_caller, refuse_unentitled, HostResult, HostRouteCaps, HostValueResponse,
};

/// The caps and label this route authenticates under.
const CAPS: HostRouteCaps = HostRouteCaps {
    read: &RateLimitConfig::HOST_SECRET_READ,
    auth_failures: &RateLimitConfig::HOST_SECRET_AUTH_FAILURES,
    label: "host secrets",
};

/// GET /v1/host/secrets/{key}
pub async fn get_host_secret(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
    path: web::Path<String>,
) -> HostResult {
    let request_id = get_request_id(&req);
    let key = path.into_inner();

    let client = authenticate_machine_caller(&req, &pool, &CAPS).await?;

    // The entitlement before the existence, so a caller cannot learn which
    // keys this host holds by asking for them one at a time.
    if !client.allowed_secret_keys.iter().any(|k| k == &key) {
        return Err(refuse_unentitled(&client, &key, &CAPS));
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
        HostValueResponse {
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
    ///
    /// The credential half moved into `host_auth` when the config route needed
    /// the same preamble (BUNYIP-1011); what stays here is that this handler
    /// authenticates before it reads the key at all, and checks the
    /// entitlement before the key's existence.
    #[test]
    fn the_entitlement_is_checked_before_the_key_exists() {
        let src = include_str!("host_secrets.rs");
        let head = &src[..src.find("mod tests").expect("this module")];
        let authenticate = head
            .find("authenticate_machine_caller(&req, &pool, &CAPS)")
            .expect("the credential check");
        let allow_list = head
            .find("client.allowed_secret_keys")
            .expect("the allow-list check");
        let parse = head
            .find("HostSecret::parse(&key)")
            .expect("the key lookup");
        assert!(
            authenticate < allow_list && allow_list < parse,
            "credentials, then entitlement, then existence"
        );
    }
}
