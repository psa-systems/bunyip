//! BUNYIP-1011: `GET /v1/host/config/{KEY}`, read-only, for a registered
//! calling app.
//!
//! The configuration twin of [`super::host_secrets`], sharing its
//! authentication preamble ([`super::host_auth`]) and differing in exactly two
//! ways. The entitlement is `oauth_clients.allowed_config_keys`, so a
//! credential that may read a suite fact is not thereby allowed to read a
//! secret (BUNYIP-855 D9). And the registry is [`HostConfig`], which contains
//! no `GovernedSecret`, so the two cannot be crossed by naming a key.

use actix_web::{web, HttpRequest};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::host_config::HostConfig;
use crate::models::RateLimitConfig;
use crate::responses::{get_request_id, success};
use bunyip_domain::config::Config;

use super::host_auth::{
    authenticate_machine_caller, refuse_unentitled, HostResult, HostRouteCaps, HostValueResponse,
};

/// The caps and label this route authenticates under. Its own, not the secrets
/// route's: a product reading its configuration every boot and one reading a
/// secret every boot are different callers, and one's burst must not spend the
/// other's budget.
const CAPS: HostRouteCaps = HostRouteCaps {
    read: &RateLimitConfig::HOST_CONFIG_READ,
    auth_failures: &RateLimitConfig::HOST_CONFIG_AUTH_FAILURES,
    label: "host config",
};

/// GET /v1/host/config/{key}
pub async fn get_host_config(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    path: web::Path<String>,
) -> HostResult {
    let request_id = get_request_id(&req);
    let key = path.into_inner();

    let client = authenticate_machine_caller(&req, &pool, &CAPS).await?;

    // The entitlement before the existence, for the secrets route's reason.
    if !client.allowed_config_keys.iter().any(|k| k == &key) {
        return Err(refuse_unentitled(&client, &key, &CAPS));
    }

    let Some(entry) = HostConfig::parse(&key) else {
        // Allow-listed and unservable: an operator's typo in
        // `allowed_config_keys`, or a secret's key asked for on the
        // configuration route, which this registry deliberately does not know.
        tracing::error!(
            client_id = %client.client_id,
            client = %client.name,
            key = %key,
            "host config: the registration lists a key this build does not serve"
        );
        return Err(AppError::not_found(format!(
            "{key} is not a host configuration value this deployment serves"
        )));
    };

    let Some(value) = entry.resolve(&config) else {
        return Err(AppError::not_found(format!(
            "{key} has no value on this deployment; an operator sets it in bunyip's own \
             configuration"
        )));
    };

    tracing::info!(
        client_id = %client.client_id,
        client = %client.name,
        key = %key,
        "served a host configuration value"
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
    /// Same rule as the secrets route: nothing here logs a value. These are
    /// not secrets, and a support address in a log is harmless, but the two
    /// handlers are read side by side and a reader should not have to work out
    /// which one is allowed to be careless.
    #[test]
    fn the_handler_never_logs_a_value() {
        let src = include_str!("host_config.rs");
        let head = &src[..src.find("mod tests").expect("this module")];
        for forbidden in ["value = %", "value = ?", "{value}"] {
            assert!(
                !head.contains(forbidden),
                "a diagnostic carries the value: {forbidden}"
            );
        }
    }

    /// Credentials, then entitlement, then existence, for the secrets route's
    /// reason: an unentitled key must answer the same whether or not it
    /// exists.
    #[test]
    fn the_entitlement_is_checked_before_the_key_exists() {
        let src = include_str!("host_config.rs");
        let head = &src[..src.find("mod tests").expect("this module")];
        let authenticate = head
            .find("authenticate_machine_caller(&req, &pool, &CAPS)")
            .expect("the credential check");
        let allow_list = head
            .find("client.allowed_config_keys")
            .expect("the allow-list check");
        let parse = head
            .find("HostConfig::parse(&key)")
            .expect("the key lookup");
        assert!(
            authenticate < allow_list && allow_list < parse,
            "credentials, then entitlement, then existence"
        );
    }

    /// This route reads the CONFIG allow-list and only that one. Reading the
    /// secrets column here would hand every host-secrets credential the
    /// configuration keys as well, which is the entitlement split BUNYIP-855
    /// D9 asked for, undone.
    #[test]
    fn it_reads_its_own_allow_list() {
        let src = include_str!("host_config.rs");
        let head = &src[..src.find("mod tests").expect("this module")];
        assert!(head.contains("client.allowed_config_keys"));
        assert!(
            !head.contains("client.allowed_secret_keys"),
            "the two entitlements stay apart"
        );
    }
}
