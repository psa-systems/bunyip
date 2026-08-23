//! Machine-to-machine caller authentication (BUNYIP-602).
//!
//! bunyip-api's mailer relay authenticates a CALLING APP, not a person, and the
//! suite already has one registry of app identities with hashed secrets:
//! `oauth_clients`. This module exposes that registry's credential check to
//! non-OIDC endpoints so a machine credential is registered, rotated and
//! disabled in exactly one place.
//!
//! The credential is presented as HTTP Basic (`client_id:client_secret`), the
//! same `client_secret_basic` credential `/oauth2/token` accepts. A machine
//! endpoint verifies it directly rather than exchanging it for an access token:
//! bunyip-api's access-token path resolves a `users` row for every verified
//! token (`verify_once`, BUNYIP-557), and a client-credentials token has no
//! user behind it. Minting one is the separate, larger change tracked apart
//! from this endpoint.

use actix_web::HttpRequest;
use base64::Engine;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::services::OAuthClient;

/// The grant a registration must list to be allowed at a machine endpoint.
///
/// `oauth_clients.allowed_grant_types` is the existing per-client opt-in
/// (BUNYIP-254 already enforces it at `/oauth2/token`), so a browser-facing
/// client registered for `authorization_code` alone can never reach one of
/// these endpoints, even holding a valid secret.
pub const MACHINE_GRANT: &str = "client_credentials";

/// `(client_id, client_secret)` from an HTTP Basic `Authorization` header.
///
/// Returns `None` when the header is absent, is not `Basic`, does not decode,
/// or carries no `:` separator. Per RFC 6749 §2.3.1 both halves are
/// form-urlencoded before the base64.
pub fn basic_credentials(req: &HttpRequest) -> Option<(String, String)> {
    let encoded = req
        .headers()
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let credentials = String::from_utf8(decoded).ok()?;
    let (id, secret) = credentials.split_once(':')?;
    Some((
        urlencoding::decode(id).ok()?.into_owned(),
        urlencoding::decode(secret).ok()?.into_owned(),
    ))
}

/// Load the registration behind `client_id`, or fail as an unknown client.
///
/// Takes the pool, not an `OidcProvider`: authenticating a calling app needs the
/// registration table and nothing else, so a machine endpoint stays usable on an
/// instance where the OIDC issuer is switched off. The query filters
/// `disabled_at IS NULL`, so a disabled registration is indistinguishable from
/// an unregistered one, which is what revoking a calling app's access means.
///
/// An unknown id returns before any Argon2 work, which is a timing difference.
/// It reveals nothing usable: a `client_id` is a random UUID, so there is no
/// candidate space an attacker can walk.
pub async fn load_machine_client(pool: &PgPool, client_id: &str) -> Result<OAuthClient, AppError> {
    let client_id = Uuid::parse_str(client_id)
        .map_err(|_| AppError::OidcInvalidClient("invalid client_id format".into()))?;
    crate::services::oidc_provider::load_client(pool, client_id)
        .await?
        .ok_or_else(|| AppError::OidcInvalidClient("unknown client".into()))
}

/// Hash a client secret for storage in `oauth_clients.client_secret_hash`.
///
/// The counterpart to [`verify_machine_client`], so provisioning a machine
/// credential and checking one agree on the format by construction rather than
/// by a comment in a migration. `Argon2::default()` is what
/// `handlers::oidc::authenticate_client` verifies with, and verification reads
/// its parameters from the PHC string either way. Runs on the blocking pool
/// like every other Argon2 call in the workspace (BUNYIP-553).
pub async fn hash_client_secret(secret: &str) -> Result<String, AppError> {
    let secret = secret.to_string();
    bunyip_domain::services::argon2_offload::offload("oidc client secret hash", move || {
        use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
        let salt = SaltString::generate(&mut OsRng);
        argon2::Argon2::default()
            .hash_password(secret.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| AppError::internal(format!("Failed to hash client secret: {e}")))
    })
    .await
}

/// Verify a machine caller against an already-loaded registration.
///
/// Split from [`load_machine_client`] so the credential and entitlement rules
/// are exercised without a database.
///
/// Order matters: the SECRET is verified before the entitlement. Checking the
/// entitlement first would answer 403 for a relay-enabled client and 401 for
/// every other one, turning the endpoint into an oracle that tells an
/// unauthenticated caller which registrations exist and which may relay.
///
/// Failure modes:
/// - wrong / missing secret, or a public (`none`-auth) registration presenting
///   one: [`AppError::OidcInvalidClient`], answered 401 with `WWW-Authenticate`;
/// - authentic but not registered for [`MACHINE_GRANT`]: [`AppError::Forbidden`],
///   answered 403.
pub async fn verify_machine_client(client: &OAuthClient, secret: &str) -> Result<(), AppError> {
    crate::handlers::oidc::authenticate_client(client, Some(secret)).await?;

    if !client
        .allowed_grant_types
        .iter()
        .any(|g| g == MACHINE_GRANT)
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use chrono::Utc;

    async fn confidential_client(secret: &str, grants: &[&str]) -> OAuthClient {
        OAuthClient {
            id: Uuid::new_v4(),
            client_id: Uuid::new_v4(),
            client_secret_hash: Some(hash_client_secret(secret).await.expect("hash")),
            client_type: "confidential".to_string(),
            name: "mokosh-server".to_string(),
            logo_uri: None,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            lifecycle_event_uri: None,
            allowed_scopes: Vec::new(),
            access_token_ttl_seconds: 600,
            refresh_token_ttl_seconds: 2_592_000,
            refresh_idle_ttl_seconds: 1_209_600,
            audience: "https://api.example.test".to_string(),
            created_at: Utc::now(),
            disabled_at: None,
            first_party: true,
            tenant_claim_name: None,
            allowed_grant_types: grants.iter().map(|g| g.to_string()).collect(),
            token_endpoint_auth_method: "client_secret_basic".to_string(),
        }
    }

    #[actix_web::test]
    async fn a_hashed_secret_round_trips_through_the_verifier() {
        // Provisioning and checking must agree on the hash format, which is the
        // whole reason `hash_client_secret` lives beside the verifier.
        let hash = hash_client_secret("provisioned").await.expect("hash");
        assert!(hash.starts_with("$argon2"), "PHC-formatted hash: {hash}");
        let mut client = confidential_client("ignored", &[MACHINE_GRANT]).await;
        client.client_secret_hash = Some(hash);
        verify_machine_client(&client, "provisioned")
            .await
            .expect("the provisioned secret authenticates");
    }

    #[actix_web::test]
    async fn a_registered_machine_client_with_the_right_secret_authenticates() {
        let client = confidential_client("s3cret", &[MACHINE_GRANT]).await;
        verify_machine_client(&client, "s3cret")
            .await
            .expect("the registered secret authenticates");
    }

    #[actix_web::test]
    async fn a_wrong_secret_is_a_401_shaped_rejection() {
        let client = confidential_client("s3cret", &[MACHINE_GRANT]).await;
        let err = verify_machine_client(&client, "wrong")
            .await
            .expect_err("a wrong secret must not authenticate");
        assert!(matches!(err, AppError::OidcInvalidClient(_)));
        assert_eq!(
            actix_web::ResponseError::status_code(&err),
            actix_web::http::StatusCode::UNAUTHORIZED
        );
    }

    #[actix_web::test]
    async fn a_client_not_registered_for_the_machine_grant_is_403_even_with_its_secret() {
        let client = confidential_client("s3cret", &["authorization_code", "refresh_token"]).await;
        let err = verify_machine_client(&client, "s3cret")
            .await
            .expect_err("a browser-only registration must not reach a machine endpoint");
        assert!(matches!(err, AppError::Forbidden));
        assert_eq!(
            actix_web::ResponseError::status_code(&err),
            actix_web::http::StatusCode::FORBIDDEN
        );
    }

    #[actix_web::test]
    async fn a_public_client_cannot_authenticate_as_a_machine_caller() {
        let mut client = confidential_client("s3cret", &[MACHINE_GRANT]).await;
        client.client_type = "public".to_string();
        client.token_endpoint_auth_method = "none".to_string();
        client.client_secret_hash = None;
        let err = verify_machine_client(&client, "s3cret")
            .await
            .expect_err("a public SPA registration has no machine credential");
        assert!(matches!(err, AppError::OidcInvalidClient(_)));
    }

    #[actix_web::test]
    async fn the_wrong_secret_is_rejected_before_the_entitlement_is_consulted() {
        // Both wrong: the answer must be the 401, never the 403 that would tell
        // an unauthenticated caller this registration exists but lacks the grant.
        let client = confidential_client("s3cret", &["authorization_code"]).await;
        let err = verify_machine_client(&client, "wrong").await.unwrap_err();
        assert!(matches!(err, AppError::OidcInvalidClient(_)));
    }

    #[test]
    fn basic_credentials_reads_the_header_and_percent_decodes_both_halves() {
        let raw = base64::engine::general_purpose::STANDARD.encode("client%2Did:se%3Acret");
        let req = TestRequest::default()
            .insert_header(("Authorization", format!("Basic {raw}")))
            .to_http_request();
        assert_eq!(
            basic_credentials(&req),
            Some(("client-id".to_string(), "se:cret".to_string()))
        );
    }

    #[test]
    fn basic_credentials_is_none_for_a_missing_or_wrong_scheme_header() {
        assert_eq!(
            basic_credentials(&TestRequest::default().to_http_request()),
            None
        );
        let bearer = TestRequest::default()
            .insert_header(("Authorization", "Bearer abc"))
            .to_http_request();
        assert_eq!(basic_credentials(&bearer), None);
        let garbage = TestRequest::default()
            .insert_header(("Authorization", "Basic !!!not-base64!!!"))
            .to_http_request();
        assert_eq!(basic_credentials(&garbage), None);
        // Decodes, but carries no `:` separator.
        let no_sep = base64::engine::general_purpose::STANDARD.encode("client-id-only");
        let no_sep = TestRequest::default()
            .insert_header(("Authorization", format!("Basic {no_sep}")))
            .to_http_request();
        assert_eq!(basic_credentials(&no_sep), None);
    }
}
