//! BUNYIP-356: the real Mokosh backup adapter.
//!
//! Calls mokosh-server's tenant data export/import API (`/api/v1/data/export`,
//! `/api/v1/data/import`) on behalf of the account admin, fulfilling the
//! [`AppBackupAdapter`] contract that [`bunyip_domain`] defines. bunyip is the
//! OIDC issuer, so it mints a short-lived Mokosh-audience `at+jwt` for the
//! acting user via [`OidcProvider::mint_access_token`] and uses it as the
//! server-to-server bearer. Mokosh scopes export/import to the token user's own
//! tenant, so the token must be user-scoped (not a bare service credential).
//!
//! This lives in bunyip-api rather than bunyip-domain because it depends on
//! bunyip-oidc (the OIDC provider), and the dependency direction forbids
//! bunyip-domain from depending on bunyip-oidc. When Mokosh is unconfigured,
//! `main.rs` registers the domain's pending stub instead of this adapter.

use std::sync::Arc;

use async_trait::async_trait;
use bunyip_oidc::services::oidc_provider::{OAuthClient, OidcProvider};
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::repositories::UserRepository;
use crate::services::{AppBackupAdapter, AppBackupContext, AppBackupOutcome};
use crate::AppError;

/// The acr the minted backup token carries; mirrors the password login-flow
/// value bunyip stamps on interactive at+jwts (`handlers/oidc.rs`).
const BACKUP_TOKEN_ACR: &str = "urn:bunyip:loa:pwd";

/// Real Mokosh backup/restore driver. Holds what it needs to mint a
/// Mokosh-audience token (provider + the Mokosh OAuth client + a pool to load
/// the user) and to make the HTTP calls (an http client + the Mokosh base URL).
pub struct MokoshHttpBackupAdapter {
    http: reqwest::Client,
    /// Mokosh API base for the server-to-server call, e.g.
    /// `http://mokosh-server-app:4301` (may differ from the token audience,
    /// which is Mokosh's public canonical URL from the OAuth client record).
    base_url: String,
    provider: Arc<OidcProvider>,
    /// The Mokosh OAuth client, source of the token `aud` + TTL.
    client: OAuthClient,
    pool: PgPool,
}

impl MokoshHttpBackupAdapter {
    pub fn new(
        http: reqwest::Client,
        base_url: String,
        provider: Arc<OidcProvider>,
        client: OAuthClient,
        pool: PgPool,
    ) -> Self {
        Self {
            http,
            base_url,
            provider,
            client,
            pool,
        }
    }

    /// Mint a short-lived Mokosh-audience `at+jwt` for `user_id`. The token's
    /// `sub` is the bunyip user id, which Mokosh JIT-mirrors as its own user id,
    /// and `bunyip_role` (stamped from the user's role) satisfies Mokosh's
    /// admin gate on the data endpoints.
    async fn mint_token(&self, user_id: Uuid) -> Result<String, AppError> {
        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or_else(|| AppError::not_found("User"))?;
        let (token, _exp) = self.provider.mint_access_token(
            &user,
            &self.client,
            &["openid".to_string(), "email".to_string()],
            Utc::now(),
            BACKUP_TOKEN_ACR,
            &[],
            None,
        )?;
        Ok(token)
    }
}

#[async_trait]
impl AppBackupAdapter for MokoshHttpBackupAdapter {
    fn slug(&self) -> &str {
        "mokosh"
    }

    async fn backup(&self, ctx: &AppBackupContext) -> Result<AppBackupOutcome, AppError> {
        let token = self.mint_token(ctx.user_id).await?;
        mokosh_export(&self.http, &self.base_url, &token).await
    }

    async fn restore(&self, ctx: &AppBackupContext, bundle: &Value) -> Result<bool, AppError> {
        // Fail fast before minting if the bundle can't satisfy the import guard.
        confirm_from_bundle(bundle)?;
        let token = self.mint_token(ctx.user_id).await?;
        mokosh_import(&self.http, &self.base_url, &token, bundle).await
    }
}

/// The `confirm` value Mokosh's import requires: the tenant name, which the
/// export envelope carries (PMS-647). A bundle without it cannot be imported.
fn confirm_from_bundle(bundle: &Value) -> Result<&str, AppError> {
    bundle
        .get("tenant_name")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::bad_request("Mokosh backup bundle is missing tenant_name; cannot restore")
        })
}

/// `GET {base}/api/v1/data/export` with the bearer token. A 2xx yields the
/// envelope; any other status is reported as unavailable (recorded in the
/// account bundle, not fatal to the overall backup).
async fn mokosh_export(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
) -> Result<AppBackupOutcome, AppError> {
    let url = format!("{}/api/v1/data/export", base_url.trim_end_matches('/'));
    let resp = http
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| AppError::upstream(format!("Mokosh export request failed: {e}")))?;
    if resp.status().is_success() {
        let envelope: Value = resp
            .json()
            .await
            .map_err(|e| AppError::upstream(format!("Mokosh export decode failed: {e}")))?;
        Ok(AppBackupOutcome::Produced(envelope))
    } else {
        Ok(AppBackupOutcome::Unavailable(format!(
            "Mokosh export returned HTTP {}",
            resp.status().as_u16()
        )))
    }
}

/// `POST {base}/api/v1/data/import` with `{confirm, export}`. Returns whether
/// Mokosh accepted the restore (2xx).
async fn mokosh_import(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    bundle: &Value,
) -> Result<bool, AppError> {
    let confirm = confirm_from_bundle(bundle)?;
    let url = format!("{}/api/v1/data/import", base_url.trim_end_matches('/'));
    let body = json!({ "confirm": confirm, "export": bundle });
    let resp = http
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .map_err(|e| AppError::upstream(format!("Mokosh import request failed: {e}")))?;
    Ok(resp.status().is_success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn confirm_requires_tenant_name() {
        let ok = json!({ "tenant_name": "Acme", "entities": {} });
        assert_eq!(confirm_from_bundle(&ok).unwrap(), "Acme");
        let missing = json!({ "entities": {} });
        assert!(confirm_from_bundle(&missing).is_err());
    }

    #[tokio::test]
    async fn export_returns_produced_envelope_on_2xx() {
        let server = MockServer::start().await;
        let envelope = json!({ "schema_version": 1, "tenant_name": "Acme", "entities": {} });
        Mock::given(method("GET"))
            .and(path("/api/v1/data/export"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(envelope.clone()))
            .mount(&server)
            .await;

        let out = mokosh_export(&reqwest::Client::new(), &server.uri(), "tok")
            .await
            .unwrap();
        match out {
            AppBackupOutcome::Produced(v) => assert_eq!(v, envelope),
            AppBackupOutcome::Unavailable(m) => panic!("expected Produced, got Unavailable: {m}"),
        }
    }

    #[tokio::test]
    async fn export_reports_unavailable_on_non_2xx() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/data/export"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let out = mokosh_export(&reqwest::Client::new(), &server.uri(), "tok")
            .await
            .unwrap();
        assert!(matches!(out, AppBackupOutcome::Unavailable(_)));
    }

    #[tokio::test]
    async fn import_posts_confirm_and_envelope_and_reads_success() {
        let server = MockServer::start().await;
        let bundle = json!({ "schema_version": 1, "tenant_name": "Acme", "entities": {} });
        Mock::given(method("POST"))
            .and(path("/api/v1/data/import"))
            .and(header("authorization", "Bearer tok"))
            .and(wiremock::matchers::body_json(json!({
                "confirm": "Acme",
                "export": bundle.clone(),
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "imported" })))
            .mount(&server)
            .await;

        let ok = mokosh_import(&reqwest::Client::new(), &server.uri(), "tok", &bundle)
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn import_returns_false_on_non_2xx() {
        let server = MockServer::start().await;
        let bundle = json!({ "tenant_name": "Acme", "entities": {} });
        Mock::given(method("POST"))
            .and(path("/api/v1/data/import"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({ "error": "nope" })))
            .mount(&server)
            .await;

        let ok = mokosh_import(&reqwest::Client::new(), &server.uri(), "tok", &bundle)
            .await
            .unwrap();
        assert!(!ok);
    }
}
