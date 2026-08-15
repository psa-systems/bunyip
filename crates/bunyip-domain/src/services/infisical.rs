//! BUNYIP-525: app-native runtime fetch of Group-2 (integration) secrets from
//! Infisical.
//!
//! Two-tier secret model. Group-1 startup secrets (postgres, DATABASE_URL,
//! APP_ENCRYPTION_KEY, JWT, ...) stay file/SOPS-based and are read via the
//! `{NAME}_FILE` convention (`secret_env`); nothing here touches them, and the
//! app never needs Infisical to boot. Group-2 integration secrets are read from
//! Infisical by the app itself, which is the deliberate, David-directed
//! exception to the old "no Rust code knows Infisical" rule. Whether this store
//! is consulted at all is `SECRETS_STORAGE` (BUNYIP-542). See
//! `docs/secrets-infisical.md`.
//!
//! Implemented with the shared `reqwest` stack (raw HTTP), NOT the `infisical`
//! crate: that crate is v0.0.3 (unstable) and Infisical's REST API is stable.
//!
//! BUNYIP-542: every call now reports its failure as an [`InfisicalError`]
//! instead of collapsing it to `None`. Whether that failure is fatal is the
//! caller's decision, and it depends on `SECRETS_STORAGE`: with `infisical`
//! declared as the store of record the read is fail-closed, while the other two
//! modes never call in at boot at all.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::InfisicalSettings;

/// Why an Infisical call did not produce a value. Carries the underlying cause
/// so a fatal boot report, an admin form and a log line can all name it.
#[derive(Debug, thiserror::Error)]
pub enum InfisicalError {
    #[error("Universal Auth login failed: {0}")]
    Login(String),
    #[error("the request to Infisical failed: {0}")]
    Request(String),
    #[error("Infisical answered {status} for secret {secret}: {body}")]
    Status {
        secret: String,
        status: u16,
        body: String,
    },
    #[error("the Infisical response for secret {secret} did not parse: {source}")]
    Parse {
        secret: String,
        source: serde_json::Error,
    },
}

/// The shared outbound timeout used across bunyip (see `main.rs`
/// `backchannel_http_client`); a slow or unreachable Infisical fails fast.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// A minimal Infisical client: Universal Auth login + read one secret by name.
#[derive(Clone)]
pub struct InfisicalClient {
    http: reqwest::Client,
    address: String,
    project_id: String,
    environment: String,
    secret_path: String,
    client_id: String,
    client_secret: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
}

#[derive(Deserialize)]
struct LoginResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
}

#[derive(Deserialize)]
struct SecretResponse {
    secret: SecretBody,
}

#[derive(Deserialize)]
struct SecretBody {
    #[serde(rename = "secretValue")]
    secret_value: String,
}

/// The v3 raw-secret write body, shared by the create (POST) and update (PATCH)
/// forms. `secretPath` is project-relative, matching the read.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WriteSecretRequest<'a> {
    workspace_id: &'a str,
    environment: &'a str,
    secret_path: &'a str,
    secret_value: &'a str,
}

impl InfisicalClient {
    /// Build a client from settings. Returns `None` when any required field is
    /// missing; the caller decides what that means, which depends on whether
    /// Infisical is the declared store (fatal) or merely inspectable (skipped).
    pub fn from_settings(settings: &InfisicalSettings) -> Option<Self> {
        if settings.address.is_empty()
            || settings.project_id.is_empty()
            || settings.environment.is_empty()
            || settings.client_id.is_empty()
            || settings.client_secret.is_empty()
        {
            return None;
        }
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .ok()?;
        let secret_path = if settings.secret_path.is_empty() {
            "/".to_string()
        } else {
            settings.secret_path.clone()
        };
        Some(Self {
            http,
            address: settings.address.trim_end_matches('/').to_string(),
            project_id: settings.project_id.clone(),
            environment: settings.environment.clone(),
            secret_path,
            client_id: settings.client_id.clone(),
            client_secret: settings.client_secret.clone(),
        })
    }

    /// The Universal Auth login URL.
    fn login_url(&self) -> String {
        format!("{}/api/v1/auth/universal-auth/login", self.address)
    }

    /// The base secret-read URL (query params added separately). Uses the
    /// long-stable v3 "raw" endpoint, confirmed on infisical.a8n.systems
    /// (unauthenticated it returns 401, so the route exists; a fetch 404 means the
    /// key is not at the queried project/env/path). A v4 form
    /// (`GET {address}/api/v4/secrets/{name}?projectId=...`) exists for
    /// deployments that drop v3.
    fn secret_url(&self, name: &str) -> String {
        format!("{}/api/v3/secrets/raw/{}", self.address, name)
    }

    /// Universal Auth login, returning the access token.
    async fn login(&self) -> Result<String, InfisicalError> {
        let body = LoginRequest {
            client_id: &self.client_id,
            client_secret: &self.client_secret,
        };
        let resp = self
            .http
            .post(self.login_url())
            .json(&body)
            .send()
            .await
            .map_err(|e| InfisicalError::Login(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(InfisicalError::Login(format!(
                "{status} from {}",
                self.login_url()
            )));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| InfisicalError::Login(e.to_string()))?;
        serde_json::from_str::<LoginResponse>(&text)
            .map(|parsed| parsed.access_token)
            .map_err(|e| InfisicalError::Login(format!("the login response did not parse: {e}")))
    }

    /// Fetch one secret value by name (logs in, then reads it).
    ///
    /// `Ok(None)` means the key is genuinely absent at the queried
    /// project/environment/path (404). Every other failure is an `Err` carrying
    /// the cause: in `SECRETS_STORAGE=infisical` the caller makes it fatal,
    /// because "the store of record is unreachable" and "the store of record is
    /// empty" are different facts.
    pub async fn fetch_secret(&self, name: &str) -> Result<Option<String>, InfisicalError> {
        let token = self.login().await?;
        let resp = self
            .http
            .get(self.secret_url(name))
            .bearer_auth(&token)
            // reqwest URL-encodes the query values.
            .query(&[
                ("workspaceId", self.project_id.as_str()),
                ("environment", self.environment.as_str()),
                ("secretPath", self.secret_path.as_str()),
            ])
            .send()
            .await
            .map_err(|e| InfisicalError::Request(e.to_string()))?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let text = resp
            .text()
            .await
            .map_err(|e| InfisicalError::Request(e.to_string()))?;
        if !status.is_success() {
            return Err(InfisicalError::Status {
                secret: name.to_string(),
                status: status.as_u16(),
                body: truncate_body(&text),
            });
        }
        serde_json::from_str::<SecretResponse>(&text)
            .map(|parsed| Some(parsed.secret.secret_value))
            .map_err(|source| InfisicalError::Parse {
                secret: name.to_string(),
                source,
            })
    }

    /// Create or replace one secret value by name (BUNYIP-542).
    ///
    /// The v3 raw endpoint splits create (POST) from update (PATCH), so this
    /// tries the update first and falls back to the create on a 404: an upsert
    /// is what both callers (the admin write path and `secrets-migrate --to
    /// infisical`) actually want, and neither knows whether the key exists yet.
    /// The machine identity needs WRITE access to `INFISICAL_SECRET_PATH`.
    pub async fn upsert_secret(&self, name: &str, value: &str) -> Result<(), InfisicalError> {
        let token = self.login().await?;
        let body = WriteSecretRequest {
            workspace_id: &self.project_id,
            environment: &self.environment,
            secret_path: &self.secret_path,
            secret_value: value,
        };

        let updated = self
            .http
            .patch(self.secret_url(name))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| InfisicalError::Request(e.to_string()))?;
        if updated.status().is_success() {
            return Ok(());
        }
        if updated.status() != reqwest::StatusCode::NOT_FOUND {
            let status = updated.status().as_u16();
            // The status IS the reported failure; an unreadable body only costs
            // the extra detail line, so it degrades to empty rather than
            // masking the error with a different one.
            let text = updated.text().await.unwrap_or_default();
            return Err(InfisicalError::Status {
                secret: name.to_string(),
                status,
                body: truncate_body(&text),
            });
        }

        let created = self
            .http
            .post(self.secret_url(name))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await
            .map_err(|e| InfisicalError::Request(e.to_string()))?;
        if created.status().is_success() {
            return Ok(());
        }
        let status = created.status().as_u16();
        let text = created.text().await.unwrap_or_default();
        Err(InfisicalError::Status {
            secret: name.to_string(),
            status,
            body: truncate_body(&text),
        })
    }

    /// Delete one secret by name, for `secrets-purge` (BUNYIP-542). A key that
    /// is already gone (404) counts as deleted, so the purge is idempotent.
    pub async fn delete_secret(&self, name: &str) -> Result<(), InfisicalError> {
        let token = self.login().await?;
        let resp = self
            .http
            .delete(self.secret_url(name))
            .bearer_auth(&token)
            .json(&serde_json::json!({
                "workspaceId": self.project_id,
                "environment": self.environment,
                "secretPath": self.secret_path,
            }))
            .send()
            .await
            .map_err(|e| InfisicalError::Request(e.to_string()))?;
        if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        Err(InfisicalError::Status {
            secret: name.to_string(),
            status,
            body: truncate_body(&text),
        })
    }
}

/// Keep an error body short enough for one log line. Infisical error bodies name
/// the project/path and the missing permission, never a secret value.
fn truncate_body(body: &str) -> String {
    const MAX: usize = 300;
    let trimmed = body.trim();
    match trimmed.char_indices().nth(MAX) {
        Some((idx, _)) => format!("{}...", &trimmed[..idx]),
        None => trimmed.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> InfisicalSettings {
        InfisicalSettings {
            enabled: true,
            address: "https://infisical.example.com/".to_string(),
            project_id: "proj-123".to_string(),
            environment: "staging".to_string(),
            secret_path: "/runtime".to_string(),
            client_id: "cid".to_string(),
            client_secret: "csecret".to_string(),
        }
    }

    #[test]
    fn from_settings_requires_every_field() {
        assert!(InfisicalClient::from_settings(&settings()).is_some());
        for mutate in [
            |s: &mut InfisicalSettings| s.address.clear(),
            |s: &mut InfisicalSettings| s.project_id.clear(),
            |s: &mut InfisicalSettings| s.environment.clear(),
            |s: &mut InfisicalSettings| s.client_id.clear(),
            |s: &mut InfisicalSettings| s.client_secret.clear(),
        ] {
            let mut s = settings();
            mutate(&mut s);
            assert!(InfisicalClient::from_settings(&s).is_none());
        }
    }

    #[test]
    fn urls_are_built_from_the_trimmed_address() {
        let client = InfisicalClient::from_settings(&settings()).unwrap();
        // Trailing slash on the address is trimmed so URLs never double up.
        assert_eq!(
            client.login_url(),
            "https://infisical.example.com/api/v1/auth/universal-auth/login"
        );
        assert_eq!(
            client.secret_url("SMTP_PASSWORD"),
            "https://infisical.example.com/api/v3/secrets/raw/SMTP_PASSWORD"
        );
    }

    #[test]
    fn empty_secret_path_defaults_to_root() {
        let mut s = settings();
        s.secret_path.clear();
        let client = InfisicalClient::from_settings(&s).unwrap();
        assert_eq!(client.secret_path, "/");
    }

    #[test]
    fn login_response_parses_access_token() {
        let parsed: LoginResponse = serde_json::from_str(
            r#"{"accessToken":"tok","expiresIn":2592000,"tokenType":"Bearer"}"#,
        )
        .unwrap();
        assert_eq!(parsed.access_token, "tok");
    }

    #[test]
    fn secret_response_parses_value() {
        let parsed: SecretResponse = serde_json::from_str(
            r#"{"secret":{"secretKey":"SMTP_PASSWORD","secretValue":"hunter2","version":1}}"#,
        )
        .unwrap();
        assert_eq!(parsed.secret.secret_value, "hunter2");
    }

    /// BUNYIP-542: the write body Infisical's v3 raw endpoint expects, for both
    /// the PATCH (update) and POST (create) halves of the upsert.
    #[test]
    fn write_secret_request_serializes_camel_case() {
        let body = serde_json::to_string(&WriteSecretRequest {
            workspace_id: "proj-123",
            environment: "staging",
            secret_path: "/runtime",
            secret_value: "hunter2",
        })
        .unwrap();
        assert_eq!(
            body,
            r#"{"workspaceId":"proj-123","environment":"staging","secretPath":"/runtime","secretValue":"hunter2"}"#
        );
    }

    /// An error body is truncated for the log line but never emptied: the cause
    /// (a missing write scope, a wrong path) has to survive into the operator's
    /// message.
    #[test]
    fn error_bodies_are_truncated_not_dropped() {
        assert_eq!(truncate_body("  permission denied  "), "permission denied");
        let long = "x".repeat(400);
        let truncated = truncate_body(&long);
        assert!(truncated.ends_with("..."));
        assert_eq!(truncated.len(), 303);
    }

    #[test]
    fn login_request_serializes_camel_case() {
        let body = serde_json::to_string(&LoginRequest {
            client_id: "a",
            client_secret: "b",
        })
        .unwrap();
        assert_eq!(body, r#"{"clientId":"a","clientSecret":"b"}"#);
    }
}
