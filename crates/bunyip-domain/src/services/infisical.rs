//! BUNYIP-525: app-native runtime fetch of Group-2 (integration) secrets from
//! Infisical.
//!
//! Two-tier secret model. Group-1 startup secrets (postgres, DATABASE_URL,
//! APP_ENCRYPTION_KEY, JWT, ...) stay file/SOPS-based and are read via the
//! `{NAME}_FILE` convention (`secret_env`); nothing here touches them, and the
//! app never needs Infisical to boot. Group-2 post-startup integration secrets
//! (SMTP first) are fetched by the app from Infisical at runtime, gracefully:
//! this is the deliberate, David-directed exception to the old "no Rust code
//! knows Infisical" rule. See `docs/secrets-infisical.md`.
//!
//! Implemented with the shared `reqwest` stack (raw HTTP), NOT the `infisical`
//! crate: that crate is v0.0.3 (unstable) and Infisical's REST API is stable.
//! Every failure resolves to `None` (fail-open, never a boot dependency).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::InfisicalSettings;

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

impl InfisicalClient {
    /// Build a client from settings. Returns `None` when any required field is
    /// missing, so a half-configured host simply does not fetch (fail-open).
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

    /// Universal Auth login, returning the access token. `None` on any failure.
    async fn login(&self) -> Option<String> {
        let body = LoginRequest {
            client_id: &self.client_id,
            client_secret: &self.client_secret,
        };
        match self.http.post(self.login_url()).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<LoginResponse>().await {
                Ok(parsed) => Some(parsed.access_token),
                Err(err) => {
                    warn!(error = %err, "Infisical login response did not parse");
                    None
                }
            },
            Ok(resp) => {
                warn!(status = %resp.status(), "Infisical login returned non-success");
                None
            }
            Err(err) => {
                warn!(error = %err, "Infisical login request failed");
                None
            }
        }
    }

    /// Fetch one secret value by name (logs in, then reads it). `None` on ANY
    /// error (unreachable, non-2xx, parse), so Infisical is never a boot
    /// dependency and a Group-2 feature simply stays off until it resolves.
    pub async fn fetch_secret(&self, name: &str) -> Option<String> {
        let token = self.login().await?;
        let request = self
            .http
            .get(self.secret_url(name))
            .bearer_auth(&token)
            // reqwest URL-encodes the query values.
            .query(&[
                ("workspaceId", self.project_id.as_str()),
                ("environment", self.environment.as_str()),
                ("secretPath", self.secret_path.as_str()),
            ]);
        match request.send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<SecretResponse>().await {
                Ok(parsed) => Some(parsed.secret.secret_value),
                Err(err) => {
                    warn!(error = %err, secret = name, "Infisical secret response did not parse");
                    None
                }
            },
            Ok(resp) => {
                warn!(status = %resp.status(), secret = name, "Infisical secret read returned non-success");
                None
            }
            Err(err) => {
                warn!(error = %err, secret = name, "Infisical secret read request failed");
                None
            }
        }
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
