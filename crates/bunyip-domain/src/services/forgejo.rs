//! Forgejo API client for fetching release metadata and streaming assets.

use bytes::Bytes;
use futures_util::Stream;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;

use crate::models::download::{ReleaseAsset, ReleaseMetadata};

#[derive(Debug, Error)]
pub enum ForgejoError {
    #[error("forgejo http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("forgejo not found")]
    NotFound,
    #[error("forgejo upstream error: status {0}")]
    Upstream(u16),
    #[error("forgejo invalid asset url")]
    InvalidUrl,
}

#[derive(Debug, Deserialize)]
struct RawAsset {
    id: i64,
    name: String,
    size: i64,
    #[serde(default)]
    #[serde(rename = "browser_download_url")]
    browser_download_url: String,
}

#[derive(Debug, Deserialize)]
struct RawRelease {
    tag_name: String,
    #[serde(default)]
    assets: Vec<RawAsset>,
}

#[derive(Clone)]
pub struct ForgejoClient {
    http: Client,
    base_url: String,
    token: String,
}

impl ForgejoClient {
    pub fn new(base_url: String, token: String) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("reqwest client builds");
        Self {
            http,
            base_url,
            token,
        }
    }

    /// Fetch release metadata for `owner/repo/tag`.
    pub async fn get_release(
        &self,
        owner: &str,
        repo: &str,
        tag: &str,
    ) -> Result<ReleaseMetadata, ForgejoError> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/releases/tags/{}",
            self.base_url.trim_end_matches('/'),
            urlencoding::encode(owner),
            urlencoding::encode(repo),
            urlencoding::encode(tag),
        );
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("token {}", self.token))
            .header("Accept", "application/json")
            .send()
            .await?;
        match resp.status().as_u16() {
            200 => {
                let raw: RawRelease = resp.json().await?;
                let assets = raw
                    .assets
                    .into_iter()
                    .map(|a| ReleaseAsset {
                        asset_id: a.id,
                        content_type: guess_content_type(&a.name),
                        name: a.name,
                        size: a.size,
                        browser_download_url: a.browser_download_url,
                    })
                    .collect();
                Ok(ReleaseMetadata {
                    tag_name: raw.tag_name,
                    assets,
                })
            }
            404 => Err(ForgejoError::NotFound),
            s => Err(ForgejoError::Upstream(s)),
        }
    }

    /// Stream the bytes of an asset given its browser_download_url.
    ///
    /// The URL's host + port must match `base_url`'s to avoid forwarding the
    /// API token to an arbitrary third-party host (a compromised or misbehaving
    /// Forgejo instance could return an attacker-controlled download URL).
    pub async fn download_asset(
        &self,
        browser_download_url: &str,
    ) -> Result<impl Stream<Item = Result<Bytes, reqwest::Error>>, ForgejoError> {
        let base = url::Url::parse(&self.base_url).map_err(|_| ForgejoError::InvalidUrl)?;
        let target = url::Url::parse(browser_download_url).map_err(|_| ForgejoError::InvalidUrl)?;
        if target.host_str() != base.host_str()
            || target.port_or_known_default() != base.port_or_known_default()
            || target.scheme() != base.scheme()
        {
            tracing::warn!(
                target = %browser_download_url,
                base = %self.base_url,
                "forgejo asset URL host mismatch; refusing to forward auth token"
            );
            return Err(ForgejoError::InvalidUrl);
        }

        let resp = self
            .http
            .get(browser_download_url)
            .header("Authorization", format!("token {}", self.token))
            .send()
            .await?;
        match resp.status().as_u16() {
            200 => Ok(resp.bytes_stream()),
            404 => Err(ForgejoError::NotFound),
            s => Err(ForgejoError::Upstream(s)),
        }
    }
}

fn guess_content_type(filename: &str) -> String {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        "application/gzip".into()
    } else if lower.ends_with(".zip") {
        "application/zip".into()
    } else if lower.ends_with(".tar") {
        "application/x-tar".into()
    } else if lower.ends_with(".exe") {
        "application/vnd.microsoft.portable-executable".into()
    } else if lower.ends_with(".json") {
        "application/json".into()
    } else {
        "application/octet-stream".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn guess_content_type_maps_common_extensions() {
        assert_eq!(guess_content_type("rus.tar.gz"), "application/gzip");
        assert_eq!(guess_content_type("rus.zip"), "application/zip");
        assert_eq!(guess_content_type("rus.tar"), "application/x-tar");
        assert_eq!(
            guess_content_type("rus.exe"),
            "application/vnd.microsoft.portable-executable"
        );
        assert_eq!(guess_content_type("rus"), "application/octet-stream");
    }

    #[actix_rt::test]
    async fn get_release_parses_metadata() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/repos/a8n/rus/releases/tags/v1.0.0"))
            .and(header("Authorization", "token tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tag_name": "v1.0.0",
                "assets": [
                    {
                        "id": 42,
                        "name": "rus-linux-x86_64.tar.gz",
                        "size": 1024,
                        "browser_download_url": format!("{}/download/42", server.uri()),
                    }
                ]
            })))
            .mount(&server)
            .await;

        let client = ForgejoClient::new(server.uri(), "tok".into());
        let release = client.get_release("a8n", "rus", "v1.0.0").await.unwrap();
        assert_eq!(release.tag_name, "v1.0.0");
        assert_eq!(release.assets.len(), 1);
        assert_eq!(release.assets[0].name, "rus-linux-x86_64.tar.gz");
        assert_eq!(release.assets[0].content_type, "application/gzip");
    }

    #[actix_rt::test]
    async fn get_release_returns_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = ForgejoClient::new(server.uri(), "tok".into());
        let err = client.get_release("a8n", "rus", "nope").await.unwrap_err();
        assert!(matches!(err, ForgejoError::NotFound));
    }
}
