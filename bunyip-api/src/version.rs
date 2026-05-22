//! Build version reporting and operator-facing update checking.
//!
//! `/version` lets a self-hosting operator see (a) what version this
//! instance is running and (b) whether a newer release is published.
//! Applying an update is always a deliberate operator action (pull the
//! new image, recreate the containers); this module only *reports*.

use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::Serialize;

/// How long a successful (or failed) upstream check is cached before the
/// next `/version` request triggers a fresh poll. Keeps the registry /
/// release API from being hit on every page load.
const CACHE_TTL: Duration = Duration::from_secs(60 * 60);

/// Per-request HTTP timeout for the upstream release lookup.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The version compiled into this binary (workspace `Cargo.toml`).
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Git revision baked in at image build time via the `BUNYIP_GIT_SHA`
/// env (set from the `GIT_SHA` build arg in the OCI Dockerfile). Empty
/// for local `cargo run` builds.
pub fn git_revision() -> String {
    std::env::var("BUNYIP_GIT_SHA").unwrap_or_default()
}

/// Operator-facing update status, serialized under `/version`'s `update`
/// key.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateStatus {
    /// `false` when no `BUNYIP_UPDATE_CHECK_URL` is configured.
    pub enabled: bool,
    /// Version this instance is running.
    pub current: String,
    /// Latest published version, when a check has succeeded.
    pub latest: Option<String>,
    /// `Some(true)` when `latest` is strictly newer than `current`.
    /// `None` when checking is disabled or the last check failed.
    pub update_available: Option<bool>,
    /// RFC 3339 timestamp of the last completed check attempt.
    pub checked_at: Option<String>,
    /// Human-readable reason the last check failed, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl UpdateStatus {
    fn disabled(current: String) -> Self {
        Self {
            enabled: false,
            current,
            latest: None,
            update_available: None,
            checked_at: None,
            error: None,
        }
    }
}

struct Cached {
    status: UpdateStatus,
    fetched: Instant,
}

/// Polls a release endpoint for the latest version and caches the result.
pub struct UpdateChecker {
    url: Option<String>,
    token: Option<String>,
    cache: RwLock<Option<Cached>>,
}

impl UpdateChecker {
    pub fn new(url: Option<String>, token: Option<String>) -> Self {
        Self {
            url,
            token,
            cache: RwLock::new(None),
        }
    }

    /// Return the current update status, serving a cached result when it
    /// is still within `CACHE_TTL`.
    pub async fn status(&self) -> UpdateStatus {
        let current = current_version().to_string();

        let Some(url) = self.url.clone() else {
            return UpdateStatus::disabled(current);
        };

        if let Some(cached) = self.cache.read().as_ref() {
            if cached.fetched.elapsed() < CACHE_TTL {
                return cached.status.clone();
            }
        }

        let status = self.fetch(&url, &current).await;
        *self.cache.write() = Some(Cached {
            status: status.clone(),
            fetched: Instant::now(),
        });
        status
    }

    async fn fetch(&self, url: &str, current: &str) -> UpdateStatus {
        let checked_at = Some(chrono::Utc::now().to_rfc3339());

        let err = |msg: String| UpdateStatus {
            enabled: true,
            current: current.to_string(),
            latest: None,
            update_available: None,
            checked_at: checked_at.clone(),
            error: Some(msg),
        };

        let client = match reqwest::Client::builder().timeout(FETCH_TIMEOUT).build() {
            Ok(c) => c,
            Err(e) => return err(format!("http client init failed: {e}")),
        };

        let mut req = client.get(url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let body = match req.send().await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(b) => b,
                Err(e) => return err(format!("reading response body: {e}")),
            },
            Ok(resp) => return err(format!("upstream returned HTTP {}", resp.status())),
            Err(e) => return err(format!("request failed: {e}")),
        };

        let latest = match parse_latest_tag(&body) {
            Some(tag) => tag,
            None => return err("no `tag_name` in upstream response".to_string()),
        };

        UpdateStatus {
            enabled: true,
            current: current.to_string(),
            update_available: Some(is_newer(&latest, current)),
            latest: Some(latest),
            checked_at,
            error: None,
        }
    }
}

/// Pull `tag_name` out of a Forgejo / Gitea `releases/latest` JSON body.
fn parse_latest_tag(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value
        .get("tag_name")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Parse a `vMAJOR.MINOR.PATCH` (or bare `MAJOR.MINOR.PATCH`) tag,
/// ignoring any pre-release / build suffix.
fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let core = s
        .trim()
        .trim_start_matches('v')
        .split(['-', '+'])
        .next()
        .unwrap_or("");
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// `true` when `latest` is a strictly higher semver than `current`.
/// Unparseable versions are treated as "no update" rather than erroring.
fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_semver(latest), parse_semver(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_parsing() {
        assert_eq!(parse_semver("v0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_semver("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_semver("v2.0.0-rc1"), Some((2, 0, 0)));
        assert_eq!(parse_semver("v1.4"), Some((1, 4, 0)));
        assert_eq!(parse_semver("nightly"), None);
    }

    #[test]
    fn newer_detection() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("v1.0.0", "0.9.9"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("v0.1.0", "0.2.0"));
        // Unparseable upstream tag is treated as "no update".
        assert!(!is_newer("garbage", "0.1.0"));
    }

    #[test]
    fn extracts_tag_name() {
        let body = r#"{"tag_name":"v0.3.0","name":"Release 0.3.0"}"#;
        assert_eq!(parse_latest_tag(body), Some("v0.3.0".to_string()));
        assert_eq!(parse_latest_tag("{}"), None);
        assert_eq!(parse_latest_tag("not json"), None);
    }
}
