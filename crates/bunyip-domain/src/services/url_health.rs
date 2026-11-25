//! URL health worker (BUNYIP-1089): a background tokio task that periodically
//! probes every hosted application's `health_check_url`, writes one row per
//! probe to `application_url_checks`, and evicts rows older than the retention
//! window at the end of each pass.
//!
//! The worker never fetches a private, loopback, link-local or ULA address:
//! [`crate::services::outbound::screen_url`] resolves the host up front and
//! refuses when any resolved IP falls in those ranges.
//!
//! Gated on the `url_health_enabled` feature toggle (BUNYIP-493 registry).
//! Flag off keeps the worker a no-op and writes no rows; the migration and
//! the admin Last-check column are present either way.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use reqwest::Client;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::feature_toggles::{Feature, FeatureToggleSnapshot};
use crate::models::application_url_check::{
    CreateApplicationUrlCheck, CHECK_STATUS_HTTP_ERROR, CHECK_STATUS_NETWORK_ERROR,
    CHECK_STATUS_OK, CHECK_STATUS_SCREEN_REFUSED, CHECK_STATUS_TIMEOUT,
};
use crate::repositories::ApplicationUrlCheckRepository;
use crate::services::outbound::{screen_url, ScreenRefusal};

/// Default poll interval: 5 minutes. Bounded [60, 3600].
pub const DEFAULT_CHECK_INTERVAL_SECS: u64 = 300;
pub const MIN_CHECK_INTERVAL_SECS: u64 = 60;
pub const MAX_CHECK_INTERVAL_SECS: u64 = 3600;
/// How long the HTTP probe waits before giving up and writing `timeout`.
pub const PROBE_TIMEOUT_SECS: u64 = 5;
/// Retention window for `application_url_checks` rows. v1 is hard-coded.
pub const RETENTION_DAYS: i64 = 7;

/// One application row the worker iterates. Narrow shape so a test can build
/// it without reaching for every column of the production `Application` struct.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub id: Uuid,
    pub health_check_url: String,
}

/// Policy parameters the worker reads at the start of each pass. Resolved
/// fresh so an admin flip of the toggle or an interval bump takes effect on
/// the next pass without a restart.
#[derive(Debug, Clone, Copy)]
pub struct WorkerPolicy {
    pub interval: Duration,
    pub retention: chrono::Duration,
}

impl Default for WorkerPolicy {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(DEFAULT_CHECK_INTERVAL_SECS),
            retention: chrono::Duration::days(RETENTION_DAYS),
        }
    }
}

/// Clamp a configured interval into [`MIN_CHECK_INTERVAL_SECS`,
/// `MAX_CHECK_INTERVAL_SECS`]. Pure; tested below.
pub fn clamp_interval(secs: u64) -> u64 {
    secs.clamp(MIN_CHECK_INTERVAL_SECS, MAX_CHECK_INTERVAL_SECS)
}

/// Spawn the worker. Owns no state of its own; the ticker fires on
/// `policy.interval`, each pass reads the live flag from `toggles` and the
/// target list from the pool, and all probes share one reqwest client.
pub fn spawn(pool: PgPool, toggles: FeatureToggleSnapshot, policy: WorkerPolicy) {
    tokio::spawn(async move {
        let client = match Client::builder()
            .timeout(Duration::from_secs(PROBE_TIMEOUT_SECS))
            // Follow redirects but cap the depth so a redirect loop fails fast.
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "UrlHealthWorker could not build reqwest client; exiting");
                return;
            }
        };
        let mut ticker = tokio::time::interval(policy.interval);
        // First tick fires immediately; skip it so a fast-cycling test restart
        // never doubles the write rate against the floor.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if !feature_enabled(&toggles) {
                continue;
            }
            match run_pass(&pool, &client, policy.retention).await {
                Ok(count) => {
                    tracing::debug!(probed = count, "UrlHealthWorker pass complete");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "UrlHealthWorker pass failed");
                }
            }
        }
    });
}

fn feature_enabled(toggles: &FeatureToggleSnapshot) -> bool {
    match toggles.read() {
        Ok(guard) => guard.enabled(Feature::UrlHealth),
        Err(poison) => poison.into_inner().enabled(Feature::UrlHealth),
    }
}

/// One pass: fetch targets, probe each, evict older than the retention window.
async fn run_pass(
    pool: &PgPool,
    client: &Client,
    retention: chrono::Duration,
) -> Result<usize, AppError> {
    let targets = list_targets(pool).await?;
    let mut count = 0usize;
    for target in &targets {
        if let Err(e) = probe_one(pool, client, target).await {
            tracing::warn!(
                application_id = %target.id,
                error = %e,
                "UrlHealthWorker: could not write probe row"
            );
        } else {
            count += 1;
        }
    }
    let cutoff = Utc::now() - retention;
    let evicted = ApplicationUrlCheckRepository::evict_before(pool, cutoff).await?;
    if evicted > 0 {
        tracing::debug!(evicted, "UrlHealthWorker evicted expired rows");
    }
    Ok(count)
}

async fn list_targets(pool: &PgPool) -> Result<Vec<ProbeTarget>, AppError> {
    let rows = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, health_check_url FROM applications \
         WHERE is_active AND is_hosted AND health_check_url IS NOT NULL AND health_check_url <> ''",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, health_check_url)| ProbeTarget {
            id,
            health_check_url,
        })
        .collect())
}

async fn probe_one(pool: &PgPool, client: &Client, target: &ProbeTarget) -> Result<(), AppError> {
    let screened = match screen_url(&target.health_check_url).await {
        Ok(s) => s,
        Err(refusal) => {
            return write_outcome(
                pool,
                target.id,
                CHECK_STATUS_SCREEN_REFUSED,
                None,
                None,
                Some(refusal_detail(&refusal)),
            )
            .await;
        }
    };
    tracing::trace!(
        application_id = %target.id,
        url = %screened.url,
        resolved = ?screened.resolved,
        "UrlHealthWorker probing"
    );
    let start = Instant::now();
    let result = client.get(screened.url.clone()).send().await;
    let latency_ms = start.elapsed().as_millis().try_into().ok();
    match result {
        Ok(resp) if resp.status().is_success() => {
            write_outcome(
                pool,
                target.id,
                CHECK_STATUS_OK,
                Some(resp.status().as_u16() as i16),
                latency_ms,
                None,
            )
            .await
        }
        Ok(resp) => {
            write_outcome(
                pool,
                target.id,
                CHECK_STATUS_HTTP_ERROR,
                Some(resp.status().as_u16() as i16),
                latency_ms,
                Some(format!("http status {}", resp.status())),
            )
            .await
        }
        Err(e) if e.is_timeout() => {
            write_outcome(
                pool,
                target.id,
                CHECK_STATUS_TIMEOUT,
                None,
                latency_ms,
                Some(format!("probe timed out after {PROBE_TIMEOUT_SECS}s")),
            )
            .await
        }
        Err(e) => {
            write_outcome(
                pool,
                target.id,
                CHECK_STATUS_NETWORK_ERROR,
                None,
                latency_ms,
                Some(e.to_string()),
            )
            .await
        }
    }
}

async fn write_outcome(
    pool: &PgPool,
    application_id: Uuid,
    status: &'static str,
    http_status: Option<i16>,
    latency_ms: Option<i32>,
    error_detail: Option<String>,
) -> Result<(), AppError> {
    ApplicationUrlCheckRepository::create(
        pool,
        &CreateApplicationUrlCheck {
            application_id,
            status,
            http_status,
            latency_ms,
            error_detail,
        },
    )
    .await?;
    Ok(())
}

fn refusal_detail(r: &ScreenRefusal) -> String {
    r.to_string()
}

// The `Arc<...>` parameter is here only so a future Shutdown handle can be
// plumbed in without a signature break; the current worker loops until process
// exit, matching every other long-running background task in this repo.
#[allow(dead_code)]
fn _noop_shutdown_handle() -> Arc<()> {
    Arc::new(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_pulls_a_too_small_interval_up() {
        assert_eq!(clamp_interval(0), MIN_CHECK_INTERVAL_SECS);
        assert_eq!(clamp_interval(10), MIN_CHECK_INTERVAL_SECS);
    }

    #[test]
    fn clamp_pulls_a_too_large_interval_down() {
        assert_eq!(clamp_interval(10_000), MAX_CHECK_INTERVAL_SECS);
    }

    #[test]
    fn clamp_passes_a_valid_value_through() {
        assert_eq!(clamp_interval(300), 300);
    }

    #[test]
    fn retention_is_seven_days_by_default() {
        let policy = WorkerPolicy::default();
        assert_eq!(policy.retention, chrono::Duration::days(7));
    }

    #[test]
    fn refusal_detail_strings_cover_each_variant() {
        use std::net::{IpAddr, Ipv4Addr};
        for r in [
            ScreenRefusal::Unparseable("x".into()),
            ScreenRefusal::Scheme {
                scheme: "ftp".into(),
            },
            ScreenRefusal::NoHost,
            ScreenRefusal::NoAddresses {
                host: "example".into(),
            },
            ScreenRefusal::ReservedAddress {
                host: "example".into(),
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            },
            ScreenRefusal::LookupTimeout {
                host: "example".into(),
            },
            ScreenRefusal::LookupError {
                host: "example".into(),
                error: "nxdomain".into(),
            },
        ] {
            let s = refusal_detail(&r);
            assert!(!s.is_empty(), "every refusal variant has a message: {r:?}");
        }
    }
}
