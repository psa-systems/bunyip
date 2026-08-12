//! Short-TTL cache for the public `/v1/pricing` payload (BUNYIP-518).
//!
//! `public_ctx` needs the pricing payload on EVERY public page render, to decide
//! whether the nav and footer links to `/pricing` are shown. Fetching it upstream
//! every render turned normal browsing into a burst of `/v1/pricing` calls, which
//! (before that endpoint was exempted from the per-IP rate-limit floor) tripped a
//! 429 that was swallowed into an unpublished payload: `/pricing` 404'd and its
//! links vanished with the switch on and every tier resolving.
//!
//! This cache coalesces those per-render fetches into at most one upstream call
//! per TTL. On a fetch error it serves the last payload it did read rather than
//! flipping the page to unpublished for a transient failure (a 429 must not
//! silently unpublish); it only falls back to the unpublished default when it has
//! never read a payload. The stale value it serves is real data the endpoint
//! returned, and it drives BOTH the link visibility and the `/pricing` page body
//! from the same source, so the two stay consistent (the page renders the cached
//! tiers rather than offering a link to a 404).

use std::future::Future;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::api::types::PricingResponse;
use crate::api::ApiError;

/// Default freshness window for the cached pricing payload. Short, so an admin
/// change surfaces quickly; the upstream `PricingCache` adds its own bound.
pub const PRICING_CACHE_TTL_SECS: u64 = 30;

/// What the cache decided to serve, so callers/tests can assert the fetch was
/// coalesced or a failure fell back correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PricingSource {
    /// A fresh cached payload; no upstream call was made.
    CacheHit,
    /// A fresh upstream fetch that succeeded and was stored.
    Fetched,
    /// A fetch failed; the last payload the cache read was served instead.
    StaleOnError,
    /// A fetch failed and the cache had nothing, so the unpublished default was
    /// served.
    DefaultOnError,
}

pub struct PricingCache {
    ttl: Duration,
    slot: RwLock<Option<(Instant, PricingResponse)>>,
}

impl PricingCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            slot: RwLock::new(None),
        }
    }

    /// The cached payload if still fresh, otherwise the result of `fetch`.
    ///
    /// The read lock is never held across the await. A fetch error is logged
    /// (with the HTTP status and the target type, BUNYIP-518) and never silently
    /// becomes an unpublished payload: the last-read payload is served if there
    /// is one, else the default.
    pub async fn get_or_fetch<F, Fut>(&self, fetch: F) -> PricingResponse
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<PricingResponse, ApiError>>,
    {
        let (payload, _) = self.get_or_fetch_traced(fetch).await;
        payload
    }

    /// [`Self::get_or_fetch`] plus the [`PricingSource`], for tests.
    pub async fn get_or_fetch_traced<F, Fut>(&self, fetch: F) -> (PricingResponse, PricingSource)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<PricingResponse, ApiError>>,
    {
        if let Some((at, hit)) = self.slot.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if at.elapsed() < self.ttl {
                return (hit.clone(), PricingSource::CacheHit);
            }
        }
        match fetch().await {
            Ok(fresh) => {
                *self.slot.write().unwrap_or_else(|e| e.into_inner()) =
                    Some((Instant::now(), fresh.clone()));
                (fresh, PricingSource::Fetched)
            }
            Err(e) => {
                let stale = self
                    .slot
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|(_, v)| v.clone());
                let source = if stale.is_some() {
                    PricingSource::StaleOnError
                } else {
                    PricingSource::DefaultOnError
                };
                tracing::error!(
                    endpoint = "/v1/pricing",
                    target = "PricingResponse",
                    status = e.status,
                    code = %e.code,
                    error = %e.message,
                    request_id = ?e.request_id,
                    served = ?source,
                    "public pricing fetch failed; a transient failure must not unpublish /pricing"
                );
                (stale.unwrap_or_default(), source)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn published() -> PricingResponse {
        PricingResponse {
            enabled: true,
            trial_days: 30,
            tiers: vec![crate::api::types::PricingTier {
                tier: Default::default(),
                amount: 900,
                currency: "usd".into(),
                interval: Some("month".into()),
                trial_days: 30,
            }],
        }
    }

    fn rate_limited() -> ApiError {
        ApiError {
            status: 429,
            code: "RATE_LIMITED".into(),
            message: "Too Many Requests".into(),
            retry_after: Some(30),
            request_id: Some("req_test_1".into()),
        }
    }

    /// The amplification fix: several renders inside the TTL make ONE upstream
    /// call, so the render that used to trip the floor never fetches at all.
    #[tokio::test]
    async fn renders_within_ttl_coalesce_to_one_fetch() {
        let cache = PricingCache::new(Duration::from_secs(60));
        let calls = AtomicUsize::new(0);
        let fetch = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(published())
        };

        let (first, s1) = cache.get_or_fetch_traced(fetch).await;
        let (second, s2) = cache.get_or_fetch_traced(fetch).await;

        assert!(first.published() && second.published());
        assert_eq!(s1, PricingSource::Fetched);
        assert_eq!(s2, PricingSource::CacheHit, "second render must not fetch");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one upstream call");
    }

    /// BUNYIP-518 AC: a 429 must not silently unpublish the page. With a payload
    /// already read, an expired-then-429 render serves the last good (published)
    /// payload, not the unpublished default.
    #[tokio::test]
    async fn a_429_does_not_unpublish_a_previously_published_page() {
        // Zero TTL so the second call is always a miss and re-fetches.
        let cache = PricingCache::new(Duration::from_secs(0));
        let (_, s1) = cache
            .get_or_fetch_traced(|| async { Ok(published()) })
            .await;
        assert_eq!(s1, PricingSource::Fetched);

        let (payload, s2) = cache
            .get_or_fetch_traced(|| async { Err(rate_limited()) })
            .await;
        assert_eq!(s2, PricingSource::StaleOnError);
        assert!(
            payload.published(),
            "a transient 429 must keep the last published payload, not unpublish"
        );
    }

    /// With nothing ever cached, a failed fetch falls back to the unpublished
    /// default (there is no honest payload to show), still logged, never panicking.
    #[tokio::test]
    async fn a_cold_failure_falls_back_to_unpublished() {
        let cache = PricingCache::new(Duration::from_secs(30));
        let (payload, source) = cache
            .get_or_fetch_traced(|| async { Err(rate_limited()) })
            .await;
        assert_eq!(source, PricingSource::DefaultOnError);
        assert!(!payload.published());
    }
}
