//! Short-TTL cache for the near-static payloads the BFF re-fetches on EVERY
//! render (BUNYIP-518 for `/v1/pricing`, BUNYIP-555 for `/v1/applications` and
//! `/v1/auth/setup/status`).
//!
//! Each of those payloads is chrome, not page content: the pricing payload
//! decides whether the nav and footer links to `/pricing` are shown, the
//! application list fills the public footer, and the setup-status flags decide
//! whether the subscribe CTA is live. Fetching them upstream on every render
//! turned normal browsing into a burst of identical calls, which (before those
//! endpoints were cached) tripped the per-IP rate-limit floor and swallowed the
//! 429 into a thinner page: `/pricing` 404'd with the switch on and every tier
//! resolving, and the footer lost its application links.
//!
//! This cache coalesces those per-render fetches into at most one upstream call
//! per TTL. On a fetch error it serves the last value it did read rather than
//! flipping the page for a transient failure (a 429 must not silently unpublish
//! `/pricing` or empty the launcher); it returns `None` only when it has never
//! read a value, and the caller then applies its own documented fallback (which
//! is NOT the same for every payload: an unreadable setup status means "assume
//! payment IS configured", so a working Stripe account is never hidden behind a
//! disabled button).

use std::future::Future;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::api::ApiError;

/// Freshness window for the cached pricing payload. Short, so an admin change
/// surfaces quickly; the upstream API adds its own bound.
pub const PRICING_CACHE_TTL_SECS: u64 = 30;

/// Freshness window for the public chrome's application list. Same as pricing:
/// both ride on every public render and change only when an admin edits the
/// catalog.
pub const APPLICATIONS_CACHE_TTL_SECS: u64 = 30;

/// Freshness window for the setup-status flags. Longer, because they change
/// only when an admin configures SMTP or Stripe, and bunyip-api hot-reloads
/// both (`StripeService::reload`), so the change still lands with no restart.
pub const SETUP_STATUS_CACHE_TTL_SECS: u64 = 60;

/// What the cache decided to serve, so callers/tests can assert the fetch was
/// coalesced or a failure fell back correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSource {
    /// A fresh cached value; no upstream call was made.
    CacheHit,
    /// A fresh upstream fetch that succeeded and was stored.
    Fetched,
    /// A fetch failed; the last value the cache read was served instead.
    StaleOnError,
    /// A fetch failed and the cache had nothing, so the caller gets `None` and
    /// applies its own fallback.
    NoValueOnError,
}

pub struct TtlCache<T> {
    ttl: Duration,
    /// The upstream path, named in the failure log so the operator knows which
    /// call went down.
    endpoint: &'static str,
    /// The decoded type, matching the BUNYIP-506 decode-failure log shape.
    target: &'static str,
    /// What the page loses when this fetch fails, so the log says why it matters.
    note: &'static str,
    slot: RwLock<Option<(Instant, T)>>,
}

impl<T: Clone> TtlCache<T> {
    pub fn new(
        endpoint: &'static str,
        target: &'static str,
        note: &'static str,
        ttl: Duration,
    ) -> Self {
        Self {
            ttl,
            endpoint,
            target,
            note,
            slot: RwLock::new(None),
        }
    }

    /// The cached value if still fresh, otherwise the result of `fetch`.
    ///
    /// The read lock is never held across the await. A fetch error is logged
    /// (with the HTTP status and the target type, BUNYIP-506/518) and never
    /// silently becomes an empty payload: the last-read value is served if
    /// there is one, else `None` for the caller to fall back on.
    pub async fn get_or_fetch<F, Fut>(&self, fetch: F) -> Option<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, ApiError>>,
    {
        let (value, _) = self.get_or_fetch_traced(fetch).await;
        value
    }

    /// [`Self::get_or_fetch`] plus the [`CacheSource`], for tests.
    pub async fn get_or_fetch_traced<F, Fut>(&self, fetch: F) -> (Option<T>, CacheSource)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, ApiError>>,
    {
        if let Some((at, hit)) = self.slot.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if at.elapsed() < self.ttl {
                return (Some(hit.clone()), CacheSource::CacheHit);
            }
        }
        match fetch().await {
            Ok(fresh) => {
                *self.slot.write().unwrap_or_else(|e| e.into_inner()) =
                    Some((Instant::now(), fresh.clone()));
                (Some(fresh), CacheSource::Fetched)
            }
            Err(e) => {
                let stale = self
                    .slot
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|(_, v)| v.clone());
                let source = if stale.is_some() {
                    CacheSource::StaleOnError
                } else {
                    CacheSource::NoValueOnError
                };
                tracing::error!(
                    endpoint = self.endpoint,
                    target = self.target,
                    status = e.status,
                    code = %e.code,
                    error = %e.message,
                    request_id = ?e.request_id,
                    served = ?source,
                    note = self.note,
                    "cached BFF fetch failed"
                );
                (stale, source)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{Application, PricingResponse, SetupStatus};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn pricing_cache(ttl_secs: u64) -> TtlCache<PricingResponse> {
        TtlCache::new(
            "/v1/pricing",
            "PricingResponse",
            "the /pricing page and its nav links",
            Duration::from_secs(ttl_secs),
        )
    }

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
                available: true,
                slots_remaining: None,
            }],
        }
    }

    fn app(slug: &str) -> Application {
        Application {
            id: slug.into(),
            slug: slug.into(),
            display_name: slug.into(),
            description: None,
            icon_url: None,
            version: None,
            source_code_url: None,
            release_notes_url: None,
            subdomain: None,
            is_accessible: false,
            maintenance_mode: false,
            maintenance_message: None,
            group_id: None,
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
        let cache = pricing_cache(60);
        let calls = AtomicUsize::new(0);
        let fetch = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(published())
        };

        let (first, s1) = cache.get_or_fetch_traced(fetch).await;
        let (second, s2) = cache.get_or_fetch_traced(fetch).await;

        assert!(first.unwrap_or_default().published() && second.unwrap_or_default().published());
        assert_eq!(s1, CacheSource::Fetched);
        assert_eq!(s2, CacheSource::CacheHit, "second render must not fetch");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one upstream call");
    }

    /// BUNYIP-518 AC: a 429 must not silently unpublish the page. With a payload
    /// already read, an expired-then-429 render serves the last good (published)
    /// payload, not the unpublished default.
    #[tokio::test]
    async fn a_429_does_not_unpublish_a_previously_published_page() {
        // Zero TTL so the second call is always a miss and re-fetches.
        let cache = pricing_cache(0);
        let (_, s1) = cache
            .get_or_fetch_traced(|| async { Ok(published()) })
            .await;
        assert_eq!(s1, CacheSource::Fetched);

        let (payload, s2) = cache
            .get_or_fetch_traced(|| async { Err(rate_limited()) })
            .await;
        assert_eq!(s2, CacheSource::StaleOnError);
        assert!(
            payload.unwrap_or_default().published(),
            "a transient 429 must keep the last published payload, not unpublish"
        );
    }

    /// With nothing ever cached, a failed fetch yields `None` (there is no
    /// honest value to show), still logged, never panicking. The pricing caller
    /// turns that into the unpublished default.
    #[tokio::test]
    async fn a_cold_failure_yields_no_value() {
        let cache = pricing_cache(30);
        let (payload, source) = cache
            .get_or_fetch_traced(|| async { Err(rate_limited()) })
            .await;
        assert_eq!(source, CacheSource::NoValueOnError);
        assert!(payload.is_none());
        assert!(!payload.unwrap_or_default().published());
    }

    /// BUNYIP-555 AC (F3): five consecutive public renders inside the TTL make
    /// ONE upstream `/v1/applications` call.
    #[tokio::test]
    async fn five_public_renders_make_one_applications_fetch() {
        let cache: TtlCache<Vec<Application>> = TtlCache::new(
            "/v1/applications",
            "Vec<Application>",
            "the public footer's application links",
            Duration::from_secs(APPLICATIONS_CACHE_TTL_SECS),
        );
        let calls = AtomicUsize::new(0);
        let fetch = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![app("mokosh")])
        };

        for _ in 0..5 {
            let apps = cache.get_or_fetch(fetch).await.unwrap_or_default();
            assert_eq!(apps.len(), 1, "every render still gets the list");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one upstream call");
    }

    /// BUNYIP-555 AC (F3): five consecutive `/dashboard` renders inside the TTL
    /// make ONE upstream `/v1/auth/setup/status` call.
    #[tokio::test]
    async fn five_dashboard_renders_make_one_setup_status_fetch() {
        let cache: TtlCache<SetupStatus> = TtlCache::new(
            "/v1/auth/setup/status",
            "SetupStatus",
            "the subscribe CTA and the onboarding email gate",
            Duration::from_secs(SETUP_STATUS_CACHE_TTL_SECS),
        );
        let calls = AtomicUsize::new(0);
        let fetch = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(SetupStatus {
                email_enabled: true,
                stripe_enabled: true,
                orgs_enabled: false,
            })
        };

        for _ in 0..5 {
            let status = cache.get_or_fetch(fetch).await;
            assert!(status.is_some_and(|s| s.stripe_enabled));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one upstream call");
    }

    /// BUNYIP-555 AC (F3): a failing fetch serves the last good list. A 429
    /// alone must never render the launcher/footer as "no applications".
    #[tokio::test]
    async fn a_429_never_empties_the_application_list() {
        let cache: TtlCache<Vec<Application>> = TtlCache::new(
            "/v1/applications",
            "Vec<Application>",
            "the public footer's application links",
            // Zero TTL so the next render is always a miss and re-fetches.
            Duration::from_secs(0),
        );
        let (good, s1) = cache
            .get_or_fetch_traced(|| async { Ok(vec![app("mokosh")]) })
            .await;
        assert_eq!(s1, CacheSource::Fetched);
        assert_eq!(good.unwrap_or_default().len(), 1);

        let (served, s2) = cache
            .get_or_fetch_traced(|| async { Err(rate_limited()) })
            .await;
        assert_eq!(s2, CacheSource::StaleOnError);
        assert_eq!(
            served.unwrap_or_default().len(),
            1,
            "a transient 429 must keep the last good list, not empty the footer"
        );
    }
}
