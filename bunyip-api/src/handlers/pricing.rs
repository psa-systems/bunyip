//! Public pricing endpoint (BUNYIP-487).
//!
//! `GET /v1/pricing` is the single source the marketing site reads: the admin
//! Pricing tiers page owns the switch and the tier -> Stripe price mapping, and
//! the advertised amount is resolved from that mapped price, so it cannot
//! disagree with what Stripe actually charges.
//!
//! Unauthenticated, and therefore cached: without the cache a public page would
//! turn one visitor into one Stripe API call. The cache is TTL-bounded and
//! explicitly invalidated whenever an admin saves tier config, so a price-id
//! change shows up immediately rather than after the TTL.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use actix_web::{web, HttpResponse};
use serde::Serialize;

use crate::config::TierConfig;
use crate::errors::AppError;
use crate::services::StripeService;

/// How long a resolved pricing payload stays fresh. Short enough that a Stripe
/// dashboard edit surfaces on its own, long enough that a public page cannot
/// drive Stripe traffic; admin-side edits do not wait for it (see
/// [`PricingCache::invalidate`]).
pub const PRICING_CACHE_TTL_SECS: u64 = 60;

/// One publicly advertised tier.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PublicPricingTier {
    /// The `MembershipTier` key (snake_case). The display name stays with the
    /// consumer so the marketing card and the in-app labels keep coming from
    /// one place rather than two.
    pub tier: &'static str,
    /// Smallest currency unit (cents), straight off the mapped Stripe price.
    pub amount: i64,
    pub currency: String,
    pub interval: Option<String>,
    pub trial_days: i64,
}

/// `GET /v1/pricing` body.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PublicPricingResponse {
    /// The admin switch. `false` means `/pricing` must 404 and every link to it
    /// must be hidden.
    pub enabled: bool,
    /// Standard-tier trial length. Top-level as well as per-tier because the
    /// homepage CTA advertises the trial even when pricing is unpublished and
    /// `tiers` is therefore empty.
    pub trial_days: i64,
    /// Only tiers that resolve to a usable Stripe price. Empty means there is
    /// nothing honest to publish, which is also a 404.
    pub tiers: Vec<PublicPricingTier>,
}

impl PublicPricingResponse {
    /// Nothing to show: either the switch is off or no tier resolved.
    fn unpublished(trial_days: i64) -> Self {
        Self {
            enabled: false,
            trial_days,
            tiers: Vec::new(),
        }
    }
}

/// Single-slot TTL cache for the resolved pricing payload.
pub struct PricingCache {
    ttl: Duration,
    slot: RwLock<Option<(Instant, Arc<PublicPricingResponse>)>>,
    /// Number of times the payload was actually resolved (i.e. Stripe was
    /// consulted). Read by `/v1/pricing`'s test and available for ops probes;
    /// it is what makes "N page loads is not N Stripe calls" observable.
    resolves: AtomicU64,
}

impl PricingCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl: Duration::from_secs(ttl_secs),
            slot: RwLock::new(None),
            resolves: AtomicU64::new(0),
        }
    }

    /// Cached payload, or `load()` on miss / expiry.
    ///
    /// The lock is never held across the await: a rare concurrent double-load
    /// is cheaper than serializing every public request behind one Stripe call.
    pub async fn get_or_resolve<F, Fut>(&self, load: F) -> Arc<PublicPricingResponse>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = PublicPricingResponse>,
    {
        if let Some((at, hit)) = self.slot.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            if at.elapsed() < self.ttl {
                return hit.clone();
            }
        }
        self.resolves.fetch_add(1, Ordering::Relaxed);
        let fresh = Arc::new(load().await);
        *self.slot.write().unwrap_or_else(|e| e.into_inner()) =
            Some((Instant::now(), fresh.clone()));
        fresh
    }

    /// Drop the cached payload so the next read re-resolves. Called whenever an
    /// admin saves tier config, so a price-id or switch change is live at once.
    pub fn invalidate(&self) {
        *self.slot.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// How many times the payload was resolved from Stripe.
    pub fn resolves(&self) -> u64 {
        self.resolves.load(Ordering::Relaxed)
    }
}

/// Resolve the advertised pricing from tier config plus the mapped Stripe price.
///
/// A Stripe failure degrades to "unpublished" rather than a 500: the marketing
/// page has nothing trustworthy to print, and a 404 is the honest answer.
async fn resolve(cfg: TierConfig, stripe: Arc<StripeService>) -> PublicPricingResponse {
    let trial_days = cfg.standard_trial_days;
    if !cfg.pricing_enabled {
        return PublicPricingResponse::unpublished(trial_days);
    }
    let Some(price_id) = cfg.standard_price_id.clone() else {
        return PublicPricingResponse::unpublished(trial_days);
    };
    if !stripe.is_configured() {
        return PublicPricingResponse::unpublished(trial_days);
    }

    let prices = match stripe.list_prices(None).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "Could not resolve the advertised price from Stripe");
            return PublicPricingResponse::unpublished(trial_days);
        }
    };

    let tiers = prices
        .into_iter()
        .find(|p| p.id == price_id && p.active)
        .and_then(|p| {
            p.unit_amount.map(|amount| PublicPricingTier {
                tier: "standard",
                amount,
                currency: p.currency,
                interval: p.recurring_interval,
                trial_days,
            })
        })
        .into_iter()
        .collect::<Vec<_>>();

    PublicPricingResponse {
        // An enabled switch with no resolvable price is still nothing to show.
        enabled: !tiers.is_empty(),
        trial_days,
        tiers,
    }
}

/// `GET /v1/pricing` - public, unauthenticated, under the rate-limit floor.
pub async fn public_pricing(
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    stripe: web::Data<Arc<StripeService>>,
    cache: web::Data<Arc<PricingCache>>,
) -> Result<HttpResponse, AppError> {
    let cfg = tier_config
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let stripe = stripe.get_ref().clone();
    let body = cache.get_or_resolve(|| resolve(cfg, stripe)).await;
    Ok(HttpResponse::Ok().json(body.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(enabled: bool) -> PublicPricingResponse {
        PublicPricingResponse {
            enabled,
            trial_days: 30,
            tiers: vec![],
        }
    }

    #[actix_rt::test]
    async fn repeat_reads_resolve_once() {
        // BUNYIP-487: the acceptance criterion is that N public page loads do
        // not become N Stripe lookups.
        let cache = PricingCache::new(PRICING_CACHE_TTL_SECS);
        for _ in 0..5 {
            let got = cache.get_or_resolve(|| async { payload(true) }).await;
            assert!(got.enabled);
        }
        assert_eq!(cache.resolves(), 1, "only the first read consults Stripe");
    }

    #[actix_rt::test]
    async fn invalidate_forces_a_fresh_resolve() {
        // An admin saving tier config must not have to wait out the TTL.
        let cache = PricingCache::new(PRICING_CACHE_TTL_SECS);
        assert!(
            cache
                .get_or_resolve(|| async { payload(true) })
                .await
                .enabled
        );
        cache.invalidate();
        assert!(
            !cache
                .get_or_resolve(|| async { payload(false) })
                .await
                .enabled
        );
        assert_eq!(cache.resolves(), 2);
    }

    #[actix_rt::test]
    async fn expired_entries_resolve_again() {
        let cache = PricingCache::new(0);
        cache.get_or_resolve(|| async { payload(true) }).await;
        cache.get_or_resolve(|| async { payload(true) }).await;
        assert_eq!(cache.resolves(), 2);
    }

    #[actix_rt::test]
    async fn pricing_switch_off_publishes_nothing() {
        let mut cfg = TierConfig::from_env();
        cfg.standard_price_id = Some("price_123".into());
        cfg.pricing_enabled = false;
        let stripe = Arc::new(StripeService::new(
            crate::services::unconfigured_stripe_config(),
        ));
        let out = resolve(cfg, stripe).await;
        assert!(!out.enabled);
        assert!(out.tiers.is_empty());
        assert_eq!(out.trial_days, 30, "trial length is still reported");
    }

    #[actix_rt::test]
    async fn enabled_without_a_mapped_price_publishes_nothing() {
        let mut cfg = TierConfig::from_env();
        cfg.pricing_enabled = true;
        cfg.standard_price_id = None;
        let stripe = Arc::new(StripeService::new(
            crate::services::unconfigured_stripe_config(),
        ));
        let out = resolve(cfg, stripe).await;
        assert!(!out.enabled, "no mapped price is nothing to advertise");
        assert!(out.tiers.is_empty());
    }
}
