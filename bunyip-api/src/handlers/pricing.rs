//! Public pricing endpoint (BUNYIP-487) plus its admin diagnosis (BUNYIP-515).
//!
//! `GET /v1/pricing` is the single source the marketing site reads: the admin
//! Pricing tiers page owns the switch and the tier -> Stripe price mapping, and
//! the advertised amount is resolved from that mapped price, so it cannot
//! disagree with what Stripe actually charges. EVERY mapped tier is published
//! (lifetime, early adopter, standard), not just the standard one.
//!
//! Unauthenticated, and therefore cached: without the cache a public page would
//! turn one visitor into one Stripe API call. The cache is TTL-bounded and
//! explicitly invalidated by every admin action that can change the answer
//! (tier config, Stripe config, price create / archive), so an admin edit shows
//! up immediately rather than after the TTL.
//!
//! BUNYIP-515: not publishing is never silent. Every branch that produces an
//! empty payload names itself in an [`UnpublishedReason`], which is logged once
//! per resolve and served (admin-only) by `GET /v1/admin/pricing/status`. The
//! public body is unchanged: reasons name price ids and configuration state, so
//! they never reach an anonymous visitor.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Serialize;

use crate::config::TierConfig;
use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::StripePriceResponse;
use crate::responses::{get_request_id, success};
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

/// Why one mapped price did not become a published tier (BUNYIP-515). Each
/// variant is a distinct fix, so they never collapse into one message.
#[derive(Debug, Clone, PartialEq)]
pub enum PriceUnresolved {
    /// The id is not in `list_prices`. That list is filtered to products
    /// carrying the app tag, so a wrong id and a correct id on an untagged
    /// product look identical here; the message names both.
    NotVisible { app_tag: String },
    /// Present but archived in Stripe.
    Archived,
    /// Present and active, but carries no `unit_amount` (e.g. a tiered or
    /// metered price), so there is no single number to advertise.
    NoAmount,
}

/// Why `/pricing` is not publishing (all of it, or one tier). Admin-only: the
/// messages name price ids, the app tag and configuration state.
#[derive(Debug, Clone, PartialEq)]
pub enum UnpublishedReason {
    /// The Enable Pricing switch is off.
    SwitchOff,
    /// The switch is on but no tier has a price id mapped.
    NoTierMapped,
    /// No Stripe secret key is saved, so no price can be read.
    StripeNotConfigured,
    /// The Stripe price listing failed.
    StripeListFailed { detail: String },
    /// One mapped tier did not resolve to a usable price.
    PriceUnresolved {
        tier: &'static str,
        price_id: String,
        detail: PriceUnresolved,
    },
}

impl UnpublishedReason {
    /// Stable machine key, so a caller can branch without parsing prose.
    pub fn code(&self) -> &'static str {
        match self {
            Self::SwitchOff => "switch_off",
            Self::NoTierMapped => "no_tier_mapped",
            Self::StripeNotConfigured => "stripe_not_configured",
            Self::StripeListFailed { .. } => "stripe_list_failed",
            Self::PriceUnresolved { .. } => "price_unresolved",
        }
    }

    /// The admin-facing sentence: what failed, and what to do about it.
    pub fn message(&self) -> String {
        match self {
            Self::SwitchOff => {
                "Enable Pricing is off, so /pricing returns 404 and every link to it is hidden."
                    .to_string()
            }
            Self::NoTierMapped => {
                "No tier has a Stripe price mapped. Map one on the Stripe page (Lifetime, \
                 Early-adopter or Standard price ID)."
                    .to_string()
            }
            Self::StripeNotConfigured => {
                "Stripe is not configured, so no price can be read. Save a secret key on the \
                 Stripe page."
                    .to_string()
            }
            Self::StripeListFailed { detail } => {
                format!("Stripe would not list prices: {detail}")
            }
            Self::PriceUnresolved {
                tier,
                price_id,
                detail,
            } => {
                let label = tier_label(tier);
                match detail {
                    PriceUnresolved::NotVisible { app_tag } => format!(
                        "{label}: {price_id} is not visible under app tag `{app_tag}`. Check the \
                         id, or set that product's app_tag metadata in Stripe."
                    ),
                    PriceUnresolved::Archived => {
                        format!("{label}: {price_id} is archived in Stripe. Map an active price.")
                    }
                    PriceUnresolved::NoAmount => format!(
                        "{label}: {price_id} has no fixed amount, so there is nothing to \
                         advertise. Map a standard recurring price."
                    ),
                }
            }
        }
    }

    /// The tier this reason belongs to, when it is per-tier.
    pub fn tier(&self) -> Option<&'static str> {
        match self {
            Self::PriceUnresolved { tier, .. } => Some(tier),
            _ => None,
        }
    }

    fn price_id(&self) -> Option<String> {
        match self {
            Self::PriceUnresolved { price_id, .. } => Some(price_id.clone()),
            _ => None,
        }
    }

    /// Log this reason exactly once, where it is produced. The deliberate
    /// states (switch off, nothing mapped) are `info`; everything else means
    /// something is misconfigured and logs at `warn`.
    fn log(&self) {
        match self {
            Self::SwitchOff | Self::NoTierMapped => tracing::info!(
                reason = self.code(),
                "/pricing publishes nothing: {}",
                self.message()
            ),
            _ => tracing::warn!(
                reason = self.code(),
                tier = self.tier().unwrap_or("-"),
                price_id = self.price_id().unwrap_or_else(|| "-".into()),
                "/pricing could not publish: {}",
                self.message()
            ),
        }
    }
}

/// One reason, on the wire. Carries the rendered sentence so the admin page
/// (which knows neither the app tag nor the price ids) renders it verbatim.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PricingReasonView {
    pub code: &'static str,
    pub tier: Option<&'static str>,
    pub price_id: Option<String>,
    pub message: String,
}

impl From<&UnpublishedReason> for PricingReasonView {
    fn from(r: &UnpublishedReason) -> Self {
        Self {
            code: r.code(),
            tier: r.tier(),
            price_id: r.price_id(),
            message: r.message(),
        }
    }
}

/// `GET /v1/admin/pricing/status` body.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AdminPricingStatus {
    /// What `/pricing` does right now: `false` means it 404s.
    pub published: bool,
    pub tiers: Vec<PublicPricingTier>,
    pub reasons: Vec<PricingReasonView>,
}

/// Admin-page label for a tier key. Mirrors the Pricing tiers page rows, so a
/// reason names the tier the admin sees rather than the column name.
fn tier_label(tier: &str) -> &'static str {
    match tier {
        "lifetime" => "Lifetime",
        "early_adopter" => "Early Adopter",
        "standard" => "Standard",
        _ => "Tier",
    }
}

/// Match each mapped `(tier, price_id, trial_days)` against the Stripe price
/// list: publishable tiers in mapping order, plus one reason per tier that did
/// not resolve. Pure, so every per-tier outcome is unit-testable without Stripe.
#[allow(clippy::type_complexity)]
fn match_mapped_tiers(
    mapped: &[(&'static str, String, i64)],
    prices: &[StripePriceResponse],
    app_tag: &str,
) -> (Vec<PublicPricingTier>, Vec<UnpublishedReason>) {
    let mut tiers = Vec::new();
    let mut reasons = Vec::new();
    for (tier, price_id, tier_trial_days) in mapped {
        let detail = match prices.iter().find(|p| &p.id == price_id) {
            None => Some(PriceUnresolved::NotVisible {
                app_tag: app_tag.to_string(),
            }),
            Some(p) if !p.active => Some(PriceUnresolved::Archived),
            Some(p) => match p.unit_amount {
                Some(amount) => {
                    tiers.push(PublicPricingTier {
                        tier,
                        amount,
                        currency: p.currency.clone(),
                        interval: p.recurring_interval.clone(),
                        trial_days: *tier_trial_days,
                    });
                    None
                }
                None => Some(PriceUnresolved::NoAmount),
            },
        };
        if let Some(detail) = detail {
            reasons.push(UnpublishedReason::PriceUnresolved {
                tier,
                price_id: price_id.clone(),
                detail,
            });
        }
    }
    (tiers, reasons)
}

/// Resolve the advertised pricing from tier config plus the mapped Stripe
/// prices, alongside the reasons anything is missing.
///
/// A Stripe failure degrades to "unpublished" rather than a 500: the marketing
/// page has nothing trustworthy to print, and a 404 is the honest answer. Every
/// such branch logs once (see [`UnpublishedReason::log`]) and is returned, so
/// the admin page can show what the public page cannot.
async fn resolve(
    cfg: TierConfig,
    stripe: Arc<StripeService>,
) -> (PublicPricingResponse, Vec<UnpublishedReason>) {
    let trial_days = cfg.standard_trial_days;
    let unpublished = |reason: UnpublishedReason| {
        reason.log();
        (PublicPricingResponse::unpublished(trial_days), vec![reason])
    };

    if !cfg.pricing_enabled {
        return unpublished(UnpublishedReason::SwitchOff);
    }

    // Publication order is the tier ladder the admin page lists: Lifetime,
    // Early Adopter, Standard. `free_price_id` is the Lifetime tier's price;
    // the model carries that naming asymmetry and we mirror it rather than
    // re-aliasing. A lifetime membership has no trial, so its trial length is 0.
    let mapped: Vec<(&'static str, String, i64)> = [
        ("lifetime", &cfg.free_price_id, 0),
        (
            "early_adopter",
            &cfg.early_adopter_price_id,
            cfg.early_adopter_trial_days,
        ),
        ("standard", &cfg.standard_price_id, cfg.standard_trial_days),
    ]
    .into_iter()
    .filter_map(|(tier, id, trial)| {
        let id = id.as_deref().map(str::trim).filter(|s| !s.is_empty())?;
        Some((tier, id.to_string(), trial))
    })
    .collect();

    if mapped.is_empty() {
        return unpublished(UnpublishedReason::NoTierMapped);
    }
    if !stripe.is_configured() {
        return unpublished(UnpublishedReason::StripeNotConfigured);
    }

    let prices = match stripe.list_prices(None).await {
        Ok(p) => p,
        Err(e) => {
            return unpublished(UnpublishedReason::StripeListFailed {
                detail: e.to_string(),
            })
        }
    };

    let (tiers, reasons) = match_mapped_tiers(&mapped, &prices, &stripe.app_tag());
    for reason in &reasons {
        reason.log();
    }

    (
        PublicPricingResponse {
            // An enabled switch with no resolvable price is still nothing to show.
            enabled: !tiers.is_empty(),
            trial_days,
            tiers,
        },
        reasons,
    )
}

/// Read the live tier config out of its lock.
fn snapshot(tier_config: &web::Data<Arc<RwLock<TierConfig>>>) -> TierConfig {
    tier_config
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// `GET /v1/pricing` - public, unauthenticated, under the rate-limit floor.
pub async fn public_pricing(
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    stripe: web::Data<Arc<StripeService>>,
    cache: web::Data<Arc<PricingCache>>,
) -> Result<HttpResponse, AppError> {
    let cfg = snapshot(&tier_config);
    let stripe = stripe.get_ref().clone();
    // The reasons are dropped here, not swallowed: `resolve` has already logged
    // each one, and the public body must not name price ids or config state.
    let body = cache
        .get_or_resolve(|| async { resolve(cfg, stripe).await.0 })
        .await;
    Ok(HttpResponse::Ok().json(body.as_ref()))
}

/// `GET /v1/admin/pricing/status` - the same resolve the public page runs, with
/// its reasons attached (BUNYIP-515).
///
/// Deliberately bypasses [`PricingCache`]: an admin who just fixed a mapping is
/// asking what is true now, not what a visitor was served up to a minute ago.
pub async fn admin_pricing_status(
    req: HttpRequest,
    _admin: AdminUser,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    stripe: web::Data<Arc<StripeService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let cfg = snapshot(&tier_config);
    let (payload, reasons) = resolve(cfg, stripe.get_ref().clone()).await;
    Ok(success(
        AdminPricingStatus {
            published: payload.enabled && !payload.tiers.is_empty(),
            tiers: payload.tiers,
            reasons: reasons.iter().map(PricingReasonView::from).collect(),
        },
        request_id,
    ))
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

    fn unconfigured_stripe() -> Arc<StripeService> {
        Arc::new(StripeService::new(
            crate::services::unconfigured_stripe_config(),
        ))
    }

    fn price(id: &str, amount: Option<i64>, active: bool) -> StripePriceResponse {
        StripePriceResponse {
            id: id.into(),
            product_id: "prod_x".into(),
            unit_amount: amount,
            currency: "usd".into(),
            recurring_interval: Some("month".into()),
            // DUNITE-9: added to the shared DTO by the dunite-stripe bump; a
            // plain monthly test price bills every 1 interval.
            recurring_interval_count: Some(1),
            active,
        }
    }

    #[actix_rt::test]
    async fn pricing_switch_off_publishes_nothing() {
        let mut cfg = TierConfig::from_env();
        cfg.standard_price_id = Some("price_123".into());
        cfg.pricing_enabled = false;
        let (out, reasons) = resolve(cfg, unconfigured_stripe()).await;
        assert!(!out.enabled);
        assert!(out.tiers.is_empty());
        assert_eq!(out.trial_days, 30, "trial length is still reported");
        assert_eq!(reasons, vec![UnpublishedReason::SwitchOff]);
    }

    #[actix_rt::test]
    async fn enabled_without_a_mapped_price_publishes_nothing() {
        let mut cfg = TierConfig::from_env();
        cfg.pricing_enabled = true;
        cfg.standard_price_id = None;
        let (out, reasons) = resolve(cfg, unconfigured_stripe()).await;
        assert!(!out.enabled, "no mapped price is nothing to advertise");
        assert!(out.tiers.is_empty());
        assert_eq!(reasons, vec![UnpublishedReason::NoTierMapped]);
    }

    /// BUNYIP-515: a blank id in the DB column is "not mapped", not a price id
    /// that will fail to resolve later.
    #[actix_rt::test]
    async fn blank_price_ids_count_as_unmapped() {
        let mut cfg = TierConfig::from_env();
        cfg.pricing_enabled = true;
        cfg.free_price_id = Some("  ".into());
        cfg.standard_price_id = Some(String::new());
        let (_, reasons) = resolve(cfg, unconfigured_stripe()).await;
        assert_eq!(reasons, vec![UnpublishedReason::NoTierMapped]);
    }

    #[actix_rt::test]
    async fn a_mapped_tier_without_stripe_keys_names_stripe() {
        let mut cfg = TierConfig::from_env();
        cfg.pricing_enabled = true;
        cfg.early_adopter_price_id = Some("price_ea".into());
        let (out, reasons) = resolve(cfg, unconfigured_stripe()).await;
        assert!(!out.enabled);
        assert_eq!(reasons, vec![UnpublishedReason::StripeNotConfigured]);
    }

    /// BUNYIP-515 AC1: every mapped tier publishes, in ladder order, each with
    /// its own trial length.
    #[test]
    fn every_mapped_tier_that_resolves_is_published() {
        let mapped = vec![
            ("lifetime", "price_life".to_string(), 0),
            ("early_adopter", "price_ea".to_string(), 90),
            ("standard", "price_std".to_string(), 30),
        ];
        let prices = vec![
            price("price_std", Some(300), true),
            price("price_ea", Some(200), true),
            price("price_life", Some(0), true),
        ];
        let (tiers, reasons) = match_mapped_tiers(&mapped, &prices, "bunyip");
        assert!(reasons.is_empty());
        assert_eq!(
            tiers.iter().map(|t| t.tier).collect::<Vec<_>>(),
            vec!["lifetime", "early_adopter", "standard"],
            "published in ladder order, not Stripe's list order"
        );
        assert_eq!(tiers[0].amount, 0, "a zero lifetime price is a real price");
        assert_eq!(tiers[1].trial_days, 90, "each tier carries its own trial");
        assert_eq!(tiers[2].amount, 300);
    }

    /// BUNYIP-515 AC10: archived resolves to the archived reason, not a
    /// generic miss, and one broken tier does not unpublish the others.
    #[test]
    fn an_archived_price_is_named_as_archived() {
        let mapped = vec![
            ("early_adopter", "price_old".to_string(), 90),
            ("standard", "price_std".to_string(), 30),
        ];
        let prices = vec![
            price("price_old", Some(200), false),
            price("price_std", Some(300), true),
        ];
        let (tiers, reasons) = match_mapped_tiers(&mapped, &prices, "bunyip");
        assert_eq!(tiers.len(), 1, "the healthy tier still publishes");
        assert_eq!(
            reasons,
            vec![UnpublishedReason::PriceUnresolved {
                tier: "early_adopter",
                price_id: "price_old".into(),
                detail: PriceUnresolved::Archived,
            }]
        );
        assert!(reasons[0].message().contains("archived"));
    }

    #[test]
    fn a_price_with_no_amount_is_named_as_such() {
        let mapped = vec![("standard", "price_metered".to_string(), 30)];
        let prices = vec![price("price_metered", None, true)];
        let (tiers, reasons) = match_mapped_tiers(&mapped, &prices, "bunyip");
        assert!(tiers.is_empty());
        assert!(matches!(
            reasons.as_slice(),
            [UnpublishedReason::PriceUnresolved {
                detail: PriceUnresolved::NoAmount,
                ..
            }]
        ));
    }

    /// BUNYIP-515 AC5: a price absent from the (app-tag filtered) list names
    /// the tag as a possible cause and quotes it.
    #[test]
    fn an_invisible_price_quotes_the_app_tag() {
        let mapped = vec![("standard", "price_dashboard".to_string(), 30)];
        let (tiers, reasons) = match_mapped_tiers(&mapped, &[], "bunyip");
        assert!(tiers.is_empty());
        let msg = reasons[0].message();
        assert!(msg.contains("price_dashboard"), "names the price id: {msg}");
        assert!(msg.contains("app tag `bunyip`"), "quotes the tag: {msg}");
        assert!(msg.contains("app_tag metadata"), "names the fix: {msg}");
    }

    /// Every reason renders a message an admin can act on, short enough to
    /// survive the admin page's 256-char box, and carries a distinct code.
    #[test]
    fn every_reason_has_a_distinct_actionable_message() {
        let all = [
            UnpublishedReason::SwitchOff,
            UnpublishedReason::NoTierMapped,
            UnpublishedReason::StripeNotConfigured,
            UnpublishedReason::StripeListFailed {
                detail: "connection refused".into(),
            },
            UnpublishedReason::PriceUnresolved {
                tier: "standard",
                price_id: "price_1U33RlAbCdEfGhIjKlMnOpQr".into(),
                detail: PriceUnresolved::NotVisible {
                    app_tag: "bunyip".into(),
                },
            },
        ];
        let mut codes: Vec<&str> = all.iter().map(UnpublishedReason::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len(), "one code per branch");
        for r in &all {
            let m = r.message();
            assert!(!m.is_empty());
            assert!(m.len() <= 256, "message fits the admin box: {m}");
            // The wire view is what the admin page renders.
            assert_eq!(PricingReasonView::from(r).message, m);
        }
    }
}
