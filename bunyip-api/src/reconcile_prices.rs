//! BUNYIP-562: reconcile duplicate active Stripe prices left by a partially
//! failed BUNYIP-511 replace.
//!
//! A replace runs create-new, repoint references, archive-old, in that order on
//! purpose: a stranded reference breaks checkout while a duplicate does not, so
//! the old price is archived last. If that final archive fails, the product is
//! left with two active prices sharing the BUNYIP-514 key - the new price (which
//! the tier columns and entitlements now point at) and the old price (still
//! active, no longer pointed at). BUNYIP-514 refuses creating that state and its
//! `/admin/stripe` warning surfaces it, but nothing cleans it. This does.
//!
//! The rule is cause-agnostic and safe. Active prices are grouped by the
//! [`ActivePriceKey`]; in each group of two or more, a price is REFERENCED when
//! it sits in a `tier_config` price column, has a `stripe_price_entitlements`
//! row, or has members (on its tier or locked to it via `users.locked_price_id`).
//! An UNREFERENCED price is archived only when the group still holds at least one
//! referenced keeper. A group with no referenced price is a business decision no
//! rule can make (which of two unmapped prices survives), so it is reported and
//! left untouched; a group where every price is referenced is an unresolved
//! conflict, also left untouched. This never archives a price anything points at
//! or anyone is on, never removes the last representative of a key, and never
//! picks a winner among equals. The `subscriptions` table is not consulted:
//! nothing in bunyip reads it (live subscription state lives only in Stripe), and
//! a member on a live subscription is already captured by the member count.

use std::collections::HashMap;

use serde_json::json;
use sqlx::PgPool;

use crate::handlers::admin_stripe::{format_price_amount, plan_for_price, ActivePriceKey};
use crate::models::{AuditAction, CreateAuditLog, StripePriceResponse};
use crate::repositories::{
    AuditLogRepository, EntitlementRepository, TierConfigRepository, UserRepository,
};
use crate::services::StripeService;

/// A price paired with whether anything references it. The reconciler decides
/// purely on this flag, never on the amount.
pub(crate) struct PriceRef<'a> {
    pub(crate) price: &'a StripePriceResponse,
    pub(crate) referenced: bool,
}

/// What the reconciler decided for one duplicate-key group of active prices.
pub(crate) enum GroupOutcome<'a> {
    /// Archive these unreferenced orphans; the referenced keeper(s) stay.
    Archive {
        keep: Vec<&'a StripePriceResponse>,
        archive: Vec<&'a StripePriceResponse>,
    },
    /// Two or more active prices, none referenced: a human must choose which
    /// survives, so nothing is touched.
    SkipNoKeeper(Vec<&'a StripePriceResponse>),
    /// Two or more active prices, all referenced: an unresolved conflict with no
    /// orphan to remove, left untouched.
    SkipAllReferenced(Vec<&'a StripePriceResponse>),
}

/// Decide one group of active prices that share a key. Returns `None` when the
/// group is not a duplicate (fewer than two active prices).
pub(crate) fn plan_group<'a>(members: &[&PriceRef<'a>]) -> Option<GroupOutcome<'a>> {
    if members.len() < 2 {
        return None;
    }
    let keep: Vec<_> = members
        .iter()
        .filter(|m| m.referenced)
        .map(|m| m.price)
        .collect();
    let archive: Vec<_> = members
        .iter()
        .filter(|m| !m.referenced)
        .map(|m| m.price)
        .collect();
    Some(match (keep.is_empty(), archive.is_empty()) {
        (true, _) => GroupOutcome::SkipNoKeeper(archive),
        (false, true) => GroupOutcome::SkipAllReferenced(keep),
        (false, false) => GroupOutcome::Archive { keep, archive },
    })
}

/// Group the active prices by [`ActivePriceKey`] and decide each duplicate
/// group. Only groups of two or more active prices appear in the result, sorted
/// by product id then currency then interval for deterministic output.
pub(crate) fn plan_reconcile<'a>(
    prices: &'a [PriceRef<'a>],
) -> Vec<(ActivePriceKey, GroupOutcome<'a>)> {
    let mut groups: HashMap<ActivePriceKey, Vec<&PriceRef<'a>>> = HashMap::new();
    for pr in prices.iter().filter(|pr| pr.price.active) {
        groups
            .entry(ActivePriceKey::of(pr.price))
            .or_default()
            .push(pr);
    }
    let mut out: Vec<(ActivePriceKey, GroupOutcome<'a>)> = groups
        .into_iter()
        .filter_map(|(key, members)| plan_group(&members).map(|outcome| (key, outcome)))
        .collect();
    out.sort_by(|(a, _), (b, _)| {
        (&a.product_id, &a.currency, &a.interval, &a.interval_count).cmp(&(
            &b.product_id,
            &b.currency,
            &b.interval,
            &b.interval_count,
        ))
    });
    out
}

/// Whether anything references this price: a `tier_config` price column, a
/// `stripe_price_entitlements` row, or a member (on its tier or locked to it).
async fn is_referenced(
    pool: &PgPool,
    tier: &crate::models::tier::TierConfigRow,
    price: &StripePriceResponse,
) -> anyhow::Result<bool> {
    let plan = plan_for_price(tier, &price.id);
    let tier_mapped = !plan.tiers.is_empty();
    let apps = EntitlementRepository::applications_for_price(pool, &price.id).await?;
    // `plan.price_ids` is `[price.id]`, so this counts members on a mapped tier
    // AND anyone locked to this price id even when it maps to no tier.
    let members =
        UserRepository::count_members_for_plan(pool, &plan.tiers, &plan.price_ids).await?;
    Ok(tier_mapped || !apps.is_empty() || members > 0)
}

/// A short human line naming a price: `price_id ($9.00/month)`.
fn describe(price: &StripePriceResponse) -> String {
    let interval = price.recurring_interval.as_deref().unwrap_or("one-time");
    format!(
        "{} ({}/{interval})",
        price.id,
        format_price_amount(price.unit_amount, &price.currency)
    )
}

/// Run the reconcile. Read-only unless `apply` is set. Returns the report to
/// print. Never returns an error for an unconfigured Stripe account: it reports
/// there is nothing to do and exits cleanly.
pub async fn reconcile(
    pool: &PgPool,
    stripe: &StripeService,
    apply: bool,
) -> anyhow::Result<String> {
    if !stripe.is_configured() {
        return Ok("Stripe is not configured; nothing to reconcile.\n".to_string());
    }

    let all = stripe.list_prices(None).await?;
    let tier = TierConfigRepository::get(pool).await?;

    let mut refs: Vec<PriceRef> = Vec::new();
    for price in all.iter().filter(|p| p.active) {
        let referenced = is_referenced(pool, &tier, price).await?;
        refs.push(PriceRef { price, referenced });
    }

    let products_scanned = refs
        .iter()
        .map(|r| r.price.product_id.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();

    let plan = plan_reconcile(&refs);
    let prefix = if apply { "" } else { "[dry-run] " };
    let mut report = String::new();
    let (mut archived, mut skipped) = (0usize, 0usize);

    for (key, outcome) in &plan {
        let product = &key.product_id;
        match outcome {
            GroupOutcome::Archive { keep, archive } => {
                let kept = keep
                    .iter()
                    .map(|p| p.id.clone())
                    .collect::<Vec<_>>()
                    .join(", ");
                for orphan in archive {
                    report.push_str(&format!(
                        "{prefix}{product}: archive {} (unreferenced); keep {kept}\n",
                        describe(orphan)
                    ));
                    if apply {
                        stripe.archive_price(&orphan.id).await?;
                        let audit = CreateAuditLog::new(AuditAction::AdminStripePlanArchived)
                            .with_metadata(json!({
                                "source": "reconcile-duplicate-prices",
                                "product_id": product,
                                "archived_price_id": orphan.id,
                                "kept_price_ids": keep.iter().map(|p| &p.id).collect::<Vec<_>>(),
                                "currency": key.currency,
                                "recurring_interval": key.interval,
                                "recurring_interval_count": key.interval_count,
                            }));
                        AuditLogRepository::create(pool, audit).await?;
                    }
                    archived += 1;
                }
            }
            GroupOutcome::SkipNoKeeper(members) => {
                skipped += 1;
                report.push_str(&format!(
                    "{product}: SKIP - {} active prices share {}, none referenced (choose one by hand)\n",
                    members.len(),
                    key_label(key)
                ));
            }
            GroupOutcome::SkipAllReferenced(members) => {
                skipped += 1;
                report.push_str(&format!(
                    "{product}: SKIP - {} active prices share {}, all referenced (migrate references, then archive by hand)\n",
                    members.len(),
                    key_label(key)
                ));
            }
        }
    }

    if plan.is_empty() {
        report.push_str("No duplicate active prices found.\n");
    }
    let verb = if apply { "archived" } else { "would archive" };
    report.push_str(&format!(
        "Summary: {verb} {archived} orphan price(s), skipped {skipped} group(s), scanned {products_scanned} product(s).\n"
    ));
    Ok(report)
}

/// `usd/month` / `usd/one-time`, for the skip lines.
fn key_label(key: &ActivePriceKey) -> String {
    format!(
        "{}/{}",
        key.currency,
        key.interval.as_deref().unwrap_or("one-time")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn price(id: &str, product: &str, currency: &str, active: bool) -> StripePriceResponse {
        StripePriceResponse {
            id: id.into(),
            product_id: product.into(),
            unit_amount: Some(900),
            currency: currency.into(),
            recurring_interval: Some("month".into()),
            recurring_interval_count: Some(1),
            active,
        }
    }

    fn refd(p: &StripePriceResponse) -> PriceRef<'_> {
        PriceRef {
            price: p,
            referenced: true,
        }
    }
    fn orphan(p: &StripePriceResponse) -> PriceRef<'_> {
        PriceRef {
            price: p,
            referenced: false,
        }
    }

    #[test]
    fn archives_the_orphan_when_a_referenced_keeper_exists() {
        let keep = price("price_new", "prod_1", "usd", true);
        let old = price("price_old", "prod_1", "usd", true);
        let refs = [refd(&keep), orphan(&old)];
        let plan = plan_reconcile(&refs);
        assert_eq!(plan.len(), 1);
        match &plan[0].1 {
            GroupOutcome::Archive { keep, archive } => {
                assert_eq!(
                    keep.iter().map(|p| &p.id).collect::<Vec<_>>(),
                    ["price_new"]
                );
                assert_eq!(
                    archive.iter().map(|p| &p.id).collect::<Vec<_>>(),
                    ["price_old"]
                );
            }
            _ => panic!("expected Archive"),
        }
    }

    #[test]
    fn skips_a_group_with_no_referenced_keeper() {
        // The manual $9 / $3 case: neither mapped, so no rule can choose.
        let a = price("price_a", "prod_1", "usd", true);
        let b = price("price_b", "prod_1", "usd", true);
        let refs = [orphan(&a), orphan(&b)];
        match &plan_reconcile(&refs)[0].1 {
            GroupOutcome::SkipNoKeeper(m) => assert_eq!(m.len(), 2),
            _ => panic!("expected SkipNoKeeper"),
        }
    }

    #[test]
    fn leaves_an_all_referenced_group_untouched() {
        let a = price("price_a", "prod_1", "usd", true);
        let b = price("price_b", "prod_1", "usd", true);
        let refs = [refd(&a), refd(&b)];
        match &plan_reconcile(&refs)[0].1 {
            GroupOutcome::SkipAllReferenced(m) => assert_eq!(m.len(), 2),
            _ => panic!("expected SkipAllReferenced"),
        }
    }

    #[test]
    fn a_single_price_per_key_is_not_a_duplicate() {
        let a = price("price_a", "prod_1", "usd", true);
        assert!(plan_reconcile(&[orphan(&a)]).is_empty());
    }

    #[test]
    fn archived_rows_never_take_part() {
        let keep = price("price_new", "prod_1", "usd", true);
        let gone = price("price_gone", "prod_1", "usd", false); // archived
                                                                // Only one ACTIVE price for the key, so it is not a duplicate group.
        assert!(plan_reconcile(&[refd(&keep), orphan(&gone)]).is_empty());
    }

    #[test]
    fn one_time_prices_bucket_separately_from_recurring() {
        let recurring = price("price_month", "prod_1", "usd", true);
        let mut one_time = price("price_once", "prod_1", "usd", true);
        one_time.recurring_interval = None;
        one_time.recurring_interval_count = None;
        // Different keys, so neither is a duplicate of the other.
        assert!(plan_reconcile(&[orphan(&recurring), orphan(&one_time)]).is_empty());
    }

    #[test]
    fn different_currency_or_product_does_not_group() {
        let usd = price("price_usd", "prod_1", "usd", true);
        let eur = price("price_eur", "prod_1", "eur", true);
        let other = price("price_other", "prod_2", "usd", true);
        assert!(plan_reconcile(&[orphan(&usd), orphan(&eur), orphan(&other)]).is_empty());
    }
}
