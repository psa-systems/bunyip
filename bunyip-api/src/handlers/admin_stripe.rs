//! Admin Stripe management handlers
//!
//! Endpoints for managing Stripe products, prices, and webhook endpoints.
//! All handlers require the `AdminUser` extractor.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::Config;
use crate::errors::AppError;
use crate::handlers::PricingCache;
use crate::middleware::AdminUser;
use crate::models::tier::TierConfigRow;
use crate::models::{AuditAction, CreateAuditLog, StripePriceResponse, StripeProductResponse};
use crate::repositories::{
    AuditLogRepository, EntitlementRepository, StripeConfigRepository, TierConfigRepository,
    UserRepository,
};
use crate::responses::{get_request_id, success, success_no_data};
use crate::services::{
    classify_probe, stripe_err_for, AppKeySet, ProbeStatus, StripePermission, StripeService,
};

// =============================================================================
// BUNYIP-512: plan archive guard + cascade
//
// A "plan" is a Stripe product plus its prices, wired to one or more membership
// tiers in `tier_config`. Two rules hold on the admin archive path:
//
//   1. Refuse the archive while the plan still has members (no Stripe call made).
//   2. Archiving a product cascades to its prices (prices first), so no active
//      price is ever left under an archived product (still chargeable at checkout).
//
// The guard lives HERE, in the archive handlers, not in `StripeService`: the
// member model is bunyip domain state and `dunite-stripe` stays domain-free.
// A future price-replace endpoint (BUNYIP-511) that archives the old price on
// purpose must call `StripeService::archive_price` DIRECTLY and NOT route
// through `archive_stripe_price`, so it is not subject to this member guard.
// =============================================================================

/// The tiers and prices that make up one archivable plan, resolved from
/// `tier_config`. `price_ids` is what the member guard checks `locked_price_id`
/// against; `tiers` is what it checks active memberships against.
pub(crate) struct PlanScope {
    pub(crate) tiers: Vec<String>,
    pub(crate) price_ids: Vec<String>,
}

/// Every `tier_config` mapping as `(tier name, price-id column, product-id
/// column)`. Reads every price/product column bunyip stores (BUNYIP-512 AC), so
/// tier resolution is not limited to the columns the admin catalog form exposes.
/// `free` and `lifetime` share the $0 `free_price_id` (BUNYIP-517), so `lifetime`
/// carries no dedicated price column; it is matched by its derived product id.
fn tier_mappings(t: &TierConfigRow) -> [(&'static str, Option<&str>, Option<&str>); 4] {
    [
        ("free", t.free_price_id.as_deref(), None),
        ("lifetime", None, t.lifetime_product_id.as_deref()),
        (
            "early_adopter",
            t.early_adopter_price_id.as_deref(),
            t.early_adopter_product_id.as_deref(),
        ),
        (
            "standard",
            t.standard_price_id.as_deref(),
            t.standard_product_id.as_deref(),
        ),
    ]
}

/// Resolve the plan for a product archive: every tier whose product id is this
/// product, or whose price id is one of the product's prices, plus the product's
/// full price set (which the whole tier is archived against at once).
fn plan_for_product(
    t: &TierConfigRow,
    product_id: &str,
    product_price_ids: &[String],
) -> PlanScope {
    let tiers = tier_mappings(t)
        .into_iter()
        .filter(|(_, price_col, product_col)| {
            *product_col == Some(product_id)
                || price_col.is_some_and(|p| product_price_ids.iter().any(|x| x == p))
        })
        .map(|(name, _, _)| name.to_string())
        .collect();
    PlanScope {
        tiers,
        price_ids: product_price_ids.to_vec(),
    }
}

/// Resolve the plan for a single-price archive: every tier whose price id is
/// this price, and this one price id. A lone price has nothing to cascade to.
pub(crate) fn plan_for_price(t: &TierConfigRow, price_id: &str) -> PlanScope {
    let tiers = tier_mappings(t)
        .into_iter()
        .filter(|(_, price_col, _)| *price_col == Some(price_id))
        .map(|(name, _, _)| name.to_string())
        .collect();
    PlanScope {
        tiers,
        price_ids: vec![price_id.to_string()],
    }
}

/// The 409 an archive is refused with while members remain. `kind` is `"product"`
/// or `"price"`.
fn refuse_archive(kind: &str, members: i64) -> AppError {
    let (subject, verb) = if members == 1 {
        ("member", "is")
    } else {
        ("members", "are")
    };
    AppError::conflict(format!(
        "Cannot archive this {kind}: {members} {subject} {verb} on it. Move them to another plan first."
    ))
}

// =============================================================================
// BUNYIP-514: refuse a second active price with the same currency and interval
//
// An active price is keyed by (product_id, currency, recurring_interval,
// recurring_interval_count). Two ACTIVE prices sharing that key are the case
// with no answer to "which one is charged", so creating or restoring one is
// refused. Currency stays in the key (a multi-currency catalog is legitimate);
// interval_count separates monthly from an externally created quarterly. The
// check runs on the create and unarchive paths; the BUNYIP-511 replace path is
// exempt because it archives the price it supersedes in the same operation.
// =============================================================================

/// The identity two active prices on one product must not share. `interval` is
/// `month`/`year`/... or `None` for a one-time price, which forms its own
/// bucket. Currency is lowercased so `USD` and `usd` compare equal.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub(crate) struct ActivePriceKey {
    pub(crate) product_id: String,
    pub(crate) currency: String,
    pub(crate) interval: Option<String>,
    pub(crate) interval_count: Option<u64>,
}

impl ActivePriceKey {
    /// Build the key from a price. When the price is recurring, a missing
    /// `recurring_interval_count` is normalized to `1`: Stripe always defaults a
    /// recurring price's `interval_count` to 1, but dunite may leave it unset,
    /// and bunyip's own create sends `Some(1)`, so the two must compare equal.
    pub(crate) fn of(p: &StripePriceResponse) -> Self {
        let interval = p.recurring_interval.clone();
        let interval_count = interval
            .as_ref()
            .map(|_| p.recurring_interval_count.unwrap_or(1));
        Self {
            product_id: p.product_id.clone(),
            currency: p.currency.to_ascii_lowercase(),
            interval,
            interval_count,
        }
    }
}

/// The first ACTIVE price in `existing` whose key matches `key`, skipping
/// `ignore` (the price being restored, so it never conflicts with itself).
/// Returns `None` when no active price holds the key.
fn find_active_conflict<'a>(
    existing: &'a [StripePriceResponse],
    key: &ActivePriceKey,
    ignore: Option<&str>,
) -> Option<&'a StripePriceResponse> {
    existing
        .iter()
        .find(|p| p.active && Some(p.id.as_str()) != ignore && ActivePriceKey::of(p) == *key)
}

/// Format a price amount for a message: "$9.00" / "€9.00" / "£9.00", else
/// "9.00 XXX". Mirrors `bunyip-web`'s `format_stripe_amount` so the admin sees
/// one amount format across the page and the refusal it triggers.
pub(crate) fn format_price_amount(unit_amount: Option<i64>, currency: &str) -> String {
    match unit_amount {
        None => "--".to_string(),
        Some(cents) => {
            let whole = cents / 100;
            let frac = (cents % 100).abs();
            match currency.to_ascii_lowercase().as_str() {
                "usd" => format!("${whole}.{frac:02}"),
                "eur" => format!("€{whole}.{frac:02}"),
                "gbp" => format!("£{whole}.{frac:02}"),
                _ => format!("{whole}.{frac:02} {}", currency.to_uppercase()),
            }
        }
    }
}

/// The 409 a create/unarchive is refused with when `existing` already holds the
/// requested key. Names the conflicting price and its amount and points at the
/// two ways forward (Archive, or Replace to change the amount).
fn refuse_duplicate_price(existing: &StripePriceResponse) -> AppError {
    let interval = existing.recurring_interval.as_deref().unwrap_or("one-time");
    let amount = format_price_amount(existing.unit_amount, &existing.currency);
    AppError::conflict(format!(
        "This product already has an active {interval} {currency} price ({id}, {amount}). \
         Archive it or use Replace to change its amount.",
        currency = existing.currency.to_uppercase(),
        id = existing.id,
    ))
}

/// BUNYIP-512: a Stripe product plus the members-on-its-plan count the admin
/// list renders. `#[serde(flatten)]` keeps the wire shape the shared
/// `StripeProductResponse` with one field added.
#[derive(Serialize)]
struct AdminStripeProduct {
    #[serde(flatten)]
    inner: StripeProductResponse,
    member_count: i64,
}

/// BUNYIP-512: a Stripe price plus its members-on-plan count (see
/// [`AdminStripeProduct`]).
#[derive(Serialize)]
struct AdminStripePrice {
    #[serde(flatten)]
    inner: StripePriceResponse,
    member_count: i64,
}

// =============================================================================
// Request types
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct CreateStripeProductRequest {
    pub name: String,
    pub description: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateStripeProductRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
    pub active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ListStripePricesQuery {
    pub product_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateStripePriceRequest {
    pub product_id: String,
    pub unit_amount: i64,
    pub currency: String,
    pub interval: String,
}

/// BUNYIP-511: the body of a price replace. Only the three fields Stripe will
/// not let you change on an existing price (amount, currency, interval), which is
/// exactly why a change to any of them is a create-plus-archive.
#[derive(Debug, Deserialize)]
pub struct ReplaceStripePriceRequest {
    pub unit_amount: i64,
    pub currency: String,
    pub interval: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateStripeWebhookRequest {
    pub url: String,
    pub enabled_events: Vec<String>,
}

// =============================================================================
// Products
// =============================================================================

/// GET /v1/admin/stripe/products
///
/// BUNYIP-512: each product carries a `member_count` (members on its plan),
/// computed with one grouped query for the whole page
/// (`UserRepository::plan_member_index`), never one query per row.
pub async fn list_stripe_products(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let products = stripe
        .list_products()
        .await
        .map_err(stripe_err_for(StripePermission::Products))?;
    // BUNYIP-512: one list of all app-tagged prices groups the product -> price
    // sets without an extra Stripe round trip per product.
    let all_prices = stripe
        .list_prices(None)
        .await
        .map_err(stripe_err_for(StripePermission::Prices))?;
    let tier = TierConfigRepository::get(&pool).await?;
    let index = UserRepository::plan_member_index(&pool).await?;

    let wrapped: Vec<AdminStripeProduct> = products
        .into_iter()
        .map(|p| {
            let price_ids: Vec<String> = all_prices
                .iter()
                .filter(|pr| pr.product_id == p.id)
                .map(|pr| pr.id.clone())
                .collect();
            let plan = plan_for_product(&tier, &p.id, &price_ids);
            let member_count = index.count_for(&plan.tiers, &plan.price_ids);
            AdminStripeProduct {
                inner: p,
                member_count,
            }
        })
        .collect();
    Ok(success(wrapped, request_id))
}

/// POST /v1/admin/stripe/products
pub async fn create_stripe_product(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    body: web::Json<CreateStripeProductRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let product = stripe
        .create_product(
            &body.name,
            body.description.as_deref(),
            body.metadata.clone().unwrap_or_default(),
        )
        .await
        .map_err(stripe_err_for(StripePermission::Products))?;
    Ok(success(product, request_id))
}

/// PUT /v1/admin/stripe/products/{id}
pub async fn update_stripe_product(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    path: web::Path<String>,
    body: web::Json<UpdateStripeProductRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let product_id = path.into_inner();
    let product = stripe
        .update_product(
            &product_id,
            body.name.as_deref(),
            body.description.as_deref(),
            body.metadata.clone(),
            body.active,
        )
        .await
        .map_err(stripe_err_for(StripePermission::Products))?;
    Ok(success(product, request_id))
}

/// DELETE /v1/admin/stripe/products/{id}
///
/// BUNYIP-512: archiving a product is all-or-nothing. Refused with 409 while the
/// plan has members (no Stripe call made); otherwise every active price of the
/// product is archived FIRST, then the product, so no active price is ever left
/// under an archived product. A partial price failure is returned and logged,
/// never swallowed, with the product left active.
pub async fn archive_stripe_product(
    req: HttpRequest,
    admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    pool: web::Data<PgPool>,
    pricing_cache: web::Data<Arc<PricingCache>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let product_id = path.into_inner();

    // Resolve the plan (the product's prices + the tiers mapped to it) and guard
    // BEFORE any Stripe write.
    let prices = stripe
        .list_prices(Some(&product_id))
        .await
        .map_err(stripe_err_for(StripePermission::Prices))?;
    let tier = TierConfigRepository::get(&pool).await?;
    let price_ids: Vec<String> = prices.iter().map(|p| p.id.clone()).collect();
    let plan = plan_for_product(&tier, &product_id, &price_ids);
    let members =
        UserRepository::count_members_for_plan(&pool, &plan.tiers, &plan.price_ids).await?;
    if members > 0 {
        return Err(refuse_archive("product", members));
    }

    // Cascade: archive the active prices first. If one fails, stop and report -
    // the product stays active and visible rather than becoming an archived
    // product with live prices, which is the exact state this issue fixes.
    let active_price_ids: Vec<String> = prices
        .iter()
        .filter(|p| p.active)
        .map(|p| p.id.clone())
        .collect();
    let mut archived: Vec<String> = Vec::new();
    for pid in &active_price_ids {
        if let Err(e) = stripe.archive_price(pid).await {
            let mapped = stripe_err_for(StripePermission::Prices)(e);
            tracing::error!(
                product_id = %product_id,
                failed_price_id = %pid,
                archived_price_ids = ?archived,
                error = %mapped,
                "BUNYIP-512: partial plan archive - a price failed to archive; product left active"
            );
            return Err(AppError::internal(format!(
                "Archive incomplete: archived price(s) [{}] but failed on {pid}; the product was left active. Retry the archive.",
                archived.join(", ")
            )));
        }
        archived.push(pid.clone());
    }

    // Prices gone; archive the product itself.
    stripe
        .archive_product(&product_id)
        .await
        .map_err(stripe_err_for(StripePermission::Products))?;

    let audit = CreateAuditLog::new(AuditAction::AdminStripePlanArchived)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({
            "product_id": product_id,
            "archived_price_ids": archived,
            "member_count": members,
        }));
    AuditLogRepository::create(&pool, audit).await?;

    // The cascade unpublishes every tier that mapped to this plan, so drop the
    // public pricing payload rather than advertise a plan nobody can buy.
    pricing_cache.invalidate();
    Ok(success_no_data(request_id))
}

/// POST /v1/admin/stripe/products/{id}/unarchive
///
/// BUNYIP-513: the reverse of archive - set the Stripe product `active = true`.
/// `metadata` is deliberately not sent (passing `None`), so `update_product`
/// leaves the existing metadata map intact and the app tag survives. There is no
/// cascade to prices on purpose (BUNYIP-513): the set of prices a given archive
/// cascade touched is not recorded, and a blanket restore would resurrect prices
/// archived for unrelated reasons (e.g. a superseded price). Each price is
/// restored explicitly via [`unarchive_stripe_price`]. Not member-guarded:
/// restoring a plan withdraws nothing.
pub async fn unarchive_stripe_product(
    req: HttpRequest,
    admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    pool: web::Data<PgPool>,
    pricing_cache: web::Data<Arc<PricingCache>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let product_id = path.into_inner();

    stripe
        .update_product(&product_id, None, None, None, Some(true))
        .await
        .map_err(stripe_err_for(StripePermission::Products))?;

    let audit = CreateAuditLog::new(AuditAction::AdminStripePlanUnarchived)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({ "product_id": product_id }));
    AuditLogRepository::create(&pool, audit).await?;

    // Restoring a product can republish a tier whose (still-active) price maps to
    // it, so refresh the public pricing payload rather than keep serving stale.
    pricing_cache.invalidate();
    Ok(success_no_data(request_id))
}

// =============================================================================
// Prices
// =============================================================================

/// GET /v1/admin/stripe/prices
///
/// BUNYIP-512: each price carries a `member_count` (members on the tier that
/// price maps to, plus anyone who locked that price), computed once for the page.
pub async fn list_stripe_prices(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    pool: web::Data<PgPool>,
    query: web::Query<ListStripePricesQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let prices = stripe
        .list_prices(query.product_id.as_deref())
        .await
        .map_err(stripe_err_for(StripePermission::Prices))?;
    let tier = TierConfigRepository::get(&pool).await?;
    let index = UserRepository::plan_member_index(&pool).await?;

    let wrapped: Vec<AdminStripePrice> = prices
        .into_iter()
        .map(|pr| {
            let plan = plan_for_price(&tier, &pr.id);
            let member_count = index.count_for(&plan.tiers, &plan.price_ids);
            AdminStripePrice {
                inner: pr,
                member_count,
            }
        })
        .collect();
    Ok(success(wrapped, request_id))
}

/// POST /v1/admin/stripe/prices
pub async fn create_stripe_price(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    pricing_cache: web::Data<Arc<PricingCache>>,
    body: web::Json<CreateStripePriceRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // BUNYIP-514: refuse a second active price with the same currency and
    // interval on this product BEFORE calling Stripe. bunyip's create form only
    // makes recurring month/year prices, so the requested key is always
    // `interval = Some(..)`, `interval_count = Some(1)`.
    let existing = stripe
        .list_prices(Some(body.product_id.as_str()))
        .await
        .map_err(stripe_err_for(StripePermission::Prices))?;
    let requested = ActivePriceKey {
        product_id: body.product_id.clone(),
        currency: body.currency.to_ascii_lowercase(),
        interval: Some(body.interval.to_ascii_lowercase()),
        interval_count: Some(1),
    };
    if let Some(conflict) = find_active_conflict(&existing, &requested, None) {
        return Err(refuse_duplicate_price(conflict));
    }

    let price = stripe
        .create_price(
            &body.product_id,
            body.unit_amount,
            &body.currency,
            &body.interval,
        )
        .await
        .map_err(stripe_err_for(StripePermission::Prices))?;
    // BUNYIP-515: the new price can be the one a tier maps to, so the public
    // payload must not stay stale for up to the TTL after an admin fixes it.
    pricing_cache.invalidate();
    Ok(success(price, request_id))
}

/// DELETE /v1/admin/stripe/prices/{id}
///
/// BUNYIP-512: refused with 409 (no Stripe call) while the price's plan has
/// members. A lone price has nothing to cascade to. The BUNYIP-511 replace flow
/// must NOT reach this handler - it archives the old price via
/// `StripeService::archive_price` directly, bypassing this guard on purpose.
pub async fn archive_stripe_price(
    req: HttpRequest,
    admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    pool: web::Data<PgPool>,
    pricing_cache: web::Data<Arc<PricingCache>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let price_id = path.into_inner();

    let tier = TierConfigRepository::get(&pool).await?;
    let plan = plan_for_price(&tier, &price_id);
    let members =
        UserRepository::count_members_for_plan(&pool, &plan.tiers, &plan.price_ids).await?;
    if members > 0 {
        return Err(refuse_archive("price", members));
    }

    stripe
        .archive_price(&price_id)
        .await
        .map_err(stripe_err_for(StripePermission::Prices))?;

    let audit = CreateAuditLog::new(AuditAction::AdminStripePlanArchived)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({
            "product_id": serde_json::Value::Null,
            "archived_price_ids": [price_id],
            "member_count": members,
        }));
    AuditLogRepository::create(&pool, audit).await?;

    // BUNYIP-515: archiving the mapped price unpublishes its tier at once
    // rather than advertising a price nobody can buy for another TTL.
    pricing_cache.invalidate();
    Ok(success_no_data(request_id))
}

/// POST /v1/admin/stripe/prices/{id}/unarchive
///
/// BUNYIP-513: restore a single archived price (`active = true`) via
/// `StripeService::unarchive_price`. Not member-guarded (restoring withdraws
/// nothing). Republishing a mapped price changes what `/pricing` resolves, so
/// the pricing cache is dropped.
pub async fn unarchive_stripe_price(
    req: HttpRequest,
    admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    pool: web::Data<PgPool>,
    pricing_cache: web::Data<Arc<PricingCache>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let price_id = path.into_inner();

    // BUNYIP-514: restoring an archived price can recreate a same-currency,
    // same-interval conflict, so it runs the same check as create. Recover the
    // price's key from the catalog (list_prices returns active AND archived),
    // then refuse if another ACTIVE price already holds it. Ignore the price's
    // own id: it is archived now, but be explicit so it never self-conflicts.
    let all = stripe
        .list_prices(None)
        .await
        .map_err(stripe_err_for(StripePermission::Prices))?;
    let target = all
        .iter()
        .find(|p| p.id == price_id)
        .ok_or_else(|| AppError::not_found("Stripe price"))?;
    let key = ActivePriceKey::of(target);
    if let Some(conflict) = find_active_conflict(&all, &key, Some(&price_id)) {
        return Err(refuse_duplicate_price(conflict));
    }

    stripe
        .unarchive_price(&price_id)
        .await
        .map_err(stripe_err_for(StripePermission::Prices))?;

    let audit = CreateAuditLog::new(AuditAction::AdminStripePlanUnarchived)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({ "price_id": price_id }));
    AuditLogRepository::create(&pool, audit).await?;

    pricing_cache.invalidate();
    Ok(success_no_data(request_id))
}

/// POST /v1/admin/stripe/prices/{id}/replace
///
/// BUNYIP-511: change what a plan costs. A Stripe price is immutable in amount,
/// currency and interval, so "edit price" is a REPLACE: create a new price on the
/// same product, repoint bunyip's own references, then archive the old price.
///
/// The order is deliberate. bunyip's references (the `tier_config` price columns
/// and the `stripe_price_entitlements` rows) are repointed to the new price
/// BEFORE the old one is archived, so no failure can strand a reference on an
/// archived price: if the final archive fails, checkout already runs on the new
/// (active) price and the old price is only a harmless still-active duplicate.
/// The old price is archived with `StripeService::archive_price` DIRECTLY,
/// bypassing the member guard on `archive_stripe_price` on purpose (BUNYIP-512):
/// a replace does not withdraw the plan, so it must succeed even with members.
///
/// `users.locked_price_id` (grandfathered pricing) and
/// `subscriptions.stripe_price_id` (a live Stripe subscription keeps billing on
/// its price until migrated in Stripe) are deliberately left untouched.
///
/// A partial failure never reports success: any step after the new price is
/// created returns an error naming the new price id and the step that failed,
/// logged at `error`, so the admin can finish the job by hand.
pub async fn replace_stripe_price(
    req: HttpRequest,
    admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    pool: web::Data<PgPool>,
    pricing_cache: web::Data<Arc<PricingCache>>,
    path: web::Path<String>,
    body: web::Json<ReplaceStripePriceRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let old_price_id = path.into_inner();

    // Recover the product the old price sits on. `list_prices(None)` returns only
    // app-tagged prices, so a price bunyip did not create is a 404 here.
    let all = stripe
        .list_prices(None)
        .await
        .map_err(stripe_err_for(StripePermission::Prices))?;
    let old = all
        .iter()
        .find(|p| p.id == old_price_id)
        .ok_or_else(|| AppError::not_found("Stripe price"))?;
    let product_id = old.product_id.clone();

    // 1. Create the replacement on the same product.
    // BUNYIP-514-exempt: a replace is the sanctioned way to end up with one
    // active price for a key. It archives the price it supersedes below (step 3),
    // so the duplicate the create/unarchive check refuses is transient by
    // construction here; running that check would refuse the very fix it points
    // admins at. The new price is created via `create_price` directly, not the
    // `create_stripe_price` handler, so the check does not run on this path.
    let new_price = stripe
        .create_price(
            &product_id,
            body.unit_amount,
            &body.currency,
            &body.interval,
        )
        .await
        .map_err(stripe_err_for(StripePermission::Prices))?;
    let new_price_id = new_price.id.clone();

    // From here on the new price EXISTS; every later failure must name it so the
    // admin is never left with a silent half-applied replace.
    let incomplete = |step: &str, err: String| -> AppError {
        tracing::error!(
            old_price_id = %old_price_id,
            new_price_id = %new_price_id,
            product_id = %product_id,
            failed_step = step,
            error = %err,
            "BUNYIP-511: price replace incomplete after creating the new price"
        );
        AppError::internal(format!(
            "Price replace incomplete: created the new price {new_price_id}, but {step} failed: {err}. \
             The new price exists in Stripe; retry the replace or finish it by hand. Old price: {old_price_id}."
        ))
    };

    // 2. Repoint bunyip's references to the new price BEFORE archiving the old
    //    one. Only the tier columns that actually equal the old price id are
    //    passed as `Some`; `None` leaves a column unchanged.
    let tier = TierConfigRepository::get(&pool)
        .await
        .map_err(|e| incomplete("reading the tier config", e.to_string()))?;
    let repoint = |col: &Option<String>| -> Option<String> {
        (col.as_deref() == Some(old_price_id.as_str())).then(|| new_price_id.clone())
    };
    let free = repoint(&tier.free_price_id);
    let early_adopter = repoint(&tier.early_adopter_price_id);
    let standard = repoint(&tier.standard_price_id);
    let mut repointed_columns: Vec<&str> = Vec::new();
    if free.is_some() {
        repointed_columns.push("free_price_id");
    }
    if early_adopter.is_some() {
        repointed_columns.push("early_adopter_price_id");
    }
    if standard.is_some() {
        repointed_columns.push("standard_price_id");
    }
    if !repointed_columns.is_empty() {
        TierConfigRepository::update(
            &pool,
            None,
            None,
            None,
            None,
            free,
            early_adopter,
            standard,
            None,
            None,
            None,
            None,
            // BUNYIP-527: visibility flags unchanged by a price replace.
            None,
            None,
            None,
            // BUNYIP-493: the organizations switch has nothing to do with a
            // price replace either.
            None,
            admin.0.sub,
        )
        .await
        .map_err(|e| incomplete("repointing the tier catalog mapping", e.to_string()))?;
    }

    // Move every application entitlement mapped to the old price onto the new
    // price (add the new mapping, then drop the old).
    let apps = EntitlementRepository::applications_for_price(&pool, &old_price_id)
        .await
        .map_err(|e| incomplete("reading the price entitlements", e.to_string()))?;
    for app_id in &apps {
        EntitlementRepository::add_price_mapping(&pool, &new_price_id, *app_id)
            .await
            .map_err(|e| incomplete("adding the new price entitlement", e.to_string()))?;
        EntitlementRepository::remove_price_mapping(&pool, &old_price_id, *app_id)
            .await
            .map_err(|e| incomplete("removing the old price entitlement", e.to_string()))?;
    }

    // 3. Archive the old price DIRECTLY (not via `archive_stripe_price`, so the
    //    member guard cannot block a legitimate price change).
    if let Err(e) = stripe.archive_price(&old_price_id).await {
        let mapped = stripe_err_for(StripePermission::Prices)(e);
        return Err(incomplete("archiving the old price", mapped.to_string()));
    }

    let audit = CreateAuditLog::new(AuditAction::AdminStripePriceReplaced)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({
            "old_price_id": old_price_id.clone(),
            "new_price_id": new_price_id.clone(),
            "product_id": product_id.clone(),
            "unit_amount": body.unit_amount,
            "currency": body.currency.clone(),
            "interval": body.interval.clone(),
            "repointed_tier_columns": repointed_columns,
            "repointed_application_ids": apps,
        }));
    AuditLogRepository::create(&pool, audit).await?;

    // The mapped tier now resolves to the new price, so drop the public payload
    // rather than keep advertising the old amount for another TTL.
    pricing_cache.invalidate();
    Ok(success(new_price, request_id))
}

// =============================================================================
// Webhooks
// =============================================================================

/// GET /v1/admin/stripe/webhooks
pub async fn list_stripe_webhooks(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let webhooks = stripe
        .list_webhook_endpoints()
        .await
        .map_err(stripe_err_for(StripePermission::WebhookEndpoints))?;
    Ok(success(webhooks, request_id))
}

/// POST /v1/admin/stripe/webhooks
///
/// Creates a Stripe webhook endpoint and auto-saves the returned signing secret
/// to the provider `SECRETS_STORAGE` declares (BUNYIP-542), then reloads the
/// StripeService. In `environment` mode there is no writable provider, so the
/// endpoint is created and the secret is reported for the operator to file,
/// rather than saved somewhere nothing reads.
pub async fn create_stripe_webhook(
    req: HttpRequest,
    admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
    pool: web::Data<PgPool>,
    body: web::Json<CreateStripeWebhookRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let webhook = stripe
        .create_webhook_endpoint(&body.url, body.enabled_events.clone())
        .await
        .map_err(stripe_err_for(StripePermission::WebhookEndpoints))?;

    // If the webhook creation returned a signing secret, persist it to the
    // declared provider.
    if let Some(ref secret) = webhook.secret {
        let provider = config.secrets_provider;
        if !provider.is_writable() {
            // The endpoint exists on Stripe's side now, so this is reported, not
            // swallowed: the admin must place the value themselves or events
            // stay rejected.
            tracing::error!(
                secrets_provider = %provider,
                "Created the Stripe webhook endpoint, but SECRETS_STORAGE=environment has no \
                 writable provider: the signing secret was NOT saved. Write it to the file \
                 STRIPE_WEBHOOK_SECRET_FILE points at and restart bunyip-api."
            );
            return Err(crate::secrets::read_only_provider_error(
                crate::config::GovernedSecret::StripeWebhookSecret,
            ));
        }
        crate::secrets::write_secret(
            &pool,
            &config,
            &app_key_set,
            provider,
            crate::config::GovernedSecret::StripeWebhookSecret,
            secret,
            Some(admin.0.sub),
        )
        .await?;

        let row = StripeConfigRepository::get(&pool).await?;
        let new_config =
            crate::secrets::stripe_runtime_config(&pool, &config, &app_key_set, &row).await?;
        stripe.reload(new_config);
        tracing::info!(
            secrets_provider = %provider,
            "Stripe service reloaded with new webhook secret"
        );
    }

    Ok(success(webhook, request_id))
}

/// DELETE /v1/admin/stripe/webhooks/{id}
pub async fn delete_stripe_webhook(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let endpoint_id = path.into_inner();
    stripe
        .delete_webhook_endpoint(&endpoint_id)
        .await
        .map_err(stripe_err_for(StripePermission::WebhookEndpoints))?;
    Ok(success_no_data(request_id))
}

// =============================================================================
// BUNYIP-532: proactive Stripe key permission self-test
//
// BUNYIP-516 explains a permission failure reactively, at the moment the admin
// attempts the operation that needs it. This endpoint lets the admin check the
// saved key up front: it makes the harmless list reads whose errors the shared
// crate classifies (products, prices, webhook endpoints - the last gained HTTP
// status handling in DUNITE-10) and reports each as granted / missing / key
// rejected. The checkout-time permissions bunyip also needs (customers, checkout
// sessions, subscriptions, invoices) are listed as required but not live-tested:
// the dunite-stripe methods for them collapse Stripe's error, so a 403 there
// cannot be told from a 404. Classifying those is a separate dunite change.
// =============================================================================

/// One permission bunyip needs, and (for the live-tested three) how the saved
/// key fared against it.
#[derive(Debug, serde::Serialize)]
pub struct StripePermissionCheck {
    /// Stable machine name (`StripePermission::key`).
    pub permission: &'static str,
    /// The label Stripe's key editor shows.
    pub label: &'static str,
    /// The access level the key needs: `"Write"` or `"Read"`.
    pub access: &'static str,
    /// When the permission is exercised: `"admin"` (on this page, live-tested) or
    /// `"checkout"` (later, by a customer; listed but not live-tested).
    pub when: &'static str,
    pub status: ProbeStatus,
}

/// The self-test result: overall key status plus the per-permission checklist.
#[derive(Debug, serde::Serialize)]
pub struct StripePermissionReport {
    /// Whether a real secret key is saved at all.
    pub configured: bool,
    /// `"ok"`, `"rejected"` (the key itself is bad) or `"not_configured"`.
    pub key_status: &'static str,
    pub checks: Vec<StripePermissionCheck>,
}

/// The permissions bunyip's Stripe calls need, with the access level and where
/// each is exercised. Single source of truth for both the live test and the
/// checklist. `Subscriptions` needs Write (bunyip creates free subscriptions and
/// cancels / reactivates them), `Invoices` only Read (billing history).
const REQUIRED_PERMISSIONS: [(StripePermission, &str, &str); 7] = [
    (StripePermission::Products, "Write", "admin"),
    (StripePermission::Prices, "Write", "admin"),
    (StripePermission::WebhookEndpoints, "Write", "admin"),
    (StripePermission::Customers, "Write", "checkout"),
    (StripePermission::CheckoutSessions, "Write", "checkout"),
    (StripePermission::Subscriptions, "Write", "checkout"),
    (StripePermission::Invoices, "Read", "checkout"),
];

/// Assemble the report from the three live probe outcomes (products, prices,
/// webhook endpoints), or `None` when no key is saved. Pure, so the mapping is
/// unit-tested without a live Stripe.
fn build_permission_report(
    probed: Option<(ProbeStatus, ProbeStatus, ProbeStatus)>,
) -> StripePermissionReport {
    let (configured, key_status) = match probed {
        None => (false, "not_configured"),
        Some((p, pr, wh)) => {
            let rejected = [p, pr, wh].contains(&ProbeStatus::KeyRejected);
            (true, if rejected { "rejected" } else { "ok" })
        }
    };

    let checks = REQUIRED_PERMISSIONS
        .iter()
        .map(|&(perm, access, when)| {
            let status = match perm {
                StripePermission::Products => probed.map_or(ProbeStatus::Untested, |l| l.0),
                StripePermission::Prices => probed.map_or(ProbeStatus::Untested, |l| l.1),
                StripePermission::WebhookEndpoints => probed.map_or(ProbeStatus::Untested, |l| l.2),
                _ => ProbeStatus::Untested,
            };
            StripePermissionCheck {
                permission: perm.key(),
                label: perm.label(),
                access,
                when,
                status,
            }
        })
        .collect();

    StripePermissionReport {
        configured,
        key_status,
        checks,
    }
}

/// GET /v1/admin/stripe/permissions
///
/// Probe the saved restricted key with harmless list reads and report which
/// permissions it holds. Read-only: makes no change in Stripe or the DB.
pub async fn check_stripe_permissions(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let probed = if stripe.is_configured() {
        let products = classify_probe(&stripe.list_products().await);
        let prices = classify_probe(&stripe.list_prices(None).await);
        let webhooks = classify_probe(&stripe.list_webhook_endpoints().await);
        Some((products, prices, webhooks))
    } else {
        None
    };
    Ok(success(build_permission_report(probed), request_id))
}

#[cfg(test)]
mod tests {
    /// BUNYIP-515: every handler here that MUTATES a Stripe price can change
    /// what `/pricing` resolves, so each must drop the pricing cache. Scanning
    /// the source (rather than listing today's handlers) is what makes the next
    /// price mutation - the BUNYIP-511 replace endpoint, say - fail the build
    /// instead of silently serving a stale payload for up to the TTL.
    #[test]
    fn every_price_mutating_handler_invalidates_the_pricing_cache() {
        let src = include_str!("admin_stripe.rs");
        let mut checked = 0;
        for chunk in src.split("\npub async fn ").skip(1) {
            let (name, rest) = chunk.split_once('(').expect("handler signature");
            // Bound the body at the closing brace in column 0 so one handler's
            // invalidate cannot vouch for the handler above it.
            let body = rest.split("\n}").next().unwrap_or(rest);
            let mutates = [
                "create",
                "update",
                "archive",
                "unarchive",
                "delete",
                "replace",
            ]
            .iter()
            .any(|verb| name.starts_with(verb));
            if !name.contains("price") || !mutates {
                continue;
            }
            checked += 1;
            assert!(
                body.contains("pricing_cache.invalidate()"),
                "{name} mutates a Stripe price but does not invalidate PricingCache"
            );
        }
        assert!(checked >= 2, "the scan matched the price handlers");
    }

    // -- BUNYIP-514: duplicate active price guard --

    use super::{
        find_active_conflict, refuse_duplicate_price, ActivePriceKey, StripePriceResponse,
    };

    /// Every handler that CREATES or RESTORES a price into the active set must
    /// run the duplicate-price check (`find_active_conflict`) or carry an
    /// explicit `BUNYIP-514-exempt` comment saying why it may skip it. Scanning
    /// the source is what makes the next price-activating handler fail the build
    /// instead of silently reopening the hole this issue closes.
    #[test]
    fn every_price_activating_handler_runs_the_duplicate_check() {
        let src = include_str!("admin_stripe.rs");
        let mut checked = 0;
        for chunk in src.split("\npub async fn ").skip(1) {
            let (name, rest) = chunk.split_once('(').expect("handler signature");
            let body = rest.split("\n}").next().unwrap_or(rest);
            let activates = ["create", "unarchive", "restore", "replace"]
                .iter()
                .any(|verb| name.starts_with(verb));
            if !name.contains("price") || !activates {
                continue;
            }
            checked += 1;
            assert!(
                body.contains("find_active_conflict") || body.contains("BUNYIP-514-exempt"),
                "{name} creates or restores a price but neither runs find_active_conflict \
                 nor carries a BUNYIP-514-exempt comment"
            );
        }
        assert!(
            checked >= 3,
            "the scan matched create, unarchive and replace"
        );
    }

    /// The replace endpoint must stay exempt: a same-currency, same-interval
    /// replace is exactly the fix the conflict message points admins at, so it
    /// must never run the duplicate check (which would refuse it). Proven by the
    /// handler body carrying the exemption marker and NOT calling the check.
    #[test]
    fn replace_is_exempt_from_the_duplicate_check() {
        let src = include_str!("admin_stripe.rs");
        let body = src
            .split("\npub async fn replace_stripe_price(")
            .nth(1)
            .expect("replace_stripe_price handler")
            .split("\n}")
            .next()
            .expect("handler body");
        assert!(
            body.contains("BUNYIP-514-exempt"),
            "replace_stripe_price must state why it skips the duplicate check"
        );
        assert!(
            !body.contains("find_active_conflict"),
            "replace_stripe_price must not run the duplicate check, or a same-key replace would 409"
        );
    }

    fn price_row(id: &str, product_id: &str, currency: &str, active: bool) -> StripePriceResponse {
        StripePriceResponse {
            id: id.into(),
            product_id: product_id.into(),
            unit_amount: Some(900),
            currency: currency.into(),
            recurring_interval: Some("month".into()),
            recurring_interval_count: Some(1),
            active,
        }
    }

    #[test]
    fn same_key_conflicts_and_currency_or_interval_differences_do_not() {
        let existing = price_row("price_a", "prod_1", "usd", true);
        let same = ActivePriceKey::of(&price_row("price_b", "prod_1", "usd", true));
        assert_eq!(
            ActivePriceKey::of(&existing),
            same,
            "same key must compare equal"
        );

        let other_currency = ActivePriceKey::of(&price_row("price_b", "prod_1", "eur", true));
        assert_ne!(ActivePriceKey::of(&existing), other_currency);

        let mut yearly = price_row("price_b", "prod_1", "usd", true);
        yearly.recurring_interval = Some("year".into());
        assert_ne!(ActivePriceKey::of(&existing), ActivePriceKey::of(&yearly));

        let mut quarterly = price_row("price_b", "prod_1", "usd", true);
        quarterly.recurring_interval_count = Some(3);
        assert_ne!(
            ActivePriceKey::of(&existing),
            ActivePriceKey::of(&quarterly)
        );

        let other_product = ActivePriceKey::of(&price_row("price_b", "prod_2", "usd", true));
        assert_ne!(ActivePriceKey::of(&existing), other_product);
    }

    #[test]
    fn missing_interval_count_normalizes_to_one_for_recurring() {
        let mut existing = price_row("price_a", "prod_1", "usd", true);
        existing.recurring_interval_count = None; // dunite left it unset
        let requested = ActivePriceKey {
            product_id: "prod_1".into(),
            currency: "usd".into(),
            interval: Some("month".into()),
            interval_count: Some(1),
        };
        assert_eq!(ActivePriceKey::of(&existing), requested);
    }

    #[test]
    fn one_time_prices_bucket_separately_from_recurring() {
        let mut one_time = price_row("price_a", "prod_1", "usd", true);
        one_time.recurring_interval = None;
        one_time.recurring_interval_count = None;
        let key = ActivePriceKey::of(&one_time);
        assert_eq!(key.interval, None);
        assert_eq!(key.interval_count, None);

        let recurring = ActivePriceKey::of(&price_row("price_b", "prod_1", "usd", true));
        assert_ne!(key, recurring, "one-time and monthly must not collide");

        let second_one_time = ActivePriceKey::of(&{
            let mut p = price_row("price_c", "prod_1", "usd", true);
            p.recurring_interval = None;
            p.recurring_interval_count = None;
            p
        });
        assert_eq!(
            key, second_one_time,
            "two one-time same-currency prices collide"
        );
    }

    #[test]
    fn find_active_conflict_ignores_archived_and_the_ignored_id() {
        let key = ActivePriceKey::of(&price_row("price_active", "prod_1", "usd", true));

        // An archived row with the same key does not conflict.
        let archived_only = [price_row("price_arch", "prod_1", "usd", false)];
        assert!(find_active_conflict(&archived_only, &key, None).is_none());

        // An active row with the same key does.
        let with_active = [
            price_row("price_arch", "prod_1", "usd", false),
            price_row("price_live", "prod_1", "usd", true),
        ];
        assert_eq!(
            find_active_conflict(&with_active, &key, None).map(|p| p.id.as_str()),
            Some("price_live")
        );

        // Ignoring the only active match clears the conflict (unarchive of self).
        assert!(find_active_conflict(&with_active, &key, Some("price_live")).is_none());
    }

    #[test]
    fn refusal_message_names_the_price_and_amount() {
        let existing = price_row("price_1U33Rl", "prod_1", "usd", true);
        let msg = refuse_duplicate_price(&existing).to_string();
        assert!(
            msg.contains("price_1U33Rl"),
            "names the conflicting id: {msg}"
        );
        assert!(msg.contains("$9.00"), "names the formatted amount: {msg}");
        assert!(msg.contains("Replace"), "points at Replace: {msg}");
    }

    // -- BUNYIP-532: permission report assembly --

    use super::{build_permission_report, ProbeStatus, REQUIRED_PERMISSIONS};

    fn status_of<'a>(
        report: &'a super::StripePermissionReport,
        key: &str,
    ) -> &'a super::StripePermissionCheck {
        report
            .checks
            .iter()
            .find(|c| c.permission == key)
            .unwrap_or_else(|| panic!("missing check for {key}"))
    }

    /// No saved key: nothing is claimed tested, and the checklist still lists
    /// every permission bunyip needs so the admin knows what to grant.
    #[test]
    fn report_unconfigured_lists_all_as_untested() {
        let r = build_permission_report(None);
        assert!(!r.configured);
        assert_eq!(r.key_status, "not_configured");
        assert_eq!(r.checks.len(), REQUIRED_PERMISSIONS.len());
        assert!(r.checks.iter().all(|c| c.status == ProbeStatus::Untested));
    }

    /// The reported incident: the Webhook Endpoints probe comes back missing.
    /// It is flagged missing while the other two tested ones pass, and the
    /// checkout-time permissions stay untested (not falsely reported as passing).
    #[test]
    fn report_flags_the_missing_probed_permission_only() {
        let r = build_permission_report(Some((
            ProbeStatus::Granted,
            ProbeStatus::Granted,
            ProbeStatus::Missing,
        )));
        assert!(r.configured);
        assert_eq!(r.key_status, "ok");
        assert_eq!(status_of(&r, "products").status, ProbeStatus::Granted);
        assert_eq!(status_of(&r, "prices").status, ProbeStatus::Granted);
        assert_eq!(
            status_of(&r, "webhook_endpoints").status,
            ProbeStatus::Missing
        );
        // Checkout-time permissions are listed but not live-tested.
        for key in [
            "customers",
            "checkout_sessions",
            "subscriptions",
            "invoices",
        ] {
            assert_eq!(status_of(&r, key).status, ProbeStatus::Untested);
        }
    }

    /// A rejected key is the key's fault: `key_status` says so once, rather than
    /// the panel reading as "three separate permissions missing".
    #[test]
    fn report_key_rejected_when_any_probe_rejects_the_key() {
        let r = build_permission_report(Some((
            ProbeStatus::KeyRejected,
            ProbeStatus::KeyRejected,
            ProbeStatus::KeyRejected,
        )));
        assert!(r.configured);
        assert_eq!(r.key_status, "rejected");
    }

    /// Every tested permission carries the access level and stage the admin
    /// needs to act on; the three admin-side ones are the live-tested set.
    #[test]
    fn report_carries_access_level_and_stage() {
        let r = build_permission_report(Some((
            ProbeStatus::Granted,
            ProbeStatus::Granted,
            ProbeStatus::Granted,
        )));
        assert_eq!(status_of(&r, "products").access, "Write");
        assert_eq!(status_of(&r, "products").when, "admin");
        assert_eq!(status_of(&r, "invoices").access, "Read");
        assert_eq!(status_of(&r, "invoices").when, "checkout");
        let admin_tested = r.checks.iter().filter(|c| c.when == "admin").count();
        assert_eq!(admin_tested, 3);
    }

    // -- BUNYIP-512: plan resolution + archive-refusal message --

    use super::{plan_for_price, plan_for_product, refuse_archive};
    use crate::models::tier::TierConfigRow;

    fn tier_row() -> TierConfigRow {
        TierConfigRow {
            id: 1,
            lifetime_slots: None,
            early_adopter_slots: None,
            early_adopter_trial_days: None,
            standard_trial_days: None,
            free_price_id: Some("price_free".into()),
            early_adopter_price_id: Some("price_ea".into()),
            standard_price_id: Some("price_std".into()),
            lifetime_product_id: Some("prod_life".into()),
            early_adopter_product_id: Some("prod_ea".into()),
            standard_product_id: Some("prod_std".into()),
            pricing_enabled: true,
            lifetime_visible: true,
            early_adopter_visible: true,
            standard_visible: true,
            orgs_enabled: false,
            updated_at: chrono::Utc::now(),
            updated_by: None,
        }
    }

    #[test]
    fn plan_for_product_matches_by_product_id_and_by_price_id() {
        let t = tier_row();

        // Matched by the product-id column.
        let by_product = plan_for_product(&t, "prod_std", &["price_std".into()]);
        assert_eq!(by_product.tiers, vec!["standard".to_string()]);
        assert_eq!(by_product.price_ids, vec!["price_std".to_string()]);

        // Matched by a price id even when the product-id column is unset for
        // that tier (e.g. `free`, which has no product column).
        let by_price = plan_for_product(&t, "prod_unknown", &["price_free".into()]);
        assert_eq!(by_price.tiers, vec!["free".to_string()]);

        // A product nothing maps to yields no tiers (but still carries its
        // prices, so a locked-price holder is still guarded).
        let none = plan_for_product(&t, "prod_orphan", &["price_orphan".into()]);
        assert!(none.tiers.is_empty());
        assert_eq!(none.price_ids, vec!["price_orphan".to_string()]);
    }

    #[test]
    fn plan_for_product_matches_lifetime_by_its_derived_product() {
        // BUNYIP-517: free and lifetime share the $0 free price, so lifetime has
        // no dedicated price column; it is matched by its derived product id.
        let t = tier_row();
        let plan = plan_for_product(&t, "prod_life", &[]);
        assert_eq!(plan.tiers, vec!["lifetime".to_string()]);
    }

    #[test]
    fn plan_for_price_resolves_tiers_from_the_single_price() {
        let t = tier_row();
        let plan = plan_for_price(&t, "price_ea");
        assert_eq!(plan.tiers, vec!["early_adopter".to_string()]);
        assert_eq!(plan.price_ids, vec!["price_ea".to_string()]);

        let orphan = plan_for_price(&t, "price_orphan");
        assert!(orphan.tiers.is_empty());
    }

    #[test]
    fn refuse_archive_pluralizes_and_names_the_count() {
        let one = refuse_archive("product", 1);
        assert!(one.to_string().contains("1 member is on it"), "{one}");
        let many = refuse_archive("price", 12);
        assert!(many.to_string().contains("12 members are on it"), "{many}");
    }

    // -- BUNYIP-513: unarchive --

    /// Return the source body of `pub async fn <name>` (up to the next
    /// column-0 `\n}`), for asserting a handler's shape without a live Stripe.
    fn handler_body(name: &str) -> String {
        let src = include_str!("admin_stripe.rs");
        let marker = format!("\npub async fn {name}(");
        let after = src.split_once(&marker).expect("handler present").1;
        after.split_once("\n}").expect("handler body").0.to_string()
    }

    /// BUNYIP-513 AC: unarchiving a product sets `active = true` and sends NO
    /// metadata (so `update_product` leaves the map intact and the app tag
    /// survives). The metadata argument to `update_product` must be `None`.
    #[test]
    fn unarchive_product_sends_active_true_and_no_metadata() {
        let body = handler_body("unarchive_stripe_product");
        assert!(
            body.contains("update_product(&product_id, None, None, None, Some(true))"),
            "unarchive must call update_product with metadata = None and active = Some(true); body was:\n{body}"
        );
    }

    /// BUNYIP-513 AC: unarchiving a product issues no price mutation - the
    /// restore is product-only and each price is restored explicitly.
    #[test]
    fn unarchive_product_issues_no_price_update() {
        let body = handler_body("unarchive_stripe_product");
        for forbidden in ["archive_price", "unarchive_price", "create_price"] {
            assert!(
                !body.contains(forbidden),
                "product unarchive must not touch prices, found `{forbidden}` in body:\n{body}"
            );
        }
    }

    /// BUNYIP-513: the single-price unarchive restores exactly that price.
    #[test]
    fn unarchive_price_restores_the_one_price() {
        let body = handler_body("unarchive_stripe_price");
        assert!(
            body.contains("unarchive_price(&price_id)"),
            "must call StripeService::unarchive_price on the path id; body was:\n{body}"
        );
    }
}
