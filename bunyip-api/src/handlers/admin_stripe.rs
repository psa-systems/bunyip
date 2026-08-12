//! Admin Stripe management handlers
//!
//! Endpoints for managing Stripe products, prices, and webhook endpoints.
//! All handlers require the `AdminUser` extractor.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;

use crate::errors::AppError;
use crate::handlers::PricingCache;
use crate::middleware::AdminUser;
use crate::models::stripe::encrypt_secret;
use crate::models::tier::TierConfigRow;
use crate::models::{AuditAction, CreateAuditLog, StripePriceResponse, StripeProductResponse};
use crate::repositories::{
    AuditLogRepository, StripeConfigRepository, TierConfigRepository, UserRepository,
};
use crate::responses::{get_request_id, success, success_no_data};
use crate::services::{stripe_config_from_db_model, stripe_err, AppKeySet, StripeService};

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
struct PlanScope {
    tiers: Vec<String>,
    price_ids: Vec<String>,
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
fn plan_for_price(t: &TierConfigRow, price_id: &str) -> PlanScope {
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
    let products = stripe.list_products().await.map_err(stripe_err)?;
    // One list of all app-tagged prices groups the product -> price sets without
    // an extra Stripe round trip per product.
    let all_prices = stripe.list_prices(None).await.map_err(stripe_err)?;
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
        .map_err(stripe_err)?;
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
        .map_err(stripe_err)?;
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
        .map_err(stripe_err)?;
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
            let mapped = stripe_err(e);
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
        .map_err(stripe_err)?;

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
        .map_err(stripe_err)?;
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
    let price = stripe
        .create_price(
            &body.product_id,
            body.unit_amount,
            &body.currency,
            &body.interval,
        )
        .await
        .map_err(stripe_err)?;
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

    stripe.archive_price(&price_id).await.map_err(stripe_err)?;

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
    let webhooks = stripe.list_webhook_endpoints().await.map_err(stripe_err)?;
    Ok(success(webhooks, request_id))
}

/// POST /v1/admin/stripe/webhooks
///
/// Creates a Stripe webhook endpoint and auto-saves the returned signing secret
/// to the database (encrypted), then reloads the StripeService.
pub async fn create_stripe_webhook(
    req: HttpRequest,
    admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    app_key_set: web::Data<AppKeySet>,
    pool: web::Data<PgPool>,
    body: web::Json<CreateStripeWebhookRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let webhook = stripe
        .create_webhook_endpoint(&body.url, body.enabled_events.clone())
        .await
        .map_err(stripe_err)?;

    // If the webhook creation returned a signing secret, persist it encrypted
    if let Some(ref secret) = webhook.secret {
        let (ws_enc, ws_nonce, key_version) = encrypt_secret(&app_key_set, secret)?;

        let updated = StripeConfigRepository::update(
            &pool,
            None, // secret_key unchanged
            None, // secret_key_nonce unchanged
            Some(ws_enc),
            Some(ws_nonce),
            admin.0.sub,
            key_version,
            None, // app_tag unchanged
            None, // success_url unchanged
            None, // cancel_url unchanged
            None, // trial_period_days unchanged
        )
        .await?;

        // Hot-reload the StripeService with the new webhook secret
        match stripe_config_from_db_model(&updated, &app_key_set) {
            Ok(new_config) => {
                stripe.reload(new_config);
                tracing::info!("Stripe service reloaded with new webhook secret");
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to reload Stripe service after webhook creation");
            }
        }
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
        .map_err(stripe_err)?;
    Ok(success_no_data(request_id))
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
            let mutates = ["create", "update", "archive", "delete", "replace"]
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
}
