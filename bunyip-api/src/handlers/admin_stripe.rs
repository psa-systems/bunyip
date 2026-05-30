//! Admin Stripe management handlers
//!
//! Endpoints for managing Stripe products, prices, and webhook endpoints.
//! All handlers require the `AdminUser` extractor.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;

use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::stripe::encrypt_secret;
use crate::repositories::StripeConfigRepository;
use crate::responses::{get_request_id, success, success_no_data};
use crate::services::{EncryptionKeySet, StripeConfig, StripeService};

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
pub async fn list_stripe_products(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let products = stripe.list_products().await?;
    Ok(success(products, request_id))
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
        .await?;
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
        .await?;
    Ok(success(product, request_id))
}

/// DELETE /v1/admin/stripe/products/{id}
pub async fn archive_stripe_product(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let product_id = path.into_inner();
    stripe.archive_product(&product_id).await?;
    Ok(success_no_data(request_id))
}

// =============================================================================
// Prices
// =============================================================================

/// GET /v1/admin/stripe/prices
pub async fn list_stripe_prices(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    query: web::Query<ListStripePricesQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let prices = stripe.list_prices(query.product_id.as_deref()).await?;
    Ok(success(prices, request_id))
}

/// POST /v1/admin/stripe/prices
pub async fn create_stripe_price(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
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
        .await?;
    Ok(success(price, request_id))
}

/// DELETE /v1/admin/stripe/prices/{id}
pub async fn archive_stripe_price(
    req: HttpRequest,
    _admin: AdminUser,
    stripe: web::Data<Arc<StripeService>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let price_id = path.into_inner();
    stripe.archive_price(&price_id).await?;
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
    let webhooks = stripe.list_webhook_endpoints().await?;
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
    stripe_key_set: web::Data<EncryptionKeySet>,
    pool: web::Data<PgPool>,
    body: web::Json<CreateStripeWebhookRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let webhook = stripe
        .create_webhook_endpoint(&body.url, body.enabled_events.clone())
        .await?;

    // If the webhook creation returned a signing secret, persist it encrypted
    if let Some(ref secret) = webhook.secret {
        let (ws_enc, ws_nonce, key_version) = encrypt_secret(&stripe_key_set, secret)?;

        let updated = StripeConfigRepository::update(
            &pool,
            None, // secret_key unchanged
            None, // secret_key_nonce unchanged
            Some(ws_enc),
            Some(ws_nonce),
            admin.0.sub,
            key_version,
            None, // app_tag unchanged
        )
        .await?;

        // Hot-reload the StripeService with the new webhook secret
        match StripeConfig::from_db_model(&updated, &stripe_key_set) {
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
    stripe.delete_webhook_endpoint(&endpoint_id).await?;
    Ok(success_no_data(request_id))
}
