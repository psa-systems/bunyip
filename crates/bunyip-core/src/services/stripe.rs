//! Stripe payment service
//!
//! All Stripe state is managed through the Stripe API. This service provides
//! proxy methods for products, prices, subscriptions, invoices, and webhook
//! endpoints. No local database tables are used for Stripe state.

use crate::errors::AppError;
use crate::models::stripe::{
    decrypt_secret, StripeInvoiceResponse, StripePriceResponse, StripeProductResponse,
    StripeSubscriptionItemResponse, StripeSubscriptionResponse, StripeWebhookEndpointResponse,
};
use crate::services::encryption::EncryptionKeySet;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Metadata key used to tag Stripe products belonging to this application.
const APP_TAG_KEY: &str = "app";

/// Stripe configuration
#[derive(Clone, Debug)]
pub struct StripeConfig {
    pub secret_key: String,
    pub webhook_secret: String,
    pub success_url: String,
    pub cancel_url: String,
    /// Stripe Price ID with unit_amount=0 for free/lifetime members
    pub free_price_id: Option<String>,
    /// Application tag stored in product metadata to filter shared Stripe accounts
    pub app_tag: String,
}

impl StripeConfig {
    pub fn from_env() -> Result<Self, AppError> {
        let frontend_origin =
            std::env::var("CORS_ORIGIN").unwrap_or_else(|_| "http://localhost:5173".to_string());
        let base = frontend_origin.trim_end_matches('/');

        Ok(Self {
            secret_key: std::env::var("STRIPE_SECRET_KEY")
                .unwrap_or_else(|_| "sk_test_placeholder".to_string()),
            webhook_secret: std::env::var("STRIPE_WEBHOOK_SECRET")
                .unwrap_or_else(|_| "whsec_placeholder".to_string()),
            success_url: std::env::var("STRIPE_SUCCESS_URL")
                .unwrap_or_else(|_| format!("{base}/checkout/success")),
            cancel_url: std::env::var("STRIPE_CANCEL_URL")
                .unwrap_or_else(|_| format!("{base}/pricing?checkout=canceled")),
            free_price_id: std::env::var("STRIPE_FREE_PRICE_ID").ok(),
            app_tag: std::env::var("STRIPE_APP_TAG")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "a8n-tools".to_string()),
        })
    }

    /// Build a `StripeConfig` from the DB model, decrypting secrets.
    /// Falls back to env vars for any fields not set in the DB.
    pub fn from_db_model(
        db: &crate::models::stripe::StripeConfig,
        key_set: &EncryptionKeySet,
    ) -> Result<Self, AppError> {
        let env_config = Self::from_env()?;

        let secret_key = match (&db.secret_key, &db.secret_key_nonce) {
            (Some(ct), Some(nonce)) => decrypt_secret(key_set, ct, nonce, db.key_version)?,
            _ => env_config.secret_key,
        };
        let webhook_secret = match (&db.webhook_secret, &db.webhook_secret_nonce) {
            (Some(ct), Some(nonce)) => decrypt_secret(key_set, ct, nonce, db.key_version)?,
            _ => env_config.webhook_secret,
        };

        let app_tag = db.app_tag.clone().unwrap_or(env_config.app_tag);

        Ok(Self {
            secret_key,
            webhook_secret,
            success_url: env_config.success_url,
            cancel_url: env_config.cancel_url,
            free_price_id: env_config.free_price_id,
            app_tag,
        })
    }
}

/// Inner state that can be swapped when admin updates Stripe config.
struct StripeServiceInner {
    config: StripeConfig,
    client: Arc<stripe::Client>,
}

/// Stripe service for payment operations.
///
/// Uses `RwLock` internally so the config + client can be hot-reloaded
/// when an admin updates Stripe keys via the dashboard.
pub struct StripeService {
    inner: RwLock<StripeServiceInner>,
}

impl StripeService {
    pub fn new(config: StripeConfig) -> Self {
        let client = stripe::Client::new(&config.secret_key);
        Self {
            inner: RwLock::new(StripeServiceInner {
                config,
                client: Arc::new(client),
            }),
        }
    }

    /// Hot-reload the service with a new config (e.g. after admin update).
    /// Builds a new Stripe client with the updated secret key.
    pub fn reload(&self, config: StripeConfig) {
        let client = stripe::Client::new(&config.secret_key);
        let mut inner = self.inner.write().expect("StripeService lock poisoned");
        inner.config = config;
        inner.client = Arc::new(client);
    }

    /// Snapshot current config + client for use in an async operation.
    fn snapshot(&self) -> (StripeConfig, Arc<stripe::Client>) {
        let inner = self.inner.read().expect("StripeService lock poisoned");
        (inner.config.clone(), inner.client.clone())
    }

    /// Returns `true` when the service holds a real Stripe secret key
    /// (i.e. not the placeholder that `from_env` returns when the env var
    /// is missing).
    pub fn is_configured(&self) -> bool {
        let key = &self
            .inner
            .read()
            .expect("StripeService lock poisoned")
            .config
            .secret_key;
        !key.is_empty() && key != "sk_test_placeholder"
    }

    /// Get the configured $0 price ID for free/lifetime subscriptions.
    pub fn free_price_id(&self) -> Option<String> {
        self.snapshot().0.free_price_id
    }

    /// Get the application tag used for product metadata filtering.
    pub fn app_tag(&self) -> String {
        self.snapshot().0.app_tag
    }

    // ─── Products ────────────────────────────────────────────

    /// List products from Stripe, filtered to only those tagged with this app's tag.
    pub async fn list_products(&self) -> Result<Vec<StripeProductResponse>, AppError> {
        let (config, client) = self.snapshot();

        let mut params = stripe::ListProducts::new();
        params.limit = Some(100);

        let products = stripe::Product::list(&client, &params).await.map_err(|e| {
            tracing::error!(
                error = %e,
                hint = "A product may have a legacy default_price with a non-standard ID \
                        (expected format: price_...). Remove the default_price from the \
                        product in the Stripe dashboard.",
                "Failed to list Stripe products"
            );
            AppError::internal("Failed to load products from Stripe")
        })?;

        Ok(products
            .data
            .into_iter()
            .filter_map(|p| {
                let metadata = p.metadata.unwrap_or_default();
                // Only include products tagged for this application
                if metadata.get(APP_TAG_KEY).map(|v| v.as_str()) != Some(&config.app_tag) {
                    return None;
                }
                Some(StripeProductResponse {
                    id: p.id.to_string(),
                    name: p.name.unwrap_or_default(),
                    description: p.description,
                    active: p.active.unwrap_or(false),
                    metadata,
                    created: p.created.unwrap_or_default(),
                })
            })
            .collect())
    }

    /// Create a product in Stripe, automatically tagging it with this app's tag.
    pub async fn create_product(
        &self,
        name: &str,
        description: Option<&str>,
        metadata: HashMap<String, String>,
    ) -> Result<StripeProductResponse, AppError> {
        let (config, client) = self.snapshot();

        let mut params = stripe::CreateProduct::new(name);
        if let Some(desc) = description {
            params.description = Some(desc);
        }
        // Auto-inject the application tag so this product is filtered correctly
        let mut metadata = metadata;
        metadata.insert(APP_TAG_KEY.to_string(), config.app_tag.clone());
        params.metadata = Some(metadata);

        let product = stripe::Product::create(&client, params)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create Stripe product");
                AppError::internal("Failed to create product")
            })?;

        tracing::info!(product_id = %product.id, name = %name, "Created Stripe product");

        Ok(StripeProductResponse {
            id: product.id.to_string(),
            name: product.name.unwrap_or_default(),
            description: product.description,
            active: product.active.unwrap_or(true),
            metadata: product.metadata.unwrap_or_default(),
            created: product.created.unwrap_or_default(),
        })
    }

    /// Update a product in Stripe
    pub async fn update_product(
        &self,
        product_id: &str,
        name: Option<&str>,
        description: Option<&str>,
        metadata: Option<HashMap<String, String>>,
        active: Option<bool>,
    ) -> Result<StripeProductResponse, AppError> {
        let (_config, client) = self.snapshot();

        let pid: stripe::ProductId = product_id
            .parse()
            .map_err(|_| AppError::validation("product_id", "Invalid product ID"))?;

        let mut params = stripe::UpdateProduct::default();
        if let Some(n) = name {
            params.name = Some(n);
        }
        if let Some(d) = description {
            params.description = Some(d.to_string());
        }
        if let Some(m) = metadata {
            params.metadata = Some(m);
        }
        if let Some(a) = active {
            params.active = Some(a);
        }

        let product = stripe::Product::update(&client, &pid, params)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, product_id = %product_id, "Failed to update Stripe product");
                AppError::internal("Failed to update product")
            })?;

        Ok(StripeProductResponse {
            id: product.id.to_string(),
            name: product.name.unwrap_or_default(),
            description: product.description,
            active: product.active.unwrap_or(true),
            metadata: product.metadata.unwrap_or_default(),
            created: product.created.unwrap_or_default(),
        })
    }

    /// Archive (deactivate) a product in Stripe
    pub async fn archive_product(&self, product_id: &str) -> Result<(), AppError> {
        let (_config, client) = self.snapshot();

        let pid: stripe::ProductId = product_id
            .parse()
            .map_err(|_| AppError::validation("product_id", "Invalid product ID"))?;

        let mut params = stripe::UpdateProduct::default();
        params.active = Some(false);

        stripe::Product::update(&client, &pid, params)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, product_id = %product_id, "Failed to archive Stripe product");
                AppError::internal("Failed to archive product")
            })?;

        tracing::info!(product_id = %product_id, "Archived Stripe product");
        Ok(())
    }

    // ─── Prices ──────────────────────────────────────────────

    /// List prices from Stripe, optionally filtered by product.
    /// When no `product_id` is given, only prices belonging to app-tagged products are returned.
    pub async fn list_prices(
        &self,
        product_id: Option<&str>,
    ) -> Result<Vec<StripePriceResponse>, AppError> {
        let (_config, client) = self.snapshot();

        let mut params = stripe::ListPrices::new();
        params.limit = Some(100);

        let parsed_product_id: Option<stripe::ProductId> = product_id
            .map(|pid| {
                pid.parse()
                    .map_err(|_| AppError::validation("product_id", "Invalid product ID"))
            })
            .transpose()?;
        if let Some(ref pid) = parsed_product_id {
            params.product = Some(stripe::IdOrCreate::Id(pid));
        }

        let prices = stripe::Price::list(&client, &params).await.map_err(|e| {
            tracing::error!(
                error = %e,
                hint = "A price or its parent product may have a legacy ID that doesn't use \
                        the price_... format. Remove or archive the legacy price in the \
                        Stripe dashboard.",
                "Failed to list Stripe prices"
            );
            AppError::internal("Failed to load prices from Stripe")
        })?;

        // When listing all prices (no product_id filter), restrict to app-tagged products
        let tagged_product_ids: Option<std::collections::HashSet<String>> =
            if parsed_product_id.is_none() {
                let products = self.list_products().await?;
                Some(products.into_iter().map(|p| p.id).collect())
            } else {
                None
            };

        Ok(prices
            .data
            .into_iter()
            .filter_map(|p| {
                let product_id = match &p.product {
                    Some(stripe::Expandable::Id(id)) => id.to_string(),
                    Some(stripe::Expandable::Object(obj)) => obj.id.to_string(),
                    None => String::new(),
                };
                // Skip prices whose product is not tagged for this app
                if let Some(ref allowed) = tagged_product_ids {
                    if !allowed.contains(&product_id) {
                        return None;
                    }
                }
                Some(StripePriceResponse {
                    id: p.id.to_string(),
                    product_id,
                    unit_amount: p.unit_amount,
                    currency: p
                        .currency
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "usd".to_string()),
                    recurring_interval: p
                        .recurring
                        .as_ref()
                        .map(|r| format!("{:?}", r.interval).to_lowercase()),
                    active: p.active.unwrap_or(false),
                })
            })
            .collect())
    }

    /// Create a price in Stripe
    pub async fn create_price(
        &self,
        product_id: &str,
        unit_amount: i64,
        currency: &str,
        interval: &str,
    ) -> Result<StripePriceResponse, AppError> {
        let (_config, client) = self.snapshot();

        let cur: stripe::Currency = currency.parse().unwrap_or(stripe::Currency::USD);
        let recurring_interval = match interval {
            "year" => stripe::CreatePriceRecurringInterval::Year,
            "week" => stripe::CreatePriceRecurringInterval::Week,
            "day" => stripe::CreatePriceRecurringInterval::Day,
            _ => stripe::CreatePriceRecurringInterval::Month,
        };

        let mut params = stripe::CreatePrice::new(cur);
        params.product = Some(stripe::IdOrCreate::Id(product_id));
        params.unit_amount = Some(unit_amount);
        params.recurring = Some(stripe::CreatePriceRecurring {
            interval: recurring_interval,
            ..Default::default()
        });

        let price = stripe::Price::create(&client, params).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to create Stripe price");
            AppError::internal("Failed to create price")
        })?;

        tracing::info!(price_id = %price.id, product_id = %product_id, "Created Stripe price");

        let pid = match &price.product {
            Some(stripe::Expandable::Id(id)) => id.to_string(),
            Some(stripe::Expandable::Object(obj)) => obj.id.to_string(),
            None => product_id.to_string(),
        };

        Ok(StripePriceResponse {
            id: price.id.to_string(),
            product_id: pid,
            unit_amount: price.unit_amount,
            currency: price
                .currency
                .map(|c| c.to_string())
                .unwrap_or_else(|| currency.to_string()),
            recurring_interval: Some(interval.to_string()),
            active: price.active.unwrap_or(true),
        })
    }

    /// Archive (deactivate) a price in Stripe
    pub async fn archive_price(&self, price_id: &str) -> Result<(), AppError> {
        let (_config, client) = self.snapshot();

        let pid: stripe::PriceId = price_id
            .parse()
            .map_err(|_| AppError::validation("price_id", "Invalid price ID"))?;

        let mut params = stripe::UpdatePrice::default();
        params.active = Some(false);

        stripe::Price::update(&client, &pid, params)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, price_id = %price_id, "Failed to archive Stripe price");
                AppError::internal("Failed to archive price")
            })?;

        tracing::info!(price_id = %price_id, "Archived Stripe price");
        Ok(())
    }

    // ─── Subscriptions ───────────────────────────────────────

    /// Get the active subscription for a customer from Stripe
    pub async fn get_customer_subscription(
        &self,
        customer_id: &str,
    ) -> Result<Option<StripeSubscriptionResponse>, AppError> {
        let (_config, client) = self.snapshot();

        let cid: stripe::CustomerId = customer_id
            .parse()
            .map_err(|_| AppError::validation("customer_id", "Invalid customer ID"))?;

        let mut params = stripe::ListSubscriptions::new();
        params.customer = Some(cid);
        params.limit = Some(1);

        let subscriptions =
            stripe::Subscription::list(&client, &params)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, customer_id = %customer_id, "Failed to list subscriptions");
                    AppError::internal("Failed to fetch subscription")
                })?;

        Ok(subscriptions.data.into_iter().next().map(|sub| {
            let items: Vec<StripeSubscriptionItemResponse> = sub
                .items
                .data
                .iter()
                .map(|item| {
                    let price_id = item
                        .price
                        .as_ref()
                        .map(|p| p.id.to_string())
                        .unwrap_or_default();
                    let product_id = item
                        .price
                        .as_ref()
                        .and_then(|p| p.product.as_ref())
                        .map(|prod| match prod {
                            stripe::Expandable::Id(id) => id.to_string(),
                            stripe::Expandable::Object(obj) => obj.id.to_string(),
                        })
                        .unwrap_or_default();
                    StripeSubscriptionItemResponse {
                        price_id,
                        product_id,
                        quantity: item.quantity.map(|q| q as u64),
                    }
                })
                .collect();

            StripeSubscriptionResponse {
                id: sub.id.to_string(),
                status: format!("{:?}", sub.status).to_lowercase(),
                current_period_start: sub.current_period_start,
                current_period_end: sub.current_period_end,
                cancel_at_period_end: sub.cancel_at_period_end,
                items,
            }
        }))
    }

    // ─── Invoices ────────────────────────────────────────────

    /// List invoices for a customer from Stripe
    pub async fn list_customer_invoices(
        &self,
        customer_id: &str,
        limit: Option<u64>,
    ) -> Result<Vec<StripeInvoiceResponse>, AppError> {
        let (_config, client) = self.snapshot();

        let cid: stripe::CustomerId = customer_id
            .parse()
            .map_err(|_| AppError::validation("customer_id", "Invalid customer ID"))?;

        let mut params = stripe::ListInvoices::new();
        params.customer = Some(cid);
        params.limit = Some(limit.unwrap_or(50));

        let invoices = stripe::Invoice::list(&client, &params).await.map_err(|e| {
            tracing::error!(error = %e, customer_id = %customer_id, "Failed to list invoices");
            AppError::internal("Failed to list invoices")
        })?;

        Ok(invoices
            .data
            .into_iter()
            .map(|inv| {
                let customer_id = inv.customer.as_ref().map(|c| match c {
                    stripe::Expandable::Id(id) => id.to_string(),
                    stripe::Expandable::Object(obj) => obj.id.to_string(),
                });
                StripeInvoiceResponse {
                    id: inv.id.to_string(),
                    customer_id,
                    amount_paid: inv.amount_paid.unwrap_or(0),
                    currency: inv
                        .currency
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "usd".to_string()),
                    status: inv.status.map(|s| format!("{:?}", s).to_lowercase()),
                    invoice_pdf: inv.invoice_pdf,
                    hosted_invoice_url: inv.hosted_invoice_url,
                    created: inv.created.unwrap_or_default(),
                    description: inv.description,
                    number: inv.number,
                }
            })
            .collect())
    }

    /// Get a single invoice from Stripe by ID
    pub async fn get_invoice(&self, invoice_id: &str) -> Result<StripeInvoiceResponse, AppError> {
        let (_config, client) = self.snapshot();

        let iid: stripe::InvoiceId = invoice_id
            .parse()
            .map_err(|_| AppError::validation("invoice_id", "Invalid invoice ID"))?;

        let inv = stripe::Invoice::retrieve(&client, &iid, &[])
            .await
            .map_err(|e| {
                tracing::error!(error = %e, invoice_id = %invoice_id, "Failed to retrieve invoice");
                AppError::not_found("Invoice")
            })?;

        let customer_id = inv.customer.as_ref().map(|c| match c {
            stripe::Expandable::Id(id) => id.to_string(),
            stripe::Expandable::Object(obj) => obj.id.to_string(),
        });

        Ok(StripeInvoiceResponse {
            id: inv.id.to_string(),
            customer_id,
            amount_paid: inv.amount_paid.unwrap_or(0),
            currency: inv
                .currency
                .map(|c| c.to_string())
                .unwrap_or_else(|| "usd".to_string()),
            status: inv.status.map(|s| format!("{:?}", s).to_lowercase()),
            invoice_pdf: inv.invoice_pdf,
            hosted_invoice_url: inv.hosted_invoice_url,
            created: inv.created.unwrap_or_default(),
            description: inv.description,
            number: inv.number,
        })
    }

    // ─── Webhook Endpoints ───────────────────────────────────

    /// List all webhook endpoints from Stripe
    pub async fn list_webhook_endpoints(
        &self,
    ) -> Result<Vec<StripeWebhookEndpointResponse>, AppError> {
        let (config, _client) = self.snapshot();

        // Use raw reqwest — async-stripe may not expose WebhookEndpoint in current features
        let url = "https://api.stripe.com/v1/webhook_endpoints?limit=100";
        let resp = reqwest::Client::new()
            .get(url)
            .bearer_auth(&config.secret_key)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to list webhook endpoints");
                AppError::internal("Failed to list webhook endpoints")
            })?;

        let body: serde_json::Value = resp.json().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to parse webhook endpoints response");
            AppError::internal("Failed to list webhook endpoints")
        })?;

        let endpoints = body["data"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|ep| StripeWebhookEndpointResponse {
                id: ep["id"].as_str().unwrap_or_default().to_string(),
                url: ep["url"].as_str().unwrap_or_default().to_string(),
                enabled_events: ep["enabled_events"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .filter_map(|e| e.as_str().map(String::from))
                    .collect(),
                status: ep["status"].as_str().unwrap_or("enabled").to_string(),
                secret: None,
            })
            .collect();

        Ok(endpoints)
    }

    /// Create a webhook endpoint in Stripe, returns the endpoint with secret
    pub async fn create_webhook_endpoint(
        &self,
        url: &str,
        events: Vec<String>,
    ) -> Result<StripeWebhookEndpointResponse, AppError> {
        let (config, _client) = self.snapshot();

        let mut form_params: Vec<(String, String)> = Vec::new();
        form_params.push(("url".to_string(), url.to_string()));
        for (i, event) in events.iter().enumerate() {
            form_params.push((format!("enabled_events[{}]", i), event.clone()));
        }

        let resp = reqwest::Client::new()
            .post("https://api.stripe.com/v1/webhook_endpoints")
            .bearer_auth(&config.secret_key)
            .form(&form_params)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create webhook endpoint");
                AppError::internal("Failed to create webhook endpoint")
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(status = %status, body = %body, "Stripe webhook endpoint creation failed");
            return Err(AppError::internal("Failed to create webhook endpoint"));
        }

        let body: serde_json::Value = resp.json().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to parse webhook endpoint response");
            AppError::internal("Failed to create webhook endpoint")
        })?;

        let endpoint = StripeWebhookEndpointResponse {
            id: body["id"].as_str().unwrap_or_default().to_string(),
            url: body["url"].as_str().unwrap_or_default().to_string(),
            enabled_events: body["enabled_events"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect(),
            status: body["status"].as_str().unwrap_or("enabled").to_string(),
            secret: body["secret"].as_str().map(String::from),
        };

        tracing::info!(
            webhook_id = %endpoint.id,
            url = %endpoint.url,
            "Created Stripe webhook endpoint"
        );

        Ok(endpoint)
    }

    /// Delete a webhook endpoint in Stripe
    pub async fn delete_webhook_endpoint(&self, endpoint_id: &str) -> Result<(), AppError> {
        let (config, _client) = self.snapshot();

        let url = format!(
            "https://api.stripe.com/v1/webhook_endpoints/{}",
            endpoint_id
        );

        let resp = reqwest::Client::new()
            .delete(&url)
            .bearer_auth(&config.secret_key)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, endpoint_id = %endpoint_id, "Failed to delete webhook endpoint");
                AppError::internal("Failed to delete webhook endpoint")
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!(status = %status, body = %body, "Stripe webhook endpoint deletion failed");
            return Err(AppError::internal("Failed to delete webhook endpoint"));
        }

        tracing::info!(endpoint_id = %endpoint_id, "Deleted Stripe webhook endpoint");
        Ok(())
    }

    // ─── Existing Methods (Checkout, Customer, etc.) ─────────

    /// Create a Stripe customer linked to a platform user
    pub async fn create_customer(&self, email: &str, user_id: Uuid) -> Result<String, AppError> {
        let (_config, client) = self.snapshot();

        let mut metadata = HashMap::new();
        metadata.insert("user_id".to_string(), user_id.to_string());

        let params = stripe::CreateCustomer {
            email: Some(email),
            metadata: Some(metadata),
            ..Default::default()
        };

        let customer = stripe::Customer::create(&client, params)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, email = %email, "Failed to create Stripe customer");
                AppError::internal("Failed to create payment customer")
            })?;

        tracing::info!(
            customer_id = %customer.id,
            user_id = %user_id,
            "Created Stripe customer"
        );

        Ok(customer.id.to_string())
    }

    /// Create a checkout session with a specific price.
    pub async fn create_checkout_session(
        &self,
        customer_id: &str,
        user_id: Uuid,
        price_id: &str,
    ) -> Result<(String, String), AppError> {
        let (config, client) = self.snapshot();

        let mut metadata = HashMap::new();
        metadata.insert("user_id".to_string(), user_id.to_string());

        let customer_id: stripe::CustomerId = customer_id.parse().map_err(|_| {
            tracing::error!(customer_id = %customer_id, "Invalid Stripe customer ID format");
            AppError::internal("Invalid customer ID")
        })?;

        let params = stripe::CreateCheckoutSession {
            mode: Some(stripe::CheckoutSessionMode::Subscription),
            customer: Some(customer_id),
            line_items: Some(vec![stripe::CreateCheckoutSessionLineItems {
                price: Some(price_id.to_string()),
                quantity: Some(1),
                ..Default::default()
            }]),
            success_url: Some(&config.success_url),
            cancel_url: Some(&config.cancel_url),
            metadata: Some(metadata.clone()),
            subscription_data: Some(stripe::CreateCheckoutSessionSubscriptionData {
                metadata: Some(metadata),
                ..Default::default()
            }),
            ..Default::default()
        };

        let session = stripe::CheckoutSession::create(&client, params)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create Stripe checkout session");
                AppError::internal("Failed to create checkout session")
            })?;

        let session_id = session.id.to_string();
        let checkout_url = session
            .url
            .ok_or_else(|| AppError::internal("Checkout session missing URL"))?;

        tracing::info!(
            session_id = %session_id,
            price_id = %price_id,
            "Created Stripe checkout session"
        );

        Ok((session_id, checkout_url))
    }

    /// Create a $0 subscription for a free/lifetime member so they receive invoices.
    ///
    /// `price_id` must be a recurring Stripe price with unit_amount = 0.
    pub async fn create_free_subscription(
        &self,
        customer_id: &str,
        price_id: &str,
    ) -> Result<String, AppError> {
        let (_config, client) = self.snapshot();

        let cid: stripe::CustomerId = customer_id
            .parse()
            .map_err(|_| AppError::validation("customer_id", "Invalid customer ID"))?;

        let pid: stripe::PriceId = price_id
            .parse()
            .map_err(|_| AppError::validation("price_id", "Invalid price ID"))?;

        let mut params = stripe::CreateSubscription::new(cid);
        params.items = Some(vec![stripe::CreateSubscriptionItems {
            price: Some(pid.to_string()),
            quantity: Some(1),
            ..Default::default()
        }]);

        let subscription = stripe::Subscription::create(&client, params)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create free subscription");
                AppError::internal("Failed to create free subscription")
            })?;

        tracing::info!(
            subscription_id = %subscription.id,
            customer_id = %customer_id,
            "Created $0 subscription for free member"
        );

        Ok(subscription.id.to_string())
    }

    /// Cancel a subscription (at period end or immediately)
    pub async fn cancel_subscription(
        &self,
        subscription_id: &str,
        at_period_end: bool,
    ) -> Result<(), AppError> {
        let sub_id: stripe::SubscriptionId = subscription_id.parse().map_err(|_| {
            tracing::error!(subscription_id = %subscription_id, "Invalid subscription ID format");
            AppError::internal("Invalid subscription ID")
        })?;

        let (_config, client) = self.snapshot();

        if at_period_end {
            let params = stripe::UpdateSubscription {
                cancel_at_period_end: Some(true),
                ..Default::default()
            };
            stripe::Subscription::update(&client, &sub_id, params)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to schedule subscription cancellation");
                    AppError::internal("Failed to cancel subscription")
                })?;
        } else {
            stripe::Subscription::cancel(&client, &sub_id, stripe::CancelSubscription::default())
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to cancel subscription immediately");
                    AppError::internal("Failed to cancel subscription")
                })?;
        }

        tracing::info!(
            subscription_id = %subscription_id,
            at_period_end = at_period_end,
            "Canceled Stripe subscription"
        );

        Ok(())
    }

    /// Reactivate a subscription (remove cancel_at_period_end flag)
    pub async fn reactivate_subscription(&self, subscription_id: &str) -> Result<(), AppError> {
        let (_config, client) = self.snapshot();

        let sub_id: stripe::SubscriptionId = subscription_id.parse().map_err(|_| {
            tracing::error!(subscription_id = %subscription_id, "Invalid subscription ID format");
            AppError::internal("Invalid subscription ID")
        })?;

        let params = stripe::UpdateSubscription {
            cancel_at_period_end: Some(false),
            ..Default::default()
        };

        stripe::Subscription::update(&client, &sub_id, params)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to reactivate subscription");
                AppError::internal("Failed to reactivate subscription")
            })?;

        tracing::info!(subscription_id = %subscription_id, "Reactivated Stripe subscription");

        Ok(())
    }

    /// Create a Stripe billing portal session for self-service management
    pub async fn create_billing_portal_session(
        &self,
        customer_id: &str,
    ) -> Result<String, AppError> {
        let (config, client) = self.snapshot();

        let customer_id: stripe::CustomerId = customer_id.parse().map_err(|_| {
            tracing::error!(customer_id = %customer_id, "Invalid customer ID format");
            AppError::internal("Invalid customer ID")
        })?;

        let mut params = stripe::CreateBillingPortalSession::new(customer_id);
        params.return_url = Some(&config.success_url);

        let session = stripe::BillingPortalSession::create(&client, params)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create billing portal session");
                AppError::internal("Failed to create billing portal session")
            })?;

        Ok(session.url)
    }

    /// Verify Stripe webhook signature (HMAC-SHA256)
    pub fn verify_webhook_signature(
        &self,
        payload: &[u8],
        signature: &str,
    ) -> Result<(), AppError> {
        let mut timestamp = None;
        let mut signatures = Vec::new();

        for part in signature.split(',') {
            if let Some((key, value)) = part.split_once('=') {
                match key.trim() {
                    "t" => timestamp = Some(value.trim()),
                    "v1" => signatures.push(value.trim().to_string()),
                    _ => {}
                }
            }
        }

        let timestamp = timestamp.ok_or_else(|| {
            AppError::validation("signature", "Missing timestamp in webhook signature")
        })?;

        if signatures.is_empty() {
            return Err(AppError::validation("signature", "No v1 signature found"));
        }

        let ts: i64 = timestamp
            .parse()
            .map_err(|_| AppError::validation("signature", "Invalid timestamp"))?;
        let now = chrono::Utc::now().timestamp();
        if (now - ts).abs() > 300 {
            tracing::warn!(
                timestamp = ts,
                now = now,
                "Webhook timestamp outside tolerance window"
            );
            return Err(AppError::validation(
                "signature",
                "Webhook timestamp too old",
            ));
        }

        let payload_str = std::str::from_utf8(payload)
            .map_err(|_| AppError::validation("body", "Invalid UTF-8 in webhook payload"))?;
        let signed_payload = format!("{}.{}", timestamp, payload_str);

        let (config, _) = self.snapshot();
        let mut mac = HmacSha256::new_from_slice(config.webhook_secret.as_bytes())
            .map_err(|_| AppError::internal("Invalid webhook secret key"))?;
        mac.update(signed_payload.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        if signatures.iter().any(|sig| sig == &expected) {
            Ok(())
        } else {
            tracing::warn!("Webhook signature verification failed");
            Err(AppError::Unauthorized)
        }
    }

    /// Create a Stripe Customer and a SetupIntent for $0 card authorization at signup.
    pub async fn create_setup_intent(&self, email: &str) -> Result<(String, String), AppError> {
        let (_config, client) = self.snapshot();

        let customer_params = stripe::CreateCustomer {
            email: Some(email),
            ..Default::default()
        };

        let customer = stripe::Customer::create(&client, customer_params)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, email = %email, "Failed to create Stripe customer for signup");
                AppError::internal("Failed to initialize payment")
            })?;

        let customer_id: stripe::CustomerId = customer
            .id
            .to_string()
            .parse()
            .map_err(|_| AppError::internal("Invalid customer ID returned from Stripe"))?;

        let intent_params = stripe::CreateSetupIntent {
            customer: Some(customer_id),
            ..Default::default()
        };

        let setup_intent = stripe::SetupIntent::create(&client, intent_params)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create SetupIntent for signup");
                AppError::internal("Failed to initialize payment")
            })?;

        let client_secret = setup_intent
            .client_secret
            .ok_or_else(|| AppError::internal("SetupIntent missing client_secret"))?;

        tracing::info!(
            customer_id = %customer.id,
            "Created Stripe customer and SetupIntent for signup"
        );

        Ok((customer.id.to_string(), client_secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> StripeConfig {
        StripeConfig {
            secret_key: "sk_test_xxx".to_string(),
            webhook_secret: "whsec_test_secret".to_string(),
            success_url: "http://localhost/checkout/success".to_string(),
            cancel_url: "http://localhost/cancel".to_string(),
            free_price_id: None,
            app_tag: "a8n-tools".to_string(),
        }
    }

    fn test_service() -> StripeService {
        StripeService::new(test_config())
    }

    // -- Webhook signature verification --

    #[test]
    fn verify_webhook_signature_valid() {
        let service = test_service();
        let payload = b"{\"type\":\"test\"}";
        let timestamp = chrono::Utc::now().timestamp().to_string();

        let signed_payload = format!("{}.{}", timestamp, std::str::from_utf8(payload).unwrap());
        let mut mac = HmacSha256::new_from_slice(b"whsec_test_secret").unwrap();
        mac.update(signed_payload.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());

        let header = format!("t={},v1={}", timestamp, sig);
        assert!(service.verify_webhook_signature(payload, &header).is_ok());
    }

    #[test]
    fn verify_webhook_signature_invalid() {
        let service = test_service();
        let payload = b"{\"type\":\"test\"}";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let header = format!("t={},v1=invalid_signature", timestamp);

        assert!(service.verify_webhook_signature(payload, &header).is_err());
    }

    #[test]
    fn verify_webhook_signature_missing_timestamp() {
        let service = test_service();
        let payload = b"{\"type\":\"test\"}";
        let header = "v1=some_signature";

        assert!(service.verify_webhook_signature(payload, header).is_err());
    }

    #[test]
    fn verify_webhook_signature_no_v1() {
        let service = test_service();
        let payload = b"{\"type\":\"test\"}";
        let header = "t=12345";

        assert!(service.verify_webhook_signature(payload, header).is_err());
    }

    #[test]
    fn verify_webhook_signature_old_timestamp() {
        let service = test_service();
        let payload = b"{\"type\":\"test\"}";
        let old_ts = (chrono::Utc::now().timestamp() - 600).to_string();

        let signed_payload = format!("{}.{}", old_ts, std::str::from_utf8(payload).unwrap());
        let mut mac = HmacSha256::new_from_slice(b"whsec_test_secret").unwrap();
        mac.update(signed_payload.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());

        let header = format!("t={},v1={}", old_ts, sig);
        assert!(service.verify_webhook_signature(payload, &header).is_err());
    }
}
