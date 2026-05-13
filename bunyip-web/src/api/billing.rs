use serde::{Deserialize, Serialize};

use super::{get_json, post_empty, post_json, ApiError};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TierConfig {
    pub tier_key: String,
    pub display_name: String,
    pub trial_days: u32,
    pub seat_count: u32,
    pub slot_limit: Option<u32>,
    pub sort_order: u32,
    pub monthly_price_cents: u32,
    pub features: Vec<String>,
}

pub async fn list_tiers() -> Result<Vec<TierConfig>, ApiError> {
    get_json("/v1/billing/tiers").await
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Trialing,
    Active,
    PastDue,
    Canceled,
    Lifetime,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Subscription {
    pub tier_key: String,
    pub status: SubscriptionStatus,
    pub trial_end: Option<String>,
    pub current_period_end: Option<String>,
    pub cancel_at_period_end: bool,
    pub grace_period_end: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct BillingView {
    pub subscription: Option<Subscription>,
    pub tier: Option<TierConfig>,
}

pub async fn get_billing(slug: &str) -> Result<BillingView, ApiError> {
    get_json(&format!("/v1/orgs/{slug}/billing")).await
}

#[derive(Debug, Serialize)]
pub struct CheckoutRequest {
    pub tier_key: String,
}

#[derive(Debug, Deserialize)]
pub struct CheckoutResponse {
    pub url: String,
}

pub async fn create_checkout(slug: &str, tier_key: String) -> Result<CheckoutResponse, ApiError> {
    post_json(&format!("/v1/orgs/{slug}/billing/checkout"), &CheckoutRequest { tier_key }).await
}

pub async fn cancel_subscription(slug: &str) -> Result<(), ApiError> {
    post_empty(&format!("/v1/orgs/{slug}/billing/cancel")).await
}

pub async fn uncancel_subscription(slug: &str) -> Result<(), ApiError> {
    post_empty(&format!("/v1/orgs/{slug}/billing/uncancel")).await
}
