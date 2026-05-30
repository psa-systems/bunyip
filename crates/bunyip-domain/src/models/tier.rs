//! Tier configuration models

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// Database row for the `tier_config` singleton table.
#[derive(Debug, sqlx::FromRow)]
pub struct TierConfigRow {
    pub id: i32,
    pub lifetime_slots: Option<i64>,
    pub early_adopter_slots: Option<i64>,
    pub early_adopter_trial_days: Option<i64>,
    pub standard_trial_days: Option<i64>,
    pub free_price_id: Option<String>,
    pub early_adopter_price_id: Option<String>,
    pub standard_price_id: Option<String>,
    pub lifetime_product_id: Option<String>,
    pub early_adopter_product_id: Option<String>,
    pub standard_product_id: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

/// API response for tier configuration.
#[derive(Debug, Serialize)]
pub struct TierConfigResponse {
    pub lifetime_slots: i64,
    pub early_adopter_slots: i64,
    pub early_adopter_trial_days: i64,
    pub standard_trial_days: i64,
    pub free_price_id: Option<String>,
    pub early_adopter_price_id: Option<String>,
    pub standard_price_id: Option<String>,
    pub lifetime_product_id: Option<String>,
    pub early_adopter_product_id: Option<String>,
    pub standard_product_id: Option<String>,
    /// Whether values come from "database" or "environment"
    pub source: &'static str,
    /// How many lifetime slots are currently filled
    pub lifetime_slots_used: i64,
    /// How many early adopter slots are currently filled
    pub early_adopter_slots_used: i64,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}
