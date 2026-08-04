//! Tier configuration models

use chrono::{DateTime, Utc};
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

// DEV-517: the response shape is shared with a8n-tools via `dunite-user-core`.
// `TierConfigRow` above stays here because it derives `sqlx::FromRow` and the two
// consumers are on different sqlx majors (a8n 0.7, bunyip 0.8).
pub use dunite_user_core::TierConfigResponse;
