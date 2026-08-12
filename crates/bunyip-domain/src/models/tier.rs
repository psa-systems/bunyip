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
    /// BUNYIP-512: the lifetime tier is sold as a one-time Stripe price. The
    /// column has existed since `20260429000045_add_price_ids_to_tier_config.sql`
    /// but was not mapped here; the archive member-guard tier resolution reads
    /// every price/product column, so it must be selectable.
    pub lifetime_price_id: Option<String>,
    pub early_adopter_price_id: Option<String>,
    pub standard_price_id: Option<String>,
    pub lifetime_product_id: Option<String>,
    pub early_adopter_product_id: Option<String>,
    pub standard_product_id: Option<String>,
    /// BUNYIP-487: publish switch for the public `/pricing` page. `NOT NULL`
    /// with a `false` default, so unlike the nullable columns above it has no
    /// env fallback.
    pub pricing_enabled: bool,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

// DEV-517: the response shape is shared with a8n-tools via `dunite-user-core`.
// `TierConfigRow` above stays here because it derives `sqlx::FromRow` and the two
// consumers are on different sqlx majors (a8n 0.7, bunyip 0.8).
pub use dunite_user_core::TierConfigResponse;

/// BUNYIP-487: the shared response plus bunyip's own `pricing_enabled` switch.
/// Flattened, so the wire shape stays the shared one with one field added and
/// `dunite-user-core` keeps a single definition for both consumers.
#[derive(Debug, serde::Serialize)]
pub struct TierConfigWithPricing {
    #[serde(flatten)]
    pub config: TierConfigResponse,
    pub pricing_enabled: bool,
}
