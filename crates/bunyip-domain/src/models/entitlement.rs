//! Per-product entitlement models (BUNYIP-39).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// How an entitlement was granted. Provenance matters because a Stripe-driven
/// revoke must not clobber a manual admin grant and vice versa.
pub mod entitlement_source {
    pub const ADMIN: &str = "admin";
    pub const STRIPE: &str = "stripe";
    pub const BACKFILL: &str = "backfill";
    /// Granted by the demo-seed loader (`bunyip-api/src/seed.rs`, PMS-709). A
    /// demo-domain reset removes these via the user CASCADE, so they never need
    /// a source-scoped revoke the way Stripe grants do; the distinct value just
    /// keeps demo provenance legible. Permitted by the
    /// `application_entitlements_source_check` constraint since migration
    /// 20260802000010.
    pub const SEED: &str = "seed";
}

/// A grant linking one user to one product. Revoked grants are retained
/// (`revoked_at` set) for audit rather than deleted.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApplicationEntitlement {
    pub user_id: Uuid,
    pub application_id: Uuid,
    pub granted_at: DateTime<Utc>,
    pub granted_by: Option<Uuid>,
    pub source: String,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Admin-facing row: an entitlement joined to its product's display fields, for
/// the "what can this user access" view.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserEntitlementRow {
    pub application_id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub requires_entitlement: bool,
    pub granted_at: DateTime<Utc>,
    pub source: String,
}
