//! Membership and payment models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Membership response for API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipResponse {
    pub status: String,
    pub price_locked: bool,
    pub locked_price_amount: Option<i32>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
    pub grace_period_end: Option<DateTime<Utc>>,
}

/// Admin membership response (sourced from users table, Stripe data fetched on demand)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminMembershipResponse {
    pub user_id: Uuid,
    pub user_email: String,
    pub stripe_customer_id: Option<String>,
    pub status: String,
    pub membership_tier: String,
    pub membership_override_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}
