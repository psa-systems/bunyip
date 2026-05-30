//! Membership and payment models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Stripe subscription status (kept as Stripe terminology since it's Stripe's API)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StripeSubscriptionStatus {
    Active,
    PastDue,
    Canceled,
    Trialing,
    Incomplete,
    IncompleteExpired,
    Unpaid,
    Paused,
}

impl StripeSubscriptionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            StripeSubscriptionStatus::Active => "active",
            StripeSubscriptionStatus::PastDue => "past_due",
            StripeSubscriptionStatus::Canceled => "canceled",
            StripeSubscriptionStatus::Trialing => "trialing",
            StripeSubscriptionStatus::Incomplete => "incomplete",
            StripeSubscriptionStatus::IncompleteExpired => "incomplete_expired",
            StripeSubscriptionStatus::Unpaid => "unpaid",
            StripeSubscriptionStatus::Paused => "paused",
        }
    }
}

impl From<String> for StripeSubscriptionStatus {
    fn from(s: String) -> Self {
        match s.as_str() {
            "active" => StripeSubscriptionStatus::Active,
            "past_due" => StripeSubscriptionStatus::PastDue,
            "canceled" => StripeSubscriptionStatus::Canceled,
            "trialing" => StripeSubscriptionStatus::Trialing,
            "incomplete" => StripeSubscriptionStatus::Incomplete,
            "incomplete_expired" => StripeSubscriptionStatus::IncompleteExpired,
            "unpaid" => StripeSubscriptionStatus::Unpaid,
            "paused" => StripeSubscriptionStatus::Paused,
            _ => StripeSubscriptionStatus::Incomplete,
        }
    }
}

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
    pub subscription_tier: String,
    pub subscription_override_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// Payment status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    Succeeded,
    Failed,
    Pending,
    Refunded,
}

impl PaymentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PaymentStatus::Succeeded => "succeeded",
            PaymentStatus::Failed => "failed",
            PaymentStatus::Pending => "pending",
            PaymentStatus::Refunded => "refunded",
        }
    }
}

impl From<String> for PaymentStatus {
    fn from(s: String) -> Self {
        match s.as_str() {
            "succeeded" => PaymentStatus::Succeeded,
            "failed" => PaymentStatus::Failed,
            "pending" => PaymentStatus::Pending,
            "refunded" => PaymentStatus::Refunded,
            _ => PaymentStatus::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stripe_status_as_str() {
        assert_eq!(StripeSubscriptionStatus::Active.as_str(), "active");
        assert_eq!(StripeSubscriptionStatus::PastDue.as_str(), "past_due");
        assert_eq!(StripeSubscriptionStatus::Canceled.as_str(), "canceled");
        assert_eq!(StripeSubscriptionStatus::Trialing.as_str(), "trialing");
        assert_eq!(
            StripeSubscriptionStatus::IncompleteExpired.as_str(),
            "incomplete_expired"
        );
        assert_eq!(StripeSubscriptionStatus::Unpaid.as_str(), "unpaid");
        assert_eq!(StripeSubscriptionStatus::Paused.as_str(), "paused");
    }

    #[test]
    fn stripe_status_from_string() {
        assert_eq!(
            StripeSubscriptionStatus::from("active".to_string()),
            StripeSubscriptionStatus::Active
        );
        assert_eq!(
            StripeSubscriptionStatus::from("past_due".to_string()),
            StripeSubscriptionStatus::PastDue
        );
        assert_eq!(
            StripeSubscriptionStatus::from("unknown".to_string()),
            StripeSubscriptionStatus::Incomplete
        );
    }

    #[test]
    fn payment_status_as_str() {
        assert_eq!(PaymentStatus::Succeeded.as_str(), "succeeded");
        assert_eq!(PaymentStatus::Failed.as_str(), "failed");
        assert_eq!(PaymentStatus::Pending.as_str(), "pending");
        assert_eq!(PaymentStatus::Refunded.as_str(), "refunded");
    }

    #[test]
    fn payment_status_from_string() {
        assert_eq!(
            PaymentStatus::from("succeeded".to_string()),
            PaymentStatus::Succeeded
        );
        assert_eq!(
            PaymentStatus::from("failed".to_string()),
            PaymentStatus::Failed
        );
        assert_eq!(
            PaymentStatus::from("unknown".to_string()),
            PaymentStatus::Pending
        );
    }
}
