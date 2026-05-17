use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    Member,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRole {
    Owner,
    Admin,
    Member,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Trialing,
    Active,
    PastDue,
    Canceled,
    Lifetime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub role: UserRole,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub lifetime_member: bool,
    pub mfa_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Org {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub owner_user_id: Uuid,
    pub stripe_customer_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: MembershipRole,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub id: Uuid,
    pub org_id: Uuid,
    pub email: String,
    pub role: MembershipRole,
    pub token: String,
    pub invited_by_user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierConfig {
    pub tier_key: String,
    pub display_name: String,
    pub stripe_price_id: Option<String>,
    pub trial_days: u32,
    pub seat_count: u32,
    pub slot_limit: Option<u32>,
    pub sort_order: u32,
    pub monthly_price_cents: u32,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub org_id: Uuid,
    pub stripe_subscription_id: Option<String>,
    pub tier_key: String,
    pub status: SubscriptionStatus,
    pub trial_end: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub cancel_at_period_end: bool,
    pub grace_period_end: Option<DateTime<Utc>>,
    pub subscription_override_by: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClient {
    pub id: Uuid,
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub actor_user_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
    pub action: String,
    pub target: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub is_admin_action: bool,
    pub ts: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackStatus {
    New,
    Triaged,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackAttachment {
    pub filename: String,
    pub size: u64,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feedback {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub org_id: Option<Uuid>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    pub tags: Vec<String>,
    pub message: String,
    pub page_path: Option<String>,
    pub user_agent: Option<String>,
    pub attachments: Vec<FeedbackAttachment>,
    pub forgejo_issue_url: Option<String>,
    pub status: FeedbackStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub id: Uuid,
    pub user_id: Uuid,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}
