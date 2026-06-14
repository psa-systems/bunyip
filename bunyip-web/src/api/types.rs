//! Data model ported from `src/types/index.ts`.
//!
//! Field names match the backend JSON exactly (snake_case), so these structs
//! deserialize straight off the `data` envelope. Enums use
//! `rename_all = "snake_case"` to match the string discriminants. Date/time
//! fields are kept as `String` (ISO-8601) to mirror the TS `string` typing;
//! pages parse them with `chrono` where they need arithmetic.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Subscriber,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipStatus {
    None,
    Active,
    PastDue,
    Canceled,
    Incomplete,
    GracePeriod,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionTier {
    Lifetime,
    Free,
    EarlyAdopter,
    Standard,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub role: UserRole,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    pub membership_status: MembershipStatus,
    pub price_locked: bool,
    pub locked_price_id: Option<String>,
    pub locked_price_amount: Option<i64>,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    pub subscription_tier: SubscriptionTier,
    pub trial_ends_at: Option<String>,
    pub lifetime_member: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthResponse {
    pub user: User,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetupStatus {
    pub setup_required: bool,
    pub email_enabled: bool,
    pub stripe_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Application {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub version: Option<String>,
    pub source_code_url: Option<String>,
    pub subdomain: Option<String>,
    pub is_accessible: bool,
    pub maintenance_mode: bool,
    pub maintenance_message: Option<String>,
    /// Group membership (BUNYIP-100); `None` = ungrouped. Used to group the
    /// applications page under group headings.
    #[serde(default)]
    pub group_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Membership {
    pub status: MembershipStatus,
    pub price_locked: bool,
    pub locked_price_amount: Option<i64>,
    pub current_period_end: Option<String>,
    pub cancel_at_period_end: bool,
    pub grace_period_end: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i64,
    #[serde(default)]
    pub page_size: Option<i64>,
    pub total_pages: i64,
}

/// `GET /v1/applications` returns `{ applications: [...] }` inside the data
/// envelope (see `src/api/applications.ts`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationList {
    pub applications: Vec<Application>,
}

// ---------------------------------------------------------------------------
// Membership / billing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckoutSessionResponse {
    pub checkout_url: String,
    pub session_id: String,
}

/// `GET /v1/memberships/payments`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripePaymentResponse {
    pub id: String,
    pub amount: i64,
    pub currency: String,
    pub status: Option<String>,
    pub created: i64,
    pub invoice_pdf: Option<String>,
}

/// `GET /v1/billing/invoices`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeInvoice {
    pub id: String,
    pub amount_paid: i64,
    pub currency: String,
    pub status: Option<String>,
    pub invoice_pdf: Option<String>,
    pub hosted_invoice_url: Option<String>,
    pub created: i64,
    pub description: Option<String>,
    pub number: Option<String>,
}

// ---------------------------------------------------------------------------
// Feedback
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackStatus {
    New,
    Reviewed,
    Responded,
    Closed,
}

impl FeedbackStatus {
    /// snake_case wire value, matching the serde discriminant. Single source
    /// for the status string the BFF sends to bunyip-api.
    pub fn as_str(&self) -> &'static str {
        match self {
            FeedbackStatus::New => "new",
            FeedbackStatus::Reviewed => "reviewed",
            FeedbackStatus::Responded => "responded",
            FeedbackStatus::Closed => "closed",
        }
    }
}

impl AsRef<str> for FeedbackStatus {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

// ---------------------------------------------------------------------------
// 2FA
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwoFactorSetupResponse {
    pub otpauth_uri: String,
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryCodesResponse {
    pub codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwoFactorStatusResponse {
    pub enabled: bool,
    pub recovery_codes_remaining: i64,
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DownloadAsset {
    pub asset_name: String,
    pub size_bytes: i64,
    pub content_type: String,
    pub download_url: String,
}

/// OCI pull coordinates for a product (mirrors the API's `AppOciImage`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciImage {
    /// Public registry hostname for `docker login`.
    pub registry: String,
    /// Repository inside the registry (the application slug).
    pub repository: String,
    /// The pinned image tag (the only tag the registry serves).
    pub tag: String,
    /// Full pull reference: `{registry}/{repository}:{tag}`.
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppDownloadGroup {
    pub app_slug: String,
    pub app_display_name: String,
    pub icon_url: Option<String>,
    /// Version of the binary assets; EMPTY for OCI-only products. Kept a
    /// plain string (not `Option`) to match the API's wire format, which
    /// stays a required string for compatibility with older clients.
    pub release_tag: String,
    pub assets: Vec<DownloadAsset>,
    /// OCI pull info, when the product has a pullable container image.
    /// `default` so this client also parses responses from an older API
    /// that does not send the field.
    #[serde(default)]
    pub oci: Option<OciImage>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DownloadGroups {
    pub groups: Vec<AppDownloadGroup>,
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminStatsResponse {
    pub total_users: i64,
    pub active_members: i64,
    pub past_due_members: i64,
    pub grace_period_members: i64,
    pub total_applications: i64,
    pub active_applications: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: String,
    pub email: String,
    pub role: UserRole,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    pub membership_status: MembershipStatus,
    pub subscription_tier: SubscriptionTier,
    pub lifetime_member: bool,
    pub created_at: String,
    pub last_login_at: Option<String>,
    pub grace_period_end: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminMembership {
    pub user_id: String,
    pub user_email: String,
    pub stripe_customer_id: Option<String>,
    pub status: String,
    pub subscription_tier: String,
    pub subscription_override_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminAuditLog {
    pub id: String,
    pub actor_id: Option<String>,
    pub actor_email: Option<String>,
    pub actor_role: Option<String>,
    pub actor_ip_address: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    #[serde(default)]
    pub old_values: Option<Value>,
    #[serde(default)]
    pub new_values: Option<Value>,
    #[serde(default)]
    pub metadata: Option<Value>,
    pub is_admin_action: bool,
    pub severity: String,
    pub created_at: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminApplication {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub is_active: bool,
    pub maintenance_mode: bool,
    pub maintenance_message: Option<String>,
    pub subdomain: Option<String>,
    pub container_name: String,
    pub version: Option<String>,
    pub source_code_url: Option<String>,
    pub sort_order: i64,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub requires_entitlement: bool,
    // Whether this is a hosted app (hub launch tile) or a catalog-only
    // distribution product. Defaults to hosted to match the DB column default.
    #[serde(default = "default_true")]
    pub is_hosted: bool,
    // Distribution config, for prefilling the admin edit form. The backend
    // serialises these straight off the `Application` model (snake_case).
    #[serde(default)]
    pub artifact_source: Option<String>,
    #[serde(default)]
    pub forgejo_owner: Option<String>,
    #[serde(default)]
    pub forgejo_repo: Option<String>,
    #[serde(default)]
    pub forgejo_package: Option<String>,
    #[serde(default)]
    pub pinned_release_tag: Option<String>,
    #[serde(default)]
    pub oci_image_owner: Option<String>,
    #[serde(default)]
    pub oci_image_name: Option<String>,
    #[serde(default)]
    pub pinned_image_tag: Option<String>,
    // Group membership (BUNYIP-100); `None` = ungrouped. Prefills the group
    // selector on the application edit form.
    #[serde(default)]
    pub group_id: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct UserEntitlement {
    pub application_id: String,
    pub slug: String,
    pub display_name: String,
    #[serde(default)]
    pub requires_entitlement: bool,
    pub granted_at: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminApplicationList {
    pub applications: Vec<AdminApplication>,
}

/// An application group (BUNYIP-100). Shared by the admin management page and
/// the user-facing grouping of the applications list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationGroup {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub sort_order: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationGroupList {
    pub groups: Vec<ApplicationGroup>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminFeedbackSummary {
    pub id: String,
    pub name: Option<String>,
    pub email_masked: Option<String>,
    pub subject: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub message_excerpt: String,
    /// Mirrors the bunyip-api summary field added in BUNYIP-84 so the admin
    /// row can show the captured `?from=` path. `#[serde(default)]` keeps
    /// rolling-deploy compatibility: an older API that does not emit the
    /// field deserializes as `None`.
    #[serde(default)]
    pub page_path: Option<String>,
    pub status: FeedbackStatus,
    pub created_at: String,
    pub responded_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminFeedbackDetail {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    /// BUNYIP-94: the API also emits a masked form (e.g.
    /// `y***@niceguyit.biz`) alongside the raw email. The detail view
    /// renders the masked form because admins do not need the unmasked
    /// address to reply (the API holds the address and routes the
    /// response email server-side). `#[serde(default)]` keeps an older
    /// API that does not emit the field deserialize-compatible.
    #[serde(default)]
    pub email_masked: Option<String>,
    pub subject: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub message: String,
    pub page_path: Option<String>,
    pub status: FeedbackStatus,
    pub admin_response: Option<String>,
    pub created_at: String,
    /// Wall-clock timestamp the admin replied at, populated by the API on
    /// successful respond. `#[serde(default)]` keeps an older API that
    /// does not send the field deserialize-compatible.
    #[serde(default)]
    pub responded_at: Option<String>,
    /// Files attached to the submission. `#[serde(default)]` so an older
    /// API that does not emit the field deserializes as an empty list.
    #[serde(default)]
    pub attachments: Vec<FeedbackAttachmentMeta>,
}

/// Per-file metadata on a feedback detail response. Mirrors bunyip-api's
/// `FeedbackAttachmentMeta`. The binary is fetched on demand through the
/// BFF proxy at `/admin/feedback/{id}/attachments/{attachment_id}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedbackAttachmentMeta {
    pub id: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: i64,
}

/// Mirror of bunyip-api's `ArchivedFeedbackItem`. Powers the dedicated
/// archive list page; only the fields the SSR row needs are bound.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArchivedFeedback {
    pub id: String,
    pub archived_at: String,
    pub name: Option<String>,
    /// API returns the unmasked email here. Admins can already see it on
    /// the active list once they open the detail page, so exposing it on
    /// the archive list is consistent.
    pub email: Option<String>,
    pub subject: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub message_excerpt: String,
    pub original_status: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeConfigResponse {
    pub secret_key_masked: Option<String>,
    pub webhook_secret_masked: Option<String>,
    pub has_secret_key: bool,
    pub has_webhook_secret: bool,
    pub app_tag: String,
    pub updated_at: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TierConfigResponse {
    pub lifetime_slots: i64,
    pub early_adopter_slots: i64,
    pub early_adopter_trial_days: i64,
    pub standard_trial_days: i64,
    pub free_price_id: Option<String>,
    pub early_adopter_price_id: Option<String>,
    pub standard_price_id: Option<String>,
    pub source: String,
    pub lifetime_slots_used: i64,
    pub early_adopter_slots_used: i64,
    #[serde(default)]
    pub updated_at: String,
    pub updated_by: Option<String>,
}
