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

/// One active session in the user's session list (BUNYIP-137). Mirrors the
/// API's `SessionResponse`. Timestamps stay as ISO-8601 strings per the
/// module convention; the settings page formats them for display.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub device_info: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub current: bool,
}

/// One trusted device (BUNYIP-138). Mirrors the API's `TrustedDeviceInfo`.
#[derive(Debug, Clone, Deserialize)]
pub struct TrustedDeviceInfo {
    pub id: String,
    pub label: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: String,
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
    /// BUNYIP-139: optional profile fields surfaced for the Settings page
    /// Profile panel and the dashboard "fill in your name" banner.
    /// `Option<String>` here is "absent OR cleared"; the dashboard treats
    /// empty / whitespace-only strings as empty for banner purposes.
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    /// BUNYIP-408: ISO-8601 timestamp of the user's most recent avatar upload,
    /// or `None`/absent when no avatar is set. Used purely as an existence flag
    /// and a cache-busting version for the avatar `<img>` URL; the bytes are
    /// fetched separately through the `/me/avatar` BFF proxy. `default` keeps an
    /// older API that predates the field deserialize-compatible.
    #[serde(default)]
    pub avatar_updated_at: Option<String>,
}

impl User {
    /// BUNYIP-408: the name to show in the top-bar profile menu. Prefers the
    /// user's first name; falls back to the email local part (before `@`) when
    /// no first name is set, so the chrome never shows a raw full email address.
    pub fn display_name(&self) -> String {
        match self.first_name.as_deref().map(str::trim) {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => self
                .email
                .split('@')
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or(&self.email)
                .to_string(),
        }
    }

    /// BUNYIP-408: single uppercase initial for the avatar fallback, derived
    /// from [`User::display_name`]. ASCII-uppercased first character; `?` if the
    /// display name is somehow empty.
    pub fn avatar_initial(&self) -> String {
        self.display_name()
            .chars()
            .next()
            .map(|c| c.to_ascii_uppercase().to_string())
            .unwrap_or_else(|| "?".to_string())
    }

    /// BUNYIP-408: same-origin `<img>` src for the avatar, or `None` when the
    /// user has no avatar (render the initials fallback instead). Points at the
    /// bunyip-web BFF proxy (`/me/avatar`) - never the API origin directly - and
    /// carries the `avatar_updated_at` timestamp as a `?v=` cache-buster so a
    /// re-upload is picked up immediately.
    pub fn avatar_src(&self) -> Option<String> {
        self.avatar_updated_at
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|v| format!("/me/avatar?v={}", urlencoding::encode(v)))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthResponse {
    pub user: User,
}

/// Feature-flags probe response (`GET /auth/setup/status`): which optional
/// integrations are wired. BUNYIP-290 removed the `setup_required` flag along
/// with the first-admin setup wizard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetupStatus {
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
    /// Release-notes URL (BUNYIP-343): the admin-set link to this app's release
    /// notes. `None` when unset; the card omits the link then.
    #[serde(default)]
    pub release_notes_url: Option<String>,
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
    /// True when the app has documentation pages (BUNYIP-388 follow-up). The
    /// catalog card shows the Documentation link only when set. `default` for
    /// back-compat with an API that predates the field.
    #[serde(default)]
    pub has_docs: bool,
    /// True when the caller may download/pull this product. False for a
    /// restricted product the caller is not entitled to - the card then shows a
    /// locked "Requires access" state instead of the download affordance
    /// (BUNYIP-395). Defaults to true for back-compat with an API that predates
    /// the field (so an older response still renders the download surface).
    #[serde(default = "default_true")]
    pub has_access: bool,
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
    /// BUNYIP-410 overhaul: soft-deleted (suspended) flag, so the users list can
    /// tell active from suspended rows on the combined "All" view. `default`
    /// keeps an older API that predates the field deserialize-compatible.
    #[serde(default)]
    pub suspended: bool,
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

/// One captured ERROR event from the API's in-memory error-log ring buffer
/// (BUNYIP-327). Mirrors `bunyip_api::error_log::ErrorLogEntry`.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminErrorLog {
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub route: Option<String>,
    #[serde(default)]
    pub client: Option<String>,
    /// Any remaining structured fields the call site attached.
    #[serde(default)]
    pub fields: std::collections::BTreeMap<String, String>,
}

/// Envelope returned by `GET /v1/admin/logs` (BUNYIP-327): the matched entries
/// plus buffer occupancy so the view can report rotation.
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorLogsResponse {
    pub entries: Vec<AdminErrorLog>,
    pub matched: i64,
    pub buffered: i64,
    pub capacity: i64,
}

/// Per-section counts returned by `POST /v1/admin/seed/import` (PSA-52).
#[derive(Debug, Clone, Deserialize)]
pub struct ImportSummary {
    pub groups: i64,
    pub applications: i64,
    pub users: i64,
    pub entitlements: i64,
    pub feedback: i64,
}

/// One embedded seed template as returned by `GET /v1/admin/seed/templates`
/// (PSA-57): its name, description, and per-section counts, for the setup picker.
#[derive(Debug, Clone, Deserialize)]
pub struct SeedTemplateInfo {
    pub name: String,
    pub description: String,
    pub groups: i64,
    pub applications: i64,
    pub users: i64,
    pub entitlements: i64,
    pub feedback: i64,
}

/// One currently-active IP auto-ban as returned by `GET /v1/admin/ip-bans`
/// (BUNYIP-320). Mirrors `bunyip_domain::middleware::auto_ban::BanInfo`: `ip`
/// serializes as a string, `banned_at` / `expires_at` as RFC3339 timestamps.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminIpBan {
    pub ip: String,
    pub reason: String,
    pub strikes: u32,
    pub banned_at: String,
    pub expires_at: String,
}

/// One currently-active throttle as returned by `GET /v1/admin/rate-limits`
/// (BUNYIP-315). Mirrors `bunyip_api::handlers::admin_rate_limits::RateLimitEntry`:
/// `user_id` serializes as a UUID string, `window_start` as an RFC3339 timestamp,
/// and `ip` / user fields are mutually exclusive (IP-keyed rows never carry a
/// user, and vice versa). `action` + `key` together identify the throttle to the
/// reset endpoint (BUNYIP-316).
#[derive(Debug, Clone, Deserialize)]
pub struct AdminRateLimit {
    pub action: String,
    pub key: String,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub ip: Option<String>,
    pub count: i64,
    pub max_requests: i32,
    pub window_start: String,
    pub retry_after: u64,
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
    #[serde(default)]
    pub release_notes_url: Option<String>,
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
    /// BUNYIP-411: request metadata captured at submission for spam tracing.
    /// `submitter_ip` is the external client IP resolved through the trusted
    /// proxy chain (bare host, no CIDR suffix). Both `#[serde(default)]` so an
    /// older API that does not emit them deserializes as `None`.
    #[serde(default)]
    pub submitter_ip: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
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
    // BUNYIP-351: resolved checkout knobs, editable from the Stripe page.
    #[serde(default)]
    pub success_url: String,
    #[serde(default)]
    pub cancel_url: String,
    #[serde(default)]
    pub trial_period_days: u32,
    pub updated_at: Option<String>,
    pub source: String,
}

/// BUNYIP-351: email / SMTP configuration surfaced to the admin settings form.
/// Mirrors `bunyip-api`'s `EmailConfigResponse`; the SMTP password is never
/// returned in plaintext (only a masked hint + `has_smtp_password`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmailConfigResponse {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: i32,
    pub smtp_tls: String,
    pub smtp_username: String,
    pub has_smtp_password: bool,
    pub smtp_password_masked: Option<String>,
    pub from_email: String,
    pub from_name: String,
    pub admin_notification_emails: Vec<String>,
    pub source: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    pub updated_by: Option<String>,
}

/// BUNYIP-351: auto-ban configuration surfaced to the admin settings form.
/// Mirrors `bunyip-api`'s `AutoBanConfigResponse`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoBanConfigResponse {
    pub enabled: bool,
    pub threshold: i64,
    pub window_secs: i64,
    pub ban_duration_secs: i64,
    pub source: String,
    #[serde(default)]
    pub updated_at: String,
    pub updated_by: Option<String>,
}

/// BUNYIP-353: result of restoring an account backup, surfaced back to the
/// admin. Mirrors `bunyip-domain`'s `RestoreReport`.
#[derive(Debug, Clone, Deserialize)]
pub struct RestoreReport {
    pub profile_restored: bool,
    pub entitlements_granted: Vec<String>,
    pub apps: Vec<AppRestoreOutcome>,
}

/// One app's restore outcome inside a [`RestoreReport`].
#[derive(Debug, Clone, Deserialize)]
pub struct AppRestoreOutcome {
    pub slug: String,
    pub status: AppRestoreStatus,
}

/// Restore-time outcome for one app. Mirrors `bunyip-domain`'s
/// `AppRestoreStatus` (internally tagged on `state`).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AppRestoreStatus {
    Restored,
    Skipped { reason: String },
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
    // BUNYIP-122: surface the Stripe product IDs that match the price IDs
    // above so the admin tier-settings form can read + render them. The
    // bunyip-api side already returns these fields (see
    // bunyip-api/src/handlers/admin.rs:1577 UpdateTierConfigRequest and
    // crates/bunyip-domain/src/models/tier.rs:35 TierConfigResponse).
    // Note the naming asymmetry the model carries: `free_price_id` /
    // `lifetime_product_id` both refer to the same tier (the "free" /
    // "lifetime" plan); we mirror it verbatim rather than re-aliasing.
    #[serde(default)]
    pub lifetime_product_id: Option<String>,
    #[serde(default)]
    pub early_adopter_product_id: Option<String>,
    #[serde(default)]
    pub standard_product_id: Option<String>,
    pub source: String,
    pub lifetime_slots_used: i64,
    pub early_adopter_slots_used: i64,
    #[serde(default)]
    pub updated_at: String,
    pub updated_by: Option<String>,
}

/// A per-application documentation page (BUNYIP-388). `body` is markdown.
#[derive(Debug, Clone, Deserialize)]
pub struct AppDoc {
    #[serde(default)]
    pub id: String,
    pub slug: String,
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub sort_order: i32,
}

/// Doc-page metadata for an app's docs index (no body).
#[derive(Debug, Clone, Deserialize)]
pub struct AppDocSummary {
    pub slug: String,
    pub title: String,
    #[serde(default)]
    pub sort_order: i32,
}

#[cfg(test)]
mod tests {
    use super::User;

    /// Build a minimal web `User` from JSON so the many required fields don't
    /// have to be spelled out in every test.
    fn user(first_name: Option<&str>, email: &str, avatar_updated_at: Option<&str>) -> User {
        serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "email": email,
            "role": "subscriber",
            "email_verified": true,
            "two_factor_enabled": false,
            "membership_status": "none",
            "price_locked": false,
            "created_at": "2026-01-01T00:00:00Z",
            "subscription_tier": "standard",
            "lifetime_member": false,
            "first_name": first_name,
            "avatar_updated_at": avatar_updated_at,
        }))
        .expect("valid user json")
    }

    #[test]
    fn display_name_prefers_first_name() {
        assert_eq!(
            user(Some("Ada"), "ada@example.com", None).display_name(),
            "Ada"
        );
    }

    #[test]
    fn display_name_falls_back_to_email_local_part() {
        // BUNYIP-408: no first name -> the local part, never the raw full email.
        assert_eq!(
            user(None, "ada.lovelace@example.com", None).display_name(),
            "ada.lovelace"
        );
        // Whitespace-only first name is treated as unset.
        assert_eq!(
            user(Some("   "), "grace@example.com", None).display_name(),
            "grace"
        );
    }

    #[test]
    fn avatar_initial_is_uppercase_first_char() {
        assert_eq!(
            user(Some("ada"), "ada@example.com", None).avatar_initial(),
            "A"
        );
        assert_eq!(user(None, "zoe@example.com", None).avatar_initial(), "Z");
    }

    #[test]
    fn avatar_src_present_only_when_avatar_set() {
        // No timestamp -> no image src (render the initials fallback instead).
        assert_eq!(
            user(Some("Ada"), "ada@example.com", None).avatar_src(),
            None
        );
        // A timestamp -> a same-origin proxy URL carrying it as a cache-buster.
        let src = user(Some("Ada"), "ada@example.com", Some("2026-07-28T10:00:00Z"))
            .avatar_src()
            .expect("avatar src");
        assert!(src.starts_with("/me/avatar?v="));
        // The ISO-8601 `:` are percent-encoded so the query value is well-formed.
        assert!(src.contains("2026-07-28T10%3A00%3A00Z"));
    }
}
