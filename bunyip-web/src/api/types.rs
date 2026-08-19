//! Data model ported from `src/types/index.ts`.
//!
//! Field names match the backend JSON exactly (snake_case), so these structs
//! deserialize straight off the `data` envelope. Enums decode through `String`
//! via [`wire_enum`], so an unrecognised discriminant becomes `Unknown` instead
//! of failing the response. Date/time fields are kept as `String` (ISO-8601) to
//! mirror the TS `string` typing; pages parse them with `chrono` where they
//! need arithmetic.
//!
//! BUNYIP-506 wire-compatibility rule: every field here carries
//! `#[serde(default)]` unless it is listed in `ESSENTIAL_FIELDS` in
//! `scripts/check-serde-compat.nu`, which gates the rule in CI. A one-release
//! skew between bunyip-web and bunyip-api then degrades (an unknown value
//! renders neutrally) instead of breaking the whole decode.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// BUNYIP-506: declare a wire string enum that tolerates a value this build does
/// not know. Deserialization goes through `String`, so a variant a newer
/// bunyip-api added decodes as `Unknown` instead of failing the whole response
/// with "unknown variant". `#[serde(other)]` cannot do this: serde only allows
/// it on internally or adjacently tagged enums.
macro_rules! wire_enum {
    ($(#[$attr:meta])* $name:ident { $($variant:ident = $wire:literal),+ $(,)? }) => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
        #[serde(from = "String", into = "String")]
        pub enum $name {
            $($variant,)+
            /// A wire value this build does not recognise. Renders as a neutral
            /// label and gates nothing open.
            #[default]
            Unknown,
        }

        impl $name {
            /// The snake_case wire value, matching what bunyip-api emits.
            /// Single source for the string the BFF sends back to the API.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)+
                    Self::Unknown => "unknown",
                }
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                match s.as_str() {
                    $($wire => Self::$variant,)+
                    _ => Self::Unknown,
                }
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> Self {
                v.as_str().to_string()
            }
        }
    };
}

wire_enum! {
    UserRole {
        Subscriber = "subscriber",
        Admin = "admin",
    }
}

wire_enum! {
    MembershipStatus {
        None = "none",
        Active = "active",
        PastDue = "past_due",
        Canceled = "canceled",
        Incomplete = "incomplete",
        GracePeriod = "grace_period",
    }
}

wire_enum! {
    MembershipTier {
        Lifetime = "lifetime",
        Free = "free",
        EarlyAdopter = "early_adopter",
        Standard = "standard",
    }
}

/// One active session in the user's session list (BUNYIP-137). Mirrors the
/// API's `SessionResponse`. Timestamps stay as ISO-8601 strings per the
/// module convention; the settings page formats them for display.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    #[serde(default)]
    pub device_info: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub current: bool,
}

/// One trusted device (BUNYIP-138). Mirrors the API's `TrustedDeviceInfo`.
#[derive(Debug, Clone, Deserialize)]
pub struct TrustedDeviceInfo {
    pub id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub expires_at: String,
}

/// BUNYIP-506: only identity and security carry the auth flow. Everything a
/// login or a 2FA verify does not need (billing, presentation, profile) is
/// `#[serde(default)]` with a least-privileged default, so a membership field
/// renamed or added by a newer bunyip-api cannot abort the decode and block
/// sign-in. Authorization is enforced server-side regardless, so a defaulted
/// tier or status is a presentation degradation, never a widened grant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub role: UserRole,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    #[serde(default = "membership_status_none")]
    pub membership_status: MembershipStatus,
    #[serde(default)]
    pub price_locked: bool,
    #[serde(default)]
    pub locked_price_id: Option<String>,
    #[serde(default)]
    pub locked_price_amount: Option<i64>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    /// v0.13.0 renamed `subscription_tier` to `membership_tier`. The alias
    /// parses a not-yet-restarted API during a rolling deploy; drop it in
    /// v0.15.0 (the contract half of the expand/contract rename).
    #[serde(default, alias = "subscription_tier")]
    pub membership_tier: MembershipTier,
    #[serde(default)]
    pub trial_ends_at: Option<String>,
    #[serde(default)]
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
    /// BUNYIP-413: the "first setup account" flag. Only a super admin sees the
    /// rate-limit / IP-ban management controls; the API enforces the same gate,
    /// so hiding them is presentation, not the security boundary. `default`
    /// keeps an older API that predates the field deserialize-compatible.
    #[serde(default)]
    pub is_super_admin: bool,
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
    #[serde(default)]
    pub email_enabled: bool,
    #[serde(default)]
    pub stripe_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Application {
    pub id: String,
    pub slug: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub source_code_url: Option<String>,
    /// Release-notes URL (BUNYIP-343): the admin-set link to this app's release
    /// notes. `None` when unset; the card omits the link then.
    #[serde(default)]
    pub release_notes_url: Option<String>,
    #[serde(default)]
    pub subdomain: Option<String>,
    #[serde(default)]
    pub is_accessible: bool,
    #[serde(default)]
    pub maintenance_mode: bool,
    #[serde(default)]
    pub maintenance_message: Option<String>,
    /// Group membership (BUNYIP-100); `None` = ungrouped. Used to group the
    /// applications page under group headings.
    #[serde(default)]
    pub group_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Membership {
    #[serde(default)]
    pub status: MembershipStatus,
    #[serde(default)]
    pub price_locked: bool,
    #[serde(default)]
    pub locked_price_amount: Option<i64>,
    #[serde(default)]
    pub current_period_end: Option<String>,
    #[serde(default)]
    pub cancel_at_period_end: bool,
    #[serde(default)]
    pub grace_period_end: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    // `default = "Vec::new"` rather than a bare `default`: the bare form makes
    // serde add a `T: Default` bound to the generated impl, which every item
    // type would then have to satisfy.
    #[serde(default = "Vec::new")]
    pub items: Vec<T>,
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub page: i64,
    #[serde(default)]
    pub page_size: Option<i64>,
    #[serde(default)]
    pub total_pages: i64,
}

/// `GET /v1/applications` returns `{ applications: [...] }` inside the data
/// envelope (see `src/api/applications.ts`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationList {
    #[serde(default)]
    pub applications: Vec<Application>,
}

// ---------------------------------------------------------------------------
// Membership / billing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckoutSessionResponse {
    pub checkout_url: String,
    #[serde(default)]
    pub session_id: String,
}

/// `GET /v1/memberships/payments`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripePaymentResponse {
    pub id: String,
    #[serde(default)]
    pub amount: i64,
    #[serde(default)]
    pub currency: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub created: i64,
    #[serde(default)]
    pub invoice_pdf: Option<String>,
}

/// `GET /v1/billing/invoices`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeInvoice {
    pub id: String,
    #[serde(default)]
    pub amount_paid: i64,
    #[serde(default)]
    pub currency: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub invoice_pdf: Option<String>,
    #[serde(default)]
    pub hosted_invoice_url: Option<String>,
    #[serde(default)]
    pub created: i64,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub number: Option<String>,
}

// ---------------------------------------------------------------------------
// Feedback
// ---------------------------------------------------------------------------

wire_enum! {
    FeedbackStatus {
        New = "new",
        Reviewed = "reviewed",
        Responded = "responded",
        Closed = "closed",
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
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub recovery_codes_remaining: i64,
}

// ---------------------------------------------------------------------------
// Downloads
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DownloadAsset {
    #[serde(default)]
    pub asset_name: String,
    #[serde(default)]
    pub size_bytes: i64,
    #[serde(default)]
    pub content_type: String,
    pub download_url: String,
}

/// OCI pull coordinates for a product (mirrors the API's `AppOciImage`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OciImage {
    /// Public registry hostname for `docker login`.
    #[serde(default)]
    pub registry: String,
    /// Repository inside the registry (the application slug).
    #[serde(default)]
    pub repository: String,
    /// The pinned image tag (the only tag the registry serves).
    #[serde(default)]
    pub tag: String,
    /// Full pull reference: `{registry}/{repository}:{tag}`.
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppDownloadGroup {
    pub app_slug: String,
    #[serde(default)]
    pub app_display_name: String,
    #[serde(default)]
    pub icon_url: Option<String>,
    /// Version of the binary assets; EMPTY for OCI-only products. Kept a
    /// plain string (not `Option`) to match the API's wire format, which
    /// stays a required string for compatibility with older clients.
    #[serde(default)]
    pub release_tag: String,
    #[serde(default)]
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
    #[serde(default)]
    pub groups: Vec<AppDownloadGroup>,
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminStatsResponse {
    #[serde(default)]
    pub total_users: i64,
    #[serde(default)]
    pub active_members: i64,
    #[serde(default)]
    pub past_due_members: i64,
    #[serde(default)]
    pub grace_period_members: i64,
    #[serde(default)]
    pub total_applications: i64,
    #[serde(default)]
    pub active_applications: i64,
}

/// Freshness of one offline IP dataset (BUNYIP-474). Mirrors
/// `bunyip_api::handlers::admin::DatasetHealth`: `age_days` is the whole days
/// since the `.BIN`'s mtime (`None` when unconfigured/unreadable), and the
/// (configured, present, stale) triple distinguishes "operator did not deploy
/// it", "path set but file missing", and "deployed but overdue for a refresh".
#[derive(Debug, Clone, Deserialize)]
pub struct DatasetHealth {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub env_var: String,
    #[serde(default)]
    pub configured: bool,
    #[serde(default)]
    pub present: bool,
    #[serde(default)]
    pub age_days: Option<i64>,
    #[serde(default)]
    pub stale: bool,
}

/// The `health` block of `GET /v1/admin/health`. Only the fields the dashboard
/// renders are captured; the rest of the payload is ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct SystemHealth {
    #[serde(default)]
    pub datasets: Vec<DatasetHealth>,
}

/// Envelope of `GET /v1/admin/health` (`{ health, stats }`).
#[derive(Debug, Clone, Deserialize)]
pub struct SystemHealthResponse {
    pub health: SystemHealth,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub role: UserRole,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub two_factor_enabled: bool,
    #[serde(default = "membership_status_none")]
    pub membership_status: MembershipStatus,
    /// v0.13.0 renamed `subscription_tier` to `membership_tier`. The alias
    /// parses a not-yet-restarted API during a rolling deploy; drop it in
    /// v0.15.0 (the contract half of the expand/contract rename).
    #[serde(default, alias = "subscription_tier")]
    pub membership_tier: MembershipTier,
    #[serde(default)]
    pub lifetime_member: bool,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub last_login_at: Option<String>,
    #[serde(default)]
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
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub actor_email: Option<String>,
    #[serde(default)]
    pub actor_role: Option<String>,
    #[serde(default)]
    pub actor_ip_address: Option<String>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub resource_type: Option<String>,
    #[serde(default)]
    pub resource_id: Option<String>,
    #[serde(default)]
    pub old_values: Option<Value>,
    #[serde(default)]
    pub new_values: Option<Value>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub is_admin_action: bool,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub created_at: String,
}

/// One captured ERROR event from the API's in-memory error-log ring buffer
/// (BUNYIP-327). Mirrors `bunyip_api::error_log::ErrorLogEntry`.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminErrorLog {
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
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
    #[serde(default)]
    pub entries: Vec<AdminErrorLog>,
    #[serde(default)]
    pub matched: i64,
    #[serde(default)]
    pub buffered: i64,
    #[serde(default)]
    pub capacity: i64,
}

/// Per-section counts returned by `POST /v1/admin/seed/import` (PSA-52).
#[derive(Debug, Clone, Deserialize)]
pub struct ImportSummary {
    #[serde(default)]
    pub groups: i64,
    #[serde(default)]
    pub applications: i64,
    #[serde(default)]
    pub users: i64,
    #[serde(default)]
    pub entitlements: i64,
    #[serde(default)]
    pub feedback: i64,
}

/// One embedded seed template as returned by `GET /v1/admin/seed/templates`
/// (PSA-57): its name, description, and per-section counts, for the setup picker.
#[derive(Debug, Clone, Deserialize)]
pub struct SeedTemplateInfo {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub groups: i64,
    #[serde(default)]
    pub applications: i64,
    #[serde(default)]
    pub users: i64,
    #[serde(default)]
    pub entitlements: i64,
    #[serde(default)]
    pub feedback: i64,
}

/// One currently-active IP auto-ban as returned by `GET /v1/admin/ip-bans`
/// (BUNYIP-320). Mirrors `bunyip_domain::middleware::auto_ban::BanInfo`: `ip`
/// serializes as a string, `banned_at` / `expires_at` as RFC3339 timestamps.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminIpBan {
    pub ip: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub strikes: u32,
    #[serde(default)]
    pub banned_at: String,
    #[serde(default)]
    pub expires_at: String,
}

/// Advisory ASN / VPN enrichment for one address as returned by
/// `GET /v1/admin/ip-enrichment?ip=<addr>` (BUNYIP-437). Mirrors
/// `bunyip_api::handlers::admin_ip_enrichment::IpEnrichmentResponse`: `category`
/// and `vpn` are lowercase labels of the classified enums, `is_anonymizing` is
/// the one-bit "looks like a VPN / proxy" summary, and `advisory` is always true
/// (the signal is context for a human, never an automatic abuse verdict). The
/// endpoint returns no data when there is nothing to report, so the client maps
/// it to `Option<IpEnrichment>`.
#[derive(Debug, Clone, Deserialize)]
pub struct IpEnrichment {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub asn: Option<String>,
    #[serde(default)]
    pub organization: Option<String>,
    #[serde(default)]
    pub isp: Option<String>,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub vpn: String,
    #[serde(default)]
    pub is_anonymizing: bool,
    #[serde(default)]
    pub proxy_type: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub threat: Option<String>,
    #[serde(default)]
    pub advisory: bool,
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
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub user_email: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub count: i64,
    #[serde(default)]
    pub max_requests: i32,
    #[serde(default)]
    pub window_start: String,
    #[serde(default)]
    pub retry_after: u64,
}

/// The configured cap/window for one rate-limit action as returned by
/// `GET /v1/admin/rate-limit-configs` (BUNYIP-413). Mirrors
/// `bunyip_api::handlers::admin_rate_limits::RateLimitConfigEntry`:
/// `max_requests` / `window_seconds` are what is enforced, the `default_*`
/// fields are the bootstrap defaults an override departs from, and `overridden`
/// says whether a persisted row is in force (and so whether a revert applies).
#[derive(Debug, Clone, Deserialize)]
pub struct AdminRateLimitConfig {
    pub action: String,
    #[serde(default)]
    pub max_requests: i32,
    #[serde(default)]
    pub window_seconds: i64,
    #[serde(default)]
    pub default_max_requests: i32,
    #[serde(default)]
    pub default_window_seconds: i64,
    #[serde(default)]
    pub overridden: bool,
    #[serde(default)]
    pub updated_at: Option<String>,
}

fn default_true() -> bool {
    true
}

/// BUNYIP-506: least-privileged default for a membership status - "no
/// membership", never a grant inferred from a field the API did not send.
fn membership_status_none() -> MembershipStatus {
    MembershipStatus::None
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminApplication {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub is_active: bool,
    #[serde(default)]
    pub maintenance_mode: bool,
    #[serde(default)]
    pub maintenance_message: Option<String>,
    #[serde(default)]
    pub subdomain: Option<String>,
    #[serde(default)]
    pub container_name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub source_code_url: Option<String>,
    #[serde(default)]
    pub release_notes_url: Option<String>,
    #[serde(default)]
    pub sort_order: i64,
    #[serde(default)]
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
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub requires_entitlement: bool,
    #[serde(default)]
    pub granted_at: String,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminApplicationList {
    #[serde(default)]
    pub applications: Vec<AdminApplication>,
}

/// An application group (BUNYIP-100). Shared by the admin management page and
/// the user-facing grouping of the applications list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApplicationGroup {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
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
    #[serde(default)]
    pub groups: Vec<ApplicationGroup>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminFeedbackSummary {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email_masked: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub message_excerpt: String,
    /// Mirrors the bunyip-api summary field added in BUNYIP-84 so the admin
    /// row can show the captured `?from=` path. `#[serde(default)]` keeps
    /// rolling-deploy compatibility: an older API that does not emit the
    /// field deserializes as `None`.
    #[serde(default)]
    pub page_path: Option<String>,
    #[serde(default)]
    pub status: FeedbackStatus,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub responded_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminFeedbackDetail {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    /// BUNYIP-94: the API also emits a masked form (e.g.
    /// `y***@niceguyit.biz`) alongside the raw email. The detail view
    /// renders the masked form because admins do not need the unmasked
    /// address to reply (the API holds the address and routes the
    /// response email server-side). `#[serde(default)]` keeps an older
    /// API that does not emit the field deserialize-compatible.
    #[serde(default)]
    pub email_masked: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub page_path: Option<String>,
    #[serde(default)]
    pub status: FeedbackStatus,
    #[serde(default)]
    pub admin_response: Option<String>,
    #[serde(default)]
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
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub size_bytes: i64,
}

/// Mirror of bunyip-api's `ArchivedFeedbackItem`. Powers the dedicated
/// archive list page; only the fields the SSR row needs are bound.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArchivedFeedback {
    pub id: String,
    #[serde(default)]
    pub archived_at: String,
    #[serde(default)]
    pub name: Option<String>,
    /// API returns the unmasked email here. Admins can already see it on
    /// the active list once they open the detail page, so exposing it on
    /// the archive list is consistent.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub message_excerpt: String,
    #[serde(default)]
    pub original_status: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StripeConfigResponse {
    #[serde(default)]
    pub secret_key_masked: Option<String>,
    #[serde(default)]
    pub webhook_secret_masked: Option<String>,
    #[serde(default)]
    pub has_secret_key: bool,
    #[serde(default)]
    pub has_webhook_secret: bool,
    #[serde(default)]
    pub app_tag: String,
    // BUNYIP-351: resolved checkout knobs, editable from the Stripe page.
    #[serde(default)]
    pub success_url: String,
    #[serde(default)]
    pub cancel_url: String,
    #[serde(default)]
    pub trial_period_days: u32,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub source: String,
    /// BUNYIP-542: the declared store for the two Stripe secrets
    /// (`SECRETS_STORAGE`).
    #[serde(default)]
    pub secrets_storage: String,
    /// Whether the two secret fields are editable. Defaults to `true` for the
    /// same reason as `EmailConfigResponse::smtp_password_editable`.
    #[serde(default = "default_true")]
    pub secrets_editable: bool,
}

/// BUNYIP-416: a Stripe product surfaced in the admin Stripe panel. Mirrors
/// bunyip-api's `StripeProductResponse` (metadata is omitted here - it is not
/// displayed, and serde ignores the extra field).
#[derive(Debug, Clone, Deserialize)]
pub struct StripeProduct {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub created: i64,
    /// BUNYIP-512: members currently on this product's plan. Drives the
    /// disabled-Archive courtesy in the admin UI (the server guard is
    /// authoritative). Not identity-bearing, so it defaults and is absent from
    /// `ESSENTIAL_FIELDS` in `scripts/check-serde-compat.nu`.
    #[serde(default)]
    pub member_count: i64,
}

/// BUNYIP-416: a Stripe price surfaced in the admin Stripe panel. Mirrors
/// bunyip-api's `StripePriceResponse`. A zero-amount lifetime price has
/// `unit_amount = Some(0)` (not `None`), so it renders as a real "$0.00".
#[derive(Debug, Clone, Deserialize)]
pub struct StripePrice {
    pub id: String,
    pub product_id: String,
    #[serde(default)]
    pub unit_amount: Option<i64>,
    #[serde(default)]
    pub currency: String,
    #[serde(default)]
    pub recurring_interval: Option<String>,
    /// BUNYIP-514: the recurring interval multiplier (monthly = 1, quarterly = 3).
    /// Part of the uniqueness key the duplicate-price warning groups on, so a
    /// monthly and an externally created quarterly price are not flagged as a
    /// pair. `#[serde(default)]` keeps `scripts/check-serde-compat.nu` green.
    #[serde(default)]
    pub recurring_interval_count: Option<i64>,
    #[serde(default)]
    pub active: bool,
    /// BUNYIP-512: members on the tier this price maps to (plus anyone who
    /// locked this price). See [`StripeProduct::member_count`].
    #[serde(default)]
    pub member_count: i64,
}

/// DEV-518: a Stripe webhook endpoint surfaced in the admin Stripe panel.
/// Mirrors bunyip-api's `StripeWebhookEndpointResponse`. `secret` (the signing
/// secret, `whsec_...`) is present ONLY in the create response - Stripe returns
/// it once at creation and never again - so the create flow shows it once for
/// the admin to paste into the Webhook secret field.
#[derive(Debug, Clone, Deserialize)]
pub struct StripeWebhookEndpoint {
    pub id: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub enabled_events: Vec<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub secret: Option<String>,
}

/// BUNYIP-532: one row of the Stripe key permission self-test. Mirrors
/// bunyip-api's `StripePermissionCheck`. `status` is one of `granted`, `missing`,
/// `key_rejected`, `unknown`, `untested` (decoded as a plain string so an added
/// variant never fails the response).
#[derive(Debug, Clone, Deserialize)]
pub struct StripePermissionCheck {
    #[serde(default)]
    pub permission: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub access: String,
    #[serde(default)]
    pub when: String,
    #[serde(default)]
    pub status: String,
}

/// BUNYIP-532: the Stripe key permission self-test result. Mirrors bunyip-api's
/// `StripePermissionReport`.
#[derive(Debug, Clone, Deserialize)]
pub struct StripePermissionReport {
    #[serde(default)]
    pub configured: bool,
    #[serde(default)]
    pub key_status: String,
    #[serde(default)]
    pub checks: Vec<StripePermissionCheck>,
}

/// BUNYIP-561: the admin-managed product branding, from `GET /v1/branding` (and
/// from `GET /v1/admin/branding`, which adds attribution fields this form does
/// not render). Mirrors bunyip-api's `Branding`.
///
/// Every field defaults, and none is in `ESSENTIAL_FIELDS` in
/// `scripts/check-serde-compat.nu`: an absent field degrades to empty, which
/// omits its markup, and that is strictly better than failing the decode and
/// losing the whole record over one missing key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Branding {
    #[serde(default)]
    pub brand_name: String,
    #[serde(default)]
    pub tagline: String,
    #[serde(default)]
    pub meta_description: String,
    #[serde(default)]
    pub og_image_url: String,
    /// BUNYIP-560: the palette. `theme_css` is the raw custom-property block
    /// emitted into `:root`; the two colours are the `theme-color` metas. Empty
    /// means omitted, exactly like the copy above.
    #[serde(default)]
    pub theme_css: String,
    #[serde(default)]
    pub theme_color_light: String,
    #[serde(default)]
    pub theme_color_dark: String,
    /// BUNYIP-560: the asset slots, as the version string their `<img src>`
    /// carries as a cache buster. Empty means the slot is unset, which is what
    /// sends the favicon links back to the committed fallback set and drops the
    /// mark image and the hero mascot from the page entirely.
    #[serde(default)]
    pub mark_version: String,
    #[serde(default)]
    pub favicon_version: String,
    #[serde(default)]
    pub mascot_version: String,
}

impl Branding {
    /// BUNYIP-560: the same-origin URL for a brand asset, or `None` when the
    /// slot is unset. `version` is the record's marker for that slot, so a
    /// re-upload changes the URL and the browser refetches instead of showing
    /// the previous logo until its cache expires.
    fn asset_src(kind: &str, version: &str) -> Option<String> {
        (!version.is_empty()).then(|| format!("/brand/{kind}?v={}", urlencoding::encode(version)))
    }

    /// The uploaded brand mark, or `None` to render the built-in reed-and-eyes
    /// glyph (a shape, not a product's artwork).
    pub fn mark_src(&self) -> Option<String> {
        Self::asset_src("mark", &self.mark_version)
    }

    /// The uploaded hero illustration, or `None`, in which case the hero
    /// renders without one rather than with another product's mascot.
    pub fn mascot_src(&self) -> Option<String> {
        Self::asset_src("mascot", &self.mascot_version)
    }

    /// One derived favicon, or `None` when no source has been uploaded (the
    /// committed set under `assets/` answers instead).
    pub fn favicon_src(&self, kind: &str) -> Option<String> {
        Self::asset_src(kind, &self.favicon_version)
    }
}

/// BUNYIP-351: email / SMTP configuration surfaced to the admin settings form.
/// Mirrors `bunyip-api`'s `EmailConfigResponse`; the SMTP password is never
/// returned in plaintext (only a masked hint + `has_smtp_password`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmailConfigResponse {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: i32,
    #[serde(default)]
    pub smtp_tls: String,
    #[serde(default)]
    pub smtp_username: String,
    /// BUNYIP-432: whether a password is stored - a boolean fact only. The API
    /// no longer sends the password or any masked/truncated form of it (the
    /// field is write-only), so the settings page renders a fixed-length mask
    /// from this flag and never receives the secret.
    #[serde(default)]
    pub has_smtp_password: bool,
    #[serde(default)]
    pub from_email: String,
    #[serde(default)]
    pub from_name: String,
    #[serde(default)]
    pub admin_notification_emails: Vec<String>,
    #[serde(default)]
    pub source: String,
    /// BUNYIP-542: the declared store for the SMTP password
    /// (`SECRETS_STORAGE`). Rendered so the page names the store that owns the
    /// value; the non-secret settings are unaffected by it.
    #[serde(default)]
    pub secrets_storage: String,
    /// Whether the password field is editable. Defaults to `true` so a response
    /// from an api that predates the field keeps the form usable; the server is
    /// the authority either way and answers 409 when the store is read-only.
    #[serde(default = "default_true")]
    pub smtp_password_editable: bool,
    /// BUNYIP-571: inbound IMAP settings. `imap_password_editable` defaults true
    /// so a response from an older api keeps the form usable.
    #[serde(default)]
    pub imap_host: String,
    #[serde(default)]
    pub imap_port: i32,
    #[serde(default)]
    pub imap_username: String,
    #[serde(default)]
    pub imap_mailbox: String,
    #[serde(default)]
    pub imap_enabled: bool,
    #[serde(default)]
    pub has_imap_password: bool,
    #[serde(default = "default_true")]
    pub imap_password_editable: bool,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub updated_by: Option<String>,
}

/// BUNYIP-580: the system-config YAML values, for the admin System settings page.
#[derive(Debug, Clone, Deserialize)]
pub struct SystemConfigResponse {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub cors_origin: String,
    #[serde(default)]
    pub web_origin: String,
    #[serde(default)]
    pub cookie_domain: String,
    #[serde(default)]
    pub login_approval_enabled: bool,
    #[serde(default)]
    pub signup_bot_guard_enabled: bool,
    #[serde(default)]
    pub country_allow: String,
    #[serde(default)]
    pub country_deny: String,
}

/// BUNYIP-433: result of the SMTP "Test connection" probe. `ok` is the headline
/// pass/fail; on failure `stage` is one of `connect` / `tls` / `auth` and
/// `message` is the admin-facing reason.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmtpTestResult {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub stage: String,
    #[serde(default)]
    pub message: String,
}

/// BUNYIP-508: result of the admin "Test email" send. `ok` is the headline
/// pass/fail; `message` is the admin-facing reason (the relay's own text on a
/// failure). Both default: a body that decodes without them reads as a failed
/// send with an empty reason, never as a silent success.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestEmailResult {
    #[serde(default)]
    pub ok: bool,
    #[serde(default)]
    pub message: String,
}

/// BUNYIP-351: auto-ban configuration surfaced to the admin settings form.
/// Mirrors `bunyip-api`'s `AutoBanConfigResponse`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoBanConfigResponse {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub threshold: i64,
    #[serde(default)]
    pub window_secs: i64,
    #[serde(default)]
    pub ban_duration_secs: i64,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub updated_by: Option<String>,
}

/// BUNYIP-353: result of restoring an account backup, surfaced back to the
/// admin. Mirrors `bunyip-domain`'s `RestoreReport`.
#[derive(Debug, Clone, Deserialize)]
pub struct RestoreReport {
    #[serde(default)]
    pub profile_restored: bool,
    #[serde(default)]
    pub entitlements_granted: Vec<String>,
    #[serde(default)]
    pub apps: Vec<AppRestoreOutcome>,
}

/// One app's restore outcome inside a [`RestoreReport`].
#[derive(Debug, Clone, Deserialize)]
pub struct AppRestoreOutcome {
    #[serde(default)]
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
    #[serde(default)]
    pub lifetime_slots: i64,
    #[serde(default)]
    pub early_adopter_slots: i64,
    #[serde(default)]
    pub early_adopter_trial_days: i64,
    #[serde(default)]
    pub standard_trial_days: i64,
    #[serde(default)]
    pub free_price_id: Option<String>,
    #[serde(default)]
    pub early_adopter_price_id: Option<String>,
    #[serde(default)]
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
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub lifetime_slots_used: i64,
    #[serde(default)]
    pub early_adopter_slots_used: i64,
    /// BUNYIP-487: the Enable Pricing switch on the Pricing tiers page.
    #[serde(default)]
    pub pricing_enabled: bool,
    /// BUNYIP-527: per-tier visibility on the public `/pricing` page. Default
    /// true so an older API (without the fields) keeps every mapped tier visible.
    #[serde(default = "default_true")]
    pub lifetime_visible: bool,
    #[serde(default = "default_true")]
    pub early_adopter_visible: bool,
    #[serde(default = "default_true")]
    pub standard_visible: bool,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub updated_by: Option<String>,
}

/// BUNYIP-487: the public `/v1/pricing` payload. The admin Pricing tiers page
/// is the only source: `enabled` is its switch and each tier's amount comes
/// from the Stripe price that tier maps to, so the advertised price cannot
/// disagree with the charged one.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct PricingResponse {
    #[serde(default)]
    pub enabled: bool,
    /// Standard-tier trial length. Reported even when nothing is published,
    /// because the homepage CTA advertises the trial without the price.
    #[serde(default)]
    pub trial_days: i64,
    #[serde(default)]
    pub tiers: Vec<PricingTier>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PricingTier {
    /// Display name comes from `handlers::dashboard::tier_name`, not the wire,
    /// so the marketing card and the in-app labels stay byte-identical.
    #[serde(default)]
    pub tier: MembershipTier,
    /// Smallest currency unit (cents), from the mapped Stripe price.
    pub amount: i64,
    #[serde(default)]
    pub currency: String,
    #[serde(default)]
    pub interval: Option<String>,
    #[serde(default)]
    pub trial_days: i64,
    /// BUNYIP-526: whether this tier can still be signed up for. A slot-limited
    /// tier is `false` once sold out; Standard is unlimited and always `true`.
    /// Defaults to `true` so an older API (without the field) never renders a
    /// tier as wrongly sold out.
    #[serde(default = "default_true")]
    pub available: bool,
    /// BUNYIP-526: remaining slots for a limited tier (an honest scarcity line);
    /// `None` for an unlimited tier.
    #[serde(default)]
    pub slots_remaining: Option<i64>,
}

impl PricingResponse {
    /// Whether `/pricing` has anything honest to show. `false` means the route
    /// 404s and every link to it stays hidden.
    pub fn published(&self) -> bool {
        self.enabled && !self.tiers.is_empty()
    }
}

/// BUNYIP-515: the admin-only diagnosis behind the public payload
/// (`GET /v1/admin/pricing/status`). Built from the same resolve the public
/// page runs, so what it reports cannot drift from what visitors get.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct PricingStatus {
    #[serde(default)]
    pub published: bool,
    #[serde(default)]
    pub tiers: Vec<PricingTier>,
    #[serde(default)]
    pub reasons: Vec<PricingReason>,
}

/// One reason `/pricing` is not publishing something.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PricingReason {
    /// Stable machine key (`switch_off`, `price_unresolved`, ...).
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub price_id: Option<String>,
    /// The admin-facing sentence. Rendered by bunyip-api, which is the side
    /// that knows the app tag and the mapped price ids, and shown verbatim.
    #[serde(default)]
    pub message: String,
}

/// A per-application documentation page (BUNYIP-388). `body` is markdown.
#[derive(Debug, Clone, Deserialize)]
pub struct AppDoc {
    #[serde(default)]
    pub id: String,
    pub slug: String,
    #[serde(default)]
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
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub sort_order: i32,
}

#[cfg(test)]
mod tests {
    use super::{AuthResponse, MembershipStatus, MembershipTier, User, UserRole};

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
            "membership_tier": "standard",
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

    // --- BUNYIP-506: wire compatibility ------------------------------------

    #[test]
    fn v0_12_0_shaped_user_still_decodes() {
        // The exact payload that broke production: the v0.12.0 wire shape, with
        // `subscription_tier` and none of the fields added since. It must decode
        // through the alias instead of failing on a missing `membership_tier`.
        let u: User = serde_json::from_value(serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "ada@example.com",
            "role": "subscriber",
            "email_verified": true,
            "two_factor_enabled": true,
            "membership_status": "active",
            "price_locked": false,
            "created_at": "2026-01-01T00:00:00Z",
            "subscription_tier": "early_adopter",
            "lifetime_member": false,
        }))
        .expect("a v0.12.0-shaped user must still decode");
        assert_eq!(u.membership_tier, MembershipTier::EarlyAdopter);
        // Fields added since v0.12.0 fall back to their least-privileged default.
        assert!(!u.is_super_admin);
        assert_eq!(u.avatar_updated_at, None);
    }

    #[test]
    fn auth_response_needs_only_the_five_essential_fields() {
        // The 2FA path decodes an AuthResponse; nothing about membership,
        // billing or profile may be load-bearing for it.
        let auth: AuthResponse = serde_json::from_value(serde_json::json!({
            "user": {
                "id": "00000000-0000-0000-0000-000000000001",
                "email": "ada@example.com",
                "role": "subscriber",
                "email_verified": true,
                "two_factor_enabled": true,
            }
        }))
        .expect("a five-field user must decode as an AuthResponse");
        assert_eq!(auth.user.role, UserRole::Subscriber);
        // Least-privileged defaults: no membership, no tier, no price lock.
        assert_eq!(auth.user.membership_status, MembershipStatus::None);
        assert_eq!(auth.user.membership_tier, MembershipTier::Unknown);
        assert!(!auth.user.lifetime_member);
        assert!(!auth.user.price_locked);
        assert_eq!(auth.user.created_at, "");
    }

    #[test]
    fn unrecognised_wire_values_decode_to_unknown() {
        let tier: MembershipTier =
            serde_json::from_value(serde_json::json!("platinum")).expect("unknown tier decodes");
        assert_eq!(tier, MembershipTier::Unknown);
        // An unknown role must never land on Admin.
        let role: UserRole =
            serde_json::from_value(serde_json::json!("root")).expect("unknown role decodes");
        assert_eq!(role, UserRole::Unknown);
        assert_ne!(role, UserRole::Admin);
        // Round-trip: Unknown serializes to a value that decodes back to Unknown.
        assert_eq!(
            serde_json::to_value(UserRole::Unknown).expect("serialize"),
            serde_json::json!("unknown")
        );
    }
}
