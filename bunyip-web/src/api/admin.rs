//! Admin-only API surface against mokosh-server's `/v1/auth/*` admin
//! endpoints. Every helper requires the caller to hold an admin token;
//! mokosh-server returns 403 otherwise.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{get_authed, post_authed, post_authed_empty, ApiError};

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct UserView {
    pub id: String,
    pub email: String,
    pub role: String,
    pub status: String,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub mfa_enrolled: bool,
    /// True when the user is the Owner of the current tenant's
    /// membership. Owners are immovable from this surface; the SPA
    /// hides per-row action buttons and shows an Owner badge.
    #[serde(default)]
    pub is_owner: bool,
    #[serde(default)]
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Filter inputs for the admin user-management list endpoint. All
/// fields are optional; default = no filter, default paging.
#[derive(Clone, Debug, Default)]
pub struct UserListFilter {
    pub search: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
    /// `Some(true)` -> only mfa-enrolled. `Some(false)` -> only not
    /// enrolled. `None` -> no filter.
    pub mfa_enrolled: Option<bool>,
    pub limit: u32,
    pub offset: u32,
}

impl UserListFilter {
    /// Encode as query-string. Empty fields drop out so the URL stays
    /// readable when no filter is active.
    fn to_query(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(s) = self.search.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!("search={}", urlencode(s)));
        }
        if let Some(s) = self.role.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!("role={}", urlencode(s)));
        }
        if let Some(s) = self.status.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!("status={}", urlencode(s)));
        }
        if let Some(b) = self.mfa_enrolled {
            parts.push(format!("mfa={}", if b { "yes" } else { "no" }));
        }
        parts.push(format!("limit={}", self.limit));
        parts.push(format!("offset={}", self.offset));
        parts.join("&")
    }
}

fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

#[derive(Clone, Debug, Deserialize)]
pub struct UserListPage {
    pub users: Vec<UserView>,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

pub async fn list_users(filter: &UserListFilter) -> Result<UserListPage, ApiError> {
    let path = format!("/v1/auth/users?{}", filter.to_query());
    get_authed::<UserListPage>(&path).await
}

#[derive(Clone, Debug, Deserialize)]
pub struct UserDetail {
    pub user: UserView,
    #[serde(default)]
    pub available_role_transitions: Vec<String>,
}

pub async fn get_user(user_id: &str) -> Result<UserDetail, ApiError> {
    get_authed::<UserDetail>(&format!("/v1/auth/users/{user_id}")).await
}

pub async fn suspend_user(user_id: &str) -> Result<(), ApiError> {
    post_authed_empty(
        &format!("/v1/auth/users/{user_id}/suspend"),
        &serde_json::json!({}),
    )
    .await
}

pub async fn reactivate_user(user_id: &str) -> Result<(), ApiError> {
    post_authed_empty(
        &format!("/v1/auth/users/{user_id}/reactivate"),
        &serde_json::json!({}),
    )
    .await
}

#[derive(Clone, Debug, Serialize)]
pub struct DisenrollMfaBody {
    pub reason: String,
}

pub async fn force_disenroll_mfa(user_id: &str, reason: &str) -> Result<(), ApiError> {
    post_authed_empty(
        &format!("/v1/auth/users/{user_id}/mfa/disenroll"),
        &DisenrollMfaBody {
            reason: reason.to_string(),
        },
    )
    .await
}

#[derive(Clone, Debug, Serialize)]
struct ChangeRoleBody<'a> {
    role: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    step_up_token: Option<String>,
}

pub async fn change_user_role(
    user_id: &str,
    role: &str,
    reason: Option<String>,
    step_up_token: Option<String>,
) -> Result<(), ApiError> {
    post_authed_empty(
        &format!("/v1/auth/users/{user_id}/role"),
        &ChangeRoleBody {
            role,
            reason,
            step_up_token,
        },
    )
    .await
}

#[derive(Clone, Debug, Serialize)]
struct DeleteUserBody {
    reason: String,
    step_up_token: String,
}

pub async fn delete_user(user_id: &str, reason: &str, step_up_token: &str) -> Result<(), ApiError> {
    post_authed_empty(
        &format!("/v1/auth/users/{user_id}/delete"),
        &DeleteUserBody {
            reason: reason.to_string(),
            step_up_token: step_up_token.to_string(),
        },
    )
    .await
}

pub async fn resend_verify(user_id: &str) -> Result<(), ApiError> {
    post_authed_empty(
        &format!("/v1/auth/users/{user_id}/resend-verify"),
        &serde_json::json!({}),
    )
    .await
}

pub async fn admin_trigger_password_reset(user_id: &str) -> Result<(), ApiError> {
    post_authed_empty(
        &format!("/v1/auth/users/{user_id}/password-reset"),
        &serde_json::json!({}),
    )
    .await
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct UserSessionView {
    pub id: String,
    pub created_at: String,
    pub last_active_at: String,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub is_current: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct UserSessionsBody {
    sessions: Vec<UserSessionView>,
}

/// GET /v1/auth/users/:id/sessions - admin lists target user's active sessions.
pub async fn list_user_sessions(user_id: &str) -> Result<Vec<UserSessionView>, ApiError> {
    super::get_authed::<UserSessionsBody>(&format!("/v1/auth/users/{user_id}/sessions"))
        .await
        .map(|b| b.sessions)
}

/// POST /v1/auth/users/:id/sessions/:sid/revoke - admin force-revoke.
pub async fn revoke_user_session(user_id: &str, session_id: &str) -> Result<(), ApiError> {
    post_authed_empty(
        &format!("/v1/auth/users/{user_id}/sessions/{session_id}/revoke"),
        &serde_json::json!({}),
    )
    .await
}

// ---------------------------------------------------------------------------
// Invites
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct InvitedByView {
    pub id: String,
    pub email: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct InviteView {
    pub id: String,
    pub email: String,
    pub role: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub invited_by: InvitedByView,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct InvitesEnvelope {
    invites: Vec<InviteView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IssueInviteBody {
    pub email: String,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IssueInviteSuccess {
    pub invite: InviteView,
    #[serde(default)]
    pub accept_url: Option<String>,
    #[serde(default)]
    pub warning: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResendInviteSuccess {
    #[serde(default)]
    pub accept_url: Option<String>,
    #[serde(default)]
    pub warning: Option<String>,
}

pub async fn list_invites() -> Result<Vec<InviteView>, ApiError> {
    get_authed::<InvitesEnvelope>("/v1/auth/invites")
        .await
        .map(|e| e.invites)
}

pub async fn issue_invite(body: &IssueInviteBody) -> Result<IssueInviteSuccess, ApiError> {
    post_authed("/v1/auth/invites", body).await
}

pub async fn resend_invite(id: &str) -> Result<ResendInviteSuccess, ApiError> {
    post_authed(
        &format!("/v1/auth/invites/{id}/resend"),
        &serde_json::json!({}),
    )
    .await
}

pub async fn revoke_invite(id: &str) -> Result<(), ApiError> {
    post_authed_empty(
        &format!("/v1/auth/invites/{id}/revoke"),
        &serde_json::json!({}),
    )
    .await
}

// ---------------------------------------------------------------------------
// Audit logs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct AuditView {
    pub id: String,
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub actor_email: Option<String>,
    pub event_kind: String,
    pub severity: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuditListBody {
    pub entries: Vec<AuditView>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Clone, Debug, Default)]
pub struct AuditFilter {
    pub kind: Option<String>,
    pub search: Option<String>,
    pub severity: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

fn url_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

impl AuditFilter {
    /// Append the filter's non-empty fields to `path` as `&k=v` pairs.
    /// Caller has already emitted the leading `?` (with limit/offset).
    pub fn append_to(&self, path: &mut String) {
        if let Some(k) = self.kind.as_deref().filter(|s| !s.is_empty()) {
            path.push_str(&format!("&kind={}", url_encode(k)));
        }
        if let Some(s) = self.search.as_deref().filter(|s| !s.is_empty()) {
            path.push_str(&format!("&search={}", url_encode(s)));
        }
        if let Some(s) = self.severity.as_deref().filter(|s| !s.is_empty()) {
            path.push_str(&format!("&severity={}", url_encode(s)));
        }
        if let Some(s) = self.from.as_deref().filter(|s| !s.is_empty()) {
            path.push_str(&format!("&from={}", url_encode(s)));
        }
        if let Some(s) = self.to.as_deref().filter(|s| !s.is_empty()) {
            path.push_str(&format!("&to={}", url_encode(s)));
        }
    }
}

pub async fn list_audit_logs(
    limit: i64,
    offset: i64,
    filter: &AuditFilter,
) -> Result<AuditListBody, ApiError> {
    let mut path = format!("/v1/auth/audit-logs?limit={limit}&offset={offset}");
    filter.append_to(&mut path);
    get_authed::<AuditListBody>(&path).await
}

/// Build a fully-qualified URL the browser can navigate to (with the
/// Authorization header injected via fetch + blob download in the page).
/// Returns the relative path; the page wraps with `issuer_url`.
pub fn audit_csv_path(filter: &AuditFilter) -> String {
    let mut path = "/v1/auth/audit-logs.csv?limit=10000&offset=0".to_string();
    filter.append_to(&mut path);
    path
}

/// Canonical event_kind values surfaced by mokosh-server, mirrored from
/// `mokosh-auth-storage/src/audit.rs::event_kind`. The dropdown on the
/// audit-logs page binds to this list so the user does not have to
/// remember the exact strings.
pub const AUDIT_EVENT_KINDS: &[&str] = &[
    "login_success",
    "login_failed",
    "logout_success",
    "password_changed",
    "password_reset_requested",
    "password_reset_completed",
    "magic_link_requested",
    "magic_link_used",
    "token_issued",
    "token_refreshed",
    "refresh_reuse_detected",
    "session_revoked",
    "client_created",
    "client_disabled",
    "key_rotated",
    "suspicious_activity",
    "admin_action",
    "invite_issued",
    "invite_revoked",
    "invite_accepted",
    "invite_attempt_failed",
    "signup_requested",
    "signup_completed",
    "signup_attempt_failed",
    "password_reset_attempt_failed",
    "totp_enrollment_started",
    "totp_enrolled",
    "totp_disenrolled",
    "mfa_challenge_issued",
    "mfa_challenge_consumed",
    "mfa_verify_failed",
    "step_up_issued",
    "step_up_consumed",
    "recovery_codes_issued",
    "recovery_codes_regenerated",
    "recovery_code_used",
    "account_lockout_hit",
    "account_locked",
];
