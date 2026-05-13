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
    #[serde(default)]
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize)]
struct UserListEnvelope {
    users: Vec<UserView>,
}

pub async fn list_users() -> Result<Vec<UserView>, ApiError> {
    get_authed::<UserListEnvelope>("/v1/auth/users")
        .await
        .map(|e| e.users)
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

pub async fn list_audit_logs(
    limit: i64,
    offset: i64,
    kind: Option<&str>,
) -> Result<AuditListBody, ApiError> {
    let mut path = format!("/v1/auth/audit-logs?limit={limit}&offset={offset}");
    if let Some(k) = kind.filter(|s| !s.is_empty()) {
        let encoded: String = k
            .chars()
            .map(|c| match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-' | '.' => c.to_string(),
                _ => format!("%{:02X}", c as u32),
            })
            .collect();
        path.push_str(&format!("&kind={encoded}"));
    }
    get_authed::<AuditListBody>(&path).await
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
