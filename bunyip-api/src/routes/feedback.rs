use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
    Json, Router,
};
use bunyip_mocks::{AuditLog, Feedback, FeedbackAttachment, FeedbackStatus, MockStore};
use chrono::Utc;
use serde::Deserialize;
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::errors::AppError;
use crate::routes::auth::current_user_id;
use crate::state::AppState;

/// Header the SPA forwards the caller's active tenant under. The active
/// tenant lives in the OIDC `mokosh_active_tenant` id_token claim
/// (issued by mokosh-server); bunyip-api itself only sees the
/// `bunyip_session` cookie, so the SPA must echo the active tenant id
/// here for multi-org-aware routing. Bunyip orgs ARE the tenants, so the
/// value is matched directly against the user's org ids.
const ACTIVE_TENANT_HEADER: &str = "x-active-tenant";

/// Resolve which org a request should be attributed to for a given user.
///
/// Prefers the active tenant signalled by the `X-Active-Tenant` header
/// (the OIDC `mokosh_active_tenant` claim, forwarded by the SPA), so a
/// user who belongs to several orgs gets feedback / audit rows tagged to
/// the org they are actually looking at. Falls back to the first
/// membership only when no usable active-tenant signal is present.
///
// TODO(m1-vas): bunyip-api does not yet receive the active-tenant claim
// on its own (it authenticates via the bunyip_session cookie, not the
// OIDC id_token). Until the SPA's api::request helper forwards the
// active tenant id as `X-Active-Tenant` (PLACEHOLDER: wire-up pending),
// requests without the header fall back to the first membership, which
// reproduces the old behaviour for single-org users. Wire the SPA to
// send the header (read from modules/oidc/tokens.rs IdTokenClaims
// .active_tenant_id) to make multi-org routing correct end to end.
fn active_org_for_user(store: &MockStore, headers: &HeaderMap, uid: Uuid) -> Option<Uuid> {
    let orgs = store.orgs_for_user(uid);
    if orgs.is_empty() {
        return None;
    }
    let active_tenant = headers
        .get(ACTIVE_TENANT_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s.trim()).ok());
    if let Some(tenant_id) = active_tenant {
        if let Some((org, _)) = orgs.iter().find(|(o, _)| o.id == tenant_id) {
            return Some(org.id);
        }
    }
    // No active-tenant signal (or it does not match a membership):
    // fall back to the first membership. See the TODO above.
    orgs.first().map(|(o, _)| o.id)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/feedback", post(submit_feedback))
        .route("/v1/feedback/upload", post(upload_attachment))
        .route("/v1/admin/feedback", get(list_feedback))
        .route("/v1/admin/feedback/{id}", patch(update_feedback_status))
}

#[derive(Debug, Deserialize)]
pub struct SubmitFeedbackRequest {
    pub name: Option<String>,
    pub email: Option<String>,
    pub subject: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub message: String,
    pub page_path: Option<String>,
    /// Honeypot: bots fill this; real users don't.
    pub website: Option<String>,
    #[serde(default)]
    pub attachments: Vec<FeedbackAttachment>,
}

async fn submit_feedback(
    State(state): State<AppState>,
    cookies: Cookies,
    headers: HeaderMap,
    Json(body): Json<SubmitFeedbackRequest>,
) -> Result<(StatusCode, Json<Feedback>), AppError> {
    if body.message.trim().is_empty() {
        return Err(AppError::BadRequest("message is required".into()));
    }
    if body
        .website
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        // Silent honeypot: pretend success without recording.
        return Err(AppError::BadRequest("nope".into()));
    }

    let actor = current_user_id(&cookies);
    let mut store = state.store.write();
    // Tag the feedback to the user's ACTIVE org, not blindly their first
    // membership: a multi-org user submitting from org B must not have
    // the row attributed to org A. See active_org_for_user.
    let org_id = actor.and_then(|uid| active_org_for_user(&store, &headers, uid));

    // If the user is signed in, fall back to their profile for name/email.
    let (name, email) = if let Some(uid) = actor {
        let user = store.find_user(uid);
        let n = body
            .name
            .clone()
            .or_else(|| user.as_ref().map(|u| u.name.clone()));
        let e = body
            .email
            .clone()
            .or_else(|| user.as_ref().map(|u| u.email.clone()));
        (n, e)
    } else {
        (body.name.clone(), body.email.clone())
    };

    let entry = Feedback {
        id: Uuid::new_v4(),
        user_id: actor,
        org_id,
        name,
        email,
        subject: body.subject,
        tags: body.tags,
        message: body.message,
        page_path: body.page_path,
        user_agent: None,
        attachments: body.attachments,
        forgejo_issue_url: None,
        status: FeedbackStatus::New,
        created_at: Utc::now(),
    };
    store.feedback.push(entry.clone());
    store.log_audit(AuditLog {
        id: Uuid::new_v4(),
        actor_user_id: actor,
        org_id,
        action: "feedback.submit".to_string(),
        target: Some(entry.id.to_string()),
        ip: None,
        user_agent: None,
        is_admin_action: false,
        ts: Utc::now(),
    });
    Ok((StatusCode::CREATED, Json(entry)))
}

async fn upload_attachment() -> Json<FeedbackAttachment> {
    // Stub - in production we'd accept multipart, save to object storage, and
    // return a real signed URL. For MVP we return a fake URL.
    Json(FeedbackAttachment {
        filename: "mock-attachment.png".into(),
        size: 102_400,
        url: format!("/mock-attachments/{}.png", Uuid::new_v4()),
    })
}

#[derive(Debug, Deserialize)]
pub struct ListFeedbackQuery {
    pub status: Option<String>,
}

async fn list_feedback(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(q): Query<ListFeedbackQuery>,
) -> Result<Json<Vec<Feedback>>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let store = state.store.read();
    let user = store.find_user(uid).ok_or(AppError::Unauthorized)?;
    if !matches!(user.role, bunyip_mocks::UserRole::Admin) {
        return Err(AppError::Forbidden);
    }
    let mut list: Vec<Feedback> = store
        .feedback
        .iter()
        .filter(|f| match q.status.as_deref() {
            Some("new") => matches!(f.status, FeedbackStatus::New),
            Some("triaged") => matches!(f.status, FeedbackStatus::Triaged),
            Some("closed") => matches!(f.status, FeedbackStatus::Closed),
            _ => true,
        })
        .cloned()
        .collect();
    list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(Json(list))
}

#[derive(Debug, Deserialize)]
pub struct UpdateFeedbackStatus {
    pub status: FeedbackStatus,
}

async fn update_feedback_status(
    State(state): State<AppState>,
    cookies: Cookies,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
    Json(body): Json<UpdateFeedbackStatus>,
) -> Result<StatusCode, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    let user = store.find_user(uid).ok_or(AppError::Unauthorized)?;
    if !matches!(user.role, bunyip_mocks::UserRole::Admin) {
        return Err(AppError::Forbidden);
    }
    let Some(entry) = store.feedback.iter_mut().find(|f| f.id == id) else {
        return Err(AppError::NotFound);
    };
    entry.status = body.status;
    Ok(StatusCode::NO_CONTENT)
}
