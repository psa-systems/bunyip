//! Org + membership + invitation handlers. All state in the mock store.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, patch, post},
    Json, Router,
};
use bunyip_mocks::{AuditLog, Invitation, MembershipRole, Org, User};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::errors::AppError;
use crate::routes::auth::current_user_id;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/orgs", get(list_my_orgs))
        .route("/v1/orgs/{slug}", get(get_org).patch(rename_org))
        .route("/v1/orgs/{slug}/leave", post(leave_org))
        .route("/v1/orgs/{slug}/members", get(list_members))
        .route("/v1/orgs/{slug}/members/{user_id}", delete(remove_member))
        .route("/v1/orgs/{slug}/members/{user_id}/role", patch(change_role))
        .route("/v1/orgs/{slug}/invitations", get(list_invitations).post(create_invitation))
        .route("/v1/orgs/{slug}/invitations/{id}", delete(revoke_invitation))
        .route("/v1/invitations/accept", post(accept_invitation))
        .route("/v1/invitations/lookup", get(lookup_invitation))
}

fn audit(action: &str, actor: Option<Uuid>, org_id: Option<Uuid>, target: Option<&str>) -> AuditLog {
    AuditLog {
        id: Uuid::new_v4(),
        actor_user_id: actor,
        org_id,
        action: action.to_string(),
        target: target.map(|s| s.to_string()),
        ip: None,
        user_agent: None,
        is_admin_action: false,
        ts: Utc::now(),
    }
}

#[derive(Debug, Serialize)]
pub struct OrgMembershipBrief {
    pub org: Org,
    pub role: MembershipRole,
}

async fn list_my_orgs(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Json<Vec<OrgMembershipBrief>>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let orgs = state
        .store
        .read()
        .orgs_for_user(uid)
        .into_iter()
        .map(|(org, role)| OrgMembershipBrief { org, role })
        .collect();
    Ok(Json(orgs))
}

async fn get_org(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(slug): Path<String>,
) -> Result<Json<Org>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let store = state.store.read();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if store.role_in_org(uid, org.id).is_none() {
        return Err(AppError::Forbidden);
    }
    Ok(Json(org))
}

#[derive(Debug, Deserialize)]
pub struct RenameOrgRequest {
    pub name: String,
}

async fn rename_org(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(slug): Path<String>,
    Json(body): Json<RenameOrgRequest>,
) -> Result<Json<Org>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    let org_id = store
        .org_by_slug(&slug)
        .ok_or(AppError::NotFound)?
        .id;
    if !matches!(store.role_in_org(uid, org_id), Some(MembershipRole::Owner | MembershipRole::Admin)) {
        return Err(AppError::Forbidden);
    }
    let Some(org) = store.orgs.iter_mut().find(|o| o.id == org_id) else {
        return Err(AppError::NotFound);
    };
    org.name = body.name.clone();
    let org = org.clone();
    store.log_audit(audit("org.rename", Some(uid), Some(org_id), Some(&org.name)));
    Ok(Json(org))
}

async fn leave_org(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(slug): Path<String>,
) -> Result<StatusCode, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if org.owner_user_id == uid {
        return Err(AppError::BadRequest("owners cannot leave their own org".into()));
    }
    if !store.remove_member(org.id, uid) {
        return Err(AppError::NotFound);
    }
    store.log_audit(audit("org.member.leave", Some(uid), Some(org.id), None));
    Ok(StatusCode::NO_CONTENT)
}

// --- Members ---

#[derive(Debug, Serialize)]
pub struct MemberBrief {
    pub user: User,
    pub role: MembershipRole,
}

async fn list_members(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(slug): Path<String>,
) -> Result<Json<Vec<MemberBrief>>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let store = state.store.read();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if store.role_in_org(uid, org.id).is_none() {
        return Err(AppError::Forbidden);
    }
    let members = store
        .members_of_org(org.id)
        .into_iter()
        .map(|(user, role)| MemberBrief { user, role })
        .collect();
    Ok(Json(members))
}

async fn remove_member(
    State(state): State<AppState>,
    cookies: Cookies,
    Path((slug, user_id)): Path<(String, Uuid)>,
) -> Result<StatusCode, AppError> {
    let actor = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if !matches!(store.role_in_org(actor, org.id), Some(MembershipRole::Owner | MembershipRole::Admin)) {
        return Err(AppError::Forbidden);
    }
    if user_id == org.owner_user_id {
        return Err(AppError::BadRequest("cannot remove the org owner".into()));
    }
    if !store.remove_member(org.id, user_id) {
        return Err(AppError::NotFound);
    }
    store.log_audit(audit("org.member.remove", Some(actor), Some(org.id), Some(&user_id.to_string())));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct ChangeRoleRequest {
    pub role: MembershipRole,
}

async fn change_role(
    State(state): State<AppState>,
    cookies: Cookies,
    Path((slug, user_id)): Path<(String, Uuid)>,
    Json(body): Json<ChangeRoleRequest>,
) -> Result<StatusCode, AppError> {
    let actor = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if store.role_in_org(actor, org.id) != Some(MembershipRole::Owner) {
        return Err(AppError::Forbidden);
    }
    if user_id == org.owner_user_id {
        return Err(AppError::BadRequest("owner role can't be changed".into()));
    }
    if !store.change_member_role(org.id, user_id, body.role) {
        return Err(AppError::NotFound);
    }
    store.log_audit(audit("org.member.role_change", Some(actor), Some(org.id), Some(&user_id.to_string())));
    Ok(StatusCode::NO_CONTENT)
}

// --- Invitations ---

async fn list_invitations(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(slug): Path<String>,
) -> Result<Json<Vec<Invitation>>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let store = state.store.read();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if !matches!(store.role_in_org(uid, org.id), Some(MembershipRole::Owner | MembershipRole::Admin)) {
        return Err(AppError::Forbidden);
    }
    Ok(Json(store.invitations_for_org(org.id)))
}

#[derive(Debug, Deserialize)]
pub struct CreateInvitationRequest {
    pub email: String,
    pub role: MembershipRole,
}

async fn create_invitation(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(slug): Path<String>,
    Json(body): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<Invitation>), AppError> {
    let actor = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if !matches!(store.role_in_org(actor, org.id), Some(MembershipRole::Owner | MembershipRole::Admin)) {
        return Err(AppError::Forbidden);
    }
    let inv = store.create_invitation(org.id, body.email.clone(), body.role, actor);
    let link = format!(
        "{}/invitations/accept?token={}",
        state.config.public_base_url, inv.token
    );
    tracing::info!(email = %body.email, link = %link, "mock invitation email sent");
    store.log_audit(audit("org.invite.send", Some(actor), Some(org.id), Some(&body.email)));
    Ok((StatusCode::CREATED, Json(inv)))
}

async fn revoke_invitation(
    State(state): State<AppState>,
    cookies: Cookies,
    Path((slug, invite_id)): Path<(String, Uuid)>,
) -> Result<StatusCode, AppError> {
    let actor = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if !matches!(store.role_in_org(actor, org.id), Some(MembershipRole::Owner | MembershipRole::Admin)) {
        return Err(AppError::Forbidden);
    }
    if !store.delete_invitation(org.id, invite_id) {
        return Err(AppError::NotFound);
    }
    store.log_audit(audit("org.invite.revoke", Some(actor), Some(org.id), Some(&invite_id.to_string())));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct InvitationLookupResponse {
    pub email: String,
    pub role: MembershipRole,
    pub org: Org,
    pub inviter_name: Option<String>,
    pub expired: bool,
}

#[derive(Debug, Deserialize)]
pub struct InvitationLookupQuery {
    pub token: String,
}

async fn lookup_invitation(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<InvitationLookupQuery>,
) -> Result<Json<InvitationLookupResponse>, AppError> {
    let store = state.store.read();
    let inv = store.invitation_by_token(&q.token).ok_or(AppError::NotFound)?;
    let org = store
        .orgs
        .iter()
        .find(|o| o.id == inv.org_id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let inviter_name = store
        .users
        .iter()
        .find(|u| u.id == inv.invited_by_user_id)
        .map(|u| u.name.clone());
    Ok(Json(InvitationLookupResponse {
        email: inv.email.clone(),
        role: inv.role,
        org,
        inviter_name,
        expired: inv.expires_at < chrono::Utc::now() || inv.accepted_at.is_some(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct AcceptInvitationRequest {
    pub token: String,
}

async fn accept_invitation(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(body): Json<AcceptInvitationRequest>,
) -> Result<Json<Org>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    let inv = store
        .accept_invitation(&body.token, uid)
        .ok_or(AppError::BadRequest("invalid or expired invitation".into()))?;
    let org = store
        .orgs
        .iter()
        .find(|o| o.id == inv.org_id)
        .cloned()
        .ok_or(AppError::NotFound)?;
    store.log_audit(audit("org.invite.accept", Some(uid), Some(inv.org_id), Some(&inv.email)));
    Ok(Json(org))
}
