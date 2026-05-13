use axum::{extract::State, routing::get, Json, Router};
use bunyip_mocks::{MembershipRole, Org, User};
use serde::Serialize;
use tower_cookies::Cookies;

use crate::errors::AppError;
use crate::routes::auth::current_user_id;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/me", get(me))
}

#[derive(Debug, Serialize)]
pub struct OrgMembership {
    pub org: Org,
    pub role: MembershipRole,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub user: User,
    pub memberships: Vec<OrgMembership>,
}

async fn me(
    State(state): State<AppState>,
    cookies: Cookies,
) -> Result<Json<MeResponse>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let store = state.store.read();
    let user = store.find_user(uid).ok_or(AppError::Unauthorized)?;
    let memberships = store
        .orgs_for_user(uid)
        .into_iter()
        .map(|(org, role)| OrgMembership { org, role })
        .collect();
    Ok(Json(MeResponse { user, memberships }))
}
