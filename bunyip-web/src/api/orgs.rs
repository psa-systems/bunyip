use serde::{Deserialize, Serialize};

use super::types::{MembershipRole, Org, User};
use super::{get_json, post_empty, post_json, post_json_empty, ApiError};

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OrgMembershipBrief {
    pub org: Org,
    pub role: MembershipRole,
}

pub async fn list_my_orgs() -> Result<Vec<OrgMembershipBrief>, ApiError> {
    get_json("/v1/orgs").await
}

pub async fn get_org(slug: &str) -> Result<Org, ApiError> {
    get_json(&format!("/v1/orgs/{slug}")).await
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct MemberBrief {
    pub user: User,
    pub role: MembershipRole,
}

pub async fn list_members(slug: &str) -> Result<Vec<MemberBrief>, ApiError> {
    get_json(&format!("/v1/orgs/{slug}/members")).await
}

#[derive(Debug, Serialize)]
pub struct CreateInvitationRequest {
    pub email: String,
    pub role: MembershipRole,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct Invitation {
    pub id: String,
    pub email: String,
    pub role: MembershipRole,
    pub token: String,
    pub expires_at: String,
    pub accepted_at: Option<String>,
}

pub async fn list_invitations(slug: &str) -> Result<Vec<Invitation>, ApiError> {
    get_json(&format!("/v1/orgs/{slug}/invitations")).await
}

pub async fn create_invitation(
    slug: &str,
    req: &CreateInvitationRequest,
) -> Result<Invitation, ApiError> {
    post_json(&format!("/v1/orgs/{slug}/invitations"), req).await
}

pub async fn revoke_invitation(slug: &str, invite_id: &str) -> Result<(), ApiError> {
    let resp = super::request("DELETE", &format!("/v1/orgs/{slug}/invitations/{invite_id}"))
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(super::error_from_response_pub(resp).await)
    }
}

pub async fn remove_member(slug: &str, user_id: &str) -> Result<(), ApiError> {
    let resp = super::request("DELETE", &format!("/v1/orgs/{slug}/members/{user_id}"))
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(super::error_from_response_pub(resp).await)
    }
}

#[derive(Debug, Serialize)]
pub struct ChangeRoleRequest {
    pub role: MembershipRole,
}

pub async fn change_member_role(
    slug: &str,
    user_id: &str,
    role: MembershipRole,
) -> Result<(), ApiError> {
    post_json_empty(
        &format!("/v1/orgs/{slug}/members/{user_id}/role"),
        &ChangeRoleRequest { role },
    )
    .await
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct InvitationLookup {
    pub email: String,
    pub role: MembershipRole,
    pub org: Org,
    pub inviter_name: Option<String>,
    pub expired: bool,
}

pub async fn lookup_invitation(token: &str) -> Result<InvitationLookup, ApiError> {
    get_json(&format!("/v1/invitations/lookup?token={token}")).await
}

#[derive(Debug, Serialize)]
pub struct AcceptInvitationRequest {
    pub token: String,
}

pub async fn accept_invitation(token: String) -> Result<Org, ApiError> {
    post_json("/v1/invitations/accept", &AcceptInvitationRequest { token }).await
}

#[allow(dead_code)]
pub async fn leave_org(slug: &str) -> Result<(), ApiError> {
    post_empty(&format!("/v1/orgs/{slug}/leave")).await
}
