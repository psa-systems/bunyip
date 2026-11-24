//! Typed calls to the `/v1/organization/*` surface (BUNYIP-672).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{error_from, ok_data, parse, Api, ApiError};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OrganizationResponse {
    pub id: String,
    pub name: String,
    pub owner_bunyip_user_id: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeamResponse {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TeamMemberResponse {
    pub team_id: String,
    pub bunyip_user_id: String,
    pub role: String,
    pub joined_at: String,
}

/// GET /v1/organization: `None` means the caller owns no organization.
pub async fn get_my_organization(
    api: &Api,
    cookie: Option<&str>,
) -> Result<Option<OrganizationResponse>, ApiError> {
    let resp = api.get("/organization", cookie).await?;
    if resp.status == 404 {
        return Ok(None);
    }
    if !resp.ok() {
        return Err(error_from(&resp));
    }
    Ok(Some(parse(resp)?))
}

pub async fn create_my_organization(
    api: &Api,
    cookie: Option<&str>,
    name: &str,
) -> Result<OrganizationResponse, ApiError> {
    parse(
        api.post("/organization", cookie, Some(json!({ "name": name })))
            .await?,
    )
}

pub async fn update_my_organization(
    api: &Api,
    cookie: Option<&str>,
    name: &str,
) -> Result<OrganizationResponse, ApiError> {
    parse(
        api.put("/organization", cookie, Some(json!({ "name": name })))
            .await?,
    )
}

pub async fn list_teams(api: &Api, cookie: Option<&str>) -> Result<Vec<TeamResponse>, ApiError> {
    parse(api.get("/organization/teams", cookie).await?)
}

pub async fn create_team(
    api: &Api,
    cookie: Option<&str>,
    name: &str,
    description: Option<&str>,
) -> Result<TeamResponse, ApiError> {
    let mut body = json!({ "name": name });
    if let Some(d) = description {
        body["description"] = Value::String(d.to_string());
    }
    parse(api.post("/organization/teams", cookie, Some(body)).await?)
}

pub async fn update_team(
    api: &Api,
    cookie: Option<&str>,
    id: &str,
    name: Option<&str>,
    description: Option<&str>,
) -> Result<TeamResponse, ApiError> {
    let mut body = json!({});
    if let Some(n) = name {
        body["name"] = Value::String(n.to_string());
    }
    if let Some(d) = description {
        body["description"] = Value::String(d.to_string());
    }
    let path = format!("/organization/teams/{}", urlencoding::encode(id));
    parse(api.put(&path, cookie, Some(body)).await?)
}

pub async fn delete_team(api: &Api, cookie: Option<&str>, id: &str) -> Result<(), ApiError> {
    let path = format!("/organization/teams/{}", urlencoding::encode(id));
    let r = api.delete(&path, cookie, None).await?;
    if !r.ok() {
        return Err(error_from(&r));
    }
    ok_data(&r)?;
    Ok(())
}

pub async fn list_team_members(
    api: &Api,
    cookie: Option<&str>,
    id: &str,
) -> Result<Vec<TeamMemberResponse>, ApiError> {
    let path = format!("/organization/teams/{}/members", urlencoding::encode(id));
    parse(api.get(&path, cookie).await?)
}

pub async fn add_team_member(
    api: &Api,
    cookie: Option<&str>,
    team_id: &str,
    bunyip_user_id: &str,
    role: Option<&str>,
) -> Result<TeamMemberResponse, ApiError> {
    let mut body = json!({ "bunyip_user_id": bunyip_user_id });
    if let Some(r) = role {
        body["role"] = Value::String(r.to_string());
    }
    let path = format!(
        "/organization/teams/{}/members",
        urlencoding::encode(team_id)
    );
    parse(api.post(&path, cookie, Some(body)).await?)
}

pub async fn update_team_member_role(
    api: &Api,
    cookie: Option<&str>,
    team_id: &str,
    user_id: &str,
    role: &str,
) -> Result<TeamMemberResponse, ApiError> {
    let path = format!(
        "/organization/teams/{}/members/{}",
        urlencoding::encode(team_id),
        urlencoding::encode(user_id)
    );
    parse(
        api.put(&path, cookie, Some(json!({ "role": role })))
            .await?,
    )
}

pub async fn remove_team_member(
    api: &Api,
    cookie: Option<&str>,
    team_id: &str,
    user_id: &str,
) -> Result<(), ApiError> {
    let path = format!(
        "/organization/teams/{}/members/{}",
        urlencoding::encode(team_id),
        urlencoding::encode(user_id)
    );
    let r = api.delete(&path, cookie, None).await?;
    if !r.ok() {
        return Err(error_from(&r));
    }
    ok_data(&r)?;
    Ok(())
}
