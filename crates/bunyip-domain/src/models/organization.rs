//! Organization, team, and team-member models for the Bunyip-side identity
//! layer (BUNYIP-626 child 1). Every read and write of these rows is gated at
//! the service layer on `TierConfig::orgs_enabled`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize, PartialEq)]
pub struct Organization {
    pub id: Uuid,
    pub owner_bunyip_user_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateOrganization {
    pub owner_bunyip_user_id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateOrganization {
    pub name: String,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize, PartialEq)]
pub struct Team {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateTeam {
    pub organization_id: Uuid,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateTeam {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize, PartialEq)]
pub struct TeamMember {
    pub team_id: Uuid,
    pub bunyip_user_id: Uuid,
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddTeamMember {
    pub team_id: Uuid,
    pub bunyip_user_id: Uuid,
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateTeamMemberRole {
    pub role: String,
}

pub const TEAM_MEMBER_ROLE_MEMBER: &str = "member";
