//! Shared types mirroring `bunyip-api` response shapes. Kept minimal -
//! only the fields the frontend reads.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRole {
    Owner,
    Admin,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub role: UserRole,
    pub email_verified_at: Option<String>,
    pub lifetime_member: bool,
    pub mfa_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Org {
    pub id: String,
    pub slug: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrgMembership {
    pub org: Org,
    pub role: MembershipRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeResponse {
    pub user: User,
    pub memberships: Vec<OrgMembership>,
}
