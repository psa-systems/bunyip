//! BUNYIP-672 [BUNYIP-626 child 1]: organization / team / team_members models.
//!
//! An organization is the identity layer above per-user Mokosh accounts.
//! Teams live under an organization; team members are Bunyip users on a
//! team, with a two-value display + notification role (`member` / `leader`)
//! per the PMS-1162 projection model. Permission checks that involve a
//! team read the caller's app-level role, not this column.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Organization row, as it lives in the database.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub owner_bunyip_user_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Team row, as it lives in the database.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Team {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One row of team_members, as it lives in the database. `role` is a
/// display + notification axis, not a permission axis (PMS-1162).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TeamMember {
    pub team_id: Uuid,
    pub bunyip_user_id: Uuid,
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

/// Body for `POST /v1/organization`.
///
/// `name` is the only field; the caller (the Bunyip user session) is the
/// implicit owner. A second create by the same owner is refused with 409
/// by the `UNIQUE(owner_bunyip_user_id)` constraint on the table.
#[derive(Debug, Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
}

/// Body for `PUT /v1/organization`.
#[derive(Debug, Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: String,
}

/// Body for `POST /v1/organization/teams`.
#[derive(Debug, Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Body for `PUT /v1/organization/teams/{id}`.
#[derive(Debug, Deserialize)]
pub struct UpdateTeamRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Body for `POST /v1/organization/teams/{id}/members`.
///
/// `role` defaults to `member` when omitted; that matches the DB default
/// and keeps the wire shape forward-compatible with older clients that do
/// not know about the leader role.
#[derive(Debug, Deserialize)]
pub struct AddTeamMemberRequest {
    pub bunyip_user_id: Uuid,
    #[serde(default = "default_member_role")]
    pub role: String,
}

/// Body for `PUT /v1/organization/teams/{id}/members/{bunyip_user_id}`.
#[derive(Debug, Deserialize)]
pub struct UpdateTeamMemberRoleRequest {
    pub role: String,
}

fn default_member_role() -> String {
    "member".to_string()
}

/// Valid roles for `team_members.role`, mirroring the CHECK constraint on
/// the table. Kept as a constant so `validate_role` and the tests read the
/// same list.
pub const VALID_TEAM_MEMBER_ROLES: &[&str] = &["member", "leader"];

pub fn validate_team_member_role(role: &str) -> bool {
    VALID_TEAM_MEMBER_ROLES.contains(&role)
}

/// Validate the shape of an org/team `name`. Trimmed length 1..=100, and
/// no ASCII control characters. Kept generic so the same rule applies to
/// both org names and team names.
pub fn validate_name(name: &str) -> Result<String, &'static str> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("name cannot be empty");
    }
    if trimmed.chars().count() > 100 {
        return Err("name cannot exceed 100 characters");
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("name cannot contain control characters");
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_name_accepts_a_trimmed_string() {
        assert_eq!(validate_name("  Ops  ").unwrap(), "Ops");
    }

    #[test]
    fn validate_name_refuses_an_empty_or_whitespace_only_string() {
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());
    }

    #[test]
    fn validate_name_refuses_over_100_chars() {
        let long = "x".repeat(101);
        assert!(validate_name(&long).is_err());
        let ok = "x".repeat(100);
        assert!(validate_name(&ok).is_ok());
    }

    #[test]
    fn validate_name_refuses_control_characters() {
        assert!(validate_name("Ops\0team").is_err());
        assert!(validate_name("Line1\nLine2").is_err());
    }

    #[test]
    fn validate_team_member_role_accepts_the_two_valid_values() {
        assert!(validate_team_member_role("member"));
        assert!(validate_team_member_role("leader"));
    }

    #[test]
    fn validate_team_member_role_refuses_anything_else() {
        assert!(!validate_team_member_role(""));
        assert!(!validate_team_member_role("admin"));
        assert!(!validate_team_member_role("MEMBER"));
    }

    #[test]
    fn valid_team_member_roles_list_matches_the_check_constraint() {
        // Kept in sync with the CHECK constraint on team_members.role
        // (migration 20260915000030). A change to one must move the other
        // in the same PR.
        assert_eq!(VALID_TEAM_MEMBER_ROLES, ["member", "leader"]);
    }
}
