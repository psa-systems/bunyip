//! BUNYIP-673 [BUNYIP-626 child 2]: cross-account Mokosh grant models.
//!
//! A grant is issued by a Bunyip user against their own Mokosh account
//! for another Bunyip user, at one of the five app-level roles PMS-1162
//! settled. The grantee sees the granted account in their Bunyip app
//! switcher (SSR surface: BUNYIP-691) and, when the "grantee signs in"
//! AC lands, in Mokosh's `at+jwt` verifier.
//!
//! The wire shape is deliberately small: a grantor picks a grantee by
//! id and by `mokosh_account_id` (the tenant slug they control), and
//! either the caller can look up their own grants or an admin can look
//! up all of them (admin path is a BUNYIP-691 follow-up; this ticket
//! ships the owner + grantee shapes).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Mokosh-grant row, as it lives in the database.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MokoshAccountGrant {
    pub id: Uuid,
    pub owner_bunyip_user_id: Uuid,
    pub grantee_bunyip_user_id: Uuid,
    pub mokosh_account_id: String,
    pub role: String,
    pub granted_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Body for `POST /v1/grants`.
///
/// The owner is the caller; `grantee_email` resolves to a Bunyip user by
/// email (the shape the parent ticket asked for) and MUST resolve to a
/// row in `users` - a portal contact is a Mokosh-side concept and is
/// separately guarded by the FK on the table. `mokosh_account_id` is
/// the tenant slug the owner controls.
#[derive(Debug, Deserialize)]
pub struct CreateGrantRequest {
    #[serde(default)]
    pub grantee_email: Option<String>,
    /// Alternative to `grantee_email`: name the grantee by their Bunyip
    /// user id directly. The service accepts either; email is the
    /// friendlier admin path, id is the machine one. Exactly one must
    /// be present.
    #[serde(default)]
    pub grantee_bunyip_user_id: Option<Uuid>,
    pub mokosh_account_id: String,
    pub role: String,
}

/// Valid roles on the wire, mirroring the CHECK constraint on the
/// table. Kept as a constant so the validator and the tests read the
/// same list.
pub const VALID_GRANT_ROLES: &[&str] = &["admin", "manager", "technician", "finance", "read_only"];

pub fn validate_grant_role(role: &str) -> bool {
    VALID_GRANT_ROLES.contains(&role)
}

/// Validate a Mokosh tenant slug shape. The mokosh RS is authoritative;
/// this check refuses obvious typos (empty, whitespace, control chars)
/// before the write reaches the FK-less TEXT column.
pub fn validate_mokosh_account_id(id: &str) -> Result<String, &'static str> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err("mokosh_account_id cannot be empty");
    }
    if trimmed.chars().count() > 128 {
        return Err("mokosh_account_id cannot exceed 128 characters");
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err("mokosh_account_id cannot contain control characters");
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_grant_role_accepts_the_five_pms_1162_roles() {
        for role in ["admin", "manager", "technician", "finance", "read_only"] {
            assert!(validate_grant_role(role), "{role} must be valid");
        }
    }

    #[test]
    fn validate_grant_role_refuses_anything_else() {
        assert!(!validate_grant_role(""));
        assert!(!validate_grant_role("owner"));
        assert!(!validate_grant_role("ADMIN"));
        assert!(!validate_grant_role("super_admin"));
    }

    #[test]
    fn valid_grant_roles_matches_the_check_constraint() {
        assert_eq!(
            VALID_GRANT_ROLES,
            ["admin", "manager", "technician", "finance", "read_only"]
        );
    }

    #[test]
    fn validate_mokosh_account_id_accepts_a_reasonable_slug() {
        assert_eq!(validate_mokosh_account_id("acme").unwrap(), "acme");
        assert_eq!(
            validate_mokosh_account_id("  ops-team  ").unwrap(),
            "ops-team"
        );
    }

    #[test]
    fn validate_mokosh_account_id_refuses_empty_and_control_chars() {
        assert!(validate_mokosh_account_id("").is_err());
        assert!(validate_mokosh_account_id("   ").is_err());
        assert!(validate_mokosh_account_id("acme\0inc").is_err());
    }
}
