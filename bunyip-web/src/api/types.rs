//! Shared types between the SPA and the mokosh-server identity backend.
//!
//! Two layers:
//! - `MeView` is the wire shape returned by `GET /v1/auth/me`. Mirrors
//!   `crates/mokosh-auth-http/src/handlers/profile.rs::MeView` field
//!   for field.
//! - `MeResponse` is the SPA-facing shape consumed by pages /
//!   components. `api::me::fetch_me` adapts a `MeView` into it,
//!   synthesizing fields that mokosh-server does not return today
//!   (e.g. memberships are fetched separately, lifetime_member is
//!   not part of the Mokosh data model).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    Manager,
    Finance,
    Member,
    Readonly,
}

impl UserRole {
    pub fn from_wire(s: &str) -> Self {
        match s {
            "admin" => UserRole::Admin,
            "manager" => UserRole::Manager,
            "finance" => UserRole::Finance,
            "readonly" => UserRole::Readonly,
            _ => UserRole::Member,
        }
    }
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
    /// mokosh-server does not surface email-verification state on `/me`
    /// today; we synthesize a `Some(...)` placeholder once the bearer
    /// extractor accepted the call. Future work can expose the real
    /// timestamp through `/me`.
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
    /// Populated in phase 04 by an additional fetch of
    /// `/v1/auth/memberships`. Empty until then.
    pub memberships: Vec<OrgMembership>,
}

/// Wire shape returned by `GET /v1/auth/me` on mokosh-server.
#[derive(Debug, Clone, Deserialize)]
pub struct MeView {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub locale: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    pub role: String,
    #[serde(default)]
    pub mfa_enrolled: bool,
}

impl MeView {
    pub fn display_name(&self) -> String {
        match (self.first_name.as_deref(), self.last_name.as_deref()) {
            (Some(f), Some(l)) if !f.is_empty() && !l.is_empty() => format!("{f} {l}"),
            (Some(f), _) if !f.is_empty() => f.to_string(),
            (_, Some(l)) if !l.is_empty() => l.to_string(),
            _ => self.email.clone(),
        }
    }

    /// Adapt a wire `MeView` into the SPA's `MeResponse`. Memberships
    /// are intentionally empty; phase 04 fetches them and merges in.
    pub fn into_me_response(self) -> MeResponse {
        let name = self.display_name();
        let role = UserRole::from_wire(&self.role);
        let mfa = self.mfa_enrolled;
        MeResponse {
            user: User {
                id: self.id,
                email: self.email,
                name,
                role,
                // Synthesized "verified" since the bearer extractor
                // already accepted the call. Replace with a real
                // timestamp when /me grows the field.
                email_verified_at: Some("verified".into()),
                lifetime_member: false,
                mfa_enabled: mfa,
            },
            memberships: Vec::new(),
        }
    }
}
