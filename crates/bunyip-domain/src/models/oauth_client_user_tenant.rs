//! `(oauth_client, user) -> tenant_id` assignment model.
//!
//! Backs the OIDC tenancy work (BUNYIP-60 umbrella): bunyip mints
//! at+jwt / id_token with a per-RP tenant claim sourced from these
//! rows. The tenant_id is OPAQUE - bunyip does not own a tenants
//! table; each RP defines what the UUID means.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct OAuthClientUserTenant {
    pub id: Uuid,
    pub oauth_client_id: Uuid,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    /// RP-specific scratch space (e.g. `owner`, `member`). v1 does not
    /// interpret this; reserved so RPs can start emitting it without a
    /// second migration.
    pub role: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
}

/// Payload for POST `/v1/admin/oauth-clients/{client_id}/user-tenants`.
#[derive(Debug, serde::Deserialize)]
pub struct CreateUserTenantAssignment {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    #[serde(default)]
    pub role: Option<String>,
}
