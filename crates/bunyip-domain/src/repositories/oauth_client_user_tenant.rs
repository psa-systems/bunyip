//! Repository for `(oauth_client, user) -> tenant_id` assignments
//! (BUNYIP-61). Powers the OIDC tenancy work in the BUNYIP-60 umbrella.
//!
//! The `assignments_for` lookup is the hot path: it runs on every
//! `/authorize` for a client whose `tenant_claim_name` is non-null,
//! and the count drives the branch (0 -> deny, 1 -> auto-select, N
//! -> render picker). The covering index in the migration
//! (`oauth_client_user_tenants_by_user`) keeps this query off a
//! sequential scan even on a saturated table.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{CreateUserTenantAssignment, OAuthClientUserTenant};

pub struct OAuthClientUserTenantRepository;

impl OAuthClientUserTenantRepository {
    /// Every assignment for the given `(client, user)` pair, oldest
    /// first. The order is stable so the tenant picker UI renders
    /// deterministically across reloads. Empty vec is a meaningful
    /// result, not an error.
    pub async fn assignments_for(
        pool: &PgPool,
        oauth_client_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<OAuthClientUserTenant>, AppError> {
        let rows = sqlx::query_as::<_, OAuthClientUserTenant>(
            r#"
            SELECT id, oauth_client_id, user_id, tenant_id, role, created_at, created_by
            FROM oauth_client_user_tenants
            WHERE oauth_client_id = $1 AND user_id = $2
            ORDER BY created_at ASC
            "#,
        )
        .bind(oauth_client_id)
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Every assignment for the given client, regardless of user.
    /// Powers the admin list view; no pagination in v1 since the
    /// realistic order of magnitude is tens to low hundreds per client.
    pub async fn list_for_client(
        pool: &PgPool,
        oauth_client_id: Uuid,
    ) -> Result<Vec<OAuthClientUserTenant>, AppError> {
        let rows = sqlx::query_as::<_, OAuthClientUserTenant>(
            r#"
            SELECT id, oauth_client_id, user_id, tenant_id, role, created_at, created_by
            FROM oauth_client_user_tenants
            WHERE oauth_client_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(oauth_client_id)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    /// Create or upsert (since the unique key is the triple, INSERT
    /// ON CONFLICT DO NOTHING). Returns the resolved row whether the
    /// caller's payload was the inserted one or an existing duplicate.
    /// `created_by` may be `None` for system-issued assignments
    /// (migrations, scripts) and `Some(admin_user_id)` for admin-API
    /// calls.
    pub async fn assign(
        pool: &PgPool,
        oauth_client_id: Uuid,
        payload: &CreateUserTenantAssignment,
        created_by: Option<Uuid>,
    ) -> Result<OAuthClientUserTenant, AppError> {
        // BUNYIP-946 F13: `role` is `Option<String>` with `#[serde(default)]`,
        // so a retried call that omits it binds NULL. The upsert used to
        // overwrite the stored `role` with that NULL, silently clearing a
        // previously-set role; `COALESCE(EXCLUDED.role, ...)` keeps the
        // retry a no-op repaint the way the doc comment claims.
        let row = sqlx::query_as::<_, OAuthClientUserTenant>(
            r#"
            INSERT INTO oauth_client_user_tenants
                (oauth_client_id, user_id, tenant_id, role, created_by)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (oauth_client_id, user_id, tenant_id) DO UPDATE
                SET role = COALESCE(EXCLUDED.role, oauth_client_user_tenants.role)
            RETURNING id, oauth_client_id, user_id, tenant_id, role, created_at, created_by
            "#,
        )
        .bind(oauth_client_id)
        .bind(payload.user_id)
        .bind(payload.tenant_id)
        .bind(payload.role.as_deref())
        .bind(created_by)
        .fetch_one(pool)
        .await?;
        Ok(row)
    }

    /// Delete a single assignment. Idempotent: returns `Ok(None)` when
    /// the row is already gone, so a retry after a network hiccup
    /// does not 500. On a real delete it returns the removed row so the
    /// caller can act on the freed `(user, tenant)` pair (BUNYIP-200:
    /// revoke that user's refresh-token families for the client).
    pub async fn unassign(
        pool: &PgPool,
        oauth_client_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<Option<OAuthClientUserTenant>, AppError> {
        // BUNYIP-946 F13: scope the DELETE to the path's client as well as
        // the assignment id so a mismatch (assignment belongs to a
        // different client) is a no-op rather than a cross-attributed
        // delete that the audit log misreports under the wrong client.
        let row = sqlx::query_as::<_, OAuthClientUserTenant>(
            r#"
            DELETE FROM oauth_client_user_tenants
            WHERE id = $1 AND oauth_client_id = $2
            RETURNING id, oauth_client_id, user_id, tenant_id, role, created_at, created_by
            "#,
        )
        .bind(assignment_id)
        .bind(oauth_client_id)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }
}
