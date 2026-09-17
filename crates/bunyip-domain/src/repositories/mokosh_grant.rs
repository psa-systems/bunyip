//! BUNYIP-673: repository for `mokosh_account_grants`.
//!
//! Thin SQL over the migration 20260915000060 table. The `orgs_enabled`
//! gate stays with the service; a background worker (BUNYIP-674's
//! webhook consumer) needs to write revocations without knowing the
//! flag decision was made upstream.

use sqlx::{Error as SqlxError, PgPool};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::MokoshAccountGrant;

pub struct MokoshGrantRepository;

impl MokoshGrantRepository {
    pub async fn create(
        pool: &PgPool,
        owner_bunyip_user_id: Uuid,
        grantee_bunyip_user_id: Uuid,
        mokosh_account_id: &str,
        role: &str,
    ) -> Result<MokoshAccountGrant, AppError> {
        sqlx::query_as::<_, MokoshAccountGrant>(
            "INSERT INTO mokosh_account_grants \
             (owner_bunyip_user_id, grantee_bunyip_user_id, mokosh_account_id, role) \
             VALUES ($1, $2, $3, $4) RETURNING *",
        )
        .bind(owner_bunyip_user_id)
        .bind(grantee_bunyip_user_id)
        .bind(mokosh_account_id)
        .bind(role)
        .fetch_one(pool)
        .await
        .map_err(map_sqlx)
    }

    pub async fn find_by_id(
        pool: &PgPool,
        id: Uuid,
    ) -> Result<Option<MokoshAccountGrant>, AppError> {
        sqlx::query_as::<_, MokoshAccountGrant>("SELECT * FROM mokosh_account_grants WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(map_sqlx)
    }

    /// Every ACTIVE grant the caller has issued. Revoked rows stay in the
    /// table for audit but are omitted from the list; a caller that needs
    /// the history is a BUNYIP-691 admin surface concern, not the shape
    /// the parent ticket asked for.
    pub async fn list_active_by_owner(
        pool: &PgPool,
        owner_bunyip_user_id: Uuid,
    ) -> Result<Vec<MokoshAccountGrant>, AppError> {
        sqlx::query_as::<_, MokoshAccountGrant>(
            "SELECT * FROM mokosh_account_grants \
             WHERE owner_bunyip_user_id = $1 AND revoked_at IS NULL \
             ORDER BY granted_at ASC",
        )
        .bind(owner_bunyip_user_id)
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)
    }

    /// Every ACTIVE grant the caller has received. This is what the app
    /// switcher renders as the "Shared with you" list (BUNYIP-691 SSR
    /// half).
    pub async fn list_active_by_grantee(
        pool: &PgPool,
        grantee_bunyip_user_id: Uuid,
    ) -> Result<Vec<MokoshAccountGrant>, AppError> {
        sqlx::query_as::<_, MokoshAccountGrant>(
            "SELECT * FROM mokosh_account_grants \
             WHERE grantee_bunyip_user_id = $1 AND revoked_at IS NULL \
             ORDER BY granted_at ASC",
        )
        .bind(grantee_bunyip_user_id)
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)
    }

    /// Revoke a grant. Returns the updated row so the caller can log the
    /// prior state. `Ok(None)` when the grant is unknown, when it is
    /// already revoked (idempotent), or when the caller is not the
    /// owner; the service picks which shape becomes a 404 vs a 403 and
    /// what to log for each.
    pub async fn revoke(
        pool: &PgPool,
        id: Uuid,
        owner_bunyip_user_id: Uuid,
    ) -> Result<Option<MokoshAccountGrant>, AppError> {
        sqlx::query_as::<_, MokoshAccountGrant>(
            "UPDATE mokosh_account_grants SET revoked_at = NOW() \
             WHERE id = $1 AND owner_bunyip_user_id = $2 AND revoked_at IS NULL \
             RETURNING *",
        )
        .bind(id)
        .bind(owner_bunyip_user_id)
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)
    }

    /// BUNYIP-748: change the role of an active grant in place.
    /// Returns the updated row (mirroring `revoke`'s shape) so the
    /// caller can log the transition AND fire the
    /// `mokosh_grant_changed` webhook against the current state.
    ///
    /// `Ok(None)` for unknown-id / foreign-caller / already-revoked:
    /// the WHERE clause names all three predicates and the service
    /// turns that into an enumeration-resistant 404, same shape as
    /// `revoke`. Same-role UPDATE returns Some (a caller asking to
    /// "change" to the current role is a no-op the service handles).
    ///
    /// The role is validated against the PMS-1162 CHECK constraint
    /// at write time; an unknown role trips 23514 and is mapped to
    /// 400 by `map_sqlx`. The partial UNIQUE index on (owner,
    /// grantee, mokosh_account) WHERE revoked_at IS NULL is
    /// unaffected because those three columns don't move; no index
    /// rebuild is needed.
    pub async fn update_role(
        pool: &PgPool,
        id: Uuid,
        owner_bunyip_user_id: Uuid,
        new_role: &str,
    ) -> Result<Option<MokoshAccountGrant>, AppError> {
        sqlx::query_as::<_, MokoshAccountGrant>(
            "UPDATE mokosh_account_grants SET role = $3 \
             WHERE id = $1 AND owner_bunyip_user_id = $2 AND revoked_at IS NULL \
             RETURNING *",
        )
        .bind(id)
        .bind(owner_bunyip_user_id)
        .bind(new_role)
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)
    }
}

/// BUNYIP-673 sqlx-to-AppError translation for a grant write.
///
/// Public so `bunyip-api::handlers::mokosh_grant_register` (the
/// PMS-1208 machine-authed registration endpoint) reuses this
/// exact mapping. Keeps 23505 -> 409, 23503 -> 400 and 23514 ->
/// 400 in one place; a second copy would drift the moment a new
/// constraint is added on the column.
pub fn map_mokosh_grant_error(e: SqlxError) -> AppError {
    map_sqlx(e)
}

fn map_sqlx(e: SqlxError) -> AppError {
    if let SqlxError::Database(db_err) = &e {
        match db_err.code().as_deref() {
            // UNIQUE violation: an active grant for this triple already
            // exists. The service returns 409 naming what to do.
            Some("23505") => return AppError::conflict(db_err.message().to_string()),
            // FOREIGN KEY violation: the grantee (or, at write time, the
            // grantor) is not a Bunyip user. Surface as 400 so a caller
            // trying to grant to a portal-contact-only email sees a
            // usable error rather than a 500.
            Some("23503") => {
                return AppError::bad_request(format!(
                    "Grantor and grantee must be Bunyip users: {}",
                    db_err.message()
                ))
            }
            // CHECK violation (bad role or self-grant). The service
            // validates role before the write, so this catches self-grant
            // slipping through the ID resolution path.
            Some("23514") => return AppError::bad_request(db_err.message().to_string()),
            _ => {}
        }
    }
    AppError::from(e)
}
