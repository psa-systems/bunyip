//! Per-user row level security plumbing (BUNYIP-344).
//!
//! [`AppPool`] is the connection pool used to serve strictly self-service reads
//! under the fail-closed `user_isolation` RLS policy (migration
//! `20260713000010_rls_self_service_tables.sql`). In production it should point
//! at a NOBYPASSRLS `bunyip_app` role (via `APP_DATABASE_URL`); when that role
//! is not provisioned it falls back to the primary pool, where RLS is a no-op
//! because the primary role bypasses it. Either way [`begin_with_user`] sets the
//! per-request user context, so rerouting a handler through it is safe whether
//! or not the isolating role exists yet.
//!
//! Only genuinely self-service paths (a logged-in user reading/writing their own
//! rows) may use this pool. Pre-auth, cross-user, Stripe-webhook, OIDC, and
//! admin paths have no current-user context and must keep using the primary
//! `web::Data<PgPool>` system pool. See the BUNYIP-344 ticket comment for the
//! rationale and the full table enumeration.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::errors::AppError;

/// The self-service connection pool, wrapped in a newtype so Actix app state can
/// distinguish it from the primary `web::Data<PgPool>` system pool. Cloning is
/// cheap (an `Arc` clone of the underlying `PgPool`).
#[derive(Clone)]
pub struct AppPool(pub PgPool);

impl AppPool {
    /// Borrow the underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.0
    }
}

/// Open a transaction with the per-user RLS GUC `app.current_user_id` set
/// transaction-locally.
///
/// The value is set with `set_config(.., true)` (transaction-scoped, the sqlx
/// equivalent of `SET LOCAL`) so it never leaks to the next request that reuses
/// the pooled connection, and it is bound as a parameter (not interpolated) so
/// there is no injection surface even though `user_id` is a `Uuid`.
///
/// Callers MUST run their self-service queries on the returned transaction (via
/// `&mut *tx`) and `commit()` it. A query run on a fresh pool checkout would not
/// see the GUC and, on a NOBYPASSRLS role, fail-close to zero rows.
pub async fn begin_with_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Transaction<'_, Postgres>, AppError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('app.current_user_id', $1, true)")
        .bind(user_id.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
