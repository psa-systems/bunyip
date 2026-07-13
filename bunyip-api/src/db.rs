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

/// Idempotently provision the unprivileged `bunyip_app` role that activates the
/// per-user RLS policies (BUNYIP-360).
///
/// Mirrors the Mokosh role posture (`mokosh-server/src/db/provision.rs`), scoped
/// to bunyip's single extra role. `pool` is the primary connection, which runs
/// as the DB owner/superuser (`bunyip`) and can therefore `CREATE ROLE` without
/// a separate admin connection. Run this AFTER migrations so the
/// `GRANT ... ON ALL TABLES` covers every table they created; every statement is
/// idempotent, so it is safe to run on each boot.
///
/// The role is `NOSUPERUSER NOBYPASSRLS`, so the `user_isolation` policies bind
/// it. It owns nothing; the primary role keeps owning the schema and running
/// migrations, and (as a superuser) keeps bypassing RLS. `ALTER DEFAULT
/// PRIVILEGES` (no `FOR ROLE`, so it applies to objects created by the current
/// role - the same role that runs migrations) auto-grants future tables.
///
/// The role name is a fixed identifier (no injection surface); the password and
/// database name cannot be bind parameters in these utility statements, so they
/// are quoted as an SQL literal / identifier with embedded quotes doubled.
pub async fn provision_app_role(pool: &PgPool, password: &str) -> Result<(), AppError> {
    let db_name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await?;

    let pw = sql_quote(password);
    let db = quote_ident(&db_name);

    // CREATE ROLE is not idempotent, so guard it with a DO block; the ALTER ROLE
    // afterwards reconciles the password + attributes on an already-existing
    // role (e.g. a rotated password).
    let statements: Vec<String> = vec![
        format!(
            "DO $do$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bunyip_app') \
             THEN CREATE ROLE bunyip_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {pw}; END IF; END $do$"
        ),
        format!("ALTER ROLE bunyip_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {pw}"),
        format!("GRANT CONNECT ON DATABASE {db} TO bunyip_app"),
        "GRANT USAGE ON SCHEMA public TO bunyip_app".to_string(),
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bunyip_app"
            .to_string(),
        "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bunyip_app".to_string(),
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public \
         GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bunyip_app"
            .to_string(),
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public \
         GRANT USAGE, SELECT ON SEQUENCES TO bunyip_app"
            .to_string(),
    ];

    for stmt in &statements {
        sqlx::query(stmt).execute(pool).await.map_err(|e| {
            AppError::internal(format!("bunyip_app provisioning step failed ({e}): {stmt}"))
        })?;
    }

    tracing::info!(
        database = %db_name,
        "bunyip_app RLS role provisioned (NOSUPERUSER NOBYPASSRLS)"
    );
    Ok(())
}

/// Quote a string as a single-quoted SQL literal, doubling embedded quotes.
fn sql_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Quote an SQL identifier, doubling embedded double-quotes.
fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::{quote_ident, sql_quote};

    #[test]
    fn sql_quote_doubles_embedded_single_quotes() {
        assert_eq!(sql_quote("plain"), "'plain'");
        assert_eq!(sql_quote("o'brien"), "'o''brien'");
        assert_eq!(sql_quote("'; DROP ROLE --"), "'''; DROP ROLE --'");
    }

    #[test]
    fn quote_ident_doubles_embedded_double_quotes() {
        assert_eq!(quote_ident("bunyip"), "\"bunyip\"");
        assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
    }
}
