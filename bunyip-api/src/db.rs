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

    for (label, stmt) in provisioning_statements(password, &db_name) {
        sqlx::query(&stmt)
            .execute(pool)
            .await
            .map_err(|e| provisioning_error(label, &e))?;
    }

    tracing::info!(
        database = %db_name,
        "bunyip_app RLS role provisioned (NOSUPERUSER NOBYPASSRLS)"
    );
    Ok(())
}

/// The provisioning statements, each paired with a stable label.
///
/// Two of them embed the password as an SQL literal, so the statement text is a
/// secret and must never reach a log or an error (BUNYIP-426 F5); the label is
/// what identifies the failing step instead.
fn provisioning_statements(password: &str, db_name: &str) -> Vec<(&'static str, String)> {
    let pw = sql_quote(password);
    let db = quote_ident(db_name);

    // CREATE ROLE is not idempotent, so guard it with a DO block; the ALTER ROLE
    // afterwards reconciles the password + attributes on an already-existing
    // role (e.g. a rotated password).
    vec![
        (
            "create_role",
            format!(
                "DO $do$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'bunyip_app') \
                 THEN CREATE ROLE bunyip_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {pw}; END IF; END $do$"
            ),
        ),
        (
            "alter_role",
            format!("ALTER ROLE bunyip_app LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {pw}"),
        ),
        (
            "grant_connect",
            format!("GRANT CONNECT ON DATABASE {db} TO bunyip_app"),
        ),
        (
            "grant_usage_schema",
            "GRANT USAGE ON SCHEMA public TO bunyip_app".to_string(),
        ),
        (
            "grant_tables",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bunyip_app"
                .to_string(),
        ),
        (
            "grant_sequences",
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bunyip_app".to_string(),
        ),
        (
            "default_privileges_tables",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public \
             GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO bunyip_app"
                .to_string(),
        ),
        (
            "default_privileges_sequences",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public \
             GRANT USAGE, SELECT ON SEQUENCES TO bunyip_app"
                .to_string(),
        ),
    ]
}

/// Build the error for a failed provisioning step. Names the step by label only;
/// the statement text is never interpolated, because two of the statements carry
/// `BUNYIP_APP_PASSWORD` in plaintext and this error is logged at `error!`.
fn provisioning_error(label: &str, e: &sqlx::Error) -> AppError {
    AppError::internal(format!(
        "bunyip_app provisioning step '{label}' failed: {e}"
    ))
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
    use super::{provisioning_error, provisioning_statements, quote_ident, sql_quote};

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

    /// BUNYIP-426 F5: a failing provisioning step must name the step and never
    /// the statement, because two statements carry the password in plaintext.
    #[test]
    fn provisioning_error_never_leaks_the_password() {
        const PASSWORD: &str = "s3cr3t-app-role-password";
        let statements = provisioning_statements(PASSWORD, "bunyip");

        // Sanity check the premise: the password really is in the statement text.
        assert!(statements[0].1.contains(PASSWORD));
        assert!(statements[1].1.contains(PASSWORD));

        for (label, _stmt) in &statements {
            let err = provisioning_error(label, &sqlx::Error::PoolClosed);
            let rendered = err.to_string();
            assert!(
                !rendered.contains(PASSWORD),
                "step '{label}' leaked the password: {rendered}"
            );
            assert!(
                rendered.contains(label),
                "step '{label}' lost the operator diagnostic: {rendered}"
            );
        }
    }
}
