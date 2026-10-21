//! Admin invite repository

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::token::{AdminInvite, CreateAdminInvite};

pub struct InviteRepository;

impl InviteRepository {
    /// Create a new admin invite
    pub async fn create(pool: &PgPool, data: CreateAdminInvite) -> Result<AdminInvite, AppError> {
        let invite = sqlx::query_as::<_, AdminInvite>(
            r#"
            INSERT INTO admin_invites (email, token_hash, invited_by, role, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(&data.email)
        .bind(&data.token_hash)
        .bind(data.invited_by)
        .bind(&data.role)
        .bind(data.expires_at)
        .fetch_one(pool)
        .await?;

        Ok(invite)
    }

    /// Find a valid (not revoked, not accepted, not expired) invite by token hash
    pub async fn find_valid_by_token_hash(
        pool: &PgPool,
        token_hash: &str,
    ) -> Result<Option<AdminInvite>, AppError> {
        let invite = sqlx::query_as::<_, AdminInvite>(
            r#"
            SELECT * FROM admin_invites
            WHERE token_hash = $1
              AND revoked_at IS NULL
              AND accepted_at IS NULL
              AND expires_at > NOW()
            "#,
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

        Ok(invite)
    }

    /// Find a pending (not revoked, not accepted, not expired) invite by email
    pub async fn find_pending_by_email(
        pool: &PgPool,
        email: &str,
    ) -> Result<Option<AdminInvite>, AppError> {
        let invite = sqlx::query_as::<_, AdminInvite>(
            r#"
            SELECT * FROM admin_invites
            WHERE LOWER(email) = LOWER($1)
              AND revoked_at IS NULL
              AND accepted_at IS NULL
              AND expires_at > NOW()
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(email)
        .fetch_optional(pool)
        .await?;

        Ok(invite)
    }

    /// Mark an invite as accepted
    pub async fn mark_accepted(pool: &PgPool, invite_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE admin_invites SET accepted_at = NOW() WHERE id = $1
            "#,
        )
        .bind(invite_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Mark an invite as revoked
    pub async fn mark_revoked(pool: &PgPool, invite_id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE admin_invites SET revoked_at = NOW() WHERE id = $1
            "#,
        )
        .bind(invite_id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Revoke all pending invites for an email
    pub async fn revoke_pending_by_email(pool: &PgPool, email: &str) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE admin_invites SET revoked_at = NOW()
            WHERE LOWER(email) = LOWER($1)
              AND revoked_at IS NULL
              AND accepted_at IS NULL
              AND expires_at > NOW()
            "#,
        )
        .bind(email)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// List all invites with pagination
    pub async fn list_all(
        pool: &PgPool,
        page: i32,
        per_page: i32,
    ) -> Result<(Vec<AdminInvite>, i64), AppError> {
        Self::list_filtered(pool, page, per_page, None, None).await
    }

    /// BUNYIP-939: paginated list with `status` (pending / accepted /
    /// revoked / expired) and `email` substring. The caller validates
    /// `status` against the closed set and caps `email` at 128 chars
    /// before passing them in.
    pub async fn list_filtered(
        pool: &sqlx::PgPool,
        page: i32,
        per_page: i32,
        status: Option<&str>,
        email: Option<&str>,
    ) -> Result<(Vec<AdminInvite>, i64), AppError> {
        use sqlx::QueryBuilder;

        let offset = (page - 1) * per_page;

        // Derived-state SQL mirrors the web renderer's classification:
        //   pending  = not used, not revoked, not expired
        //   accepted = used
        //   revoked  = revoked
        //   expired  = not used, not revoked, past expires_at
        let status_predicate: Option<&'static str> = match status {
            Some("pending") => {
                Some("used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()")
            }
            Some("accepted") => Some("used_at IS NOT NULL"),
            Some("revoked") => Some("revoked_at IS NOT NULL"),
            Some("expired") => {
                Some("used_at IS NULL AND revoked_at IS NULL AND expires_at <= NOW()")
            }
            _ => None,
        };

        fn push_where<'a>(
            qb: &mut QueryBuilder<'a, sqlx::Postgres>,
            status_predicate: Option<&'static str>,
            email: Option<&'a str>,
        ) {
            let mut sep = " WHERE ";
            if let Some(p) = status_predicate {
                qb.push(sep).push(p);
                sep = " AND ";
            }
            if let Some(e) = email {
                let pattern = format!("%{e}%");
                qb.push(sep).push("email ILIKE ").push_bind(pattern);
            }
        }

        let mut q = QueryBuilder::new("SELECT * FROM admin_invites");
        push_where(&mut q, status_predicate, email);
        q.push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(per_page as i64)
            .push(" OFFSET ")
            .push_bind(offset as i64);

        let mut c = QueryBuilder::new("SELECT COUNT(*) FROM admin_invites");
        push_where(&mut c, status_predicate, email);

        let invites = q.build_query_as::<AdminInvite>().fetch_all(pool).await?;
        let total: (i64,) = c.build_query_as().fetch_one(pool).await?;
        Ok((invites, total.0))
    }
}
