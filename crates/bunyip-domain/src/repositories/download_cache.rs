//! Database access for the `download_cache` table.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::download::DownloadCacheRow;

pub struct DownloadCacheRepository;

impl DownloadCacheRepository {
    pub async fn find(
        pool: &PgPool,
        application_id: Uuid,
        release_tag: &str,
        asset_name: &str,
    ) -> Result<Option<DownloadCacheRow>, AppError> {
        let row = sqlx::query_as::<_, DownloadCacheRow>(
            r#"
            SELECT * FROM download_cache
            WHERE application_id = $1 AND release_tag = $2 AND asset_name = $3
            "#,
        )
        .bind(application_id)
        .bind(release_tag)
        .bind(asset_name)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }

    /// Insert-or-update the cache row. Returns the new row, plus the SHA of
    /// the row it replaced (only when the upsert hit an existing row and the
    /// SHA changed). Callers use the replaced SHA to unlink an orphaned
    /// on-disk blob if nothing else references it.
    pub async fn upsert(
        pool: &PgPool,
        application_id: Uuid,
        release_tag: &str,
        asset_name: &str,
        content_sha256: &str,
        size_bytes: i64,
        content_type: &str,
    ) -> Result<(DownloadCacheRow, Option<String>), AppError> {
        let mut tx = pool.begin().await?;
        let prior: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT content_sha256 FROM download_cache
            WHERE application_id = $1 AND release_tag = $2 AND asset_name = $3
            FOR UPDATE
            "#,
        )
        .bind(application_id)
        .bind(release_tag)
        .bind(asset_name)
        .fetch_optional(&mut *tx)
        .await?;

        let row = sqlx::query_as::<_, DownloadCacheRow>(
            r#"
            INSERT INTO download_cache
                (application_id, release_tag, asset_name, content_sha256, size_bytes, content_type)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (application_id, release_tag, asset_name)
            DO UPDATE SET content_sha256 = EXCLUDED.content_sha256,
                          size_bytes = EXCLUDED.size_bytes,
                          content_type = EXCLUDED.content_type,
                          last_accessed_at = NOW()
            RETURNING *
            "#,
        )
        .bind(application_id)
        .bind(release_tag)
        .bind(asset_name)
        .bind(content_sha256)
        .bind(size_bytes)
        .bind(content_type)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        let replaced = prior.map(|p| p.0).filter(|s| s != content_sha256);
        Ok((row, replaced))
    }

    pub async fn touch(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        let res = sqlx::query("UPDATE download_cache SET last_accessed_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        if res.rows_affected() == 0 {
            tracing::warn!(id = %id, "download_cache touch matched no row (concurrently evicted?)");
        }
        Ok(())
    }

    /// Delete all rows for `(application_id, release_tag)`. Returns the
    /// SHA-256 values whose on-disk files may now be unreferenced.
    pub async fn delete_for_tag(
        pool: &PgPool,
        application_id: Uuid,
        release_tag: &str,
    ) -> Result<Vec<String>, AppError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            DELETE FROM download_cache
            WHERE application_id = $1 AND release_tag = $2
            RETURNING content_sha256
            "#,
        )
        .bind(application_id)
        .bind(release_tag)
        .fetch_all(pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Returns true if any row still references this SHA (after a delete).
    pub async fn sha_referenced(pool: &PgPool, content_sha256: &str) -> Result<bool, AppError> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM download_cache WHERE content_sha256 = $1")
                .bind(content_sha256)
                .fetch_one(pool)
                .await?;
        Ok(count > 0)
    }

    pub async fn total_bytes(pool: &PgPool) -> Result<i64, AppError> {
        let (total,): (Option<i64>,) = sqlx::query_as("SELECT SUM(size_bytes) FROM download_cache")
            .fetch_one(pool)
            .await?;
        Ok(total.unwrap_or(0))
    }

    /// Returns up to `limit` oldest-by-last-accessed rows.
    pub async fn list_lru(pool: &PgPool, limit: i64) -> Result<Vec<DownloadCacheRow>, AppError> {
        let rows = sqlx::query_as::<_, DownloadCacheRow>(
            "SELECT * FROM download_cache ORDER BY last_accessed_at ASC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(pool)
        .await?;
        Ok(rows)
    }

    pub async fn delete_by_id(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        sqlx::query("DELETE FROM download_cache WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
