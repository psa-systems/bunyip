//! Database access for the `download_cache` table.
//!
//! Implements the dunite-download [`AssetStore`](dunite_download::store::AssetStore)
//! trait against Bunyip's Postgres schema, so the generic
//! [`DownloadCache`](dunite_download::services::DownloadCache) engine can record
//! per-asset bookkeeping (cache hits, LRU eviction, orphan cleanup) without
//! depending on the schema.

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::download::{DownloadCacheRow, NewCachedAsset};

/// Postgres-backed asset-cache bookkeeping store.
#[derive(Clone)]
pub struct DownloadCacheRepository {
    pool: PgPool,
}

impl DownloadCacheRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find(
        &self,
        application_id: Uuid,
        version: &str,
        asset_name: &str,
    ) -> Result<Option<DownloadCacheRow>, AppError> {
        let row = sqlx::query_as::<_, DownloadCacheRow>(
            r#"
            SELECT * FROM download_cache
            WHERE application_id = $1 AND version = $2 AND asset_name = $3
            "#,
        )
        .bind(application_id)
        .bind(version)
        .bind(asset_name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Insert-or-update the cache row. Returns the new row, plus the SHA of
    /// the row it replaced (only when the upsert hit an existing row and the
    /// SHA changed).
    ///
    /// The prior-SHA read and the write happen in one transaction holding a
    /// row lock (`SELECT ... FOR UPDATE`), as the `AssetStore::upsert`
    /// contract requires: a non-atomic find-then-write could mis-report the
    /// replaced SHA under concurrent upserts and break orphan-file cleanup.
    pub async fn upsert(
        &self,
        asset: &NewCachedAsset,
    ) -> Result<(DownloadCacheRow, Option<String>), AppError> {
        let mut tx = self.pool.begin().await?;
        let prior: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT content_sha256 FROM download_cache
            WHERE application_id = $1 AND version = $2 AND asset_name = $3
            FOR UPDATE
            "#,
        )
        .bind(asset.application_id)
        .bind(&asset.version)
        .bind(&asset.asset_name)
        .fetch_optional(&mut *tx)
        .await?;

        let row = sqlx::query_as::<_, DownloadCacheRow>(
            r#"
            INSERT INTO download_cache
                (application_id, version, asset_name, content_sha256, size_bytes, content_type)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (application_id, version, asset_name)
            DO UPDATE SET content_sha256 = EXCLUDED.content_sha256,
                          size_bytes = EXCLUDED.size_bytes,
                          content_type = EXCLUDED.content_type,
                          last_accessed_at = NOW()
            RETURNING *
            "#,
        )
        .bind(asset.application_id)
        .bind(&asset.version)
        .bind(&asset.asset_name)
        .bind(&asset.content_sha256)
        .bind(asset.size_bytes)
        .bind(&asset.content_type)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        let replaced = prior.map(|p| p.0).filter(|s| s != &asset.content_sha256);
        Ok((row, replaced))
    }

    pub async fn touch(&self, id: Uuid) -> Result<(), AppError> {
        let res = sqlx::query("UPDATE download_cache SET last_accessed_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if res.rows_affected() == 0 {
            tracing::warn!(id = %id, "download_cache touch matched no row (concurrently evicted?)");
        }
        Ok(())
    }

    /// Delete all rows for `(application_id, version)`. Returns the SHA-256
    /// values whose on-disk files may now be unreferenced.
    pub async fn delete_for_version(
        &self,
        application_id: Uuid,
        version: &str,
    ) -> Result<Vec<String>, AppError> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            DELETE FROM download_cache
            WHERE application_id = $1 AND version = $2
            RETURNING content_sha256
            "#,
        )
        .bind(application_id)
        .bind(version)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Returns true if any row still references this SHA (after a delete).
    pub async fn sha_referenced(&self, content_sha256: &str) -> Result<bool, AppError> {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM download_cache WHERE content_sha256 = $1")
                .bind(content_sha256)
                .fetch_one(&self.pool)
                .await?;
        Ok(count > 0)
    }

    pub async fn total_size_bytes(&self) -> Result<i64, AppError> {
        let (total,): (Option<i64>,) = sqlx::query_as("SELECT SUM(size_bytes) FROM download_cache")
            .fetch_one(&self.pool)
            .await?;
        Ok(total.unwrap_or(0))
    }

    /// Returns up to `limit` oldest-by-last-accessed rows.
    pub async fn oldest(&self, limit: i64) -> Result<Vec<DownloadCacheRow>, AppError> {
        let rows = sqlx::query_as::<_, DownloadCacheRow>(
            "SELECT * FROM download_cache ORDER BY last_accessed_at ASC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), AppError> {
        sqlx::query("DELETE FROM download_cache WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// Wire the Postgres repository to the engine's storage trait. Each method
/// simply delegates to the inherent SQL method above.
#[async_trait]
impl dunite_download::store::AssetStore for DownloadCacheRepository {
    async fn find(
        &self,
        application_id: Uuid,
        version: &str,
        asset_name: &str,
    ) -> Result<Option<DownloadCacheRow>, AppError> {
        DownloadCacheRepository::find(self, application_id, version, asset_name).await
    }

    async fn upsert(
        &self,
        asset: &NewCachedAsset,
    ) -> Result<(DownloadCacheRow, Option<String>), AppError> {
        DownloadCacheRepository::upsert(self, asset).await
    }

    async fn touch(&self, id: Uuid) -> Result<(), AppError> {
        DownloadCacheRepository::touch(self, id).await
    }

    async fn delete_for_version(
        &self,
        application_id: Uuid,
        version: &str,
    ) -> Result<Vec<String>, AppError> {
        DownloadCacheRepository::delete_for_version(self, application_id, version).await
    }

    async fn sha_referenced(&self, content_sha256: &str) -> Result<bool, AppError> {
        DownloadCacheRepository::sha_referenced(self, content_sha256).await
    }

    async fn total_size_bytes(&self) -> Result<i64, AppError> {
        DownloadCacheRepository::total_size_bytes(self).await
    }

    async fn oldest(&self, limit: i64) -> Result<Vec<DownloadCacheRow>, AppError> {
        DownloadCacheRepository::oldest(self, limit).await
    }

    async fn delete(&self, id: Uuid) -> Result<(), AppError> {
        DownloadCacheRepository::delete(self, id).await
    }
}
