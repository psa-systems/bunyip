//! DB access for the `oci_blob_cache` table.
//!
//! Implements the dunite-oci [`BlobStore`](dunite_oci::store::BlobStore) trait
//! against Bunyip's Postgres schema, so the generic
//! [`BlobCache`](dunite_oci::services::BlobCache) can record per-digest
//! bookkeeping (LRU eviction, reachability sweeps) without depending on the
//! schema.

use async_trait::async_trait;
use sqlx::PgPool;

use crate::errors::AppError;
use crate::models::oci::{NewCachedBlob, OciBlobCacheRow};

/// Postgres-backed blob-cache bookkeeping store.
#[derive(Clone)]
pub struct OciBlobCacheRepository {
    pool: PgPool,
}

impl OciBlobCacheRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn find(&self, digest: &str) -> Result<Option<OciBlobCacheRow>, AppError> {
        let row = sqlx::query_as::<_, OciBlobCacheRow>(
            "SELECT content_digest, size_bytes, media_type, created_at, last_accessed_at
             FROM oci_blob_cache WHERE content_digest = $1",
        )
        .bind(digest)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Insert or update a cache entry. Bumps `last_accessed_at` on conflict.
    pub async fn upsert(&self, new_blob: &NewCachedBlob) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO oci_blob_cache (content_digest, size_bytes, media_type)
             VALUES ($1, $2, $3)
             ON CONFLICT (content_digest) DO UPDATE
                 SET size_bytes = EXCLUDED.size_bytes,
                     media_type = COALESCE(EXCLUDED.media_type, oci_blob_cache.media_type),
                     last_accessed_at = NOW()",
        )
        .bind(&new_blob.content_digest)
        .bind(new_blob.size_bytes)
        .bind(&new_blob.media_type)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn touch(&self, digest: &str) -> Result<(), AppError> {
        sqlx::query("UPDATE oci_blob_cache SET last_accessed_at = NOW() WHERE content_digest = $1")
            .bind(digest)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn total_size_bytes(&self) -> Result<i64, AppError> {
        let (total,): (Option<i64>,) = sqlx::query_as("SELECT SUM(size_bytes) FROM oci_blob_cache")
            .fetch_one(&self.pool)
            .await?;
        Ok(total.unwrap_or(0))
    }

    /// Return rows for LRU eviction in oldest-last-access-first order, up to `limit`.
    pub async fn oldest(&self, limit: i64) -> Result<Vec<OciBlobCacheRow>, AppError> {
        let rows = sqlx::query_as::<_, OciBlobCacheRow>(
            "SELECT content_digest, size_bytes, media_type, created_at, last_accessed_at
             FROM oci_blob_cache ORDER BY last_accessed_at ASC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn delete(&self, digest: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM oci_blob_cache WHERE content_digest = $1")
            .bind(digest)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete rows whose digest is NOT in the given set. Returns deleted digests
    /// so the caller can unlink files.
    pub async fn delete_except(&self, keep: &[String]) -> Result<Vec<String>, AppError> {
        let deleted: Vec<(String,)> = sqlx::query_as(
            "DELETE FROM oci_blob_cache WHERE content_digest <> ALL($1)
             RETURNING content_digest",
        )
        .bind(keep)
        .fetch_all(&self.pool)
        .await?;
        Ok(deleted.into_iter().map(|(d,)| d).collect())
    }
}

/// Wire the Postgres repository to the engine's storage trait. Each method
/// simply delegates to the inherent SQL method above.
#[async_trait]
impl dunite_oci::store::BlobStore for OciBlobCacheRepository {
    async fn find(&self, digest: &str) -> Result<Option<OciBlobCacheRow>, AppError> {
        OciBlobCacheRepository::find(self, digest).await
    }

    async fn upsert(&self, blob: &NewCachedBlob) -> Result<(), AppError> {
        OciBlobCacheRepository::upsert(self, blob).await
    }

    async fn touch(&self, digest: &str) -> Result<(), AppError> {
        OciBlobCacheRepository::touch(self, digest).await
    }

    async fn total_size_bytes(&self) -> Result<i64, AppError> {
        OciBlobCacheRepository::total_size_bytes(self).await
    }

    async fn oldest(&self, limit: i64) -> Result<Vec<OciBlobCacheRow>, AppError> {
        OciBlobCacheRepository::oldest(self, limit).await
    }

    async fn delete(&self, digest: &str) -> Result<(), AppError> {
        OciBlobCacheRepository::delete(self, digest).await
    }

    async fn delete_except(&self, keep: &[String]) -> Result<Vec<String>, AppError> {
        OciBlobCacheRepository::delete_except(self, keep).await
    }
}

#[cfg(test)]
mod tests {
    //! DB-backed integration tests. Skipped when DATABASE_URL is unset.
    use super::*;

    async fn maybe_repo() -> Option<OciBlobCacheRepository> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = PgPool::connect(&url).await.ok()?;
        Some(OciBlobCacheRepository::new(pool))
    }

    /// Clean rows this test family might have inserted, so reruns are idempotent.
    async fn cleanup(repo: &OciBlobCacheRepository, digests: &[&str]) {
        for d in digests {
            repo.delete(d).await.ok();
        }
    }

    #[actix_rt::test]
    async fn upsert_inserts_then_touches() {
        let Some(repo) = maybe_repo().await else {
            return;
        };
        let digest = format!("sha256:test-upsert-{}", uuid::Uuid::new_v4());
        cleanup(&repo, &[&digest]).await;

        repo.upsert(&NewCachedBlob {
            content_digest: digest.clone(),
            size_bytes: 100,
            media_type: Some("application/octet-stream".into()),
        })
        .await
        .unwrap();

        let first = repo.find(&digest).await.unwrap().unwrap();
        let first_access = first.last_accessed_at;

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        repo.upsert(&NewCachedBlob {
            content_digest: digest.clone(),
            size_bytes: 100,
            media_type: None,
        })
        .await
        .unwrap();

        let second = repo.find(&digest).await.unwrap().unwrap();
        assert!(second.last_accessed_at > first_access);
        assert_eq!(
            second.media_type.as_deref(),
            Some("application/octet-stream")
        );

        cleanup(&repo, &[&digest]).await;
    }

    #[actix_rt::test]
    async fn oldest_orders_by_last_accessed() {
        let Some(repo) = maybe_repo().await else {
            return;
        };
        let a = format!("sha256:test-oldest-a-{}", uuid::Uuid::new_v4());
        let b = format!("sha256:test-oldest-b-{}", uuid::Uuid::new_v4());
        cleanup(&repo, &[&a, &b]).await;

        repo.upsert(&NewCachedBlob {
            content_digest: a.clone(),
            size_bytes: 1,
            media_type: None,
        })
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        repo.upsert(&NewCachedBlob {
            content_digest: b.clone(),
            size_bytes: 1,
            media_type: None,
        })
        .await
        .unwrap();

        let rows = repo.oldest(1000).await.unwrap();
        let a_idx = rows
            .iter()
            .position(|r| r.content_digest == a)
            .expect("a present");
        let b_idx = rows
            .iter()
            .position(|r| r.content_digest == b)
            .expect("b present");
        assert!(a_idx < b_idx, "a was inserted first, should come before b");

        cleanup(&repo, &[&a, &b]).await;
    }

    #[actix_rt::test]
    async fn delete_removes_row() {
        let Some(repo) = maybe_repo().await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let a = format!("sha256:test-del-a-{}", suffix);
        let b = format!("sha256:test-del-b-{}", suffix);
        let c = format!("sha256:test-del-c-{}", suffix);
        cleanup(&repo, &[&a, &b, &c]).await;

        for d in [&a, &b, &c] {
            repo.upsert(&NewCachedBlob {
                content_digest: d.clone(),
                size_bytes: 1,
                media_type: None,
            })
            .await
            .unwrap();
        }

        repo.delete(&c).await.unwrap();

        assert!(repo.find(&a).await.unwrap().is_some());
        assert!(repo.find(&b).await.unwrap().is_some());
        assert!(repo.find(&c).await.unwrap().is_none());

        cleanup(&repo, &[&a, &b, &c]).await;
    }
}
