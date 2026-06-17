//! Trusted device repository (BUNYIP-138).
//!
//! Backs the "remember this device, skip TOTP" feature. Rows store only the
//! SHA-256 hash of the opaque cookie secret, mirroring `refresh_tokens`.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{CreateTrustedDevice, TrustedDevice};

pub struct TrustedDeviceRepository;

impl TrustedDeviceRepository {
    /// Create a trusted-device row.
    pub async fn create(
        pool: &PgPool,
        data: CreateTrustedDevice,
    ) -> Result<TrustedDevice, AppError> {
        let device = sqlx::query_as::<_, TrustedDevice>(
            r#"
            INSERT INTO trusted_devices (user_id, token_hash, label, ip_address, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
        )
        .bind(data.user_id)
        .bind(&data.token_hash)
        .bind(&data.label)
        .bind(data.ip_address)
        .bind(data.expires_at)
        .fetch_one(pool)
        .await?;

        Ok(device)
    }

    /// Find a trusted device by token hash that is still valid (not revoked,
    /// not expired). This is the lookup that gates a TOTP skip.
    pub async fn find_valid_by_hash(
        pool: &PgPool,
        token_hash: &str,
    ) -> Result<Option<TrustedDevice>, AppError> {
        let device = sqlx::query_as::<_, TrustedDevice>(
            r#"
            SELECT * FROM trusted_devices
            WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await?;

        Ok(device)
    }

    /// List a user's active (non-revoked, non-expired) trusted devices.
    pub async fn find_user_devices(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<TrustedDevice>, AppError> {
        let devices = sqlx::query_as::<_, TrustedDevice>(
            r#"
            SELECT * FROM trusted_devices
            WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;

        Ok(devices)
    }

    /// Find a trusted device by id (any state), for the ownership check on
    /// revoke.
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<TrustedDevice>, AppError> {
        let device = sqlx::query_as::<_, TrustedDevice>(
            r#"
            SELECT * FROM trusted_devices WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;

        Ok(device)
    }

    /// Bump `last_used_at` after a successful skip.
    pub async fn touch_last_used(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE trusted_devices SET last_used_at = NOW() WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Revoke a single trusted device.
    pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE trusted_devices SET revoked_at = NOW() WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Revoke all of a user's trusted devices. Called on password change,
    /// password reset, 2FA disable, and "log out everywhere", so a credential
    /// or 2FA change re-arms the TOTP prompt on every device.
    pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> Result<u64, AppError> {
        let result = sqlx::query(
            r#"
            UPDATE trusted_devices SET revoked_at = NOW()
            WHERE user_id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}
