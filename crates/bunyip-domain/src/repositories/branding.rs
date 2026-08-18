//! Branding repository (singleton, id = 1) - BUNYIP-561.
//!
//! Runtime `sqlx::query_as`, like every other repository in this crate; only
//! `bunyip-oidc` uses the compile-time macros, so `.sqlx/` needs no
//! regeneration when these queries change.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::branding::{BrandingAssetSlot, BrandingRow};

pub struct BrandingRepository;

impl BrandingRepository {
    pub async fn get(pool: &PgPool) -> Result<BrandingRow, AppError> {
        let row = sqlx::query_as::<_, BrandingRow>("SELECT * FROM branding WHERE id = 1")
            .fetch_one(pool)
            .await?;
        Ok(row)
    }

    /// Replace every editable text field. Deliberately NOT a COALESCE update:
    /// an empty string is the meaningful value that clears a tagline,
    /// description, Open Graph image or palette entry, and "leave it alone"
    /// would make clearing impossible. The asset markers are NOT touched here;
    /// they belong to [`Self::set_asset`] / [`Self::clear_asset`].
    pub async fn update(
        pool: &PgPool,
        brand_name: &str,
        tagline: &str,
        meta_description: &str,
        og_image_url: &str,
        theme_css: &str,
        theme_color_light: &str,
        theme_color_dark: &str,
        updated_by: Uuid,
    ) -> Result<BrandingRow, AppError> {
        let row = sqlx::query_as::<_, BrandingRow>(
            r#"
            UPDATE branding
            SET brand_name        = $1,
                tagline           = $2,
                meta_description  = $3,
                og_image_url      = $4,
                theme_css         = $5,
                theme_color_light = $6,
                theme_color_dark  = $7,
                updated_at        = NOW(),
                updated_by        = $8
            WHERE id = 1
            RETURNING *
            "#,
        )
        .bind(brand_name)
        .bind(tagline)
        .bind(meta_description)
        .bind(og_image_url)
        .bind(theme_css)
        .bind(theme_color_light)
        .bind(theme_color_dark)
        .bind(updated_by)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }

    /// BUNYIP-560: the stored bytes for one asset key, or `None` when the slot
    /// is unset. The only read that transfers a BYTEA.
    pub async fn get_asset(
        pool: &PgPool,
        kind: &str,
    ) -> Result<Option<(String, Vec<u8>)>, AppError> {
        let row: Option<(String, Vec<u8>)> =
            sqlx::query_as("SELECT mime_type, data FROM branding_assets WHERE kind = $1")
                .bind(kind)
                .fetch_optional(pool)
                .await?;
        Ok(row)
    }

    /// BUNYIP-560: replace every key a slot owns and stamp its version marker,
    /// in ONE transaction.
    ///
    /// `files` is the complete new content of the slot: the favicon slot writes
    /// its source plus the whole derived set here, so a partially derived icon
    /// set can never be observed, and a failure anywhere leaves the previous
    /// brand intact rather than half-replaced.
    pub async fn set_asset(
        pool: &PgPool,
        slot: BrandingAssetSlot,
        files: &[(&str, String, Vec<u8>)],
        updated_by: Uuid,
    ) -> Result<BrandingRow, AppError> {
        let mut tx = pool.begin().await?;

        // Delete first: a slot's key set can shrink (a derived size retired),
        // and a stale key would otherwise keep being served.
        for kind in slot.storage_kinds() {
            sqlx::query("DELETE FROM branding_assets WHERE kind = $1")
                .bind(kind)
                .execute(&mut *tx)
                .await?;
        }
        for (kind, mime, data) in files {
            sqlx::query(
                "INSERT INTO branding_assets (kind, mime_type, size_bytes, data, updated_at) \
                 VALUES ($1, $2, $3, $4, NOW())",
            )
            .bind(kind)
            .bind(mime)
            .bind(data.len() as i32)
            .bind(data)
            .execute(&mut *tx)
            .await?;
        }

        // The column name comes from the slot enum, never from a request, so
        // the format! is over a fixed alphabet of three identifiers.
        let row = sqlx::query_as::<_, BrandingRow>(&format!(
            "UPDATE branding SET {} = NOW(), updated_at = NOW(), updated_by = $1 \
             WHERE id = 1 RETURNING *",
            slot.version_column()
        ))
        .bind(updated_by)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(row)
    }

    /// BUNYIP-560: clear every key a slot owns and null its version marker, in
    /// one transaction. Idempotent.
    pub async fn clear_asset(
        pool: &PgPool,
        slot: BrandingAssetSlot,
        updated_by: Uuid,
    ) -> Result<BrandingRow, AppError> {
        let mut tx = pool.begin().await?;
        for kind in slot.storage_kinds() {
            sqlx::query("DELETE FROM branding_assets WHERE kind = $1")
                .bind(kind)
                .execute(&mut *tx)
                .await?;
        }
        let row = sqlx::query_as::<_, BrandingRow>(&format!(
            "UPDATE branding SET {} = NULL, updated_at = NOW(), updated_by = $1 \
             WHERE id = 1 RETURNING *",
            slot.version_column()
        ))
        .bind(updated_by)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The version column is interpolated into the UPDATE, so it must never be
    /// anything but one of the three identifiers the enum owns. A slot that
    /// grew a caller-supplied name would be an injection point.
    #[test]
    fn every_version_column_is_a_fixed_identifier() {
        for slot in [
            BrandingAssetSlot::Mark,
            BrandingAssetSlot::Favicon,
            BrandingAssetSlot::Mascot,
        ] {
            let column = slot.version_column();
            assert!(
                ["mark_updated_at", "favicon_updated_at", "mascot_updated_at"].contains(&column),
                "{column} is not one of the branding marker columns"
            );
        }
    }
}
