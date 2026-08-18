//! Branding repository (singleton, id = 1) - BUNYIP-561.
//!
//! Runtime `sqlx::query_as`, like every other repository in this crate; only
//! `bunyip-oidc` uses the compile-time macros, so `.sqlx/` needs no
//! regeneration when these queries change.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::branding::BrandingRow;

pub struct BrandingRepository;

impl BrandingRepository {
    pub async fn get(pool: &PgPool) -> Result<BrandingRow, AppError> {
        let row = sqlx::query_as::<_, BrandingRow>("SELECT * FROM branding WHERE id = 1")
            .fetch_one(pool)
            .await?;
        Ok(row)
    }

    /// Replace all four fields. Deliberately NOT a COALESCE update: an empty
    /// string is the meaningful value that clears a tagline, description or
    /// Open Graph image, and "leave it alone" would make clearing impossible.
    pub async fn update(
        pool: &PgPool,
        brand_name: &str,
        tagline: &str,
        meta_description: &str,
        og_image_url: &str,
        updated_by: Uuid,
    ) -> Result<BrandingRow, AppError> {
        let row = sqlx::query_as::<_, BrandingRow>(
            r#"
            UPDATE branding
            SET brand_name       = $1,
                tagline          = $2,
                meta_description = $3,
                og_image_url     = $4,
                updated_at       = NOW(),
                updated_by       = $5
            WHERE id = 1
            RETURNING *
            "#,
        )
        .bind(brand_name)
        .bind(tagline)
        .bind(meta_description)
        .bind(og_image_url)
        .bind(updated_by)
        .fetch_one(pool)
        .await?;

        Ok(row)
    }
}
