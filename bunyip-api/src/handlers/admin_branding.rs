//! Admin branding configuration (BUNYIP-561).
//!
//! Modelled on the email-config pair: a singleton row read and replaced whole.
//! A save writes the row AND refreshes the api-side cache in the same request,
//! so email subjects and the TOTP issuer pick the change up without a restart.

use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::{
    validate_branding, AuditAction, BrandingCache, BrandingResponse, CreateAuditLog,
    UpdateBrandingRequest,
};
use crate::repositories::{AuditLogRepository, BrandingRepository};
use crate::responses::{get_request_id, success};

/// `GET /v1/admin/branding`
pub async fn get_branding(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    branding: web::Data<Arc<BrandingCache>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let row = BrandingRepository::get(&pool).await?;
    Ok(success(
        BrandingResponse {
            branding: branding.resolve(&row),
            updated_at: row.updated_at,
            updated_by: row.updated_by,
        },
        request_id,
    ))
}

/// `PUT /v1/admin/branding`
///
/// Validation failures are `AppError::validation`, i.e. a 400 carrying the
/// field and an admin-facing message. A 5xx here would be collapsed by
/// bunyip-web into the generic error line (BUNYIP-506), so the admin would
/// never learn which field was wrong.
pub async fn update_branding(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    branding: web::Data<Arc<BrandingCache>>,
    body: web::Json<UpdateBrandingRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Nothing is written until every field passes.
    let clean = validate_branding(&body)
        .map_err(|e| AppError::validation(e.field.to_string(), e.message))?;

    let row = BrandingRepository::update(
        &pool,
        &clean.brand_name,
        &clean.tagline,
        &clean.meta_description,
        &clean.og_image_url,
        admin.0.sub,
    )
    .await?;

    // Same request: the next email subject and the next TOTP enrolment already
    // use the new name.
    let resolved = branding.store(&row);
    tracing::info!(
        brand_name = %resolved.brand_name,
        "Branding updated and hot-reloaded"
    );

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminBrandingUpdated)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_metadata(serde_json::json!({
                "setting": "branding",
                // Public copy, not secrets: recording the values is what makes
                // "who renamed the product" answerable.
                "brand_name": clean.brand_name,
                "tagline": clean.tagline,
                "meta_description": clean.meta_description,
                "og_image_url": clean.og_image_url,
            })),
    )
    .await?;

    Ok(success(
        BrandingResponse {
            branding: resolved.as_ref().clone(),
            updated_at: row.updated_at,
            updated_by: row.updated_by,
        },
        request_id,
    ))
}

#[cfg(test)]
mod tests {
    use crate::models::{validate_branding, UpdateBrandingRequest, MAX_BRAND_NAME_LEN};

    /// The three rejections the admin form must be able to render: they are
    /// 400s with a per-field message, never a 500.
    #[test]
    fn rejections_carry_the_field_and_a_message() {
        let cases = [
            (
                UpdateBrandingRequest {
                    brand_name: "x".repeat(MAX_BRAND_NAME_LEN + 1),
                    ..UpdateBrandingRequest::default()
                },
                "brand_name",
            ),
            (
                UpdateBrandingRequest {
                    meta_description: "x".repeat(400),
                    ..UpdateBrandingRequest::default()
                },
                "meta_description",
            ),
            (
                UpdateBrandingRequest {
                    og_image_url: "/assets/card.png".into(),
                    ..UpdateBrandingRequest::default()
                },
                "og_image_url",
            ),
        ];
        for (req, field) in cases {
            let err = validate_branding(&req).expect_err("must be rejected");
            assert_eq!(err.field, field);
            assert!(!err.message.is_empty(), "the form renders this message");
            let app_error = crate::errors::AppError::validation(err.field.to_string(), err.message);
            assert_eq!(
                actix_web::ResponseError::status_code(&app_error),
                actix_web::http::StatusCode::BAD_REQUEST,
                "a 4xx, so bunyip-web does not collapse it to the generic line"
            );
        }
    }
}
