//! Admin branding configuration (BUNYIP-561).
//!
//! Modelled on the email-config pair: a singleton row read and replaced whole.
//! A save writes the row AND refreshes the api-side cache in the same request,
//! so email subjects and the TOTP issuer pick the change up without a restart.

use std::sync::Arc;

use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use dunite_image_upload::{validate_image, ImagePolicy, ImageValidationError};
use futures_util::TryStreamExt;
use sqlx::PgPool;

use crate::branding_assets::{derive_favicons, DerivedAsset};
use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::{
    validate_branding, AuditAction, BrandingAssetSlot, BrandingCache, BrandingResponse,
    CreateAuditLog, UpdateBrandingRequest,
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
        &clean.theme_css,
        &clean.theme_color_light,
        &clean.theme_color_dark,
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
                "theme_css": clean.theme_css,
                "theme_color_light": clean.theme_color_light,
                "theme_color_dark": clean.theme_color_dark,
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

/// BUNYIP-560: the slot named in the path, or a 400 that names the legal set.
/// Parsed before anything is read, so an unknown slot never reaches storage.
fn parse_slot(raw: &str) -> Result<BrandingAssetSlot, AppError> {
    BrandingAssetSlot::parse(raw).ok_or_else(|| {
        AppError::validation(
            "asset",
            "Unknown brand asset. Expected mark, favicon or mascot.",
        )
    })
}

/// Convert a shared-crate validation failure into bunyip's error type, keeping
/// the crate's wording (it describes the rule, never the bytes) and scoping it
/// to the `asset` field so the admin form attaches it to the right input.
fn asset_err(e: ImageValidationError) -> AppError {
    tracing::warn!(reason = ?e, "Brand asset rejected");
    AppError::validation("asset", e.to_string())
}

/// Read the single uploaded file part, enforcing the byte cap while streaming.
async fn read_upload(payload: &mut Multipart, policy: &ImagePolicy) -> Result<Vec<u8>, AppError> {
    while let Some(mut field) = payload
        .try_next()
        .await
        .map_err(|_| AppError::validation("asset", "Invalid multipart data"))?
    {
        let is_file = field
            .content_disposition()
            .and_then(|cd| cd.get_filename())
            .is_some();
        if !is_file {
            // Drain and skip any stray text field.
            while field
                .try_next()
                .await
                .map_err(|_| AppError::validation("asset", "Failed to read field"))?
                .is_some()
            {}
            continue;
        }

        let mut bytes = Vec::new();
        while let Some(chunk) = field
            .try_next()
            .await
            .map_err(|_| AppError::validation("asset", "Failed to read field"))?
        {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > policy.max_bytes {
                return Err(asset_err(ImageValidationError::TooLarge {
                    max_bytes: policy.max_bytes,
                }));
            }
        }
        return Ok(bytes);
    }
    Err(asset_err(ImageValidationError::Empty))
}

/// `POST /v1/admin/branding/assets/{slot}` (multipart, one file part).
///
/// Nothing is written until the bytes validate AND, for the favicon slot, the
/// whole derived set encodes: the slot is replaced as one transaction, so a
/// failure leaves the previous brand intact rather than half-replaced, and the
/// reason reaches the admin form as a 400 rather than a 500 (BUNYIP-506).
pub async fn upload_branding_asset(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    branding: web::Data<Arc<BrandingCache>>,
    slot: web::Path<String>,
    mut payload: Multipart,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let slot = parse_slot(&slot)?;
    // Same policy the avatar upload enforces (2 MiB / 4096px / PNG-JPEG-WebP-
    // GIF), which is also what the branding_assets size CHECK is set to.
    let policy = ImagePolicy::avatar();

    let bytes = read_upload(&mut payload, &policy).await?;
    let mime = validate_image(&bytes, &policy).map_err(asset_err)?;

    let files: Vec<DerivedAsset> = match slot {
        // BUNYIP-553: decoding and seven resizes are CPU work, and actix never
        // migrates a connection's futures off its arbiter, so this runs on the
        // blocking pool. A JoinError is logged and surfaced, never collapsed
        // into "that image was invalid".
        BrandingAssetSlot::Favicon => {
            match tokio::task::spawn_blocking(move || derive_favicons(bytes)).await {
                Ok(Ok(files)) => files,
                Ok(Err(message)) => return Err(AppError::validation("asset", message)),
                Err(e) => {
                    tracing::error!(error = %e, "Favicon derivation task failed to join");
                    return Err(AppError::internal("Could not process that image"));
                }
            }
        }
        BrandingAssetSlot::Mark => vec![("mark", mime.clone(), bytes)],
        BrandingAssetSlot::Mascot => vec![("mascot", mime.clone(), bytes)],
    };

    let row = BrandingRepository::set_asset(&pool, slot, &files, admin.0.sub).await?;
    let resolved = branding.store(&row);
    tracing::info!(
        slot = slot.as_str(),
        mime = %mime,
        files = files.len(),
        "Brand asset uploaded"
    );

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminBrandingUpdated)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_metadata(serde_json::json!({
                "setting": "branding_asset",
                "slot": slot.as_str(),
                "action": "upload",
                "mime": mime,
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

/// `DELETE /v1/admin/branding/assets/{slot}`. Idempotent: clearing a slot that
/// is already empty is a success, because the state the admin asked for is the
/// state they get.
pub async fn delete_branding_asset(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    branding: web::Data<Arc<BrandingCache>>,
    slot: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let slot = parse_slot(&slot)?;

    let row = BrandingRepository::clear_asset(&pool, slot, admin.0.sub).await?;
    let resolved = branding.store(&row);
    tracing::info!(slot = slot.as_str(), "Brand asset cleared");

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminBrandingUpdated)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_metadata(serde_json::json!({
                "setting": "branding_asset",
                "slot": slot.as_str(),
                "action": "clear",
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
    use super::*;
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

    /// BUNYIP-560: the path parameter reaches a fixed enum, never storage. An
    /// unknown slot is a 400 the form can render, not a 500 and not a query.
    #[test]
    fn an_unknown_asset_slot_is_a_renderable_rejection() {
        for slot in ["mark", "favicon", "mascot"] {
            assert_eq!(
                parse_slot(slot).expect("a known slot").as_str(),
                slot,
                "the slot round-trips"
            );
        }
        for bad in ["logo", "", "../mark", "favicon-32"] {
            let err = parse_slot(bad).expect_err("an unknown slot is refused");
            assert_eq!(
                actix_web::ResponseError::status_code(&err),
                actix_web::http::StatusCode::BAD_REQUEST
            );
        }
    }

    /// The upload path's failures are all field-scoped 400s carrying the rule,
    /// so an admin who picks a 12 MB TIFF learns why instead of seeing the
    /// generic error line.
    #[test]
    fn an_upload_rejection_carries_the_rule_to_the_form() {
        match asset_err(ImageValidationError::UnknownType) {
            AppError::ValidationError { field, message } => {
                assert_eq!(field, "asset");
                assert!(!message.is_empty());
            }
            other => panic!("expected a field validation error, got {other:?}"),
        }
        // The app-layer cap and the branding_assets CHECK have to agree, or a
        // valid upload passes validation and then fails on insert.
        assert_eq!(ImagePolicy::avatar().max_bytes, 2 * 1024 * 1024);
    }
}
