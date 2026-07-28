//! BUNYIP-408: profile avatar upload / removal / serving.
//!
//! Storage and validation mirror the feedback-attachment hardening (BUNYIP-90):
//! the bytes live in a Postgres BYTEA (`user_avatars`), every check runs against
//! file CONTENT (magic-byte sniff + header-only dimension parse), never the
//! browser's declared MIME or filename, and the bytes are served back only
//! through [`get_avatar`] with an explicit image Content-Type and
//! `Content-Disposition: inline`. bunyip-api has no static file mount, so an
//! uploaded avatar can never be served from an origin where it could execute.

use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use sqlx::PgPool;

use crate::errors::AppError;
use crate::middleware::AuthenticatedUser;
use crate::models::UserResponse;
use crate::repositories::UserRepository;
use crate::responses::{get_request_id, success};

/// 2 MiB. Matches the `user_avatars.size_bytes` CHECK constraint so a bypassed
/// app-layer check still cannot store an unbounded blob.
const MAX_AVATAR_SIZE: usize = 2 * 1024 * 1024;

/// Avatars are images only - a tighter allowlist than feedback (no text/plain).
const ALLOWED_MIME_TYPES: &[&str] = &["image/png", "image/jpeg", "image/webp", "image/gif"];

/// Reject decompression-bomb / oversized images by their pixel dimensions,
/// parsed header-only so no decoder ever runs against adversarial input.
const MAX_IMAGE_DIMENSION: usize = 4096;

/// Resolve the canonical MIME from the file's magic bytes, ignoring whatever the
/// browser claimed. Only the sniffed type is trusted, and it must be in the
/// image allowlist; anything unrecognised or non-image is rejected.
fn sniff_image_mime(bytes: &[u8]) -> Result<String, AppError> {
    match infer::get(bytes) {
        Some(kind) if ALLOWED_MIME_TYPES.contains(&kind.mime_type()) => {
            Ok(kind.mime_type().to_string())
        }
        Some(kind) => {
            tracing::warn!(sniffed_mime = %kind.mime_type(), "Avatar rejected: not an allowed image type");
            Err(AppError::validation(
                "avatar",
                "File must be a PNG, JPEG, WebP, or GIF image",
            ))
        }
        None => {
            tracing::warn!("Avatar rejected: could not verify image type from content");
            Err(AppError::validation(
                "avatar",
                "Could not verify the file is an image",
            ))
        }
    }
}

/// Header-only dimension guard (via `imagesize`, no pixel decode). Blocks a
/// billion-pixel "PNG" bomb before it is ever stored or served.
fn enforce_dimensions(bytes: &[u8]) -> Result<(), AppError> {
    let size = imagesize::blob_size(bytes).map_err(|e| {
        tracing::warn!(error = %e, "Avatar rejected: could not parse image dimensions");
        AppError::validation("avatar", "Could not parse image dimensions")
    })?;
    if size.width > MAX_IMAGE_DIMENSION || size.height > MAX_IMAGE_DIMENSION {
        tracing::warn!(
            width = size.width,
            height = size.height,
            "Avatar rejected: dimensions exceed limit"
        );
        return Err(AppError::validation(
            "avatar",
            "Image is larger than 4096x4096 pixels",
        ));
    }
    Ok(())
}

/// POST /v1/users/me/avatar (multipart, field name `avatar`).
///
/// Reads the single file part, enforces the 2 MiB cap while streaming, sniffs
/// the MIME from content, guards dimensions, then UPSERTs the bytes. Returns the
/// refreshed [`UserResponse`] so the caller sees the new `avatar_updated_at`.
pub async fn upload_avatar(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    mut payload: Multipart,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let mut avatar_bytes: Option<Vec<u8>> = None;
    while let Some(mut field) = payload
        .try_next()
        .await
        .map_err(|_| AppError::validation("avatar", "Invalid multipart data"))?
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
                .map_err(|_| AppError::validation("avatar", "Failed to read field"))?
                .is_some()
            {}
            continue;
        }

        let mut bytes = Vec::new();
        while let Some(chunk) = field
            .try_next()
            .await
            .map_err(|_| AppError::validation("avatar", "Failed to read field"))?
        {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > MAX_AVATAR_SIZE {
                return Err(AppError::validation(
                    "avatar",
                    "Image exceeds the 2 MB limit",
                ));
            }
        }
        avatar_bytes = Some(bytes);
        break;
    }

    let bytes = avatar_bytes.ok_or_else(|| AppError::validation("avatar", "No image provided"))?;
    if bytes.is_empty() {
        return Err(AppError::validation("avatar", "No image provided"));
    }

    let mime = sniff_image_mime(&bytes)?;
    enforce_dimensions(&bytes)?;

    let updated = UserRepository::set_avatar(&pool, user.0.sub, &mime, &bytes).await?;
    tracing::info!(user_id = %user.0.sub, mime = %mime, size = bytes.len(), "Avatar updated");

    Ok(success(UserResponse::from(updated), request_id))
}

/// DELETE /v1/users/me/avatar. Idempotent removal; returns the refreshed user.
pub async fn delete_avatar(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let updated = UserRepository::clear_avatar(&pool, user.0.sub).await?;
    tracing::info!(user_id = %user.0.sub, "Avatar removed");
    Ok(success(UserResponse::from(updated), request_id))
}

/// GET /v1/users/me/avatar. Streams the stored bytes with the stored image MIME
/// and `inline` disposition. 404 when the user has no avatar (the caller renders
/// the initials/icon fallback). Authenticated: only the owner fetches their own
/// avatar, so no cross-user enumeration surface is exposed.
pub async fn get_avatar(
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let (mime, data) = UserRepository::get_avatar(&pool, user.0.sub)
        .await?
        .ok_or_else(|| AppError::not_found("Avatar"))?;

    Ok(HttpResponse::Ok()
        .content_type(mime)
        .insert_header(("Content-Disposition", "inline"))
        // Private: it is a per-user resource behind auth, and the ?v= version in
        // the URL already busts the cache on change.
        .insert_header(("Cache-Control", "private, max-age=300"))
        .body(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1x1 transparent PNG.
    const PNG_1X1: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    #[test]
    fn sniffs_png_from_magic_bytes() {
        assert_eq!(sniff_image_mime(PNG_1X1).unwrap(), "image/png");
    }

    #[test]
    fn rejects_non_image_content() {
        // A plain-text payload has no image magic bytes.
        let err = sniff_image_mime(b"#!/bin/sh\necho pwned\n").unwrap_err();
        assert!(matches!(err, AppError::ValidationError { .. }));
    }

    #[test]
    fn rejects_disallowed_image_type_by_content() {
        // A BMP is a real image but not in the allowlist; the sniffer catches it
        // regardless of any claimed content-type.
        let bmp = b"BM\x00\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00";
        let err = sniff_image_mime(bmp).unwrap_err();
        assert!(matches!(err, AppError::ValidationError { .. }));
    }

    #[test]
    fn accepts_dimensions_within_limit() {
        assert!(enforce_dimensions(PNG_1X1).is_ok());
    }
}
