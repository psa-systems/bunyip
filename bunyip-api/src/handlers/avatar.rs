//! BUNYIP-408: profile avatar upload / removal / serving.
//!
//! DEV-531: the validation moved to the shared `dunite-image-upload` crate,
//! which a8n-tools consumes too (DEV-525). The rules are unchanged - every
//! check still runs against file CONTENT (magic-byte sniff + header-only
//! dimension parse), never the browser's declared MIME or filename, and
//! `ImagePolicy::avatar()` carries the same 2 MiB / 4096px / PNG-JPEG-WebP-GIF
//! limits this file used to define as constants.
//!
//! Storage and serving are unchanged and stay here: the bytes live in a
//! Postgres BYTEA (`user_avatars`) and come back only through [`get_avatar`]
//! with an explicit image Content-Type and `Content-Disposition: inline`.
//! bunyip-api has no static file mount, so an uploaded avatar can never be
//! served from an origin where it could execute.

use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use dunite_image_upload::{validate_image, ImagePolicy, ImageValidationError};
use futures_util::TryStreamExt;
use sqlx::PgPool;

use crate::errors::AppError;
use crate::middleware::AuthenticatedUser;
use crate::models::UserResponse;
use crate::repositories::UserRepository;
use crate::responses::{get_request_id, success};

/// Convert a shared-crate validation failure into bunyip's error type.
///
/// The wording is the crate's, which describes the rule and never the bytes;
/// the field name stays `avatar` so the client attaches it to the right input.
fn avatar_err(e: ImageValidationError) -> AppError {
    tracing::warn!(reason = ?e, "Avatar rejected");
    AppError::validation("avatar", e.to_string())
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
    let policy = ImagePolicy::avatar();

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
            if bytes.len() > policy.max_bytes {
                return Err(avatar_err(ImageValidationError::TooLarge {
                    max_bytes: policy.max_bytes,
                }));
            }
        }
        avatar_bytes = Some(bytes);
        break;
    }

    let bytes = avatar_bytes.ok_or_else(|| avatar_err(ImageValidationError::Empty))?;
    let mime = validate_image(&bytes, &policy).map_err(avatar_err)?;

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

    #[test]
    fn validation_failures_are_field_scoped_and_carry_the_rule() {
        // DEV-531: the sniffing and dimension cases live in dunite-image-upload
        // now, with a superset of what was here. What is still bunyip's to get
        // right is the conversion: the client attaches the message to the
        // avatar input, so the field name has to be ours while the wording
        // stays the shared crate's.
        match avatar_err(ImageValidationError::UnknownType) {
            AppError::ValidationError { field, message } => {
                assert_eq!(field, "avatar");
                assert_eq!(message, "Could not verify the file is an image");
            }
            other => panic!("expected a field validation error, got {other:?}"),
        }
    }

    #[test]
    fn the_size_cap_matches_the_storage_constraint() {
        // `user_avatars.size_bytes` has a CHECK at 2 MiB. If the shared policy
        // ever exceeded it, a valid upload would pass validation and then fail
        // on insert with a database error instead of a useful message.
        assert_eq!(ImagePolicy::avatar().max_bytes, 2 * 1024 * 1024);
    }
}
