//! Admin Mokosh host settings (BUNYIP-983).
//!
//! The Google OAuth client a hosted Mokosh uses for contact sync. Modelled on
//! the Mirzam pair (BUNYIP-997): the public half is the singleton
//! `mokosh_config` row and the secret half is the governed secret
//! `MOKOSH_GOOGLE_CLIENT_SECRET`, read from and written to the ONE provider
//! `SECRETS_STORAGE` declares and never sent back.
//!
//! One thing is unlike every other config pair here. Changing the client id
//! invalidates every Google grant a Mokosh tenant has already given: their
//! refresh tokens were issued to the OLD client, so contact sync stops for all
//! of them until each one reconnects. So a changed id is refused once, with the
//! consequence spelled out, and accepted on a second request that carries
//! `confirm_client_id_change` (BUNYIP-855 D10). The secret can be rotated
//! freely, which is the point of having it separate: a leaked secret is
//! replaced without touching anybody's grant.

use actix_web::{web, HttpRequest, HttpResponse};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::config::{Config, GovernedSecret};
use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::{
    validate_google_client_id, validate_google_client_secret, AuditAction, CreateAuditLog,
    MokoshConfigResponse, UpdateMokoshConfigRequest,
};
use crate::repositories::{AuditLogRepository, MokoshConfigRepository};
use crate::responses::{get_request_id, success};
use crate::services::EncryptionKeySet;

/// What an admin is warned about before a changed client id is accepted. The
/// text is the consequence, not the mechanism: the reader decides whether to
/// break every tenant's sync right now or at a quieter hour.
pub const CLIENT_ID_CHANGE_WARNING: &str =
    "Changing the client id stops Google contact sync for every Mokosh tenant until each one \
     reconnects their Google account: their existing permission was granted to the old client. \
     Send the same change again with confirm_client_id_change to go ahead.";

/// The secret as the declared provider holds it, blank read as absent.
async fn stored_secret(
    pool: &PgPool,
    config: &Config,
    key_set: &EncryptionKeySet,
) -> Result<Option<String>, AppError> {
    Ok(crate::secrets::read_secret(
        pool,
        config,
        key_set,
        GovernedSecret::MokoshGoogleClientSecret,
    )
    .await?
    .filter(|s| !s.trim().is_empty()))
}

/// The SHA-256 of a secret, hex. What the audit row carries so two saves can be
/// told apart and a re-save of the same value is visible as one, without the
/// value itself reaching the trail.
fn content_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// `GET /v1/admin/mokosh`
pub async fn get_mokosh_config(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<EncryptionKeySet>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let row = MokoshConfigRepository::get(&pool).await?;
    let has_secret = stored_secret(&pool, &config, &app_key_set).await?.is_some();
    Ok(success(
        MokoshConfigResponse::new(&row, config.secrets_provider, has_secret),
        request_id,
    ))
}

/// `PUT /v1/admin/mokosh`
///
/// The client id is replaced whole; `google_client_secret` empty or absent
/// leaves the stored secret as it is, so correcting a mistyped id does not mean
/// re-entering the secret. A changed id without `confirm_client_id_change` is a
/// 409 carrying [`CLIENT_ID_CHANGE_WARNING`].
pub async fn update_mokosh_config(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<EncryptionKeySet>,
    body: web::Json<UpdateMokoshConfigRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let provider = config.secrets_provider;
    let secret = body
        .google_client_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if secret.is_some() && !provider.is_writable() {
        return Err(crate::secrets::read_only_provider_error(
            GovernedSecret::MokoshGoogleClientSecret,
        ));
    }

    // Nothing is written until every field passes.
    let client_id = validate_google_client_id(&body.google_client_id)
        .map_err(|e| AppError::validation(e.field.to_string(), e.message))?;
    let secret = match secret {
        Some(raw) => Some(
            validate_google_client_secret(raw)
                .map_err(|e| AppError::validation(e.field.to_string(), e.message))?,
        ),
        None => None,
    };

    let row = MokoshConfigRepository::get(&pool).await?;
    let previous_id = row.google_client_id.trim().to_string();
    let id_changed = client_id != previous_id;
    // BUNYIP-855 D10. Only a change away from an id that was already set
    // warns: the first time one is set there is no grant to invalidate, and
    // asking twice for the initial setup would be ceremony.
    if id_changed && !previous_id.is_empty() && !body.confirm_client_id_change {
        return Err(AppError::Conflict {
            message: CLIENT_ID_CHANGE_WARNING.to_string(),
        });
    }

    // A client id with no secret is not a usable credential, so the pair is
    // refused rather than served half-set: the route would answer "not set"
    // either way, and saying so here names the field an admin is looking at.
    if !client_id.is_empty()
        && secret.is_none()
        && stored_secret(&pool, &config, &app_key_set).await?.is_none()
    {
        return Err(AppError::validation(
            GovernedSecret::MokoshGoogleClientSecret.form_field(),
            "Set the client secret too: an id without it authenticates as nothing.",
        ));
    }

    // The secret goes first, so a failed Infisical write aborts the save with
    // its cause and leaves the row untouched.
    if let Some(secret) = secret.as_deref() {
        crate::secrets::write_secret(
            &pool,
            &config,
            &app_key_set,
            provider,
            GovernedSecret::MokoshGoogleClientSecret,
            secret,
            Some(admin.0.sub),
        )
        .await?;
    }
    let row = MokoshConfigRepository::update_client_id(&pool, &client_id, admin.0.sub).await?;

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminMokoshConfigUpdated)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_metadata(serde_json::json!({
                "setting": "mokosh_config",
                // Public by nature, and recording it is what makes "who
                // pointed the suite at that Google project" answerable.
                "google_client_id": client_id,
                "client_id_changed": id_changed,
                // Never the secret: that it changed, where it went, and a hash
                // so two saves can be told apart.
                "secret_changed": secret.is_some(),
                "secret": secret
                    .as_ref()
                    .map(|_| GovernedSecret::MokoshGoogleClientSecret.name()),
                "secret_store": secret.as_ref().map(|_| provider.as_str()),
                "secret_sha256": secret.as_deref().map(content_hash),
            })),
    )
    .await?;

    let has_secret =
        secret.is_some() || stored_secret(&pool, &config, &app_key_set).await?.is_some();
    Ok(success(
        MokoshConfigResponse::new(&row, provider, has_secret),
        request_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_content_hash_is_sha256_hex_and_not_the_value() {
        let hash = content_hash("fixture-client-secret");
        assert_eq!(hash.len(), 64, "sha256 as hex");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(hash, "fixture-client-secret");
        assert_eq!(
            hash,
            content_hash("fixture-client-secret"),
            "the same value hashes the same, so a re-save reads as one"
        );
        assert_ne!(hash, content_hash("fixture-client-secret-2"));
    }

    /// The warning names the consequence for a tenant, not the mechanism. An
    /// admin deciding whether to do this now needs to know what breaks.
    #[test]
    fn the_warning_says_what_a_changed_client_id_costs() {
        assert!(CLIENT_ID_CHANGE_WARNING.contains("every Mokosh tenant"));
        assert!(CLIENT_ID_CHANGE_WARNING.contains("reconnect"));
        assert!(
            CLIENT_ID_CHANGE_WARNING.contains("confirm_client_id_change"),
            "and how to go ahead"
        );
    }

    /// The secret never reaches the audit metadata. Read off this file's own
    /// source, so a later edit that adds it fails the build.
    #[test]
    fn the_audit_metadata_never_carries_the_secret() {
        let src = include_str!("admin_mokosh.rs");
        let head = &src[..src.find("mod tests").expect("this module")];
        let metadata = head
            .find("with_metadata(serde_json::json!({")
            .map(|at| {
                &head[at..head[at..]
                    .find("})),")
                    .map(|end| at + end)
                    .unwrap_or(head.len())]
            })
            .expect("the audit metadata block");
        assert!(
            !metadata.contains("\"secret_value\""),
            "the audit row carries a hash, never the value: {metadata}"
        );
        assert!(
            metadata.contains("secret_sha256"),
            "and it does carry the hash: {metadata}"
        );
    }
}
