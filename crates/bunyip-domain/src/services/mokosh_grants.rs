//! BUNYIP-673 [BUNYIP-626 child 2]: cross-account Mokosh grants service.
//!
//! Every method gates on `orgs_enabled` (BUNYIP-493 rule) matching the
//! sibling org services. The grantee resolution accepts either
//! `grantee_email` or `grantee_bunyip_user_id`; email is the friendlier
//! admin path and the shape the parent ticket asked for, id is the
//! machine one. Exactly one must be present.
//!
//! Portal-contact separation (BUNYIP-675) is enforced at write time by
//! the FK to `users(id)` on the table: portal contacts are a Mokosh-side
//! concept and never appear in `users`, so a caller granting to a
//! portal-contact-only email surfaces as a `not_found` on the email
//! lookup rather than a foreign-key violation.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{
    validate_grant_role, validate_mokosh_account_id, CreateGrantRequest, MokoshAccountGrant,
};
use crate::repositories::{MokoshGrantRepository, UserRepository};

pub struct MokoshGrantsService;

impl MokoshGrantsService {
    pub async fn create_grant(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        req: CreateGrantRequest,
    ) -> Result<MokoshAccountGrant, AppError> {
        gate(orgs_enabled)?;

        // Exactly-one grantee identifier. `serde(default)` on both
        // fields lets the caller pick either; here we refuse both-set
        // and neither-set with a validation error naming which.
        let grantee_id = resolve_grantee_id(pool, &req).await?;
        if grantee_id == owner_bunyip_user_id {
            return Err(AppError::validation(
                "grantee",
                "cannot grant access to yourself",
            ));
        }

        let mokosh_account_id = validate_mokosh_account_id(&req.mokosh_account_id)
            .map_err(|msg| AppError::validation("mokosh_account_id", msg))?;

        if !validate_grant_role(&req.role) {
            return Err(AppError::validation(
                "role",
                "role must be one of admin | manager | technician | finance | read_only",
            ));
        }

        MokoshGrantRepository::create(
            pool,
            owner_bunyip_user_id,
            grantee_id,
            &mokosh_account_id,
            &req.role,
        )
        .await
    }

    pub async fn list_own(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
    ) -> Result<Vec<MokoshAccountGrant>, AppError> {
        gate(orgs_enabled)?;
        MokoshGrantRepository::list_active_by_owner(pool, owner_bunyip_user_id).await
    }

    pub async fn list_received(
        pool: &PgPool,
        orgs_enabled: bool,
        grantee_bunyip_user_id: Uuid,
    ) -> Result<Vec<MokoshAccountGrant>, AppError> {
        gate(orgs_enabled)?;
        MokoshGrantRepository::list_active_by_grantee(pool, grantee_bunyip_user_id).await
    }

    /// Revoke a grant. The caller must be the grant's owner: a grantee
    /// who no longer wants the access can ask the owner to revoke, or
    /// leave (a "leave" endpoint is BUNYIP-673 follow-up work; keeping
    /// the write path single-owner for v1 keeps the audit trail clean).
    pub async fn revoke_grant(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
        grant_id: Uuid,
    ) -> Result<MokoshAccountGrant, AppError> {
        gate(orgs_enabled)?;
        // Distinguish "unknown id" from "not yours" so the caller sees
        // 404 on genuinely-missing and the audit log records the 403 on
        // an attempted foreign revoke.
        let existing = MokoshGrantRepository::find_by_id(pool, grant_id)
            .await?
            .ok_or_else(|| AppError::not_found("Mokosh grant"))?;
        if existing.owner_bunyip_user_id != owner_bunyip_user_id {
            return Err(AppError::Forbidden);
        }
        // Already revoked is a no-op that reads back the current row so
        // the caller sees the same shape; the partial UNIQUE index
        // means a second revoke can never leave a stale active row.
        if existing.revoked_at.is_some() {
            return Ok(existing);
        }
        MokoshGrantRepository::revoke(pool, grant_id, owner_bunyip_user_id)
            .await?
            .ok_or_else(|| AppError::not_found("Mokosh grant"))
    }
}

async fn resolve_grantee_id(pool: &PgPool, req: &CreateGrantRequest) -> Result<Uuid, AppError> {
    match (&req.grantee_email, &req.grantee_bunyip_user_id) {
        (Some(email), None) => {
            let trimmed = email.trim();
            if trimmed.is_empty() {
                return Err(AppError::validation("grantee_email", "cannot be empty"));
            }
            UserRepository::find_by_email(pool, trimmed)
                .await?
                .map(|u| u.id)
                .ok_or_else(|| AppError::not_found("Bunyip user"))
        }
        (None, Some(id)) => UserRepository::find_by_id(pool, *id)
            .await?
            .map(|u| u.id)
            .ok_or_else(|| AppError::not_found("Bunyip user")),
        (Some(_), Some(_)) => Err(AppError::validation(
            "grantee",
            "supply grantee_email OR grantee_bunyip_user_id, not both",
        )),
        (None, None) => Err(AppError::validation(
            "grantee",
            "grantee_email or grantee_bunyip_user_id is required",
        )),
    }
}

fn gate(orgs_enabled: bool) -> Result<(), AppError> {
    if orgs_enabled {
        Ok(())
    } else {
        // Mirrors sibling gates: off is invisible, not inert.
        Err(AppError::not_found("Grants"))
    }
}
