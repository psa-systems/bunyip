//! Bearer-token extractor for the OCI registry server.
//!
//! - Validates the token (aud=registry, exp, iss) via `OciTokenService`.
//! - Re-loads the user on every request and re-checks membership.
//! - Does NOT enforce scope — handlers that take a `<slug>` are
//!   responsible for calling `user.assert_scope(slug)`.

use actix_web::{dev::Payload, FromRequest, HttpRequest};
use sqlx::PgPool;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::errors::OciError;
use crate::repositories::UserRepository;
use crate::services::{OciTokenService, RegistryTokenClaims};

#[derive(Debug, Clone)]
pub struct OciBearerUser {
    pub claims: RegistryTokenClaims,
    pub email: String,
    pub role: String,
}

impl OciBearerUser {
    pub fn assert_scope(&self, slug: &str) -> Result<(), OciError> {
        let expected = format!("repository:{slug}:pull");
        if self.claims.scope == expected {
            Ok(())
        } else {
            Err(OciError::Denied)
        }
    }
}

impl FromRequest for OciBearerUser {
    type Error = OciError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let header = req
            .headers()
            .get(actix_web::http::header::AUTHORIZATION)
            .cloned();
        let token_svc = req.app_data::<Arc<OciTokenService>>().cloned();
        let pool = req.app_data::<actix_web::web::Data<PgPool>>().cloned();

        Box::pin(async move {
            let svc = token_svc.ok_or(OciError::Internal)?;
            let pool = pool.ok_or(OciError::Internal)?;

            let raw = header
                .and_then(|v| v.to_str().ok().map(str::to_string))
                .ok_or(OciError::Unauthorized)?;
            let token = raw.strip_prefix("Bearer ").ok_or(OciError::Unauthorized)?;
            let claims = svc.verify(token)?;

            let user = UserRepository::find_by_id(pool.get_ref(), claims.sub)
                .await
                .map_err(|_| OciError::Internal)?
                .ok_or(OciError::Unauthorized)?;
            if user.deleted_at.is_some() {
                return Err(OciError::Unauthorized);
            }
            if !user.is_access_allowed() {
                return Err(OciError::Unauthorized);
            }

            Ok(OciBearerUser {
                claims,
                email: user.email.clone(),
                role: user.role.clone(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_scope_accepts_matching_slug() {
        let user = OciBearerUser {
            claims: RegistryTokenClaims {
                sub: uuid::Uuid::new_v4(),
                aud: "registry".into(),
                scope: "repository:my-app:pull".into(),
                iat: 0,
                exp: i64::MAX,
                iss: "bunyip".into(),
            },
            email: "test@example.com".into(),
            role: "subscriber".into(),
        };
        assert!(user.assert_scope("my-app").is_ok());
        assert!(matches!(user.assert_scope("other"), Err(OciError::Denied)));
    }
}
