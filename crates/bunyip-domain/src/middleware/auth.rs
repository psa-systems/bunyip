//! Authentication middleware and extractors
//!
//! This module provides JWT-based authentication middleware and extractors
//! for securing API endpoints.
//!
//! Two access-token shapes are accepted (BUNYIP-55):
//!
//! 1. Legacy HS256 access tokens issued by `bunyip-api`'s password-login
//!    path and stored in the `access_token` cookie. Verified by
//!    [`JwtService::verify_access_token`].
//! 2. OIDC EdDSA `at+jwt` access tokens minted by `bunyip-oidc`'s
//!    `/oauth2/token` endpoint and presented as
//!    `Authorization: Bearer <token>`. Verified by an
//!    [`AtJwtVerifier`] implementation registered in actix `app_data`
//!    (in practice, `bunyip-oidc`'s `OidcProvider`).
//!
//! The extractor peeks at the JWT header's `typ` claim to route: `typ
//! == "at+jwt"` goes through the EdDSA verifier (async path: signature
//! verify + DB user lookup), anything else goes through the legacy
//! HS256 verifier (sync path). Both paths produce the same
//! [`AccessTokenClaims`] so downstream handlers cannot tell which one
//! authenticated the caller. The HS256 path is unchanged from before
//! BUNYIP-55 landed.
//!
//! Endpoints that do not (or cannot) register an `AtJwtVerifier` keep
//! the legacy HS256-only behaviour: an `at+jwt` token presented at such
//! an endpoint is rejected with `AppError::Unauthorized`, identical to
//! the pre-BUNYIP-55 behaviour.

use crate::errors::AppError;
use crate::models::User;
use crate::repositories::user::UserRepository;
use crate::services::{AccessTokenClaims, JwtService};
use actix_web::{
    cookie::{Cookie, SameSite},
    dev::Payload,
    http::header,
    FromRequest, HttpMessage, HttpRequest,
};
use async_trait::async_trait;
use sqlx::PgPool;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use uuid::Uuid;

/// Verifier for OIDC EdDSA `at+jwt` access tokens.
///
/// Implemented by the OIDC vertical (`bunyip-oidc::OidcProvider`).
/// Defined here in `bunyip-domain` so the extractor can call into it
/// without `bunyip-domain` taking a dependency on `bunyip-oidc` (the
/// dependency direction goes the other way).
///
/// Implementations are expected to:
///
/// 1. Verify the token's EdDSA signature against the OP's JWKS (no
///    network round-trip; keys are in-process).
/// 2. Validate `typ == "at+jwt"`, `iss == <this OP's issuer>`, and
///    `exp > now` (with the standard ~30s leeway).
/// 3. Look up the user identified by `sub` in the `users` table and
///    populate `email`, `role`, `membership_status`, etc. The at+jwt
///    payload itself is RFC 9068 minimal and does not carry profile
///    claims, so the DB lookup is the only way to fill them in.
///
/// Returns the same [`AccessTokenClaims`] shape `JwtService` returns,
/// so downstream extractors (`AdminUser`, `MemberUser`) are unchanged.
#[async_trait]
pub trait AtJwtVerifier: Send + Sync {
    async fn verify_and_resolve(&self, token: &str) -> Result<AccessTokenClaims, AppError>;
}

/// Stub verifier that rejects every at+jwt with `Unauthorized`. Wired
/// in by `bunyip-api`'s `main.rs` when the OIDC provider is disabled
/// (no `OIDC_ISSUER` env), so the extractor logic can call
/// `verify_and_resolve` unconditionally without a runtime branch. The
/// observable behaviour matches the pre-BUNYIP-55 world: an `at+jwt`
/// presented to a non-OIDC bunyip deployment is rejected, while HS256
/// tokens are still accepted.
pub struct DisabledAtJwtVerifier;

#[async_trait]
impl AtJwtVerifier for DisabledAtJwtVerifier {
    async fn verify_and_resolve(&self, _token: &str) -> Result<AccessTokenClaims, AppError> {
        Err(AppError::Unauthorized)
    }
}

impl AccessTokenClaims {
    /// Build the legacy [`AccessTokenClaims`] shape from a verified
    /// at+jwt's standard claims plus a `User` row fetched from the DB.
    /// Used by [`AtJwtVerifier`] implementations to bridge between
    /// RFC 9068 minimal at+jwt and bunyip's richer per-handler claim
    /// view. BUNYIP-55.
    pub fn from_atjwt_and_user(
        token_iss: &str,
        token_iat: i64,
        token_exp: i64,
        token_jti: &str,
        user: &User,
    ) -> Self {
        Self {
            sub: user.id,
            email: user.email.clone(),
            role: user.role.clone(),
            membership_status: user.membership_status.clone(),
            price_locked: user.price_locked,
            price_id: user.locked_price_id.clone(),
            lifetime_member: user.lifetime_member,
            trial_ends_at: user.trial_ends_at.map(|t| t.timestamp()),
            iat: token_iat,
            exp: token_exp,
            jti: token_jti.to_string(),
            iss: token_iss.to_string(),
        }
    }
}

/// Look up a user by `sub` for the at+jwt resolution path. Pulled into
/// the domain crate so any future verifier implementation can reuse it
/// without duplicating the repo call. Returns `AppError::Unauthorized`
/// (not `NotFound`) when the user row is missing, because the only
/// reason `sub` would not resolve is a stale or forged token.
pub async fn resolve_user_for_atjwt(pool: &PgPool, sub: &str) -> Result<User, AppError> {
    let user_id = Uuid::parse_str(sub).map_err(|_| AppError::Unauthorized)?;
    UserRepository::find_by_id(pool, user_id)
        .await?
        .ok_or(AppError::Unauthorized)
}

/// True when the JWT's header `typ` is `at+jwt`. Used by the extractors
/// to route between the legacy HS256 verifier and the EdDSA verifier
/// without needing to know either format ahead of time.
fn token_is_atjwt(token: &str) -> bool {
    jsonwebtoken::decode_header(token)
        .ok()
        .and_then(|h| h.typ)
        .as_deref()
        == Some("at+jwt")
}

/// Type alias for the boxed-future shape every extractor in this
/// module shares. Necessary because the at+jwt path does an async DB
/// lookup; the HS256 path is sync but gets wrapped in the same future
/// so both extractors compose under one [`FromRequest::Future`].
type ExtractorFuture<T> = Pin<Box<dyn Future<Output = Result<T, AppError>>>>;

/// Key for storing authenticated user claims in request extensions
#[derive(Debug, Clone)]
pub struct AuthenticatedClaims(pub AccessTokenClaims);

/// Extractor for authenticated users - returns 401 if not authenticated
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub AccessTokenClaims);

impl FromRequest for AuthenticatedUser {
    type Error = AppError;
    type Future = ExtractorFuture<Self>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let jwt_service = req.app_data::<Arc<JwtService>>().cloned();
        let at_jwt_verifier = req.app_data::<Arc<dyn AtJwtVerifier>>().cloned();
        let token = extract_token(req);
        let req = req.clone();

        Box::pin(async move {
            let token = token.ok_or(AppError::Unauthorized)?;
            let claims =
                verify_either(&token, jwt_service.as_ref(), at_jwt_verifier.as_ref()).await?;
            req.extensions_mut()
                .insert(AuthenticatedClaims(claims.clone()));
            Ok(AuthenticatedUser(claims))
        })
    }
}

/// Extractor for optionally authenticated users - returns None if not authenticated
#[derive(Debug, Clone)]
pub struct OptionalUser(pub Option<AccessTokenClaims>);

impl FromRequest for OptionalUser {
    type Error = AppError;
    type Future = ExtractorFuture<Self>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let jwt_service = req.app_data::<Arc<JwtService>>().cloned();
        let at_jwt_verifier = req.app_data::<Arc<dyn AtJwtVerifier>>().cloned();
        let token = extract_token(req);
        let req = req.clone();

        Box::pin(async move {
            let Some(token) = token else {
                tracing::debug!(path = %req.path(), "OptionalUser: no token in request");
                return Ok(OptionalUser(None));
            };
            match verify_either(&token, jwt_service.as_ref(), at_jwt_verifier.as_ref()).await {
                Ok(claims) => {
                    req.extensions_mut()
                        .insert(AuthenticatedClaims(claims.clone()));
                    Ok(OptionalUser(Some(claims)))
                }
                Err(e) => {
                    tracing::debug!(error = %e, path = %req.path(), "OptionalUser: token present but verification failed");
                    Ok(OptionalUser(None))
                }
            }
        })
    }
}

/// Extractor for admin users - returns 403 if not admin
#[derive(Debug, Clone)]
pub struct AdminUser(pub AccessTokenClaims);

impl FromRequest for AdminUser {
    type Error = AppError;
    type Future = ExtractorFuture<Self>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let jwt_service = req.app_data::<Arc<JwtService>>().cloned();
        let at_jwt_verifier = req.app_data::<Arc<dyn AtJwtVerifier>>().cloned();
        let token = extract_token(req);
        let req = req.clone();

        Box::pin(async move {
            let token = token.ok_or(AppError::Unauthorized)?;
            let claims =
                verify_either(&token, jwt_service.as_ref(), at_jwt_verifier.as_ref()).await?;
            if claims.role != "admin" {
                return Err(AppError::Forbidden);
            }
            req.extensions_mut()
                .insert(AuthenticatedClaims(claims.clone()));
            Ok(AdminUser(claims))
        })
    }
}

/// Extractor for users with active membership - returns 403 if not a member
#[derive(Debug, Clone)]
pub struct MemberUser(pub AccessTokenClaims);

impl FromRequest for MemberUser {
    type Error = AppError;
    type Future = ExtractorFuture<Self>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let jwt_service = req.app_data::<Arc<JwtService>>().cloned();
        let at_jwt_verifier = req.app_data::<Arc<dyn AtJwtVerifier>>().cloned();
        let token = extract_token(req);
        let req = req.clone();

        Box::pin(async move {
            let token = token.ok_or(AppError::Unauthorized)?;
            let claims =
                verify_either(&token, jwt_service.as_ref(), at_jwt_verifier.as_ref()).await?;
            if !claims.has_member_access() {
                return Err(AppError::Forbidden);
            }
            req.extensions_mut()
                .insert(AuthenticatedClaims(claims.clone()));
            Ok(MemberUser(claims))
        })
    }
}

/// Route the token through the right verifier and produce a unified
/// [`AccessTokenClaims`]. Peeks at the JWT's header `typ` claim so an
/// `at+jwt` is never passed to the HS256 verifier (which would reject
/// it with a misleading "invalid credentials") and vice versa. Both
/// extractors and the optional variant share this helper.
///
/// Behaviour matrix when both verifiers are registered:
///
/// | Header `typ`     | Path                    | Failure mapped to |
/// |------------------|-------------------------|-------------------|
/// | `"at+jwt"`       | [`AtJwtVerifier`] async | verifier's error  |
/// | anything else    | [`JwtService`] sync     | HS256 error       |
///
/// When `at_jwt_verifier` is `None` (the OIDC vertical is disabled or
/// the binary did not register one), an `at+jwt` token is rejected
/// with `AppError::Unauthorized`, identical to the pre-BUNYIP-55
/// behaviour where the HS256 verifier would reject it.
async fn verify_either(
    token: &str,
    jwt_service: Option<&Arc<JwtService>>,
    at_jwt_verifier: Option<&Arc<dyn AtJwtVerifier>>,
) -> Result<AccessTokenClaims, AppError> {
    if token_is_atjwt(token) {
        match at_jwt_verifier {
            Some(v) => v.verify_and_resolve(token).await,
            None => {
                tracing::debug!(
                    "at+jwt token presented but no AtJwtVerifier registered; \
                     falling back to Unauthorized"
                );
                Err(AppError::Unauthorized)
            }
        }
    } else {
        match jwt_service {
            Some(svc) => svc.verify_access_token(token),
            None => {
                tracing::error!("JwtService not found in app data");
                Err(AppError::internal("Authentication service not available"))
            }
        }
    }
}

/// Extract JWT token from request
/// Checks cookie first (access_token), then Authorization header
fn extract_token(req: &HttpRequest) -> Option<String> {
    // Try cookie first
    if let Some(cookie) = req.cookie("access_token") {
        return Some(cookie.value().to_string());
    }

    // Try Authorization header
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(stripped) = auth_str.strip_prefix("Bearer ") {
                return Some(stripped.to_string());
            }
        }
    }

    None
}

/// Cookie configuration for auth tokens
pub struct AuthCookies;

impl AuthCookies {
    /// Create access token cookie
    pub fn access_token(token: &str, secure: bool, cookie_domain: Option<&str>) -> Cookie<'static> {
        let mut builder = Cookie::build("access_token", token.to_owned())
            .path("/")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(actix_web::cookie::time::Duration::minutes(15));

        if let Some(domain) = cookie_domain {
            builder = builder.domain(domain.to_owned());
        }

        builder.finish()
    }

    /// Create refresh token cookie
    pub fn refresh_token(
        token: &str,
        secure: bool,
        remember: bool,
        cookie_domain: Option<&str>,
    ) -> Cookie<'static> {
        let max_age = if remember {
            actix_web::cookie::time::Duration::days(30)
        } else {
            actix_web::cookie::time::Duration::days(7)
        };

        let mut builder = Cookie::build("refresh_token", token.to_owned())
            .path("/")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(max_age);

        if let Some(domain) = cookie_domain {
            builder = builder.domain(domain.to_owned());
        }

        builder.finish()
    }

    /// Name of the OIDC OP session cookie. Holds the opaque `op_sessions.sid`
    /// value that `/oauth2/authorize` validates server-side.
    pub const OP_SESSION_COOKIE: &'static str = "bunyip_op_session";

    /// Create the OP session cookie carrying the opaque `sid`.
    /// Max-Age mirrors the 7-day `op_sessions.expires_at` set at session creation.
    pub fn op_session(sid: &str, secure: bool, cookie_domain: Option<&str>) -> Cookie<'static> {
        let mut builder = Cookie::build(Self::OP_SESSION_COOKIE, sid.to_owned())
            .path("/")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(actix_web::cookie::time::Duration::days(7));

        if let Some(domain) = cookie_domain {
            builder = builder.domain(domain.to_owned());
        }

        builder.finish()
    }

    /// Cookies that clear ONLY the OP session cookie (preserving
    /// access_token and refresh_token, which may still be valid hub
    /// auth state). Used by `/oauth2/authorize` when it detects the
    /// browser is sending a `bunyip_op_session` cookie whose sid does
    /// not resolve to a live `op_sessions` row: the cookie is stale,
    /// and leaving it in the jar causes every subsequent request to
    /// repeat the "load op_session -> None -> redirect to /login"
    /// dance with no progress. Aggressively clearing it removes the
    /// cookie from the equation immediately, and the next OIDC handshake
    /// runs through the no-cookie branch cleanly (cleaner code path,
    /// no stale state).
    ///
    /// Returns both a no-domain clear (matches a stale hostname-scoped
    /// cookie issued before COOKIE_DOMAIN was configured) and a
    /// domain-scoped clear when `cookie_domain` is set. Mirrors the
    /// `clear_stale` + `clear` two-axis pattern the existing helpers
    /// use, so a freshly-misconfigured deployment still recovers.
    pub fn clear_op_session_only(
        secure: bool,
        cookie_domain: Option<&str>,
    ) -> Vec<Cookie<'static>> {
        let mut cookies = vec![Cookie::build(Self::OP_SESSION_COOKIE, "")
            .path("/")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(actix_web::cookie::time::Duration::seconds(0))
            .finish()];

        if let Some(domain) = cookie_domain {
            cookies.push(
                Cookie::build(Self::OP_SESSION_COOKIE, "")
                    .path("/")
                    .domain(domain.to_owned())
                    .http_only(true)
                    .secure(secure)
                    .same_site(SameSite::Lax)
                    .max_age(actix_web::cookie::time::Duration::seconds(0))
                    .finish(),
            );
        }

        cookies
    }

    /// Create cookies to clear stale hostname-scoped tokens.
    /// When COOKIE_DOMAIN is set (e.g. `.example.com`), any old cookies set
    /// without a domain attribute (scoped to the exact hostname like `api.example.com`)
    /// won't be overwritten by the new domain-scoped cookies. The browser sends
    /// the more-specific hostname cookie first, so the server reads the stale value.
    /// These clearing cookies (no domain attribute) force the browser to delete them.
    pub fn clear_stale(secure: bool) -> Vec<Cookie<'static>> {
        ["access_token", "refresh_token", Self::OP_SESSION_COOKIE]
            .into_iter()
            .map(|name| {
                Cookie::build(name, "")
                    .path("/")
                    .http_only(true)
                    .secure(secure)
                    .same_site(SameSite::Lax)
                    .max_age(actix_web::cookie::time::Duration::seconds(0))
                    .finish()
            })
            .collect()
    }

    /// Create cookies to clear auth tokens
    pub fn clear(secure: bool, cookie_domain: Option<&str>) -> Vec<Cookie<'static>> {
        let mut cookies = Self::clear_stale(secure);

        let mut access_builder = Cookie::build("access_token", "")
            .path("/")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(actix_web::cookie::time::Duration::seconds(0));

        let mut refresh_builder = Cookie::build("refresh_token", "")
            .path("/")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(actix_web::cookie::time::Duration::seconds(0));

        let mut op_builder = Cookie::build(Self::OP_SESSION_COOKIE, "")
            .path("/")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(actix_web::cookie::time::Duration::seconds(0));

        if let Some(domain) = cookie_domain {
            access_builder = access_builder.domain(domain.to_owned());
            refresh_builder = refresh_builder.domain(domain.to_owned());
            op_builder = op_builder.domain(domain.to_owned());
            // Only add domain-scoped clearing cookies if a domain is configured
            cookies.push(access_builder.finish());
            cookies.push(refresh_builder.finish());
            cookies.push(op_builder.finish());
        }

        cookies
    }
}

/// Extract client IP address from request
pub fn extract_client_ip(req: &HttpRequest) -> Option<std::net::IpAddr> {
    // Try X-Forwarded-For header first (for proxied requests)
    if let Some(forwarded) = req.headers().get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Try X-Real-IP header
    if let Some(real_ip) = req.headers().get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse() {
                return Some(ip);
            }
        }
    }

    // Fall back to connection info
    req.connection_info()
        .realip_remote_addr()
        .and_then(|addr| addr.parse().ok())
}

/// Extract device info from User-Agent header
pub fn extract_device_info(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get(header::USER_AGENT)
        .and_then(|ua| ua.to_str().ok())
        .map(|s| {
            // Truncate to reasonable length
            if s.len() > 256 {
                s[..256].to_string()
            } else {
                s.to_string()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_cookies_clear() {
        let cookies = AuthCookies::clear(false, None);
        // access_token + refresh_token + bunyip_op_session (no-domain stale clears)
        assert_eq!(cookies.len(), 3);
        assert!(cookies.iter().any(|c| c.name() == "access_token"));
        assert!(cookies.iter().any(|c| c.name() == "refresh_token"));
        assert!(cookies
            .iter()
            .any(|c| c.name() == AuthCookies::OP_SESSION_COOKIE));
    }

    #[test]
    fn test_auth_cookies_clear_with_domain() {
        let cookies = AuthCookies::clear(true, Some(".example.com"));
        // 3 stale-clearing cookies (no domain) + 3 domain-scoped clearing cookies
        assert_eq!(cookies.len(), 6);
        let domain_cookies: Vec<_> = cookies
            .iter()
            .filter(|c| c.domain() == Some(".example.com"))
            .collect();
        assert_eq!(domain_cookies.len(), 3);
        assert!(domain_cookies.iter().any(|c| c.name() == "access_token"));
        assert!(domain_cookies.iter().any(|c| c.name() == "refresh_token"));
        assert!(domain_cookies
            .iter()
            .any(|c| c.name() == AuthCookies::OP_SESSION_COOKIE));
    }

    #[test]
    fn test_clear_op_session_only_no_domain() {
        // Single no-domain clear (matches a hostname-scoped stale cookie).
        let cookies = AuthCookies::clear_op_session_only(false, None);
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name(), AuthCookies::OP_SESSION_COOKIE);
        assert!(
            cookies[0].value().is_empty(),
            "cleared cookie has empty value"
        );
        assert_eq!(
            cookies[0].max_age(),
            Some(actix_web::cookie::time::Duration::seconds(0)),
            "cleared cookie has Max-Age=0",
        );
        assert!(
            cookies[0].domain().is_none(),
            "no-domain branch leaves Domain unset"
        );
    }

    #[test]
    fn test_clear_op_session_only_with_domain() {
        // No-domain clear (for hostname-scoped stale cookies) PLUS the
        // domain-scoped clear that matches the live cookie shape.
        let cookies = AuthCookies::clear_op_session_only(true, Some(".a8n.systems"));
        assert_eq!(cookies.len(), 2);
        assert!(cookies
            .iter()
            .all(|c| c.name() == AuthCookies::OP_SESSION_COOKIE));
        assert_eq!(
            cookies
                .iter()
                .filter(|c| c.domain() == Some(".a8n.systems"))
                .count(),
            1,
            "exactly one domain-scoped clear",
        );
        assert_eq!(
            cookies.iter().filter(|c| c.domain().is_none()).count(),
            1,
            "exactly one no-domain clear",
        );
        // Critical: neither access_token nor refresh_token appear; only the
        // OP session cookie is touched. The hub session stays intact so
        // `/login` can still identify the user when they re-authenticate.
        assert!(
            !cookies.iter().any(|c| c.name() == "access_token"),
            "must not clear access_token",
        );
        assert!(
            !cookies.iter().any(|c| c.name() == "refresh_token"),
            "must not clear refresh_token",
        );
    }

    #[test]
    fn test_op_session_cookie_properties() {
        let cookie = AuthCookies::op_session("sid123", true, Some(".example.com"));
        assert_eq!(cookie.name(), AuthCookies::OP_SESSION_COOKIE);
        assert_eq!(cookie.value(), "sid123");
        assert_eq!(cookie.path(), Some("/"));
        assert!(cookie.http_only().unwrap_or(false));
        assert!(cookie.secure().unwrap_or(false));
        assert_eq!(cookie.domain(), Some(".example.com"));
        assert_eq!(
            cookie.max_age(),
            Some(actix_web::cookie::time::Duration::days(7))
        );
    }

    #[test]
    fn test_access_token_cookie_properties() {
        let cookie = AuthCookies::access_token("tok123", true, None);
        assert_eq!(cookie.name(), "access_token");
        assert_eq!(cookie.value(), "tok123");
        assert_eq!(cookie.path(), Some("/"));
        assert!(cookie.http_only().unwrap_or(false));
        assert!(cookie.secure().unwrap_or(false));
        assert_eq!(
            cookie.max_age(),
            Some(actix_web::cookie::time::Duration::minutes(15))
        );
        assert!(cookie.domain().is_none());
    }

    #[test]
    fn test_access_token_cookie_with_domain() {
        let cookie = AuthCookies::access_token("tok123", false, Some(".example.com"));
        assert_eq!(cookie.domain(), Some(".example.com"));
        // secure=false in dev
        assert!(!cookie.secure().unwrap_or(true));
    }

    #[test]
    fn test_refresh_token_remember_true() {
        let cookie = AuthCookies::refresh_token("ref123", true, true, None);
        assert_eq!(cookie.name(), "refresh_token");
        assert_eq!(cookie.value(), "ref123");
        assert_eq!(cookie.path(), Some("/"));
        assert!(cookie.http_only().unwrap_or(false));
        assert_eq!(
            cookie.max_age(),
            Some(actix_web::cookie::time::Duration::days(30))
        );
    }

    #[test]
    fn test_refresh_token_remember_false() {
        let cookie = AuthCookies::refresh_token("ref123", true, false, None);
        assert_eq!(
            cookie.max_age(),
            Some(actix_web::cookie::time::Duration::days(7))
        );
    }

    #[test]
    fn test_refresh_token_with_domain() {
        let cookie = AuthCookies::refresh_token("ref123", true, true, Some(".a8n.run"));
        assert_eq!(cookie.domain(), Some(".a8n.run"));
    }

    // ── BUNYIP-55: dual-path token verification ────────────────────────────

    /// Craft a JWT shell with the given header `typ` value. The body
    /// and signature segments are filler; only the header is decoded
    /// by [`token_is_atjwt`]. Sufficient for routing-logic tests.
    fn jwt_with_typ(typ: &str) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let header = format!(r#"{{"alg":"EdDSA","typ":"{typ}","kid":"k1"}}"#);
        let body = r#"{"sub":"00000000-0000-0000-0000-000000000001"}"#;
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(body),
            URL_SAFE_NO_PAD.encode("filler"),
        )
    }

    #[test]
    fn token_is_atjwt_recognises_rfc9068_typ() {
        assert!(token_is_atjwt(&jwt_with_typ("at+jwt")));
    }

    #[test]
    fn token_is_atjwt_rejects_legacy_jwt_typ() {
        assert!(!token_is_atjwt(&jwt_with_typ("JWT")));
    }

    #[test]
    fn token_is_atjwt_rejects_malformed_token() {
        // Garbage in is never an at+jwt; the routing falls through to
        // the HS256 path so the legacy verifier reports the real error.
        assert!(!token_is_atjwt("not-even-a-jwt"));
        assert!(!token_is_atjwt(""));
        assert!(!token_is_atjwt("a.b.c"));
    }

    /// Stub verifier that returns a fixed `Ok` payload and records the
    /// call count. Used by `verify_either` tests so we can assert the
    /// routing decision without standing up a real EdDSA keyset or a
    /// database. `AppError` is not `Clone`, so we hand the success
    /// payload by clone and skip the error case here (the no-verifier
    /// rejection case is covered by a separate test that does not need
    /// a stub).
    struct RecordingOkVerifier {
        claims: AccessTokenClaims,
        calls: std::sync::Mutex<u32>,
    }

    impl RecordingOkVerifier {
        fn new(claims: AccessTokenClaims) -> Self {
            Self {
                claims,
                calls: std::sync::Mutex::new(0),
            }
        }
        fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }

    #[async_trait]
    impl AtJwtVerifier for RecordingOkVerifier {
        async fn verify_and_resolve(&self, _token: &str) -> Result<AccessTokenClaims, AppError> {
            *self.calls.lock().unwrap() += 1;
            Ok(self.claims.clone())
        }
    }

    fn stub_claims(role: &str) -> AccessTokenClaims {
        AccessTokenClaims {
            sub: uuid::Uuid::from_u128(1),
            email: "e2e@example.com".to_string(),
            role: role.to_string(),
            membership_status: "active".to_string(),
            price_locked: false,
            price_id: None,
            lifetime_member: false,
            trial_ends_at: None,
            iat: 0,
            exp: i64::MAX,
            jti: "jti-1".to_string(),
            iss: "https://api.example.test".to_string(),
        }
    }

    #[actix_rt::test]
    async fn verify_either_routes_atjwt_to_verifier_when_present() {
        let recording = Arc::new(RecordingOkVerifier::new(stub_claims("admin")));
        // Same Arc behind both handles: the trait-object reference the
        // helper consumes, and the concrete-type reference the test
        // reads the counter through afterwards.
        let verifier: Arc<dyn AtJwtVerifier> = recording.clone();
        let token = jwt_with_typ("at+jwt");
        let claims = verify_either(&token, None, Some(&verifier))
            .await
            .expect("at+jwt verifier returns claims");
        assert_eq!(claims.role, "admin");
        assert_eq!(
            recording.call_count(),
            1,
            "at+jwt token should hit the AtJwtVerifier once"
        );
    }

    #[actix_rt::test]
    async fn verify_either_rejects_atjwt_when_no_verifier_registered() {
        let token = jwt_with_typ("at+jwt");
        let err = verify_either(&token, None, None)
            .await
            .expect_err("at+jwt with no verifier must reject");
        assert!(
            matches!(err, AppError::Unauthorized),
            "expected Unauthorized, got {err:?}"
        );
    }

    #[actix_rt::test]
    async fn verify_either_routes_legacy_jwt_to_jwt_service() {
        // No JWT service registered and the at+jwt verifier is irrelevant
        // because the token is NOT an at+jwt; the legacy path must be
        // taken AND must surface "service not available" rather than
        // accidentally falling into the at+jwt path.
        let token = jwt_with_typ("JWT");
        let err = verify_either(&token, None, None)
            .await
            .expect_err("legacy token with no JwtService must error");
        // The pre-BUNYIP-55 message; pinning the exact text keeps the
        // operator-facing diagnostic stable across this refactor.
        assert!(
            format!("{err:?}").contains("Authentication service not available"),
            "expected legacy-path internal error, got {err:?}"
        );
    }

    #[actix_rt::test]
    async fn disabled_atjwt_verifier_always_rejects() {
        let v = DisabledAtJwtVerifier;
        let err = v
            .verify_and_resolve(&jwt_with_typ("at+jwt"))
            .await
            .expect_err("DisabledAtJwtVerifier must reject every token");
        assert!(matches!(err, AppError::Unauthorized));
    }

    #[test]
    fn access_token_claims_from_atjwt_and_user_maps_fields() {
        // Build a User row with the exact fields `from_atjwt_and_user`
        // reads. Pin the mapping; a future refactor that drops or
        // renames one of these fields will break this test before it
        // reaches a handler.
        let user = User {
            id: uuid::Uuid::from_u128(42),
            email: "e2e-admin@example.com".to_string(),
            email_verified: true,
            password_hash: None,
            role: "admin".to_string(),
            stripe_customer_id: None,
            stripe_payment_method_id: None,
            membership_status: "active".to_string(),
            price_locked: true,
            locked_price_id: Some("price_42".to_string()),
            locked_price_amount: Some(4200),
            grace_period_start: None,
            grace_period_end: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            two_factor_enabled: false,
            last_login_at: None,
            deleted_at: None,
            subscription_tier: "lifetime".to_string(),
            trial_ends_at: None,
            lifetime_member: true,
            subscription_override_by: None,
        };

        let claims = AccessTokenClaims::from_atjwt_and_user(
            "https://api.example.test",
            1_700_000_000,
            1_700_000_900,
            "jti-99",
            &user,
        );

        assert_eq!(claims.sub, uuid::Uuid::from_u128(42));
        assert_eq!(claims.email, "e2e-admin@example.com");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.membership_status, "active");
        assert!(claims.price_locked);
        assert_eq!(claims.price_id, Some("price_42".to_string()));
        assert!(claims.lifetime_member);
        assert_eq!(claims.trial_ends_at, None);
        assert_eq!(claims.iss, "https://api.example.test");
        assert_eq!(claims.iat, 1_700_000_000);
        assert_eq!(claims.exp, 1_700_000_900);
        assert_eq!(claims.jti, "jti-99");
    }
}
