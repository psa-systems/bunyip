//! Authentication middleware and extractors
//!
//! This module provides JWT-based authentication middleware and extractors
//! for securing API endpoints.

use crate::errors::AppError;
use crate::services::{AccessTokenClaims, JwtService};
use actix_web::{
    cookie::{Cookie, SameSite},
    dev::Payload,
    http::header,
    FromRequest, HttpMessage, HttpRequest,
};
use std::future::{ready, Ready};
use std::sync::Arc;

/// Key for storing authenticated user claims in request extensions
#[derive(Debug, Clone)]
pub struct AuthenticatedClaims(pub AccessTokenClaims);

/// Extractor for authenticated users - returns 401 if not authenticated
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub AccessTokenClaims);

impl FromRequest for AuthenticatedUser {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Try to get JWT service from app data
        let jwt_service = match req.app_data::<Arc<JwtService>>() {
            Some(service) => service.clone(),
            None => {
                tracing::error!("JwtService not found in app data");
                return ready(Err(AppError::internal(
                    "Authentication service not available",
                )));
            }
        };

        // Try to extract token from cookie first, then Authorization header
        let token = extract_token(req);

        match token {
            Some(token) => match jwt_service.verify_access_token(&token) {
                Ok(claims) => {
                    // Store claims in request extensions for later use
                    req.extensions_mut()
                        .insert(AuthenticatedClaims(claims.clone()));
                    ready(Ok(AuthenticatedUser(claims)))
                }
                Err(e) => ready(Err(e)),
            },
            None => ready(Err(AppError::Unauthorized)),
        }
    }
}

/// Extractor for optionally authenticated users - returns None if not authenticated
#[derive(Debug, Clone)]
pub struct OptionalUser(pub Option<AccessTokenClaims>);

impl FromRequest for OptionalUser {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Try to get JWT service from app data
        let jwt_service = match req.app_data::<Arc<JwtService>>() {
            Some(service) => service.clone(),
            None => {
                tracing::warn!("JwtService not found in app data for optional auth");
                return ready(Ok(OptionalUser(None)));
            }
        };

        // Try to extract token
        let token = extract_token(req);

        match token {
            Some(token) => match jwt_service.verify_access_token(&token) {
                Ok(claims) => {
                    req.extensions_mut()
                        .insert(AuthenticatedClaims(claims.clone()));
                    ready(Ok(OptionalUser(Some(claims))))
                }
                Err(e) => {
                    tracing::debug!(error = %e, path = %req.path(), "OptionalUser: token present but verification failed");
                    ready(Ok(OptionalUser(None)))
                }
            },
            None => {
                tracing::debug!(path = %req.path(), "OptionalUser: no token in request");
                ready(Ok(OptionalUser(None)))
            }
        }
    }
}

/// Extractor for admin users - returns 403 if not admin
#[derive(Debug, Clone)]
pub struct AdminUser(pub AccessTokenClaims);

impl FromRequest for AdminUser {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Try to get JWT service from app data
        let jwt_service = match req.app_data::<Arc<JwtService>>() {
            Some(service) => service.clone(),
            None => {
                tracing::error!("JwtService not found in app data");
                return ready(Err(AppError::internal(
                    "Authentication service not available",
                )));
            }
        };

        // Try to extract token
        let token = extract_token(req);

        match token {
            Some(token) => match jwt_service.verify_access_token(&token) {
                Ok(claims) => {
                    if claims.role != "admin" {
                        return ready(Err(AppError::Forbidden));
                    }
                    req.extensions_mut()
                        .insert(AuthenticatedClaims(claims.clone()));
                    ready(Ok(AdminUser(claims)))
                }
                Err(e) => ready(Err(e)),
            },
            None => ready(Err(AppError::Unauthorized)),
        }
    }
}

/// Extractor for users with active membership - returns 403 if not a member
#[derive(Debug, Clone)]
pub struct MemberUser(pub AccessTokenClaims);

impl FromRequest for MemberUser {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let jwt_service = match req.app_data::<Arc<JwtService>>() {
            Some(service) => service.clone(),
            None => {
                tracing::error!("JwtService not found in app data");
                return ready(Err(AppError::internal(
                    "Authentication service not available",
                )));
            }
        };

        let token = extract_token(req);

        match token {
            Some(token) => match jwt_service.verify_access_token(&token) {
                Ok(claims) => {
                    if !claims.has_member_access() {
                        return ready(Err(AppError::Forbidden));
                    }

                    req.extensions_mut()
                        .insert(AuthenticatedClaims(claims.clone()));
                    ready(Ok(MemberUser(claims)))
                }
                Err(e) => ready(Err(e)),
            },
            None => ready(Err(AppError::Unauthorized)),
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
            if auth_str.starts_with("Bearer ") {
                return Some(auth_str[7..].to_string());
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

    /// Create cookies to clear stale hostname-scoped tokens.
    /// When COOKIE_DOMAIN is set (e.g. `.example.com`), any old cookies set
    /// without a domain attribute (scoped to the exact hostname like `api.example.com`)
    /// won't be overwritten by the new domain-scoped cookies. The browser sends
    /// the more-specific hostname cookie first, so the server reads the stale value.
    /// These clearing cookies (no domain attribute) force the browser to delete them.
    pub fn clear_stale(secure: bool) -> Vec<Cookie<'static>> {
        vec![
            Cookie::build("access_token", "")
                .path("/")
                .http_only(true)
                .secure(secure)
                .same_site(SameSite::Lax)
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .finish(),
            Cookie::build("refresh_token", "")
                .path("/")
                .http_only(true)
                .secure(secure)
                .same_site(SameSite::Lax)
                .max_age(actix_web::cookie::time::Duration::seconds(0))
                .finish(),
        ]
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

        if let Some(domain) = cookie_domain {
            access_builder = access_builder.domain(domain.to_owned());
            refresh_builder = refresh_builder.domain(domain.to_owned());
            // Only add domain-scoped clearing cookies if a domain is configured
            cookies.push(access_builder.finish());
            cookies.push(refresh_builder.finish());
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
        assert_eq!(cookies.len(), 2);
        assert!(cookies.iter().any(|c| c.name() == "access_token"));
        assert!(cookies.iter().any(|c| c.name() == "refresh_token"));
    }

    #[test]
    fn test_auth_cookies_clear_with_domain() {
        let cookies = AuthCookies::clear(true, Some(".example.com"));
        // 2 stale-clearing cookies (no domain) + 2 domain-scoped clearing cookies
        assert_eq!(cookies.len(), 4);
        let domain_cookies: Vec<_> = cookies
            .iter()
            .filter(|c| c.domain() == Some(".example.com"))
            .collect();
        assert_eq!(domain_cookies.len(), 2);
        assert!(domain_cookies.iter().any(|c| c.name() == "access_token"));
        assert!(domain_cookies.iter().any(|c| c.name() == "refresh_token"));
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
}
