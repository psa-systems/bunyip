//! OIDC / OAuth 2.1 route configuration.
//!
//! Well-known endpoints live at the root level (outside `/v1`).
//! OAuth endpoints live under `/oauth2` at the root level.

use actix_web::web;

use crate::handlers::oidc::{authorize, discovery, jwks, logout, revoke, token, userinfo};

/// Configure OIDC well-known discovery and JWKS endpoints.
/// These are registered at the root level (not under `/v1`).
pub fn configure_well_known(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/.well-known")
            .route("/openid-configuration", web::get().to(discovery))
            .route("/jwks.json", web::get().to(jwks)),
    );
}

/// Configure OAuth 2.1 / OIDC endpoints under `/oauth2`.
pub fn configure_oauth2(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/oauth2")
            .route("/authorize", web::get().to(authorize))
            .route("/token", web::post().to(token))
            .route("/userinfo", web::get().to(userinfo))
            .route("/revoke", web::post().to(revoke))
            .route("/logout", web::get().to(logout)),
    );
}
