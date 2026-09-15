//! BUNYIP-673 [BUNYIP-626 child 2]: `/v1/grants/*` route configuration.
//!
//! Every route sits behind [`AuthenticatedUser`] and gates on
//! `tier_config.orgs_enabled` inside the handler. Flag-off returns 404
//! per BUNYIP-493's "off means invisible" rule.

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/grants")
            .route("", web::post().to(handlers::mokosh_grants::create_grant))
            .route("", web::get().to(handlers::mokosh_grants::list_grants))
            .route(
                "/{id}",
                web::delete().to(handlers::mokosh_grants::revoke_grant),
            )
            // BUNYIP-673 / 674: mint an at+jwt scoped to the granted
            // Mokosh account. Behind AuthenticatedUser; the caller is
            // the grantee, and Bunyip mints a token Mokosh's OIDC-RS
            // consults its mokosh_bunyip_grants mirror to verify.
            .route(
                "/{id}/access-token",
                web::post().to(handlers::mokosh_grants::mint_grant_token),
            ),
    );
}
