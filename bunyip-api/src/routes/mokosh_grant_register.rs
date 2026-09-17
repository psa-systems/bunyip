//! PMS-1208 / BUNYIP-673 / MAPPS-875: `/v1/mokosh-grants` route
//! configuration.
//!
//! A separate scope from `/v1/grants` deliberately: the sibling
//! scope's routes are all owner-authenticated (`AuthenticatedUser`),
//! and the mount point is what says which caller kind belongs there
//! (a machine-authed route in the same scope would blur that
//! contract for every reader).
//!
//! Three ops today, all machine-authed:
//! - POST `/v1/mokosh-grants`             (PMS-1208): register a grant that
//!   mokosh-server minted on accept.
//! - GET  `/v1/mokosh-grants?owner_bunyip_user_id={sub}` (MAPPS-875):
//!   list an owner's active grants for mokosh's owner-outbox page.
//! - DELETE `/v1/mokosh-grants/{id}`      (MAPPS-875): revoke a grant
//!   from the same owner-outbox page.

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/mokosh-grants")
            .route(
                "",
                web::post().to(handlers::mokosh_grant_register::register_grant),
            )
            .route(
                "",
                web::get().to(handlers::mokosh_grant_list::list_owner_grants),
            )
            .route(
                "/{id}",
                web::delete().to(handlers::mokosh_grant_revoke::revoke_grant),
            ),
    );
}
