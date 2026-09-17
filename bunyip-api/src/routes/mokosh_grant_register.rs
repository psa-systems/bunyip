//! PMS-1208 / BUNYIP-673: `/v1/mokosh-grants` route configuration.
//!
//! A separate scope from `/v1/grants` deliberately: the sibling
//! scope's routes are all owner-authenticated (`AuthenticatedUser`),
//! and the mount point is what says which caller kind belongs there
//! (a machine-authed route in the same scope would blur that
//! contract for every reader). See `handlers::mokosh_grant_register`
//! for the shape.

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/mokosh-grants").route(
        "",
        web::post().to(handlers::mokosh_grant_register::register_grant),
    ));
}
