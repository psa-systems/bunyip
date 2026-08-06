//! Public pricing route configuration (BUNYIP-487).
//!
//! Unauthenticated and deliberately NOT in `rate_limit_floor::EXEMPT_PATHS`, so
//! the default per-IP cap applies like it does to every other route.

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/pricing", web::get().to(handlers::public_pricing));
}
