//! Public branding route configuration (BUNYIP-561).
//!
//! Unauthenticated and deliberately NOT in `rate_limit_floor::EXEMPT_PATHS`, so
//! the default per-IP cap applies like it does to every other route. Registered
//! the same way `routes/pricing.rs` is.

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/branding", web::get().to(handlers::public_branding));
}
