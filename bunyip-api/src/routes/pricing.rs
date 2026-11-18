//! Public pricing route configuration (BUNYIP-487).
//!
//! Unauthenticated. `/v1/pricing` is in `rate_limit_floor::EXEMPT_PATHS`
//! (BUNYIP-518) because the BFF fetches this payload on every page render;
//! the default per-IP cap otherwise swallowed the 429 into a cache miss that
//! silently 404'd /pricing after a few page loads. The per-IP cap still
//! applies at other routes.

use actix_web::web;

use crate::handlers;

// SPEC-9.24.5: public pricing payload
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/pricing", web::get().to(handlers::public_pricing));
}
