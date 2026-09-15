//! Public pricing route configuration (BUNYIP-487).
//!
//! Unauthenticated and deliberately NOT in `rate_limit_floor::EXEMPT_PATHS`, so
//! the default per-IP cap applies like it does to every other route.

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/pricing", web::get().to(handlers::public_pricing));
    // BUNYIP-692: public org-tier catalogue. Behind the same
    // unauthenticated rate-limit floor as /v1/pricing; the service
    // answers `[]` when `orgs_enabled` is off so a public visitor never
    // learns whether the feature is configured.
    cfg.route(
        "/pricing/orgs",
        web::get().to(handlers::org_pricing::public_list),
    );
}
