//! Public branding route configuration (BUNYIP-561).
//!
//! Unauthenticated and NOT in `rate_limit_floor::EXEMPT_PATHS`, so the default
//! per-IP cap applies. `routes/pricing.rs` is registered the same way, though
//! pricing is exempt from the cap (BUNYIP-518); branding is not.

use actix_web::web;

use crate::handlers;

// SPEC-9.24.6: public branding; stays under the per-IP floor
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/branding", web::get().to(handlers::public_branding))
        // BUNYIP-560: the brand images (mark, mascot, derived favicon set).
        // Unauthenticated for the same reason: they are the chrome every
        // visitor already sees.
        .route(
            "/branding/assets/{kind}",
            web::get().to(handlers::public_branding_asset),
        );
}
