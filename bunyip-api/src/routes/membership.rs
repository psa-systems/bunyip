//! Membership routes

use actix_web::web;

use crate::handlers;

/// Configure membership routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/memberships")
            .route("/me", web::get().to(handlers::get_membership))
            .route("/checkout", web::post().to(handlers::create_checkout))
            .route("/subscribe", web::post().to(handlers::subscribe))
            .route("/cancel", web::post().to(handlers::cancel_membership))
            .route(
                "/cancel-now",
                web::post().to(handlers::cancel_membership_immediate),
            )
            .route(
                "/reactivate",
                web::post().to(handlers::reactivate_membership),
            )
            .route("/billing-portal", web::post().to(handlers::billing_portal))
            .route("/payments", web::get().to(handlers::get_payment_history)),
    );
}
