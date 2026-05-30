//! Webhook routes

use actix_web::web;

use crate::handlers;

/// Configure webhook routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/webhooks").route("/stripe", web::post().to(handlers::stripe_webhook)));
}
