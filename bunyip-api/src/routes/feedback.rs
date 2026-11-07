//! Feedback routes

use actix_web::web;

use crate::handlers;

// SPEC-9.25.4: feedback submission
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/feedback").route("", web::post().to(handlers::submit_feedback)));
}
