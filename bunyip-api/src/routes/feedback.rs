//! Feedback routes

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/feedback").route("", web::post().to(handlers::submit_feedback)));
}
