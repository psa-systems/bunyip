//! Routes for the global downloads endpoint.

use crate::handlers;
use actix_web::web;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/downloads", web::get().to(handlers::list_all_downloads));
}
