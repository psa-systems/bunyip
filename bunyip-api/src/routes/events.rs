//! BUNYIP-145: Server-Sent Events route. Single endpoint under /v1/events
//! that streams real-time mutation events to the signed-in user's SPA.

use actix_web::web;

use crate::handlers;

// SPEC-9.25.3: single SSE stream endpoint
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/events").route("", web::get().to(handlers::events_stream)));
}
