//! BUNYIP-145: Server-Sent Events streaming endpoint.
//!
//! `GET /v1/events` opens a long-lived stream the bunyip-web SPA subscribes to
//! after sign-in. DEV-528: the bus and the SSE framing moved to the shared
//! `dunite-events` crate; this handler authenticates the request and hands the
//! bus + user id to the shared adapter. Per-user mutation events (e.g. an admin
//! granting lifetime to the signed-in user) and global events fan out to every
//! active subscription for that user, and the SPA reacts without a hard
//! refresh.
//!
//! Authentication reuses the standard `AuthenticatedUser` extractor, so an
//! unauthenticated connection is impossible by construction; the stream is
//! keyed by `claims.sub`.

use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use bunyip_domain::services::EventBus;

use crate::errors::AppError;
use crate::middleware::AuthenticatedUser;

/// `GET /v1/events` - streams `text/event-stream` (per-user + global events,
/// merged, with keepalive) for the signed-in user. The body ends when the
/// client disconnects.
pub async fn events_stream(
    _req: HttpRequest,
    user: AuthenticatedUser,
    bus: web::Data<Arc<EventBus>>,
) -> Result<HttpResponse, AppError> {
    // BUNYIP-559 F12: exempt from the `Compress` middleware. actix's Compress
    // has no content-type predicate and would run this stream through deflate,
    // which holds an event back until it has enough bytes to emit.
    Ok(crate::compress::mark_uncompressed(
        dunite_events::sse::sse_response(&bus, user.0.sub),
    ))
}
