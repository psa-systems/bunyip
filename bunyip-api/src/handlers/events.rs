//! BUNYIP-145: Server-Sent Events streaming endpoint.
//!
//! `GET /v1/events` opens a long-lived HTTP/1.1 stream the bunyip-web SPA
//! subscribes to after sign-in. Per-user mutation events (e.g. an admin
//! granting lifetime to the signed-in user) fan out from
//! `services::EventBus::publish` to every active subscription for that
//! user, and the SPA reacts by silently calling `/v1/auth/refresh` +
//! `/v1/auth/me` and patching the in-memory `CurrentUser` signal. The
//! dashboard's per-app gate (Mokosh / Drillmark / Lets Chat tiles)
//! re-renders without a hard refresh.
//!
//! Authentication reuses the standard `AuthenticatedUser` extractor; the
//! request must carry a valid Bearer at+jwt or session cookie. We subscribe
//! to the per-user channel keyed by `claims.sub`, so an unauth'd connection
//! is impossible by construction.
//!
//! Wire format mirrors the WHATWG `text/event-stream`:
//! ```text
//! event: claims_changed
//! data: {"type":"claims_changed","user_id":"<uuid>"}
//!
//! : keepalive    <-- comment, every 25 s, keeps proxies from killing the conn
//! ```
//!
//! The 25-second keepalive cadence is below the default 30 s / 60 s idle
//! limits on Cloudflare, Traefik, and most corporate egress proxies.

use std::sync::Arc;
use std::time::Duration;

use actix_web::http::header;
use actix_web::{web, HttpRequest, HttpResponse};
use bunyip_domain::services::{BunyipEvent, EventBus};
use futures_util::stream::{self, StreamExt};
use tokio::sync::broadcast;
use tokio::time::interval;
use tokio_stream::wrappers::IntervalStream;

use crate::errors::AppError;
use crate::middleware::AuthenticatedUser;

const KEEPALIVE: Duration = Duration::from_secs(25);

/// `GET /v1/events`
///
/// Streams `text/event-stream` for the signed-in user. Per-user events and
/// global events are merged into a single stream. The handler returns as
/// soon as the client disconnects (actix-web drops the response body
/// future when the TCP socket closes).
pub async fn events_stream(
    _req: HttpRequest,
    user: AuthenticatedUser,
    bus: web::Data<Arc<EventBus>>,
) -> Result<HttpResponse, AppError> {
    let user_id = user.0.sub;
    let user_rx = bus.subscribe_user(user_id);
    let global_rx = bus.subscribe_global();

    let event_stream = merged_event_stream(user_rx, global_rx);
    let keepalive_stream = IntervalStream::new(interval(KEEPALIVE))
        .map(|_| Ok::<_, std::io::Error>(actix_web::web::Bytes::from(": keepalive\n\n")));

    let body = stream::select(event_stream, keepalive_stream);

    Ok(HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/event-stream"))
        .insert_header((header::CACHE_CONTROL, "no-cache, no-transform"))
        // Disable nginx-style buffering on intermediate proxies. Some
        // setups (Traefik default, nginx ingress) buffer streaming
        // responses by default, defeating the keepalive cadence.
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(body))
}

/// Merge the per-user + global broadcast receivers into one byte-stream of
/// SSE frames. On a `Lagged(n)` signal (the slow-consumer case), emit a
/// `resync` event so the SPA refetches state from scratch; on `Closed`,
/// stop.
fn merged_event_stream(
    user_rx: broadcast::Receiver<BunyipEvent>,
    global_rx: broadcast::Receiver<BunyipEvent>,
) -> impl futures_util::Stream<Item = Result<actix_web::web::Bytes, std::io::Error>> {
    let user_stream = receiver_to_sse_stream(user_rx);
    let global_stream = receiver_to_sse_stream(global_rx);
    stream::select(user_stream, global_stream)
}

fn receiver_to_sse_stream(
    rx: broadcast::Receiver<BunyipEvent>,
) -> impl futures_util::Stream<Item = Result<actix_web::web::Bytes, std::io::Error>> {
    use tokio_stream::wrappers::BroadcastStream;
    BroadcastStream::new(rx).filter_map(|res| async move {
        match res {
            Ok(event) => Some(Ok(encode_event(&event))),
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(_)) => {
                // Slow consumer: tell the SPA to do a full refresh.
                Some(Ok(encode_resync()))
            }
        }
    })
}

fn encode_event(event: &BunyipEvent) -> actix_web::web::Bytes {
    let name = event.name();
    // Serialize the event variant directly; serde puts the `type` field
    // first via the `#[serde(tag = "type")]` attribute on `BunyipEvent`.
    let json = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string());
    let frame = format!("event: {name}\ndata: {json}\n\n");
    actix_web::web::Bytes::from(frame)
}

fn encode_resync() -> actix_web::web::Bytes {
    actix_web::web::Bytes::from("event: resync\ndata: {\"type\":\"resync\"}\n\n".to_string())
}
