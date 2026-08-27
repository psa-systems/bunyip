//! Mailer relay route (BUNYIP-602).
//!
//! Authenticated per request by the calling app's `oauth_clients` machine
//! credential, and throttled per app rather than per IP, so the endpoint is
//! listed in `rate_limit_floor::EXEMPT_PATHS`: the suite's apps share egress,
//! and the per-IP floor would let one app's mail volume throttle another's.
//! `RateLimitConfig::MAILER_SEND` (per app) and `MAILER_AUTH_FAILURES` (per IP,
//! failures only) are the controls that replace it.

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/mailer")
            .route("/send", web::post().to(handlers::mailer::relay_send))
            // BUNYIP-603: inbound bounce/complaint feedback. Authenticated by an
            // `X-Webhook-Signature` HMAC over the body, not by a machine
            // credential, so it is exempt from the per-IP floor like the Stripe
            // webhook (an external provider posts from one address).
            .route(
                "/webhooks/feedback",
                web::post().to(handlers::mailer::relay_feedback_webhook),
            ),
    );
}
