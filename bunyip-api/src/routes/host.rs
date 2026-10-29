//! Host-secrets route (BUNYIP-983).
//!
//! `GET /v1/host/secrets/{KEY}` serves one secret bunyip holds to a registered
//! calling app, authenticated by the same machine credential the mailer relay
//! takes (BUNYIP-602/604) and entitled per registration by
//! `oauth_clients.allowed_secret_keys`.
//!
//! The key is a tail pattern because a key is namespaced by the product that
//! reads it (`mokosh/google_oauth_client`), so it carries a `/` and a single
//! path segment would not match it.
//!
//! Deliberately NOT in `rate_limit_floor::EXEMPT_PATHS`, unlike the relay. The
//! floor's exemption list matches whole paths and this one varies by key, and
//! the floor is the right shape here anyway: a reader fetches at boot, which is
//! far below 20 per minute, and a deployment restarting fast enough to trip it
//! is a deployment that should back off. The route's own per-app cap
//! (`RateLimitConfig::HOST_SECRET_READ`) and per-IP failed-authentication cap
//! sit over it.

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/host").route(
        "/secrets/{key:.*}",
        web::get().to(handlers::host_secrets::get_host_secret),
    ));
}
