//! Default per-IP / per-user request cap for bunyip-api (BUNYIP-426 F7).
//!
//! `RateLimitConfig::API_UNAUTH` and `API_AUTH` were written as the generic
//! floor and then wired to nothing, so per-endpoint `check_rate_limit` calls
//! were the whole story and any handler added without one was uncapped. This
//! middleware applies the two presets underneath every route, so an endpoint is
//! throttled by default rather than by remembering.
//!
//! It is a floor, not a replacement: the per-endpoint caps are tighter and
//! specific, and still run inside this one.

use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::Method,
    Error, HttpResponse,
};
use std::{
    future::{ready, Future, Ready},
    pin::Pin,
    rc::Rc,
};

use crate::middleware::{extract_client_ip, resolve_rate_limit_subject};
use crate::models::RateLimitConfig;
use crate::repositories::RateLimitRepository;
use sqlx::PgPool;

/// Paths the floor never throttles.
///
/// The probes are hit by orchestration on a fixed schedule and must not be able
/// to consume a real client's budget; the Stripe webhook is HMAC-authenticated,
/// carries no ambient credential, and legitimately arrives in retry bursts.
/// `register-challenge` (BUNYIP-450) mints only a stateless, signed timestamp
/// token (`JwtService::create_signup_challenge_token`: no DB write, no side
/// effect), so minting is harmless and the floor added no protection - only a
/// false 429 for real clients that share a source IP (a NAT/proxy, or the E2E
/// runner) and for the register form's own challenge fetch. The register POST
/// it precedes stays floored and bot-guarded (BUNYIP-377).
const EXEMPT_PATHS: &[&str] = &[
    "/",
    "/health",
    "/version",
    "/e2e-bootstrapped",
    "/v1/health",
    "/v1/version",
    "/v1/auth/register-challenge",
    "/v1/webhooks/stripe",
    // BUNYIP-518: the public pricing payload. It is unauthenticated, read-only,
    // and already TTL-cached server-side (`PricingCache`), so it drives no Stripe
    // traffic and needs no floor. `bunyip-web::public_ctx` fetches it on EVERY
    // public page render (for the nav/footer links), so under the 20/60s-per-IP
    // floor a few page loads from one browser exhausted that visitor's bucket;
    // the 429 was swallowed into an unpublished payload, which 404'd `/pricing`
    // and hid its links with the switch on and every tier resolving.
    "/v1/pricing",
    // BUNYIP-555: the feature-flags probe. It is unauthenticated, read-only, and
    // answered entirely from process state (`config.email.enabled` plus
    // `StripeService::is_configured()`), so it touches no table and drives no
    // downstream traffic: the floor buys nothing and costs two rate-limit
    // queries per call. `bunyip-web` reads it for the subscribe CTA and the
    // onboarding email gate on five surfaces and now caches it (`TtlCache`), so
    // the remaining calls are one per TTL per web process.
    "/v1/auth/setup/status",
    // BUNYIP-602: the mailer relay. It authenticates a CALLING APP, not a
    // browser, and carries its own per-app throughput cap
    // (`RateLimitConfig::MAILER_SEND`) plus a per-IP failed-authentication cap
    // (`MAILER_AUTH_FAILURES`). The per-IP floor is the wrong shape here: the
    // suite's apps sit behind shared egress, so one app's legitimate mail volume
    // would throttle its neighbours, and 20/minute is far below a transactional
    // relay's normal rate.
    "/v1/mailer/send",
    // BUNYIP-603: the inbound bounce/complaint feedback webhook. It is
    // authenticated by an `X-Webhook-Signature` HMAC over the body and fails
    // closed without the secret, exactly like `/v1/webhooks/stripe`. An external
    // SMTP provider posts every bounce from one address, so the per-IP floor is
    // the wrong shape and would throttle a burst of legitimate feedback.
    "/v1/mailer/webhooks/feedback",
];

/// Whether the floor applies to this request.
pub(crate) fn is_exempt(path: &str, method: &Method) -> bool {
    // CORS preflights carry no credential and are answered by the cors layer.
    method == Method::OPTIONS || EXEMPT_PATHS.contains(&path)
}

/// Actix middleware factory for the default request cap.
pub struct RateLimitFloor {
    pool: PgPool,
}

impl RateLimitFloor {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitFloor
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = RateLimitFloorService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitFloorService {
            service: Rc::new(service),
            pool: self.pool.clone(),
        }))
    }
}

pub struct RateLimitFloorService<S> {
    service: Rc<S>,
    pool: PgPool,
}

impl<S, B> Service<ServiceRequest> for RateLimitFloorService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let pool = self.pool.clone();

        if is_exempt(req.path(), req.method()) {
            let fut = service.call(req);
            return Box::pin(async move { fut.await.map(|res| res.map_into_left_body()) });
        }

        let path = req.path().to_string();

        Box::pin(async move {
            // Borrow the inner HttpRequest, never clone it: actix's router calls
            // `match_info_mut`, which asserts it holds the only reference, so a
            // clone alive across `service.call` panics the worker.
            //
            // An unverifiable token falls back to the tighter unauthenticated
            // budget, so presenting garbage cannot buy the larger one.
            let (key, config) = {
                let http_req = req.request();
                match resolve_rate_limit_subject(http_req).await {
                    Some(sub) => (sub.to_string(), &RateLimitConfig::API_AUTH),
                    None => (
                        extract_client_ip(http_req)
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "unknown".into()),
                        &RateLimitConfig::API_UNAUTH,
                    ),
                }
            };

            match RateLimitRepository::check_and_increment(&pool, &key, config).await {
                Ok((_count, true)) => {
                    let retry_after = RateLimitRepository::get_retry_after(&pool, &key, config)
                        .await
                        .unwrap_or(config.window_seconds.max(0) as u64);
                    tracing::warn!(
                        action = config.action,
                        path = %path,
                        "request cap floor exceeded"
                    );
                    let res = HttpResponse::TooManyRequests()
                        .insert_header(("Retry-After", retry_after.to_string()))
                        .finish();
                    Ok(req.into_response(res).map_into_right_body())
                }
                Ok((_count, false)) => service.call(req).await.map(|res| res.map_into_left_body()),
                Err(e) => {
                    // Fail open: a rate-limit table outage must not take the API
                    // down. The per-endpoint caps and the auto-ban still apply.
                    tracing::error!(error = %e, "request cap floor check failed; passing through");
                    service.call(req).await.map(|res| res.map_into_left_body())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_and_the_stripe_webhook_are_exempt() {
        assert!(is_exempt("/health", &Method::GET));
        assert!(is_exempt("/v1/health", &Method::GET));
        assert!(is_exempt("/version", &Method::GET));
        assert!(is_exempt("/v1/version", &Method::GET));
        assert!(is_exempt("/v1/webhooks/stripe", &Method::POST));
        assert!(is_exempt("/v1/auth/refresh", &Method::OPTIONS));
        // BUNYIP-450: the stateless signup timing-challenge mint is exempt.
        assert!(is_exempt("/v1/auth/register-challenge", &Method::GET));
        // BUNYIP-518: the public pricing payload is fetched on every BFF render
        // and is server-side TTL-cached, so it is exempt from the per-IP floor
        // that was silently 404'ing /pricing after a few page loads.
        assert!(is_exempt("/v1/pricing", &Method::GET));
        // BUNYIP-555: the feature-flags probe touches no table and is read on
        // every BFF render, so it is exempt and TTL-cached web-side.
        assert!(is_exempt("/v1/auth/setup/status", &Method::GET));
        // BUNYIP-602: the mailer relay is throttled per calling app, not per IP.
        assert!(is_exempt("/v1/mailer/send", &Method::POST));
        // BUNYIP-603: the signed bounce/complaint feedback webhook, like Stripe's.
        assert!(is_exempt("/v1/mailer/webhooks/feedback", &Method::POST));
    }

    #[test]
    fn ordinary_endpoints_are_capped() {
        assert!(!is_exempt("/v1/auth/refresh", &Method::POST));
        // The register POST stays floored even though its challenge is exempt.
        assert!(!is_exempt("/v1/auth/register", &Method::POST));
        assert!(!is_exempt("/v1/users/me", &Method::GET));
        assert!(!is_exempt("/v1/auth/password-reset/verify", &Method::GET));
        // Near-misses must not fall through the exact-match list.
        assert!(!is_exempt("/v1/healthz", &Method::GET));
        assert!(!is_exempt("/v1/webhooks/stripe/extra", &Method::POST));
        assert!(!is_exempt(
            "/v1/auth/register-challenge/extra",
            &Method::GET
        ));
        assert!(!is_exempt("/v1/auth/setup/status/extra", &Method::GET));
        assert!(!is_exempt("/v1/mailer/send/extra", &Method::POST));
        assert!(!is_exempt("/v1/mailer", &Method::POST));
    }

    /// Regression guard: this middleware must never hold a cloned
    /// [`actix_web::HttpRequest`] across the inner `service.call`. Actix's
    /// router calls `HttpRequest::match_info_mut`, which unwraps
    /// `Rc::get_mut` and panics the worker when a second reference is alive, so
    /// a clone here took down every non-exempt request rather than throttling
    /// it. Borrow `req.request()` instead.
    #[test]
    fn never_clones_the_inner_http_request() {
        let src = include_str!("rate_limit_floor.rs");
        let body = src.split("\n#[cfg(test)]").next().unwrap();
        assert!(
            !body.contains("req.request().clone()"),
            "cloning the inner HttpRequest panics actix's router; borrow it instead"
        );
    }
}
