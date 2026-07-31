//! BUNYIP-423: Origin / Referer CSRF guard for cookie-authenticated writes
//! against bunyip-api.
//!
//! `extract_token` (bunyip-domain `middleware/auth.rs`) reads the `access_token`
//! cookie before the `Authorization` header, so every `/v1/*` handler is
//! reachable on ambient cookie credentials. The cookies are `SameSite=Lax`,
//! which is a cross-SITE control: with `COOKIE_DOMAIN` set to a shared apex, a
//! sibling host under the same registrable domain is same-site and the browser
//! still attaches the cookie. CORS gates response READING and preflighted
//! writes, not a bodyless form POST (a CORS simple request), and several admin
//! POST handlers take no body extractor at all. This middleware closes that
//! surface: a state-changing request carrying an ambient auth cookie must name
//! an allow-listed origin.
//!
//! Runs INSIDE the CORS wrap (registered before `.wrap(cors)` in `main.rs`, and
//! actix executes wraps outside-in in reverse registration order), so preflight
//! `OPTIONS` is answered by CORS and never reaches this guard.
//!
//! Missing headers pass. Per WHATWG Fetch ("Append a request `Origin` header"),
//! a browser appends `Origin` to EVERY request whose method is not `GET` /
//! `HEAD`, using the literal `null` when the referrer policy suppresses the
//! real value, so any browser-driven write arrives with the header present and
//! `null` fails the allow-list like any other foreign origin. A request with
//! neither header is therefore not browser-driven: it is the bunyip-web BFF hop
//! (`bunyip-web/src/api/mod.rs` forwards the user's cookie server-to-server and
//! sends no `Origin`), a service client, or a test harness. None of those carry
//! an ambient credential the attacker can ride, and failing them closed would
//! take down every authenticated write in the product.
//!
//! Exemptions: `/oauth2/*` and `/.well-known/*` are cross-origin by design and
//! are gated by PKCE + state + nonce + client authentication (the same carve-out
//! `bunyip-web/src/csrf.rs` makes), and `/v1/webhooks/stripe` is HMAC-
//! authenticated by Stripe and carries no `Origin`.

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
    sync::Arc,
};

/// Paths exempt from the check, matched by prefix.
const EXEMPT_PREFIXES: [&str; 3] = ["/oauth2/", "/.well-known/", "/v1/webhooks/stripe"];

/// Cookies that authenticate a request without the caller proving intent: the
/// access token every `/v1` handler accepts, and the refresh token
/// `POST /v1/auth/refresh` accepts once the access cookie has expired.
const AMBIENT_COOKIES: [&str; 2] = ["access_token", "refresh_token"];

/// One allow-list entry, pre-parsed from a `CORS_ORIGIN` value.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AllowedOrigin {
    /// Serialized origin (`https://app.example.com`), compared against `Origin`.
    origin: String,
    /// Host with any explicit port (`app.example.com`, `localhost:4400`),
    /// compared against the `Referer` fallback.
    host: String,
}

/// Parse a `CORS_ORIGIN` entry / header value into its origin and host forms.
/// Returns `None` for anything that is not an absolute hierarchical URL, which
/// includes the literal `null` origin.
fn parse_origin(value: &str) -> Option<AllowedOrigin> {
    let url = url::Url::parse(value.trim()).ok()?;
    let origin = url.origin();
    if !origin.is_tuple() {
        return None;
    }
    let host = match (url.host_str()?, url.port()) {
        (h, Some(p)) => format!("{h}:{p}"),
        (h, None) => h.to_string(),
    };
    Some(AllowedOrigin {
        origin: origin.ascii_serialization(),
        host,
    })
}

/// Actix middleware factory. Built once from the parsed `CORS_ORIGIN` list.
#[derive(Clone)]
pub struct OriginGuard {
    allowed: Arc<Vec<AllowedOrigin>>,
}

impl OriginGuard {
    /// Build the guard from the `CORS_ORIGIN` entries. Unparseable entries are
    /// logged and dropped rather than aborting startup, matching how the CORS
    /// layer itself tolerates a bad entry.
    pub fn new(origins: &[String]) -> Self {
        let allowed = origins
            .iter()
            .filter_map(|o| match parse_origin(o) {
                Some(parsed) => Some(parsed),
                None => {
                    tracing::warn!(entry = %o, "ignoring unparseable CORS_ORIGIN entry in CSRF guard");
                    None
                }
            })
            .collect();
        Self {
            allowed: Arc::new(allowed),
        }
    }
}

/// Whether the request may proceed. `false` means reject with 403.
fn is_permitted(req: &ServiceRequest, allowed: &[AllowedOrigin]) -> bool {
    // Safe methods change no state.
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }

    let path = req.path();
    if EXEMPT_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return true;
    }

    // No ambient cookie means no CSRF surface: a Bearer token is never attached
    // by the browser on its own.
    if !AMBIENT_COOKIES.iter().any(|c| req.cookie(c).is_some()) {
        return true;
    }

    let header = |name| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
    };

    match (
        header(actix_web::http::header::ORIGIN),
        header(actix_web::http::header::REFERER),
    ) {
        (Some(origin), _) => {
            parse_origin(origin).is_some_and(|o| allowed.iter().any(|a| a.origin == o.origin))
        }
        // Referer carries a full URL; compare host + port only, since a
        // downgraded scheme cannot be forged into a matching host.
        (None, Some(referer)) => {
            parse_origin(referer).is_some_and(|r| allowed.iter().any(|a| a.host == r.host))
        }
        // Neither header: not a browser request (see the module docs).
        (None, None) => true,
    }
}

impl<S, B> Transform<S, ServiceRequest> for OriginGuard
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = OriginGuardService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(OriginGuardService {
            service: Rc::new(service),
            allowed: self.allowed.clone(),
        }))
    }
}

pub struct OriginGuardService<S> {
    service: Rc<S>,
    allowed: Arc<Vec<AllowedOrigin>>,
}

impl<S, B> Service<ServiceRequest> for OriginGuardService<S>
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
        if is_permitted(&req, &self.allowed) {
            let fut = self.service.call(req);
            return Box::pin(async move { fut.await.map(ServiceResponse::map_into_left_body) });
        }

        tracing::warn!(
            method = %req.method(),
            path = %req.path(),
            origin = ?req.headers().get(actix_web::http::header::ORIGIN),
            referer = ?req.headers().get(actix_web::http::header::REFERER),
            "CSRF: rejecting cookie-authenticated write from an unlisted origin"
        );
        let res = HttpResponse::Forbidden().json(serde_json::json!({
            "success": false,
            "error": {
                "code": "CSRF_ORIGIN_REJECTED",
                "message": "Cross-origin request refused. Retry from the application.",
            }
        }));
        Box::pin(async move { Ok(req.into_response(res).map_into_right_body()) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App, HttpResponse as Resp};

    const ALLOWED: &str = "http://localhost:4400";
    const EVIL: &str = "https://evil.example";

    fn guard() -> OriginGuard {
        OriginGuard::new(&[ALLOWED.to_string(), "https://app.a8n.systems".to_string()])
    }

    /// A one-route app behind the guard. The route answers every path and
    /// method, so a 403 proves the guard short-circuited before routing.
    macro_rules! app {
        () => {
            test::init_service(
                App::new()
                    .wrap(guard())
                    .default_service(web::to(|| async { Resp::Ok().body("handler ran") })),
            )
            .await
        };
    }

    // `use actix_web::test` shadows the built-in `#[test]` attribute, so the
    // pure-function cases run under the actix harness like the rest.
    #[actix_web::test]
    async fn parse_origin_normalizes_default_ports() {
        assert_eq!(
            parse_origin("https://a8n.systems").unwrap().origin,
            "https://a8n.systems"
        );
        assert_eq!(
            parse_origin("https://a8n.systems:443/").unwrap().origin,
            "https://a8n.systems"
        );
        assert_eq!(
            parse_origin("http://localhost:4400").unwrap().host,
            "localhost:4400"
        );
    }

    #[actix_web::test]
    async fn parse_origin_rejects_opaque_and_garbage() {
        // The literal `null` origin a browser sends under a no-referrer policy.
        assert_eq!(parse_origin("null"), None);
        assert_eq!(parse_origin(""), None);
        assert_eq!(parse_origin("not a url"), None);
    }

    // BUNYIP-423 AC1: an admin write with a valid cookie and a foreign Origin is
    // refused before routing, so the handler never runs.
    #[actix_web::test]
    async fn rejects_cookie_write_from_foreign_origin() {
        let req = test::TestRequest::post()
            .uri("/v1/admin/users/00000000-0000-0000-0000-000000000001/two-factor/reset")
            .cookie(actix_web::cookie::Cookie::new("access_token", "jwt"))
            .insert_header(("Origin", EVIL))
            .to_request();
        let res = test::call_service(&app!(), req).await;
        assert_eq!(res.status(), 403);
        let body = test::read_body(res).await;
        assert!(!String::from_utf8_lossy(&body).contains("handler ran"));
    }

    // BUNYIP-423 AC2: the same write from a configured CORS_ORIGIN passes.
    #[actix_web::test]
    async fn allows_cookie_write_from_allowed_origin() {
        let req = test::TestRequest::post()
            .uri("/v1/admin/users/00000000-0000-0000-0000-000000000001/two-factor/reset")
            .cookie(actix_web::cookie::Cookie::new("access_token", "jwt"))
            .insert_header(("Origin", ALLOWED))
            .to_request();
        let res = test::call_service(&app!(), req).await;
        assert_eq!(res.status(), 200);
    }

    // BUNYIP-423 AC3: a Bearer-authenticated service call carries no ambient
    // credential and legitimately has no Origin.
    #[actix_web::test]
    async fn allows_bearer_write_without_cookie_or_origin() {
        let req = test::TestRequest::post()
            .uri("/v1/admin/users/00000000-0000-0000-0000-000000000001/two-factor/reset")
            .insert_header(("Authorization", "Bearer at+jwt"))
            .to_request();
        let res = test::call_service(&app!(), req).await;
        assert_eq!(res.status(), 200);
    }

    // BUNYIP-423 AC4: the OIDC OP surface and the Stripe webhook are exempt.
    #[actix_web::test]
    async fn exempts_oauth2_and_stripe_webhook() {
        for path in [
            "/oauth2/token",
            "/.well-known/openid-configuration",
            "/v1/webhooks/stripe",
        ] {
            let req = test::TestRequest::post()
                .uri(path)
                .cookie(actix_web::cookie::Cookie::new("access_token", "jwt"))
                .insert_header(("Origin", EVIL))
                .to_request();
            let res = test::call_service(&app!(), req).await;
            assert_eq!(res.status(), 200, "{path} must be exempt");
        }
    }

    // The bunyip-web BFF hop forwards the cookie server-to-server with no
    // Origin; browsers always send one on a write, so this cannot be an attack.
    #[actix_web::test]
    async fn allows_cookie_write_with_no_origin_or_referer() {
        let req = test::TestRequest::post()
            .uri("/v1/users/me/email")
            .cookie(actix_web::cookie::Cookie::new("access_token", "jwt"))
            .to_request();
        let res = test::call_service(&app!(), req).await;
        assert_eq!(res.status(), 200);
    }

    #[actix_web::test]
    async fn falls_back_to_referer_when_origin_absent() {
        let allowed = test::TestRequest::post()
            .uri("/v1/users/me/email")
            .cookie(actix_web::cookie::Cookie::new("access_token", "jwt"))
            .insert_header(("Referer", format!("{ALLOWED}/admin/users")))
            .to_request();
        assert_eq!(test::call_service(&app!(), allowed).await.status(), 200);

        let foreign = test::TestRequest::post()
            .uri("/v1/users/me/email")
            .cookie(actix_web::cookie::Cookie::new("access_token", "jwt"))
            .insert_header(("Referer", format!("{EVIL}/pwn")))
            .to_request();
        assert_eq!(test::call_service(&app!(), foreign).await.status(), 403);
    }

    // The refresh cookie outlives the access cookie, so it is an ambient
    // credential in its own right.
    #[actix_web::test]
    async fn guards_refresh_cookie_writes() {
        let req = test::TestRequest::post()
            .uri("/v1/auth/refresh")
            .cookie(actix_web::cookie::Cookie::new("refresh_token", "opaque"))
            .insert_header(("Origin", EVIL))
            .to_request();
        assert_eq!(test::call_service(&app!(), req).await.status(), 403);
    }

    // A browser under `Referrer-Policy: no-referrer` sends the literal `null`
    // origin, which must not be mistaken for an absent header.
    #[actix_web::test]
    async fn rejects_null_origin() {
        let req = test::TestRequest::post()
            .uri("/v1/users/me/email")
            .cookie(actix_web::cookie::Cookie::new("access_token", "jwt"))
            .insert_header(("Origin", "null"))
            .to_request();
        assert_eq!(test::call_service(&app!(), req).await.status(), 403);
    }

    #[actix_web::test]
    async fn safe_methods_are_never_blocked() {
        let req = test::TestRequest::get()
            .uri("/v1/admin/users")
            .cookie(actix_web::cookie::Cookie::new("access_token", "jwt"))
            .insert_header(("Origin", EVIL))
            .to_request();
        assert_eq!(test::call_service(&app!(), req).await.status(), 200);
    }
}
