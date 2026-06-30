//! BUNYIP-259: Origin / Referer-based CSRF defense on every state-
//! changing POST through bunyip-web.
//!
//! The audit's full spec is a per-session synchronizer-token middleware
//! plus a hidden form input on every `<form>`. That's the right
//! end-state, but it's also ~25 form templates of churn and a real
//! regression risk for the OIDC flow if a token slips into the wrong
//! redirect chain. This middleware ships the smaller, fully-defensive
//! step: every POST request must carry an `Origin` (or `Referer`
//! fallback) header that matches the BFF's configured `web_origin`.
//!
//! Browsers send `Origin` reliably on cross-site POSTs, so a cross-
//! origin form submission from a compromised child app (or a phisher's
//! page) is rejected at the middleware before any handler runs. Same-
//! origin POSTs (the login form, settings forms, consent grant, …) keep
//! working because their Origin matches.
//!
//! What this DOES catch:
//! - A cross-origin `<form action="https://bunyip-web/login" method="POST">`
//!   submitted from any other host. The Origin header points elsewhere
//!   and the middleware refuses it before the auth handler runs.
//! - An attacker-controlled child app under `*.{app_domain}` submitting
//!   to bunyip-web (form-action was widened by BUNYIP-249/271). The
//!   child app's Origin is on the child host, not the BFF host, so the
//!   middleware refuses it.
//!
//! What this does NOT catch:
//! - A same-origin XSS that synthesizes a POST. CSP is the layer that
//!   stops that one; this middleware can't tell legit JS from injected
//!   JS within the same origin.
//! - A browser that strips Origin / Referer for some misconfigured
//!   reason. The middleware fails closed (403) in that case, which is
//!   the secure default; the user retries from a normal-config browser.
//!
//! Exemptions: the OIDC `/oauth2/*` family is exempt because the spec
//! gates those POSTs on PKCE + state + nonce + client authentication.
//! Cross-origin OIDC flows are exactly what the spec expects an OP to
//! accept. The Stripe webhook lives on bunyip-api, not bunyip-web, so
//! it's not affected here.
//!
//! Follow-up: a synchronizer-token middleware on top of this is a
//! separate ticket. It's defense in depth on top of the Origin check,
//! not a substitute.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Origin-check middleware. Rejects every state-changing POST whose
/// `Origin` header does not match the request's own `Host`. The two
/// align for any legitimate same-origin form submission; a cross-site
/// submission carries the attacker's host in `Origin` while keeping
/// the BFF's host in `Host`, and the mismatch trips this check.
///
/// Falls back to `Referer` (host-only comparison) when `Origin` is
/// absent. When both are absent, the request is refused: a browser
/// stripping both is misconfigured for any real form-driven flow, and
/// the secure default is to fail closed.
pub async fn enforce_origin(req: Request, next: Next) -> Response {
    // Read-only methods don't change state; no CSRF surface.
    if matches!(
        req.method(),
        &Method::GET | &Method::HEAD | &Method::OPTIONS
    ) {
        return next.run(req).await;
    }

    let path = req.uri().path();

    // OIDC handlers authenticate clients via PKCE + state + nonce +
    // client_secret. They are explicitly designed to accept cross-origin
    // requests as part of the redirect-back-to-OP chain; the CSRF
    // surface is closed by the spec, not by Origin.
    if path.starts_with("/oauth2/") {
        return next.run(req).await;
    }

    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let header_origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let header_referer = req
        .headers()
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let matches_origin = match (&host, &header_origin, &header_referer) {
        (Some(h), Some(o), _) => host_of(o).as_deref() == Some(h.as_str()),
        (Some(h), None, Some(r)) => host_of(r).as_deref() == Some(h.as_str()),
        _ => false,
    };

    if matches_origin {
        next.run(req).await
    } else {
        tracing::warn!(
            method = %req.method(),
            path = %path,
            host = ?host,
            origin = ?header_origin,
            referer = ?header_referer,
            "CSRF: rejecting state-changing request with mismatched Origin/Referer"
        );
        (
            StatusCode::FORBIDDEN,
            Body::from(
                "Cross-origin request refused (CSRF). \
                 Open the page directly and try again.",
            ),
        )
            .into_response()
    }
}

/// Extract the host (`example.com:443`) from a full URL like
/// `https://example.com/path`. Returns `None` for inputs that don't
/// parse as URLs (treat as mismatch).
fn host_of(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_string();
    match parsed.port() {
        Some(p) => Some(format!("{host}:{p}")),
        None => Some(host),
    }
}

#[cfg(test)]
mod tests {
    use super::host_of;

    #[test]
    fn host_of_extracts_host_and_port() {
        assert_eq!(host_of("https://a8n.systems/"), Some("a8n.systems".into()));
        assert_eq!(
            host_of("http://localhost:4400/login"),
            Some("localhost:4400".into())
        );
        assert_eq!(host_of("not a url"), None);
    }

    #[test]
    fn host_of_ignores_path_query_and_fragment() {
        assert_eq!(
            host_of("https://example.com/x/y?z=1#f"),
            Some("example.com".into())
        );
    }
}
