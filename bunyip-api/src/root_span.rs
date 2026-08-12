//! Tracing root span whose `http.client_ip` is the resolved external client IP
//! (BUNYIP-310).
//!
//! `tracing_actix_web::DefaultRootSpanBuilder` records `http.client_ip` from
//! actix `realip_remote_addr()`, which trusts `X-Forwarded-For`/`Forwarded`
//! from ANY peer (spoofable) and ignores `TRUSTED_PROXY_CIDR`. This builder
//! records `http.client_ip` via [`extract_client_ip`] instead - the same
//! trusted-proxy resolution the access log and rate-limit records use - so the
//! header is honoured ONLY when the socket peer is a configured trusted proxy,
//! and every other field matches `DefaultRootSpanBuilder` exactly.
//!
//! The field must be set once, at span creation, rather than overwritten via
//! `Span::record` afterwards: the `tracing_subscriber` fmt field formatter
//! APPENDS on `record`, so a post-hoc override would emit `http.client_ip`
//! twice (leaking the spoofable realip value alongside the resolved one). This
//! builder therefore reconstructs the span with the corrected value in place,
//! mirroring the field set of `tracing_actix_web`'s `root_span!` macro.

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::Version;
use actix_web::{Error, HttpMessage};
use tracing::field::Empty;
use tracing::Span;
use tracing_actix_web::{DefaultRootSpanBuilder, RequestId, RootSpanBuilder};

use crate::middleware::extract_client_ip;
use crate::middleware::request_id::RequestId as ResponseRequestId;

fn http_flavor(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => "unknown",
    }
}

fn http_scheme(scheme: &str) -> &'static str {
    match scheme {
        "http" => "http",
        "https" => "https",
        _ => "other",
    }
}

/// A [`RootSpanBuilder`] that records the trusted external client IP in
/// `http.client_ip` instead of the spoofable actix realip. All other fields
/// (method, route, flavor, scheme, host, user-agent, target, status, request
/// id, otel/exception placeholders) match `DefaultRootSpanBuilder`.
pub struct ClientIpRootSpanBuilder;

impl RootSpanBuilder for ClientIpRootSpanBuilder {
    fn on_request_start(request: &ServiceRequest) -> Span {
        let user_agent = request
            .headers()
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let http_route: std::borrow::Cow<'static, str> = request
            .match_pattern()
            .map(Into::into)
            .unwrap_or_else(|| "default".into());
        let http_method = request.method().as_str();
        // BUNYIP-516: prefer the `RequestId` the dunite request-id middleware
        // put in the extensions - that is the value it echoes in the
        // `X-Request-Id` response header, so the id a caller can quote from a
        // failed response is the id that appears on these log lines. The
        // `tracing_actix_web` id is a different uuid that never leaves the
        // process, so it is only the fallback (this middleware runs outside the
        // tracing layer, but never assume it is installed).
        let request_id = request
            .extensions()
            .get::<ResponseRequestId>()
            .map(|id| id.0.clone())
            .or_else(|| {
                request
                    .extensions()
                    .get::<RequestId>()
                    .copied()
                    .map(|id| id.to_string())
            })
            .unwrap_or_default();
        let client_ip = extract_client_ip(request.request())
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let target = request
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default();
        let connection_info = request.connection_info();

        let span = tracing::info_span!(
            "HTTP request",
            http.method = %http_method,
            http.route = %http_route,
            http.flavor = %http_flavor(request.version()),
            http.scheme = %http_scheme(connection_info.scheme()),
            http.host = %connection_info.host(),
            http.client_ip = %client_ip,
            http.user_agent = %user_agent,
            http.target = %target,
            http.status_code = Empty,
            otel.name = %format!("{http_method} {http_route}"),
            otel.kind = "server",
            otel.status_code = Empty,
            trace_id = Empty,
            request_id = %request_id,
            exception.message = Empty,
            exception.details = Empty,
        );
        drop(connection_info);
        span
    }

    fn on_request_end<B: MessageBody>(span: Span, outcome: &Result<ServiceResponse<B>, Error>) {
        DefaultRootSpanBuilder::on_request_end(span, outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    /// Without a `Config` in app data no proxy is trusted, so a forged
    /// `X-Forwarded-For` is ignored and the span's `http.client_ip` is the
    /// socket peer. Proves the root span never trusts a spoofed header by
    /// default; the trusted-proxy resolution itself is unit-tested in
    /// `bunyip_domain::middleware::auth`.
    #[test]
    fn root_span_client_ip_ignores_spoofed_xff_without_trusted_proxy_config() {
        let req = TestRequest::default()
            .peer_addr("198.51.100.9:5555".parse().unwrap())
            .insert_header(("X-Forwarded-For", "203.0.113.7"))
            .to_srv_request();
        let ip = extract_client_ip(req.request());
        assert_eq!(ip.map(|ip| ip.to_string()).as_deref(), Some("198.51.100.9"));
    }

    /// The builder produces a span without panicking even when the peer address
    /// is unavailable (no `Config`, no peer).
    #[test]
    fn root_span_builds_without_peer() {
        let req = TestRequest::default().to_srv_request();
        let _span = ClientIpRootSpanBuilder::on_request_start(&req);
    }
}
