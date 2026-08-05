//! Server-side client for the separate `/v1` API (the BFF hop).
//!
//! The browser talks only to this Axum frontend; every authed call here runs
//! server-to-server with the user's session cookie forwarded verbatim in the
//! `Cookie` header (the API scopes it to the apex domain, so it reaches us).
//! Auth endpoints return `Set-Cookie`, which we capture in `Resp.set_cookies`
//! so the handler can relay it back to the browser.

pub mod admin;
pub mod auth;
pub mod calls;
pub mod types;

use reqwest::header::{ACCEPT, COOKIE, RETRY_AFTER, SET_COOKIE};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde_json::Value;

#[derive(Clone)]
pub struct Api {
    base_v1: String,
    http: reqwest::Client,
}

/// One API response: status, parsed JSON body, and any `Set-Cookie` headers to
/// relay to the browser.
pub struct Resp {
    pub status: u16,
    pub body: Value,
    pub set_cookies: Vec<String>,
    /// The `Retry-After` header value (whole seconds), captured for 429
    /// responses so `error_from` can surface an accurate wait time
    /// (BUNYIP-314). `None` when the header is absent or non-numeric.
    pub retry_after_header: Option<u64>,
}

impl Resp {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
    /// Seconds the caller should wait before retrying, for a 429 response
    /// (BUNYIP-314). Read from the `Retry-After` header, falling back to the
    /// `error.details.retry_after` body field. `None` for non-throttle errors.
    pub retry_after: Option<u64>,
}

/// Standard human phrasing for a `Retry-After` duration in seconds
/// (BUNYIP-314): under a minute rounds up to "a minute", an hour or more
/// collapses to "an hour", and anything in between rounds the minutes up.
pub fn humanize_retry_after(secs: u64) -> String {
    if secs >= 3600 {
        "in about an hour".to_string()
    } else if secs < 60 {
        "in about a minute".to_string()
    } else {
        format!("in about {} minutes", secs.div_ceil(60))
    }
}

impl ApiError {
    fn network(msg: impl Into<String>) -> Self {
        ApiError {
            status: 0,
            code: "NETWORK_ERROR".into(),
            message: msg.into(),
            retry_after: None,
        }
    }

    pub fn user_message(&self) -> String {
        if self.status == 429 {
            if let Some(secs) = self.retry_after {
                return format!(
                    "Too many attempts. Please try again {}.",
                    humanize_retry_after(secs)
                );
            }
        }
        // BUNYIP-477: never surface backend/transport internals to the browser.
        // status 0 is a transport or JSON-decode failure whose raw text carries
        // the internal API URL or serde detail; a 5xx body can carry a raw
        // backend string. Both collapse to a generic line (the unauthenticated
        // login page renders this directly). A 4xx carries API-authored,
        // user-safe copy and passes through.
        match self.status {
            0 => "Couldn't reach the server. Please try again in a moment.".to_string(),
            500..=599 => "An unexpected error occurred. Please try again later.".to_string(),
            _ if self.message.is_empty() => "An unexpected error occurred".to_string(),
            _ => self.message.clone(),
        }
    }

    /// Verification-email-specific copy for a throttled (429) resend
    /// (BUNYIP-314). Falls back to the generic `user_message()` for any other
    /// error so non-429 handling is unchanged.
    pub fn verification_message(&self) -> String {
        if self.status == 429 {
            if let Some(secs) = self.retry_after {
                return format!(
                    "You have requested too many verification emails. Please try again {}.",
                    humanize_retry_after(secs)
                );
            }
        }
        self.user_message()
    }
}

impl Api {
    pub fn new(api_url: &str) -> Self {
        Api {
            base_v1: format!("{}/v1", api_url.trim_end_matches('/')),
            http: reqwest::Client::new(),
        }
    }

    /// Perform a request. Returns a `Resp` for any HTTP response (including 4xx/5xx);
    /// only transport failures are `Err`.
    pub async fn send(
        &self,
        method: Method,
        path: &str,
        cookie: Option<&str>,
        body: Option<Value>,
    ) -> Result<Resp, ApiError> {
        let url = format!("{}{}", self.base_v1, path);
        let mut rb = self
            .http
            .request(method, &url)
            .header(ACCEPT, "application/json");
        if let Some(c) = cookie {
            rb = rb.header(COOKIE, c);
        }
        rb = forward_client_ip(rb);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let resp = rb.send().await.map_err(|e| {
            // BUNYIP-243: a transport failure means bunyip-api is unreachable.
            // BUNYIP-477: user_message() shows the browser a generic line, so
            // log the real transport detail here for operators.
            tracing::warn!(error = %e, %url, "bunyip-api request failed (transport)");
            crate::server_status::note_transport_error();
            ApiError::network(e.to_string())
        })?;
        let status = resp.status().as_u16();
        // BUNYIP-243: any response clears the down state; a 5xx sets it.
        crate::server_status::note_status(status);
        let set_cookies = resp
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();
        let retry_after_header = retry_after_from_headers(resp.headers());
        let text = resp.text().await.unwrap_or_default();
        let body = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::Null)
        };
        Ok(Resp {
            status,
            body,
            set_cookies,
            retry_after_header,
        })
    }

    pub async fn get(&self, path: &str, cookie: Option<&str>) -> Result<Resp, ApiError> {
        self.send(Method::GET, path, cookie, None).await
    }
    pub async fn post(
        &self,
        path: &str,
        cookie: Option<&str>,
        body: Option<Value>,
    ) -> Result<Resp, ApiError> {
        self.send(Method::POST, path, cookie, body).await
    }
    pub async fn put(
        &self,
        path: &str,
        cookie: Option<&str>,
        body: Option<Value>,
    ) -> Result<Resp, ApiError> {
        self.send(Method::PUT, path, cookie, body).await
    }
    pub async fn delete(
        &self,
        path: &str,
        cookie: Option<&str>,
        body: Option<Value>,
    ) -> Result<Resp, ApiError> {
        self.send(Method::DELETE, path, cookie, body).await
    }

    /// GET returning the raw `reqwest::Response` for streaming a binary body
    /// (the download proxy). Unlike `send`, the body is neither read nor parsed
    /// as JSON here, so a large asset streams through to the browser rather than
    /// buffering in memory. Cookie is forwarded verbatim, same as `send`.
    pub async fn get_stream(
        &self,
        path: &str,
        cookie: Option<&str>,
    ) -> Result<reqwest::Response, ApiError> {
        let url = format!("{}{}", self.base_v1, path);
        let mut rb = self.http.request(Method::GET, &url);
        if let Some(c) = cookie {
            rb = rb.header(COOKIE, c);
        }
        rb = forward_client_ip(rb);
        match rb.send().await {
            Ok(resp) => {
                // BUNYIP-243: classify the streaming-proxy response too.
                crate::server_status::note_status(resp.status().as_u16());
                Ok(resp)
            }
            Err(e) => {
                // BUNYIP-477: generic to the user, detailed in the operator log.
                tracing::warn!(error = %e, %url, "bunyip-api stream request failed (transport)");
                crate::server_status::note_transport_error();
                Err(ApiError::network(e.to_string()))
            }
        }
    }

    /// POST a multipart form (feedback submission).
    pub async fn post_form(
        &self,
        path: &str,
        cookie: Option<&str>,
        form: reqwest::multipart::Form,
    ) -> Result<Resp, ApiError> {
        let url = format!("{}{}", self.base_v1, path);
        let mut rb = self
            .http
            .post(&url)
            .header(ACCEPT, "application/json")
            .multipart(form);
        if let Some(c) = cookie {
            rb = rb.header(COOKIE, c);
        }
        rb = forward_client_ip(rb);
        let resp = rb.send().await.map_err(|e| {
            // BUNYIP-243: a transport failure means bunyip-api is unreachable.
            // BUNYIP-477: generic to the user, detailed in the operator log.
            tracing::warn!(error = %e, %url, "bunyip-api form request failed (transport)");
            crate::server_status::note_transport_error();
            ApiError::network(e.to_string())
        })?;
        let status = resp.status().as_u16();
        // BUNYIP-243: any response clears the down state; a 5xx sets it.
        crate::server_status::note_status(status);
        let set_cookies = resp
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();
        let retry_after_header = retry_after_from_headers(resp.headers());
        let text = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Ok(Resp {
            status,
            body,
            set_cookies,
            retry_after_header,
        })
    }
}

/// BUNYIP-311: attach the end-user's client IP as `X-Forwarded-For` on an
/// outbound API request when the per-request middleware resolved one (i.e. the
/// browser reached the BFF through a trusted proxy). When there is no resolved
/// IP - dev, an untrusted direct peer, or a non-request context like the
/// background health poll - the request is left unchanged, so bunyip-api keeps
/// attributing it to bunyip-web rather than to a fabricated address. bunyip-api
/// reads this as the external client because bunyip-web is in its own
/// `TRUSTED_PROXY_CIDR`.
fn forward_client_ip(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    let mut rb = match crate::client_ip::current() {
        Some(ip) => rb.header("X-Forwarded-For", ip.to_string()),
        None => rb,
    };
    // BUNYIP-409: forward the browser's User-Agent so bunyip-api's session rows
    // record a real device instead of the BFF's HTTP-client UA. Overriding the
    // outbound UA is safe: bunyip-api only uses it for device labelling / access
    // logs, both of which are more correct attributed to the real client.
    if let Some(ua) = crate::client_ip::current_ua() {
        rb = rb.header(reqwest::header::USER_AGENT, ua);
    }
    rb
}

/// Parse the `Retry-After` header as whole seconds (BUNYIP-314). bunyip-api
/// emits it as an integer count of seconds (dunite-core `AppError::RateLimited`);
/// the HTTP-date form is not produced by the API, so only the delta-seconds
/// form is honoured here.
fn retry_after_from_headers(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// Turn the `{ success, error: { code, message } }` envelope into an `ApiError`.
pub fn error_from(resp: &Resp) -> ApiError {
    let err = resp.body.get("error");
    let code = err
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())
        .unwrap_or("REQUEST_FAILED")
        .to_string();
    let message = err
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("Request failed ({})", resp.status));
    // BUNYIP-314: prefer the `Retry-After` header, fall back to the
    // `error.details.retry_after` field in the JSON envelope.
    let retry_after = resp.retry_after_header.or_else(|| {
        err.and_then(|e| e.get("details"))
            .and_then(|d| d.get("retry_after"))
            .and_then(Value::as_u64)
    });
    ApiError {
        status: resp.status,
        code,
        message,
        retry_after,
    }
}

/// `&resp.body["data"]` if 2xx, else the error envelope.
pub fn ok_data(resp: &Resp) -> Result<&Value, ApiError> {
    if resp.ok() {
        Ok(resp.body.get("data").unwrap_or(&Value::Null))
    } else {
        Err(error_from(resp))
    }
}

/// Deserialize `resp.body["data"]` into `T` (or the error envelope).
pub fn parse<T: DeserializeOwned>(resp: Resp) -> Result<T, ApiError> {
    if resp.ok() {
        let data = resp.body.get("data").cloned().unwrap_or(Value::Null);
        serde_json::from_value(data).map_err(|e| {
            // BUNYIP-477: the user sees a generic message; log the decode detail
            // (a 2xx body that did not match the expected shape) for operators.
            tracing::warn!(error = %e, "failed to decode bunyip-api response body");
            ApiError {
                status: 0,
                code: "DECODE_ERROR".into(),
                message: e.to_string(),
                retry_after: None,
            }
        })
    } else {
        Err(error_from(&resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // BUNYIP-314: humanizer boundaries (minute / minutes / hour).
    #[test]
    fn humanize_under_a_minute_says_a_minute() {
        assert_eq!(humanize_retry_after(1), "in about a minute");
        assert_eq!(humanize_retry_after(59), "in about a minute");
    }

    #[test]
    fn humanize_sixty_seconds_crosses_into_minutes() {
        // 60s is the first value past the "a minute" boundary; ceil(60/60) = 1.
        assert_eq!(humanize_retry_after(60), "in about 1 minutes");
    }

    #[test]
    fn humanize_rounds_minutes_up() {
        assert_eq!(humanize_retry_after(61), "in about 2 minutes");
        assert_eq!(humanize_retry_after(120), "in about 2 minutes");
    }

    #[test]
    fn humanize_just_under_an_hour_says_minutes() {
        // 3599s -> ceil(3599/60) = 60 minutes, still under the hour boundary.
        assert_eq!(humanize_retry_after(3599), "in about 60 minutes");
    }

    #[test]
    fn humanize_an_hour_or_more_says_an_hour() {
        assert_eq!(humanize_retry_after(3600), "in about an hour");
        assert_eq!(humanize_retry_after(7200), "in about an hour");
    }

    fn err_resp(status: u16, retry_after_header: Option<u64>, body: Value) -> Resp {
        Resp {
            status,
            body,
            set_cookies: vec![],
            retry_after_header,
        }
    }

    #[test]
    fn error_from_reads_retry_after_header() {
        let resp = err_resp(
            429,
            Some(90),
            json!({ "error": { "code": "RATE_LIMITED", "message": "Too many requests." } }),
        );
        let e = error_from(&resp);
        assert_eq!(e.status, 429);
        assert_eq!(e.retry_after, Some(90));
    }

    #[test]
    fn error_from_falls_back_to_details_retry_after() {
        // No header: the body's `details.retry_after` is used instead.
        let resp = err_resp(
            429,
            None,
            json!({ "error": { "code": "RATE_LIMITED", "message": "x", "details": { "retry_after": 1800 } } }),
        );
        assert_eq!(error_from(&resp).retry_after, Some(1800));
    }

    #[test]
    fn error_from_prefers_header_over_details() {
        let resp = err_resp(
            429,
            Some(45),
            json!({ "error": { "code": "RATE_LIMITED", "details": { "retry_after": 1800 } } }),
        );
        assert_eq!(error_from(&resp).retry_after, Some(45));
    }

    #[test]
    fn user_message_for_429_uses_humanized_retry() {
        let resp = err_resp(
            429,
            Some(1800),
            json!({ "error": { "code": "RATE_LIMITED", "message": "raw dunite text" } }),
        );
        let e = error_from(&resp);
        assert_eq!(
            e.user_message(),
            "Too many attempts. Please try again in about 30 minutes."
        );
        assert_eq!(
            e.verification_message(),
            "You have requested too many verification emails. Please try again in about 30 minutes."
        );
    }

    #[test]
    fn server_and_transport_errors_never_echo_internals() {
        // BUNYIP-477: a 5xx body must collapse to a generic line, never echoing
        // a raw backend string (schema names, SQL, migration detail) to the
        // browser. The unauthenticated login page renders user_message() directly.
        let resp = err_resp(
            500,
            None,
            json!({ "error": { "code": "INTERNAL_ERROR", "message": "relation \"app.users\" violates constraint app_users_source_check" } }),
        );
        let e = error_from(&resp);
        assert_eq!(e.retry_after, None);
        let msg = e.user_message();
        assert!(
            !msg.contains("constraint"),
            "5xx must not echo backend text: {msg}"
        );
        assert_eq!(msg, "An unexpected error occurred. Please try again later.");
        assert_eq!(e.verification_message(), msg);

        // A transport failure (status 0) carries the internal API URL in its
        // message; it must not reach the browser.
        let transport = ApiError {
            status: 0,
            code: "NETWORK_ERROR".into(),
            message: "error sending request for url (http://bunyip-api:4401/v1/auth/login): connection refused".into(),
            retry_after: None,
        };
        let tmsg = transport.user_message();
        assert!(
            !tmsg.contains("bunyip-api"),
            "transport error must not leak the internal host: {tmsg}"
        );
        assert!(
            !tmsg.contains("4401"),
            "transport error must not leak the internal port: {tmsg}"
        );
        assert_eq!(
            tmsg,
            "Couldn't reach the server. Please try again in a moment."
        );
    }

    #[test]
    fn a_429_without_retry_after_keeps_raw_message() {
        // Defensive: a 429 that somehow carries no Retry-After must not panic
        // and falls back to the API's message verbatim.
        let resp = err_resp(
            429,
            None,
            json!({ "error": { "code": "RATE_LIMITED", "message": "Too many requests." } }),
        );
        let e = error_from(&resp);
        assert_eq!(e.retry_after, None);
        assert_eq!(e.user_message(), "Too many requests.");
        assert_eq!(e.verification_message(), "Too many requests.");
    }
}
