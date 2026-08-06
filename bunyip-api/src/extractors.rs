//! Generic error handlers for actix's built-in extractors (BUNYIP-481).
//!
//! Without these, a malformed request body or a bad path/query/form parameter
//! returns actix's default extractor error, whose body is raw framework parse
//! text (field names, parse positions) and bypasses the standard `AppError`
//! envelope. These configs return the `AppError` envelope with a generic
//! message and log the real parse detail server-side instead.

use actix_web::web;

use crate::errors::AppError;

/// Log the real extractor error and return a generic 400 in the `AppError`
/// envelope. `kind` tags the log line; `client_msg` is the only text the caller
/// sees.
fn reject(
    kind: &'static str,
    err: impl std::fmt::Display,
    client_msg: &'static str,
) -> actix_web::Error {
    tracing::warn!(extractor = kind, error = %err, "rejected malformed request");
    AppError::bad_request(client_msg).into()
}

/// JSON body config: keeps the 32 KB limit, generic error on parse failure.
pub fn json_config() -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(32_768)
        .error_handler(|err, _| reject("json", err, "The request body was malformed or invalid."))
}

/// Path parameter config: generic error on parse failure.
pub fn path_config() -> web::PathConfig {
    web::PathConfig::default().error_handler(|err, _| reject("path", err, "Invalid request."))
}

/// Query string config: generic error on parse failure.
pub fn query_config() -> web::QueryConfig {
    web::QueryConfig::default().error_handler(|err, _| reject("query", err, "Invalid request."))
}

/// Urlencoded form config: generic error on parse failure.
pub fn form_config() -> web::FormConfig {
    web::FormConfig::default()
        .error_handler(|err, _| reject("form", err, "The request body was malformed or invalid."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App, HttpResponse};

    async fn ok(_b: web::Json<serde_json::Value>) -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    #[actix_rt::test]
    async fn malformed_json_returns_generic_envelope_no_parse_detail() {
        let app = test::init_service(
            App::new()
                .app_data(json_config())
                .route("/p", web::post().to(ok)),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/p")
            .insert_header(("content-type", "application/json"))
            .set_payload("{ not valid json")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 400);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["success"], false);
        assert_eq!(body["error"]["code"], "BAD_REQUEST");
        assert_eq!(
            body["error"]["message"],
            "The request body was malformed or invalid."
        );
        assert!(body["meta"]["request_id"].is_string());

        // None of actix's raw parse text (field names, positions) leaks.
        let s = body.to_string();
        assert!(!s.contains("expected"), "must not echo parse detail: {s}");
        assert!(
            !s.contains("deserialize"),
            "must not echo parse detail: {s}"
        );
    }
}
