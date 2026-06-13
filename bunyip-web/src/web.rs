//! Shared web plumbing: app state and response builders that relay `Set-Cookie`.

use std::sync::Arc;

use axum::http::header::{HeaderValue, LOCATION, SET_COOKIE};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use maud::Markup;

use crate::api::Api;
use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub api: Api,
    pub cfg: Arc<Config>,
}

fn attach_cookies(resp: &mut Response, cookies: &[String]) {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(SET_COOKIE, v);
        }
    }
}

/// 200 HTML response.
pub fn html(markup: Markup) -> Response {
    Html(markup.into_string()).into_response()
}

/// 200 HTML response that also relays refreshed cookies.
pub fn html_cookies(markup: Markup, cookies: &[String]) -> Response {
    let mut resp = Html(markup.into_string()).into_response();
    attach_cookies(&mut resp, cookies);
    resp
}

/// 303 redirect (so a POST -> GET after form submit).
pub fn redirect(path: &str) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    resp.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(path).unwrap_or(HeaderValue::from_static("/")),
    );
    resp
}

/// 303 redirect that relays cookies (login/logout).
pub fn redirect_cookies(path: &str, cookies: &[String]) -> Response {
    let mut resp = redirect(path);
    attach_cookies(&mut resp, cookies);
    resp
}
