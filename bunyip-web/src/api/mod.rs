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

use reqwest::header::{ACCEPT, COOKIE, SET_COOKIE};
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
}

impl ApiError {
    fn network(msg: impl Into<String>) -> Self {
        ApiError {
            status: 0,
            code: "NETWORK_ERROR".into(),
            message: msg.into(),
        }
    }

    pub fn user_message(&self) -> String {
        if self.message.is_empty() {
            "An unexpected error occurred".into()
        } else {
            self.message.clone()
        }
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
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| ApiError::network(e.to_string()))?;
        let status = resp.status().as_u16();
        let set_cookies = resp
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();
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
        let resp = rb
            .send()
            .await
            .map_err(|e| ApiError::network(e.to_string()))?;
        let status = resp.status().as_u16();
        let set_cookies = resp
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();
        let text = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        Ok(Resp {
            status,
            body,
            set_cookies,
        })
    }
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
    ApiError {
        status: resp.status,
        code,
        message,
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
        serde_json::from_value(data).map_err(|e| ApiError {
            status: 0,
            code: "DECODE_ERROR".into(),
            message: e.to_string(),
        })
    } else {
        Err(error_from(&resp))
    }
}
