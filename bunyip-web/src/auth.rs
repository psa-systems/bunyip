//! Request-scoped authentication for the BFF.
//!
//! `authenticate` validates the forwarded session cookie against `/users/me`.
//! On a 401 it tries `/auth/refresh` once and, if that rotates the cookie,
//! re-reads `/users/me` with the merged cookie. The rotated `Set-Cookie`s are
//! returned for relay to the browser, and `forward` is the cookie string to use
//! for any further API calls in the same request (so they see the fresh token).

use std::collections::BTreeMap;

use axum::http::{header::COOKIE, HeaderMap};

use crate::api::{self, types::User, Api};

/// Read the `Cookie` request header.
pub fn req_cookie(headers: &HeaderMap) -> Option<String> {
    headers.get(COOKIE)?.to_str().ok().map(str::to_string)
}

pub struct AuthCtx {
    pub user: Option<User>,
    /// `Set-Cookie` strings to relay back to the browser (from a refresh).
    pub set_cookies: Vec<String>,
    /// Cookie header to forward on further API calls this request.
    pub forward: Option<String>,
}

impl AuthCtx {
    pub fn is_signed_in(&self) -> bool {
        self.user.is_some()
    }
}

pub async fn authenticate(api: &Api, cookie: Option<&str>) -> AuthCtx {
    let Some(cookie) = cookie else {
        return AuthCtx { user: None, set_cookies: vec![], forward: None };
    };

    match api::auth::me(api, Some(cookie)).await {
        Ok(user) => AuthCtx { user: Some(user), set_cookies: vec![], forward: Some(cookie.to_string()) },
        Err(e) if e.status == 401 => match api::auth::refresh(api, Some(cookie)).await {
            Ok(set) => {
                let merged = merge_cookies(Some(cookie), &set);
                let user = api::auth::me(api, Some(&merged)).await.ok();
                AuthCtx { user, set_cookies: set, forward: Some(merged) }
            }
            Err(_) => AuthCtx { user: None, set_cookies: vec![], forward: Some(cookie.to_string()) },
        },
        Err(_) => AuthCtx { user: None, set_cookies: vec![], forward: Some(cookie.to_string()) },
    }
}

fn cookie_name_value(set_cookie: &str) -> Option<(String, String)> {
    let first = set_cookie.split(';').next()?;
    let (n, v) = first.split_once('=')?;
    Some((n.trim().to_string(), v.trim().to_string()))
}

/// Merge the original `Cookie` header with `Set-Cookie` values (later wins;
/// empty value = deletion).
pub fn merge_cookies(original: Option<&str>, set_cookies: &[String]) -> String {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    if let Some(orig) = original {
        for kv in orig.split(';') {
            if let Some((n, v)) = kv.split_once('=') {
                map.insert(n.trim().to_string(), v.trim().to_string());
            }
        }
    }
    for sc in set_cookies {
        if let Some((n, v)) = cookie_name_value(sc) {
            if v.is_empty() {
                map.remove(&n);
            } else {
                map.insert(n, v);
            }
        }
    }
    map.iter().map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>().join("; ")
}
