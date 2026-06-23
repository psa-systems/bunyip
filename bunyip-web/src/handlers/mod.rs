pub mod admin;
pub mod auth_pages;
pub mod consent;
pub mod content;
pub mod dashboard;
pub mod health;
pub mod public;
/// BUNYIP-112/113/115/117: shared web-edge field validators that bound and
/// shape user input before it hits the API. Replaces per-form ad-hoc trims
/// and silent `unwrap_or(0)` numeric coercions.
pub mod validate;

use axum::http::HeaderMap;
use axum::response::Response;
use maud::Markup;

use crate::api::calls;
use crate::api::types::{Application, User, UserRole};
use crate::auth::{self, AuthCtx};
use crate::views::layout::{admin_shell, dashboard_shell, document, public_shell};
use crate::web::{html_cookies, redirect_cookies, AppState};

/// Read the forwarded cookie from the request.
pub fn cookie_of(headers: &HeaderMap) -> Option<String> {
    auth::req_cookie(headers)
}

/// Authenticate (optional) for a page that renders differently when signed in.
pub async fn ctx(st: &AppState, headers: &HeaderMap) -> (AuthCtx, Option<String>) {
    let cookie = cookie_of(headers);
    let ctx = auth::authenticate(&st.api, cookie.as_deref()).await;
    let fwd = ctx.forward.clone();
    (ctx, fwd)
}

/// Pseudo-random index (no rand dep): derive from the clock. Fine for picking a
/// rotating hero/tagline line per request.
pub fn rotating_index(len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    (chrono::Utc::now().timestamp_subsec_nanos() as usize) % len
}

/// Authenticate (optional) and fetch the applications list (for header + footer).
pub async fn public_ctx(st: &AppState, headers: &HeaderMap) -> (AuthCtx, Vec<Application>) {
    let (c, fwd) = ctx(st, headers).await;
    let apps = calls::applications(&st.api, fwd.as_deref())
        .await
        .unwrap_or_default();
    (c, apps)
}

/// Wrap content in the public shell + document and relay any refreshed cookies.
pub fn public_response(
    st: &AppState,
    c: &AuthCtx,
    apps: &[Application],
    title: &str,
    launcher: bool,
    content: Markup,
) -> Response {
    let body = public_shell(&st.cfg, c.user.as_ref(), apps, launcher, content);
    html_cookies(document(title, body), &c.set_cookies)
}

/// Render an auth/token page (public shell, no feedback launcher). `content` is
/// computed by the caller.
pub async fn auth_page(
    st: &AppState,
    headers: &HeaderMap,
    title: &str,
    content: Markup,
) -> Response {
    let (c, apps) = public_ctx(st, headers).await;
    public_response(st, &c, &apps, title, false, content)
}

/// Read a single named cookie from the request.
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = cookie_of(headers)?;
    for kv in raw.split(';') {
        if let Some((n, v)) = kv.split_once('=') {
            if n.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Server-side password policy (mirrors the zod schema).
pub fn password_ok(p: &str) -> bool {
    p.len() >= 12
        && p.chars().any(|c| c.is_ascii_lowercase())
        && p.chars().any(|c| c.is_ascii_uppercase())
        && p.chars().any(|c| c.is_ascii_digit())
        && p.chars().any(|c| !c.is_ascii_alphanumeric())
}

/// Authenticate a protected page. `Err` is a ready redirect (to /login when
/// signed out, or to 2FA setup for an admin who hasn't enabled it yet).
pub async fn guard(
    st: &AppState,
    headers: &HeaderMap,
    path: &str,
) -> Result<(User, AuthCtx), Response> {
    let cookie = cookie_of(headers);
    let c = auth::authenticate(&st.api, cookie.as_deref()).await;
    match c.user.clone() {
        None => Err(redirect_cookies("/login", &c.set_cookies)),
        Some(u) => {
            if u.role == UserRole::Admin && !u.two_factor_enabled && path != "/settings/2fa/setup" {
                return Err(redirect_cookies("/settings/2fa/setup", &c.set_cookies));
            }
            Ok((u, c))
        }
    }
}

/// Like `guard` but also requires the admin role (non-admins -> dashboard).
pub async fn admin_guard(st: &AppState, headers: &HeaderMap) -> Result<(User, AuthCtx), Response> {
    let (user, c) = guard(st, headers, "/admin").await?;
    if user.role != UserRole::Admin {
        return Err(redirect_cookies("/dashboard", &c.set_cookies));
    }
    Ok((user, c))
}

/// Standard form-input class used across dashboard/admin forms.
pub fn dashboard_input() -> &'static str {
    "flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
}

pub fn dashboard_response(
    c: &AuthCtx,
    user: &User,
    active: &str,
    title: &str,
    content: Markup,
) -> Response {
    // `title` carries the browser tab title (e.g. "Settings · Bunyip"); the
    // top bar wants just "Settings" with no brand suffix. Strip the suffix
    // here so every handler keeps its existing call shape. A handler that
    // somehow passes a title without the suffix falls through unchanged.
    let topbar_title = topbar_title(title);
    html_cookies(
        document(title, dashboard_shell(user, active, topbar_title, content)),
        &c.set_cookies,
    )
}

pub fn admin_response(
    c: &AuthCtx,
    user: &User,
    active: &str,
    title: &str,
    content: Markup,
) -> Response {
    let topbar_title = topbar_title(title);
    html_cookies(
        document(title, admin_shell(user, active, topbar_title, content)),
        &c.set_cookies,
    )
}

/// Strip the `" · Bunyip"` brand suffix from a browser-tab title so the
/// in-page top bar can render just the page name. Title-without-suffix passes
/// through unchanged.
fn topbar_title(title: &str) -> &str {
    title.strip_suffix(" · Bunyip").unwrap_or(title)
}
