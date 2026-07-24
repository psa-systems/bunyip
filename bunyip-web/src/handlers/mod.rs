pub mod admin;
pub mod auth_pages;
pub mod consent;
pub mod content;
pub mod dashboard;
pub mod health;
/// BUNYIP-206: forced post-registration onboarding (name + verified email).
pub mod onboarding;
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

/// BUNYIP-206: a user has supplied their name once both first AND last name are
/// non-empty (phone is optional). Whitespace-only values count as empty,
/// mirroring the trim-at-the-API-edge behaviour of the profile write.
pub fn names_present(user: &User) -> bool {
    fn present(v: &Option<String>) -> bool {
        matches!(v.as_deref().map(str::trim), Some(s) if !s.is_empty())
    }
    present(&user.first_name) && present(&user.last_name)
}

/// BUNYIP-206: paths a not-yet-onboarded user may still reach, so the onboarding
/// gate cannot trap them: the onboarding page itself, the emailed verification
/// link landing plus its resend control, logout, and static assets.
/// (`/settings/verify-email` and `/logout` do not currently run `guard`, but are
/// listed so this allowlist is the single source of truth for the flow.)
fn onboarding_allowed(path: &str) -> bool {
    matches!(
        path,
        "/onboarding" | "/settings/verify-email" | "/settings/verify-email/resend" | "/logout"
    ) || path.starts_with("/assets")
}

/// BUNYIP-206: the onboarding gate decision. A user still needs onboarding while
/// they lack a name, or - WHEN email delivery is actually configured - while
/// their email is unverified. Email verification is treated as not-required when
/// delivery is disabled (local dev / no-SMTP deploys, `email.enabled` reported
/// via `setup_status.email_enabled`), so the gate can never permanently trap a
/// user who could never receive the verification link. An admin is likewise
/// never held on the email-verification arm: an admin must always be able to
/// reach `/admin/email` to configure or repair the SMTP relay, and a relay that
/// is enabled-but-not-delivering (bad credentials, DMARC/SPF reject, wrong
/// `SMTP_FROM`) would otherwise pin the only admin to `/onboarding` with no way
/// for the verification mail to ever arrive - the chicken-and-egg this closes.
/// A name is still required (it is self-service and needs no email). The
/// dashboard keeps showing the "unverified" badge + resend control, so an admin
/// can still verify once mail works. `setup_status` is only queried for the
/// rare non-admin, name-present-but-unverified case; the common already-
/// onboarded path returns without any API call.
pub async fn needs_onboarding(st: &AppState, user: &User) -> bool {
    let is_admin = user.role == UserRole::Admin;
    // Only a named, unverified, NON-admin user actually consults email delivery
    // status; short-circuit every other case (including the common already-
    // onboarded path) without the API round-trip.
    if !names_present(user) || user.email_verified || is_admin {
        return onboarding_needed(names_present(user), user.email_verified, is_admin, false);
    }
    let email_enabled = crate::api::auth::setup_status(&st.api)
        .await
        .map(|s| s.email_enabled)
        .unwrap_or(false);
    onboarding_needed(true, false, false, email_enabled)
}

/// Pure onboarding-gate policy, split out of [`needs_onboarding`] so the
/// name / verified / admin / email-delivery matrix is unit-testable without an
/// [`AppState`]. A user still needs onboarding while they lack a name; once
/// named, a verified email (or the admin role, or email delivery being off)
/// clears the gate, and only a named, unverified, non-admin user on an
/// email-enabled deployment is held.
fn onboarding_needed(names_present: bool, email_verified: bool, is_admin: bool, email_enabled: bool) -> bool {
    if !names_present {
        return true;
    }
    if email_verified {
        return false;
    }
    // BUNYIP: never trap an admin on unverified email (see `needs_onboarding`).
    if is_admin {
        return false;
    }
    email_enabled
}

/// Authenticate a protected page. `Err` is a ready redirect (to /login when
/// signed out, to 2FA setup for an admin who hasn't enabled it yet, or to
/// /onboarding for a user who hasn't finished onboarding - BUNYIP-206).
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
            // Admin 2FA-setup gate takes precedence over onboarding. An admin
            // who still owes 2FA is pinned to the setup page; while they are ON
            // it we let them through WITHOUT applying the onboarding gate, so
            // the two gates can never fight (or loop) over the same request.
            // Once 2FA is enabled the next request falls through to onboarding.
            if u.role == UserRole::Admin && !u.two_factor_enabled {
                if path != "/settings/2fa/setup" {
                    return Err(redirect_cookies("/settings/2fa/setup", &c.set_cookies));
                }
                return Ok((u, c));
            }
            // BUNYIP-206: force a new user through /onboarding (name + verified
            // email) before any app surface. A no-op for bootstrap admins
            // (already named + verified) and for any already-onboarded user.
            // `needs_onboarding` is only consulted for non-allowlisted paths, so
            // the /onboarding page + flow routes never re-enter the gate.
            if !onboarding_allowed(path) && needs_onboarding(st, &u).await {
                return Err(redirect_cookies("/onboarding", &c.set_cookies));
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

#[cfg(test)]
mod onboarding_gate_tests {
    use super::{names_present, onboarding_allowed};
    use crate::api::types::{MembershipStatus, SubscriptionTier, User, UserRole};

    fn user(first: Option<&str>, last: Option<&str>) -> User {
        User {
            id: "u1".into(),
            email: "u@example.com".into(),
            role: UserRole::Subscriber,
            email_verified: false,
            two_factor_enabled: false,
            membership_status: MembershipStatus::None,
            price_locked: false,
            locked_price_id: None,
            locked_price_amount: None,
            created_at: String::new(),
            updated_at: String::new(),
            subscription_tier: SubscriptionTier::Free,
            trial_ends_at: None,
            lifetime_member: false,
            first_name: first.map(str::to_string),
            last_name: last.map(str::to_string),
            phone: None,
        }
    }

    #[test]
    fn names_present_needs_both() {
        assert!(names_present(&user(Some("Ada"), Some("Lovelace"))));
        assert!(!names_present(&user(None, None)));
        assert!(!names_present(&user(Some("Ada"), None)));
        assert!(!names_present(&user(None, Some("Lovelace"))));
    }

    #[test]
    fn whitespace_only_names_count_as_empty() {
        assert!(!names_present(&user(Some("   "), Some("Lovelace"))));
        assert!(!names_present(&user(Some("Ada"), Some("\t"))));
    }

    #[test]
    fn onboarding_gate_matrix() {
        use super::onboarding_needed;
        // A missing name always gates, regardless of anything else.
        assert!(onboarding_needed(false, false, false, false));
        assert!(onboarding_needed(false, true, true, true));
        // Named + verified never gates.
        assert!(!onboarding_needed(true, true, false, true));
        // Named, unverified, NON-admin: gated only when email delivery is on.
        assert!(onboarding_needed(true, false, false, true));
        assert!(!onboarding_needed(true, false, false, false));
    }

    #[test]
    fn admin_is_never_trapped_on_unverified_email() {
        use super::onboarding_needed;
        // BUNYIP: a named admin with an unverified email is NOT gated even when
        // email delivery is enabled - otherwise a broken relay could pin the
        // only admin to /onboarding with no way to reach /admin/email.
        assert!(!onboarding_needed(true, false, true, true));
        assert!(!onboarding_needed(true, false, true, false));
        // But an admin still needs a name (self-service, no email required).
        assert!(onboarding_needed(false, false, true, true));
    }

    #[test]
    fn allowlist_admits_flow_paths_only() {
        for p in [
            "/onboarding",
            "/settings/verify-email",
            "/settings/verify-email/resend",
            "/logout",
            "/assets/app.css",
        ] {
            assert!(onboarding_allowed(p), "{p} should be allowed");
        }
        for p in ["/dashboard", "/settings", "/membership", "/admin", "/"] {
            assert!(!onboarding_allowed(p), "{p} should be gated");
        }
    }
}
