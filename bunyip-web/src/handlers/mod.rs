pub mod admin;
pub mod auth_pages;
pub mod consent;
pub mod dashboard;
pub mod health;
/// BUNYIP-206: forced post-registration onboarding (name + verified email).
pub mod onboarding;
/// BUNYIP-493: the organizations and teams surface, behind its feature flag.
pub mod organizations;
// BUNYIP-501: the public marketing / legal / docs / landing pages moved to
// `crate::skin` (content.rs, public.rs). Only framework handlers live here now.
/// BUNYIP-112/113/115/117: shared web-edge field validators that bound and
/// shape user input before it hits the API. Replaces per-form ad-hoc trims
/// and silent `unwrap_or(0)` numeric coercions.
pub mod validate;

use axum::http::HeaderMap;
use axum::response::Response;
use maud::Markup;

use crate::api::types::{Application, PricingResponse, User, UserRole};
use crate::auth::{self, AuthCtx};
use crate::util::urlenc;
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

/// Authenticate (optional) and fetch the chrome's shared data: the applications
/// list (header + footer) and the public pricing payload.
///
/// BUNYIP-487: the pricing payload rides along because the Pricing nav link and
/// footer link must vanish whenever `/pricing` would 404.
///
/// BUNYIP-515: both fetches still degrade to an empty value, because a dead nav
/// link is worse for a visitor than a missing one, but neither degrades
/// silently. The failure is logged at `error` with the endpoint first: a public
/// page rendering without its pricing or its app list is a deployment fault, and
/// the operator has no other witness (the visitor sees a page that merely looks
/// thin, and the admin sees /pricing 404 with nothing to explain it).
///
/// BUNYIP-518/555: both payloads drive chrome on EVERY public render, so both go
/// through a short-TTL cache (`AppState::public_applications` / `pricing`):
/// renders coalesce into one upstream call each, keeping the per-render fetches
/// off the rate-limit floor that used to 404 `/pricing` and empty the footer. A
/// cache miss on both runs the two fetches CONCURRENTLY - neither consumes the
/// other's result - so the render costs the slower of the two, not their sum.
/// `join!`, not `try_join!`: each payload degrades independently.
pub async fn public_ctx(
    st: &AppState,
    headers: &HeaderMap,
) -> (AuthCtx, Vec<Application>, PricingResponse) {
    let (c, _fwd) = ctx(st, headers).await;
    let (apps, pricing) = tokio::join!(st.public_applications(), st.pricing());
    (c, apps, pricing)
}

/// Wrap content in the public shell + document and relay any refreshed cookies.
pub fn public_response(
    st: &AppState,
    c: &AuthCtx,
    apps: &[Application],
    pricing: &PricingResponse,
    title: &str,
    launcher: bool,
    content: Markup,
) -> Response {
    let body = public_shell(
        &st.cfg,
        c.user.as_ref(),
        apps,
        pricing.published(),
        launcher,
        content,
    );
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
    let (c, apps, pricing) = public_ctx(st, headers).await;
    public_response(st, &c, &apps, &pricing, title, false, content)
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
    // BUNYIP-515: "could not evaluate" defaulted to "email is off" with nothing
    // logged, which is the same answer as a genuinely mail-less deployment. The
    // default stays (it keeps the user off a verification wall they cannot
    // clear), but the failure is now named. BUNYIP-555: the flags come from the
    // shared TTL cache, which logs the failed fetch itself and serves the last
    // good flags rather than letting a transient 429 decide the gate.
    let email_enabled = match st.setup_status().await {
        Some(s) => s.email_enabled,
        None => {
            tracing::warn!(
                endpoint = "/v1/auth/setup/status",
                "onboarding gate assuming email delivery is unavailable"
            );
            false
        }
    };
    onboarding_needed(true, false, false, email_enabled)
}

/// Pure onboarding-gate policy, split out of [`needs_onboarding`] so the
/// name / verified / admin / email-delivery matrix is unit-testable without an
/// [`AppState`]. A user still needs onboarding while they lack a name; once
/// named, a verified email (or the admin role, or email delivery being off)
/// clears the gate, and only a named, unverified, non-admin user on an
/// email-enabled deployment is held.
fn onboarding_needed(
    names_present: bool,
    email_verified: bool,
    is_admin: bool,
    email_enabled: bool,
) -> bool {
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

/// BUNYIP-619: the message a refused verification-gated action shows. It NAMES
/// verification (not permission) so an admin knows the wall is their unverified
/// email, and points at the resend control that clears it. The reason must be
/// unmistakable, per the acceptance criteria.
pub const VERIFICATION_REQUIRED_MESSAGE: &str =
    "Verify your email before performing this action. Use the resend link on your dashboard.";

/// BUNYIP-619: a principal is verification-complete once their name is present
/// AND their email is verified. This is the property a privileged action
/// requires, and it is deliberately distinct from the onboarding wall an admin
/// is allowed to pass ([`needs_onboarding`]).
pub fn is_verified(user: &User) -> bool {
    names_present(user) && user.email_verified
}

/// BUNYIP-619: refuse a verification-gated action when the acting principal is
/// not verification-complete, ADMIN INCLUDED. `Some(redirect)` bounces back to
/// `back` carrying a toast that names verification as the reason; `None` lets the
/// action proceed.
///
/// This is not the onboarding wall. BUNYIP-401 lifted the wall for admins so an
/// admin whose verification mail cannot be delivered can still sign in, reach the
/// dashboard, and repair SMTP; that same carve-out lifted every verification
/// requirement, which let an unverified admin edit users, grant tiers and
/// memberships, and send mail on the account's behalf. This gate restores the
/// floor at each privileged action without re-trapping the admin at the entry
/// gate: they still get in, they just cannot exercise a gated action until
/// verification succeeds. It gates on `email_verified` itself, never on whether
/// mail delivery is configured, so turning mail off cannot turn the requirement
/// off.
pub fn verification_gate(user: &User, c: &AuthCtx, back: &str) -> Option<Response> {
    if is_verified(user) {
        return None;
    }
    tracing::warn!(
        user_id = %user.id,
        back,
        "refused a verification-gated action: acting admin is unverified (BUNYIP-619)"
    );
    let sep = if back.contains('?') { '&' } else { '?' };
    Some(redirect_cookies(
        &format!(
            "{back}{sep}toast_err={}",
            urlenc(VERIFICATION_REQUIRED_MESSAGE)
        ),
        &c.set_cookies,
    ))
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
    // BUNYIP-499: `title` is the bare page title (e.g. "Settings"). The browser
    // tab suffix (" · {app_name}") is appended in `document()`; the top bar
    // renders the bare title.
    html_cookies(
        document(title, dashboard_shell(user, active, title, content)),
        &c.set_cookies,
    )
}

/// BUNYIP-554: `dashboard_response` for the one page that renders
/// `views::avatar_picker::avatar_picker` (`/settings`). Only this response
/// carries the picker's stylesheet and `assets/js/avatar-picker.js`; every
/// other page ships the slot rule alone. Rendering the picker through the plain
/// `dashboard_response` leaves it unstyled and inert.
pub fn dashboard_response_with_avatar_picker(
    c: &AuthCtx,
    user: &User,
    active: &str,
    title: &str,
    content: Markup,
) -> Response {
    html_cookies(
        crate::views::layout::document_with_avatar_picker(
            title,
            dashboard_shell(user, active, title, content),
            true,
        ),
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
    html_cookies(
        document(title, admin_shell(user, active, title, content)),
        &c.set_cookies,
    )
}

#[cfg(test)]
mod onboarding_gate_tests {
    use super::{names_present, onboarding_allowed};
    use crate::api::types::{MembershipStatus, MembershipTier, User, UserRole};

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
            membership_tier: MembershipTier::Free,
            trial_ends_at: None,
            lifetime_member: false,
            first_name: first.map(str::to_string),
            last_name: last.map(str::to_string),
            phone: None,
            avatar_updated_at: None,
            is_super_admin: false,
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

/// BUNYIP-619: the verification gate on privileged admin actions.
///
/// The escape hatch BUNYIP-401 added lets an unverified admin sign in and reach
/// the dashboard; this gate stops that same admin from exercising a
/// verification-gated action until their email is verified. The two behaviours
/// are tested together so a future edit cannot silently trade one for the other.
#[cfg(test)]
mod verification_gate_tests {
    use super::{is_verified, verification_gate, VERIFICATION_REQUIRED_MESSAGE};
    use crate::api::types::{MembershipStatus, MembershipTier, User, UserRole};
    use crate::auth::AuthCtx;
    use crate::util::urlenc;
    use axum::http::header::LOCATION;

    fn admin(verified: bool, first: Option<&str>, last: Option<&str>) -> User {
        User {
            id: "admin-1".into(),
            email: "admin@example.com".into(),
            role: UserRole::Admin,
            email_verified: verified,
            two_factor_enabled: true,
            membership_status: MembershipStatus::None,
            price_locked: false,
            locked_price_id: None,
            locked_price_amount: None,
            created_at: String::new(),
            updated_at: String::new(),
            membership_tier: MembershipTier::Free,
            trial_ends_at: None,
            lifetime_member: false,
            first_name: first.map(str::to_string),
            last_name: last.map(str::to_string),
            phone: None,
            avatar_updated_at: None,
            is_super_admin: false,
        }
    }

    fn ctx() -> AuthCtx {
        AuthCtx {
            user: None,
            set_cookies: Vec::new(),
            forward: None,
        }
    }

    #[test]
    fn verification_needs_both_name_and_email() {
        // Only a named AND email-verified principal is verification-complete.
        assert!(is_verified(&admin(true, Some("Ada"), Some("Lovelace"))));
        assert!(!is_verified(&admin(false, Some("Ada"), Some("Lovelace"))));
        assert!(!is_verified(&admin(true, None, None)));
        assert!(!is_verified(&admin(true, Some("Ada"), None)));
    }

    #[test]
    fn an_unverified_admin_still_reaches_the_dashboard() {
        // AC2 / BUNYIP-401: the gate must not re-trap the admin at the entry
        // wall. A named, unverified admin still clears onboarding (so sign-in and
        // the dashboard succeed) whether or not mail delivery is configured - it
        // is only the privileged ACTIONS above that refuse them.
        assert!(!super::onboarding_needed(true, false, true, true));
        assert!(!super::onboarding_needed(true, false, true, false));
    }

    #[test]
    fn a_verified_admin_passes_the_gate() {
        // The gate never stands in the way of a verified admin: the action runs.
        let user = admin(true, Some("Ada"), Some("Lovelace"));
        assert!(verification_gate(&user, &ctx(), "/admin/users").is_none());
    }

    #[test]
    fn an_unverified_admin_is_refused_with_a_reason_that_names_verification() {
        // BUNYIP-619: an unverified admin is refused, bounced back to the same
        // page, and told verification (not permission) is what stands in the way.
        let user = admin(false, Some("Ada"), Some("Lovelace"));
        let refusal = verification_gate(&user, &ctx(), "/admin/users/u42")
            .expect("an unverified admin must be refused");
        let location = refusal
            .headers()
            .get(LOCATION)
            .expect("a refusal redirects")
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            location.starts_with("/admin/users/u42?toast_err="),
            "refusal must bounce back to the originating page: {location}"
        );
        assert!(
            location.contains(&urlenc(VERIFICATION_REQUIRED_MESSAGE)),
            "refusal must carry the verification message: {location}"
        );
        // The message itself must actually name verification, not read as a
        // generic permission error.
        assert!(
            VERIFICATION_REQUIRED_MESSAGE
                .to_lowercase()
                .contains("verify"),
            "the refusal message must name verification"
        );
    }

    #[test]
    fn a_back_path_that_already_has_a_query_appends_the_toast() {
        // `?status=suspended` etc. must keep their query and gain the toast with
        // `&`, not a second `?`.
        let user = admin(false, Some("Ada"), Some("Lovelace"));
        let refusal =
            verification_gate(&user, &ctx(), "/admin/users?status=suspended").expect("refused");
        let location = refusal
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            location.starts_with("/admin/users?status=suspended&toast_err="),
            "existing query must be preserved with `&`: {location}"
        );
    }

    /// The bunyip-web admin handler sources, with the set of gated action
    /// functions in each. Every listed function MUST refuse an unverified admin
    /// by calling `verification_gate`; the scan below fails the build if one
    /// stops doing so, which is exactly how the BUNYIP-401 carve-out silently
    /// dropped the requirement from every action at once.
    const GATED_ACTIONS: &[(&str, &str, &[&str])] = &[
        (
            "bunyip-web/src/handlers/admin/users.rs",
            include_str!("admin/users.rs"),
            &[
                "user_role",
                "user_delete",
                "user_suspend",
                "user_reactivate",
                "user_reset_password",
                "user_email",
                "user_verify_email",
                "user_reset_2fa",
                "user_grant_lifetime",
                "user_revoke_lifetime",
                "user_set_tier",
            ],
        ),
        (
            "bunyip-web/src/handlers/admin/memberships.rs",
            include_str!("admin/memberships.rs"),
            &["membership_grant", "membership_revoke"],
        ),
        (
            "bunyip-web/src/handlers/admin/entitlements.rs",
            include_str!("admin/entitlements.rs"),
            &["grant_user_entitlement_h", "revoke_user_entitlement_h"],
        ),
        (
            "bunyip-web/src/handlers/admin/feedback.rs",
            include_str!("admin/feedback.rs"),
            &["feedback_respond"],
        ),
    ];

    /// The escape-hatch handlers an unverified admin MUST still be able to run,
    /// so a mail-less deployment can repair SMTP and the admin can then verify
    /// (BUNYIP-401). The scan asserts none of them gates, so the hatch cannot be
    /// closed by a future edit that gates too broadly.
    const ESCAPE_HATCH_ACTIONS: &[(&str, &str, &[&str])] = &[
        (
            "bunyip-web/src/handlers/admin/email_config.rs",
            include_str!("admin/email_config.rs"),
            &["email_save", "email_test", "email_test_send"],
        ),
        (
            "bunyip-web/src/handlers/admin/system_config.rs",
            include_str!("admin/system_config.rs"),
            &["system_config_save"],
        ),
    ];

    /// Return the source slice of the `async fn {name}` body: from its signature
    /// to the next top-level item, so a "contains" check cannot leak into the
    /// next function.
    fn fn_body<'a>(source: &'a str, name: &str) -> &'a str {
        let needle = format!("async fn {name}(");
        let start = source
            .find(&needle)
            .unwrap_or_else(|| panic!("async fn {name} not found in source"));
        let rest = &source[start..];
        let end = [
            "\npub async fn ",
            "\npub fn ",
            "\npub(super) fn ",
            "\nasync fn ",
            "\nfn ",
        ]
        .iter()
        // Skip the signature we start on (offset 0) by searching past it.
        .filter_map(|m| rest[1..].find(m).map(|i| i + 1))
        .min()
        .unwrap_or(rest.len());
        &rest[..end]
    }

    #[test]
    fn every_gated_admin_action_calls_the_verification_gate() {
        for (path, source, actions) in GATED_ACTIONS {
            for name in *actions {
                assert!(
                    fn_body(source, name).contains("verification_gate("),
                    "{path}: {name} is a verification-gated action but does not call \
                     verification_gate, so an unverified admin could still run it (BUNYIP-619)"
                );
            }
        }
    }

    #[test]
    fn the_escape_hatch_actions_never_gate() {
        for (path, source, actions) in ESCAPE_HATCH_ACTIONS {
            for name in *actions {
                assert!(
                    !fn_body(source, name).contains("verification_gate("),
                    "{path}: {name} must NOT call verification_gate - an unverified admin \
                     needs it to repair mail and then verify, or BUNYIP-401 reopens"
                );
            }
        }
    }
}
