//! Auth-flow handlers. Login + logout here for the slice; the rest of the
//! auth/public pages arrive in phase 2.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::auth::{self as auth_api, LoginOutcome};
use crate::config::Config;
use crate::handlers::{auth_page, cookie_of, cookie_value, ctx, dashboard_input, password_ok};
use crate::views::common::{auth_card, auth_card_plain};
use crate::views::layout::{document, public_shell};

/// BUNYIP-487: whether the header and footer should carry a Pricing link. The
/// auth cards render the public shell directly (they need to attach their own
/// cookies), so they resolve the flag themselves rather than through
/// `public_ctx`. A failed fetch hides the link, never offers a dead one.
///
/// BUNYIP-555: through the shared TTL cache, like `public_ctx`. These pages are
/// public renders too, so an uncached fetch here reopened the amplification
/// BUNYIP-518 closed, and it swallowed the error into "unpublished" with nothing
/// logged; the cache logs the failure and serves the last good payload.
async fn pricing_published(st: &AppState) -> bool {
    st.pricing().await.published()
}

/// BUNYIP-255: 2FA challenge-token TTL aligned with the JWT exp set in
/// `crates/bunyip-domain/src/services/jwt.rs::create_2fa_challenge_token`.
/// Stays under that exp so the cookie never outlives the token it carries.
const BUNYIP_2FA_COOKIE_MAX_AGE_SECS: u64 = 600;

/// BUNYIP-255: emit the `bunyip_2fa` cookie via a single helper so the
/// `Secure` / `HttpOnly` / `SameSite` / `Max-Age` attributes can be set
/// consistently. The previous raw-string emit (`bunyip_2fa=...; Path=/;
/// HttpOnly; SameSite=Lax`) missed `Secure` (HTTPS-only on production)
/// and `Max-Age` (the cookie outlived the challenge token).
fn bunyip_2fa_cookie_set(cfg: &Config, challenge_token: &str) -> String {
    let secure = if cfg.use_secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    format!(
        "bunyip_2fa={challenge_token}; Path=/; HttpOnly; SameSite=Lax{secure}; Max-Age={}",
        BUNYIP_2FA_COOKIE_MAX_AGE_SECS
    )
}

/// BUNYIP-255: matching clear for the `bunyip_2fa` cookie. The clear
/// MUST share the original cookie's `HttpOnly` / `Secure` / `SameSite`
/// attributes or browsers may decide the clear is for a different
/// cookie and leave the live one in the jar.
fn bunyip_2fa_cookie_clear(cfg: &Config) -> String {
    let secure = if cfg.use_secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    format!("bunyip_2fa=; Path=/; HttpOnly; SameSite=Lax{secure}; Max-Age=0")
}

/// BUNYIP-323: defense-in-depth clearing cookies emitted by bunyip-web's
/// own `/logout` handler, independent of whatever bunyip-api returns.
/// bunyip-api is meant to emit these too (POST /v1/auth/logout was widened
/// in the same ticket so it clears cookies even when the access_token is
/// stale), but bunyip-web must also guarantee cookie clearing when the API
/// is unreachable / errors out / returns an unexpected shape - the user's
/// intent is "log me out", and clearing local cookies is what makes that
/// visible in the browser.
///
/// Emits BOTH the host-only clear (matches a stale hostname-scoped cookie
/// from a pre-COOKIE_DOMAIN deploy) and the domain-scoped clear (matches
/// the currently-set cookie), mirroring `AuthCookies::clear`'s two-axis
/// pattern in `crates/bunyip-domain/src/middleware/auth.rs`. Only issue
/// domain-scoped clears when the BFF is configured with a cookie domain.
fn bunyip_auth_cookie_clears(cfg: &Config) -> Vec<String> {
    let secure = if cfg.use_secure_cookies() {
        "; Secure"
    } else {
        ""
    };
    // The three names must match what bunyip-api sets on login:
    // access_token, refresh_token, and the OP session cookie.
    const NAMES: [&str; 3] = ["access_token", "refresh_token", "bunyip_op_session"];
    let mut out: Vec<String> = Vec::with_capacity(NAMES.len() * 2);
    for name in NAMES {
        // Host-only clear (no Domain attribute) - kills a cookie set before
        // BUNYIP_COOKIE_SHARED_DOMAIN was configured.
        out.push(format!(
            "{name}=; Path=/; HttpOnly; SameSite=Lax{secure}; Max-Age=0"
        ));
    }
    if !cfg.app_domain.is_empty() {
        let domain = cfg.app_domain.as_str();
        for name in NAMES {
            // Domain-scoped clear - matches a cookie set on the shared apex
            // domain (bunyip-api's `AuthCookies::clear` emits these when
            // COOKIE_DOMAIN is configured). Uses the bare apex here; the
            // browser matches its own cookie regardless of whether it was
            // stored with or without the leading dot.
            out.push(format!(
                "{name}=; Path=/; Domain={domain}; HttpOnly; SameSite=Lax{secure}; Max-Age=0"
            ));
        }
    }
    out
}
use crate::views::ui::{back_link, button_class, error_box, icon};
use crate::web::{html, html_cookies, redirect, redirect_cookies, AppState};

fn field(id: &str, label: &str, ty: &str, placeholder: &str, autocomplete: &str) -> Markup {
    field_with_value(id, label, ty, placeholder, autocomplete, "", false)
}

/// BUNYIP-486: `field` for the FIRST editable field of a single-purpose auth
/// card, which takes keyboard focus on load so the user can type without
/// tabbing past the site nav. Native `autofocus`, so it works with JS off.
/// Only ever one per rendered page.
fn field_autofocus(
    id: &str,
    label: &str,
    ty: &str,
    placeholder: &str,
    autocomplete: &str,
) -> Markup {
    field_with_value(id, label, ty, placeholder, autocomplete, "", true)
}

/// BUNYIP-240: like `field`, but preserves a pre-filled `value` across
/// server re-renders so an error-rejected password / email doesn't blank
/// out. For password fields the browser's autocomplete also recovers the
/// value, but only if the user is not typing into a fresh field; the
/// explicit `value=` is the durable path.
fn field_with_value(
    id: &str,
    label: &str,
    ty: &str,
    placeholder: &str,
    autocomplete: &str,
    value: &str,
    autofocus: bool,
) -> Markup {
    html! {
        div class="space-y-2" {
            label for=(id) class="text-sm font-medium leading-none" { (label) }
            input id=(id) name=(id) type=(ty) placeholder=(placeholder) autocomplete=(autocomplete) value=(value) autofocus[autofocus] class=(dashboard_input());
        }
    }
}

fn submit_btn(label: &str) -> Markup {
    html! { button type="submit" class=(button_class("default", "default", "w-full")) { (label) } }
}

/// BUNYIP-554: both eye states, pre-rendered. `input.css` shows exactly one per
/// the button's `aria-pressed`, so `assets/js/password.js` never builds markup -
/// SVG generation stays in Rust and the script only flips the ARIA state.
fn pw_toggle_glyphs() -> Markup {
    html! {
        span data-pw-icon="eye" aria-hidden="true" { (icon("eye", "h-4 w-4")) }
        span data-pw-icon="eye-off" aria-hidden="true" { (icon("eye-off", "h-4 w-4")) }
    }
}

/// BUNYIP-554: the three indicator states of a `pw_reqs()` row, pre-rendered.
/// `input.css` reveals the one matching the row's `pw-pending` / `pw-pass` /
/// `pw-fail` class, so the script flips a class instead of writing markup.
fn pw_state_glyphs() -> Markup {
    html! {
        span class="pw-indicator inline-flex justify-center w-4" aria-hidden="true" {
            span data-pw-state="pending" { (icon("circle", "h-3.5 w-3.5")) }
            span data-pw-state="pass" { (icon("circle-check", "h-3.5 w-3.5")) }
            span data-pw-state="fail" { (icon("circle-x", "h-3.5 w-3.5")) }
        }
    }
}

/// BUNYIP-282: password input with an inline show/hide eye toggle.
/// Default state is hidden (`type=password`, eye glyph, `aria-pressed=false`,
/// `aria-label="Show password"`); `assets/js/password.js` flips
/// `type`, `aria-pressed` and `aria-label` on click, and the CSS in
/// `pw_toggle_glyphs()` swaps which glyph is visible. The `pr-10` padding
/// on the input keeps the typed text from running under the button. Scoped
/// strictly to the signup card; login / reset / change-password fields keep
/// using `field()`.
fn password_field(id: &str, label: &str, autocomplete: &str) -> Markup {
    let input_class = format!("{} pr-10", dashboard_input());
    html! {
        div class="space-y-2" {
            label for=(id) class="text-sm font-medium leading-none" { (label) }
            div class="relative" {
                input id=(id) name=(id) type="password" autocomplete=(autocomplete) class=(input_class);
                button type="button"
                    data-pw-toggle=(id)
                    aria-label="Show password"
                    aria-pressed="false"
                    class="absolute right-2 top-1/2 -translate-y-1/2 inline-flex items-center justify-center w-7 h-7 rounded text-muted-foreground hover:text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring" {
                    (pw_toggle_glyphs())
                }
            }
        }
    }
}

/// BUNYIP-240: per-requirement password indicators. Each `<li>` carries a
/// stable id so `assets/js/password.js` can
/// flip its leading indicator between three states: `pw-pending` (neutral
/// circle while the user has not satisfied this rule yet), `pw-pass` (green
/// check), `pw-fail` (red x). The fourth indicator (`pw-breach`) is
/// driven by the HaveIBeenPwned k-anonymity lookup: only the first 5 chars
/// of the SHA-1 hash ever leave the browser, so the actual password never
/// crosses any wire to HIBP or to bunyip.
///
/// BUNYIP-250: the breach row uses a `.pw-label` span (rather than a bare
/// text node) so the script can swap the wording on fail to
/// "Found in a known data breach. Pick a different password." - the
/// previous static "Not found ..." label paired with a ✗ glyph read as
/// the validator being broken. A `<p id="pw-breach-help">` is rendered
/// hidden and revealed on fail so the user has a one-line path forward.
fn pw_reqs() -> Markup {
    html! {
        ul id="pw-reqs" class="text-sm text-muted-foreground space-y-1.5 mt-2" {
            li id="pw-len" class="pw-pending flex items-center gap-2" {
                (pw_state_glyphs())
                span class="pw-label" { "At least 12 characters" }
            }
            li id="pw-case" class="pw-pending flex items-center gap-2" {
                (pw_state_glyphs())
                span class="pw-label" { "Upper and lowercase letters" }
            }
            li id="pw-digit" class="pw-pending flex items-center gap-2" {
                (pw_state_glyphs())
                span class="pw-label" { "At least one digit and one special character" }
            }
            li id="pw-breach" class="pw-pending flex items-center gap-2"
                data-label-pass="Not found in a known data breach"
                data-label-fail="Found in a known data breach. Pick a different password."
                data-label-pending="Not found in a known data breach" {
                (pw_state_glyphs())
                span class="pw-label" { "Not found in a known data breach" }
            }
        }
        // Surfaced only when the breach row is in `pw-fail`. Hidden by
        // default; `assets/js/password.js` toggles `hidden` per state.
        p id="pw-breach-help" class="text-xs text-destructive-text mt-1.5 ml-6" hidden {
            "HaveIBeenPwned has seen this password in a public breach. Even strong passwords are unsafe once leaked - pick a fresh one."
        }
        // Sub-input for confirm-password match feedback; toggled by the same
        // script. Empty until the user types into the Confirm field.
        p id="pw-confirm-msg" class="text-sm mt-2 pw-pending" {}
    }
}

/// BUNYIP-240 / BUNYIP-282: the password UX script (per-rule indicators, the
/// HaveIBeenPwned breach check, and the show/hide eye toggle). BUNYIP-424: the
/// code lives in `assets/js/password.js` and is loaded from `'self'`, so
/// bunyip-web's CSP no longer needs `script-src 'unsafe-inline'`.
fn password_script() -> Markup {
    html! { script src=(crate::views::layout::asset("/assets/js/password.js")) defer {} }
}

/// Validate and normalise a post-login redirect target.
///
/// Accepts two shapes:
/// - Relative paths starting with `/` (but not `//`, which would be a
///   protocol-relative URL and could escape the BFF host).
/// - Absolute URLs whose origin equals `oidc_issuer` (bunyip-api's host).
///   This is what lets the `/oauth2/authorize` -> `/login` -> `/oauth2/authorize`
///   round-trip complete: bunyip-api passes the full authorize URL in
///   `?redirect=`, bunyip-web logs the user in, then bounces them back.
///
/// Anything else (other hostnames, schemes, javascript:, etc.) falls back to
/// `/dashboard` so a malicious `?redirect=` can't be weaponised.
fn safe_redirect(raw: Option<&str>, oidc_issuer: &str) -> String {
    const FALLBACK: &str = "/dashboard";
    let Some(r) = raw else {
        return FALLBACK.into();
    };
    if r.starts_with('/') && !r.starts_with("//") {
        return r.to_string();
    }
    // Match by exact origin prefix. The issuer is normalised to its origin
    // (scheme + host + optional port, no trailing slash); the redirect must
    // start with `{issuer}/` so a path on the same origin always follows.
    // No `url` crate dep is needed for this check.
    let issuer = oidc_issuer.trim_end_matches('/');
    if !issuer.is_empty() && (r == issuer || r.starts_with(&format!("{issuer}/"))) {
        return r.to_string();
    }
    FALLBACK.into()
}

#[derive(Deserialize)]
pub struct RedirectQuery {
    pub redirect: Option<String>,
    /// Set by `/oauth2/authorize` when it bounced the user here because it
    /// found no valid OP session. Its presence means "the IdP already checked
    /// and there is no server-side session", so `login_get` must NOT trust a
    /// surviving hub session and redirect back to `authorize` (that is the
    /// redirect loop). It renders the login form instead, forcing a
    /// credentialed re-login that mints a fresh OP session.
    #[serde(default)]
    pub checked: Option<String>,
}

fn login_content(error: Option<&str>, redirect: &str) -> Markup {
    // Login's header is title + subtitle only (no icon bubble), so it routes
    // through `auth_card_plain` instead of re-implementing the card shell
    // (BUNYIP-467 F14).
    let body = html! {
        form method="post" action="/login" class="space-y-4" {
            input type="hidden" name="redirect" value=(redirect);
            @if let Some(e) = error { (error_box(e)) }
            div class="space-y-2" {
                label for="email" class="text-sm font-medium leading-none" { "Email" }
                // BUNYIP-486: first editable field of the card takes focus on load.
                input id="email" name="email" type="email" placeholder="you@example.com" autocomplete="email"
                    autofocus class=(dashboard_input());
            }
            div class="space-y-2" {
                div class="flex items-center justify-between" {
                    label for="password" class="text-sm font-medium leading-none" { "Password" }
                    a href="/password-reset" class="text-sm text-primary-text hover:underline" { "Forgot password?" }
                }
                input id="password" name="password" type="password" autocomplete="current-password"
                    class=(dashboard_input());
            }
            div class="flex items-center space-x-2" {
                input id="remember" name="remember" type="checkbox" value="on" class="h-4 w-4 rounded border-border";
                label for="remember" class="text-sm font-normal cursor-pointer" { "Remember me for 30 days" }
            }
            button type="submit" class=(button_class("default", "default", "w-full")) { "Sign in" }
        }
        div class="mt-6" {
            div class="relative" {
                div class="absolute inset-0 flex items-center" { span class="w-full border-t" {} }
                div class="relative flex justify-center text-xs uppercase" {
                    span class="bg-background px-2 text-muted-foreground" { "Or continue with" }
                }
            }
            a href="/magic-link" class=(button_class("outline", "default", "mt-4 w-full")) { "Sign in with Magic Link" }
        }
        p class="mt-6 text-center text-sm text-muted-foreground" {
            "Don't have an account? "
            a href="/register" class="text-primary-text hover:underline" { "Sign up" }
        }
    };
    auth_card_plain("Welcome back", "Sign in to your account to continue", body)
}

pub async fn login_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RedirectQuery>,
) -> Response {
    let (c, _fwd) = ctx(&st, &headers).await;
    // `checked` is set only when `/oauth2/authorize` redirected here after
    // finding no valid OP session. In that case a hub session can still look
    // "signed in" (the 30-day refresh cookie outlives the 7-day OP session),
    // but redirecting back to `authorize` would loop forever. Fall through to
    // the login form so the POST re-establishes the OP session.
    if c.is_signed_in() && q.checked.is_none() {
        // Relay any cookie `authenticate()` refreshed (a rotated session JWT)
        // so the already-signed-in bounce doesn't drop it.
        return redirect_cookies(
            &safe_redirect(q.redirect.as_deref(), &st.cfg.oidc_issuer),
            &c.set_cookies,
        );
    }
    // BUNYIP-555: the two chrome payloads come from the shared TTL caches and
    // are fetched concurrently on a miss; neither consumes the other's result.
    let (apps, pricing) = tokio::join!(st.public_applications(), pricing_published(&st));
    let content = login_content(None, q.redirect.as_deref().unwrap_or("/dashboard"));
    let body = public_shell(&st.cfg, None, &apps, pricing, false, content);
    html(document("Sign in", body))
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
    pub remember: Option<String>,
    pub redirect: Option<String>,
}

pub async fn login_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<LoginForm>,
) -> Response {
    let cookie = cookie_of(&headers);
    let remember = f.remember.is_some();
    let target = safe_redirect(f.redirect.as_deref(), &st.cfg.oidc_issuer);

    match auth_api::login(
        &st.api,
        cookie.as_deref(),
        f.email.trim(),
        &f.password,
        remember,
    )
    .await
    {
        Ok((LoginOutcome::SignedIn(_), cookies)) => redirect_cookies(&target, &cookies),
        Ok((LoginOutcome::TwoFactorRequired { challenge_token }, mut cookies)) => {
            cookies.push(bunyip_2fa_cookie_set(&st.cfg, &challenge_token));
            // Carry the original ?redirect= forward so the OIDC return-URL
            // survives the 2FA step.
            let path = match f.redirect.as_deref().filter(|s| !s.is_empty()) {
                Some(r) => format!("/login/2fa?redirect={}", urlencoding::encode(r)),
                None => "/login/2fa".to_string(),
            };
            redirect_cookies(&path, &cookies)
        }
        Err(e) => {
            let (apps, pricing) = tokio::join!(st.public_applications(), pricing_published(&st));
            let content = login_content(Some(&e.user_message()), &target);
            let body = public_shell(&st.cfg, None, &apps, pricing, false, content);
            html(document("Sign in", body))
        }
    }
}

pub async fn logout(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RedirectQuery>,
) -> Response {
    let cookie = cookie_of(&headers);
    // BUNYIP-323: use the bunyip-api response's clearing cookies when it
    // returns them (the common case, and the one that lets the API also
    // revoke the refresh token + fan out OIDC back-channel logouts). But
    // do NOT depend on it: an unreachable / errored API used to leave the
    // browser signed in because bunyip-web emitted no clears of its own.
    // Merge in a local defensive clear set unconditionally so `Set-Cookie`
    // headers reach the browser even when the API call failed entirely.
    let mut cleared = auth_api::logout(&st.api, cookie.as_deref())
        .await
        .unwrap_or_default();
    for defensive in bunyip_auth_cookie_clears(&st.cfg) {
        cleared.push(defensive);
    }
    // Also drop any pending-2FA cookie.
    cleared.push(bunyip_2fa_cookie_clear(&st.cfg));
    // Logout lands on the public homepage by default: a user who
    // clicked "Logout" wanted to be done, not be shown another login
    // form. Callers that DO want the post-logout login-then-redirect
    // chain (e.g. session-timeout banners) can still pass ?redirect=
    // and bunyip routes them to /login with that path as the next
    // destination.
    let target = match q.redirect {
        Some(r) if r.starts_with('/') && !r.starts_with("//") => format!("/login?redirect={r}"),
        _ => "/".to_string(),
    };
    redirect_cookies(&target, &cleared)
}

// ===========================================================================
// Register
// ===========================================================================

#[derive(Deserialize)]
pub struct RegisterForm {
    pub email: String,
    pub password: String,
    pub confirm: String,
    /// BUNYIP-377: honeypot - a hidden field a human leaves empty.
    #[serde(default)]
    pub contact_channel: String,
    /// BUNYIP-377: the signup timing-challenge token the form was rendered with.
    #[serde(default)]
    pub signup_token: String,
}

/// BUNYIP-271: per-field registration errors. On a rejected submit the server
/// re-renders the form with each failing rule attached to the specific input
/// it governs (email / password / confirm) instead of collapsing everything
/// into one generic banner. `general` carries an error that is not attributable
/// to a single field (e.g. an API failure), and still renders as a top banner.
#[derive(Default)]
struct RegisterErrors {
    email: Option<String>,
    password: Option<String>,
    confirm: Option<String>,
    general: Option<String>,
}

impl RegisterErrors {
    /// True when at least one error is present, i.e. this is an error
    /// re-render. Drives the "please re-enter your password" hint, because on
    /// any rejected submit the password fields come back blank (never echoed).
    fn any(&self) -> bool {
        self.email.is_some()
            || self.password.is_some()
            || self.confirm.is_some()
            || self.general.is_some()
    }
}

/// BUNYIP-271: an inline, field-level error rendered directly beneath the
/// offending input so the user sees which specific rule failed, rather than a
/// single generic banner at the top of the form.
fn field_error_msg(msg: &str) -> Markup {
    html! {
        p class="text-sm text-destructive-text mt-1" role="alert" { (msg) }
    }
}

/// BUNYIP-271: passwords are never echoed back into the HTML (see the note in
/// `register_card`), so on a rejected submit both password fields come back
/// blank. Tell the user why they are empty and that a re-entry is needed.
fn password_reentry_hint() -> Markup {
    html! {
        p class="text-sm text-muted-foreground mt-1" {
            "For your security your password is never stored - please re-enter your password."
        }
    }
}

fn register_card(errors: &RegisterErrors, email: &str, signup_token: &str) -> Markup {
    auth_card(
        "shield",
        "bg-primary/10 text-primary-text",
        "Create your account",
        "Get access to all tools for $3/month",
        html! {
            form method="post" action="/register" class="space-y-4" {
                // BUNYIP-271: the top banner is reserved for a non-field error
                // (e.g. an API failure). Rule-specific messages render next to
                // their input below via `field_error_msg`.
                @if let Some(e) = errors.general.as_deref() { (error_box(e)) }
                // BUNYIP-377: honeypot - off-screen, aria-hidden, not tabbable,
                // autocomplete off, so it is invisible to humans; a bot that
                // fills every field trips the server-side guard. Inline style is
                // permitted by bunyip-web's CSP (style-src 'unsafe-inline').
                input type="text" name="contact_channel" value="" tabindex="-1"
                    autocomplete="off" aria-hidden="true"
                    style="position:absolute;left:-9999px;width:1px;height:1px;opacity:0;";
                // BUNYIP-377: signed submit-timing token issued at form render.
                input type="hidden" name="signup_token" value=(signup_token);
                // BUNYIP-240: preserve the typed email on server-side rejection
                // so the user does not have to retype it. The password fields
                // intentionally stay blank for re-entry (no value= for type=password
                // - browsers refuse to render persisted password values for
                // autofill safety, and re-rendering with a server-known password
                // would round-trip plaintext through HTML history).
                div {
                    (field_with_value("email", "Email", "email", "you@example.com", "email", email, true))
                    // BUNYIP-271: surface an invalid-email rule next to the input.
                    @if let Some(e) = errors.email.as_deref() { (field_error_msg(e)) }
                }
                // BUNYIP-282: signup uses the password_field helper so each
                // input carries an inline eye toggle. Other auth surfaces
                // (login, reset, change-password) deliberately stay on the
                // plain `field` helper - reveal toggles are sign-up only.
                div {
                    (password_field("password", "Password", "new-password"))
                    @if let Some(e) = errors.password.as_deref() { (field_error_msg(e)) }
                    // BUNYIP-271: on any rejected submit the cleared password
                    // fields need re-entry; say so explicitly.
                    @if errors.any() { (password_reentry_hint()) }
                }
                (pw_reqs())
                div {
                    (password_field("confirm", "Confirm Password", "new-password"))
                    // BUNYIP-271: surface a passwords-don't-match rule inline.
                    @if let Some(e) = errors.confirm.as_deref() { (field_error_msg(e)) }
                }
                (submit_btn("Sign up"))
            }
            div class="mt-6" {
                a href="/magic-link" class=(button_class("outline", "default", "w-full")) { "Sign up with Magic Link" }
            }
            p class="mt-6 text-center text-sm text-muted-foreground" {
                "Already have an account? " a href="/login" class="text-primary-text hover:underline" { "Sign in" }
            }
            p class="mt-4 text-center text-xs text-muted-foreground" {
                "By creating an account, you agree to our "
                a href="/terms" class="underline hover:text-foreground" { "Terms of Service" } " and "
                a href="/privacy" class="underline hover:text-foreground" { "Privacy Policy" } "."
            }
            // BUNYIP-240 live per-rule feedback + HIBP breach check, and the
            // BUNYIP-282 eye toggle on every `[data-pw-toggle]` button rendered
            // by `password_field` above.
            (password_script())
        },
    )
}

pub async fn register_get(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, _) = ctx(&st, &headers).await;
    if c.is_signed_in() {
        // Relay any refreshed session cookie on the already-signed-in bounce.
        return redirect_cookies("/dashboard", &c.set_cookies);
    }
    // BUNYIP-377: mint a fresh submit-timing token to embed in the form.
    let signup_token = auth_api::register_challenge(&st.api)
        .await
        .unwrap_or_default();
    auth_page(
        &st,
        &headers,
        "Sign up",
        register_card(&RegisterErrors::default(), "", &signup_token),
    )
    .await
}

pub async fn register_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<RegisterForm>,
) -> Response {
    // BUNYIP-271: attribute each failing rule to the field it governs so the
    // re-rendered form shows the message next to the offending input. All
    // failing rules surface at once (not just the first), and the typed email
    // is preserved; the password fields intentionally stay blank for re-entry.
    let mut errs = RegisterErrors::default();
    if !f.email.contains('@') {
        errs.email = Some("Enter a valid email address.".to_string());
    }
    if !password_ok(&f.password) {
        errs.password = Some("Password does not meet the requirements below.".to_string());
    } else if f.password != f.confirm {
        // Only meaningful once the password itself is valid; otherwise the
        // password rule already tells the user what to fix.
        errs.confirm = Some("Passwords don't match.".to_string());
    }
    if errs.any() {
        return auth_page(
            &st,
            &headers,
            "Sign up",
            register_card(&errs, f.email.trim(), &f.signup_token),
        )
        .await;
    }
    match auth_api::register(
        &st.api,
        f.email.trim(),
        &f.password,
        &f.contact_channel,
        &f.signup_token,
    )
    .await
    {
        // BUNYIP-206: a new user lands on /onboarding (name + email verification)
        // before any app surface. The `guard()` gate enforces this for every
        // other entry path; sending them straight here avoids the extra hop.
        Ok((_, cookies)) => redirect_cookies("/onboarding", &cookies),
        Err(e) => {
            // BUNYIP-271: an API-side rejection is not reliably attributable to
            // a single field (already-registered, rate limit, transient 5xx),
            // so it renders as the top banner while the email stays preserved.
            let errs = RegisterErrors {
                general: Some(e.user_message()),
                ..Default::default()
            };
            auth_page(
                &st,
                &headers,
                "Sign up",
                register_card(&errs, f.email.trim(), &f.signup_token),
            )
            .await
        }
    }
}

// ===========================================================================
// Magic link
// ===========================================================================

#[derive(Deserialize)]
pub struct TokenQuery {
    pub token: Option<String>,
}

#[derive(Deserialize)]
pub struct EmailForm {
    pub email: String,
}

fn magic_form(error: Option<&str>, success: bool) -> Markup {
    if success {
        return auth_card(
            "check-circle",
            "bg-teal-500/10 text-teal-600 dark:text-teal-400",
            "Check your email",
            "We've sent a magic link to your email address.",
            html! {
                p class="text-center text-sm text-muted-foreground" { "The link will expire in 15 minutes." }
                a href="/login" class=(button_class("outline", "default", "mt-6 w-full")) { "Back to sign in" }
            },
        );
    }
    auth_card(
        "mail",
        "bg-primary/10 text-primary-text",
        "Sign in with Magic Link",
        "We'll email you a link to sign in - no password needed.",
        html! {
            form method="post" action="/magic-link" class="space-y-4" {
                @if let Some(e) = error { (error_box(e)) }
                (field_autofocus("email", "Email", "email", "you@example.com", "email"))
                (submit_btn("Send Magic Link"))
            }
            p class="mt-6 text-center text-sm text-muted-foreground" {
                a href="/login" class="text-primary-text hover:underline" { "Sign in with password" } " · "
                a href="/register" class="text-primary-text hover:underline" { "Sign up" }
            }
        },
    )
}

pub async fn magic_link_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> Response {
    if let Some(token) = q.token {
        return match auth_api::verify_magic_link(&st.api, &token).await {
            Ok((LoginOutcome::SignedIn(_), cookies)) => redirect_cookies("/dashboard", &cookies),
            Ok((LoginOutcome::TwoFactorRequired { challenge_token }, mut cookies)) => {
                cookies.push(bunyip_2fa_cookie_set(&st.cfg, &challenge_token));
                redirect_cookies("/login/2fa", &cookies)
            }
            Err(e) => {
                let card = auth_card(
                    "alert-circle",
                    "bg-destructive/10 text-destructive-text",
                    "Verification Failed",
                    &e.user_message(),
                    html! {
                        a href="/magic-link" class=(button_class("default", "default", "w-full")) { "Request New Magic Link" }
                    },
                );
                auth_page(&st, &headers, "Magic link", card).await
            }
        };
    }
    auth_page(&st, &headers, "Magic link", magic_form(None, false)).await
}

pub async fn magic_link_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<EmailForm>,
) -> Response {
    let card = match auth_api::request_magic_link(&st.api, f.email.trim()).await {
        Ok(()) => magic_form(None, true),
        Err(e) => magic_form(Some(&e.user_message()), false),
    };
    auth_page(&st, &headers, "Magic link", card).await
}

// ===========================================================================
// Password reset
// ===========================================================================

fn reset_form(error: Option<&str>, success: bool) -> Markup {
    if success {
        return auth_card(
            "check-circle",
            "bg-teal-500/10 text-teal-600 dark:text-teal-400",
            "Check your email",
            "If an account exists with that email, we've sent reset instructions.",
            html! {
                p class="text-center text-sm text-muted-foreground" { "The link will expire in 1 hour." }
                a href="/login" class=(button_class("outline", "default", "mt-6 w-full")) { "Back to sign in" }
            },
        );
    }
    auth_card(
        "key",
        "bg-primary/10 text-primary-text",
        "Reset your password",
        "Enter your email and we'll send you a reset link.",
        html! {
            form method="post" action="/password-reset" class="space-y-4" {
                @if let Some(e) = error { (error_box(e)) }
                (field_autofocus("email", "Email", "email", "you@example.com", "email"))
                (submit_btn("Send Reset Link"))
            }
            p class="mt-6 text-center text-sm text-muted-foreground" {
                "Remember your password? " a href="/login" class="text-primary-text hover:underline" { "Sign in" }
            }
        },
    )
}

pub async fn password_reset_get(State(st): State<AppState>, headers: HeaderMap) -> Response {
    auth_page(&st, &headers, "Reset password", reset_form(None, false)).await
}

pub async fn password_reset_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<EmailForm>,
) -> Response {
    let card = match auth_api::request_password_reset(&st.api, f.email.trim()).await {
        Ok(()) => reset_form(None, true),
        Err(e) => reset_form(Some(&e.user_message()), false),
    };
    auth_page(&st, &headers, "Reset password", card).await
}

// ===========================================================================
// Password reset confirm
// ===========================================================================

#[derive(Deserialize)]
pub struct ResetConfirmForm {
    pub token: String,
    pub password: String,
    pub confirm: String,
}

fn reset_confirm_card(token: &str, error: Option<&str>) -> Markup {
    auth_card(
        "key",
        "bg-primary/10 text-primary-text",
        "Set new password",
        "Choose a strong password for your account.",
        html! {
            form method="post" action="/password-reset/confirm" class="space-y-4" {
                input type="hidden" name="token" value=(token);
                @if let Some(e) = error { (error_box(e)) }
                (field_autofocus("password", "New Password", "password", "", "new-password"))
                (pw_reqs())
                (field("confirm", "Confirm Password", "password", "", "new-password"))
                (submit_btn("Reset Password"))
            }
            // BUNYIP-240: same live-feedback script as /register. The
            // pw_reqs() rows + the script's id-based binding are identical
            // across the two forms, so the script is reusable as-is.
            (password_script())
        },
    )
}

pub async fn password_reset_confirm_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> Response {
    match q.token {
        Some(token) => {
            auth_page(
                &st,
                &headers,
                "Reset password",
                reset_confirm_card(&token, None),
            )
            .await
        }
        None => {
            let card = auth_card(
                "alert-circle",
                "bg-destructive/10 text-destructive-text",
                "Invalid Reset Link",
                "This password reset link is invalid or has expired.",
                html! {
                    a href="/password-reset" class=(button_class("default", "default", "w-full")) { "Request New Reset Link" }
                },
            );
            auth_page(&st, &headers, "Reset password", card).await
        }
    }
}

pub async fn password_reset_confirm_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<ResetConfirmForm>,
) -> Response {
    let err = if !password_ok(&f.password) {
        Some("Password does not meet the requirements".to_string())
    } else if f.password != f.confirm {
        Some("Passwords don't match".to_string())
    } else {
        None
    };
    if let Some(e) = err {
        return auth_page(
            &st,
            &headers,
            "Reset password",
            reset_confirm_card(&f.token, Some(&e)),
        )
        .await;
    }
    match auth_api::confirm_password_reset(&st.api, &f.token, &f.password).await {
        Ok(()) => redirect("/login"),
        Err(e) => {
            auth_page(
                &st,
                &headers,
                "Reset password",
                reset_confirm_card(&f.token, Some(&e.user_message())),
            )
            .await
        }
    }
}

// ===========================================================================
// 2FA verify (after login/magic-link)
// ===========================================================================

#[derive(Deserialize)]
pub struct TwoFactorForm {
    pub code: String,
    pub redirect: Option<String>,
}

fn twofa_card(error: Option<&str>, redirect: Option<&str>) -> Markup {
    let redirect = redirect.unwrap_or_default();
    auth_card(
        "shield",
        "bg-primary/10 text-primary-text",
        "Two-Factor Authentication",
        "Enter the 6-digit code from your authenticator app",
        html! {
            form method="post" action="/login/2fa" class="space-y-4" {
                @if !redirect.is_empty() {
                    input type="hidden" name="redirect" value=(redirect);
                }
                @if let Some(e) = error { (error_box(e)) }
                // BUNYIP-382: the "trust this device for 30 days" opt-in was
                // removed here and merged into the sign-in "Remember me" choice,
                // which now drives both session length and device trust.
                div class="space-y-2" {
                    label for="code" class="text-sm font-medium leading-none" { "Authentication Code" }
                    // BUNYIP-117: maxlength + pattern so the browser bounds
                    // and format-checks the 6-digit TOTP before submit.
                    // Authoritative validation still happens in the domain
                    // (services::totp::verify_code). BUNYIP-331:
                    // data-otp-autosubmit submits the form once the code is
                    // a complete six digits (typed / pasted / autofilled).
                    // BUNYIP-486: autofocus so the whole screen is "type six
                    // digits" - the autosubmit fires on input, not on focus,
                    // so focusing alone submits nothing.
                    input id="code" name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" minlength="6" required placeholder="000 000" autocomplete="one-time-code" autofocus data-otp-autosubmit class={ (dashboard_input()) " text-center text-lg tracking-widest" };
                }
                (submit_btn("Verify"))
            }
            div class="mt-4 flex justify-center" { (back_link("/login", "Back to sign in")) }
        },
    )
}

pub async fn twofa_verify_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RedirectQuery>,
) -> Response {
    if cookie_value(&headers, "bunyip_2fa").is_none() {
        let card = auth_card(
            "shield",
            "bg-primary/10 text-primary-text",
            "No pending verification",
            "Please log in first.",
            html! {
                a href="/login" class=(button_class("default", "default", "w-full")) { "Back to sign in" }
            },
        );
        return auth_page(&st, &headers, "Two-factor", card).await;
    }
    auth_page(
        &st,
        &headers,
        "Two-factor",
        twofa_card(None, q.redirect.as_deref()),
    )
    .await
}

pub async fn twofa_verify_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TwoFactorForm>,
) -> Response {
    let Some(challenge) = cookie_value(&headers, "bunyip_2fa") else {
        return redirect("/login");
    };
    let cookie = cookie_of(&headers);
    let target = safe_redirect(f.redirect.as_deref(), &st.cfg.oidc_issuer);
    match auth_api::verify_2fa(&st.api, cookie.as_deref(), &challenge, f.code.trim()).await {
        Ok((_, mut cookies)) => {
            cookies.push(bunyip_2fa_cookie_clear(&st.cfg));
            redirect_cookies(&target, &cookies)
        }
        Err(e) => {
            auth_page(
                &st,
                &headers,
                "Two-factor",
                twofa_card(Some(&e.user_message()), f.redirect.as_deref()),
            )
            .await
        }
    }
}

// ===========================================================================
// Accept invite
// ===========================================================================

#[derive(Deserialize)]
pub struct InviteForm {
    pub token: String,
    pub password: String,
    pub confirm: String,
}

fn invite_password_card(token: &str, email: &str, error: Option<&str>) -> Markup {
    auth_card(
        "shield",
        "bg-primary/10 text-primary-text",
        "Create your account",
        &format!("Set a password for {email} to complete your account setup."),
        html! {
            form method="post" action="/invite/accept" class="space-y-4" {
                input type="hidden" name="token" value=(token);
                @if let Some(e) = error { (error_box(e)) }
                (field_autofocus("password", "Password", "password", "At least 12 characters", "new-password"))
                (field("confirm", "Confirm Password", "password", "Re-enter your password", "new-password"))
                (pw_reqs())
                (submit_btn("Sign up"))
            }
        },
    )
}

pub async fn invite_accept_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> Response {
    let Some(token) = q.token else {
        let card = auth_card(
            "alert-circle",
            "bg-destructive/10 text-destructive-text",
            "Invitation Failed",
            "No invite token provided.",
            html! {
                a href="/login" class=(button_class("default", "default", "w-full")) { "Back to sign in" }
            },
        );
        return auth_page(&st, &headers, "Accept invite", card).await;
    };
    match auth_api::accept_invite(&st.api, &token, None).await {
        Ok((Some(email), _, _)) => {
            auth_page(
                &st,
                &headers,
                "Accept invite",
                invite_password_card(&token, &email, None),
            )
            .await
        }
        Ok((None, Some(_), cookies)) => redirect_cookies("/dashboard", &cookies),
        Ok(_) => {
            auth_page(
                &st,
                &headers,
                "Accept invite",
                invite_password_card(&token, "your account", None),
            )
            .await
        }
        Err(e) => {
            let card = auth_card(
                "alert-circle",
                "bg-destructive/10 text-destructive-text",
                "Invitation Failed",
                &e.user_message(),
                html! {
                    a href="/login" class=(button_class("default", "default", "w-full")) { "Back to sign in" }
                },
            );
            auth_page(&st, &headers, "Accept invite", card).await
        }
    }
}

pub async fn invite_accept_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<InviteForm>,
) -> Response {
    if !password_ok(&f.password) || f.password != f.confirm {
        let e = if f.password != f.confirm {
            "Passwords do not match"
        } else {
            "Password does not meet the requirements"
        };
        return auth_page(
            &st,
            &headers,
            "Accept invite",
            invite_password_card(&f.token, "your account", Some(e)),
        )
        .await;
    }
    match auth_api::accept_invite(&st.api, &f.token, Some(&f.password)).await {
        Ok((_, Some(_), cookies)) => redirect_cookies("/dashboard", &cookies),
        Ok(_) => {
            auth_page(
                &st,
                &headers,
                "Accept invite",
                invite_password_card(&f.token, "your account", Some("Failed to accept invite")),
            )
            .await
        }
        Err(e) => {
            auth_page(
                &st,
                &headers,
                "Accept invite",
                invite_password_card(&f.token, "your account", Some(&e.user_message())),
            )
            .await
        }
    }
}

// BUNYIP-290: the first-run setup wizard (`SetupForm`, `setup_card`,
// `setup_get`, `setup_post`) is gone. The first admin is now bootstrapped from
// the BOOTSTRAP_ADMIN_EMAIL env var when that user signs up or signs in; there
// is no `/setup` page.

// ===========================================================================
// Email change confirm / email verification (token links)
// ===========================================================================

pub async fn confirm_email(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> Response {
    let card = match q.token {
        None => auth_card(
            "alert-circle",
            "bg-destructive/10 text-destructive-text",
            "Invalid Link",
            "This email confirmation link is invalid or has expired.",
            html! {
                a href="/settings" class=(button_class("default", "default", "w-full")) { "Go to Settings" }
            },
        ),
        Some(token) => match auth_api::confirm_email_change(&st.api, &token).await {
            Ok(()) => auth_card(
                "check",
                "bg-teal-500/10 text-teal-600 dark:text-teal-400",
                "Email Updated",
                "Your email address has been changed. Please log in with your new email.",
                html! {
                    a href="/login" class=(button_class("default", "default", "w-full")) { "Back to sign in" }
                },
            ),
            Err(e) => auth_card(
                "alert-circle",
                "bg-destructive/10 text-destructive-text",
                "Confirmation Failed",
                &e.user_message(),
                html! {
                    a href="/settings" class=(button_class("default", "default", "w-full")) { "Go to Settings" }
                },
            ),
        },
    };
    auth_page(&st, &headers, "Confirm email", card).await
}

pub async fn verify_email(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> Response {
    // BUNYIP-226: when the verify succeeds AND the user is signed in (which
    // is the common case - the verify link is clicked in the same session),
    // rotate the access token before rendering. BUNYIP-221's
    // `maybe_grant_initial_tier` may have just flipped `trial_ends_at` on
    // the DB row, and the cookie's pre-grant JWT carries stale claims that
    // make `has_member_access()` return false. A rotation here ensures the
    // "Continue" link on the celebration card lands on /dashboard with a
    // fresh JWT, so the app launcher renders unlocked on first paint.
    let session_cookie = cookie_of(&headers);
    let (card, rotated_cookies) = match q.token {
        None => (
            auth_card(
                "alert-circle",
                "bg-destructive/10 text-destructive-text",
                "Invalid Link",
                "This email verification link is invalid or has expired.",
                html! {
                    a href="/settings" class=(button_class("default", "default", "w-full")) { "Go to Settings" }
                },
            ),
            Vec::new(),
        ),
        Some(token) => match auth_api::confirm_email_verification(&st.api, &token).await {
            Ok(tier) => {
                let msg = match tier.as_str() {
                    "lifetime" => "You're one of our founding members - free for life!",
                    "early_adopter" => "You get 3 months free - no credit card needed.",
                    "standard" => "You get 1 month free - no credit card needed.",
                    _ => "Your email address has been verified successfully.",
                };
                let card = auth_card(
                    "check",
                    "bg-teal-500/10 text-teal-600 dark:text-teal-400",
                    "Email Verified!",
                    msg,
                    html! {
                        // BUNYIP-206: forward onward instead of dumping the user on
                        // settings. The `guard()` gate routes a still-onboarding user
                        // (name not yet saved) to /onboarding, everyone else to the
                        // dashboard.
                        a href="/dashboard" class=(button_class("default", "default", "w-full")) { "Continue" }
                    },
                );
                // Only attempt the rotation when the request actually carries
                // a session cookie - a fresh-browser click on the verify link
                // signs the user in via the next visit instead, so there is
                // nothing to rotate here. A refresh failure is non-fatal: the
                // verify still succeeded; the user just keeps the stale JWT
                // until the next refresh trigger.
                let mut cookies = Vec::new();
                if let Some(cookie) = session_cookie.as_deref() {
                    if let Ok(rotated) = auth_api::refresh(&st.api, Some(cookie)).await {
                        cookies = rotated;
                    }
                }
                (card, cookies)
            }
            Err(e) => (
                auth_card(
                    "alert-circle",
                    "bg-destructive/10 text-destructive-text",
                    "Verification Failed",
                    &e.user_message(),
                    html! {
                        a href="/settings" class=(button_class("default", "default", "w-full")) { "Go to Settings" }
                    },
                ),
                Vec::new(),
            ),
        },
    };
    if rotated_cookies.is_empty() {
        auth_page(&st, &headers, "Verify email", card).await
    } else {
        // The celebration card needs to ride out on a response that carries
        // the rotated `Set-Cookie` headers; `auth_page`'s shell doesn't
        // accept extra cookies, so render through the lower-level path
        // directly here. The chrome payloads come from the same shared TTL
        // caches `public_ctx` reads (BUNYIP-555).
        let (apps, pricing) = tokio::join!(st.public_applications(), pricing_published(&st));
        let body = public_shell(&st.cfg, None, &apps, pricing, false, card);
        html_cookies(document("Verify email", body), &rotated_cookies)
    }
}

#[cfg(test)]
mod safe_redirect_tests {
    use super::safe_redirect;

    const ISSUER: &str = "https://api.a8n.systems";

    #[test]
    fn none_falls_back_to_dashboard() {
        assert_eq!(safe_redirect(None, ISSUER), "/dashboard");
    }

    #[test]
    fn relative_path_passes_through() {
        assert_eq!(safe_redirect(Some("/membership"), ISSUER), "/membership");
    }

    #[test]
    fn protocol_relative_url_is_rejected() {
        // `//evil.example.com/x` would escape the host on a real browser.
        assert_eq!(safe_redirect(Some("//evil.com/x"), ISSUER), "/dashboard");
    }

    #[test]
    fn absolute_url_on_issuer_origin_passes_through() {
        let target = "https://api.a8n.systems/oauth2/authorize?client_id=abc&response_type=code";
        assert_eq!(safe_redirect(Some(target), ISSUER), target);
    }

    #[test]
    fn absolute_url_on_different_origin_falls_back() {
        let target = "https://evil.example.com/oauth2/authorize";
        assert_eq!(safe_redirect(Some(target), ISSUER), "/dashboard");
    }

    #[test]
    fn issuer_prefix_match_is_origin_anchored() {
        // `https://api.a8n.systems.evil.com/...` must NOT match a substring of
        // the issuer; the trailing-slash anchor on the prefix check prevents it.
        let target = "https://api.a8n.systems.evil.com/oauth2/authorize";
        assert_eq!(safe_redirect(Some(target), ISSUER), "/dashboard");
    }

    #[test]
    fn javascript_scheme_rejected() {
        assert_eq!(
            safe_redirect(Some("javascript:alert(1)"), ISSUER),
            "/dashboard"
        );
    }
}

#[cfg(test)]
mod logout_clear_tests {
    //! BUNYIP-323: bunyip-web must clear cookies UNCONDITIONALLY on logout,
    //! not just when bunyip-api responds with clearing Set-Cookies. These
    //! tests pin the shape of the defensive clears so a future refactor can
    //! not silently drop them.

    use super::bunyip_auth_cookie_clears;
    use crate::config::Config;

    fn cfg(app_domain: &str, api_public: &str) -> Config {
        Config {
            bind_addr: "127.0.0.1:4400".into(),
            api_url: "http://bunyip-api-app:4401".into(),
            api_public_origin: api_public.into(),
            oidc_issuer: api_public.into(),
            app_domain: app_domain.into(),
            community_url: String::new(),
            trusted_proxies: Vec::new(),
            theme_css: None,
            theme_color_light: None,
            theme_color_dark: None,
            csp: crate::config::CspConfig::default(),
        }
    }

    #[test]
    fn dev_config_emits_host_only_clears_for_the_three_auth_cookies() {
        // No app_domain, http api_public_origin -> host-only clears only,
        // no Secure attribute.
        let cs = bunyip_auth_cookie_clears(&cfg("", "http://localhost:4401"));
        assert_eq!(
            cs.len(),
            3,
            "expected exactly three host-only clears; got {cs:?}"
        );
        for c in &cs {
            assert!(c.starts_with(match c.split('=').next().unwrap_or("") {
                n if n == "access_token" || n == "refresh_token" || n == "bunyip_op_session" => n,
                _ => panic!("unexpected cookie name in {c:?}"),
            }));
            assert!(c.contains("Path=/"), "{c:?}");
            assert!(c.contains("HttpOnly"), "{c:?}");
            assert!(c.contains("SameSite=Lax"), "{c:?}");
            assert!(c.contains("Max-Age=0"), "{c:?}");
            assert!(!c.contains("Secure"), "dev must not set Secure: {c:?}");
            assert!(!c.contains("Domain="), "dev must not set Domain: {c:?}");
        }
    }

    #[test]
    fn prod_config_emits_host_only_and_domain_scoped_clears_with_secure() {
        // With app_domain set and an HTTPS public origin, we expect three
        // host-only clears AND three domain-scoped clears, all with Secure.
        let cs = bunyip_auth_cookie_clears(&cfg("a8n.systems", "https://api.a8n.systems"));
        assert_eq!(
            cs.len(),
            6,
            "expected 6 clears (3 host + 3 domain); got {cs:?}"
        );
        let host_only: Vec<&String> = cs.iter().filter(|c| !c.contains("Domain=")).collect();
        let domain_scoped: Vec<&String> = cs.iter().filter(|c| c.contains("Domain=")).collect();
        assert_eq!(host_only.len(), 3, "host-only count: {host_only:?}");
        assert_eq!(
            domain_scoped.len(),
            3,
            "domain-scoped count: {domain_scoped:?}"
        );
        for c in &cs {
            assert!(c.contains("Secure"), "prod must set Secure: {c:?}");
            assert!(c.contains("Max-Age=0"), "{c:?}");
            assert!(c.contains("HttpOnly"), "{c:?}");
            assert!(c.contains("SameSite=Lax"), "{c:?}");
        }
        for c in &domain_scoped {
            assert!(c.contains("Domain=a8n.systems"), "{c:?}");
        }
    }

    #[test]
    fn every_auth_cookie_name_is_cleared_exactly_once_per_axis() {
        // Guard against a future edit that adds a name to `AuthCookies::set`
        // on the bunyip-api side without updating this list.
        let cs = bunyip_auth_cookie_clears(&cfg("a8n.systems", "https://api.a8n.systems"));
        for name in ["access_token", "refresh_token", "bunyip_op_session"] {
            let host_only = cs
                .iter()
                .filter(|c| c.starts_with(&format!("{name}=")) && !c.contains("Domain="))
                .count();
            let domain_scoped = cs
                .iter()
                .filter(|c| c.starts_with(&format!("{name}=")) && c.contains("Domain="))
                .count();
            assert_eq!(host_only, 1, "{name}: expected 1 host-only clear");
            assert_eq!(domain_scoped, 1, "{name}: expected 1 domain-scoped clear");
        }
    }
}

#[cfg(test)]
mod register_card_tests {
    //! BUNYIP-271: a rejected registration submit must re-render with the
    //! user's non-secret inputs preserved and the failing rule shown next to
    //! the offending field - never a wiped form with a lone generic banner.
    //! It must also never echo a password back into the HTML.

    use super::{register_card, RegisterErrors};

    /// Return the full `<input ...>` tag whose `name="{name}"` attribute
    /// matches, so a test can assert on that input's attributes in isolation.
    fn input_tag<'a>(html: &'a str, name: &str) -> &'a str {
        let needle = format!("name=\"{name}\"");
        let at = html
            .find(&needle)
            .unwrap_or_else(|| panic!("no input named {name} in: {html}"));
        let lt = html[..at].rfind('<').expect("input opens with <");
        let gt = html[lt..].find('>').expect("input closes with >") + lt;
        &html[lt..=gt]
    }

    #[test]
    fn preserves_typed_email_on_rejection() {
        let errs = RegisterErrors {
            email: Some("Enter a valid email address.".into()),
            ..Default::default()
        };
        let html = register_card(&errs, "user@example.com", "").into_string();
        assert!(
            input_tag(&html, "email").contains(r#"value="user@example.com""#),
            "typed email not preserved: {html}"
        );
    }

    #[test]
    fn shows_email_rule_next_to_the_email_field() {
        let errs = RegisterErrors {
            email: Some("Enter a valid email address.".into()),
            ..Default::default()
        };
        let html = register_card(&errs, "nope", "").into_string();
        assert!(
            html.contains("Enter a valid email address."),
            "email rule not surfaced inline: {html}"
        );
        // The inline field error is an alert-role paragraph, not the generic
        // top banner (`error_box` renders an alert-circle icon, no role=alert).
        assert!(
            html.contains(r#"role="alert""#),
            "expected an inline field-level alert: {html}"
        );
    }

    #[test]
    fn shows_password_and_confirm_rules_inline() {
        let errs = RegisterErrors {
            password: Some("Password does not meet the requirements below.".into()),
            confirm: Some("Passwords don't match.".into()),
            ..Default::default()
        };
        let html = register_card(&errs, "user@example.com", "").into_string();
        assert!(
            html.contains("Password does not meet the requirements below."),
            "password rule missing: {html}"
        );
        assert!(
            html.contains("Passwords don't match."),
            "confirm rule missing: {html}"
        );
    }

    #[test]
    fn tells_user_to_reenter_password_on_any_error() {
        let errs = RegisterErrors {
            confirm: Some("Passwords don't match.".into()),
            ..Default::default()
        };
        let html = register_card(&errs, "user@example.com", "").into_string();
        assert!(
            html.to_lowercase().contains("re-enter your password"),
            "missing password re-entry hint: {html}"
        );
    }

    #[test]
    fn never_echoes_a_password_value_into_the_html() {
        // register_card takes no password argument, so a password can never
        // reach the HTML. Pin it: neither password input carries a value=.
        let html = register_card(&RegisterErrors::default(), "user@example.com", "").into_string();
        for name in ["password", "confirm"] {
            assert!(
                !input_tag(&html, name).contains("value="),
                "{name} input must not carry a value= attribute: {}",
                input_tag(&html, name)
            );
        }
    }

    #[test]
    fn clean_render_has_no_errors_or_reentry_hint() {
        // The success/first-load path (register_get) renders with default
        // errors: no inline alerts, no banner, no re-entry hint.
        let html = register_card(&RegisterErrors::default(), "", "").into_string();
        assert!(
            !html.contains(r#"role="alert""#),
            "clean render must have no field alerts: {html}"
        );
        assert!(
            !html.to_lowercase().contains("re-enter your password"),
            "clean render must not nag about re-entry: {html}"
        );
    }
}

#[cfg(test)]
mod autofocus_tests {
    //! BUNYIP-486: every single-purpose auth card focuses its first editable
    //! field on load, exactly once. Cards whose only control is a link keep the
    //! default document focus.

    use super::{
        invite_password_card, login_content, magic_form, register_card, reset_confirm_card,
        reset_form, twofa_card, RegisterErrors,
    };

    fn autofocus_count(html: &str) -> usize {
        html.matches("autofocus").count()
    }

    /// The autofocused input must be the one named `name`, so the attribute
    /// cannot drift onto a later field.
    fn assert_focuses(html: &str, name: &str) {
        assert_eq!(
            autofocus_count(html),
            1,
            "expected exactly one autofocus: {html}"
        );
        let at = html.find("autofocus").expect("autofocus present");
        let lt = html[..at].rfind('<').expect("input opens with <");
        let gt = html[lt..].find('>').expect("input closes with >") + lt;
        let tag = &html[lt..=gt];
        assert!(
            tag.contains(&format!("name=\"{name}\"")),
            "autofocus landed on the wrong input, expected name={name}: {tag}"
        );
    }

    #[test]
    fn every_auth_card_focuses_its_first_field() {
        assert_focuses(&login_content(None, "/dashboard").into_string(), "email");
        assert_focuses(
            &register_card(&RegisterErrors::default(), "", "").into_string(),
            "email",
        );
        assert_focuses(&magic_form(None, false).into_string(), "email");
        assert_focuses(&reset_form(None, false).into_string(), "email");
        assert_focuses(&reset_confirm_card("tok", None).into_string(), "password");
        assert_focuses(&twofa_card(None, None).into_string(), "code");
        assert_focuses(
            &invite_password_card("tok", "user@example.com", None).into_string(),
            "password",
        );
    }

    #[test]
    fn error_rerenders_still_focus_the_first_field() {
        // The wrong-code retry is a full page load of the same card, so the
        // attribute has to survive the error path too.
        assert_focuses(
            &twofa_card(Some("Invalid code."), None).into_string(),
            "code",
        );
        assert_focuses(
            &login_content(Some("Bad login."), "/").into_string(),
            "email",
        );
        assert_focuses(
            &register_card(
                &RegisterErrors {
                    email: Some("Enter a valid email address.".into()),
                    ..Default::default()
                },
                "user@example.com",
                "",
            )
            .into_string(),
            "email",
        );
        assert_focuses(
            &magic_form(Some("Try again."), false).into_string(),
            "email",
        );
        assert_focuses(
            &reset_form(Some("Try again."), false).into_string(),
            "email",
        );
        assert_focuses(
            &reset_confirm_card("tok", Some("Try again.")).into_string(),
            "password",
        );
        assert_focuses(
            &invite_password_card("tok", "user@example.com", Some("Try again.")).into_string(),
            "password",
        );
    }

    #[test]
    fn twofa_error_box_never_shows_serde_internals() {
        // BUNYIP-506: the outage rendered a raw serde string ("missing field
        // `subscription_tier`") in this box while the user was typing a TOTP
        // code. A decode failure now renders one fixed line, nothing else.
        let e = crate::api::decode_error::<crate::api::types::AuthResponse>(
            "/auth/2fa/verify",
            &serde_json::from_str::<crate::api::types::AuthResponse>("{}").unwrap_err(),
        );
        let html = twofa_card(Some(&e.user_message()), None).into_string();
        assert!(
            html.contains("We could not read the response from the server."),
            "expected the fixed decode message: {html}"
        );
        for leak in ["missing field", "AuthResponse", "`user`", "line 1 column"] {
            assert!(
                !html.contains(leak),
                "decode internals leaked into the 2FA error box ({leak}): {html}"
            );
        }
    }

    #[test]
    fn link_only_confirmation_cards_do_not_steal_focus() {
        for html in [
            magic_form(None, true).into_string(),
            reset_form(None, true).into_string(),
        ] {
            assert_eq!(
                autofocus_count(&html),
                0,
                "a card with no form field must not autofocus: {html}"
            );
        }
    }
}
