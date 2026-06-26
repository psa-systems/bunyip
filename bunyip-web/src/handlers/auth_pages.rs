//! Auth-flow handlers. Login + logout here for the slice; the rest of the
//! auth/public pages arrive in phase 2.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::auth::{self as auth_api, LoginOutcome};
use crate::api::calls;
use crate::handlers::{auth_page, cookie_of, cookie_value, ctx, dashboard_input, password_ok};
use crate::views::common::auth_card;
use crate::views::layout::{document, public_shell};
use crate::views::ui::{button_class, error_box};
use crate::web::{html, html_cookies, redirect, redirect_cookies, AppState};

fn field(id: &str, label: &str, ty: &str, placeholder: &str, autocomplete: &str) -> Markup {
    html! {
        div class="space-y-2" {
            label for=(id) class="text-sm font-medium leading-none" { (label) }
            input id=(id) name=(id) type=(ty) placeholder=(placeholder) autocomplete=(autocomplete) class=(dashboard_input());
        }
    }
}

fn submit_btn(label: &str) -> Markup {
    html! { button type="submit" class=(button_class("default", "default", "w-full")) { (label) } }
}

fn pw_reqs() -> Markup {
    html! {
        ul class="text-xs text-muted-foreground space-y-1 mt-2" {
            li { "At least 12 characters" }
            li { "Upper and lowercase letters" }
            li { "At least one digit and one special character" }
        }
    }
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
    html! {
        div class="flex min-h-[calc(100vh-8rem)] items-center justify-center py-12" {
            div class="w-full max-w-md rounded-lg border bg-card text-card-foreground shadow-sm" {
                div class="flex flex-col space-y-1.5 p-6 text-center" {
                    h3 class="text-2xl font-semibold leading-none tracking-tight" { "Welcome back" }
                    p class="text-sm text-muted-foreground" { "Sign in to your account to continue" }
                }
                div class="p-6 pt-0" {
                    form method="post" action="/login" class="space-y-4" {
                        input type="hidden" name="redirect" value=(redirect);
                        @if let Some(e) = error { (error_box(e)) }
                        div class="space-y-2" {
                            label for="email" class="text-sm font-medium leading-none" { "Email" }
                            input id="email" name="email" type="email" placeholder="you@example.com" autocomplete="email"
                                class=(dashboard_input());
                        }
                        div class="space-y-2" {
                            div class="flex items-center justify-between" {
                                label for="password" class="text-sm font-medium leading-none" { "Password" }
                                a href="/password-reset" class="text-sm text-primary hover:underline" { "Forgot password?" }
                            }
                            input id="password" name="password" type="password" autocomplete="current-password"
                                class=(dashboard_input());
                        }
                        div class="flex items-center space-x-2" {
                            input id="remember" name="remember" type="checkbox" value="on" class="h-4 w-4 rounded border-border";
                            label for="remember" class="text-sm font-normal cursor-pointer" { "Remember me for 30 days" }
                        }
                        button type="submit" class=(button_class("default", "default", "w-full")) { "Sign In" }
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
                        a href="/register" class="text-primary hover:underline" { "Sign up" }
                    }
                }
            }
        }
    }
}

pub async fn login_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RedirectQuery>,
) -> Response {
    let (c, fwd) = ctx(&st, &headers).await;
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
    let apps = calls::applications(&st.api, fwd.as_deref())
        .await
        .unwrap_or_default();
    let content = login_content(None, q.redirect.as_deref().unwrap_or("/dashboard"));
    let body = public_shell(&st.cfg, None, &apps, false, content);
    html(document("Sign in · Bunyip", body))
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
            cookies.push(format!(
                "bunyip_2fa={challenge_token}; Path=/; HttpOnly; SameSite=Lax"
            ));
            // Carry the original ?redirect= forward so the OIDC return-URL
            // survives the 2FA step.
            let path = match f.redirect.as_deref().filter(|s| !s.is_empty()) {
                Some(r) => format!("/login/2fa?redirect={}", urlencoding::encode(r)),
                None => "/login/2fa".to_string(),
            };
            redirect_cookies(&path, &cookies)
        }
        Err(e) => {
            let apps = calls::applications(&st.api, None).await.unwrap_or_default();
            let content = login_content(Some(&e.user_message()), &target);
            let body = public_shell(&st.cfg, None, &apps, false, content);
            html(document("Sign in · Bunyip", body))
        }
    }
}

pub async fn logout(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RedirectQuery>,
) -> Response {
    let cookie = cookie_of(&headers);
    let mut cleared = auth_api::logout(&st.api, cookie.as_deref())
        .await
        .unwrap_or_default();
    // Also drop any pending-2FA cookie.
    cleared.push("bunyip_2fa=; Path=/; Max-Age=0".to_string());
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
}

fn register_card(error: Option<&str>) -> Markup {
    auth_card(
        "shield",
        "bg-primary/10 text-primary",
        "Create an account",
        "Get access to all tools for $3/month",
        html! {
            form method="post" action="/register" class="space-y-4" {
                @if let Some(e) = error { (error_box(e)) }
                (field("email", "Email", "email", "you@example.com", "email"))
                (field("password", "Password", "password", "", "new-password"))
                (pw_reqs())
                (field("confirm", "Confirm Password", "password", "", "new-password"))
                (submit_btn("Create Account"))
            }
            div class="mt-6" {
                a href="/magic-link" class=(button_class("outline", "default", "w-full")) { "Sign up with Magic Link" }
            }
            p class="mt-6 text-center text-sm text-muted-foreground" {
                "Already have an account? " a href="/login" class="text-primary hover:underline" { "Sign in" }
            }
            p class="mt-4 text-center text-xs text-muted-foreground" {
                "By creating an account, you agree to our "
                a href="/terms" class="underline hover:text-foreground" { "Terms of Service" } " and "
                a href="/privacy" class="underline hover:text-foreground" { "Privacy Policy" } "."
            }
        },
    )
}

pub async fn register_get(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let (c, _) = ctx(&st, &headers).await;
    if c.is_signed_in() {
        // Relay any refreshed session cookie on the already-signed-in bounce.
        return redirect_cookies("/dashboard", &c.set_cookies);
    }
    auth_page(
        &st,
        &headers,
        "Create account · Bunyip",
        register_card(None),
    )
    .await
}

pub async fn register_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<RegisterForm>,
) -> Response {
    let err = if !f.email.contains('@') {
        Some("Invalid email address".to_string())
    } else if !password_ok(&f.password) {
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
            "Create account · Bunyip",
            register_card(Some(&e)),
        )
        .await;
    }
    match auth_api::register(&st.api, f.email.trim(), &f.password).await {
        // BUNYIP-206: a new user lands on /onboarding (name + email verification)
        // before any app surface. The `guard()` gate enforces this for every
        // other entry path; sending them straight here avoids the extra hop.
        Ok((_, cookies)) => redirect_cookies("/onboarding", &cookies),
        Err(e) => {
            auth_page(
                &st,
                &headers,
                "Create account · Bunyip",
                register_card(Some(&e.user_message())),
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
                a href="/login" class=(button_class("outline", "default", "mt-6 w-full")) { "Back to Login" }
            },
        );
    }
    auth_card(
        "mail",
        "bg-primary/10 text-primary",
        "Sign in with Magic Link",
        "We'll email you a link to sign in - no password needed.",
        html! {
            form method="post" action="/magic-link" class="space-y-4" {
                @if let Some(e) = error { (error_box(e)) }
                (field("email", "Email", "email", "you@example.com", "email"))
                (submit_btn("Send Magic Link"))
            }
            p class="mt-6 text-center text-sm text-muted-foreground" {
                a href="/login" class="text-primary hover:underline" { "Sign in with password" } " · "
                a href="/register" class="text-primary hover:underline" { "Create account" }
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
                cookies.push(format!(
                    "bunyip_2fa={challenge_token}; Path=/; HttpOnly; SameSite=Lax"
                ));
                redirect_cookies("/login/2fa", &cookies)
            }
            Err(e) => {
                let card = auth_card(
                    "alert-circle",
                    "bg-destructive/10 text-destructive",
                    "Verification Failed",
                    &e.user_message(),
                    html! {
                        a href="/magic-link" class=(button_class("default", "default", "w-full")) { "Request New Magic Link" }
                    },
                );
                auth_page(&st, &headers, "Magic link · Bunyip", card).await
            }
        };
    }
    auth_page(
        &st,
        &headers,
        "Magic link · Bunyip",
        magic_form(None, false),
    )
    .await
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
    auth_page(&st, &headers, "Magic link · Bunyip", card).await
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
                a href="/login" class=(button_class("outline", "default", "mt-6 w-full")) { "Back to Login" }
            },
        );
    }
    auth_card(
        "key",
        "bg-primary/10 text-primary",
        "Reset your password",
        "Enter your email and we'll send you a reset link.",
        html! {
            form method="post" action="/password-reset" class="space-y-4" {
                @if let Some(e) = error { (error_box(e)) }
                (field("email", "Email", "email", "you@example.com", "email"))
                (submit_btn("Send Reset Link"))
            }
            p class="mt-6 text-center text-sm text-muted-foreground" {
                "Remember your password? " a href="/login" class="text-primary hover:underline" { "Sign in" }
            }
        },
    )
}

pub async fn password_reset_get(State(st): State<AppState>, headers: HeaderMap) -> Response {
    auth_page(
        &st,
        &headers,
        "Reset password · Bunyip",
        reset_form(None, false),
    )
    .await
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
    auth_page(&st, &headers, "Reset password · Bunyip", card).await
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
        "bg-primary/10 text-primary",
        "Set new password",
        "Choose a strong password for your account.",
        html! {
            form method="post" action="/password-reset/confirm" class="space-y-4" {
                input type="hidden" name="token" value=(token);
                @if let Some(e) = error { (error_box(e)) }
                (field("password", "New Password", "password", "", "new-password"))
                (pw_reqs())
                (field("confirm", "Confirm Password", "password", "", "new-password"))
                (submit_btn("Reset Password"))
            }
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
                "Reset password · Bunyip",
                reset_confirm_card(&token, None),
            )
            .await
        }
        None => {
            let card = auth_card(
                "alert-circle",
                "bg-destructive/10 text-destructive",
                "Invalid Reset Link",
                "This password reset link is invalid or has expired.",
                html! {
                    a href="/password-reset" class=(button_class("default", "default", "w-full")) { "Request New Reset Link" }
                },
            );
            auth_page(&st, &headers, "Reset password · Bunyip", card).await
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
            "Reset password · Bunyip",
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
                "Reset password · Bunyip",
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
    /// "Trust this device" checkbox. Present (Some) only when checked
    /// (BUNYIP-138).
    #[serde(default)]
    pub trust_device: Option<String>,
}

fn twofa_card(error: Option<&str>, redirect: Option<&str>) -> Markup {
    let redirect = redirect.unwrap_or_default();
    auth_card(
        "shield",
        "bg-primary/10 text-primary",
        "Two-Factor Authentication",
        "Enter the 6-digit code from your authenticator app",
        html! {
            form method="post" action="/login/2fa" class="space-y-4" {
                @if !redirect.is_empty() {
                    input type="hidden" name="redirect" value=(redirect);
                }
                @if let Some(e) = error { (error_box(e)) }
                div class="space-y-2" {
                    label for="code" class="text-sm font-medium leading-none" { "Authentication Code" }
                    // BUNYIP-117: maxlength + pattern so the browser bounds
                    // and format-checks the 6-digit TOTP before submit.
                    // Authoritative validation still happens in the domain
                    // (services::totp::verify_code).
                    input id="code" name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" minlength="6" required placeholder="000 000" autocomplete="one-time-code" class={ (dashboard_input()) " text-center text-lg tracking-widest" };
                }
                // Trusted device opt-in (BUNYIP-138). Honored only for
                // subscribers; the API ignores it for admins.
                label class="flex items-center gap-2 text-sm text-muted-foreground" {
                    input type="checkbox" name="trust_device" value="on" class="h-4 w-4";
                    "Trust this device for 30 days (skip codes here)"
                }
                (submit_btn("Verify"))
            }
            div class="mt-4 text-center" {
                a href="/login" class="inline-flex items-center text-sm text-muted-foreground hover:text-foreground" { "Back to login" }
            }
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
            "bg-primary/10 text-primary",
            "No pending verification",
            "Please log in first.",
            html! {
                a href="/login" class=(button_class("default", "default", "w-full")) { "Go to Login" }
            },
        );
        return auth_page(&st, &headers, "Two-factor · Bunyip", card).await;
    }
    auth_page(
        &st,
        &headers,
        "Two-factor · Bunyip",
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
    let trust_device = f.trust_device.is_some();
    match auth_api::verify_2fa(
        &st.api,
        cookie.as_deref(),
        &challenge,
        f.code.trim(),
        trust_device,
    )
    .await
    {
        Ok((_, mut cookies)) => {
            cookies.push("bunyip_2fa=; Path=/; Max-Age=0".to_string());
            redirect_cookies(&target, &cookies)
        }
        Err(e) => {
            auth_page(
                &st,
                &headers,
                "Two-factor · Bunyip",
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
        "bg-primary/10 text-primary",
        "Create Your Account",
        &format!("Set a password for {email} to complete your account setup."),
        html! {
            form method="post" action="/invite/accept" class="space-y-4" {
                input type="hidden" name="token" value=(token);
                @if let Some(e) = error { (error_box(e)) }
                (field("password", "Password", "password", "At least 12 characters", "new-password"))
                (field("confirm", "Confirm Password", "password", "Re-enter your password", "new-password"))
                (pw_reqs())
                (submit_btn("Create Account"))
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
            "bg-destructive/10 text-destructive",
            "Invitation Failed",
            "No invite token provided.",
            html! {
                a href="/login" class=(button_class("default", "default", "w-full")) { "Go to Login" }
            },
        );
        return auth_page(&st, &headers, "Accept invite · Bunyip", card).await;
    };
    match auth_api::accept_invite(&st.api, &token, None).await {
        Ok((Some(email), _, _)) => {
            auth_page(
                &st,
                &headers,
                "Accept invite · Bunyip",
                invite_password_card(&token, &email, None),
            )
            .await
        }
        Ok((None, Some(_), cookies)) => redirect_cookies("/dashboard", &cookies),
        Ok(_) => {
            auth_page(
                &st,
                &headers,
                "Accept invite · Bunyip",
                invite_password_card(&token, "your account", None),
            )
            .await
        }
        Err(e) => {
            let card = auth_card(
                "alert-circle",
                "bg-destructive/10 text-destructive",
                "Invitation Failed",
                &e.user_message(),
                html! {
                    a href="/login" class=(button_class("default", "default", "w-full")) { "Go to Login" }
                },
            );
            auth_page(&st, &headers, "Accept invite · Bunyip", card).await
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
            "Accept invite · Bunyip",
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
                "Accept invite · Bunyip",
                invite_password_card(&f.token, "your account", Some("Failed to accept invite")),
            )
            .await
        }
        Err(e) => {
            auth_page(
                &st,
                &headers,
                "Accept invite · Bunyip",
                invite_password_card(&f.token, "your account", Some(&e.user_message())),
            )
            .await
        }
    }
}

// ===========================================================================
// First-run setup
// ===========================================================================

#[derive(Deserialize)]
pub struct SetupForm {
    pub email: String,
    pub password: String,
    pub confirm: String,
}

fn setup_card(error: Option<&str>) -> Markup {
    auth_card(
        "shield",
        "bg-primary/10 text-primary",
        "Initial Setup",
        "Create the first admin account to get started",
        html! {
            form method="post" action="/setup" class="space-y-4" {
                @if let Some(e) = error { (error_box(e)) }
                (field("email", "Admin Email", "email", "admin@example.com", "email"))
                (field("password", "Password", "password", "", "new-password"))
                (pw_reqs())
                (field("confirm", "Confirm Password", "password", "", "new-password"))
                (submit_btn("Create Admin Account"))
            }
        },
    )
}

pub async fn setup_get(State(st): State<AppState>, headers: HeaderMap) -> Response {
    auth_page(&st, &headers, "Setup · Bunyip", setup_card(None)).await
}

pub async fn setup_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<SetupForm>,
) -> Response {
    let err = if !f.email.contains('@') {
        Some("Invalid email address".to_string())
    } else if !password_ok(&f.password) {
        Some("Password does not meet the requirements".to_string())
    } else if f.password != f.confirm {
        Some("Passwords don't match".to_string())
    } else {
        None
    };
    if let Some(e) = err {
        return auth_page(&st, &headers, "Setup · Bunyip", setup_card(Some(&e))).await;
    }
    match auth_api::setup(&st.api, f.email.trim(), &f.password).await {
        Ok((_, cookies)) => redirect_cookies("/dashboard", &cookies),
        Err(e) => {
            auth_page(
                &st,
                &headers,
                "Setup · Bunyip",
                setup_card(Some(&e.user_message())),
            )
            .await
        }
    }
}

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
            "bg-destructive/10 text-destructive",
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
                    a href="/login" class=(button_class("default", "default", "w-full")) { "Go to Login" }
                },
            ),
            Err(e) => auth_card(
                "alert-circle",
                "bg-destructive/10 text-destructive",
                "Confirmation Failed",
                &e.user_message(),
                html! {
                    a href="/settings" class=(button_class("default", "default", "w-full")) { "Go to Settings" }
                },
            ),
        },
    };
    auth_page(&st, &headers, "Confirm email · Bunyip", card).await
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
                "bg-destructive/10 text-destructive",
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
                    "bg-destructive/10 text-destructive",
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
        auth_page(&st, &headers, "Verify email · Bunyip", card).await
    } else {
        // The celebration card needs to ride out on a response that carries
        // the rotated `Set-Cookie` headers; `auth_page`'s shell doesn't
        // accept extra cookies, so render through the lower-level path
        // directly here. Apps list is hydrated identically (signed-out call
        // because the rotated cookie isn't visible yet on this response).
        let apps = calls::applications(&st.api, session_cookie.as_deref())
            .await
            .unwrap_or_default();
        let body = public_shell(&st.cfg, None, &apps, false, card);
        html_cookies(document("Verify email · Bunyip", body), &rotated_cookies)
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
