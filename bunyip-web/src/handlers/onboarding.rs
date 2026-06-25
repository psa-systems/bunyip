//! BUNYIP-206: forced post-registration onboarding. A new user must provide a
//! first + last name and verify their email before any app surface unlocks.
//! The hard enforcement lives in `guard()` (handlers/mod.rs); this module only
//! renders the page and saves the name. The emailed verification link continues
//! to land on the existing `/settings/verify-email` handler.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use maud::{html, Markup};
use serde::Deserialize;

use crate::api::auth as auth_api;
use crate::api::types::User;
use crate::handlers::{cookie_value, dashboard_input, dashboard_response, guard, needs_onboarding};
use crate::util::urlenc;
use crate::views::ui::{button_class, error_box, icon};
use crate::web::{redirect_cookies, AppState};

/// Set after the onboarding page auto-sends the verification email so a refresh
/// (or the POST-name redirect back here) does not fire a second mail.
/// `request_email_verification` is NOT idempotent: it mints a new token and
/// sends a fresh message on every call, capped at 3/hour
/// (`services::auth::request_email_verification`). The cookie is what keeps
/// "send on arrival" from becoming "send on every load". It expires with the
/// token's 1h lifetime, after which a reload re-sends - fine, because the old
/// link has expired too.
const VERIFY_SENT_COOKIE: &str = "bunyip_onboard_verify_sent";

#[derive(Deserialize)]
pub struct OnboardingQuery {
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct OnboardingForm {
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    #[serde(default)]
    pub phone: String,
}

pub async fn onboarding_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<OnboardingQuery>,
) -> Response {
    let (user, mut c) = match guard(&st, &headers, "/onboarding").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    // An already-onboarded user never sees this page. `needs_onboarding` also
    // treats email verification as satisfied when delivery is disabled, so a
    // dev / no-SMTP user who has set their name is forwarded on, not trapped.
    if !needs_onboarding(&st, &user).await {
        return redirect_cookies("/dashboard", &c.set_cookies);
    }

    // Auto-send the verification email on first arrival only (cookie-gated, see
    // VERIFY_SENT_COOKIE). The result is intentionally ignored: a failure
    // (including the 3/hour rate limit) must not break the page, and the Resend
    // control stays available either way.
    if !user.email_verified && cookie_value(&headers, VERIFY_SENT_COOKIE).is_none() {
        let _ = auth_api::request_email_verification(&st.api, c.forward.as_deref()).await;
        c.set_cookies.push(format!(
            "{VERIFY_SENT_COOKIE}=1; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600"
        ));
    }

    let content = onboarding_content(&user, q.error.as_deref());
    dashboard_response(&c, &user, "/onboarding", "Welcome · Bunyip", content)
}

pub async fn onboarding_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<OnboardingForm>,
) -> Response {
    let (_, c) = match guard(&st, &headers, "/onboarding").await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let first = f.first_name.trim();
    let last = f.last_name.trim();
    if first.is_empty() || last.is_empty() {
        return redirect_cookies(
            &format!(
                "/onboarding?error={}",
                urlenc("Enter both your first and last name.")
            ),
            &c.set_cookies,
        );
    }
    match auth_api::update_profile(
        &st.api,
        c.forward.as_deref(),
        Some(first),
        Some(last),
        Some(f.phone.trim()),
    )
    .await
    {
        // Back to /onboarding: the GET re-checks completeness and forwards to
        // /dashboard once the email is verified too.
        Ok(()) => redirect_cookies("/onboarding", &c.set_cookies),
        Err(e) => redirect_cookies(
            &format!("/onboarding?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

fn name_present(v: &Option<String>) -> bool {
    matches!(v.as_deref().map(str::trim), Some(s) if !s.is_empty())
}

fn onboarding_content(user: &User, error: Option<&str>) -> Markup {
    let name_done = name_present(&user.first_name) && name_present(&user.last_name);
    html! {
        div class="mx-auto max-w-2xl space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "Welcome to Bunyip" }
                p class="mt-2 text-muted-foreground" { "Two quick steps and your account is ready." }
            }
            @if let Some(e) = error { (error_box(e)) }

            // Step 1: name.
            (step_card("user-cog", "from-primary to-indigo-500", "Tell us your name", name_done, html! {
                form method="post" action="/onboarding" class="space-y-4" {
                    div class="grid gap-4 sm:grid-cols-2" {
                        div class="space-y-2" { label class="text-sm font-medium" { "First name" } input name="first_name" type="text" required maxlength="64" value=(user.first_name.as_deref().unwrap_or("")) class=(dashboard_input()); }
                        div class="space-y-2" { label class="text-sm font-medium" { "Last name" } input name="last_name" type="text" required maxlength="64" value=(user.last_name.as_deref().unwrap_or("")) class=(dashboard_input()); }
                    }
                    div class="space-y-2" { label class="text-sm font-medium" { "Phone " span class="text-xs text-muted-foreground" { "(optional)" } } input name="phone" type="tel" maxlength="64" value=(user.phone.as_deref().unwrap_or("")) class=(dashboard_input()); }
                    button type="submit" class=(button_class("default", "default", "bg-gradient-to-r from-primary to-indigo-500 text-white border-0")) { "Save and continue" }
                }
            }))

            // Step 2: verify email.
            (step_card("mail", "from-indigo-500 to-teal-500", "Verify your email", user.email_verified, html! {
                @if user.email_verified {
                    p class="text-sm text-muted-foreground flex items-center gap-2" {
                        (icon("check", "h-4 w-4 text-teal-600 dark:text-teal-400")) "Your email address is verified."
                    }
                } @else {
                    p class="text-sm text-muted-foreground" {
                        "We sent a verification link to " span class="font-medium text-foreground" { (user.email) } ". Open it to confirm your address, then refresh this page."
                    }
                    form method="post" action="/settings/verify-email/resend" class="mt-3" {
                        button type="submit" class=(button_class("outline", "sm", "")) { (icon("mail", "mr-2 h-4 w-4")) "Resend verification email" }
                    }
                }
            }))
        }
    }
}

/// A numbered onboarding step rendered as a card; shows a teal check once `done`.
fn step_card(icon_name: &str, gradient: &str, title: &str, done: bool, body: Markup) -> Markup {
    html! {
        div class="rounded-lg border bg-card text-card-foreground shadow-sm border-border/50" {
            div class="flex items-center gap-3 p-6 pb-0" {
                div class={ "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br " (gradient) } { (icon(icon_name, "h-4 w-4 text-white")) }
                h3 class="text-xl font-semibold leading-none tracking-tight flex-1" { (title) }
                @if done { (icon("check", "h-5 w-5 text-teal-600 dark:text-teal-400")) }
            }
            div class="p-6 pt-4" { (body) }
        }
    }
}
