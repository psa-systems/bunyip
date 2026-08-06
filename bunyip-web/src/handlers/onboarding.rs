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
use crate::views::ui::{button_class, error_box, icon, success_box};
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
    /// BUNYIP-324: success feedback (e.g. "Verification email sent to ...")
    /// carried back here when a resend originated on the onboarding page.
    pub ok: Option<String>,
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
    //
    // BUNYIP-229: when the user lands here AFTER the dual gate has been
    // satisfied OUT-OF-BAND (the cross-browser case: they verified email
    // in a different browser, then refreshed this tab), the next hop is
    // /dashboard but their cookie still carries a pre-grant JWT with
    // `trial_ends_at = None`. Rotate the access token before the
    // redirect so /dashboard's /v1/applications call reads fresh claims
    // on first paint and the launcher does not stay Locked. BUNYIP-226
    // covered the same-browser flow on `onboarding_post`; this completes
    // the coverage on the GET-side forwarder. Refresh failure is
    // non-fatal: the redirect still happens with the original cookies.
    if !needs_onboarding(&st, &user).await {
        let mut cookies = c.set_cookies.clone();
        if let Some(cookie) = c.forward.as_deref() {
            if let Ok(rotated) = auth_api::refresh(&st.api, Some(cookie)).await {
                cookies.extend(rotated);
            }
        }
        return redirect_cookies("/dashboard", &cookies);
    }

    // Auto-send the verification email on first arrival only (cookie-gated, see
    // VERIFY_SENT_COOKIE). A failure must not break the page and the Resend
    // control stays available either way, but a 429 is no longer swallowed
    // silently (BUNYIP-314): surface the standard "try again in about N
    // minutes" copy via the page's error slot so a throttled user knows why no
    // email arrived. Other errors stay silent, exactly as before.
    let mut send_error: Option<String> = None;
    if !user.email_verified && cookie_value(&headers, VERIFY_SENT_COOKIE).is_none() {
        if let Err(e) = auth_api::request_email_verification(&st.api, c.forward.as_deref()).await {
            if e.status == 429 {
                send_error = Some(e.verification_message());
            }
        }
        c.set_cookies.push(format!(
            "{VERIFY_SENT_COOKIE}=1; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600"
        ));
    }

    let content = onboarding_content(
        &user,
        q.error.as_deref().or(send_error.as_deref()),
        q.ok.as_deref(),
    );
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
        //
        // BUNYIP-226: when this name save closes BUNYIP-221's dual gate
        // (email already verified), the API runs `maybe_grant_initial_tier`
        // and the user's `trial_ends_at` flips on the DB row. The session
        // cookie's JWT is still the pre-grant one with `trial_ends_at =
        // None`, so the next page's `/v1/applications` call reads
        // `has_member_access() == false` from stale claims and renders
        // the launcher tiles as Locked. Force a token rotation now so the
        // redirect carries a fresh JWT and the dashboard reads the new
        // claims on first paint. A refresh failure is non-fatal: the
        // grant already landed in the DB, the user just keeps the stale
        // JWT until something else triggers a refresh (no worse than
        // pre-BUNYIP-226).
        Ok(()) => {
            let mut cookies = c.set_cookies.clone();
            if let Some(cookie) = c.forward.as_deref() {
                if let Ok(rotated) = auth_api::refresh(&st.api, Some(cookie)).await {
                    cookies.extend(rotated);
                }
            }
            redirect_cookies("/onboarding", &cookies)
        }
        Err(e) => redirect_cookies(
            &format!("/onboarding?error={}", urlenc(&e.user_message())),
            &c.set_cookies,
        ),
    }
}

fn name_present(v: &Option<String>) -> bool {
    matches!(v.as_deref().map(str::trim), Some(s) if !s.is_empty())
}

fn onboarding_content(user: &User, error: Option<&str>, ok: Option<&str>) -> Markup {
    let name_done = name_present(&user.first_name) && name_present(&user.last_name);
    html! {
        div class="mx-auto max-w-2xl space-y-6" {
            div {
                h1 class="text-3xl font-bold" { "Welcome to Bunyip" }
                p class="mt-2 text-muted-foreground" { "Two quick steps and your account is ready." }
            }
            @if let Some(ok) = ok { (success_box(ok)) }
            @if let Some(e) = error { (error_box(e)) }

            // Step 1: name.
            (step_card("user-cog", "from-primary to-indigo-500", "Tell us your name", name_done, html! {
                form method="post" action="/onboarding" class="space-y-4" {
                    div class="grid gap-4 sm:grid-cols-2" {
                        div class="space-y-2" { label for="first_name" class="text-sm font-medium" { "First name" } input id="first_name" name="first_name" type="text" required maxlength="64" value=(user.first_name.as_deref().unwrap_or("")) class=(dashboard_input()); }
                        div class="space-y-2" { label for="last_name" class="text-sm font-medium" { "Last name" } input id="last_name" name="last_name" type="text" required maxlength="64" value=(user.last_name.as_deref().unwrap_or("")) class=(dashboard_input()); }
                    }
                    div class="space-y-2" { label for="phone" class="text-sm font-medium" { "Phone " span class="text-xs text-muted-foreground" { "(optional)" } } input id="phone" name="phone" type="tel" maxlength="64" value=(user.phone.as_deref().unwrap_or("")) class=(dashboard_input()); }
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
                h3 class="text-2xl font-semibold leading-none tracking-tight flex-1" { (title) }
                @if done { (icon("check", "h-5 w-5 text-teal-600 dark:text-teal-400")) }
            }
            div class="p-6 pt-4" { (body) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::onboarding_content;
    use crate::api::types::{MembershipStatus, SubscriptionTier, User, UserRole};

    /// A named-but-unverified user: the state in which the onboarding page shows
    /// the "Resend verification email" control whose feedback BUNYIP-324 routes
    /// back here.
    fn unverified_user() -> User {
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
            first_name: Some("Ada".into()),
            last_name: Some("Lovelace".into()),
            phone: None,
            avatar_updated_at: None,
            is_super_admin: false,
        }
    }

    // BUNYIP-324: before the fix, a resend that originated on /onboarding
    // redirected to /settings, was bounced back to /onboarding by the
    // onboarding gate (dropping the query param), and the page rendered no
    // feedback. These assert the queued-success and send-failure indications
    // now render here.

    #[test]
    fn renders_queued_success_indication() {
        let html = onboarding_content(
            &unverified_user(),
            None,
            Some("Verification email sent to u@example.com"),
        )
        .into_string();
        assert!(
            html.contains("Verification email sent to u@example.com"),
            "onboarding page must show the resend success indication"
        );
    }

    #[test]
    fn renders_send_failure_indication() {
        let msg = "You have requested too many verification emails. Please try again in about 42 minutes.";
        let html = onboarding_content(&unverified_user(), Some(msg), None).into_string();
        assert!(
            html.contains("too many verification emails"),
            "onboarding page must show the resend failure indication"
        );
    }

    /// BUNYIP-367: the two step cards stack on the same 24px rhythm as the rest
    /// of the authenticated screens.
    #[test]
    fn step_cards_are_spaced() {
        let html = onboarding_content(&unverified_user(), None, None).into_string();
        crate::views::ui::assert_cards_are_spaced(&html);
    }

    #[test]
    fn no_feedback_boxes_when_both_none() {
        let html = onboarding_content(&unverified_user(), None, None).into_string();
        // The success banner uses the teal check; absent when there is nothing
        // to report, so a plain page load stays clean.
        assert!(!html.contains("Verification email sent"));
    }
}
