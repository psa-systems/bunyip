//! Auth pages wired to mokosh-server.
//!
//! Single-component state machines:
//!   - LoginPage: password form -> MFA prompt (auto-submits on 6 digits)
//!     -> token persistence -> route to Dashboard / `return_to`.
//!   - SignupPage: email-only "we sent you a link" form.
//!   - SignupCompletePage: at /signup/:token, sets password + names.
//!   - ForgotPasswordPage: "we sent reset instructions" form.
//!   - ResetPasswordPage: at /reset-password/:token, sets new password.

use dioxus::prelude::*;

use crate::api::{self, auth::*};
use crate::components::layout::AuthShell;
use crate::components::password_checklist::{password_meets_policy, PasswordChecklist};
use crate::modules::oidc::{self, FlowError, LoginOutcome};
use crate::routes::Route;
use crate::stores::auth::{refresh_auth, use_auth, AuthState};
use crate::stores::config::OidcConfig;
use crate::stores::toast::use_toast;
use crate::stores::tokens::{save_tokens, Tokens};

const TRUST_TOKEN_KEY: &str = "bunyip.trust_token";

fn read_trust_token() -> Option<String> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item(TRUST_TOKEN_KEY).ok().flatten())
        .filter(|s| !s.is_empty())
}

fn write_trust_token(token: &str) {
    if let Some(Ok(Some(s))) = web_sys::window().map(|w| w.local_storage()) {
        let _ = s.set_item(TRUST_TOKEN_KEY, token);
    }
}

#[derive(Default, Clone, PartialEq)]
struct LoginState {
    email: String,
    password: String,
    submitting: bool,
    error: Option<String>,
    mfa_challenge: Option<String>,
    mfa_code: String,
    remember_device: bool,
}

/// Read `?return_to=<percent-encoded authorize query>` from the URL.
/// Strict-validated: the value must look like the serialized OIDC
/// authorize query that mokosh-server's `/oauth2/authorize` produces on
/// a 302-to-login. Anything else returns `None` so this cannot be
/// abused as an open-redirect oracle.
///
/// The guard is intentionally narrow:
///   - the decoded value MUST begin with `response_type=`
///   - it MUST NOT contain CR or LF (header-splitting paranoia)
///   - it MUST contain `&client_id=` (so the downstream bounce has
///     somewhere to go)
///
/// We deliberately do not try to verify the client_id or redirect_uri
/// from the SPA: mokosh-server's authorize endpoint runs its own ACL
/// against the registered redirect_uris on the next hop, and replaying
/// that check client-side would need a synchronous client registry. The
/// SPA's job is to keep the value structurally sane; defense in depth
/// happens on the server.
fn read_safe_return_to() -> Option<String> {
    // Read from the search-string snapshot taken at program entry, NOT
    // from `window.location.search()` directly. The Dioxus router runs
    // `history.replaceState()` on mount to normalise the URL to its
    // declared route shape (no query params), which would erase
    // `?return_to=...` before this memo reads it. Without the snapshot
    // we'd silently treat every cross-RP /login arrival as a no-op
    // landing → bunyip dashboard instead of resuming the OIDC flow.
    let search = crate::modules::oidc::current_search();
    let params = web_sys::UrlSearchParams::new_with_str(&search).ok()?;
    let raw = params.get("return_to")?;
    if !is_safe_return_to(&raw) {
        return None;
    }
    Some(raw)
}

fn is_safe_return_to(s: &str) -> bool {
    if s.is_empty() || s.contains('\n') || s.contains('\r') {
        return false;
    }
    s.starts_with("response_type=") && s.contains("client_id=")
}

#[component]
pub fn LoginPage() -> Element {
    let nav = navigator();
    let toast = use_toast();
    let auth = use_auth();

    let mut state = use_signal(LoginState::default);
    let return_to = use_memo(read_safe_return_to);

    // Single-sign-on shortcut. If the user is already signed in
    // (either with an active session or a still-valid refresh chain
    // that use_auth_provider just exchanged for fresh tokens) and
    // they hit /login - typically via the SSO bridge from another
    // first-party RP - skip the form entirely and complete whatever
    // they were trying to do:
    //
    //   - return_to set → top-level navigate to ${issuer}/oauth2/authorize?<return_to>
    //     so mokosh-server can mint a code for the originating RP
    //     and 302 the user back there.
    //   - return_to absent → push them at the hub dashboard.
    //
    // While auth is still Loading we render the form's placeholder
    // (the use_effect re-fires on the next signal change).
    use_effect(move || {
        if matches!(*auth.read(), AuthState::SignedIn(_)) {
            if let Some(rt) = return_to.read().clone() {
                let cfg = OidcConfig::from_env();
                let url = format!("{}/oauth2/authorize?{}", cfg.issuer_trimmed(), rt);
                if let Some(win) = web_sys::window() {
                    let _ = win.location().replace(&url);
                }
            } else {
                nav.replace(Route::DashboardPage {});
            }
        }
    });

    let after_login = move |tokens: Tokens| {
        save_tokens(&tokens);
        let rt = return_to.read().clone();
        spawn(async move {
            refresh_auth(auth).await;
            if let Some(rt) = rt {
                let cfg = OidcConfig::from_env();
                let url = format!("{}/oauth2/authorize?{}", cfg.issuer_trimmed(), rt);
                if let Some(win) = web_sys::window() {
                    let _ = win.location().set_href(&url);
                }
            } else {
                nav.replace(Route::DashboardPage {});
            }
        });
    };

    let submit_password = move |evt: Event<FormData>| {
        evt.prevent_default();
        if state.read().submitting {
            return;
        }
        let email = state.read().email.clone();
        let password = state.read().password.clone();
        spawn(async move {
            state.with_mut(|s| {
                s.submitting = true;
                s.error = None;
            });
            let cfg = OidcConfig::from_env();
            let trust = read_trust_token();
            match oidc::password_login(&cfg, &email, &password, trust.as_deref()).await {
                Ok(LoginOutcome::Success(tokens)) => after_login(tokens),
                Ok(LoginOutcome::MfaRequired { challenge, .. }) => {
                    state.with_mut(|s| {
                        s.submitting = false;
                        s.mfa_challenge = Some(challenge);
                        s.mfa_code.clear();
                    });
                }
                Err(e) => {
                    let msg = friendly_login_error(&e);
                    state.with_mut(|s| {
                        s.submitting = false;
                        s.error = Some(msg.clone());
                    });
                    toast.error(msg);
                }
            }
        });
    };

    let submit_mfa = move || {
        if state.read().submitting {
            return;
        }
        let challenge = match state.read().mfa_challenge.clone() {
            Some(c) => c,
            None => return,
        };
        let code = state.read().mfa_code.trim().to_string();
        let remember = state.read().remember_device;
        spawn(async move {
            state.with_mut(|s| {
                s.submitting = true;
                s.error = None;
            });
            let cfg = OidcConfig::from_env();
            match oidc::mfa_verify(&cfg, &challenge, &code, remember).await {
                Ok(ok) => {
                    if let Some(t) = ok.trust_token.as_deref() {
                        write_trust_token(t);
                    }
                    after_login(ok.tokens);
                }
                Err(FlowError::TokenEndpoint { error, .. }) if error == "challenge_not_found" => {
                    state.with_mut(|s| {
                        s.submitting = false;
                        s.error = Some("Your code prompt expired. Sign in again.".into());
                        s.mfa_challenge = None;
                        s.mfa_code.clear();
                    });
                }
                Err(FlowError::TokenEndpoint { error, .. }) if error == "rate_limited" => {
                    state.with_mut(|s| {
                        s.submitting = false;
                        s.mfa_code.clear();
                        s.error = Some("Too many attempts. Wait a few minutes.".into());
                    });
                }
                Err(_) => {
                    state.with_mut(|s| {
                        s.submitting = false;
                        s.mfa_code.clear();
                        s.error = Some("That code didn't match. Try again.".into());
                    });
                }
            }
        });
    };

    let submit_mfa_form = move |evt: Event<FormData>| {
        evt.prevent_default();
        submit_mfa();
    };

    rsx! {
        AuthShell {
            title: "Welcome back",
            subtitle: "Sign in to your Bunyip account.",
            if state.read().mfa_challenge.is_some() {
                form { class: "space-y-4", onsubmit: submit_mfa_form,
                    p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                        "Enter the 6-digit code from your authenticator app, or paste a recovery code."
                    }
                    if let Some(err) = state.read().error.clone() {
                        InlineError { message: err }
                    }
                    AuthInput {
                        name: "mfa_code",
                        label: "Authenticator code",
                        input_type: "text",
                        placeholder: "123456",
                        value: state.read().mfa_code.clone(),
                        oninput: move |v: String| {
                            state.write().mfa_code = v.clone();
                            let trimmed = v.trim();
                            if trimmed.len() == 6
                                && trimmed.chars().all(|c| c.is_ascii_digit())
                                && !state.read().submitting
                            {
                                submit_mfa();
                            }
                        },
                    }
                    label { class: "flex items-center gap-2 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                        input {
                            r#type: "checkbox",
                            class: "h-4 w-4",
                            checked: state.read().remember_device,
                            onchange: move |e: Event<FormData>| {
                                state.write().remember_device = e.value() == "true";
                            },
                        }
                        "Trust this browser for 7 days"
                    }
                    SubmitButton { busy: state.read().submitting, label: "Verify" }
                    button {
                        r#type: "button",
                        class: "block w-full text-center text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300 hover:text-bunyip-reed-800",
                        onclick: move |_| {
                            state.with_mut(|s| {
                                s.mfa_challenge = None;
                                s.mfa_code.clear();
                                s.error = None;
                            });
                        },
                        "Cancel and sign in again"
                    }
                }
            } else {
                form { class: "space-y-4", onsubmit: submit_password,
                    if let Some(err) = state.read().error.clone() {
                        InlineError { message: err }
                    }
                    AuthInput {
                        name: "email",
                        label: "Email",
                        input_type: "email",
                        placeholder: "you@example.com",
                        value: state.read().email.clone(),
                        oninput: move |v: String| { state.write().email = v; },
                    }
                    AuthInput {
                        name: "password",
                        label: "Password",
                        input_type: "password",
                        placeholder: "",
                        value: state.read().password.clone(),
                        oninput: move |v: String| { state.write().password = v; },
                    }
                    SubmitButton { busy: state.read().submitting, label: "Sign in" }
                    div { class: "flex justify-between text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                        Link { to: Route::ForgotPasswordPage {}, class: "underline", "Forgot password?" }
                        Link { to: Route::SignupPage {}, class: "underline", "Create account" }
                    }
                }
            }
        }
    }
}

fn friendly_login_error(e: &FlowError) -> String {
    match e {
        FlowError::TokenEndpoint { error, description } => match error.as_str() {
            "rate_limited" => "Too many attempts. Wait a few minutes.".into(),
            "access_denied" | "invalid_grant" | "login_failed" => {
                "Email or password didn't match.".into()
            }
            _ if !description.is_empty() => description.clone(),
            _ => "Could not sign in. Please try again.".into(),
        },
        FlowError::Network(_) => "Network error. Check your connection.".into(),
        _ => "Could not sign in. Please try again.".into(),
    }
}

#[component]
pub fn SignupPage() -> Element {
    let toast = use_toast();
    let mut email = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut sent = use_signal(|| false);

    let submit = move |evt: Event<FormData>| {
        evt.prevent_default();
        if submitting() {
            return;
        }
        let value = email().trim().to_string();
        spawn(async move {
            submitting.set(true);
            match api::auth::signup_start(value).await {
                Ok(()) => {
                    sent.set(true);
                    toast.info("Check your email for a confirmation link.");
                }
                Err(e) => toast.error(e.user_message()),
            }
            submitting.set(false);
        });
    };

    rsx! {
        AuthShell {
            title: "Create your account",
            subtitle: "Enter your email; we'll send a confirmation link.",
            if sent() {
                p { class: "text-sm text-bunyip-reed-800 dark:text-bunyip-reed-100",
                    "If that email is registerable, we've sent a confirmation link. Click it to set your password."
                }
            } else {
                form { class: "space-y-4", onsubmit: submit,
                    AuthInput {
                        name: "email",
                        label: "Email",
                        input_type: "email",
                        placeholder: "you@example.com",
                        value: email(),
                        oninput: move |v: String| email.set(v),
                    }
                    SubmitButton { busy: submitting(), label: "Send link" }
                    p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 text-center",
                        "Already have an account? "
                        Link { to: Route::LoginPage {}, class: "underline", "Sign in" }
                    }
                }
            }
        }
    }
}

#[derive(Default, Clone, PartialEq)]
struct SignupCompleteState {
    first_name: String,
    last_name: String,
    password: String,
    submitting: bool,
    preview_loaded: bool,
    preview_email: Option<String>,
    error: Option<String>,
}

#[component]
pub fn SignupCompletePage(token: String) -> Element {
    let nav = navigator();
    let toast = use_toast();
    let mut state = use_signal(SignupCompleteState::default);

    let preview_token = token.clone();
    use_future(move || {
        let token = preview_token.clone();
        async move {
            match api::auth::signup_preview(&token).await {
                Ok(p) => state.with_mut(|s| {
                    s.preview_loaded = true;
                    s.preview_email = Some(p.email);
                }),
                Err(_) => state.with_mut(|s| {
                    s.preview_loaded = true;
                    s.error = Some("This link is invalid or has expired.".into());
                }),
            }
        }
    });

    let submit_token = token.clone();
    let submit = move |evt: Event<FormData>| {
        evt.prevent_default();
        if state.read().submitting {
            return;
        }
        let req = SignupCompleteRequest {
            password: state.read().password.clone(),
            first_name: Some(state.read().first_name.clone()).filter(|s| !s.trim().is_empty()),
            last_name: Some(state.read().last_name.clone()).filter(|s| !s.trim().is_empty()),
        };
        let token = submit_token.clone();
        spawn(async move {
            state.with_mut(|s| {
                s.submitting = true;
                s.error = None;
            });
            match api::auth::signup_complete(&token, &req).await {
                Ok(_) => {
                    toast.success("Account created. Sign in to continue.");
                    nav.replace(Route::LoginPage {});
                }
                Err(e) => state.with_mut(|s| {
                    s.submitting = false;
                    s.error = Some(e.user_message());
                }),
            }
        });
    };

    let subtitle = state.read().preview_email.clone().unwrap_or_default();
    rsx! {
        AuthShell {
            title: "Finish creating your account",
            subtitle: subtitle,
            match (state.read().preview_loaded, state.read().error.clone(), state.read().preview_email.is_some()) {
                (false, _, _) => rsx! { p { "Verifying link..." } },
                (true, Some(err), false) => rsx! { InlineError { message: err } },
                _ => {
                    let password = state.read().password.clone();
                    let email = state.read().preview_email.clone().unwrap_or_default();
                    let policy_ok = password_meets_policy(&password, &email);
                    let submitting = state.read().submitting;
                    rsx! {
                        form { class: "space-y-4", onsubmit: submit,
                            if let Some(err) = state.read().error.clone() {
                                InlineError { message: err }
                            }
                            AuthInput {
                                name: "first_name",
                                label: "First name",
                                input_type: "text",
                                placeholder: "",
                                value: state.read().first_name.clone(),
                                oninput: move |v: String| { state.write().first_name = v; },
                            }
                            AuthInput {
                                name: "last_name",
                                label: "Last name",
                                input_type: "text",
                                placeholder: "",
                                value: state.read().last_name.clone(),
                                oninput: move |v: String| { state.write().last_name = v; },
                            }
                            AuthInput {
                                name: "password",
                                label: "Password",
                                input_type: "password",
                                placeholder: "",
                                value: password.clone(),
                                oninput: move |v: String| { state.write().password = v; },
                            }
                            PasswordChecklist { password: password, email: email }
                            SubmitButton {
                                busy: submitting,
                                disabled: !policy_ok,
                                label: "Create account",
                            }
                        }
                    }
                },
            }
        }
    }
}

#[component]
pub fn ForgotPasswordPage() -> Element {
    let toast = use_toast();
    let mut email = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut sent = use_signal(|| false);

    let submit = move |evt: Event<FormData>| {
        evt.prevent_default();
        if submitting() {
            return;
        }
        let value = email().trim().to_string();
        spawn(async move {
            submitting.set(true);
            match api::auth::forgot_password(value).await {
                Ok(()) => {
                    sent.set(true);
                    toast.info("If that email is registered, we've sent reset instructions.");
                }
                Err(e) => toast.error(e.user_message()),
            }
            submitting.set(false);
        });
    };

    rsx! {
        AuthShell {
            title: "Reset your password",
            subtitle: "Tell us your email and we'll send a reset link.",
            if sent() {
                p { class: "text-sm text-bunyip-reed-800 dark:text-bunyip-reed-100",
                    "Check your email for the reset link."
                }
            } else {
                form { class: "space-y-4", onsubmit: submit,
                    AuthInput {
                        name: "email",
                        label: "Email",
                        input_type: "email",
                        placeholder: "you@example.com",
                        value: email(),
                        oninput: move |v: String| email.set(v),
                    }
                    SubmitButton { busy: submitting(), label: "Send reset link" }
                    p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 text-center",
                        Link { to: Route::LoginPage {}, class: "underline", "Back to sign in" }
                    }
                }
            }
        }
    }
}

#[derive(Default, Clone, PartialEq)]
struct ResetState {
    password: String,
    confirm: String,
    submitting: bool,
    preview_loaded: bool,
    preview_email: Option<String>,
    error: Option<String>,
}

#[component]
pub fn ResetPasswordPage(token: String) -> Element {
    let nav = navigator();
    let toast = use_toast();
    let mut state = use_signal(ResetState::default);

    let preview_token = token.clone();
    use_future(move || {
        let token = preview_token.clone();
        async move {
            match api::auth::reset_preview(&token).await {
                Ok(p) => state.with_mut(|s| {
                    s.preview_loaded = true;
                    s.preview_email = Some(p.email);
                }),
                Err(_) => state.with_mut(|s| {
                    s.preview_loaded = true;
                    s.error = Some("This link is invalid or has expired.".into());
                }),
            }
        }
    });

    let submit_token = token.clone();
    let submit = move |evt: Event<FormData>| {
        evt.prevent_default();
        if state.read().submitting {
            return;
        }
        if state.read().password != state.read().confirm {
            state.write().error = Some("Passwords do not match.".into());
            return;
        }
        let req = ResetCompleteRequest {
            password: state.read().password.clone(),
            password_confirmation: state.read().confirm.clone(),
        };
        let token = submit_token.clone();
        spawn(async move {
            state.with_mut(|s| {
                s.submitting = true;
                s.error = None;
            });
            match api::auth::reset_complete(&token, &req).await {
                Ok(_) => {
                    toast.success("Password updated. Sign in with your new password.");
                    nav.replace(Route::LoginPage {});
                }
                Err(e) => state.with_mut(|s| {
                    s.submitting = false;
                    s.error = Some(e.user_message());
                }),
            }
        });
    };

    let subtitle = state.read().preview_email.clone().unwrap_or_default();
    rsx! {
        AuthShell {
            title: "Choose a new password",
            subtitle: subtitle,
            match (state.read().preview_loaded, state.read().preview_email.is_some()) {
                (false, _) => rsx! { p { "Verifying link..." } },
                (true, false) => rsx! {
                    InlineError {
                        message: state.read().error.clone().unwrap_or_else(|| "This link is invalid or has expired.".into())
                    }
                },
                _ => {
                    let password = state.read().password.clone();
                    let confirm = state.read().confirm.clone();
                    let email = state.read().preview_email.clone().unwrap_or_default();
                    let policy_ok = password_meets_policy(&password, &email);
                    let confirm_matches = !confirm.is_empty() && password == confirm;
                    let submitting = state.read().submitting;
                    rsx! {
                        form { class: "space-y-4", onsubmit: submit,
                            if let Some(err) = state.read().error.clone() {
                                InlineError { message: err }
                            }
                            AuthInput {
                                name: "password",
                                label: "New password",
                                input_type: "password",
                                placeholder: "",
                                value: password.clone(),
                                oninput: move |v: String| { state.write().password = v; },
                            }
                            AuthInput {
                                name: "confirm",
                                label: "Confirm password",
                                input_type: "password",
                                placeholder: "",
                                value: confirm.clone(),
                                oninput: move |v: String| { state.write().confirm = v; },
                            }
                            PasswordChecklist { password: password, email: email }
                            SubmitButton {
                                busy: submitting,
                                disabled: !(policy_ok && confirm_matches),
                                label: "Save password",
                            }
                        }
                    }
                },
            }
        }
    }
}

// --- Compat shims so the existing routes/login-totp etc. still compile.
//   The route components themselves get pruned in routes.rs below to
//   one-line redirects.

#[component]
pub fn LoginTotpPage() -> Element {
    let nav = navigator();
    use_effect(move || {
        nav.replace(Route::LoginPage {});
    });
    rsx! { p { class: "p-8 text-sm text-bunyip-reed-500", "Redirecting to sign in..." } }
}

#[component]
pub fn MagicLinkPage() -> Element {
    let nav = navigator();
    use_effect(move || {
        nav.replace(Route::LoginPage {});
    });
    rsx! { p { class: "p-8 text-sm text-bunyip-reed-500", "Redirecting to sign in..." } }
}

#[component]
pub fn VerifyEmailPage() -> Element {
    let nav = navigator();
    use_effect(move || {
        nav.replace(Route::LoginPage {});
    });
    rsx! { p { class: "p-8 text-sm text-bunyip-reed-500", "Redirecting to sign in..." } }
}

// --- Components -----------------------------------------------------

#[component]
fn AuthInput(
    name: &'static str,
    label: &'static str,
    input_type: &'static str,
    placeholder: &'static str,
    value: String,
    oninput: EventHandler<String>,
) -> Element {
    rsx! {
        label { class: "block",
            span { class: "text-sm font-medium text-bunyip-reed-800 dark:text-bunyip-reed-100", "{label}" }
            input {
                class: "mt-1 w-full px-3 py-2 rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600 dark:focus:ring-bunyip-reed-400",
                name: "{name}",
                r#type: "{input_type}",
                placeholder: "{placeholder}",
                value: "{value}",
                autocomplete: "on",
                oninput: move |evt| oninput.call(evt.value()),
            }
        }
    }
}

#[component]
fn SubmitButton(
    busy: bool,
    label: &'static str,
    #[props(default = false)] disabled: bool,
) -> Element {
    rsx! {
        button {
            class: "w-full px-4 py-2.5 rounded-lg bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 disabled:opacity-60 disabled:cursor-not-allowed transition-colors",
            r#type: "submit",
            disabled: busy || disabled,
            if busy { "Working..." } else { "{label}" }
        }
    }
}

#[component]
fn InlineError(message: String) -> Element {
    rsx! {
        div { class: "rounded p-3 text-sm bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-200",
            "{message}"
        }
    }
}
