//! Auth pages wired to the mock backend. Signup creates a user + org and
//! drops a verification link in the dev logs. Login uses `MOCK_PASSWORD`.

use dioxus::prelude::*;

use crate::api::{self, auth::*};
use crate::components::layout::AuthShell;
use crate::routes::Route;
use crate::stores::auth::{refresh_auth, use_auth};
use crate::stores::toast::use_toast;

#[component]
pub fn SignupPage() -> Element {
    let nav = navigator();
    let toast = use_toast();
    let auth = use_auth();

    let mut name = use_signal(String::new);
    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut org_name = use_signal(String::new);
    let mut submitting = use_signal(|| false);

    let submit = move |evt: Event<FormData>| {
        evt.prevent_default();
        if submitting() {
            return;
        }
        let req = SignupRequest {
            name: name(),
            email: email(),
            password: password(),
            org_name: org_name(),
        };
        spawn(async move {
            submitting.set(true);
            match api::auth::signup(&req).await {
                Ok(resp) => {
                    toast.success(format!("Welcome {}! Check the dev log for your verification email.", resp.user.name));
                    refresh_auth(auth).await;
                    nav.replace(Route::DashboardPage {});
                }
                Err(e) => toast.error(e.user_message()),
            }
            submitting.set(false);
        });
    };

    rsx! {
        AuthShell {
            title: "Create your Bunyip account",
            subtitle: "Get the team onboarded. We'll set up your organization automatically.",
            form { class: "space-y-4", onsubmit: submit,
                AuthInput { name: "name", label: "Full name", input_type: "text", placeholder: "Ada Lovelace", value: name() , oninput: move |v| name.set(v) }
                AuthInput { name: "email", label: "Work email", input_type: "email", placeholder: "you@example.com", value: email(), oninput: move |v| email.set(v) }
                AuthInput { name: "password", label: "Password", input_type: "password", placeholder: "demo", value: password(), oninput: move |v| password.set(v) }
                AuthInput { name: "org", label: "Organization name", input_type: "text", placeholder: "Example MSP", value: org_name(), oninput: move |v| org_name.set(v) }
                SubmitButton { busy: submitting(), label: "Create account" }
                p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 text-center",
                    "Already have an account? "
                    Link { to: Route::LoginPage {}, class: "underline", "Sign in" }
                }
            }
        }
    }
}

#[component]
pub fn LoginPage() -> Element {
    let nav = navigator();
    let toast = use_toast();
    let auth = use_auth();

    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut submitting = use_signal(|| false);

    let submit = move |evt: Event<FormData>| {
        evt.prevent_default();
        if submitting() {
            return;
        }
        let req = LoginRequest {
            email: email(),
            password: password(),
        };
        spawn(async move {
            submitting.set(true);
            match api::auth::login(&req).await {
                Ok(resp) if resp.requires_mfa => {
                    toast.info("Enter your 6-digit code to continue.");
                    nav.push(Route::LoginTotpPage {});
                }
                Ok(_) => {
                    toast.success("Welcome back.");
                    refresh_auth(auth).await;
                    nav.replace(Route::DashboardPage {});
                }
                Err(e) => toast.error(e.user_message()),
            }
            submitting.set(false);
        });
    };

    rsx! {
        AuthShell {
            title: "Welcome back",
            subtitle: "Sign in to your Bunyip account.",
            form { class: "space-y-4", onsubmit: submit,
                AuthInput { name: "email", label: "Email", input_type: "email", placeholder: "owner@example.com", value: email(), oninput: move |v| email.set(v) }
                AuthInput { name: "password", label: "Password", input_type: "password", placeholder: "demo", value: password(), oninput: move |v| password.set(v) }
                SubmitButton { busy: submitting(), label: "Sign in" }
                div { class: "flex justify-between text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                    Link { to: Route::MagicLinkPage {}, class: "underline", "Email me a magic link" }
                    Link { to: Route::ForgotPasswordPage {}, class: "underline", "Forgot password?" }
                }
                p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 text-center",
                    "No account? "
                    Link { to: Route::SignupPage {}, class: "underline", "Sign up" }
                }
            }
        }
    }
}

#[component]
pub fn LoginTotpPage() -> Element {
    let nav = navigator();
    let toast = use_toast();
    let auth = use_auth();
    let mut code = use_signal(String::new);
    let mut submitting = use_signal(|| false);

    let submit = move |evt: Event<FormData>| {
        evt.prevent_default();
        if submitting() {
            return;
        }
        let value = code();
        spawn(async move {
            submitting.set(true);
            match totp_verify(value).await {
                Ok(user) => {
                    toast.success(format!("Welcome back, {}.", user.name));
                    refresh_auth(auth).await;
                    nav.replace(Route::DashboardPage {});
                }
                Err(e) => toast.error(e.user_message()),
            }
            submitting.set(false);
        });
    };

    rsx! {
        AuthShell {
            title: "Two-factor code",
            subtitle: "Enter the 6-digit code from your authenticator app. (Dev: any 6 digits work.)",
            form { class: "space-y-4", onsubmit: submit,
                AuthInput { name: "code", label: "Code", input_type: "text", placeholder: "000000", value: code(), oninput: move |v| code.set(v) }
                SubmitButton { busy: submitting(), label: "Verify" }
            }
        }
    }
}

#[component]
pub fn MagicLinkPage() -> Element {
    let toast = use_toast();
    let mut email = use_signal(String::new);
    let mut submitting = use_signal(|| false);
    let mut sent = use_signal(|| false);

    let submit = move |evt: Event<FormData>| {
        evt.prevent_default();
        if submitting() {
            return;
        }
        let value = email();
        spawn(async move {
            submitting.set(true);
            match magic_link_request(value).await {
                Ok(()) => {
                    sent.set(true);
                    toast.info("Magic link sent. Check the dev log for the click-through URL.");
                }
                Err(e) => toast.error(e.user_message()),
            }
            submitting.set(false);
        });
    };

    rsx! {
        AuthShell {
            title: "Sign in with magic link",
            subtitle: "We'll email you a one-time link.",
            if sent() {
                div { class: "text-sm text-bunyip-reed-800 dark:text-bunyip-reed-100",
                    p { "Check the dev container logs:" }
                    pre { class: "mt-2 p-3 rounded bg-bunyip-reed-50 dark:bg-bunyip-reed-900 text-xs overflow-x-auto",
                        "docker logs dev-bunyip-api-$USER | grep magic-link"
                    }
                    p { class: "mt-3",
                        "Click the printed URL to sign in."
                    }
                }
            } else {
                form { class: "space-y-4", onsubmit: submit,
                    AuthInput { name: "email", label: "Email", input_type: "email", placeholder: "owner@example.com", value: email(), oninput: move |v| email.set(v) }
                    SubmitButton { busy: submitting(), label: "Send link" }
                    p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 text-center",
                        Link { to: Route::LoginPage {}, class: "underline", "Back to sign in" }
                    }
                }
            }
        }
    }
}

#[component]
pub fn VerifyEmailPage() -> Element {
    let toast = use_toast();
    let mut state = use_signal(|| VerifyState::Idle);

    let token = use_memo(|| {
        web_sys::window()
            .and_then(|w| w.location().search().ok())
            .and_then(|s| {
                let qs = s.trim_start_matches('?').to_string();
                qs.split('&')
                    .find_map(|p| p.strip_prefix("token=").map(|t| t.to_string()))
            })
    });

    use_effect(move || {
        let t = token();
        if let Some(t) = t {
            spawn(async move {
                state.set(VerifyState::Working);
                match verify_email(t).await {
                    Ok(()) => {
                        state.set(VerifyState::Verified);
                        toast.success("Email verified.");
                    }
                    Err(e) => {
                        state.set(VerifyState::Failed(e.user_message()));
                    }
                }
            });
        } else {
            state.set(VerifyState::NoToken);
        }
    });

    rsx! {
        AuthShell {
            title: "Verify your email",
            subtitle: "We're confirming the link you clicked.",
            div { class: "text-sm text-bunyip-reed-800 dark:text-bunyip-reed-100",
                match state() {
                    VerifyState::Idle | VerifyState::Working => rsx! { p { "Verifying…" } },
                    VerifyState::Verified => rsx! {
                        p { "Your email is verified. " }
                        Link { to: Route::DashboardPage {}, class: "underline mt-2 inline-block", "Continue to dashboard" }
                    },
                    VerifyState::NoToken => rsx! { p { class: "text-bunyip-reed-900 dark:text-bunyip-reed-100", "Missing or invalid verification link." } },
                    VerifyState::Failed(msg) => rsx! { p { class: "text-red-700", "{msg}" } },
                }
            }
        }
    }
}

#[derive(Clone, PartialEq)]
enum VerifyState {
    Idle,
    Working,
    Verified,
    NoToken,
    Failed(String),
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
        let value = email();
        spawn(async move {
            submitting.set(true);
            match forgot_password(value).await {
                Ok(()) => {
                    sent.set(true);
                    toast.info("If an account exists for that email, we've sent reset instructions.");
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
                    "Check the dev logs for the reset link if you used a seeded email."
                }
            } else {
                form { class: "space-y-4", onsubmit: submit,
                    AuthInput { name: "email", label: "Email", input_type: "email", placeholder: "owner@example.com", value: email(), oninput: move |v| email.set(v) }
                    SubmitButton { busy: submitting(), label: "Send reset link" }
                }
            }
        }
    }
}

#[component]
pub fn ResetPasswordPage() -> Element {
    rsx! {
        AuthShell {
            title: "Choose a new password",
            subtitle: "Pick something strong.",
            form { class: "space-y-4",
                AuthInput { name: "password", label: "New password", input_type: "password", placeholder: "", value: String::new(), oninput: move |_| {} }
                AuthInput { name: "confirm", label: "Confirm password", input_type: "password", placeholder: "", value: String::new(), oninput: move |_| {} }
                SubmitButton { busy: false, label: "Save password" }
                p { class: "text-xs text-bunyip-reed-600 dark:text-bunyip-reed-300",
                    "(Phase 3c wires this up to the mock backend.)"
                }
            }
        }
    }
}

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
fn SubmitButton(busy: bool, label: &'static str) -> Element {
    rsx! {
        button {
            class: "w-full px-4 py-2.5 rounded-lg bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 disabled:opacity-60 disabled:cursor-not-allowed transition-colors",
            r#type: "submit",
            disabled: busy,
            if busy { "Working…" } else { "{label}" }
        }
    }
}
