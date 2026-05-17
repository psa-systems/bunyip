//! `/settings/security` - TOTP MFA + recovery codes.
//!
//! State machine on `/v1/auth/mfa/status`:
//!   - Loading - first fetch.
//!   - Disabled - "Enable two-factor" button.
//!   - Enrolling - three sub-steps: ScanQr / ConfirmCode / SaveCodes.
//!   - Enrolled - shows recovery_codes_unused; Regenerate + Disable
//!     gated by an inline step-up flow.

use dioxus::prelude::*;
use serde::Deserialize;

use crate::components::layout::AppShell;
use crate::modules::oidc::{self, OidcConfig};
use crate::pages::profile::{
    DangerButton, InlineMessage, MessageKind, PrimaryButton, SecondaryButton, SettingsCard,
};
use crate::routes::Route;
use crate::stores::auth::{use_auth, AuthState};

#[derive(Clone, Debug, Deserialize)]
struct StatusBody {
    mfa_enrolled: bool,
    #[serde(default)]
    recovery_codes_unused: u32,
    #[serde(default)]
    low_warning: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct SetupBody {
    secret: String,
    #[allow(dead_code)]
    provisioning_uri: String,
    qr_svg: String,
    recovery_codes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ChallengeBody {
    challenge: String,
}

#[derive(Clone, Debug, Deserialize)]
struct StepUpTokenBody {
    step_up_token: String,
}

#[derive(Clone, Debug, Deserialize)]
struct RegenerateBody {
    recovery_codes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
enum EnrollStep {
    ScanQr,
    ConfirmCode,
    SaveCodes,
}

#[derive(Clone, PartialEq)]
struct EnrollmentInProgress {
    setup: SetupBody,
    step: EnrollStep,
    code_input: String,
    confirm_error: Option<String>,
    submitting: bool,
}

#[derive(Clone, PartialEq)]
struct InlineNotice {
    message: String,
    severity: NoticeSeverity,
}

#[derive(Clone, Copy, PartialEq)]
enum NoticeSeverity {
    Info,
    Error,
}

#[derive(Clone, PartialEq)]
struct StepUpInProgress {
    challenge: String,
    code_input: String,
    error: Option<String>,
    submitting: bool,
    intent: StepUpIntent,
}

#[derive(Clone, Copy, PartialEq)]
enum StepUpIntent {
    Regenerate,
    Disable,
}

#[component]
pub fn SecurityPage() -> Element {
    let nav = navigator();
    let auth = use_auth();
    use_effect(move || {
        if matches!(*auth.read(), AuthState::SignedOut) {
            nav.replace(Route::LoginPage {});
        }
    });

    let mut status: Signal<Option<Result<StatusBody, String>>> = use_signal(|| None);
    let mut enrollment: Signal<Option<EnrollmentInProgress>> = use_signal(|| None);
    let mut step_up: Signal<Option<StepUpInProgress>> = use_signal(|| None);
    let mut fresh_codes: Signal<Option<Vec<String>>> = use_signal(|| None);
    let mut notice: Signal<Option<InlineNotice>> = use_signal(|| None);
    let mut bump = use_signal(|| 0u32);

    use_future(move || async move {
        let _ = bump.read();
        status.set(None);
        let cfg = OidcConfig::from_env();
        let r = oidc::issuer_get_authed::<StatusBody>(&cfg, "/v1/auth/mfa/status")
            .await
            .map_err(|e| e.to_string());
        status.set(Some(r));
    });

    let refetch = use_callback(move |_| bump.with_mut(|n| *n += 1));

    let start_enroll = use_callback(move |_| {
        spawn(async move {
            notice.set(None);
            let cfg = OidcConfig::from_env();
            let r = oidc::issuer_post_authed::<SetupBody, _>(
                &cfg,
                "/v1/auth/mfa/setup",
                &serde_json::json!({}),
            )
            .await;
            match r {
                Ok(setup) => enrollment.set(Some(EnrollmentInProgress {
                    setup,
                    step: EnrollStep::ScanQr,
                    code_input: String::new(),
                    confirm_error: None,
                    submitting: false,
                })),
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("already_enrolled") {
                        notice.set(Some(InlineNotice {
                            message:
                                "Two-factor was already enabled on this account; refreshing status."
                                    .into(),
                            severity: NoticeSeverity::Info,
                        }));
                        bump.with_mut(|n| *n += 1);
                    } else {
                        notice.set(Some(InlineNotice {
                            message: format!("Could not start enrollment: {msg}"),
                            severity: NoticeSeverity::Error,
                        }));
                    }
                }
            }
        });
    });

    let submit_confirm = use_callback(move |_| {
        let enr = match enrollment.read().clone() {
            Some(e) if e.step == EnrollStep::ConfirmCode => e,
            _ => return,
        };
        spawn(async move {
            enrollment.with_mut(|e| {
                if let Some(e) = e.as_mut() {
                    e.submitting = true;
                    e.confirm_error = None;
                }
            });
            let cfg = OidcConfig::from_env();
            let r = oidc::issuer_post_authed::<serde_json::Value, _>(
                &cfg,
                "/v1/auth/mfa/confirm",
                &serde_json::json!({"code": enr.code_input.trim()}),
            )
            .await;
            match r {
                Ok(_) => enrollment.with_mut(|e| {
                    if let Some(e) = e.as_mut() {
                        e.step = EnrollStep::SaveCodes;
                        e.submitting = false;
                    }
                }),
                Err(e) => enrollment.with_mut(|en| {
                    if let Some(en) = en.as_mut() {
                        en.submitting = false;
                        en.confirm_error = Some(format!("Code rejected: {e}"));
                    }
                }),
            }
        });
    });

    let finish_enrollment = use_callback(move |_| {
        enrollment.set(None);
        refetch.call(());
    });

    let start_step_up = use_callback(move |intent: StepUpIntent| {
        spawn(async move {
            let cfg = OidcConfig::from_env();
            let r = oidc::issuer_post_authed::<ChallengeBody, _>(
                &cfg,
                "/v1/auth/mfa/step-up/start",
                &serde_json::json!({}),
            )
            .await;
            match r {
                Ok(c) => step_up.set(Some(StepUpInProgress {
                    challenge: c.challenge,
                    code_input: String::new(),
                    error: None,
                    submitting: false,
                    intent,
                })),
                Err(e) => step_up.set(Some(StepUpInProgress {
                    challenge: String::new(),
                    code_input: String::new(),
                    error: Some(format!("{e}")),
                    submitting: false,
                    intent,
                })),
            }
        });
    });

    let submit_step_up = use_callback(move |_| {
        let su = match step_up.read().clone() {
            Some(s) if !s.challenge.is_empty() => s,
            _ => return,
        };
        spawn(async move {
            step_up.with_mut(|s| {
                if let Some(s) = s.as_mut() {
                    s.submitting = true;
                    s.error = None;
                }
            });
            let cfg = OidcConfig::from_env();
            let verify = oidc::issuer_post_authed::<StepUpTokenBody, _>(
                &cfg,
                "/v1/auth/mfa/step-up/verify",
                &serde_json::json!({"challenge": su.challenge, "code": su.code_input.trim()}),
            )
            .await;
            let token = match verify {
                Ok(t) => t.step_up_token,
                Err(e) => {
                    step_up.with_mut(|s| {
                        if let Some(s) = s.as_mut() {
                            s.submitting = false;
                            s.error = Some(format!("{e}"));
                        }
                    });
                    return;
                }
            };
            match su.intent {
                StepUpIntent::Regenerate => {
                    let r = oidc::issuer_post_authed::<RegenerateBody, _>(
                        &cfg,
                        "/v1/auth/mfa/recovery-codes/regenerate",
                        &serde_json::json!({"step_up_token": token}),
                    )
                    .await;
                    match r {
                        Ok(b) => {
                            fresh_codes.set(Some(b.recovery_codes));
                            step_up.set(None);
                            refetch.call(());
                        }
                        Err(e) => step_up.with_mut(|s| {
                            if let Some(s) = s.as_mut() {
                                s.submitting = false;
                                s.error = Some(format!("regenerate: {e}"));
                            }
                        }),
                    }
                }
                StepUpIntent::Disable => {
                    let r = oidc::issuer_post_authed::<serde_json::Value, _>(
                        &cfg,
                        "/v1/auth/mfa/disable",
                        &serde_json::json!({"step_up_token": token}),
                    )
                    .await;
                    match r {
                        Ok(_) => {
                            step_up.set(None);
                            fresh_codes.set(None);
                            refetch.call(());
                        }
                        Err(e) => step_up.with_mut(|s| {
                            if let Some(s) = s.as_mut() {
                                s.submitting = false;
                                s.error = Some(format!("disable: {e}"));
                            }
                        }),
                    }
                }
            }
        });
    });

    rsx! {
        AppShell {
            title: "Security".to_string(),
            back_to: Some(Route::SettingsPage {}),
            back_label: "Settings".to_string(),
            div { class: "max-w-2xl mx-auto px-6 space-y-6",
                h1 { class: "text-3xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50", "Security" }
                p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                    "Two-factor authentication and recovery codes."
                }

                SettingsCard { title: "Two-factor authentication",
                    if let Some(n) = notice.read().clone() {
                        InlineMessage {
                            kind: match n.severity {
                                NoticeSeverity::Info => MessageKind::Info,
                                NoticeSeverity::Error => MessageKind::Error,
                            },
                            text: n.message,
                        }
                    }
                    match &*status.read() {
                        None => rsx! {
                            p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300", "Loading..." }
                        },
                        Some(Err(e)) => rsx! {
                            p { class: "text-sm text-red-600", "Failed to load: {e}" }
                        },
                        Some(Ok(s)) => {
                            if let Some(codes) = fresh_codes.read().clone() {
                                rsx! { RecoveryCodesView { codes: codes, on_done: move |_| fresh_codes.set(None) } }
                            } else if let Some(en) = enrollment.read().clone() {
                                rsx! {
                                    EnrollmentFlow {
                                        enrollment: en.clone(),
                                        on_continue_to_confirm: move |_| {
                                            enrollment.with_mut(|e| if let Some(e) = e.as_mut() { e.step = EnrollStep::ConfirmCode; });
                                        },
                                        on_code_input: move |v: String| {
                                            enrollment.with_mut(|e| if let Some(e) = e.as_mut() { e.code_input = v; });
                                        },
                                        on_submit_confirm: move |_| submit_confirm.call(()),
                                        on_finish: move |_| finish_enrollment.call(()),
                                    }
                                }
                            } else if let Some(su) = step_up.read().clone() {
                                rsx! {
                                    StepUpPrompt {
                                        step_up: su.clone(),
                                        on_code_input: move |v: String| {
                                            step_up.with_mut(|s| if let Some(s) = s.as_mut() { s.code_input = v; });
                                        },
                                        on_submit: move |_| submit_step_up.call(()),
                                        on_cancel: move |_| step_up.set(None),
                                    }
                                }
                            } else if s.mfa_enrolled {
                                rsx! {
                                    div { class: "space-y-4",
                                        p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                            "Two-factor authentication is "
                                            span { class: "font-medium text-green-600 dark:text-green-400", "enabled" }
                                            "."
                                        }
                                        p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                            "{s.recovery_codes_unused} recovery codes remaining."
                                            if s.low_warning {
                                                span { class: "ml-2 text-yellow-700 dark:text-yellow-400 font-medium", "Low; regenerate now." }
                                            }
                                        }
                                        div { class: "flex gap-2",
                                            SecondaryButton {
                                                label: "Regenerate recovery codes".to_string(),
                                                onclick: move |_| start_step_up.call(StepUpIntent::Regenerate),
                                            }
                                            DangerButton {
                                                label: "Disable two-factor".to_string(),
                                                onclick: move |_| start_step_up.call(StepUpIntent::Disable),
                                            }
                                        }
                                    }
                                }
                            } else {
                                rsx! {
                                    div { class: "space-y-4",
                                        p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                                            "Two-factor authentication is "
                                            span { class: "font-medium", "off" }
                                            ". Enable it to add a second factor (TOTP) to your sign-in."
                                        }
                                        button {
                                            r#type: "button",
                                            class: "px-4 py-2 rounded-lg bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 transition-colors",
                                            onclick: move |_| start_enroll.call(()),
                                            "Enable two-factor"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct EnrollmentFlowProps {
    enrollment: EnrollmentInProgress,
    on_continue_to_confirm: EventHandler<()>,
    on_code_input: EventHandler<String>,
    on_submit_confirm: EventHandler<()>,
    on_finish: EventHandler<()>,
}

#[component]
fn EnrollmentFlow(props: EnrollmentFlowProps) -> Element {
    let en = &props.enrollment;
    match en.step {
        EnrollStep::ScanQr => rsx! {
            div { class: "space-y-4",
                p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                    "Scan this QR with your authenticator app (Aegis, Bitwarden, 1Password, Google Authenticator)."
                }
                div {
                    class: "mx-auto bg-white p-3 rounded-lg",
                    style: "max-width: 256px;",
                    dangerous_inner_html: "{en.setup.qr_svg}",
                }
                details { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                    summary { class: "cursor-pointer", "Cannot scan? Type the code instead" }
                    p { class: "text-xs font-mono mt-2 break-all", "{en.setup.secret}" }
                }
                button {
                    r#type: "button",
                    class: "px-4 py-2 rounded-lg bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 transition-colors",
                    onclick: move |_| props.on_continue_to_confirm.call(()),
                    "I've added the code; continue"
                }
            }
        },
        EnrollStep::ConfirmCode => rsx! {
            form {
                class: "space-y-4",
                onsubmit: move |e: Event<FormData>| {
                    e.prevent_default();
                    props.on_submit_confirm.call(());
                },
                p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                    "Enter the 6-digit code your authenticator is currently showing."
                }
                if let Some(err) = en.confirm_error.clone() {
                    InlineMessage { kind: MessageKind::Error, text: err }
                }
                input {
                    r#type: "text",
                    class: "block w-full px-3 py-2 rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600 dark:focus:ring-bunyip-reed-400 text-lg tracking-wider font-mono",
                    placeholder: "123456",
                    value: "{en.code_input}",
                    oninput: move |e: Event<FormData>| props.on_code_input.call(e.value()),
                }
                PrimaryButton { busy: en.submitting, label: "Verify and enable" }
            }
        },
        EnrollStep::SaveCodes => rsx! {
            div { class: "space-y-4",
                p { class: "text-sm font-medium text-bunyip-reed-800 dark:text-bunyip-reed-100",
                    "Save these recovery codes somewhere safe. Each one works once. You will not see them again."
                }
                ul { class: "grid grid-cols-2 gap-2 font-mono text-sm",
                    for code in en.setup.recovery_codes.iter() {
                        li { class: "bg-bunyip-reed-50 dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 px-2 py-1 rounded",
                            "{code}"
                        }
                    }
                }
                button {
                    r#type: "button",
                    class: "px-4 py-2 rounded-lg bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 transition-colors",
                    onclick: move |_| props.on_finish.call(()),
                    "I've saved them"
                }
            }
        },
    }
}

#[derive(Props, Clone, PartialEq)]
struct StepUpPromptProps {
    step_up: StepUpInProgress,
    on_code_input: EventHandler<String>,
    on_submit: EventHandler<()>,
    on_cancel: EventHandler<()>,
}

#[component]
fn StepUpPrompt(props: StepUpPromptProps) -> Element {
    let su = &props.step_up;
    rsx! {
        form {
            class: "space-y-4",
            onsubmit: move |e: Event<FormData>| {
                e.prevent_default();
                props.on_submit.call(());
            },
            p { class: "text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
                "Enter the 6-digit code from your authenticator to continue."
            }
            if let Some(err) = su.error.clone() {
                InlineMessage { kind: MessageKind::Error, text: err }
            }
            input {
                r#type: "text",
                class: "block w-full px-3 py-2 rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600 dark:focus:ring-bunyip-reed-400 text-lg tracking-wider font-mono",
                placeholder: "123456",
                value: "{su.code_input}",
                oninput: move |e: Event<FormData>| props.on_code_input.call(e.value()),
            }
            div { class: "flex gap-2",
                PrimaryButton { busy: su.submitting, label: "Continue" }
                SecondaryButton {
                    label: "Cancel".to_string(),
                    onclick: move |_| props.on_cancel.call(()),
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct RecoveryCodesViewProps {
    codes: Vec<String>,
    on_done: EventHandler<()>,
}

#[component]
fn RecoveryCodesView(props: RecoveryCodesViewProps) -> Element {
    rsx! {
        div { class: "space-y-4",
            p { class: "text-sm font-medium text-bunyip-reed-800 dark:text-bunyip-reed-100",
                "Save these recovery codes somewhere safe. Each one works once. You will not see them again."
            }
            ul { class: "grid grid-cols-2 gap-2 font-mono text-sm",
                for code in props.codes.iter() {
                    li { class: "bg-bunyip-reed-50 dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 px-2 py-1 rounded",
                        "{code}"
                    }
                }
            }
            button {
                r#type: "button",
                class: "px-4 py-2 rounded-lg bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 transition-colors",
                onclick: move |_| props.on_done.call(()),
                "Done"
            }
        }
    }
}
