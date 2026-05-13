//! `/settings/profile` - Profile + Change password.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::api;
use crate::components::layout::AppShell;
use crate::modules::oidc::{self, OidcConfig};
use crate::routes::Route;
use crate::stores::auth::{use_auth, AuthState};

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct MeBody {
    email: String,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
    #[serde(default)]
    mfa_enrolled: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
struct UpdateProfileBody {
    first_name: Option<String>,
    last_name: Option<String>,
    timezone: String,
    avatar_url: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct ProfileFormState {
    first_name: String,
    last_name: String,
    timezone: String,
    avatar_url: String,
    saving: bool,
    saved: bool,
    error: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct PasswordFormState {
    current_password: String,
    new_password: String,
    password_confirmation: String,
    submitting: bool,
    success: bool,
    error: Option<String>,
}

#[component]
pub fn ProfilePage() -> Element {
    let nav = navigator();
    let auth = use_auth();

    // Redirect to /login if signed out.
    use_effect(move || {
        if matches!(*auth.read(), AuthState::SignedOut) {
            nav.replace(Route::LoginPage {});
        }
    });

    let mut me: Signal<Option<Result<MeBody, String>>> = use_signal(|| None);
    let mut profile: Signal<ProfileFormState> = use_signal(ProfileFormState::default);
    let mut password: Signal<PasswordFormState> = use_signal(PasswordFormState::default);
    let mut bump = use_signal(|| 0u32);

    use_future(move || async move {
        let _ = bump.read();
        me.set(None);
        let cfg = OidcConfig::from_env();
        let r = oidc::issuer_get_authed::<MeBody>(&cfg, "/v1/auth/me")
            .await
            .map_err(|e| e.to_string());
        if let Ok(b) = &r {
            profile.set(ProfileFormState {
                first_name: b.first_name.clone().unwrap_or_default(),
                last_name: b.last_name.clone().unwrap_or_default(),
                timezone: b.timezone.clone().unwrap_or_default(),
                avatar_url: b.avatar_url.clone().unwrap_or_default(),
                ..ProfileFormState::default()
            });
        }
        me.set(Some(r));
    });

    let save_profile = use_callback(move |_| {
        let p = profile.read().clone();
        spawn(async move {
            profile.with_mut(|p| {
                p.saving = true;
                p.saved = false;
                p.error = None;
            });
            let body = UpdateProfileBody {
                first_name: option_from_str(&p.first_name),
                last_name: option_from_str(&p.last_name),
                timezone: if p.timezone.trim().is_empty() {
                    "UTC".to_string()
                } else {
                    p.timezone.trim().to_string()
                },
                avatar_url: option_from_str(&p.avatar_url),
            };
            let r = api::put_authed::<_, serde_json::Value>("/v1/auth/me/profile", &body).await;
            profile.with_mut(|s| {
                s.saving = false;
                match r {
                    Ok(_) => {
                        s.saved = true;
                        s.error = None;
                    }
                    Err(e) => {
                        s.saved = false;
                        s.error = Some(e.user_message());
                    }
                }
            });
            bump.with_mut(|n| *n += 1);
        });
    });

    let submit_password = use_callback(move |_| {
        let p = password.read().clone();
        spawn(async move {
            password.with_mut(|s| {
                s.submitting = true;
                s.success = false;
                s.error = None;
            });
            let r = api::post_authed::<serde_json::Value, serde_json::Value>(
                "/v1/auth/me/password",
                &serde_json::json!({
                    "current_password": p.current_password,
                    "new_password": p.new_password,
                    "password_confirmation": p.password_confirmation,
                }),
            )
            .await;
            password.with_mut(|s| {
                s.submitting = false;
                match r {
                    Ok(_) => {
                        s.success = true;
                        s.error = None;
                        s.current_password.clear();
                        s.new_password.clear();
                        s.password_confirmation.clear();
                    }
                    Err(e) => {
                        s.success = false;
                        s.error = Some(e.user_message());
                    }
                }
            });
        });
    });

    rsx! {
        AppShell { title: "Profile".to_string(),
            div { class: "max-w-2xl mx-auto px-6 space-y-6",
                h1 { class: "text-3xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                    "Profile"
                }
                p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                    "Your account details and password."
                }

                SettingsCard { title: "Profile",
                    match &*me.read() {
                        None => rsx! {
                            p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                "Loading..."
                            }
                        },
                        Some(Err(e)) => rsx! {
                            p { class: "text-sm text-red-700 dark:text-red-300", "Failed to load: {e}" }
                        },
                        Some(Ok(b)) => rsx! {
                            form {
                                class: "space-y-4",
                                onsubmit: move |e: Event<FormData>| {
                                    e.prevent_default();
                                    save_profile.call(());
                                },
                                p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                    "Email: "
                                    span { class: "text-bunyip-reed-900 dark:text-bunyip-reed-50 font-medium", "{b.email}" }
                                }

                                FieldInput {
                                    name: "first_name",
                                    label: "First name",
                                    input_type: "text",
                                    value: profile.read().first_name.clone(),
                                    oninput: move |v: String| { profile.write().first_name = v; },
                                }
                                FieldInput {
                                    name: "last_name",
                                    label: "Last name",
                                    input_type: "text",
                                    value: profile.read().last_name.clone(),
                                    oninput: move |v: String| { profile.write().last_name = v; },
                                }
                                FieldInput {
                                    name: "timezone",
                                    label: "Timezone",
                                    input_type: "text",
                                    placeholder: "UTC",
                                    value: profile.read().timezone.clone(),
                                    oninput: move |v: String| { profile.write().timezone = v; },
                                }
                                FieldInput {
                                    name: "avatar_url",
                                    label: "Avatar URL",
                                    input_type: "url",
                                    placeholder: "https://...",
                                    value: profile.read().avatar_url.clone(),
                                    oninput: move |v: String| { profile.write().avatar_url = v; },
                                }

                                if let Some(err) = profile.read().error.clone() {
                                    InlineMessage { kind: MessageKind::Error, text: err }
                                }
                                if profile.read().saved {
                                    InlineMessage { kind: MessageKind::Success, text: "Saved.".to_string() }
                                }

                                PrimaryButton { busy: profile.read().saving, label: "Save profile" }
                            }
                        },
                    }
                }

                SettingsCard { title: "Change password",
                    form {
                        class: "space-y-4",
                        onsubmit: move |e: Event<FormData>| {
                            e.prevent_default();
                            submit_password.call(());
                        },
                        FieldInput {
                            name: "current_password",
                            label: "Current password",
                            input_type: "password",
                            value: password.read().current_password.clone(),
                            oninput: move |v: String| { password.write().current_password = v; },
                        }
                        FieldInput {
                            name: "new_password",
                            label: "New password",
                            input_type: "password",
                            value: password.read().new_password.clone(),
                            oninput: move |v: String| { password.write().new_password = v; },
                        }
                        FieldInput {
                            name: "password_confirmation",
                            label: "Confirm new password",
                            input_type: "password",
                            value: password.read().password_confirmation.clone(),
                            oninput: move |v: String| { password.write().password_confirmation = v; },
                        }
                        if let Some(err) = password.read().error.clone() {
                            InlineMessage { kind: MessageKind::Error, text: err }
                        }
                        if password.read().success {
                            InlineMessage { kind: MessageKind::Success, text: "Password changed.".to_string() }
                        }
                        PrimaryButton { busy: password.read().submitting, label: "Change password" }
                    }
                }
            }
        }
    }
}

fn option_from_str(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

// --- shared building blocks reused by the account / admin pages -----

#[component]
pub fn SettingsCard(title: &'static str, children: Element) -> Element {
    rsx! {
        section { class: "rounded-2xl border border-bunyip-reed-100 dark:border-bunyip-reed-800 bg-white dark:bg-bunyip-reed-800 shadow-sm",
            header { class: "px-6 py-4 border-b border-bunyip-reed-100 dark:border-bunyip-reed-800",
                h2 { class: "text-base font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                    "{title}"
                }
            }
            div { class: "p-6", {children} }
        }
    }
}

#[component]
pub fn FieldInput(
    name: &'static str,
    label: &'static str,
    input_type: &'static str,
    #[props(default = "")] placeholder: &'static str,
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
pub fn PrimaryButton(busy: bool, label: &'static str) -> Element {
    rsx! {
        button {
            class: "px-4 py-2 rounded-lg bg-bunyip-reed-700 text-white font-medium hover:bg-bunyip-reed-800 disabled:opacity-60 disabled:cursor-not-allowed transition-colors",
            r#type: "submit",
            disabled: busy,
            if busy { "Working..." } else { "{label}" }
        }
    }
}

#[component]
pub fn SecondaryButton(label: String, onclick: EventHandler<()>) -> Element {
    rsx! {
        button {
            r#type: "button",
            class: "px-4 py-2 rounded-lg border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 transition-colors",
            onclick: move |_| onclick.call(()),
            "{label}"
        }
    }
}

#[component]
pub fn DangerButton(label: String, onclick: EventHandler<()>) -> Element {
    rsx! {
        button {
            r#type: "button",
            class: "px-4 py-2 rounded-lg border border-red-300 dark:border-red-700 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/30 transition-colors",
            onclick: move |_| onclick.call(()),
            "{label}"
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum MessageKind {
    Success,
    Info,
    Error,
}

#[component]
pub fn InlineMessage(kind: MessageKind, text: String) -> Element {
    let cls = match kind {
        MessageKind::Success => "text-sm text-green-700 dark:text-green-300 bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800 rounded p-3",
        MessageKind::Info => "text-sm text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3",
        MessageKind::Error => "text-sm text-red-700 dark:text-red-200 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded p-3",
    };
    rsx! { div { class: "{cls}", "{text}" } }
}
