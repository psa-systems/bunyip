//! `/settings/sessions` - active sessions list + rename + revoke.

use chrono::{DateTime, Utc};
use dioxus::prelude::*;
use serde::Deserialize;

use crate::components::layout::AppShell;
use crate::modules::oidc::{self, OidcConfig};
use crate::pages::profile::SettingsCard;
use crate::routes::Route;
use crate::stores::auth::{use_auth, AuthState};

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct SessionView {
    id: String,
    created_at: DateTime<Utc>,
    last_active_at: DateTime<Utc>,
    #[allow(dead_code)]
    expires_at: DateTime<Utc>,
    #[serde(default)]
    user_agent: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    is_current: bool,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct SessionListBody {
    sessions: Vec<SessionView>,
}

#[component]
pub fn SessionsPage() -> Element {
    let nav = navigator();
    let auth = use_auth();
    use_effect(move || {
        if matches!(*auth.read(), AuthState::SignedOut) {
            nav.replace(Route::LoginPage {});
        }
    });

    let mut sessions: Signal<Option<Result<Vec<SessionView>, String>>> = use_signal(|| None);
    let mut revoking: Signal<Option<String>> = use_signal(|| None);

    let load = use_callback(move |_| {
        spawn(async move {
            sessions.set(None);
            let cfg = OidcConfig::from_env();
            let result = oidc::issuer_get_authed::<SessionListBody>(&cfg, "/v1/auth/sessions")
                .await
                .map(|b| b.sessions)
                .map_err(|e| e.to_string());
            sessions.set(Some(result));
        });
    });

    use_effect(move || {
        load.call(());
    });

    let revoke = use_callback(move |(id, is_current): (String, bool)| {
        revoking.set(Some(id.clone()));
        spawn(async move {
            let cfg = OidcConfig::from_env();
            let path = format!("/v1/auth/sessions/{id}/revoke");
            let _ = oidc::issuer_post_authed_empty(&cfg, &path).await;
            if is_current {
                // Funnel through /logout so the OP cookie is cleared,
                // tokens are dropped, and the auth signal moves to
                // SignedOut in one place (same as every other sign-out
                // entry point in the app).
                nav.replace(Route::LogoutPage {});
                return;
            }
            revoking.set(None);
            load.call(());
        });
    });

    rsx! {
        AppShell {
            title: "Active sessions".to_string(),
            back_to: Some(Route::SettingsPage {}),
            back_label: "Settings".to_string(),
            div { class: "max-w-2xl mx-auto px-6 space-y-6",
                h1 { class: "text-3xl font-bold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                    "Active sessions"
                }
                p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                    "Devices currently signed in to your account."
                }

                SettingsCard { title: "Sessions",
                    {
                        let mut revoking_others = use_signal(|| false);
                        let on_revoke_others = move |_| {
                            if revoking_others() { return; }
                            revoking_others.set(true);
                            spawn(async move {
                                let cfg = OidcConfig::from_env();
                                let _ = oidc::issuer_post_authed_empty(&cfg, "/v1/auth/sessions/revoke-others").await;
                                revoking_others.set(false);
                                load.call(());
                            });
                        };
                        rsx! {
                            div { class: "mb-4 flex justify-end",
                                button {
                                    r#type: "button",
                                    class: "px-3 py-1.5 rounded-lg border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-60 focus-visible:ring-2 focus-visible:ring-bunyip-reed-600",
                                    disabled: revoking_others(),
                                    onclick: on_revoke_others,
                                    if revoking_others() { "Signing out..." } else { "Sign out of all other sessions" }
                                }
                            }
                        }
                    }
                    match sessions.read().clone() {
                        None => rsx! {
                            p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300", "Loading..." }
                        },
                        Some(Err(e)) => rsx! {
                            p { class: "text-sm text-red-700 dark:text-red-300", "Could not load sessions: {e}" }
                        },
                        Some(Ok(list)) if list.is_empty() => rsx! {
                            p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300", "No active sessions." }
                        },
                        Some(Ok(list)) => rsx! {
                            div { class: "divide-y divide-bunyip-reed-100 dark:divide-bunyip-reed-700 -mx-6 -my-6",
                                for s in list {
                                    SessionRow {
                                        key: "{s.id}",
                                        session: s.clone(),
                                        revoking_id: revoking.read().clone(),
                                        on_revoke: {
                                            let id = s.id.clone();
                                            let is_current = s.is_current;
                                            move |_| revoke.call((id.clone(), is_current))
                                        },
                                    }
                                }
                            }
                        },
                    }
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct SessionRowProps {
    session: SessionView,
    revoking_id: Option<String>,
    on_revoke: EventHandler<()>,
}

/// Bucket an IP address into a human-readable location hint. Anything
/// in RFC1918 / loopback gets a friendly label; otherwise we surface
/// nothing (IP-to-geo lookup is out of scope; even MaxMind GeoLite is a
/// per-deploy decision). Doc 06 polish item #1.
fn friendly_ip(addr: &str) -> &'static str {
    if matches!(addr, "127.0.0.1" | "::1") {
        "This device"
    } else if addr.starts_with("10.")
        || addr.starts_with("192.168.")
        || addr.starts_with("169.254.")
        || (addr.starts_with("172.")
            && addr
                .get(4..6)
                .and_then(|s| s.parse::<u8>().ok())
                .map(|n| (16..=31).contains(&n))
                .unwrap_or(false))
        || addr.starts_with("fc")
        || addr.starts_with("fd")
    {
        "Local network"
    } else {
        ""
    }
}

/// Best-effort short label for a UA string. We do not pull a parser
/// crate; the heuristic picks the most relevant browser + OS fragment.
fn ua_short_label(ua: Option<&str>) -> String {
    let Some(ua) = ua else {
        return "Unknown device".into();
    };
    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("Chrome/") && !ua.contains("Chromium/") {
        "Chrome"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else if ua.contains("Safari/") && !ua.contains("Chrome/") {
        "Safari"
    } else {
        "Browser"
    };
    let os = if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "device"
    };
    format!("{browser} on {os}")
}

#[component]
fn SessionRow(props: SessionRowProps) -> Element {
    let s = props.session.clone();
    let busy = props.revoking_id.as_deref() == Some(s.id.as_str());
    let default_label = ua_short_label(s.user_agent.as_deref());
    let label = s
        .display_name
        .clone()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| default_label.clone());
    let ip = s.ip.clone().unwrap_or_else(|| "unknown".into());
    let last_active = s.last_active_at.format("%Y-%m-%d %H:%M UTC").to_string();
    let signed_in = s.created_at.format("%Y-%m-%d %H:%M UTC").to_string();

    let mut editing = use_signal(|| false);
    let mut draft = use_signal(|| s.display_name.clone().unwrap_or_default());
    let mut saving = use_signal(|| false);

    let id_for_save = s.id.clone();
    let save = use_callback(move |_| {
        let id = id_for_save.clone();
        let value = draft.read().trim().to_string();
        spawn(async move {
            saving.set(true);
            let cfg = OidcConfig::from_env();
            let path = format!("/v1/auth/sessions/{id}/rename");
            let body = serde_json::json!({
                "display_name": if value.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(value) }
            });
            let _ = oidc::issuer_post_authed::<serde_json::Value, _>(&cfg, &path, &body).await;
            saving.set(false);
            editing.set(false);
            if let Some(w) = web_sys::window() {
                let _ = w.location().reload();
            }
        });
    });

    rsx! {
        div { class: "flex items-start justify-between gap-4 px-6 py-4",
            div { class: "min-w-0 flex-1",
                div { class: "flex items-center gap-2 flex-wrap",
                    if *editing.read() {
                        input {
                            r#type: "text",
                            class: "block rounded border border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-900 text-bunyip-reed-900 dark:text-bunyip-reed-50 text-sm px-2 py-1 focus:outline-none focus:ring-2 focus:ring-bunyip-reed-600 dark:focus:ring-bunyip-reed-400",
                            placeholder: "{default_label}",
                            value: "{draft.read()}",
                            oninput: move |e: Event<FormData>| draft.set(e.value()),
                        }
                        button {
                            r#type: "button",
                            class: "text-xs px-2 py-1 rounded text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                            disabled: *saving.read(),
                            onclick: move |_| save.call(()),
                            if *saving.read() { "Saving..." } else { "Save" }
                        }
                        button {
                            r#type: "button",
                            class: "text-xs px-2 py-1 rounded text-bunyip-reed-500 hover:text-bunyip-reed-700",
                            onclick: move |_| {
                                editing.set(false);
                                draft.set(s.display_name.clone().unwrap_or_default());
                            },
                            "Cancel"
                        }
                    } else {
                        p { class: "text-sm font-medium text-bunyip-reed-900 dark:text-bunyip-reed-50 truncate",
                            "{label}"
                        }
                        button {
                            r#type: "button",
                            class: "text-xs text-bunyip-reed-500 hover:text-bunyip-reed-700 dark:hover:text-bunyip-reed-200",
                            onclick: move |_| editing.set(true),
                            "Rename"
                        }
                    }
                    if s.is_current {
                        span { class: "ml-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300",
                            "Current session"
                        }
                    }
                }
                p { class: "mt-1 text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                    "{default_label} - {ip}",
                    if !friendly_ip(&ip).is_empty() {
                        span { " ({friendly_ip(&ip)})" }
                    }
                    " - last active {last_active}"
                }
                p { class: "text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400",
                    "Signed in {signed_in}"
                }
            }
            button {
                r#type: "button",
                class: "px-3 py-1.5 rounded-lg border border-bunyip-reed-300 dark:border-bunyip-reed-600 text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900 disabled:opacity-60",
                disabled: busy,
                onclick: move |_| props.on_revoke.call(()),
                if busy { "..." } else if s.is_current { "Sign out" } else { "Revoke" }
            }
        }
    }
}
