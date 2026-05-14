//! `/dashboard` - the App Launcher. One tile per OAuth client the
//! signed-in user can launch; clicking a tile kicks off an OIDC
//! code+PKCE flow against mokosh-server with that tile's client_id +
//! redirect_uri, landing the user on the target app.

use dioxus::prelude::*;

use crate::api::apps::{self, AppView};
use crate::api::types::MeResponse;
use crate::components::image::SafeImage;
use crate::components::layout::BrandMark;
use crate::components::theme::ThemeToggle;
use crate::modules::oidc::OidcConfig;
use crate::routes::Route;
use crate::stores::auth::{use_auth, AuthState};
use crate::stores::toast::use_toast;

/// Given an OAuth client's registered redirect_uri (e.g.
/// `https://a contributor-mokosh.a8n.run/auth/callback`), derive the URL the
/// launcher tile should send the browser to. We keep the origin and
/// append `/dashboard` - the conventional protected landing page that
/// every first-party Mokosh app exposes under its AuthGuard. The
/// AuthGuard then runs start_login locally to set up PKCE for this
/// origin.
fn launch_url(redirect_uri: &str) -> Option<String> {
    let url = web_sys::Url::new(redirect_uri).ok()?;
    Some(format!("{}//{}/dashboard", url.protocol(), url.host()))
}

#[component]
pub fn DashboardPage() -> Element {
    let auth = use_auth();
    let nav = navigator();
    // Bounce signed-out users to /login synchronously rather than
    // sitting on a "You're signed out" notice - the dashboard is
    // gated content, not an entry point. Pair with
    // use_bfcache_invalidator (mounted at app root) so a back-button
    // press after logout reloads + lands here in Loading → SignedOut
    // → /login.
    use_effect(move || {
        if matches!(*auth.read(), AuthState::SignedOut) {
            nav.replace(Route::LoginPage {});
        }
    });
    let state = auth.read().clone();

    match state {
        AuthState::Loading | AuthState::SignedOut => {
            rsx! { Splash { message: "Loading your dashboard…" } }
        }
        AuthState::SignedIn(me) => rsx! { Authenticated { me: me } },
    }
}

#[component]
fn Splash(message: &'static str) -> Element {
    rsx! {
        div { class: "min-h-screen flex items-center justify-center text-sm text-bunyip-reed-700 dark:text-bunyip-reed-200",
            "{message}"
        }
    }
}

#[component]
fn Authenticated(me: MeResponse) -> Element {
    let primary_org = me.memberships.first().cloned();
    let org_name = primary_org
        .as_ref()
        .map(|m| m.org.name.clone())
        .unwrap_or_else(|| "Personal".to_string());

    let mut apps: Signal<Option<Result<Vec<AppView>, String>>> = use_signal(|| None);

    use_future(move || async move {
        // The launcher only shows OTHER apps. Bunyip is the hub the
        // user is already inside, so a tile that "launches" it would
        // be a no-op at best and a confusing re-auth round-trip at
        // worst. Filter our own client_id out of the list before
        // splitting first-party / third-party.
        let cfg = OidcConfig::from_env();
        let own_client_id = cfg.client_id.clone();
        let r = apps::list_apps()
            .await
            .map(|list| {
                list.into_iter()
                    .filter(|a| a.client_id != own_client_id)
                    .collect::<Vec<_>>()
            })
            .map_err(|e| e.user_message());
        apps.set(Some(r));
    });

    let toast = use_toast();
    let launch = use_callback(move |app: AppView| {
        // The launcher does NOT drive an OIDC dance on behalf of the
        // target. PKCE requires the code_verifier to live on the same
        // origin as the /auth/callback page that exchanges the code,
        // and the verifier cannot cross origins. So we just navigate
        // the browser to the target's entry URL and let the target's
        // own AuthGuard call start_login - storing the PendingFlow
        // (verifier + state + nonce) on the target's sessionStorage.
        // Authorize then 302s back to the target's /auth/callback
        // with the OP cookie that was set when the user signed in
        // here on the hub.
        //
        // Entry URL = the redirect_uri's origin + /dashboard. The
        // /dashboard path is the conventional protected landing page;
        // it is under the target's AuthGuard, so the un-authed visit
        // immediately kicks off start_login.
        let entry_url = match launch_url(&app.redirect_uri) {
            Some(u) => u,
            None => {
                toast.error(format!("Could not derive launch URL for {}.", app.name));
                return;
            }
        };
        if let Some(win) = web_sys::window() {
            let _ = win.location().set_href(&entry_url);
        }
    });

    rsx! {
        div { class: "min-h-screen flex flex-col bg-bunyip-reed-50 dark:bg-bunyip-reed-900",
            DashboardHeader { user_name: me.user.name.clone(), org_name: org_name.clone() }

            main { class: "flex-1 px-6 py-10",
                div { class: "max-w-6xl mx-auto space-y-8",
                    div {
                        p { class: "text-sm uppercase tracking-wide text-bunyip-reed-600 dark:text-bunyip-reed-300 font-semibold",
                            "Welcome back, {me.user.name}"
                        }
                        h1 { class: "mt-1 text-3xl font-bold tracking-tight text-bunyip-reed-900 dark:text-bunyip-reed-50",
                            "Your apps"
                        }
                        p { class: "mt-2 text-bunyip-reed-700 dark:text-bunyip-reed-200 max-w-2xl",
                            "Pick a tool to sign in to. Account, billing, and members live here in Bunyip; everything else lives in the launched app."
                        }
                    }

                    match &*apps.read() {
                        None => rsx! {
                            p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                "Loading your apps..."
                            }
                        },
                        Some(Err(e)) => rsx! {
                            div { class: "rounded-md bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4",
                                p { class: "text-sm text-red-700 dark:text-red-300",
                                    "Could not load apps: {e}"
                                }
                            }
                        },
                        Some(Ok(list)) if list.is_empty() => rsx! {
                            div { class: "rounded-xl border border-dashed border-bunyip-reed-200 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 p-8 text-center",
                                p { class: "text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300",
                                    "You do not have any apps yet. Ask an administrator to invite you."
                                }
                            }
                        },
                        Some(Ok(list)) => {
                            let (first_party, third_party): (Vec<_>, Vec<_>) =
                                list.iter().cloned().partition(|a| a.is_first_party);
                            rsx! {
                                if !first_party.is_empty() {
                                    AppGroup {
                                        title: "Your apps",
                                        apps: first_party,
                                        on_launch: move |a: AppView| launch.call(a),
                                    }
                                }
                                if !third_party.is_empty() {
                                    AppGroup {
                                        title: "Connected third-party apps",
                                        apps: third_party,
                                        on_launch: move |a: AppView| launch.call(a),
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
struct AppGroupProps {
    title: &'static str,
    apps: Vec<AppView>,
    on_launch: EventHandler<AppView>,
}

#[component]
fn AppGroup(props: AppGroupProps) -> Element {
    rsx! {
        section {
            h2 { class: "text-lg font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50",
                "{props.title}"
            }
            div { class: "mt-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 auto-rows-fr",
                for app in props.apps.iter().cloned() {
                    AppTile {
                        key: "{app.client_id}",
                        app: app.clone(),
                        on_launch: move |_| props.on_launch.call(app.clone()),
                    }
                }
            }
        }
    }
}

#[derive(Props, Clone, PartialEq)]
struct AppTileProps {
    app: AppView,
    on_launch: EventHandler<()>,
}

#[component]
fn AppTile(props: AppTileProps) -> Element {
    let a = &props.app;
    let initial = a
        .name
        .chars()
        .next()
        .map(|c| c.to_string().to_uppercase())
        .unwrap_or_default();

    rsx! {
        button {
            r#type: "button",
            class: "group h-full flex flex-col text-left p-5 rounded-xl border border-bunyip-reed-100 dark:border-bunyip-reed-700 bg-white dark:bg-bunyip-reed-800 hover:border-bunyip-reed-300 dark:hover:border-bunyip-reed-500 hover:shadow-md transition-all",
            onclick: move |_| props.on_launch.call(()),
            div { class: "flex items-start gap-4 flex-1",
                div { class: "shrink-0 w-12 h-12 rounded-lg bg-bunyip-reed-100 dark:bg-bunyip-reed-700 flex items-center justify-center overflow-hidden",
                    SafeImage {
                        src: a.icon_url.clone().unwrap_or_default(),
                        alt: a.name.clone(),
                        class: "w-12 h-12 object-cover",
                        // Fallback: the app's first letter, same look as
                        // when no icon_url was registered at all.
                        span { class: "text-lg font-semibold text-bunyip-reed-700 dark:text-bunyip-reed-200",
                            "{initial}"
                        }
                    }
                }
                div { class: "min-w-0 flex-1 flex flex-col",
                    div { class: "flex items-center gap-2",
                        h3 { class: "text-base font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50 group-hover:text-bunyip-reed-700 dark:group-hover:text-white truncate",
                            "{a.name}"
                        }
                    }
                    if let Some(d) = a.description.as_deref().filter(|s| !s.is_empty()) {
                        p { class: "mt-1 text-sm text-bunyip-reed-600 dark:text-bunyip-reed-300 line-clamp-2",
                            "{d}"
                        }
                    }
                    // mt-auto pins "Launch →" to the bottom of the tile so
                    // it aligns across the row regardless of name/description.
                    p { class: "mt-auto pt-2 text-xs text-bunyip-reed-500 dark:text-bunyip-reed-400 group-hover:text-bunyip-reed-700 dark:group-hover:text-bunyip-reed-200",
                        "Launch →"
                    }
                }
            }
        }
    }
}

#[component]
fn DashboardHeader(user_name: String, org_name: String) -> Element {
    let nav = navigator();

    // All sign-out paths converge on /logout (pages/logout.rs) so the
    // OP cookie + localStorage tokens + auth signal die in one place.
    let sign_out = move |_| {
        nav.replace(Route::LogoutPage {});
    };

    rsx! {
        header { class: "px-6 py-3 bg-white dark:bg-bunyip-reed-800 border-b border-bunyip-reed-100 dark:border-bunyip-reed-700 sticky top-0 z-10",
            div { class: "max-w-7xl mx-auto flex items-center justify-between",
                div { class: "flex items-center gap-4",
                    Link { to: Route::DashboardPage {}, class: "flex items-center gap-2",
                        BrandMark {}
                        span { class: "text-lg font-semibold text-bunyip-reed-900 dark:text-bunyip-reed-50", "Bunyip" }
                    }
                    span { class: "h-5 w-px bg-bunyip-reed-200 dark:bg-bunyip-reed-700" }
                    div { class: "flex items-center gap-2 px-3 py-1.5 rounded-md bg-bunyip-reed-50 dark:bg-bunyip-reed-900",
                        span { class: "w-2 h-2 rounded-full bg-bunyip-reed-600 dark:bg-bunyip-reed-400" }
                        span { class: "text-sm font-medium text-bunyip-reed-900 dark:text-bunyip-reed-100", "{org_name}" }
                    }
                }
                nav { class: "flex items-center gap-2 text-sm",
                    Link {
                        to: Route::SettingsPage {},
                        class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                        "Settings"
                    }
                    Link {
                        to: Route::OrgListPage {},
                        class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:bg-bunyip-reed-50 dark:hover:bg-bunyip-reed-900",
                        "Orgs"
                    }
                    span { class: "text-bunyip-reed-700 dark:text-bunyip-reed-200", "{user_name}" }
                    button {
                        class: "px-3 py-1.5 rounded-md text-bunyip-reed-700 dark:text-bunyip-reed-200 hover:text-bunyip-reed-900 hover:bg-bunyip-reed-50 dark:hover:text-white dark:hover:bg-bunyip-reed-900 transition-colors",
                        onclick: sign_out,
                        "Sign out"
                    }
                    ThemeToggle {}
                }
            }
        }
    }
}
