//! Auth state signal.
//!
//! Boots once via `use_auth_provider`: reads the persisted token bundle
//! from `localStorage` (key `bunyip.tokens`), hydrates the in-memory
//! access_token, then fetches `/v1/auth/me` to materialize the SignedIn
//! state. If no tokens or the /me fetch 401s, the state collapses to
//! SignedOut.

use chrono::{Duration, Utc};
use dioxus::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::api::types::{MeResponse, UserRole};
use crate::api::ApiError;
use crate::stores::config::OidcConfig;
use crate::stores::tokens::{self, Tokens};

#[derive(Clone, Copy)]
pub struct AuthSignal(pub Signal<AuthState>);

#[derive(Debug, Clone, PartialEq)]
pub enum AuthState {
    Loading,
    SignedOut,
    SignedIn(MeResponse),
}

impl AuthState {
    pub fn is_signed_in(&self) -> bool {
        matches!(self, AuthState::SignedIn(_))
    }
    pub fn me(&self) -> Option<&MeResponse> {
        if let AuthState::SignedIn(me) = self {
            Some(me)
        } else {
            None
        }
    }
}

/// Mount this once at the top of the tree so all descendants can read
/// auth. Hydrates the in-memory access_token from localStorage on
/// boot, refreshes the access token if it has expired, then fetches
/// /me.
///
/// Error handling matters here: an over-eager clear_tokens turns any
/// transient /me failure (CORS preflight blip, momentary network
/// glitch) into a forced logout that survives a reload. Only a true
/// 401 from /me - meaning the server is rejecting this Bearer token -
/// clears the bundle. Everything else leaves the tokens in place so
/// the next reload can retry.
pub fn use_auth_provider() -> AuthSignal {
    let signal = use_context_provider(|| AuthSignal(Signal::new(AuthState::Loading)));
    let mut sig = signal.0;
    use_future(move || async move {
        // 1. Hydrate from localStorage.
        let tokens = match tokens::load_tokens() {
            Some(t) => t,
            None => {
                sig.set(AuthState::SignedOut);
                return;
            }
        };

        // 2. Refresh the access token if it has already expired (or
        //    is within 30s of expiry). Saves an extra round-trip
        //    later when /me would have 401'd.
        let tokens = maybe_refresh(tokens).await;
        let tokens = match tokens {
            Some(t) => t,
            None => {
                // refresh failed; tokens already cleared inside
                // maybe_refresh.
                sig.set(AuthState::SignedOut);
                return;
            }
        };

        // 3. Fetch /me. On 401, attempt one more refresh-and-retry
        //    before giving up - covers the case where the access
        //    token was rejected for a reason other than expiry
        //    (server-side revocation, clock skew, ...).
        let signed_in = match crate::api::me::fetch_me().await {
            Ok(me) => {
                sig.set(AuthState::SignedIn(me));
                true
            }
            Err(ApiError::Status { status: 401, .. }) => {
                if let Some(_new) = force_refresh(&tokens).await {
                    match crate::api::me::fetch_me().await {
                        Ok(me) => {
                            sig.set(AuthState::SignedIn(me));
                            true
                        }
                        Err(_) => {
                            tokens::clear_tokens();
                            sig.set(AuthState::SignedOut);
                            false
                        }
                    }
                } else {
                    tokens::clear_tokens();
                    sig.set(AuthState::SignedOut);
                    false
                }
            }
            Err(_) => {
                // Transient: network, CORS preflight, decode, etc.
                // Do NOT clear localStorage - a reload should retry
                // cleanly. The signal goes to SignedOut so the
                // gated pages bounce to /login, but the stored
                // tokens remain available for the next attempt.
                sig.set(AuthState::SignedOut);
                false
            }
        };

        // 4. As long as we are signed in, run the background refresh
        //    loop forever. It sleeps until ~30s before the access
        //    token expires, refreshes silently, and reschedules.
        //    When refresh ultimately fails (refresh token expired or
        //    revoked) it signs the user out and the loop returns -
        //    nav.replace to /login is driven by the bounce-on-
        //    SignedOut effect on every protected page.
        if signed_in {
            run_token_refresh_loop(sig).await;
        }
    });
    signal
}

/// Background loop: sleep until the current access token is about to
/// expire, refresh it, repeat. Exits the moment a refresh fails (or
/// there is no refresh token to use), having already cleared local
/// storage + dropped the signal to SignedOut.
///
/// This is what turns "JWT expired" into "you are back on /login"
/// without the user having to click anything: the loop wakes up at
/// the right moment regardless of whether the user is making
/// requests.
async fn run_token_refresh_loop(mut sig: Signal<AuthState>) {
    loop {
        let current = match tokens::load_tokens() {
            Some(t) => t,
            None => {
                sig.set(AuthState::SignedOut);
                return;
            }
        };

        // Wake up REFRESH_LEAD_SECONDS before expiry. Clamp to a
        // minimum of 1s so a token that is already past expiry
        // (clock skew, paused tab) refreshes immediately rather
        // than wedging the loop in a negative-duration sleep.
        const REFRESH_LEAD_SECONDS: i64 = 30;
        let wait_for = (current.expires_at - Utc::now() - Duration::seconds(REFRESH_LEAD_SECONDS))
            .num_milliseconds()
            .max(1) as u32;
        gloo_timers::future::TimeoutFuture::new(wait_for).await;

        // Refresh. On failure, this is the moment we hand the user
        // back to /login: clear tokens + flip the signal. Every
        // protected page has a use_effect watching SignedOut that
        // calls nav.replace(LoginPage), so the redirect is
        // automatic.
        match force_refresh(&current).await {
            Some(_new) => {
                // Loop again; the new tokens are already persisted
                // by force_refresh.
            }
            None => {
                tokens::clear_tokens();
                sig.set(AuthState::SignedOut);
                return;
            }
        }
    }
}

/// If `tokens.access_token` is expired or about to expire, attempt to
/// refresh it. Returns the (possibly-rotated) tokens to use going
/// forward, or `None` if refresh failed irrecoverably (cleared
/// localStorage as a side effect). If the token is still fresh, just
/// returns it unchanged.
async fn maybe_refresh(tokens: Tokens) -> Option<Tokens> {
    let near_expiry = tokens.expires_at < Utc::now() + Duration::seconds(30);
    if !near_expiry {
        return Some(tokens);
    }
    force_refresh(&tokens).await.or_else(|| {
        tokens::clear_tokens();
        None
    })
}

/// Always attempt a refresh against the token endpoint regardless of
/// the current access_token's expiry. Returns the new tokens (already
/// saved to localStorage + the in-memory holder) or `None` on failure.
async fn force_refresh(tokens: &Tokens) -> Option<Tokens> {
    let refresh_token = tokens.refresh_token.as_deref()?;
    let cfg = OidcConfig::from_env();
    let new_tokens = crate::modules::oidc::refresh_tokens(&cfg, refresh_token, &tokens.id_token)
        .await
        .ok()?;
    tokens::save_tokens(&new_tokens);
    Some(new_tokens)
}

pub fn use_auth() -> Signal<AuthState> {
    use_context::<AuthSignal>().0
}

/// Replace the auth signal with a fresh `/v1/auth/me` fetch.
pub async fn refresh_auth(mut sig: Signal<AuthState>) {
    sig.set(AuthState::Loading);
    match crate::api::me::fetch_me().await {
        Ok(me) => sig.set(AuthState::SignedIn(me)),
        Err(_) => {
            tokens::clear_tokens();
            sig.set(AuthState::SignedOut);
        }
    }
}

/// Clear the persisted token bundle + in-memory access_token, drop the
/// AuthContext to SignedOut. Phase 03 wires the actual server-side
/// `/v1/auth/logout` POST; this helper is what the SPA components call
/// after a successful logout response.
pub fn sign_out(mut sig: Signal<AuthState>) {
    tokens::clear_tokens();
    sig.set(AuthState::SignedOut);
}

/// Mount once at app root so a back-button after logout (or after
/// any auth-state transition) does not show a stale dashboard from
/// the browser's bfcache.
///
/// Modern browsers cache the entire JS-process state of pages so the
/// back/forward buttons restore them instantly. That means after a
/// user signs out and presses Back, the browser bypasses our
/// `use_auth_provider` future entirely and shows the rendered
/// "SignedIn" DOM that existed before the sign-out. The `pageshow`
/// event fires with `persisted=true` exactly in that case; we listen
/// for it and force a full reload, which re-runs `use_auth_provider`
/// from scratch, finds no tokens in localStorage, and lands the user
/// on /login.
pub fn use_bfcache_invalidator() {
    use_effect(|| {
        let Some(win) = web_sys::window() else {
            return;
        };
        let closure = Closure::<dyn FnMut(web_sys::PageTransitionEvent)>::new(
            move |evt: web_sys::PageTransitionEvent| {
                if evt.persisted() {
                    if let Some(w) = web_sys::window() {
                        let _ = w.location().reload();
                    }
                }
            },
        );
        let _ = win.add_event_listener_with_callback("pageshow", closure.as_ref().unchecked_ref());
        // Forget the closure: the listener stays attached for the
        // lifetime of the document, which is precisely what we want.
        // The SPA never tears this down, so leaking it is correct.
        closure.forget();
    });
}

/// Redirect away from the current page if the signed-in user doesn't
/// hold `required_role`. Used by admin pages to bounce non-admins to
/// the dashboard. While auth is still `Loading` we do nothing (so the
/// page renders its own loading state); once we resolve to SignedOut or
/// a non-matching role, navigate away.
pub fn use_require_role(required: &'static str) {
    let auth = use_auth();
    let nav = navigator();
    use_effect(move || match &*auth.read() {
        AuthState::Loading => {}
        AuthState::SignedOut => {
            nav.replace(crate::routes::Route::LoginPage {});
        }
        AuthState::SignedIn(me) => {
            let required_role = UserRole::from_wire(required);
            if me.user.role != required_role {
                nav.replace(crate::routes::Route::DashboardPage {});
            }
        }
    });
}
