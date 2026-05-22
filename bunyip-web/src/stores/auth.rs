//! Auth state signal.
//!
//! Boots once via `use_auth_provider`: reads the persisted token bundle
//! from `localStorage` (key `bunyip.tokens`), hydrates the in-memory
//! access_token, then fetches `/v1/auth/me` to materialize the SignedIn
//! state. If no tokens or the /me fetch 401s, the state collapses to
//! SignedOut.

use std::sync::Mutex;

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

        // Wake up REFRESH_LEAD_SECONDS before expiry. Two clamps:
        //   - lower bound `MIN_LOOP_INTERVAL`: prevents the loop from
        //     busy-cycling if expires_at is already in the past (clock
        //     jumped backward, tab was suspended, server issued a token
        //     with a stale exp). Without this the loop would fire every
        //     ~1 ms, burning refresh-token rotations as fast as Mokosh
        //     could mint them. The singleflight gate stops reuse
        //     detection from triggering, but it still hammers the OP.
        //   - upper bound is implicit (token TTL ~hour minus 30 s);
        //     no need to cap the wait, just the floor.
        const REFRESH_LEAD_SECONDS: i64 = 30;
        const MIN_LOOP_INTERVAL_MS: i64 = 5_000;
        let wait_for_ms = (current.expires_at - Utc::now() - Duration::seconds(REFRESH_LEAD_SECONDS))
            .num_milliseconds()
            .max(MIN_LOOP_INTERVAL_MS) as u32;
        gloo_timers::future::TimeoutFuture::new(wait_for_ms).await;

        // Refresh. On failure, this is the moment we hand the user
        // back to /login: clear tokens + flip the signal. Every
        // protected page has a use_effect watching SignedOut that
        // calls nav.replace(LoginPage), so the redirect is
        // automatic.
        match force_refresh(&current).await {
            Some(_new) => {
                // On a successful rotation, also re-fetch /v1/auth/me
                // so any server-side change to the user (role, name,
                // primary org) propagates to the UI within one refresh
                // window instead of waiting for a page reload. This
                // matters because mokosh-server is RFC-compliant and
                // may omit `id_token` on refresh-grant responses, so
                // the cached id_token's claims (role, etc.) can be
                // stale; fetch_me bypasses the id_token and reads
                // current state. Failures here are silent: the user
                // continues with the previous me snapshot rather than
                // being signed out.
                if let Ok(me) = crate::api::me::fetch_me().await {
                    sig.set(AuthState::SignedIn(me));
                }
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

/// On-demand single-shot refresh callable from the API client when a
/// request unexpectedly returns 401 (background loop missed expiry due
/// to tab suspend / system sleep / clock skew). Returns the new access
/// token; on failure, clears tokens + leaves the auth signal alone
/// (caller surfaces the 401 to the user normally).
pub(crate) async fn try_refresh_access_token() -> Option<String> {
    let current = tokens::load_tokens()?;
    let new = force_refresh(&current).await?;
    Some(new.access_token)
}

/// Single-flight gate. mokosh-server enforces single-use refresh tokens
/// with family-wide reuse detection: presenting an already-rotated
/// refresh_token revokes the whole family and silently signs the user
/// out on the next call. WASM is single-threaded but futures interleave
/// at .await boundaries, so the background loop + the api/mod.rs 401
/// retry can both enter force_refresh holding the same refresh_token.
/// This flag serializes them so only one refresh hits the wire per
/// rotation.
static REFRESH_IN_FLIGHT: Mutex<bool> = Mutex::new(false);

/// RAII guard: clears `REFRESH_IN_FLIGHT` on drop, including when the
/// holding future is cancelled mid-await (the dx-renderer can drop a
/// future at any await point - navigation, hot-reload, panic). Without
/// this, a cancelled `force_refresh` left the gate locked permanently
/// and every subsequent refresh attempt got stuck in the wait loop
/// until the user reloaded the tab.
struct RefreshGuard;

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        if let Ok(mut g) = REFRESH_IN_FLIGHT.lock() {
            *g = false;
        }
    }
}

fn try_acquire_refresh() -> Option<RefreshGuard> {
    match REFRESH_IN_FLIGHT.lock() {
        Ok(mut g) if !*g => {
            *g = true;
            Some(RefreshGuard)
        }
        _ => None,
    }
}

async fn wait_for_in_flight_refresh() {
    loop {
        let busy = REFRESH_IN_FLIGHT
            .lock()
            .map(|g| *g)
            .unwrap_or(false);
        if !busy {
            return;
        }
        gloo_timers::future::TimeoutFuture::new(25).await;
    }
}

/// Always attempt a refresh against the token endpoint regardless of
/// the current access_token's expiry. Returns the new tokens (already
/// saved to localStorage + the in-memory holder) or `None` on failure.
///
/// Two callers racing into this function with the same stored
/// refresh_token would both present it to mokosh-server; the second
/// presentation trips reuse detection and revokes the family. To avoid
/// that we (1) serialize via REFRESH_IN_FLIGHT so a second caller waits
/// for the first to land, and (2) re-read storage on the way in so a
/// caller whose `tokens` view is stale (the background loop already
/// rotated while they were waiting) returns the newly-stored tokens
/// instead of replaying their own already-used refresh_token.
async fn force_refresh(tokens: &Tokens) -> Option<Tokens> {
    let _guard = match try_acquire_refresh() {
        Some(g) => g,
        None => {
            wait_for_in_flight_refresh().await;
            let current = tokens::load_tokens()?;
            if current.access_token != tokens.access_token {
                return Some(current);
            }
            // Other refresh ran but did not advance storage (it failed).
            // Replaying our refresh_token would trip reuse detection.
            return None;
        }
    };
    // Holding the gate via `_guard`. The guard drops at every return path
    // below (including future cancellation at the await on
    // refresh_tokens), so the gate cannot leak.
    if let Some(latest) = tokens::load_tokens() {
        if latest.access_token != tokens.access_token {
            return Some(latest);
        }
    }
    let refresh_token = tokens.refresh_token.as_deref()?;
    let cfg = OidcConfig::from_env();
    match crate::modules::oidc::refresh_tokens(&cfg, refresh_token, &tokens.id_token).await {
        Ok(new_tokens) => {
            tokens::save_tokens(&new_tokens);
            Some(new_tokens)
        }
        Err(_) => None,
    }
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
                if !evt.persisted() {
                    return;
                }
                // bfcache snapshots the entire JS heap including
                // REFRESH_IN_FLIGHT. If the page was frozen mid-refresh,
                // we cannot tell whether the server-side rotation
                // completed (and our locally-stored refresh_token is
                // now invalid) or whether the request never landed.
                // Either way, blindly reloading would race: the new
                // page would hydrate from localStorage and present the
                // same refresh_token, which can trip Mokosh's family-
                // reuse detection and silently sign the user out of
                // EVERY app sharing this OP session.
                //
                // Safe action: clear local tokens before reload so the
                // restarted page lands on /login cleanly and re-auths
                // through the OP rather than gambling with a possibly-
                // used refresh_token.
                let was_refreshing = REFRESH_IN_FLIGHT
                    .lock()
                    .map(|g| *g)
                    .unwrap_or(false);
                if was_refreshing {
                    tokens::clear_tokens();
                }
                if let Some(w) = web_sys::window() {
                    let _ = w.location().reload();
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
