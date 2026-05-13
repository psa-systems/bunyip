//! Auth state signal.
//!
//! Boots once via `use_auth_provider`: reads the persisted token bundle
//! from `localStorage` (key `bunyip.tokens`), hydrates the in-memory
//! access_token, then fetches `/v1/auth/me` to materialize the SignedIn
//! state. If no tokens or the /me fetch 401s, the state collapses to
//! SignedOut.

use dioxus::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::api::types::{MeResponse, UserRole};
use crate::stores::tokens;

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
/// boot, then fetches /me.
pub fn use_auth_provider() -> AuthSignal {
    let signal = use_context_provider(|| AuthSignal(Signal::new(AuthState::Loading)));
    let mut sig = signal.0;
    use_future(move || async move {
        // Hydrate the in-memory access_token from localStorage so the
        // first /me fetch carries a Bearer header.
        let _ = tokens::load_tokens();
        match crate::api::me::fetch_me().await {
            Ok(me) => sig.set(AuthState::SignedIn(me)),
            Err(_) => {
                tokens::clear_tokens();
                sig.set(AuthState::SignedOut);
            }
        }
    });
    signal
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
