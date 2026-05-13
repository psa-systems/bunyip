//! Auth state signal.
//!
//! Boots once via `use_auth_provider`: reads the persisted token bundle
//! from `localStorage` (key `bunyip.tokens`), hydrates the in-memory
//! access_token, then fetches `/v1/auth/me` to materialize the SignedIn
//! state. If no tokens or the /me fetch 401s, the state collapses to
//! SignedOut.

use dioxus::prelude::*;

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
