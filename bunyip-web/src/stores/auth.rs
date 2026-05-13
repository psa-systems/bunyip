//! Auth state signal. Provider lives at the App root; reading components
//! call `use_auth()` to subscribe to the current user / loading state.

use dioxus::prelude::*;

use crate::api::types::MeResponse;

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

/// Mount this once at the top of the tree so all descendants can read auth.
pub fn use_auth_provider() -> AuthSignal {
    let signal = use_context_provider(|| AuthSignal(Signal::new(AuthState::Loading)));
    let mut sig = signal.0;
    use_future(move || async move {
        match crate::api::me::fetch_me().await {
            Ok(me) => sig.set(AuthState::SignedIn(me)),
            Err(_) => sig.set(AuthState::SignedOut),
        }
    });
    signal
}

pub fn use_auth() -> Signal<AuthState> {
    use_context::<AuthSignal>().0
}

/// Replace the auth signal with a fresh `/v1/me` fetch.
pub async fn refresh_auth(mut sig: Signal<AuthState>) {
    sig.set(AuthState::Loading);
    match crate::api::me::fetch_me().await {
        Ok(me) => sig.set(AuthState::SignedIn(me)),
        Err(_) => sig.set(AuthState::SignedOut),
    }
}
