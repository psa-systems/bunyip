//! OIDC public-client (SPA) flow against mokosh-server.
//!
//! Bunyip-web is a pure WASM single-page app, so we use the
//! authorization-code flow with PKCE as a public client (no
//! `client_secret`). The flow:
//!
//!  1. `start_login()` generates a `code_verifier`, computes the S256
//!     `code_challenge`, generates `state` and `nonce`, persists those
//!     in `sessionStorage`, then redirects the browser to
//!     `<issuer>/oauth2/authorize`.
//!  2. mokosh-server walks the user through login (today via bunyip
//!     itself once the SSO bridge in phase 07 lands) and redirects
//!     back to `redirect_uri` with `?code=...&state=...`.
//!  3. The `/auth/callback` route page calls [`complete_login`], which
//!     verifies `state`, POSTs the code + verifier to `/oauth2/token`,
//!     and returns parsed [`Tokens`].
//!  4. Tokens live in memory (in `AuthContext`) AND in localStorage
//!     under `bunyip.tokens` so the user does not have to re-auth on
//!     every reload. The same XSS surface area applies as everywhere
//!     else in the SPA.

pub mod flow;
pub mod pkce;
pub mod storage;
pub mod tokens;

pub use flow::{
    complete_login, current_search, issuer_get, issuer_get_authed, issuer_post,
    issuer_post_authed, issuer_post_authed_empty, mfa_verify, password_login, refresh_tokens,
    revoke_refresh_token, snapshot_initial_search, start_login, start_login_for, FlowError,
    LoginOutcome, MfaVerifyOk,
};
pub use tokens::IdTokenClaims;

// Re-export `OidcConfig` from the existing `stores::config` so the
// flow module and the SPA agree on a single source of truth.
pub use crate::stores::config::OidcConfig;
pub use crate::stores::tokens::{StoredTokens, Tokens};
