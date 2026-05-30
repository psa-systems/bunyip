//! bunyip-oidc - OIDC / OAuth 2.1 provider vertical for Bunyip (PSA Systems).
//!
//! Implements the OpenID Provider: discovery, JWKS, authorization, token,
//! userinfo, revocation, and RP-initiated logout, backed by the
//! `oauth_*` / `oidc_*` tables. Built on `bunyip-core`, and consumes the
//! generic `dunite-oidc` key/JWKS engine for Ed25519 signing keys.
//!
//! This crate uses compile-time-checked `sqlx::query!` macros, so its
//! `.sqlx/` offline query cache lives alongside this manifest. Regenerate
//! with `cargo sqlx prepare` run from this crate directory.
//!
//! ## Module layout
//!
//! `config`, `errors`, `middleware`, `models`, and `repositories` are thin
//! local modules that glob-re-export their `bunyip_core` counterparts, so the
//! OIDC sources keep using `crate::errors::AppError`, `crate::models::User`,
//! `crate::middleware::auth`, etc. unchanged. The `services` module also
//! re-exports core's `jwt` submodule so `crate::services::jwt` resolves,
//! alongside the OIDC-local provider and the `dunite-oidc` key set.

pub mod config {
    pub use bunyip_core::config::*;
}

pub mod errors {
    pub use bunyip_core::errors::*;
}

pub mod middleware {
    pub use bunyip_core::middleware::*;
    // Re-export the submodule so `crate::middleware::auth::...` paths resolve.
    pub use bunyip_core::middleware::auth;
}

pub mod models {
    pub use bunyip_core::models::*;
}

pub mod repositories {
    pub use bunyip_core::repositories::*;
}

pub mod services {
    pub use bunyip_core::services::*;
    // Re-export the submodule so `crate::services::jwt::...` paths resolve.
    pub use bunyip_core::services::jwt;

    // Ed25519 key material + JWKS come from the generic dunite-oidc engine.
    pub use dunite_oidc::services::oidc_keys;

    pub mod oidc_provider;

    pub use dunite_oidc::OidcKeySet;
    pub use oidc_provider::{OAuthClient, OidcProvider};
}

pub mod handlers {
    pub mod oidc;
}

pub mod routes {
    pub mod oidc;
}
