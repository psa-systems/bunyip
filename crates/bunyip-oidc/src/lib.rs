//! bunyip-oidc - OIDC / OAuth 2.1 provider vertical for Bunyip (PSA Systems).
//!
//! **SCAFFOLD - intentionally empty.** Structural placeholder mirroring
//! `menkent-oidc`. Bunyip is itself the OpenID Provider (issuer); mokosh-server
//! and other relying parties are registered clients in the `oauth_clients`
//! table. When filled this will wire the generic `dunite-oidc` provider engine
//! (discovery, JWKS, authorize, token, userinfo, revoke, RP-initiated logout)
//! to actix-web handlers/routes, building on `bunyip-core`, and own the
//! compile-time `sqlx::query!` offline cache (`.sqlx/`).
//!
//! Empty until upstream stabilizes - see
//! `dev-docs/bunyip-on-dunite-scaffold.md`.
