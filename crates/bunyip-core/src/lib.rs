//! bunyip-core - shared layers for the Bunyip (PSA Systems) API.
//!
//! **SCAFFOLD - intentionally empty.** This crate is the structural placeholder
//! for Bunyip's core domain layer, mirroring `menkent-core` (the reference
//! consumer). It will house the foundation every vertical builds on:
//!
//! - `config`      - environment-driven application configuration
//! - `errors`      - the application error type (`AppError`)
//! - `responses`   - API response envelopes
//! - `validation`  - input validation helpers
//! - `middleware`  - HTTP middleware (auth extractors, security headers, ...)
//! - `models`      - database models (user, token, subscription, tier, ...)
//! - `repositories`- data-access layer over Postgres
//! - `services`    - business-logic services (auth, jwt, password, totp,
//!                   stripe, email, encryption, webhook, ...)
//!
//! ## Why empty right now
//!
//! Both upstream repos are mid-refactor (see
//! `dev-docs/bunyip-on-dunite-scaffold.md`):
//!
//! - `dunite` is on step 2/4 of a library-only refactor; `dunite-core` still
//!   ships fat domain code that is slated for removal (steps 3/4).
//! - `menkent` is dropping its `dunite` dependency and owning everything
//!   wholesale (`menkent-core` now declares "no dunite dependency").
//!
//! The directive for Bunyip is to CONSUME the generic `dunite-core` kernel
//! (`dunite` is meant to be 100% generic). That conflicts with menkent's
//! current trajectory, so the consumption boundary is deliberately left
//! undecided here: `dunite-core` is an optional dep behind the `dunite`
//! feature (off by default). Fill this crate once the upstream API stabilizes.
