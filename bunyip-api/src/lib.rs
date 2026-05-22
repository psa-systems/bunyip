//! Thin Axum backend for Bunyip's MVP.
//!
//! - Serves the Dioxus SPA static output (in production builds).
//! - Exposes mock JSON endpoints under `/v1/*` backed by `bunyip-mocks`.
//! - All routes are scaffolded stubs in the MVP; the goal is to wire the
//!   frontend against realistic shapes. Real implementations move to Mokosh
//!   Server post-MVP (see `For AI/bunyip-feature-sso-port-notes.md`).

pub mod config;
pub mod errors;
pub mod responses;
pub mod routes;
pub mod state;
pub mod version;
