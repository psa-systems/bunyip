//! In-memory mock store for the Bunyip MVP frontend.
//!
//! Loaded from `seeds/*.json` at boot. All mutations live in `Arc<RwLock<MockStore>>`
//! and reset on restart. Replaced by Mokosh Server endpoints once real backend work
//! lands - see `For AI/bunyip-feature-sso-port-notes.md`.

pub mod models;
pub mod store;

pub use models::*;
pub use store::{MockStore, SharedMockStore};
