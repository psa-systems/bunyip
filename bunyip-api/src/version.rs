//! Build version reporting and operator-facing update checking.
//!
//! `/version` reports (a) what version this instance is running and (b) whether
//! a newer release is published. Applying an update is always a deliberate
//! operator action (pull the new image, recreate the containers); this only
//! reports.
//!
//! DEV-530: the update checker moved to the shared `dunite-update-check` crate
//! (config-driven, no product identity). This module keeps the bunyip-specific
//! version identity - `current_version()` (the compiled version) and
//! `git_revision()` (the build SHA) - and re-exports the checker so every
//! `crate::version::{UpdateChecker, UpdateStatus}` path is unchanged.

pub use dunite_update_check::{UpdateChecker, UpdateStatus};

/// The version compiled into this binary (workspace `Cargo.toml`).
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Git revision baked in at image build time via the `BUNYIP_GIT_SHA` env (set
/// from the `GIT_SHA` build arg in the OCI Dockerfile). Empty for local
/// `cargo run` builds.
pub fn git_revision() -> String {
    std::env::var("BUNYIP_GIT_SHA").unwrap_or_default()
}
