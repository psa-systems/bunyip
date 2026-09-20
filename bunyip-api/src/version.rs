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

/// Git revision baked in at image build time via the `GIT_COMMIT` compile-time
/// env (the same `option_env!` the `/v1/version` status endpoint reads).
/// `"unknown"` for local `cargo run` builds, which set no `GIT_COMMIT`.
pub fn git_revision() -> String {
    option_env!("GIT_COMMIT").unwrap_or("unknown").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::health::GIT_COMMIT;

    /// BUNYIP-752: root `/version`'s revision and `/v1/version`'s commit must
    /// report the same value in a built image. Asserting equality against
    /// `/v1/version`'s own compile-time constant, rather than a literal, is
    /// what catches a regression back to a runtime env read (which would
    /// diverge from this the moment the two are compiled with different env).
    #[test]
    fn git_revision_matches_the_v1_version_commit() {
        assert_eq!(git_revision(), GIT_COMMIT);
    }
}
