//! bunyip-api - backend API binary crate.
//!
//! The shared layers live in [`bunyip_domain`]; the OCI and OIDC subsystems live
//! in [`bunyip_oci`] and [`bunyip_oidc`]. This crate re-exports the core layers
//! under their original module names so the main-app handlers and routes keep
//! using `crate::models`, `crate::services`, `crate::errors`, etc. unchanged,
//! and hosts the main-app `handlers` and `routes` themselves.

pub use bunyip_domain::{
    config, errors, middleware, models, repositories, responses, services, validation,
};

pub mod access_log;
pub mod error_log;
pub mod handlers;
pub mod migrate_reconcile;
pub mod mokosh_backup;
pub mod root_span;
pub mod routes;
pub mod seed;
pub mod version;

// Re-export commonly used types
pub use config::Config;
pub use errors::AppError;
pub use responses::{ApiResponse, ResponseMeta};

/// The two seeded E2E account emails (BUNYIP-52 / BUNYIP-163). Single source of
/// truth shared by the `bunyip-e2e-bootstrap` binary (which seeds exactly these)
/// and the `GET /e2e-bootstrapped` readiness probe (`routes/health.rs`, which
/// checks both exist + are active). Keep in lock-step with the suite's login
/// accounts.
pub const E2E_ACCOUNT_EMAILS: [&str; 2] = ["e2e-user@a8n.run", "e2e-admin@a8n.run"];
