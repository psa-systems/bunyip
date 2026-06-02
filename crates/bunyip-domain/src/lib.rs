//! bunyip-domain - Bunyip (PSA Systems) core domain layer.
//!
//! Owns the domain: configuration, database models, repositories, business
//! services, and the domain middleware (auth extractors, auto-ban). Builds on
//! the generic [`dunite_core`] kernel and re-exports its layers under their
//! original module names so domain sources keep using `crate::errors`,
//! `crate::responses`, `crate::validation`, and
//! `crate::services::{jwt, password, encryption}` unchanged. The OCI and OIDC
//! verticals live in their own crates (`bunyip-oci`, `bunyip-oidc`).

// Generic kernel, re-exported from the dunite-core framework crate.
pub use dunite_core::{errors, responses, validation};

// Domain layers (owned by bunyip).
pub mod config;
pub mod middleware;
pub mod models;
pub mod repositories;
pub mod services;

// Shared test utilities (env-var lock); test builds only.
#[cfg(test)]
pub(crate) mod test_support;

// Re-export commonly used types.
pub use config::Config;
pub use errors::AppError;
pub use responses::{ApiResponse, ResponseMeta};
