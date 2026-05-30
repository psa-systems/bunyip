//! bunyip-api - backend API binary crate.
//!
//! The shared layers live in [`bunyip_core`]; the OCI and OIDC subsystems live
//! in [`bunyip_oci`] and [`bunyip_oidc`]. This crate re-exports the core layers
//! under their original module names so the main-app handlers and routes keep
//! using `crate::models`, `crate::services`, `crate::errors`, etc. unchanged,
//! and hosts the main-app `handlers` and `routes` themselves.

pub use bunyip_core::{
    config, errors, middleware, models, repositories, responses, services, validation,
};

pub mod handlers;
pub mod routes;
pub mod version;

// Re-export commonly used types
pub use config::Config;
pub use errors::AppError;
pub use responses::{ApiResponse, ResponseMeta};
