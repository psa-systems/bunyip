//! Feedback models and DTOs.
//!
//! DEV-516: extracted to the shared `dunite-feedback` crate (consumed by
//! a8n-tools too) and re-exported here, so `crate::models::feedback::*` and
//! `crate::models::*` paths stay unchanged across bunyip-domain and bunyip-api.

// SPEC-7.2.2: shared crate owns these types; keep this a pure re-export.
pub use dunite_feedback::models::*;
