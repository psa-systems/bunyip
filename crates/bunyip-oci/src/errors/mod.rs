//! Domain errors (`AppError`) from bunyip-domain plus the OCI-wire-format
//! `OciError` from the dunite-oci engine, and the collapse-and-log-once
//! helper that maps a failure onto it (BUNYIP-565). The helper itself
//! lives upstream in `dunite_oci::errors::context` (DUNITE-19); this
//! module re-exports it so call sites keep their `crate::errors::`
//! paths unchanged.

pub use bunyip_domain::errors::*;

pub use dunite_oci::errors::oci;
pub use dunite_oci::errors::oci::OciError;

pub use dunite_oci::errors::context::{internal_fault, OciErrorContext};
