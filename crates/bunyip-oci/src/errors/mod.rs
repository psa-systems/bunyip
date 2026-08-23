//! Domain errors (`AppError`) from bunyip-domain plus the OCI-wire-format
//! `OciError` from the dunite-oci engine, and the one place that maps a
//! failure onto it ([`context`], BUNYIP-565).

pub use bunyip_domain::errors::*;

pub use dunite_oci::errors::oci;
pub use dunite_oci::errors::oci::OciError;

pub mod context;

pub use context::{internal_fault, OciErrorContext};
