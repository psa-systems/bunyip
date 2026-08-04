//! IP -> ASN / VPN enrichment via an IP2Proxy PX database (BUNYIP-437).
//!
//! The abuse-signal counterpart to [`crate::services::geoip`]. The
//! implementation lives in the shared `dunite-ipenrich` crate (which mokosh
//! consumes too), and this module is the seam so every
//! `crate::services::IpEnrichService` path in bunyip is stable regardless of
//! where the code lives.
//!
//! Behaviour mirrors the geoip seam: lookups read an offline IP2Proxy PX `.BIN`
//! (`IP2PROXY_DB_PATH`), no client IP is sent to a third party, and a private or
//! reserved address (or a missing database) resolves to `None` rather than to a
//! bogus signal.
//!
//! The one difference from the shared crate's boundary is the error type:
//! [`IpEnrichService::new`](dunite_ipenrich::IpEnrichService::new) returns
//! `dunite_ipenrich::IpEnrichError`, owned by the shared crate so consumers are
//! not forced onto one `dunite-core` revision (the DEV-515 cascade). bunyip's
//! only caller logs it via `Display`, so nothing needs converting.
//!
//! Advisory only: [`VpnLikelihood`] describes an address, it never decides that
//! a request is abuse. BUNYIP-437 was explicit that a VPN must not auto-classify
//! a submission as spam.

pub use dunite_ipenrich::{
    IpEnrichError, IpEnrichService, IpEnrichment, NetworkCategory, VpnLikelihood,
};
