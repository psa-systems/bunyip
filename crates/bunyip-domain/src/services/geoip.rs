//! IP -> country resolution via an IP2Location LITE database (BUNYIP-366).
//!
//! DEV-531: the implementation moved to the shared `dunite-geoip` crate, which
//! a8n-tools consumes too (DEV-525). This module is kept as the seam so every
//! `crate::services::GeoIpService` path in bunyip is unchanged.
//!
//! Behaviour is identical to the copy it replaces: lookups read the same
//! IP2Location LITE `.BIN` the ecosystem already deploys
//! (`IP2LOCATION_DB_PATH`, e.g. `/data/IP2LOCATION-LITE-DB11.BIN`, as used by
//! dmarc-reporter), they are offline - no per-login external call, and no
//! client IP sent to a third party - and the `"-"` and blank country fields
//! IP2Location stores for reserved ranges still resolve to `None` rather than
//! to a country.
//!
//! The one difference is the error type: `GeoIpService::new` now returns
//! `dunite_geoip::GeoIpError` rather than [`crate::errors::AppError`]. The
//! shared crate owns its error deliberately - returning `dunite_core::AppError`
//! would force every consumer onto one `dunite-core` revision, the version
//! cascade DEV-515 backed out of. bunyip's only caller logs it via `Display`,
//! so nothing needed converting.

pub use dunite_geoip::{GeoIpError, GeoIpService};
