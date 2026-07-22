//! IP -> country resolution via an IP2Location LITE database (BUNYIP-366).
//!
//! Reads the same IP2Location LITE `.BIN` DB the ecosystem already deploys
//! (`IP2LOCATION_DB_PATH`, e.g. `/data/IP2LOCATION-LITE-DB11.BIN`, as used by
//! dmarc-reporter). It is used only to detect a country-level change between a
//! user's logins; when no DB is configured the login-location-alert feature is
//! disabled (this service is never constructed). Lookups are offline: no
//! per-login external call, and no client IP is sent to a third party.

use std::net::IpAddr;

use ip2location::{Record, DB};

use crate::errors::AppError;

/// An opened IP2Location database, queried for the country of a client IP.
pub struct GeoIpService {
    db: DB,
}

impl GeoIpService {
    /// Open the IP2Location `.BIN` database at `db_path`. Fails loudly if the
    /// path is set but unreadable, so a misconfiguration surfaces at startup
    /// rather than silently disabling alerts.
    pub fn new(db_path: &str) -> Result<Self, AppError> {
        let db = DB::from_file(db_path)
            .map_err(|e| AppError::internal(format!("IP2Location DB load failed: {e}")))?;
        Ok(Self { db })
    }

    /// The ISO 3166-1 alpha-2 country code for `ip`, or `None` when the IP is not
    /// resolvable (private / reserved / unknown ranges carry no country).
    pub fn country_code(&self, ip: IpAddr) -> Option<String> {
        let raw = match self.db.ip_lookup(ip).ok()? {
            Record::LocationDb(rec) => rec.country.map(|c| c.short_name),
            Record::ProxyDb(_) => None,
        }?;
        normalize_country_code(&raw)
    }

    /// The full country name for `ip` (e.g. "United States"), or `None` when the
    /// IP is not resolvable. The IP2Location LITE DB stores the long name
    /// alongside the code, so this needs no extra dependency. Used for the
    /// human-facing password-reset email (BUNYIP-397); the login-location alert
    /// keeps the terser code.
    pub fn country_name(&self, ip: IpAddr) -> Option<String> {
        let raw = match self.db.ip_lookup(ip).ok()? {
            Record::LocationDb(rec) => rec.country.map(|c| c.long_name),
            Record::ProxyDb(_) => None,
        }?;
        normalize_country_name(&raw)
    }
}

/// Normalize an IP2Location country field into a usable ISO 3166-1 alpha-2 code,
/// or `None`. IP2Location stores `"-"` (and occasionally a blank) for unknown /
/// reserved ranges; those are not real countries and must never be treated as a
/// login-location change (BUNYIP-366).
fn normalize_country_code(raw: &str) -> Option<String> {
    let code = raw.trim();
    if code.is_empty() || code == "-" {
        None
    } else {
        Some(code.to_string())
    }
}

/// Normalize an IP2Location country long name into a display string, or `None`.
/// Like the code field, unknown / reserved ranges store `"-"` (or a blank),
/// which are not real countries and must not appear in the reset email.
fn normalize_country_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    if name.is_empty() || name == "-" {
        None
    } else {
        Some(name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_country_code, normalize_country_name};

    #[test]
    fn rejects_placeholder_and_blank() {
        assert_eq!(normalize_country_code("-"), None);
        assert_eq!(normalize_country_code(""), None);
        assert_eq!(normalize_country_code("   "), None);
    }

    #[test]
    fn keeps_and_trims_iso2() {
        assert_eq!(normalize_country_code("US"), Some("US".to_string()));
        assert_eq!(normalize_country_code(" GB "), Some("GB".to_string()));
    }

    #[test]
    fn name_rejects_placeholder_and_blank() {
        assert_eq!(normalize_country_name("-"), None);
        assert_eq!(normalize_country_name(""), None);
        assert_eq!(normalize_country_name("   "), None);
    }

    #[test]
    fn name_keeps_and_trims_long_name() {
        assert_eq!(
            normalize_country_name("United States of America"),
            Some("United States of America".to_string())
        );
        assert_eq!(
            normalize_country_name(" United Kingdom "),
            Some("United Kingdom".to_string())
        );
    }
}
