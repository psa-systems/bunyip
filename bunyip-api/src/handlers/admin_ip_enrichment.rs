//! Admin IP enrichment lookup (BUNYIP-437).
//!
//! A narrow "address in, enrichment out" endpoint: given a client IP, return
//! its ASN, owning organization, network category and VPN/proxy likelihood so
//! an admin deciding whether to ban or trust an address has the context in front
//! of them. The lookup is offline (an IP2Proxy PX `.BIN` via
//! `dunite-ipenrich`), and the signal is strictly advisory: it never classifies
//! a request as abuse on its own, which BUNYIP-437 was explicit about.
//!
//! Everything is `None`-tolerant. When `IP2PROXY_DB_PATH` is unset (no service),
//! the address is private/reserved, or the dataset has no record for it, the
//! endpoint returns a no-data success rather than an error, so the caller shows
//! "no enrichment" instead of a failure. Only a malformed IP is a client error.

use std::net::IpAddr;
use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::responses::{get_request_id, success, success_no_data};
use crate::services::{IpEnrichService, IpEnrichment};

/// Query for `GET /v1/admin/ip-enrichment?ip=<addr>`.
#[derive(Debug, Deserialize)]
pub struct IpEnrichmentQuery {
    pub ip: String,
}

/// The advisory enrichment of one address, as returned to the admin UI.
///
/// `category` and `vpn` are the stable lowercase labels of the classified enums
/// (so the web layer renders them without re-deriving IP2Proxy's vocabulary),
/// and `is_anonymizing` is the one-bit "looks like a VPN / proxy" summary.
/// `advisory` is always `true`: it is a reminder in the payload itself that this
/// signal is context for a human, not a verdict.
#[derive(Debug, Serialize)]
pub struct IpEnrichmentResponse {
    pub ip: String,
    pub asn: Option<String>,
    pub organization: Option<String>,
    pub isp: Option<String>,
    pub category: String,
    pub vpn: String,
    pub is_anonymizing: bool,
    pub proxy_type: Option<String>,
    pub provider: Option<String>,
    pub threat: Option<String>,
    pub advisory: bool,
}

impl IpEnrichmentResponse {
    fn from_enrichment(ip: &str, e: &IpEnrichment) -> Self {
        Self {
            ip: ip.to_string(),
            asn: e.asn.clone(),
            organization: e.organization.clone(),
            isp: e.isp.clone(),
            category: e.category.label().to_string(),
            vpn: e.vpn.label().to_string(),
            is_anonymizing: e.vpn.is_anonymizing(),
            proxy_type: e.proxy_type.clone(),
            provider: e.provider.clone(),
            threat: e.threat.clone(),
            advisory: true,
        }
    }
}

/// GET /v1/admin/ip-enrichment?ip=<addr>
///
/// AdminUser-guarded. Returns the [`IpEnrichmentResponse`] for `ip`, or a
/// no-data success when there is nothing to report (see the module docs).
pub async fn ip_enrichment(
    req: HttpRequest,
    _admin: AdminUser,
    query: web::Query<IpEnrichmentQuery>,
    enrich: web::Data<Option<Arc<IpEnrichService>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let ip: IpAddr = query
        .ip
        .trim()
        .parse()
        .map_err(|_| AppError::bad_request("Invalid IP address"))?;

    // No database configured -> the feature is off; report nothing rather than
    // erroring, so an admin box without the dataset degrades cleanly.
    let Some(svc) = enrich.get_ref().as_ref() else {
        return Ok(success_no_data(request_id));
    };

    // A private/reserved address or an address the dataset does not know both
    // resolve to None; neither is an error.
    match svc.enrich(ip) {
        Some(e) => Ok(success(
            IpEnrichmentResponse::from_enrichment(query.ip.trim(), &e),
            request_id,
        )),
        None => Ok(success_no_data(request_id)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{NetworkCategory, VpnLikelihood};

    #[test]
    fn response_maps_labels_and_is_always_advisory() {
        let e = IpEnrichment {
            asn: Some("15169".into()),
            organization: Some("Google LLC".into()),
            isp: None,
            category: NetworkCategory::Hosting,
            vpn: VpnLikelihood::Vpn,
            proxy_type: Some("VPN".into()),
            provider: Some("NordVPN".into()),
            threat: None,
        };
        let r = IpEnrichmentResponse::from_enrichment("203.0.113.7", &e);
        assert_eq!(r.category, "hosting");
        assert_eq!(r.vpn, "vpn");
        assert!(r.is_anonymizing);
        assert!(r.advisory, "the response always marks itself advisory");
        assert_eq!(r.organization.as_deref(), Some("Google LLC"));
        assert_eq!(r.isp, None);
    }

    #[test]
    fn data_center_is_shown_but_not_flagged_anonymizing() {
        let e = IpEnrichment {
            asn: Some("16509".into()),
            organization: Some("Amazon.com".into()),
            isp: None,
            category: NetworkCategory::Hosting,
            vpn: VpnLikelihood::DataCenter,
            proxy_type: Some("DCH".into()),
            provider: None,
            threat: None,
        };
        let r = IpEnrichmentResponse::from_enrichment("203.0.113.9", &e);
        assert_eq!(r.vpn, "data-center");
        assert!(!r.is_anonymizing);
    }
}
