//! Outbound-URL screening for the BUNYIP-1089 URL health worker.
//!
//! Resolves the host once, up front, and refuses when any resolved address
//! sits in an IANA-reserved private, loopback, link-local or wildcard range.
//! The caller then makes an HTTP request against the same URL with reqwest's
//! own resolver; a DNS-rebinding window still exists between our check and
//! the request, and the worker's log line records every resolved IP so an
//! incident is attributable. v1 trade-off; a resolve-then-connect-by-IP
//! client is the eventual fix, tracked under its own ticket when it becomes
//! necessary.
//!
//! Scope: this module is for operator-configured destinations the worker
//! fetches at a known cadence. Do not wire it into a user-triggered fetch
//! without also adding the rate-limit and auth layer that path needs.

use std::net::IpAddr;
use std::time::Duration;

use thiserror::Error;
use tokio::net::lookup_host;
use url::Url;

/// How long we let the up-front DNS lookup run before refusing the URL.
/// A health-check probe that cannot resolve inside this window is not worth
/// retrying on this pass; the next pass will try again.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScreenRefusal {
    #[error("URL does not parse: {0}")]
    Unparseable(String),
    #[error("URL scheme must be http or https, not `{scheme}`")]
    Scheme { scheme: String },
    #[error("URL has no host")]
    NoHost,
    #[error("host `{host}` resolves to no addresses")]
    NoAddresses { host: String },
    #[error("host `{host}` resolves to a reserved address ({addr})")]
    ReservedAddress { host: String, addr: IpAddr },
    #[error("DNS lookup for `{host}` timed out")]
    LookupTimeout { host: String },
    #[error("DNS lookup for `{host}` failed: {error}")]
    LookupError { host: String, error: String },
}

/// The screening result the caller gets on success: the parsed URL plus every
/// address the host resolved to, so the caller's log line names them.
#[derive(Debug, Clone)]
pub struct ScreenedUrl {
    pub url: Url,
    pub resolved: Vec<IpAddr>,
}

/// Screen `raw` for the URL health worker.
///
/// Rejects every reserved range: loopback (127/8, ::1), private IPv4
/// (RFC 1918), link-local IPv4 (169.254/16), ULA (fc00::/7), link-local IPv6
/// (fe80::/10), the wildcard addresses 0.0.0.0 and ::, and anything that is
/// not http(s).
pub async fn screen_url(raw: &str) -> Result<ScreenedUrl, ScreenRefusal> {
    let url = Url::parse(raw).map_err(|e| ScreenRefusal::Unparseable(e.to_string()))?;
    let scheme = url.scheme().to_string();
    if scheme != "http" && scheme != "https" {
        return Err(ScreenRefusal::Scheme { scheme });
    }
    let host = url.host_str().ok_or(ScreenRefusal::NoHost)?.to_string();
    let port = url.port_or_known_default().unwrap_or(0);

    // Resolve once, up front. `reqwest` will resolve again at request time;
    // see the module docstring for the rebinding trade-off.
    let lookup_target = format!("{host}:{port}");
    let addrs = match tokio::time::timeout(LOOKUP_TIMEOUT, lookup_host(lookup_target)).await {
        Ok(Ok(iter)) => iter.map(|sa| sa.ip()).collect::<Vec<_>>(),
        Ok(Err(e)) => {
            return Err(ScreenRefusal::LookupError {
                host,
                error: e.to_string(),
            });
        }
        Err(_) => {
            return Err(ScreenRefusal::LookupTimeout { host });
        }
    };
    if addrs.is_empty() {
        return Err(ScreenRefusal::NoAddresses { host });
    }
    for addr in &addrs {
        if is_reserved(addr) {
            return Err(ScreenRefusal::ReservedAddress { host, addr: *addr });
        }
    }
    Ok(ScreenedUrl {
        url,
        resolved: addrs,
    })
}

/// Pure, testable classifier. Covered by its own unit tests below.
pub fn is_reserved(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            let segs = v6.segments();
            // Unique local addresses: fc00::/7.
            if (segs[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // Link-local: fe80::/10.
            if (segs[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // v4-mapped: classify by the embedded v4 address so a reserved
            // v4 target hidden under `::ffff:0:0/96` is still refused.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_reserved(&IpAddr::V4(v4));
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn classifier_refuses_every_reserved_range() {
        let cases: &[IpAddr] = &[
            // IPv4 ranges we must refuse.
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), // loopback
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),  // 10/8
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), // 192.168/16
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), // 172.16/12
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), // link-local
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),   // unspecified
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), // broadcast
            IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3)),   // 0/8
            // IPv6 ranges we must refuse.
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)), // ULA
            IpAddr::V6(Ipv6Addr::new(0xfd12, 0, 0, 0, 0, 0, 0, 1)), // ULA second half
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), // link-local
            // v4-mapped reserved: must bottom out through the classifier again.
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
        ];
        for addr in cases {
            assert!(is_reserved(addr), "classifier must refuse {addr}");
        }
    }

    #[test]
    fn classifier_permits_public_addresses() {
        let cases: &[IpAddr] = &[
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),       // Cloudflare
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),       // Google
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), // example.com's historical v4
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), // docs range; not actually reserved in classifier terms
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)), // Cloudflare v6
        ];
        for addr in cases {
            assert!(!is_reserved(addr), "classifier must accept {addr}");
        }
    }

    #[tokio::test]
    async fn screen_rejects_non_http_scheme() {
        let err = screen_url("ftp://example.com/").await.unwrap_err();
        assert!(matches!(err, ScreenRefusal::Scheme { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn screen_rejects_unparseable() {
        let err = screen_url("not a url").await.unwrap_err();
        assert!(matches!(err, ScreenRefusal::Unparseable(_)), "{err:?}");
    }

    #[tokio::test]
    async fn screen_rejects_loopback_literal() {
        let err = screen_url("http://127.0.0.1/health").await.unwrap_err();
        assert!(
            matches!(
                err,
                ScreenRefusal::ReservedAddress { addr: IpAddr::V4(v), .. } if v.is_loopback()
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn screen_rejects_private_v4_literal() {
        let err = screen_url("https://10.0.0.5/health").await.unwrap_err();
        assert!(
            matches!(err, ScreenRefusal::ReservedAddress { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn screen_rejects_ipv6_loopback_literal() {
        let err = screen_url("http://[::1]/health").await.unwrap_err();
        assert!(
            matches!(err, ScreenRefusal::ReservedAddress { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn screen_rejects_a_host_with_no_resolvable_addresses() {
        // A reserved TLD (RFC 2606) that no DNS server resolves.
        let err = screen_url("https://nothing.invalid/health")
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ScreenRefusal::NoAddresses { .. } | ScreenRefusal::LookupError { .. }
            ),
            "{err:?}"
        );
    }
}
