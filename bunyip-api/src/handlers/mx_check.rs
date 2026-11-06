//! BUNYIP-925: MX-record lookup for the feedback-intake spam gate. A feedback
//! submission whose email domain is NXDOMAIN or holds no MX records is quarantined
//! as spam, so marketing floods from unregistered domains never reach the Active
//! queue. An A/AAAA-only domain still counts as no-MX (per David's call), matching
//! what real inbound mail servers reject.
//!
//! The resolver call is behind a trait so unit tests can drive the four outcomes
//! (has-MX, no-MX, NXDOMAIN, resolver error / timeout) without a network. Results
//! are cached per domain for one hour so a spam burst from one domain costs one
//! lookup, not N. On resolver error or timeout we fail OPEN (`Unknown`): a
//! transient DNS outage must not swallow real feedback.
//!
//! No DB schema change; the classifier downstream uses this crate's
//! `MxLookupOutcome` to decide whether to flip `is_spam`.

use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::error::{ResolveError, ResolveErrorKind};
use hickory_resolver::TokioAsyncResolver;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Per-lookup DNS timeout. A bulk spam burst does not deserve a long wait,
/// and a slow resolver should degrade to `Unknown` (fail open) quickly.
const MX_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a resolved outcome is cached before a re-lookup. One hour matches
/// the ticket's assumption; long enough that a spam burst pays for one lookup.
const MX_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

/// Outcome of the MX lookup. The classifier only fires on `NoMx`; `HasMx`
/// leaves the submission alone, and `Unknown` leaves it alone too (fail open
/// so transient DNS outages do not drop real feedback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MxLookupOutcome {
    /// Domain resolves and holds at least one MX record.
    HasMx,
    /// Domain is NXDOMAIN, or resolves but holds no MX records (an A/AAAA-only
    /// domain cannot receive mail by the SMTP RFCs and counts as no-MX here).
    NoMx,
    /// Lookup could not be completed (timeout, resolver error, non-authoritative
    /// failure). Fail open.
    Unknown,
}

#[async_trait]
pub trait MxResolver: Send + Sync {
    async fn lookup(&self, domain: &str) -> MxLookupOutcome;
}

/// Pull the domain part out of an email. Returns `None` for input without an
/// `@`, an empty domain, or a domain longer than DNS allows (253 octets).
/// Lower-cases the result so the cache keys and the lookup hostname match
/// the DNS canonical form. Deliberately permissive on the local-part: this
/// gate runs AFTER `validate_email`, so the string is already a sane address.
pub fn domain_of(email: &str) -> Option<String> {
    let at = email.rfind('@')?;
    let domain = email[at + 1..].trim();
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}

/// Production resolver backed by hickory's tokio async resolver. Reads the
/// system `resolv.conf` so operators do not configure DNS twice; falls back
/// to Google's public resolver only if parsing the system config fails,
/// which keeps a misconfigured container from silently disabling the gate.
pub struct HickoryMxResolver {
    inner: TokioAsyncResolver,
    cache: Arc<RwLock<HashMap<String, (Instant, MxLookupOutcome)>>>,
}

impl HickoryMxResolver {
    pub fn new() -> Self {
        let inner = match hickory_resolver::system_conf::read_system_conf() {
            Ok((config, opts)) => TokioAsyncResolver::tokio(config, opts),
            Err(_) => TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default()),
        };
        Self {
            inner,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn cache_get(&self, domain: &str) -> Option<MxLookupOutcome> {
        let guard = self.cache.read();
        let (at, outcome) = guard.get(domain)?;
        if at.elapsed() < MX_CACHE_TTL {
            Some(*outcome)
        } else {
            None
        }
    }

    fn cache_put(&self, domain: String, outcome: MxLookupOutcome) {
        let mut guard = self.cache.write();
        guard.insert(domain, (Instant::now(), outcome));
    }
}

impl Default for HickoryMxResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MxResolver for HickoryMxResolver {
    async fn lookup(&self, domain: &str) -> MxLookupOutcome {
        if let Some(cached) = self.cache_get(domain) {
            return cached;
        }
        let outcome =
            match tokio::time::timeout(MX_LOOKUP_TIMEOUT, self.inner.mx_lookup(domain)).await {
                Ok(Ok(lookup)) => {
                    if lookup.iter().next().is_some() {
                        MxLookupOutcome::HasMx
                    } else {
                        MxLookupOutcome::NoMx
                    }
                }
                Ok(Err(e)) => match e.kind() {
                    ResolveErrorKind::NoRecordsFound { .. } => MxLookupOutcome::NoMx,
                    _ => resolver_error_to_outcome(&e),
                },
                Err(_) => MxLookupOutcome::Unknown,
            };
        self.cache_put(domain.to_string(), outcome);
        outcome
    }
}

/// Map a hickory resolver error to an outcome. NXDOMAIN counts as `NoMx`;
/// everything else (timeout, upstream SERVFAIL, I/O error) is `Unknown` so
/// we fail open.
fn resolver_error_to_outcome(e: &ResolveError) -> MxLookupOutcome {
    match e.kind() {
        ResolveErrorKind::NoRecordsFound { .. } => MxLookupOutcome::NoMx,
        _ => MxLookupOutcome::Unknown,
    }
}

#[cfg(test)]
pub mod test_support {
    use super::*;

    /// Fixed-answer resolver for unit tests. The classifier's unit tests need
    /// to drive the four outcomes without a network round-trip.
    pub struct StubResolver {
        pub outcome: MxLookupOutcome,
    }

    #[async_trait]
    impl MxResolver for StubResolver {
        async fn lookup(&self, _domain: &str) -> MxLookupOutcome {
            self.outcome
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_of_extracts_lowercase_domain_part() {
        assert_eq!(
            domain_of("alice@EXAMPLE.com"),
            Some("example.com".to_string())
        );
        assert_eq!(domain_of("  bob@a.test  "), Some("a.test".to_string()));
    }

    #[test]
    fn domain_of_returns_none_without_an_at_sign() {
        assert_eq!(domain_of("not-an-email"), None);
    }

    #[test]
    fn domain_of_rejects_empty_or_oversized_domain() {
        assert_eq!(domain_of("alice@"), None);
        let too_long = format!("a@{}", "x".repeat(254));
        assert_eq!(domain_of(&too_long), None);
    }

    #[tokio::test]
    async fn stub_resolver_returns_configured_outcome() {
        let r = test_support::StubResolver {
            outcome: MxLookupOutcome::NoMx,
        };
        assert_eq!(r.lookup("example.com").await, MxLookupOutcome::NoMx);
    }
}
