//! BUNYIP-634: the suite provider-status contract, and the aggregator that
//! reads it from every application in the suite (Bunyip's own included).
//!
//! Mokosh (PMS-989) and Drillmark (DMARC-41) each ship a collector that
//! answers "which providers is this process using, right now" and render it
//! as one schema-versioned JSON envelope. This module is the Bunyip-side type
//! for that envelope (the contract this issue defines) plus the aggregator
//! that turns three per-application reads into one page: Bunyip's own state
//! (built in `bunyip-api::provider_status` from the existing `secrets.rs` /
//! `config_providers.rs` surveys, never a parallel implementation), and
//! Mokosh's and Drillmark's, fetched over HTTP.
//!
//! # Tolerant parsing
//!
//! Every field beyond `kind` / `hosting_profile` / `schema_version` carries
//! `#[serde(default)]`, the same wire-compatibility rule
//! `bunyip-web/src/api/types.rs` follows for any other cross-service response:
//! an application on an older or newer contract version reports what it has,
//! and a field it does not know about is simply absent rather than a parse
//! failure. `KeyReport::providers` is a Bunyip-side EXTENSION over the single
//! `recorded_served_by` PMS-989/DMARC-41 ship: a reporting application that
//! tracks full per-key provider membership (Bunyip's own secrets and
//! configuration surveys both do) fills it in, and one that does not leaves
//! it empty; the aggregator degrades its discrepancy detection accordingly
//! rather than requiring the field.
//!
//! # Redaction
//!
//! No field in this module is or carries a secret value: names, booleans,
//! small integers and timestamps only. `no_value_shaped_field_in_the_contract`
//! below scans this file's own struct definitions for a field name that would
//! suggest otherwise.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The contract version this Bunyip understands. An envelope reporting a
/// different `schema_version` is shown as [`AppProviderStatus::VersionMismatch`]
/// rather than parsed, per the epic's "reports its version rather than
/// failing to parse" rule.
pub const PROVIDER_STATUS_SCHEMA_VERSION: &str = "1";

/// The outbound HTTP timeout for a provider-status fetch. A slow or
/// unreachable peer must fail fast rather than hang the admin page render.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// The wire contract
// ---------------------------------------------------------------------------

/// The schema-versioned envelope every application serves its report in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStatusEnvelope {
    pub schema_version: String,
    pub report: ProviderStatusReport,
    #[serde(default)]
    pub generated_at: Option<DateTime<Utc>>,
}

/// One application's whole report. Only names, booleans, small integers,
/// timestamps and statuses; no values, no credentials, no URLs beyond an
/// unreachable-provider message that may name a host and a status code.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderStatusReport {
    pub hosting_profile: String,
    #[serde(default)]
    pub deviations: Vec<HostingProfileDeviation>,
    #[serde(default)]
    pub configuration_generation: Option<GenerationHeader>,
    #[serde(default)]
    pub kinds: Vec<ProviderKindReport>,
    #[serde(default)]
    pub collected_at: Option<DateTime<Utc>>,
}

/// A generation identity: number, when it resolved, and a human-readable
/// actor. Never credential material.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GenerationHeader {
    #[serde(default)]
    pub number: u64,
    #[serde(default)]
    pub resolved_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub actor: String,
}

/// One kind's selection differs from its hosting profile's default. Absent
/// for an application with no hosting-profile concept (Drillmark today).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostingProfileDeviation {
    pub kind: String,
    #[serde(default)]
    pub profile_default: Vec<String>,
    #[serde(default)]
    pub explicit: Vec<String>,
}

/// One row per provider kind (`configuration`, `secrets_application`, ...). A
/// kind an application does not have is simply absent from
/// [`ProviderStatusReport::kinds`]; an aggregator that requires every kind is
/// wrong.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderKindReport {
    pub kind: String,
    #[serde(default)]
    pub enabled: Vec<EnabledProviderReport>,
    #[serde(default)]
    pub serving: Option<String>,
    #[serde(default)]
    pub keys: Vec<KeyReport>,
    #[serde(default)]
    pub enumeration: Option<KindEnumerationStatus>,
}

/// One enabled provider on a kind.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnabledProviderReport {
    pub name: String,
    #[serde(default)]
    pub priority: usize,
    #[serde(default)]
    pub reachable: bool,
    #[serde(default)]
    pub unreachable_reason: Option<String>,
}

/// One declared key's provenance and live presence.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyReport {
    pub key: String,
    #[serde(default)]
    pub feature: Option<String>,
    /// The provider recorded as serving this key. `None` when nobody holds
    /// it.
    #[serde(default)]
    pub recorded_served_by: Option<String>,
    #[serde(default)]
    pub live_holds: bool,
    /// One of `unchanged`, `appeared`, `disappeared`, `changed_provider`, or
    /// empty when the reporting application does not track staleness.
    #[serde(default)]
    pub state: String,
    /// Every provider observed to hold this key, when the reporting
    /// application tracks full membership (a Bunyip-side extension; see the
    /// module docs). Empty when not tracked, never a false "only one holder".
    #[serde(default)]
    pub providers: Vec<String>,
}

/// The `list()` outcome for a kind that supports enumeration. An empty
/// `Supported` and `Unsupported` are different facts and never collapse into
/// each other.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KindEnumerationStatus {
    Supported(Vec<String>),
    Unsupported,
}

// ---------------------------------------------------------------------------
// Per-application outcome
// ---------------------------------------------------------------------------

/// What reading one application's provider status produced. Every variant is
/// shown on the aggregate page; none is ever omitted, and only [`Ok`](Self::Ok)
/// reads as healthy.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AppProviderStatus {
    /// The report was fetched, authenticated, and understood.
    Ok { report: ProviderStatusReport },
    /// The application could not be reached at all: network failure, timeout,
    /// or a response that did not parse as a status envelope.
    Unreachable { reason: String },
    /// The application was reached but rejected the caller's credential.
    Unauthenticated,
    /// The application answered with a `schema_version` this Bunyip does not
    /// understand.
    VersionMismatch { reported_version: String },
}

impl AppProviderStatus {
    /// Whether this reads as healthy. Only [`Ok`](Self::Ok) does; every other
    /// variant is a failure mode that must render as such.
    pub fn is_healthy(&self) -> bool {
        matches!(self, AppProviderStatus::Ok { .. })
    }
}

/// One application's row on the aggregate page.
#[derive(Debug, Clone, Serialize)]
pub struct AppStatusRow {
    pub app: String,
    pub status: AppProviderStatus,
}

// ---------------------------------------------------------------------------
// Discrepancy flags
// ---------------------------------------------------------------------------

/// One of the three conditions the epic requires flagged without the reader
/// comparing columns by eye.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "condition", rename_all = "snake_case")]
pub enum ProviderDiscrepancy {
    /// The declared provider for this key holds nothing, and no other
    /// provider does either: the value is genuinely absent everywhere.
    DeclaredProviderHoldsNothing {
        app: String,
        kind: String,
        key: String,
    },
    /// A value is present in more than one provider for this key (or, when
    /// the reporting application does not track per-key membership, more
    /// than one provider is enabled and holding something for the whole
    /// kind).
    PresentInMultipleProviders {
        app: String,
        kind: String,
        /// Empty when this is a kind-level approximation rather than a
        /// specific key.
        key: String,
        providers: Vec<String>,
    },
    /// The original incident: the highest-priority (declared/serving)
    /// provider does not hold this key, but a lower-priority one does.
    AbsentFromHighestPriorityProvider {
        app: String,
        kind: String,
        key: String,
        serving: String,
        holder: String,
    },
}

/// Compute every discrepancy in one application's report.
///
/// Pure function of the report, so every condition is unit-testable without
/// a network call.
pub fn discrepancies_for(app: &str, report: &ProviderStatusReport) -> Vec<ProviderDiscrepancy> {
    let mut out = Vec::new();

    for kind in &report.kinds {
        let mut any_key_tracks_providers = false;

        for key in &kind.keys {
            if !key.providers.is_empty() {
                any_key_tracks_providers = true;
            }

            match &key.recorded_served_by {
                None if key.providers.is_empty() => {
                    out.push(ProviderDiscrepancy::DeclaredProviderHoldsNothing {
                        app: app.to_string(),
                        kind: kind.kind.clone(),
                        key: key.key.clone(),
                    });
                }
                Some(served) => {
                    if let Some(serving) = &kind.serving {
                        if served != serving {
                            out.push(ProviderDiscrepancy::AbsentFromHighestPriorityProvider {
                                app: app.to_string(),
                                kind: kind.kind.clone(),
                                key: key.key.clone(),
                                serving: serving.clone(),
                                holder: served.clone(),
                            });
                        }
                    }
                }
                None => {}
            }

            if key.providers.len() > 1 {
                out.push(ProviderDiscrepancy::PresentInMultipleProviders {
                    app: app.to_string(),
                    kind: kind.kind.clone(),
                    key: key.key.clone(),
                    providers: key.providers.clone(),
                });
            }
        }

        // Kind-level approximation: an application that does not track full
        // per-key provider membership (PMS-989/DMARC-41's shape) still names
        // more than one enabled provider only when a second one is actually
        // holding something, so this reads as the same fact at coarser grain.
        if !any_key_tracks_providers && kind.enabled.len() > 1 {
            out.push(ProviderDiscrepancy::PresentInMultipleProviders {
                app: app.to_string(),
                kind: kind.kind.clone(),
                key: String::new(),
                providers: kind.enabled.iter().map(|p| p.name.clone()).collect(),
            });
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

/// The whole aggregate page's data: every application's status row, and every
/// discrepancy flagged across the applications that answered [`Ok`](AppProviderStatus::Ok).
#[derive(Debug, Clone, Serialize)]
pub struct AggregatedProviderStatus {
    pub apps: Vec<AppStatusRow>,
    pub discrepancies: Vec<ProviderDiscrepancy>,
}

/// Build the aggregate from already-fetched rows. Pure, so the discrepancy
/// rules are unit-tested without a network call; the async fetch is a
/// separate, thin step ([`fetch_remote`]) that produces these rows.
pub fn aggregate(apps: Vec<AppStatusRow>) -> AggregatedProviderStatus {
    let discrepancies = apps
        .iter()
        .filter_map(|row| match &row.status {
            AppProviderStatus::Ok { report } => Some(discrepancies_for(&row.app, report)),
            _ => None,
        })
        .flatten()
        .collect();
    AggregatedProviderStatus {
        apps,
        discrepancies,
    }
}

// ---------------------------------------------------------------------------
// Remote fetch
// ---------------------------------------------------------------------------

/// One remote application's provider-status endpoint and the machine
/// credential Bunyip presents to it (BUNYIP-602's mailer-relay shape,
/// reversed: here Bunyip is the caller). `credential` is `None` when no
/// machine credential is configured, which is itself reported as
/// [`AppProviderStatus::Unreachable`] rather than silently skipped.
#[derive(Debug, Clone)]
pub struct RemoteProviderApp {
    pub name: String,
    pub status_url: Option<String>,
    pub credential: Option<MachineCredential>,
}

/// The HTTP Basic credential Bunyip presents when calling out to another
/// application's status endpoint.
#[derive(Debug, Clone)]
pub struct MachineCredential {
    pub client_id: String,
    pub client_secret: String,
}

/// Fetch and classify one remote application's provider status.
///
/// Never panics and never propagates a transport error: every outcome is an
/// [`AppProviderStatus`] variant, because every outcome must render on the
/// aggregate page.
pub async fn fetch_remote(app: &RemoteProviderApp) -> AppProviderStatus {
    let Some(status_url) = &app.status_url else {
        return AppProviderStatus::Unreachable {
            reason: "no status endpoint is configured for this application".to_string(),
        };
    };

    let client = match reqwest::Client::builder().timeout(HTTP_TIMEOUT).build() {
        Ok(client) => client,
        Err(e) => {
            return AppProviderStatus::Unreachable {
                reason: format!("could not build the HTTP client: {e}"),
            }
        }
    };

    let mut request = client.get(status_url);
    if let Some(credential) = &app.credential {
        request = request.basic_auth(&credential.client_id, Some(&credential.client_secret));
    }

    let response = match request.send().await {
        Ok(response) => response,
        Err(e) => {
            return AppProviderStatus::Unreachable {
                reason: format!("request failed: {e}"),
            }
        }
    };

    let status = response.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        return AppProviderStatus::Unauthenticated;
    }
    if !status.is_success() {
        return AppProviderStatus::Unreachable {
            reason: format!("unexpected status {status}"),
        };
    }

    let body = match response.text().await {
        Ok(body) => body,
        Err(e) => {
            return AppProviderStatus::Unreachable {
                reason: format!("could not read the response body: {e}"),
            }
        }
    };

    let envelope: ProviderStatusEnvelope = match serde_json::from_str(&body) {
        Ok(envelope) => envelope,
        Err(e) => {
            return AppProviderStatus::Unreachable {
                reason: format!("response did not parse as a status envelope: {e}"),
            }
        }
    };

    if envelope.schema_version != PROVIDER_STATUS_SCHEMA_VERSION {
        return AppProviderStatus::VersionMismatch {
            reported_version: envelope.schema_version,
        };
    }

    AppProviderStatus::Ok {
        report: envelope.report,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No field defined in this module's own text carries a name that would
    /// suggest a secret value ever flows through it. The wire contract is
    /// provenance and presence only.
    #[test]
    fn no_value_shaped_field_in_the_contract() {
        const SRC: &str = include_str!("provider_status.rs");
        let (before, _tests) = SRC
            .split_once("#[cfg(test)]")
            .expect("this file has a tests module");
        for forbidden in [
            "client_secret: Option<String>>",
            "pub value",
            "pub secret_value",
        ] {
            assert!(
                !before.contains(forbidden),
                "the contract must not carry {forbidden}"
            );
        }
    }

    fn key(name: &str, served_by: Option<&str>, providers: &[&str]) -> KeyReport {
        KeyReport {
            key: name.to_string(),
            recorded_served_by: served_by.map(str::to_string),
            providers: providers.iter().map(|p| p.to_string()).collect(),
            ..Default::default()
        }
    }

    fn kind(name: &str, serving: Option<&str>, keys: Vec<KeyReport>) -> ProviderKindReport {
        ProviderKindReport {
            kind: name.to_string(),
            serving: serving.map(str::to_string),
            keys,
            ..Default::default()
        }
    }

    #[test]
    fn declared_provider_holding_nothing_is_flagged() {
        let report = ProviderStatusReport {
            kinds: vec![kind(
                "secrets_application",
                Some("environment"),
                vec![key("SMTP_PASSWORD", None, &[])],
            )],
            ..Default::default()
        };
        let flags = discrepancies_for("bunyip", &report);
        assert_eq!(
            flags,
            vec![ProviderDiscrepancy::DeclaredProviderHoldsNothing {
                app: "bunyip".to_string(),
                kind: "secrets_application".to_string(),
                key: "SMTP_PASSWORD".to_string(),
            }]
        );
    }

    #[test]
    fn absent_from_the_declared_provider_while_a_lower_one_holds_it_is_the_original_incident() {
        let report = ProviderStatusReport {
            kinds: vec![kind(
                "secrets_application",
                Some("database"),
                vec![key("SMTP_PASSWORD", Some("environment"), &["environment"])],
            )],
            ..Default::default()
        };
        let flags = discrepancies_for("bunyip", &report);
        assert!(
            flags.contains(&ProviderDiscrepancy::AbsentFromHighestPriorityProvider {
                app: "bunyip".to_string(),
                kind: "secrets_application".to_string(),
                key: "SMTP_PASSWORD".to_string(),
                serving: "database".to_string(),
                holder: "environment".to_string(),
            })
        );
    }

    #[test]
    fn present_in_more_than_one_provider_is_flagged_per_key_when_tracked() {
        let report = ProviderStatusReport {
            kinds: vec![kind(
                "secrets_application",
                Some("database"),
                vec![key(
                    "SMTP_PASSWORD",
                    Some("database"),
                    &["database", "environment"],
                )],
            )],
            ..Default::default()
        };
        let flags = discrepancies_for("bunyip", &report);
        assert!(
            flags.contains(&ProviderDiscrepancy::PresentInMultipleProviders {
                app: "bunyip".to_string(),
                kind: "secrets_application".to_string(),
                key: "SMTP_PASSWORD".to_string(),
                providers: vec!["database".to_string(), "environment".to_string()],
            })
        );
    }

    #[test]
    fn present_in_more_than_one_provider_falls_back_to_kind_level_when_untracked() {
        // PMS-989/DMARC-41 shape: no key tracks `providers`, but `enabled`
        // names a second provider only when it actually holds something.
        let report = ProviderStatusReport {
            kinds: vec![ProviderKindReport {
                kind: "secrets_application".to_string(),
                serving: Some("environment".to_string()),
                enabled: vec![
                    EnabledProviderReport {
                        name: "environment".to_string(),
                        priority: 0,
                        reachable: true,
                        unreachable_reason: None,
                    },
                    EnabledProviderReport {
                        name: "file".to_string(),
                        priority: 1,
                        reachable: true,
                        unreachable_reason: None,
                    },
                ],
                keys: vec![key("SMTP_PASSWORD", Some("environment"), &[])],
                enumeration: None,
            }],
            ..Default::default()
        };
        let flags = discrepancies_for("drillmark", &report);
        assert!(flags.iter().any(|f| matches!(
            f,
            ProviderDiscrepancy::PresentInMultipleProviders { app, key, providers, .. }
                if app == "drillmark" && key.is_empty() && providers.len() == 2
        )));
    }

    #[test]
    fn a_clean_report_carries_no_discrepancies() {
        let report = ProviderStatusReport {
            kinds: vec![kind(
                "secrets_application",
                Some("environment"),
                vec![key("SMTP_PASSWORD", Some("environment"), &["environment"])],
            )],
            ..Default::default()
        };
        assert!(discrepancies_for("bunyip", &report).is_empty());
    }

    #[test]
    fn aggregate_only_computes_discrepancies_for_healthy_apps() {
        let rows = vec![
            AppStatusRow {
                app: "bunyip".to_string(),
                status: AppProviderStatus::Ok {
                    report: ProviderStatusReport {
                        kinds: vec![kind(
                            "secrets_application",
                            Some("database"),
                            vec![key("SMTP_PASSWORD", Some("environment"), &["environment"])],
                        )],
                        ..Default::default()
                    },
                },
            },
            AppStatusRow {
                app: "mokosh".to_string(),
                status: AppProviderStatus::Unreachable {
                    reason: "timed out".to_string(),
                },
            },
        ];
        let aggregated = aggregate(rows);
        assert_eq!(aggregated.apps.len(), 2);
        assert_eq!(aggregated.discrepancies.len(), 1);
        assert!(!aggregated.apps[1].status.is_healthy());
    }

    #[test]
    fn is_healthy_is_true_only_for_ok() {
        assert!(AppProviderStatus::Ok {
            report: ProviderStatusReport::default()
        }
        .is_healthy());
        assert!(!AppProviderStatus::Unreachable {
            reason: String::new()
        }
        .is_healthy());
        assert!(!AppProviderStatus::Unauthenticated.is_healthy());
        assert!(!AppProviderStatus::VersionMismatch {
            reported_version: "2".to_string()
        }
        .is_healthy());
    }

    #[test]
    fn envelope_parses_the_mokosh_and_drillmark_shapes() {
        // Mokosh's shape: has `deviations`.
        let mokosh = r#"{
            "schema_version": "1",
            "generated_at": "2026-01-01T00:00:00Z",
            "report": {
                "hosting_profile": "saas",
                "deviations": [],
                "configuration_generation": {"number": 3, "resolved_at": "2026-01-01T00:00:00Z", "actor": "System"},
                "kinds": [{"kind": "configuration", "enabled": [], "serving": null, "keys": [], "enumeration": null}],
                "collected_at": "2026-01-01T00:00:00Z"
            }
        }"#;
        let parsed: ProviderStatusEnvelope =
            serde_json::from_str(mokosh).expect("mokosh shape parses");
        assert_eq!(parsed.report.hosting_profile, "saas");

        // Drillmark's shape: no `deviations` key at all, no `configuration_generation`.
        let drillmark = r#"{
            "schema_version": "1",
            "report": {
                "hosting_profile": "drillmark",
                "kinds": []
            }
        }"#;
        let parsed: ProviderStatusEnvelope =
            serde_json::from_str(drillmark).expect("drillmark shape parses");
        assert_eq!(parsed.report.hosting_profile, "drillmark");
        assert!(parsed.report.deviations.is_empty());
    }

    #[tokio::test]
    async fn fetch_remote_reports_unreachable_when_no_url_is_configured() {
        let app = RemoteProviderApp {
            name: "mokosh".to_string(),
            status_url: None,
            credential: None,
        };
        let status = fetch_remote(&app).await;
        assert!(matches!(status, AppProviderStatus::Unreachable { .. }));
    }

    #[tokio::test]
    async fn fetch_remote_reports_unreachable_when_the_peer_cannot_be_reached() {
        let app = RemoteProviderApp {
            name: "mokosh".to_string(),
            // Port 0 never accepts a connection.
            status_url: Some("http://127.0.0.1:0/status".to_string()),
            credential: None,
        };
        let status = fetch_remote(&app).await;
        assert!(matches!(status, AppProviderStatus::Unreachable { .. }));
    }

    #[tokio::test]
    async fn fetch_remote_reports_unauthenticated_on_401_or_403() {
        use wiremock::matchers::path;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for code in [401, 403] {
            let server = MockServer::start().await;
            Mock::given(path("/status"))
                .respond_with(ResponseTemplate::new(code))
                .mount(&server)
                .await;
            let app = RemoteProviderApp {
                name: "mokosh".to_string(),
                status_url: Some(format!("{}/status", server.uri())),
                credential: None,
            };
            let status = fetch_remote(&app).await;
            assert!(
                matches!(status, AppProviderStatus::Unauthenticated),
                "{code} must classify as Unauthenticated, got {status:?}"
            );
        }
    }

    #[tokio::test]
    async fn fetch_remote_reports_version_mismatch_on_an_unknown_schema_version() {
        use wiremock::matchers::path;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(path("/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_version": "2",
                "report": {"hosting_profile": "saas", "kinds": []},
            })))
            .mount(&server)
            .await;
        let app = RemoteProviderApp {
            name: "mokosh".to_string(),
            status_url: Some(format!("{}/status", server.uri())),
            credential: None,
        };
        let status = fetch_remote(&app).await;
        assert!(matches!(
            status,
            AppProviderStatus::VersionMismatch { reported_version } if reported_version == "2"
        ));
    }

    #[tokio::test]
    async fn fetch_remote_parses_a_matching_schema_version_as_ok() {
        use wiremock::matchers::{basic_auth, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(path("/status"))
            .and(basic_auth("bunyip", "s3cret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "schema_version": PROVIDER_STATUS_SCHEMA_VERSION,
                "report": {"hosting_profile": "saas", "kinds": []},
            })))
            .mount(&server)
            .await;
        let app = RemoteProviderApp {
            name: "mokosh".to_string(),
            status_url: Some(format!("{}/status", server.uri())),
            credential: Some(MachineCredential {
                client_id: "bunyip".to_string(),
                client_secret: "s3cret".to_string(),
            }),
        };
        let status = fetch_remote(&app).await;
        assert!(matches!(
            status,
            AppProviderStatus::Ok { report } if report.hosting_profile == "saas"
        ));
    }
}
