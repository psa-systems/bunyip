//! BUNYIP-634: Bunyip's own row on the suite provider-status aggregate.
//!
//! Maps the EXISTING governed-secrets survey (`crate::secrets`) and
//! configuration-provider stack (`crate::config_status` /
//! `bunyip_domain::config_providers`) into the shared
//! [`bunyip_domain::services::provider_status`] contract. No parallel
//! implementation: both surveys already redact to names, booleans and
//! provenance only (`secrets-status` / `config-status`), so this module is
//! purely a reshape of data those two already compute.

use bunyip_domain::config::{secret_env, SecretsProvider};
use bunyip_domain::config_providers::ConfigStack;
use bunyip_domain::services::provider_status::{
    EnabledProviderReport, KeyReport, MachineCredential, ProviderKindReport, ProviderStatusReport,
    RemoteProviderApp,
};

use crate::secrets::{status_report as secrets_status_report, Survey};

/// The static hosting-profile identifier Bunyip reports. Bunyip has no
/// `DeploymentMode` equivalent (that concept is Mokosh's); a single stable
/// string keeps the field uniform across the suite, the same choice
/// Drillmark made for the same reason.
pub const HOSTING_PROFILE: &str = "bunyip";

/// Build Bunyip's own provider-status report from its two existing surveys.
pub fn own_report(secrets_survey: &Survey, config_stack: &ConfigStack) -> ProviderStatusReport {
    ProviderStatusReport {
        hosting_profile: HOSTING_PROFILE.to_string(),
        deviations: Vec::new(),
        configuration_generation: None,
        kinds: vec![
            configuration_kind(config_stack),
            secrets_application_kind(secrets_survey),
        ],
        collected_at: Some(chrono::Utc::now()),
    }
}

fn configuration_kind(stack: &ConfigStack) -> ProviderKindReport {
    let report = bunyip_domain::config_providers::status_report(stack);

    let enabled: Vec<EnabledProviderReport> = report
        .priority
        .iter()
        .enumerate()
        .map(|(priority, name)| {
            let unreadable = report.unreadable.iter().find(|e| &e.provider == name);
            EnabledProviderReport {
                name: name.clone(),
                priority,
                reachable: unreadable.is_none(),
                unreachable_reason: unreadable.map(|e| e.error.clone()),
            }
        })
        .collect();

    let keys: Vec<KeyReport> = report
        .keys
        .iter()
        .map(|key| KeyReport {
            key: key.key.clone(),
            feature: None,
            recorded_served_by: key.serving.clone(),
            live_holds: key.serving.is_some(),
            state: key.condition.clone(),
            providers: key.providers.clone(),
        })
        .collect();

    ProviderKindReport {
        kind: "configuration".to_string(),
        enabled,
        serving: report.priority.first().cloned(),
        keys,
        enumeration: None,
    }
}

fn secrets_application_kind(survey: &Survey) -> ProviderKindReport {
    let report = secrets_status_report(survey);

    let enabled: Vec<EnabledProviderReport> = SecretsProvider::ALL
        .iter()
        .enumerate()
        .map(|(priority, provider)| {
            let name = provider.as_str().to_string();
            let (reachable, unreachable_reason) =
                if *provider == SecretsProvider::Infisical && !report.infisical_inspected {
                    (
                        report.infisical_error.is_none(),
                        report.infisical_error.clone(),
                    )
                } else {
                    (true, None)
                };
            EnabledProviderReport {
                name,
                priority,
                reachable,
                unreachable_reason,
            }
        })
        .collect();

    let keys: Vec<KeyReport> = report
        .secrets
        .iter()
        .map(|s| KeyReport {
            key: s.secret.clone(),
            feature: None,
            recorded_served_by: s.live_source.clone(),
            live_holds: s.live_source.is_some(),
            state: "unchanged".to_string(),
            providers: s.providers.clone(),
        })
        .collect();

    ProviderKindReport {
        kind: "secrets_application".to_string(),
        enabled,
        serving: Some(report.declared.clone()),
        keys,
        enumeration: None,
    }
}

/// Every remote application in the suite, and the machine credential Bunyip
/// presents to each. Both Mokosh and Drillmark appear here unconditionally
/// (BUNYIP-634's "never omitted" rule): an unset URL or credential means a
/// `None`, and [`bunyip_domain::services::provider_status::fetch_remote`]
/// reports that as `Unreachable` rather than dropping the row.
pub fn remote_apps() -> Vec<RemoteProviderApp> {
    let client_id = std::env::var("PROVIDER_STATUS_CLIENT_ID")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let client_secret =
        secret_env("PROVIDER_STATUS_CLIENT_SECRET").filter(|v| !v.trim().is_empty());
    let credential = match (client_id, client_secret) {
        (Some(client_id), Some(client_secret)) => Some(MachineCredential {
            client_id,
            client_secret,
        }),
        _ => None,
    };

    let mokosh_url = std::env::var("MOKOSH_PROVIDER_STATUS_URL")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let drillmark_url = std::env::var("DRILLMARK_PROVIDER_STATUS_URL")
        .ok()
        .filter(|v| !v.trim().is_empty());

    vec![
        RemoteProviderApp {
            name: "mokosh".to_string(),
            status_url: mokosh_url,
            credential: credential.clone(),
        },
        RemoteProviderApp {
            name: "drillmark".to_string(),
            status_url: drillmark_url,
            credential,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{SecretSurvey, Survey};
    use bunyip_domain::config::GovernedSecret;

    fn survey_with(holders: Vec<(GovernedSecret, Vec<SecretsProvider>)>) -> Survey {
        Survey {
            provider: SecretsProvider::Environment,
            secrets: holders
                .into_iter()
                .map(|(secret, holders)| SecretSurvey {
                    secret,
                    holders,
                    value: None,
                })
                .collect(),
            infisical_inspected: false,
            infisical_error: None,
        }
    }

    fn full_survey(declared: SecretsProvider, holders: Vec<SecretsProvider>) -> Survey {
        Survey {
            provider: declared,
            secrets: GovernedSecret::ALL
                .iter()
                .map(|secret| SecretSurvey {
                    secret: *secret,
                    holders: holders.clone(),
                    value: None,
                })
                .collect(),
            infisical_inspected: false,
            infisical_error: None,
        }
    }

    #[test]
    fn own_report_names_the_static_hosting_profile() {
        let survey = full_survey(
            SecretsProvider::Environment,
            vec![SecretsProvider::Environment],
        );
        let stack = ConfigStack::new(Vec::new());
        let report = own_report(&survey, &stack);
        assert_eq!(report.hosting_profile, "bunyip");
    }

    #[test]
    fn own_report_carries_both_kinds() {
        let survey = full_survey(
            SecretsProvider::Environment,
            vec![SecretsProvider::Environment],
        );
        let stack = ConfigStack::new(Vec::new());
        let report = own_report(&survey, &stack);
        let kinds: Vec<&str> = report.kinds.iter().map(|k| k.kind.as_str()).collect();
        assert_eq!(kinds, vec!["configuration", "secrets_application"]);
    }

    #[test]
    fn secrets_kind_reflects_the_declared_provider_and_holders() {
        let survey = full_survey(SecretsProvider::Database, vec![SecretsProvider::Database]);
        let stack = ConfigStack::new(Vec::new());
        let report = own_report(&survey, &stack);
        let secrets_kind = report
            .kinds
            .iter()
            .find(|k| k.kind == "secrets_application")
            .unwrap();
        assert_eq!(secrets_kind.serving.as_deref(), Some("database"));
        for key in &secrets_kind.keys {
            assert_eq!(key.recorded_served_by.as_deref(), Some("database"));
            assert!(key.live_holds);
        }
    }

    #[test]
    fn secrets_kind_names_every_governed_secret() {
        let survey = full_survey(SecretsProvider::Environment, vec![]);
        let stack = ConfigStack::new(Vec::new());
        let report = own_report(&survey, &stack);
        let secrets_kind = report
            .kinds
            .iter()
            .find(|k| k.kind == "secrets_application")
            .unwrap();
        assert_eq!(secrets_kind.keys.len(), GovernedSecret::ALL.len());
    }

    #[test]
    fn a_secret_held_by_more_than_one_provider_carries_every_holder() {
        let survey = survey_with(
            GovernedSecret::ALL
                .iter()
                .map(|s| {
                    (
                        *s,
                        vec![SecretsProvider::Environment, SecretsProvider::Database],
                    )
                })
                .collect(),
        );
        let stack = ConfigStack::new(Vec::new());
        let report = own_report(&survey, &stack);
        let secrets_kind = report
            .kinds
            .iter()
            .find(|k| k.kind == "secrets_application")
            .unwrap();
        for key in &secrets_kind.keys {
            assert_eq!(key.providers.len(), 2);
        }
    }
}
