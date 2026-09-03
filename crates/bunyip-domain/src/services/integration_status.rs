//! BUNYIP-623: the per-integration status the admin System Status page renders.
//!
//! A self-hosted deployment starts with every integration switched off and stays
//! usable; this module turns "what is configured, what is off, what is half-set"
//! into a named list so a degraded capability is visible rather than inferred
//! from a failure. Each integration is one of three states, mirroring the Mokosh
//! status view's ok / skipped / error:
//!
//! - `Configured`: every input the integration needs is present.
//! - `Unconfigured`: the operator has not turned it on. Off by choice, not broken.
//! - `Failing`: turned on but missing a required piece, so the capability is
//!   broken. The blank SMTP password from the 2026-08-24 standup is this state.
//!
//! The reason and remedy text is single-sourced from the same [`ENV_INVENTORY`]
//! (BUNYIP-537) and [`GovernedSecret::feature`] the boot report uses, not a
//! second description of the same thing.
//!
//! [`ENV_INVENTORY`]: crate::config::ENV_INVENTORY

use serde::Serialize;

use crate::config::{env_spec, GovernedSecret, SecretsProvider};

/// One integration's state, mirroring Mokosh's ok / skipped / error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationState {
    /// Every input the integration needs is present.
    Configured,
    /// The operator has not turned it on. The capability is off by choice.
    Unconfigured,
    /// Turned on but missing a required piece, so the capability is broken.
    Failing,
}

/// One integration as the status view lists it.
#[derive(Debug, Clone, Serialize)]
pub struct IntegrationStatus {
    /// Stable machine key, e.g. `"email"`.
    pub key: &'static str,
    /// Display name, e.g. `"Email (SMTP)"`.
    pub name: &'static str,
    pub state: IntegrationState,
    /// What is configured, what is off, or what is broken, in an operator's words.
    pub detail: String,
    /// How to configure it. Empty when the integration is already configured.
    pub remedy: String,
}

/// The runtime facts the classifier needs, gathered by the caller from `Config`
/// and the governed-secrets survey. Plain data so the rules below are unit-tested
/// without a database or an environment.
#[derive(Debug, Clone, Copy)]
pub struct IntegrationSignals {
    /// The declared governed-secret provider, named in the SMTP / IMAP failure
    /// text.
    pub secrets_provider: SecretsProvider,
    /// An SMTP relay host is configured.
    pub smtp_host_set: bool,
    /// The SMTP password is present and non-empty in the declared provider.
    pub smtp_password_present: bool,
    /// The Stripe secret key is present in the declared provider.
    pub stripe_secret_present: bool,
    /// The Stripe webhook signing secret is present in the declared provider.
    pub stripe_webhook_present: bool,
    /// The support IMAP mailbox is enabled or has a host configured.
    pub imap_configured: bool,
    /// The IMAP password is present and non-empty in the declared provider.
    pub imap_password_present: bool,
    /// `INFISICAL_ENABLED` is set.
    pub infisical_enabled: bool,
    /// Every Infisical credential is present, so the client can be built.
    pub infisical_complete: bool,
    /// `SECRETS_STORAGE=infisical`: Infisical is the declared provider of record.
    pub infisical_is_provider: bool,
    /// A Forgejo base URL is configured for the distribution proxy.
    pub forgejo_base_set: bool,
    /// The Forgejo API token is present.
    pub forgejo_token_present: bool,
    /// The OCI registry endpoint is enabled.
    pub oci_enabled: bool,
    /// The OCI registry has a public hostname configured.
    pub oci_service_set: bool,
    /// The IP2Location `.BIN` path is configured.
    pub ip2location_set: bool,
    /// The IP2Proxy `.BIN` path is configured.
    pub ip2proxy_set: bool,
}

/// The `feature` text an inventory variable carries: what stops working when it
/// is absent. Empty for a name the inventory does not carry (the coverage test in
/// `bunyip-api/tests/env_inventory.rs` keeps that from happening for a real var).
fn feature_of(var: &str) -> String {
    env_spec(var)
        .map(|s| s.feature.to_string())
        .unwrap_or_default()
}

/// The `remedy` text an inventory variable carries: how the operator supplies it.
fn remedy_of(var: &str) -> String {
    env_spec(var)
        .map(|s| s.remedy.to_string())
        .unwrap_or_default()
}

fn status(
    key: &'static str,
    name: &'static str,
    state: IntegrationState,
    detail: String,
    remedy: String,
) -> IntegrationStatus {
    IntegrationStatus {
        key,
        name,
        state,
        detail,
        remedy,
    }
}

/// Classify every integration from the gathered [`IntegrationSignals`]. Pure, so
/// each rule below is unit-tested. The order is the order the status view lists
/// them in.
pub fn integration_statuses(sig: &IntegrationSignals) -> Vec<IntegrationStatus> {
    let provider = sig.secrets_provider.as_str();
    let mut out = Vec::new();

    // Email (SMTP). The blank-password case is `Failing`, not `Configured`: the
    // relay is reached but never authenticated, which is the exact degradation
    // the 2026-08-24 standup asked to see named rather than hit as a 500.
    out.push(if !sig.smtp_host_set {
        status(
            "email",
            "Email (SMTP)",
            IntegrationState::Unconfigured,
            feature_of("SMTP_HOST"),
            remedy_of("SMTP_HOST"),
        )
    } else if sig.smtp_password_present {
        status(
            "email",
            "Email (SMTP)",
            IntegrationState::Configured,
            "The SMTP relay is configured and authenticated.".to_string(),
            String::new(),
        )
    } else {
        status(
            "email",
            "Email (SMTP)",
            IntegrationState::Failing,
            format!(
                "SMTP_PASSWORD is unset in the {provider} provider: {}.",
                GovernedSecret::SmtpPassword.feature()
            ),
            format!(
                "Set the SMTP password in the {provider} provider (admin Email page, or \
                 `bunyip-api secrets-migrate`)."
            ),
        )
    });

    // Stripe billing. The secret key turns the feature on; the webhook secret is
    // the second half, without which webhook verification fails closed.
    out.push(if !sig.stripe_secret_present {
        status(
            "stripe",
            "Stripe billing",
            IntegrationState::Unconfigured,
            format!("{}.", GovernedSecret::StripeSecretKey.feature()),
            format!("Enter the Stripe secret key in the {provider} provider (admin Stripe page)."),
        )
    } else if sig.stripe_webhook_present {
        status(
            "stripe",
            "Stripe billing",
            IntegrationState::Configured,
            "The Stripe secret key and webhook signing secret are configured.".to_string(),
            String::new(),
        )
    } else {
        status(
            "stripe",
            "Stripe billing",
            IntegrationState::Failing,
            format!(
                "STRIPE_WEBHOOK_SECRET is unset in the {provider} provider: {}.",
                GovernedSecret::StripeWebhookSecret.feature()
            ),
            format!(
                "Enter the Stripe webhook signing secret in the {provider} provider (admin \
                 Stripe page)."
            ),
        )
    });

    // Support inbox (IMAP).
    out.push(if !sig.imap_configured {
        status(
            "support_inbox",
            "Support inbox (IMAP)",
            IntegrationState::Unconfigured,
            "Support-queue ingestion is off: replies to the system mailbox are not polled into \
             support tickets."
                .to_string(),
            "Set the IMAP host and enable the support inbox on the admin Email page.".to_string(),
        )
    } else if sig.imap_password_present {
        status(
            "support_inbox",
            "Support inbox (IMAP)",
            IntegrationState::Configured,
            "The IMAP mailbox is configured and authenticated.".to_string(),
            String::new(),
        )
    } else {
        status(
            "support_inbox",
            "Support inbox (IMAP)",
            IntegrationState::Failing,
            format!(
                "SUPPORT_IMAP_PASSWORD is unset in the {provider} provider: {}.",
                GovernedSecret::SupportImapPassword.feature()
            ),
            format!("Set the IMAP password in the {provider} provider (admin Email page)."),
        )
    });

    // Secrets provider (Infisical). `SECRETS_STORAGE=infisical` makes it the
    // provider of record (the app would not have booted if the client were
    // unbuildable, but it is reported so the operator can see the provider it
    // depends on); otherwise it is an optional inspection target for
    // `secrets-status`.
    out.push(if sig.infisical_is_provider {
        if sig.infisical_complete {
            status(
                "infisical",
                "Secrets provider (Infisical)",
                IntegrationState::Configured,
                "Infisical is the declared secrets provider and its client is configured."
                    .to_string(),
                String::new(),
            )
        } else {
            status(
                "infisical",
                "Secrets provider (Infisical)",
                IntegrationState::Failing,
                "SECRETS_STORAGE=infisical, but the Infisical client is not fully configured."
                    .to_string(),
                remedy_of("INFISICAL_ADDRESS"),
            )
        }
    } else if !sig.infisical_enabled {
        status(
            "infisical",
            "Secrets provider (Infisical)",
            IntegrationState::Unconfigured,
            feature_of("INFISICAL_ENABLED"),
            remedy_of("INFISICAL_ENABLED"),
        )
    } else if sig.infisical_complete {
        status(
            "infisical",
            "Secrets provider (Infisical)",
            IntegrationState::Configured,
            "Infisical is enabled and its client is configured for secrets-status inspection."
                .to_string(),
            String::new(),
        )
    } else {
        status(
            "infisical",
            "Secrets provider (Infisical)",
            IntegrationState::Failing,
            "INFISICAL_ENABLED is set, but the Infisical client is not fully configured."
                .to_string(),
            remedy_of("INFISICAL_ADDRESS"),
        )
    });

    // Distribution proxy (Forgejo): the upstream for member downloads and the
    // OCI registry.
    out.push(if !sig.forgejo_base_set {
        status(
            "distribution",
            "Distribution proxy (Forgejo)",
            IntegrationState::Unconfigured,
            feature_of("FORGEJO_BASE_URL"),
            remedy_of("FORGEJO_BASE_URL"),
        )
    } else if sig.forgejo_token_present {
        status(
            "distribution",
            "Distribution proxy (Forgejo)",
            IntegrationState::Configured,
            "The Forgejo base URL and API token are configured.".to_string(),
            String::new(),
        )
    } else {
        status(
            "distribution",
            "Distribution proxy (Forgejo)",
            IntegrationState::Failing,
            feature_of("FORGEJO_API_TOKEN"),
            remedy_of("FORGEJO_API_TOKEN"),
        )
    });

    // OCI registry endpoint.
    out.push(if !sig.oci_enabled {
        status(
            "oci",
            "OCI registry",
            IntegrationState::Unconfigured,
            feature_of("OCI_REGISTRY_ENABLED"),
            remedy_of("OCI_REGISTRY_ENABLED"),
        )
    } else if sig.oci_service_set {
        status(
            "oci",
            "OCI registry",
            IntegrationState::Configured,
            "The OCI registry is enabled with a public hostname.".to_string(),
            String::new(),
        )
    } else {
        status(
            "oci",
            "OCI registry",
            IntegrationState::Failing,
            feature_of("OCI_REGISTRY_SERVICE"),
            remedy_of("OCI_REGISTRY_SERVICE"),
        )
    });

    // GeoIP enrichment. A path either resolves at boot or the feature is off;
    // on-disk freshness is the admin dashboard Datasets card's job, not this one.
    out.push(geoip(
        "ip2location",
        "Login-location (IP2Location)",
        sig.ip2location_set,
        "IP2LOCATION_DB_PATH",
    ));
    out.push(geoip(
        "ip2proxy",
        "Proxy / ASN enrichment (IP2Proxy)",
        sig.ip2proxy_set,
        "IP2PROXY_DB_PATH",
    ));

    out
}

/// A dataset-path integration: configured when the path is set, unconfigured
/// otherwise. There is no half-configured state, so no `Failing`.
fn geoip(key: &'static str, name: &'static str, set: bool, var: &'static str) -> IntegrationStatus {
    if set {
        status(
            key,
            name,
            IntegrationState::Configured,
            format!("{var} is configured."),
            String::new(),
        )
    } else {
        status(
            key,
            name,
            IntegrationState::Unconfigured,
            feature_of(var),
            remedy_of(var),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deployment with nothing configured: every integration reads
    /// `Unconfigured`, none `Failing`. This is the self-hosting default the
    /// standup asked to keep usable, and it must never present as broken.
    fn nothing_configured() -> IntegrationSignals {
        IntegrationSignals {
            secrets_provider: SecretsProvider::Database,
            smtp_host_set: false,
            smtp_password_present: false,
            stripe_secret_present: false,
            stripe_webhook_present: false,
            imap_configured: false,
            imap_password_present: false,
            infisical_enabled: false,
            infisical_complete: false,
            infisical_is_provider: false,
            forgejo_base_set: false,
            forgejo_token_present: false,
            oci_enabled: false,
            oci_service_set: false,
            ip2location_set: false,
            ip2proxy_set: false,
        }
    }

    fn find<'a>(list: &'a [IntegrationStatus], key: &str) -> &'a IntegrationStatus {
        list.iter()
            .find(|s| s.key == key)
            .unwrap_or_else(|| panic!("no integration keyed {key}"))
    }

    #[test]
    fn with_nothing_configured_every_integration_is_unconfigured_never_failing() {
        let list = integration_statuses(&nothing_configured());
        assert!(!list.is_empty());
        for s in &list {
            assert_eq!(
                s.state,
                IntegrationState::Unconfigured,
                "{} should be Unconfigured, got {:?}",
                s.key,
                s.state
            );
            assert!(!s.remedy.is_empty(), "{} should carry a remedy", s.key);
        }
    }

    /// The standup's example: a blank SMTP password reads as Failing, and names
    /// the secret, the provider it was expected in, and the capability it
    /// disables.
    #[test]
    fn a_blank_smtp_password_is_a_named_failure_not_a_configured_relay() {
        let mut sig = nothing_configured();
        sig.secrets_provider = SecretsProvider::Infisical;
        sig.smtp_host_set = true;
        sig.smtp_password_present = false;

        let list = integration_statuses(&sig);
        let email = find(&list, "email");
        assert_eq!(email.state, IntegrationState::Failing);
        assert!(email.detail.contains("SMTP_PASSWORD"), "{}", email.detail);
        assert!(email.detail.contains("infisical"), "{}", email.detail);
        assert!(
            email.detail.contains("magic links"),
            "names the disabled capability: {}",
            email.detail
        );
    }

    #[test]
    fn a_configured_smtp_relay_reads_configured_with_no_remedy() {
        let mut sig = nothing_configured();
        sig.smtp_host_set = true;
        sig.smtp_password_present = true;

        let email = integration_statuses(&sig)
            .into_iter()
            .find(|s| s.key == "email")
            .unwrap();
        assert_eq!(email.state, IntegrationState::Configured);
        assert!(email.remedy.is_empty());
    }

    /// Stripe with a secret key but no webhook secret is half-configured: the
    /// webhook verification is the missing half, so the state is Failing.
    #[test]
    fn stripe_with_a_key_but_no_webhook_secret_is_failing() {
        let mut sig = nothing_configured();
        sig.stripe_secret_present = true;
        sig.stripe_webhook_present = false;

        let stripe = find(&integration_statuses(&sig), "stripe").clone();
        assert_eq!(stripe.state, IntegrationState::Failing);
        assert!(
            stripe.detail.contains("STRIPE_WEBHOOK_SECRET"),
            "{}",
            stripe.detail
        );

        sig.stripe_webhook_present = true;
        let stripe = find(&integration_statuses(&sig), "stripe").clone();
        assert_eq!(stripe.state, IntegrationState::Configured);
    }

    /// `SECRETS_STORAGE=infisical` with an incomplete client is Failing, and
    /// complete is Configured.
    #[test]
    fn infisical_as_the_declared_provider_reflects_client_completeness() {
        let mut sig = nothing_configured();
        sig.secrets_provider = SecretsProvider::Infisical;
        sig.infisical_is_provider = true;
        sig.infisical_complete = false;
        assert_eq!(
            find(&integration_statuses(&sig), "infisical").state,
            IntegrationState::Failing
        );

        sig.infisical_complete = true;
        assert_eq!(
            find(&integration_statuses(&sig), "infisical").state,
            IntegrationState::Configured
        );
    }
}
