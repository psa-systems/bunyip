//! BUNYIP-1011: the non-secret suite facts bunyip serves to a registered
//! calling app.
//!
//! The configuration twin of [`crate::host_secrets`]. Same shape, same
//! reasoning, one difference that is the whole point of a second route: these
//! values are not secrets, so they travel under their own entitlement
//! (`oauth_clients.allowed_config_keys`) and a credential that may read them is
//! not thereby allowed to read a secret (BUNYIP-855 D9).
//!
//! ## Why a registry here too
//!
//! For the reason the secrets route has one: a route that looks a caller's
//! string up in bunyip's configuration would serve whatever that string names.
//! A key is servable only if it is a variant here, and a `GovernedSecret`'s
//! name is deliberately not one of them, so the two registries cannot be
//! crossed by naming a key.
//!
//! ## The first key
//!
//! `mokosh/abuse_contact_email`, resolved from `SUPPORT_INBOX_EMAIL`: bunyip
//! owns the monitored support mailbox, and Mokosh carries the same address as
//! `ABUSE_CONTACT_EMAIL` for its abuse and legal surfaces. Today changing
//! mailbox means editing every product's environment, which is the same
//! two-homes-for-one-value problem BUNYIP-983 removed for the Google client.

use bunyip_domain::config::Config;

/// A configuration value this route can serve, by the key a caller asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostConfig {
    /// `mokosh/abuse_contact_email`: the monitored support mailbox, which
    /// Mokosh renders on its abuse and legal surfaces (PMS-1553 reads it).
    MokoshAbuseContactEmail,
}

/// Every servable key, which is also what `machine-client register
/// --config-key` validates an operator's spelling against.
pub const HOST_CONFIG_KEYS: &[&str] = &[HostConfig::MokoshAbuseContactEmail.key()];

impl HostConfig {
    /// The key as a caller spells it, namespaced by the product that reads it.
    pub const fn key(self) -> &'static str {
        match self {
            Self::MokoshAbuseContactEmail => "mokosh/abuse_contact_email",
        }
    }

    /// The variant for a key, or `None` for a key this build cannot serve.
    pub fn parse(key: &str) -> Option<Self> {
        match key {
            "mokosh/abuse_contact_email" => Some(Self::MokoshAbuseContactEmail),
            _ => None,
        }
    }

    /// The value, or `None` when this deployment has not set it.
    ///
    /// Synchronous and allocation-light on purpose: every value here comes from
    /// configuration bunyip has already resolved at boot, which is what makes
    /// this route a read of process state rather than a second trip to the
    /// database.
    pub fn resolve(self, config: &Config) -> Option<String> {
        match self {
            Self::MokoshAbuseContactEmail => config
                .email
                .support_inbox_email
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_registered_key_is_servable() {
        assert_eq!(
            HostConfig::parse("mokosh/abuse_contact_email"),
            Some(HostConfig::MokoshAbuseContactEmail)
        );
        for unservable in [
            "SUPPORT_INBOX_EMAIL",
            "mokosh/abuse_contact_email ",
            "mokosh/",
            "",
        ] {
            assert_eq!(HostConfig::parse(unservable), None, "{unservable}");
        }
    }

    /// The two registries stay apart: a configuration credential naming a
    /// secret's key gets a 404 from this route, not the secret. That is what
    /// makes two allow-lists worth having rather than one shared entitlement
    /// (BUNYIP-855 D9).
    #[test]
    fn no_governed_secret_is_servable_as_configuration() {
        for secret in bunyip_domain::config::GovernedSecret::ALL {
            assert_eq!(
                HostConfig::parse(secret.name()),
                None,
                "{} is a secret, not configuration",
                secret.name()
            );
        }
        for key in crate::host_secrets::HOST_SECRET_KEYS {
            assert_eq!(
                HostConfig::parse(key),
                None,
                "{key} belongs to the secrets route"
            );
        }
        for key in HOST_CONFIG_KEYS {
            assert_eq!(
                crate::host_secrets::HostSecret::parse(key),
                None,
                "{key} belongs to the config route"
            );
        }
    }

    #[test]
    fn every_listed_key_parses_back_to_a_variant() {
        for key in HOST_CONFIG_KEYS {
            let config = HostConfig::parse(key).expect("a listed key is servable");
            assert_eq!(config.key(), *key);
        }
    }
}
