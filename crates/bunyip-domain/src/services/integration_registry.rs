//! BUNYIP-661: the integration registry.
//!
//! Payment and accounting connections are added one at a time, and each supports
//! a different subset of capabilities: QuickBooks and Stripe do both payments and
//! invoicing, PayPal is payments only, Xero is invoicing only. Without a registry
//! each connection ends up hard-coded into whichever screen needs it, and every
//! screen has to know each provider by name. This module lists the integrations
//! uniformly and lets a screen ASK which ones support a capability instead of
//! branching on the provider.
//!
//! It is metadata ONLY: the id, the display name and the declared capability set.
//! Provider CREDENTIALS are deliberately not here; they resolve through the
//! configured secret provider (`SECRETS_STORAGE`, BUNYIP-542). Keeping secrets
//! out is what lets the registry be a compile-time constant with nothing
//! sensitive in it.
//!
//! A new provider is one entry in [`INTEGRATION_REGISTRY`]. The capability filter
//! ([`integrations_with`]) iterates the table and matches on the capability,
//! never on the provider id, so a payment or invoicing screen that filters by
//! capability needs no change when the fourth or fifth provider is added
//! (BUNYIP-661 AC4). Credential state, health and the admin screens that consume
//! this are the follow-ups (BUNYIP-660 payments, BUNYIP-662 invoicing sync).

use serde::Serialize;

/// What an integration can do. An integration declares one or more; the model
/// never forces a single one, because Stripe and QuickBooks do both payments and
/// invoicing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationCapability {
    /// Take a payment from a customer (the "payment method" type).
    Payment,
    /// Issue and reconcile invoices (the "invoicing" type).
    Invoicing,
}

impl IntegrationCapability {
    /// Stable machine token, matching the `Serialize` rename.
    pub fn as_str(&self) -> &'static str {
        match self {
            IntegrationCapability::Payment => "payment",
            IntegrationCapability::Invoicing => "invoicing",
        }
    }
}

/// One registered integration: its stable key, display name and declared
/// capability set. Metadata only, no credentials (see the module docs).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RegisteredIntegration {
    /// Stable machine key, e.g. `"quickbooks"`.
    pub id: &'static str,
    /// Display name, e.g. `"QuickBooks"`.
    pub name: &'static str,
    /// Everything this integration can do. Never empty.
    pub capabilities: &'static [IntegrationCapability],
}

impl RegisteredIntegration {
    /// Whether this integration declares `capability`.
    pub fn supports(&self, capability: IntegrationCapability) -> bool {
        self.capabilities.contains(&capability)
    }
}

use IntegrationCapability::{Invoicing, Payment};

/// The seeded registry (BUNYIP-661). Add a provider here and every
/// capability-filtered screen picks it up with no call-site change.
pub static INTEGRATION_REGISTRY: &[RegisteredIntegration] = &[
    RegisteredIntegration {
        id: "quickbooks",
        name: "QuickBooks",
        capabilities: &[Payment, Invoicing],
    },
    RegisteredIntegration {
        id: "stripe",
        name: "Stripe",
        capabilities: &[Payment, Invoicing],
    },
    RegisteredIntegration {
        id: "paypal",
        name: "PayPal",
        capabilities: &[Payment],
    },
    RegisteredIntegration {
        id: "xero",
        name: "Xero",
        capabilities: &[Invoicing],
    },
];

/// Every registered integration that supports `capability`, in registry order.
///
/// This is what a payment or invoicing screen calls instead of naming providers:
/// `integrations_with(IntegrationCapability::Invoicing)` never returns PayPal,
/// and the set updates itself when a provider is added to the table above.
pub fn integrations_with(
    capability: IntegrationCapability,
) -> impl Iterator<Item = &'static RegisteredIntegration> {
    INTEGRATION_REGISTRY
        .iter()
        .filter(move |i| i.supports(capability))
}

/// The registered integration with `id`, if any.
pub fn integration(id: &str) -> Option<&'static RegisteredIntegration> {
    INTEGRATION_REGISTRY.iter().find(|i| i.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filtered_ids(capability: IntegrationCapability) -> Vec<&'static str> {
        integrations_with(capability).map(|i| i.id).collect()
    }

    #[test]
    fn the_four_known_integrations_declare_the_right_capabilities() {
        // AC2: the four are registered with correct capabilities. The expected
        // set is stated in full so a later edit that drops or adds a capability
        // fails here.
        let expected: &[(&str, &[IntegrationCapability])] = &[
            ("quickbooks", &[Payment, Invoicing]),
            ("stripe", &[Payment, Invoicing]),
            ("paypal", &[Payment]),
            ("xero", &[Invoicing]),
        ];
        for (id, caps) in expected {
            let entry = integration(id).unwrap_or_else(|| panic!("{id} is registered"));
            for capability in *caps {
                assert!(
                    entry.supports(*capability),
                    "{id} must support {}",
                    capability.as_str()
                );
            }
            assert_eq!(
                entry.capabilities.len(),
                caps.len(),
                "{id} declares exactly its capability set, no more"
            );
        }
    }

    #[test]
    fn invoicing_excludes_payment_only_integrations() {
        // AC3 / AC5: PayPal is payment-only and must never appear as an invoicing
        // option; the other three do invoicing.
        let invoicing = filtered_ids(Invoicing);
        assert_eq!(invoicing, vec!["quickbooks", "stripe", "xero"]);
        assert!(
            !invoicing.contains(&"paypal"),
            "PayPal is payment-only and is not an invoicing option"
        );
    }

    #[test]
    fn payments_exclude_invoicing_only_integrations() {
        // AC5: the mirror case. Xero is invoicing-only and is not a payment
        // method; the other three take payments.
        let payments = filtered_ids(Payment);
        assert_eq!(payments, vec!["quickbooks", "stripe", "paypal"]);
        assert!(
            !payments.contains(&"xero"),
            "Xero is invoicing-only and is not a payment method"
        );
    }

    #[test]
    fn every_integration_declares_at_least_one_capability() {
        // An empty set makes an integration invisible to every filter, which is
        // never intended: a registered provider that does nothing is a mistake.
        for entry in INTEGRATION_REGISTRY {
            assert!(
                !entry.capabilities.is_empty(),
                "{} declares no capability",
                entry.id
            );
        }
    }

    #[test]
    fn filtering_matches_on_capability_not_on_provider_id() {
        // AC4: a screen filters through `integrations_with`, which is a pure
        // predicate over the table. Two proofs. First, the filter's result is
        // exactly the table filtered by `supports`, so the function holds no
        // per-provider special-casing.
        for capability in [Payment, Invoicing] {
            let via_fn = filtered_ids(capability);
            let via_predicate: Vec<&str> = INTEGRATION_REGISTRY
                .iter()
                .filter(|i| i.supports(capability))
                .map(|i| i.id)
                .collect();
            assert_eq!(via_fn, via_predicate);
        }
        // Second, a provider the registry has never heard of is selected purely by
        // the capability it declares, so adding one needs no call-site change.
        let newcomer = RegisteredIntegration {
            id: "square",
            name: "Square",
            capabilities: &[Payment],
        };
        assert!(newcomer.supports(Payment));
        assert!(!newcomer.supports(Invoicing));
    }
}
