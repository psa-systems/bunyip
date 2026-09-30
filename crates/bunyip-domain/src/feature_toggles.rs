//! The feature-toggle registry (BUNYIP-840): one [`Feature`] variant per switch,
//! one `feature_toggles` row per stored state. See `docs/feature-toggles.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, RwLock};

/// One admin-managed feature switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// Tenant hostnames (BUNYIP-591). Gates nothing yet; the routing writer lands with BUNYIP-679.
    TenantHostnames,
}

impl Feature {
    /// Every registered feature, in admin-page order.
    pub const ALL: &'static [Feature] = &[Feature::TenantHostnames];

    /// The stable key: the `feature_toggles.key` value and the wire name.
    /// Never rename one; a renamed key reads as a new, off feature.
    pub const fn key(self) -> &'static str {
        match self {
            Feature::TenantHostnames => "tenant_hostnames",
        }
    }

    /// The admin page's row title.
    pub const fn label(self) -> &'static str {
        match self {
            Feature::TenantHostnames => "Tenant Hostnames",
        }
    }

    /// The admin page's help text: what the switch shows or hides.
    pub const fn help(self) -> &'static str {
        match self {
            Feature::TenantHostnames => {
                "Custom hostnames per tenant. Nothing reads this switch yet, so flipping it changes nothing today."
            }
        }
    }

    /// The owning issue, for code and logs only (never user-facing copy).
    pub const fn issue(self) -> &'static str {
        match self {
            Feature::TenantHostnames => "BUNYIP-591",
        }
    }

    /// The variant a stored key names, or `None` for a key no variant matches.
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.key() == key)
    }
}

/// Unknown keys already warned about, so a stale row warns once per process.
static WARNED_UNKNOWN_KEYS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// The resolved state of every registered feature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeatureToggles {
    on: BTreeSet<Feature>,
}

/// The process-wide snapshot bunyip-api reads; all off until the first load.
pub type FeatureToggleSnapshot = Arc<RwLock<FeatureToggles>>;

impl FeatureToggles {
    /// Resolve stored `(key, enabled)` rows. No row means off; an unknown key is ignored.
    pub fn from_rows<'a>(rows: impl IntoIterator<Item = (&'a str, bool)>) -> Self {
        let mut on = BTreeSet::new();
        for (key, enabled) in rows {
            match Feature::from_key(key) {
                Some(feature) if enabled => {
                    on.insert(feature);
                }
                Some(_) => {}
                None => {
                    let first = WARNED_UNKNOWN_KEYS
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(key.to_string());
                    if first {
                        tracing::warn!(
                            key,
                            "feature_toggles holds a key no Feature variant matches; ignoring it"
                        );
                    }
                }
            }
        }
        Self { on }
    }

    pub fn enabled(&self, feature: Feature) -> bool {
        self.on.contains(&feature)
    }

    /// Every registered key with its state, the shape the public probe publishes.
    pub fn as_map(&self) -> BTreeMap<&'static str, bool> {
        Feature::ALL
            .iter()
            .map(|f| (f.key(), self.enabled(*f)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_is_unique_and_snake_case() {
        let mut seen = BTreeSet::new();
        for feature in Feature::ALL {
            let key = feature.key();
            assert!(seen.insert(key), "{key} is registered twice");
            assert!(
                key.starts_with(|c: char| c.is_ascii_lowercase())
                    && key
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{key} is not snake_case (the migration's CHECK would refuse it)"
            );
            assert_eq!(Feature::from_key(key), Some(*feature));
            assert!(!feature.label().is_empty() && !feature.help().is_empty());
            assert!(feature.issue().starts_with("BUNYIP-"));
        }
    }

    #[test]
    fn a_feature_with_no_row_is_off() {
        let toggles = FeatureToggles::from_rows([]);
        for feature in Feature::ALL {
            assert!(!toggles.enabled(*feature), "{} defaults on", feature.key());
        }
        assert_eq!(FeatureToggles::default(), toggles);
    }

    #[test]
    fn an_unknown_key_is_ignored() {
        let toggles =
            FeatureToggles::from_rows([("retired_feature", true), ("tenant_hostnames", true)]);
        assert!(toggles.enabled(Feature::TenantHostnames));
        let map = toggles.as_map();
        assert_eq!(
            map.len(),
            Feature::ALL.len(),
            "only registered keys publish"
        );
        assert!(!map.contains_key("retired_feature"));
    }

    /// No environment variable, declared configuration key or file-provider key
    /// names a feature, so none can turn one on.
    #[test]
    fn no_other_provider_can_turn_a_feature_on() {
        use crate::config::ENV_INVENTORY;
        use crate::config_providers::{CONFIG_KEYS, SYSTEM_SETTINGS_KEYS};

        for feature in Feature::ALL {
            let key = feature.key();
            let upper = key.to_ascii_uppercase();
            for name in [key, upper.as_str()] {
                assert!(
                    !CONFIG_KEYS
                        .iter()
                        .any(|spec| spec.key == name || spec.source_var == name),
                    "{name} is a declared configuration key"
                );
                assert!(
                    !ENV_INVENTORY.iter().any(|spec| spec.name == name),
                    "{name} is an environment variable"
                );
                assert!(
                    !SYSTEM_SETTINGS_KEYS.contains(&name),
                    "{name} is a file-provider key"
                );
            }
        }
    }
}
