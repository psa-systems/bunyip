//! The feature-toggle registry (BUNYIP-840).
//!
//! A switch that hides an unbuilt or optional surface is one [`Feature`]
//! variant, persisted as one row of the `feature_toggles` table and flipped on
//! the admin Feature Toggles page. Adding a feature is adding a variant: no
//! migration, no new admin form, no new probe field.
//!
//! Two states only. Off means INVISIBLE, not inert: the feature's routes 404
//! and its nav entries are not rendered. A missing row reads as off, so a new
//! feature ships dark everywhere until an admin turns it on. The toggles are
//! database-only: no `CONFIG_KEYS` entry, environment variable or file-provider
//! key can turn one on (`no_other_provider_can_turn_a_feature_on` below).
//!
//! bunyip-api holds the rows in a process-wide [`FeatureToggleCache`], read at
//! startup, refreshed every 60 seconds and right after an admin save, so every
//! api process converges on a change within one interval.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, RwLock};

/// One admin-managed feature switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// Organizations and teams (BUNYIP-493).
    Organizations,
    /// Tenant hostnames and their Traefik routing file (BUNYIP-591). Read only
    /// through `bunyip_api::tenant_routing::tenant_routing_enabled`.
    TenantHostnames,
}

impl Feature {
    /// Every registered feature, in admin-page order.
    pub const ALL: &'static [Feature] = &[Feature::Organizations, Feature::TenantHostnames];

    /// The stable key: the `feature_toggles.key` value and the wire name.
    /// Never rename one; a renamed key reads as a new, off feature.
    pub const fn key(self) -> &'static str {
        match self {
            Feature::Organizations => "organizations",
            Feature::TenantHostnames => "tenant_hostnames",
        }
    }

    /// The admin page's row title.
    pub const fn label(self) -> &'static str {
        match self {
            Feature::Organizations => "Organizations and Teams",
            Feature::TenantHostnames => "Tenant Hostnames",
        }
    }

    /// The admin page's help text: what the switch shows or hides.
    pub const fn help(self) -> &'static str {
        match self {
            Feature::Organizations => {
                "While this is off, the Organizations nav entry is hidden and its page returns 404."
            }
            Feature::TenantHostnames => {
                "While this is off, no tenant hostname is routed, and the Traefik tenant routing \
                 file is deleted if one exists."
            }
        }
    }

    /// The issue the feature belongs to, for code and logs only (never copy).
    pub const fn issue(self) -> &'static str {
        match self {
            Feature::Organizations => "BUNYIP-493",
            Feature::TenantHostnames => "BUNYIP-591",
        }
    }

    /// The variant a stored key names, or `None` for a key no variant matches.
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|f| f.key() == key)
    }
}

/// Keys already reported as unknown, so a stale row warns once per process
/// rather than once per refresh.
static WARNED_UNKNOWN_KEYS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// The resolved state of every registered feature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeatureToggles {
    on: BTreeSet<Feature>,
}

impl FeatureToggles {
    /// Resolve stored `(key, enabled)` rows. A feature with no row stays off; a
    /// key no variant matches is ignored and logged once at `warn`.
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

/// The process-wide snapshot bunyip-api reads, refreshed on a timer and after
/// an admin save.
#[derive(Debug, Default)]
pub struct FeatureToggleCache {
    slot: RwLock<Option<FeatureToggles>>,
}

impl FeatureToggleCache {
    /// An empty cache: every feature off until the first successful load.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store(&self, toggles: FeatureToggles) {
        *self.slot.write().unwrap_or_else(|e| e.into_inner()) = Some(toggles);
    }

    /// Whether a load has ever succeeded. The tenant-routing file is reconciled
    /// only from a real reading, never from the all-off default.
    pub fn is_loaded(&self) -> bool {
        self.slot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// The current snapshot (all off before the first load).
    pub fn current(&self) -> FeatureToggles {
        // A poisoned lock means a writer panicked; the data is still whole.
        self.slot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_default()
    }

    pub fn enabled(&self, feature: Feature) -> bool {
        self.slot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|t| t.enabled(feature))
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
        }
    }

    #[test]
    fn a_feature_with_no_row_is_off() {
        let toggles = FeatureToggles::from_rows([]);
        for feature in Feature::ALL {
            assert!(!toggles.enabled(*feature), "{} defaults on", feature.key());
        }
        assert!(!FeatureToggleCache::new().enabled(Feature::Organizations));
        assert!(!FeatureToggleCache::new().is_loaded());
    }

    #[test]
    fn an_unknown_key_is_ignored() {
        let toggles = FeatureToggles::from_rows([
            ("organizations", true),
            ("retired_feature", true),
            ("tenant_hostnames", false),
        ]);
        assert!(toggles.enabled(Feature::Organizations));
        assert!(!toggles.enabled(Feature::TenantHostnames));
        let map = toggles.as_map();
        assert_eq!(
            map.len(),
            Feature::ALL.len(),
            "only registered keys publish"
        );
        assert!(!map.contains_key("retired_feature"));
    }

    #[test]
    fn the_cache_serves_what_was_stored() {
        let cache = FeatureToggleCache::new();
        cache.store(FeatureToggles::from_rows([("organizations", true)]));
        assert!(cache.is_loaded());
        assert!(cache.enabled(Feature::Organizations));
        assert!(!cache.enabled(Feature::TenantHostnames));
    }

    /// The negative case: no environment variable, declared configuration key
    /// or file-provider key names a feature, so none can turn one on.
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
