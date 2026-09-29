//! Tenant hostname routing, gated by the `tenant_hostnames` feature toggle
//! (BUNYIP-840 for the gate, BUNYIP-591 for the feature).
//!
//! [`tenant_routing_enabled`] is the ONE place that reads the toggle, and the
//! Traefik file writer (BUNYIP-679) must call it before every write. While the
//! toggle is off, [`reconcile_dynamic_config`] deletes the file at
//! `BUNYIP_TRAEFIK_DYNAMIC_CONFIG_PATH`, so off means no tenant host is routed.
//! It runs at startup, after every toggle save and on every snapshot refresh, so
//! an api process that did not serve the save still removes the file.

use std::io;
use std::path::{Path, PathBuf};

use crate::feature_toggles::{Feature, FeatureToggleCache};

/// Where the Traefik tenant routing file lives, read once at startup.
#[derive(Debug, Clone, Default)]
pub struct TenantRoutingConfig {
    /// `None` means this deployment manages no file.
    pub dynamic_config_path: Option<PathBuf>,
}

impl TenantRoutingConfig {
    pub fn from_env() -> Self {
        let dynamic_config_path = std::env::var("BUNYIP_TRAEFIK_DYNAMIC_CONFIG_PATH")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        Self {
            dynamic_config_path,
        }
    }
}

/// Whether tenant hostnames are switched on. The only read of the toggle.
pub fn tenant_routing_enabled(toggles: &FeatureToggleCache) -> bool {
    toggles.enabled(Feature::TenantHostnames)
}

/// What [`reconcile_dynamic_config`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconciled {
    /// No path is configured, so there is nothing to manage.
    NoPath,
    /// The feature is on; the file is left to its writer.
    Enabled,
    /// The feature is off and a file was deleted.
    Deleted,
    /// The feature is off and no file was there.
    Absent,
}

/// Delete the routing file while the feature is off. Idempotent: a missing
/// file is not an error.
pub fn reconcile_dynamic_config(enabled: bool, path: Option<&Path>) -> io::Result<Reconciled> {
    let Some(path) = path else {
        return Ok(Reconciled::NoPath);
    };
    if enabled {
        return Ok(Reconciled::Enabled);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(Reconciled::Deleted),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Reconciled::Absent),
        Err(e) => Err(e),
    }
}

/// Reconcile against the live snapshot, logging rather than failing: a delete
/// that did not work must never fail a toggle save. Skipped until the snapshot
/// has been read once, so a database outage at boot cannot delete the file.
pub fn reconcile(toggles: &FeatureToggleCache, config: &TenantRoutingConfig) {
    if !toggles.is_loaded() {
        return;
    }
    let path = config.dynamic_config_path.as_deref();
    match reconcile_dynamic_config(tenant_routing_enabled(toggles), path) {
        Ok(Reconciled::Deleted) => tracing::info!(
            path = %path.map(Path::display).map(|d| d.to_string()).unwrap_or_default(),
            "tenant_hostnames is off; deleted the Traefik tenant routing file"
        ),
        Ok(_) => {}
        Err(e) => tracing::error!(
            error = %e,
            path = %path.map(Path::display).map(|d| d.to_string()).unwrap_or_default(),
            "tenant_hostnames is off but the Traefik tenant routing file could not be deleted"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature_toggles::FeatureToggles;

    #[test]
    fn off_deletes_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tenants.yml");
        std::fs::write(&file, "http: {}\n").unwrap();
        assert_eq!(
            reconcile_dynamic_config(false, Some(&file)).unwrap(),
            Reconciled::Deleted
        );
        assert!(!file.exists());
    }

    #[test]
    fn off_with_no_file_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tenants.yml");
        assert_eq!(
            reconcile_dynamic_config(false, Some(&file)).unwrap(),
            Reconciled::Absent
        );
    }

    #[test]
    fn on_leaves_the_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tenants.yml");
        std::fs::write(&file, "http: {}\n").unwrap();
        assert_eq!(
            reconcile_dynamic_config(true, Some(&file)).unwrap(),
            Reconciled::Enabled
        );
        assert!(file.exists());
    }

    #[test]
    fn no_path_is_a_no_op() {
        assert_eq!(
            reconcile_dynamic_config(false, None).unwrap(),
            Reconciled::NoPath
        );
    }

    #[test]
    fn an_unloaded_snapshot_never_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tenants.yml");
        std::fs::write(&file, "http: {}\n").unwrap();
        let config = TenantRoutingConfig {
            dynamic_config_path: Some(file.clone()),
        };
        let toggles = FeatureToggleCache::new();
        reconcile(&toggles, &config);
        assert!(file.exists(), "no reading yet, so the file must survive");
        toggles.store(FeatureToggles::from_rows([("tenant_hostnames", false)]));
        reconcile(&toggles, &config);
        assert!(!file.exists(), "a real off reading deletes it");
    }

    /// Every other module reads tenant routing through
    /// [`tenant_routing_enabled`], so BUNYIP-679's writer cannot skip the gate.
    #[test]
    fn tenant_routing_enabled_is_the_only_read_site() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let allowed = [
            root.join("bunyip-api/src/tenant_routing.rs"),
            root.join("crates/bunyip-domain/src/feature_toggles.rs"),
        ];
        let mut offenders = Vec::new();
        for dir in ["bunyip-api", "bunyip-web", "crates"] {
            for file in rust_sources(&root.join(dir)) {
                if allowed.contains(&file) {
                    continue;
                }
                let src = std::fs::read_to_string(&file).unwrap();
                if src.contains(concat!("Feature::", "TenantHostnames")) {
                    offenders.push(file.display().to_string());
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "read the tenant_hostnames toggle through tenant_routing_enabled: {offenders:?}"
        );
    }

    fn rust_sources(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .file_name()
                .is_some_and(|n| n == "target" || n == "node_modules")
            {
                continue;
            }
            if path.is_dir() {
                out.extend(rust_sources(&path));
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
        out
    }
}
