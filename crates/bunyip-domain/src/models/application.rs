//! Application model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::download::{AppOciImage, ArtifactSource};

/// Application database model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Application {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub is_active: bool,
    /// Whether this is a hosted app (appears as a hub launch tile) or a
    /// catalog-only distribution product (downloads / OCI registry only).
    pub is_hosted: bool,
    pub maintenance_mode: bool,
    pub maintenance_message: Option<String>,
    pub subdomain: Option<String>,
    pub container_name: String,
    pub health_check_url: Option<String>,
    pub webhook_url: Option<String>,
    pub version: Option<String>,
    pub source_code_url: Option<String>,
    pub forgejo_owner: Option<String>,
    pub forgejo_repo: Option<String>,
    pub pinned_release_tag: Option<String>,
    /// Which Forgejo artifact API serves this application's binaries:
    /// `"release"` (release attachments) or `"generic_package"` (generic
    /// package registry).
    pub artifact_source: String,
    /// Generic-package name, when `artifact_source` is `"generic_package"`.
    /// Falls back to `forgejo_repo` when unset.
    pub forgejo_package: Option<String>,
    pub oci_image_owner: Option<String>,
    pub oci_image_name: Option<String>,
    pub pinned_image_tag: Option<String>,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Application response for public API (excludes internal fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationResponse {
    pub id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub version: Option<String>,
    pub source_code_url: Option<String>,
    pub subdomain: Option<String>,
    pub is_accessible: bool,
    pub maintenance_mode: bool,
    pub maintenance_message: Option<String>,
}

impl ApplicationResponse {
    /// Create from Application with access flag
    pub fn from_application(app: Application, has_access: bool) -> Self {
        Self {
            id: app.id,
            slug: app.slug,
            display_name: app.display_name,
            description: app.description,
            icon_url: app.icon_url,
            version: app.version,
            source_code_url: app.source_code_url,
            subdomain: app.subdomain,
            is_accessible: has_access && app.is_active && !app.maintenance_mode,
            maintenance_mode: app.maintenance_mode,
            maintenance_message: if app.maintenance_mode {
                app.maintenance_message
            } else {
                None
            },
        }
    }
}

/// `applications.artifact_source` value: download via the Forgejo Releases API.
pub const ARTIFACT_SOURCE_RELEASE: &str = "release";
/// `applications.artifact_source` value: download via the Forgejo generic
/// package registry.
pub const ARTIFACT_SOURCE_GENERIC_PACKAGE: &str = "generic_package";

impl Application {
    /// Whether `value` is an allowed `artifact_source` (mirrors the DB CHECK
    /// constraint; admin handlers validate against this before writing).
    pub fn valid_artifact_source(value: &str) -> bool {
        value == ARTIFACT_SOURCE_RELEASE || value == ARTIFACT_SOURCE_GENERIC_PACKAGE
    }

    /// Convenience wrapper over [`Application::download_source`]: whether this
    /// application's Forgejo download configuration is complete. Public API
    /// surface for admin/UI code (BUNYIP-33/34); handlers that also need the
    /// source itself call `download_source()` directly.
    pub fn is_downloadable(&self) -> bool {
        self.download_source().is_some()
    }

    /// Build the dunite-download [`ArtifactSource`] for this application, when
    /// its Forgejo download configuration is complete.
    ///
    /// `"release"` sources need `forgejo_owner` + `forgejo_repo` +
    /// `pinned_release_tag`; `"generic_package"` sources need `forgejo_owner`
    /// + (`forgejo_package` or `forgejo_repo`) + `pinned_release_tag`.
    pub fn download_source(&self) -> Option<ArtifactSource> {
        let owner = self.forgejo_owner.clone()?;
        let version = self.pinned_release_tag.clone()?;
        match self.artifact_source.as_str() {
            ARTIFACT_SOURCE_GENERIC_PACKAGE => Some(ArtifactSource::GenericPackage {
                owner,
                package: self
                    .forgejo_package
                    .clone()
                    .or_else(|| self.forgejo_repo.clone())?,
                version,
            }),
            ARTIFACT_SOURCE_RELEASE => Some(ArtifactSource::Release {
                owner,
                repo: self.forgejo_repo.clone()?,
                tag: version,
            }),
            other => {
                // The DB CHECK constraint should make this unreachable; warn
                // instead of silently picking a source so misconfiguration is
                // visible in logs.
                tracing::warn!(
                    application = %self.slug,
                    artifact_source = %other,
                    "unknown artifact_source; treating application as not downloadable"
                );
                None
            }
        }
    }

    /// True when all three OCI fields are set AND the application is active.
    pub fn is_pullable(&self) -> bool {
        self.is_active
            && self.oci_image_owner.is_some()
            && self.oci_image_name.is_some()
            && self.pinned_image_tag.is_some()
    }

    /// Member-facing OCI pull coordinates against the public registry host,
    /// `Some` only when this application [`is pullable`](Self::is_pullable).
    ///
    /// The registry serves repositories by application SLUG: the bunyip-oci
    /// `/v2/{slug}/...` routes and the token scope check both resolve
    /// repositories with `find_active_by_slug`. This method is the single
    /// definition of that convention; anything that advertises a pull
    /// reference must build it here so it cannot drift from what the
    /// registry accepts.
    pub fn oci_pull_image(&self, registry_host: &str) -> Option<AppOciImage> {
        if !self.is_pullable() {
            return None;
        }
        let tag = self
            .pinned_image_tag
            .as_deref()
            .expect("is_pullable() guarantees pinned_image_tag is set");
        Some(AppOciImage {
            registry: registry_host.to_string(),
            repository: self.slug.clone(),
            tag: tag.to_string(),
            reference: format!("{registry_host}/{}:{tag}", self.slug),
        })
    }
}

/// The distribution-related fields of an application configuration, borrowed
/// for validation. Handlers build it via [`CreateApplication::distribution`] /
/// [`UpdateApplication::distribution_merged`] so the field mapping AND the
/// validity rules live in one place and the two handlers cannot drift.
#[derive(Debug, Default)]
pub struct DistributionConfig<'a> {
    pub artifact_source: Option<&'a str>,
    pub forgejo_owner: Option<&'a str>,
    pub forgejo_repo: Option<&'a str>,
    pub forgejo_package: Option<&'a str>,
    pub pinned_release_tag: Option<&'a str>,
    pub oci_image_owner: Option<&'a str>,
    pub oci_image_name: Option<&'a str>,
    pub pinned_image_tag: Option<&'a str>,
}

impl DistributionConfig<'_> {
    /// Validate the configuration. Returns `(field, message)` on failure so
    /// handlers can map it to a validation error.
    ///
    /// Rules (matching [`Application::download_source`] and
    /// [`Application::is_pullable`]):
    /// - No field may be an empty or whitespace-only string (omit it or send
    ///   null instead); empty coordinates would pass the presence checks here
    ///   but break at pull/download time.
    /// - `artifact_source`, when set, must be a known value.
    /// - `forgejo_package` is only meaningful for `generic_package` sources.
    /// - Download config is all-or-nothing: `release` sources need owner +
    ///   repo + tag; `generic_package` sources need owner + (package or repo)
    ///   + tag.
    /// - OCI config is all-or-nothing: owner + name + tag.
    pub fn validate(&self) -> Result<(), (&'static str, String)> {
        // Reject empty/whitespace values outright: every later check treats
        // Some("") as "present", so letting them through would store unusable
        // coordinates that only fail when a member tries to pull or download.
        for (field, value) in [
            ("artifact_source", self.artifact_source),
            ("forgejo_owner", self.forgejo_owner),
            ("forgejo_repo", self.forgejo_repo),
            ("forgejo_package", self.forgejo_package),
            ("pinned_release_tag", self.pinned_release_tag),
            ("oci_image_owner", self.oci_image_owner),
            ("oci_image_name", self.oci_image_name),
            ("pinned_image_tag", self.pinned_image_tag),
        ] {
            if let Some(v) = value {
                if v.trim().is_empty() {
                    return Err((
                        field,
                        format!("{field} must not be empty; omit the field or send null"),
                    ));
                }
            }
        }

        if let Some(source) = self.artifact_source {
            if !Application::valid_artifact_source(source) {
                return Err((
                    "artifact_source",
                    "artifact_source must be 'release' or 'generic_package'".to_string(),
                ));
            }
        }

        let is_generic_package = self.artifact_source == Some(ARTIFACT_SOURCE_GENERIC_PACKAGE);

        // A package name on a release source is silently dead configuration;
        // reject it so the misconfiguration is visible at write time.
        if self.forgejo_package.is_some() && !is_generic_package {
            return Err((
                "forgejo_package",
                "forgejo_package requires artifact_source = 'generic_package'".to_string(),
            ));
        }

        let forgejo_any = self.forgejo_owner.is_some()
            || self.forgejo_repo.is_some()
            || self.forgejo_package.is_some()
            || self.pinned_release_tag.is_some();
        let forgejo_all = self.forgejo_owner.is_some()
            && self.pinned_release_tag.is_some()
            && if is_generic_package {
                self.forgejo_package.is_some() || self.forgejo_repo.is_some()
            } else {
                self.forgejo_repo.is_some()
            };
        if forgejo_any && !forgejo_all {
            return Err((
                "forgejo",
                if is_generic_package {
                    "generic_package downloads need forgejo_owner, pinned_release_tag, and \
                     forgejo_package (or forgejo_repo) set together"
                        .to_string()
                } else {
                    "forgejo_owner, forgejo_repo, and pinned_release_tag must all be set together"
                        .to_string()
                },
            ));
        }

        let oci_any = self.oci_image_owner.is_some()
            || self.oci_image_name.is_some()
            || self.pinned_image_tag.is_some();
        let oci_all = self.oci_image_owner.is_some()
            && self.oci_image_name.is_some()
            && self.pinned_image_tag.is_some();
        if oci_any && !oci_all {
            return Err((
                "oci",
                "oci_image_owner, oci_image_name, and pinned_image_tag must all be set together"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

/// Data for creating an application (admin only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApplication {
    pub name: String,
    pub slug: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub container_name: String,
    pub health_check_url: Option<String>,
    pub subdomain: Option<String>,
    pub webhook_url: Option<String>,
    pub version: Option<String>,
    pub source_code_url: Option<String>,
    /// Whether this is a hosted app (hub launch tile) or a catalog-only
    /// distribution product. Defaults to hosted (the DB column default).
    pub is_hosted: Option<bool>,
    // Distribution config (all optional): Forgejo download coordinates and/or
    // OCI image coordinates, so a product can be fully created in one call.
    pub forgejo_owner: Option<String>,
    pub forgejo_repo: Option<String>,
    pub forgejo_package: Option<String>,
    pub pinned_release_tag: Option<String>,
    /// One of [`ARTIFACT_SOURCE_RELEASE`] / [`ARTIFACT_SOURCE_GENERIC_PACKAGE`];
    /// defaults to `release` (the DB column default) when omitted.
    pub artifact_source: Option<String>,
    pub oci_image_owner: Option<String>,
    pub oci_image_name: Option<String>,
    pub pinned_image_tag: Option<String>,
}

impl CreateApplication {
    /// The distribution fields of this request, for validation. Owns the
    /// body-to-[`DistributionConfig`] mapping so handlers cannot drift from
    /// [`UpdateApplication::distribution_merged`].
    pub fn distribution(&self) -> DistributionConfig<'_> {
        DistributionConfig {
            artifact_source: self.artifact_source.as_deref(),
            forgejo_owner: self.forgejo_owner.as_deref(),
            forgejo_repo: self.forgejo_repo.as_deref(),
            forgejo_package: self.forgejo_package.as_deref(),
            pinned_release_tag: self.pinned_release_tag.as_deref(),
            oci_image_owner: self.oci_image_owner.as_deref(),
            oci_image_name: self.oci_image_name.as_deref(),
            pinned_image_tag: self.pinned_image_tag.as_deref(),
        }
    }
}

/// Request body for deleting an application (requires password + 2FA)
#[derive(Debug, Clone, Deserialize)]
pub struct DeleteApplicationRequest {
    pub password: String,
    pub totp_code: String,
}

/// Request body for swapping application order
#[derive(Debug, Clone, Deserialize)]
pub struct SwapApplicationOrderRequest {
    pub target_app_id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn test_app() -> Application {
        Application {
            id: Uuid::new_v4(),
            name: "test-app".to_string(),
            slug: "test-app".to_string(),
            display_name: "Test App".to_string(),
            description: Some("A test application".to_string()),
            icon_url: None,
            is_active: true,
            is_hosted: true,
            maintenance_mode: false,
            maintenance_message: None,
            subdomain: Some("test".to_string()),
            container_name: "test-app".to_string(),
            health_check_url: None,
            webhook_url: None,
            version: Some("1.0.0".to_string()),
            source_code_url: None,
            forgejo_owner: None,
            forgejo_repo: None,
            pinned_release_tag: None,
            artifact_source: "release".to_string(),
            forgejo_package: None,
            oci_image_owner: None,
            oci_image_name: None,
            pinned_image_tag: None,
            sort_order: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn application_response_accessible_when_active_and_has_access() {
        let app = test_app();
        let response = ApplicationResponse::from_application(app, true);
        assert!(response.is_accessible);
        assert!(!response.maintenance_mode);
        assert!(response.maintenance_message.is_none());
    }

    #[test]
    fn application_response_not_accessible_without_membership() {
        let app = test_app();
        let response = ApplicationResponse::from_application(app, false);
        assert!(!response.is_accessible);
    }

    #[test]
    fn application_response_not_accessible_when_inactive() {
        let mut app = test_app();
        app.is_active = false;
        let response = ApplicationResponse::from_application(app, true);
        assert!(!response.is_accessible);
    }

    #[test]
    fn application_response_not_accessible_in_maintenance() {
        let mut app = test_app();
        app.maintenance_mode = true;
        app.maintenance_message = Some("Under maintenance".to_string());
        let response = ApplicationResponse::from_application(app, true);
        assert!(!response.is_accessible);
        assert!(response.maintenance_mode);
        assert_eq!(
            response.maintenance_message.as_deref(),
            Some("Under maintenance")
        );
    }

    #[test]
    fn application_is_downloadable_when_all_forgejo_fields_set() {
        let mut app = test_app();
        app.forgejo_owner = Some("a8n".to_string());
        app.forgejo_repo = Some("rus".to_string());
        app.pinned_release_tag = Some("v1.0.0".to_string());
        assert!(app.is_downloadable());
        assert_eq!(
            app.download_source(),
            Some(ArtifactSource::Release {
                owner: "a8n".into(),
                repo: "rus".into(),
                tag: "v1.0.0".into(),
            })
        );

        app.pinned_release_tag = None;
        assert!(!app.is_downloadable());
    }

    #[test]
    fn generic_package_source_uses_package_name_with_repo_fallback() {
        let mut app = test_app();
        app.artifact_source = "generic_package".to_string();
        app.forgejo_owner = Some("psa".to_string());
        app.forgejo_repo = Some("mokosh-apps".to_string());
        app.pinned_release_tag = Some("0.3.0".to_string());

        // Falls back to forgejo_repo when forgejo_package is unset.
        assert_eq!(
            app.download_source(),
            Some(ArtifactSource::GenericPackage {
                owner: "psa".into(),
                package: "mokosh-apps".into(),
                version: "0.3.0".into(),
            })
        );

        // Explicit package name wins.
        app.forgejo_package = Some("mokosh".to_string());
        assert_eq!(
            app.download_source(),
            Some(ArtifactSource::GenericPackage {
                owner: "psa".into(),
                package: "mokosh".into(),
                version: "0.3.0".into(),
            })
        );

        // Generic packages do not require forgejo_repo when package is set.
        app.forgejo_repo = None;
        assert!(app.is_downloadable());
    }

    #[test]
    fn unknown_artifact_source_is_not_downloadable() {
        let mut app = test_app();
        app.forgejo_owner = Some("a8n".to_string());
        app.forgejo_repo = Some("rus".to_string());
        app.pinned_release_tag = Some("v1.0.0".to_string());
        app.artifact_source = "not-a-real-source".to_string();
        // Unknown values must not silently behave as a release source.
        assert_eq!(app.download_source(), None);
        assert!(!app.is_downloadable());
    }

    #[test]
    fn valid_artifact_source_accepts_only_known_values() {
        assert!(Application::valid_artifact_source("release"));
        assert!(Application::valid_artifact_source("generic_package"));
        assert!(!Application::valid_artifact_source("generic-package"));
        assert!(!Application::valid_artifact_source("RELEASE"));
        assert!(!Application::valid_artifact_source(""));
    }

    #[test]
    fn distribution_config_validation_rules() {
        // Empty config is valid (no distribution).
        assert!(DistributionConfig::default().validate().is_ok());

        // Complete release config.
        assert!(DistributionConfig {
            forgejo_owner: Some("psa"),
            forgejo_repo: Some("mokosh"),
            pinned_release_tag: Some("v1"),
            ..Default::default()
        }
        .validate()
        .is_ok());

        // Partial release config rejected.
        let err = DistributionConfig {
            forgejo_owner: Some("psa"),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.0, "forgejo");

        // generic_package: package (no repo) is sufficient.
        assert!(DistributionConfig {
            artifact_source: Some(ARTIFACT_SOURCE_GENERIC_PACKAGE),
            forgejo_owner: Some("psa"),
            forgejo_package: Some("vervain-agent"),
            pinned_release_tag: Some("0.1.0"),
            ..Default::default()
        }
        .validate()
        .is_ok());

        // generic_package without package or repo rejected.
        assert!(DistributionConfig {
            artifact_source: Some(ARTIFACT_SOURCE_GENERIC_PACKAGE),
            forgejo_owner: Some("psa"),
            pinned_release_tag: Some("0.1.0"),
            ..Default::default()
        }
        .validate()
        .is_err());

        // Unknown artifact_source rejected.
        let err = DistributionConfig {
            artifact_source: Some("not-a-source"),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.0, "artifact_source");

        // Partial OCI config rejected; complete accepted.
        assert!(DistributionConfig {
            oci_image_owner: Some("psa"),
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(DistributionConfig {
            oci_image_owner: Some("psa"),
            oci_image_name: Some("mokosh-server"),
            pinned_image_tag: Some("v0.2.0"),
            ..Default::default()
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn distribution_config_rejects_empty_and_whitespace_values() {
        // Empty string would pass presence checks but break at pull time.
        let err = DistributionConfig {
            oci_image_owner: Some(""),
            oci_image_name: Some("mokosh-server"),
            pinned_image_tag: Some("v0.2.0"),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.0, "oci_image_owner");

        // Whitespace-only is as bad as empty.
        let err = DistributionConfig {
            forgejo_owner: Some("psa"),
            forgejo_repo: Some("   "),
            pinned_release_tag: Some("v1"),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.0, "forgejo_repo");

        // Empty artifact_source caught by the emptiness rule, not the
        // known-value rule (field name points at the actual problem).
        let err = DistributionConfig {
            artifact_source: Some(""),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.0, "artifact_source");
        assert!(err.1.contains("empty"));
    }

    #[test]
    fn distribution_config_rejects_package_on_release_source() {
        // forgejo_package on a release source is dead configuration.
        let err = DistributionConfig {
            artifact_source: Some(ARTIFACT_SOURCE_RELEASE),
            forgejo_owner: Some("psa"),
            forgejo_repo: Some("mokosh"),
            forgejo_package: Some("mokosh-pkg"),
            pinned_release_tag: Some("v1"),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.0, "forgejo_package");

        // Also rejected when artifact_source is omitted (defaults to release).
        let err = DistributionConfig {
            forgejo_owner: Some("psa"),
            forgejo_repo: Some("mokosh"),
            forgejo_package: Some("mokosh-pkg"),
            pinned_release_tag: Some("v1"),
            ..Default::default()
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.0, "forgejo_package");
    }

    #[test]
    fn is_pullable_requires_all_three_oci_fields_and_active() {
        let base = Application {
            is_active: true,
            oci_image_owner: Some("a8n".into()),
            oci_image_name: Some("rus".into()),
            pinned_image_tag: Some("v1.0".into()),
            ..test_app()
        };
        assert!(base.is_pullable());

        let mut inactive = base.clone();
        inactive.is_active = false;
        assert!(!inactive.is_pullable());

        let mut no_tag = base.clone();
        no_tag.pinned_image_tag = None;
        assert!(!no_tag.is_pullable());
    }

    #[test]
    fn oci_pull_image_builds_reference_from_host_slug_and_pinned_tag() {
        let app = Application {
            is_active: true,
            oci_image_owner: Some("psa-systems-private".into()),
            oci_image_name: Some("mokosh-server".into()),
            pinned_image_tag: Some("v0.2.0".into()),
            ..test_app()
        };
        let image = app.oci_pull_image("oci.example.com").expect("pullable");
        assert_eq!(image.registry, "oci.example.com");
        // Repository is the SLUG, not oci_image_name: the registry's
        // /v2/{slug}/... routes resolve by slug.
        assert_eq!(image.repository, "test-app");
        assert_eq!(image.tag, "v0.2.0");
        assert_eq!(image.reference, "oci.example.com/test-app:v0.2.0");
    }

    #[test]
    fn oci_pull_image_none_when_not_pullable() {
        // Missing tag.
        let mut app = Application {
            is_active: true,
            oci_image_owner: Some("a8n".into()),
            oci_image_name: Some("rus".into()),
            pinned_image_tag: None,
            ..test_app()
        };
        assert!(app.oci_pull_image("oci.example.com").is_none());

        // Inactive.
        app.pinned_image_tag = Some("v1".into());
        app.is_active = false;
        assert!(app.oci_pull_image("oci.example.com").is_none());
    }

    #[test]
    fn application_response_hides_maintenance_message_when_not_in_maintenance() {
        let mut app = test_app();
        app.maintenance_mode = false;
        app.maintenance_message = Some("leftover message".to_string());
        let response = ApplicationResponse::from_application(app, true);
        assert!(response.maintenance_message.is_none());
    }
}

/// Data for updating an application (admin only)
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateApplication {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub source_code_url: Option<String>,
    pub version: Option<String>,
    pub subdomain: Option<String>,
    pub container_name: Option<String>,
    pub health_check_url: Option<String>,
    pub is_active: Option<bool>,
    /// Whether this is a hosted app (hub launch tile) or a catalog-only
    /// distribution product.
    pub is_hosted: Option<bool>,
    pub maintenance_mode: Option<bool>,
    pub maintenance_message: Option<String>,
    pub webhook_url: Option<String>,
    pub forgejo_owner: Option<String>,
    pub forgejo_repo: Option<String>,
    pub pinned_release_tag: Option<String>,
    /// Must be one of [`ARTIFACT_SOURCE_RELEASE`] / [`ARTIFACT_SOURCE_GENERIC_PACKAGE`].
    pub artifact_source: Option<String>,
    /// Set to `""` (empty string) to clear back to NULL (falling back to
    /// `forgejo_repo`); `null`/omitted keeps the current value.
    pub forgejo_package: Option<String>,
    pub oci_image_owner: Option<String>,
    pub oci_image_name: Option<String>,
    pub pinned_image_tag: Option<String>,
}

impl UpdateApplication {
    /// The distribution fields of this request MERGED over the existing row,
    /// for validation: every field falls back to `old`'s value when the
    /// request omits it. An empty-string `forgejo_package` (the documented
    /// clear-to-NULL sentinel) is treated as absent rather than as a value.
    pub fn distribution_merged<'a>(&'a self, old: &'a Application) -> DistributionConfig<'a> {
        DistributionConfig {
            artifact_source: Some(
                self.artifact_source
                    .as_deref()
                    .unwrap_or(old.artifact_source.as_str()),
            ),
            forgejo_owner: self
                .forgejo_owner
                .as_deref()
                .or(old.forgejo_owner.as_deref()),
            forgejo_repo: self.forgejo_repo.as_deref().or(old.forgejo_repo.as_deref()),
            // Three states: Some("") = explicit clear (validate against the
            // cleared state, since the UPDATE will NULLIF it), Some(p) =
            // explicit new value, None = keep the old value.
            forgejo_package: match self.forgejo_package.as_deref() {
                Some("") => None,
                Some(p) => Some(p),
                None => old.forgejo_package.as_deref(),
            },
            pinned_release_tag: self
                .pinned_release_tag
                .as_deref()
                .or(old.pinned_release_tag.as_deref()),
            oci_image_owner: self
                .oci_image_owner
                .as_deref()
                .or(old.oci_image_owner.as_deref()),
            oci_image_name: self
                .oci_image_name
                .as_deref()
                .or(old.oci_image_name.as_deref()),
            pinned_image_tag: self
                .pinned_image_tag
                .as_deref()
                .or(old.pinned_image_tag.as_deref()),
        }
    }
}
