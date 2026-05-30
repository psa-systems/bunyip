//! Application model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

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

impl Application {
    pub fn is_downloadable(&self) -> bool {
        self.forgejo_owner.is_some()
            && self.forgejo_repo.is_some()
            && self.pinned_release_tag.is_some()
    }

    /// True when all three OCI fields are set AND the application is active.
    pub fn is_pullable(&self) -> bool {
        self.is_active
            && self.oci_image_owner.is_some()
            && self.oci_image_name.is_some()
            && self.pinned_image_tag.is_some()
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

        app.pinned_release_tag = None;
        assert!(!app.is_downloadable());
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
    pub maintenance_mode: Option<bool>,
    pub maintenance_message: Option<String>,
    pub webhook_url: Option<String>,
    pub forgejo_owner: Option<String>,
    pub forgejo_repo: Option<String>,
    pub pinned_release_tag: Option<String>,
    pub oci_image_owner: Option<String>,
    pub oci_image_name: Option<String>,
    pub pinned_image_tag: Option<String>,
}
