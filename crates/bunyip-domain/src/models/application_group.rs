//! Application group model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A user-facing grouping of applications (BUNYIP-100). Applications reference a
/// group through the nullable `applications.group_id` FK; one group per app.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApplicationGroup {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Data for creating an application group (admin only).
#[derive(Debug, Clone, Deserialize)]
pub struct CreateApplicationGroup {
    pub name: String,
    pub slug: String,
    pub display_name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub sort_order: Option<i32>,
}

/// Data for updating an application group (admin only). Every field is optional;
/// `None` leaves the existing column unchanged.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateApplicationGroup {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub sort_order: Option<i32>,
}

/// Request body for assigning an application to a group (or clearing it).
/// `group_id = null` (or omitted) ungroups the application.
#[derive(Debug, Clone, Deserialize)]
pub struct SetApplicationGroupRequest {
    #[serde(default)]
    pub group_id: Option<Uuid>,
}
