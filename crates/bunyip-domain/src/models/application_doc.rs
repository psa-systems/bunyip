//! Per-application documentation models (BUNYIP-388).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A single documentation page belonging to an application.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApplicationDoc {
    pub id: Uuid,
    pub application_id: Uuid,
    pub slug: String,
    pub title: String,
    pub body: String,
    pub sort_order: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Lightweight page metadata for a docs index (omits the markdown body).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApplicationDocSummary {
    pub slug: String,
    pub title: String,
    pub sort_order: i32,
}

/// Admin input for creating a documentation page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApplicationDoc {
    pub slug: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub sort_order: i32,
}

/// Admin input for updating a documentation page. Every field is optional so a
/// caller can patch just a title, body, or sort order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateApplicationDoc {
    pub slug: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
    pub sort_order: Option<i32>,
}
