//! Admin feature toggles (BUNYIP-840). Listed to any admin, flipped by the super
//! admin only: a toggle hides or shows a whole surface for every user.

use std::collections::HashMap;

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::feature_toggles::{Feature, FeatureToggleSnapshot};
use crate::middleware::{AdminUser, SuperAdminUser};
use crate::models::{AuditAction, CreateAuditLog};
use crate::repositories::{AuditLogRepository, FeatureToggleRepository, FeatureToggleRow};
use crate::responses::{get_request_id, success};

/// One registry entry as the admin page renders it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeatureToggleEntry {
    pub key: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub enabled: bool,
    /// `None` until the toggle has been saved once.
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
    pub updated_by_email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFeatureToggleRequest {
    pub enabled: bool,
}

/// Every registered feature, stored state or default-off, in registry order.
fn entries(rows: &[FeatureToggleRow], emails: &HashMap<Uuid, String>) -> Vec<FeatureToggleEntry> {
    Feature::ALL
        .iter()
        .map(|feature| {
            let row = rows.iter().find(|r| r.key == feature.key());
            let updated_by = row.and_then(|r| r.updated_by);
            FeatureToggleEntry {
                key: feature.key(),
                label: feature.label(),
                help: feature.help(),
                enabled: row.is_some_and(|r| r.enabled),
                updated_at: row.map(|r| r.updated_at),
                updated_by,
                updated_by_email: updated_by.and_then(|id| emails.get(&id).cloned()),
            }
        })
        .collect()
}

async fn actor_emails(
    pool: &PgPool,
    rows: &[FeatureToggleRow],
) -> Result<HashMap<Uuid, String>, AppError> {
    let ids: Vec<Uuid> = rows.iter().filter_map(|r| r.updated_by).collect();
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let pairs: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, email FROM users WHERE id = ANY($1)")
            .bind(&ids)
            .fetch_all(pool)
            .await?;
    Ok(pairs.into_iter().collect())
}

/// Re-read the table into the process snapshot. A failure keeps the last good snapshot.
pub async fn refresh_snapshot(pool: &PgPool, snapshot: &FeatureToggleSnapshot) {
    match FeatureToggleRepository::load(pool).await {
        Ok(fresh) => *snapshot.write().unwrap_or_else(|e| e.into_inner()) = fresh,
        Err(e) => tracing::warn!(
            error = %e,
            "feature_toggles could not be re-read; keeping the last loaded snapshot"
        ),
    }
}

/// GET /v1/admin/feature-toggles
pub async fn list_feature_toggles(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let rows = FeatureToggleRepository::get_all(&pool).await?;
    let emails = actor_emails(&pool, &rows).await?;
    Ok(success(entries(&rows, &emails), request_id))
}

/// PUT /v1/admin/feature-toggles/{key}
///
/// Upserts the row and its audit entry in one transaction, then refreshes this
/// process's snapshot. An unknown key is a 404: only registered features are stored.
pub async fn update_feature_toggle(
    req: HttpRequest,
    admin: SuperAdminUser,
    pool: web::Data<PgPool>,
    snapshot: web::Data<FeatureToggleSnapshot>,
    path: web::Path<String>,
    body: web::Json<UpdateFeatureToggleRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let feature =
        Feature::from_key(&path.into_inner()).ok_or_else(|| AppError::not_found("Feature"))?;

    let mut tx = pool.begin().await?;
    FeatureToggleRepository::set(&mut *tx, feature.key(), body.enabled, Some(admin.0.sub)).await?;
    let log = CreateAuditLog::new(AuditAction::AdminFeatureToggleUpdated)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({
            "key": feature.key(),
            "enabled": body.enabled,
        }));
    AuditLogRepository::create_in_tx(&mut *tx, log).await?;
    tx.commit().await?;

    refresh_snapshot(&pool, &snapshot).await;

    let rows = FeatureToggleRepository::get_all(&pool).await?;
    let emails = actor_emails(&pool, &rows).await?;
    let entry = entries(&rows, &emails)
        .into_iter()
        .find(|e| e.key == feature.key())
        .ok_or_else(|| AppError::internal("a saved feature is missing from the registry"))?;
    Ok(success(entry, request_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(key: &str, enabled: bool) -> FeatureToggleRow {
        FeatureToggleRow {
            key: key.to_string(),
            enabled,
            updated_at: Utc::now(),
            updated_by: None,
        }
    }

    #[test]
    fn every_registered_feature_is_listed_and_a_missing_row_is_off() {
        let listed = entries(&[], &HashMap::new());
        let keys: Vec<&str> = listed.iter().map(|e| e.key).collect();
        let registry: Vec<&str> = Feature::ALL.iter().map(|f| f.key()).collect();
        assert_eq!(keys, registry);
        assert!(listed.iter().all(|e| !e.enabled && e.updated_at.is_none()));

        let saved = entries(&[row("tenant_hostnames", true)], &HashMap::new());
        let tenant = saved.iter().find(|e| e.key == "tenant_hostnames").unwrap();
        assert!(tenant.enabled && tenant.updated_at.is_some());
    }

    #[test]
    fn an_unknown_stored_key_is_not_listed() {
        let listed = entries(&[row("retired_feature", true)], &HashMap::new());
        assert!(listed.iter().all(|e| e.key != "retired_feature"));
        assert_eq!(listed.len(), Feature::ALL.len());
    }
}
