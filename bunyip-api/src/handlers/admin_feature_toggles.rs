//! Admin feature toggles (BUNYIP-840).
//!
//! One row per [`Feature`], listed to any admin and flipped by the super admin
//! only, the same split as the rate-limit configuration: a toggle hides or
//! shows a whole surface for every user.

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::feature_toggles::{Feature, FeatureToggleCache};
use crate::middleware::{AdminUser, SuperAdminUser};
use crate::models::{AuditAction, CreateAuditLog};
use crate::repositories::{AuditLogRepository, FeatureToggleRepository, FeatureToggleRow};
use crate::responses::{get_request_id, success};
use crate::tenant_routing::{self, TenantRoutingConfig};

/// One registry entry as the admin page renders it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeatureToggleEntry {
    pub key: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub enabled: bool,
    /// BUNYIP-843: false while no decision is stored, which is what the
    /// review prompt lists.
    pub decided: bool,
    /// `None` until the toggle has been saved once.
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
    pub updated_by_email: Option<String>,
}

/// The admin list, with the environment a decision applies to (BUNYIP-843).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeatureToggleList {
    pub environment: String,
    pub toggles: Vec<FeatureToggleEntry>,
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
                decided: row.is_some(),
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

/// Re-read the table into the process snapshot. A failure keeps the last good
/// snapshot; the 60-second refresh retries.
pub async fn refresh_snapshot(pool: &PgPool, toggles: &FeatureToggleCache) {
    match FeatureToggleRepository::load(pool).await {
        Ok(fresh) => toggles.store(fresh),
        Err(e) => tracing::error!(
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
    config: web::Data<crate::config::Config>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let rows = FeatureToggleRepository::get_all(&pool).await?;
    let emails = actor_emails(&pool, &rows).await?;
    Ok(success(
        FeatureToggleList {
            environment: config.environment.clone(),
            toggles: entries(&rows, &emails),
        },
        request_id,
    ))
}

/// PUT /v1/admin/feature-toggles/{key}
///
/// Upserts the row and its audit entry in one transaction, refreshes this
/// process's snapshot, then reconciles the side effects a toggle owns. An
/// unknown key is a 404: only registered features can be stored.
pub async fn update_feature_toggle(
    req: HttpRequest,
    admin: SuperAdminUser,
    pool: web::Data<PgPool>,
    toggles: web::Data<Arc<FeatureToggleCache>>,
    routing: web::Data<TenantRoutingConfig>,
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

    refresh_snapshot(&pool, &toggles).await;
    // Idempotent and cheap, so it runs after every save rather than per feature.
    tenant_routing::reconcile(&toggles, &routing);

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
        let listed = entries(&[row("organizations", true)], &HashMap::new());
        let keys: Vec<&str> = listed.iter().map(|e| e.key).collect();
        let registry: Vec<&str> = Feature::ALL.iter().map(|f| f.key()).collect();
        assert_eq!(keys, registry);
        let tenant = listed.iter().find(|e| e.key == "tenant_hostnames").unwrap();
        assert!(!tenant.enabled && !tenant.decided && tenant.updated_at.is_none());
        assert!(
            listed
                .iter()
                .find(|e| e.key == "organizations")
                .unwrap()
                .decided
        );
        assert!(
            listed
                .iter()
                .find(|e| e.key == "organizations")
                .unwrap()
                .enabled
        );
    }

    /// BUNYIP-840 moved the organizations switch into `feature_toggles` and
    /// dropped the column. Outside the migrations, the only survivor on the api
    /// side is the probe field derived from the registry in `handlers/auth.rs`
    /// and the probe test that reads it.
    #[test]
    fn orgs_enabled_column_does_not_come_back() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let allowed = [
            root.join("bunyip-api/src/handlers/auth.rs"),
            root.join("bunyip-api/tests/feature_toggles.rs"),
            // This guard names the column in its own test name.
            root.join("bunyip-api/src/handlers/admin_feature_toggles.rs"),
        ];
        let needle = concat!("orgs_", "enabled");
        let mut offenders = Vec::new();
        let mut stack = vec![
            root.join("bunyip-api/src"),
            root.join("bunyip-api/tests"),
            root.join("crates/bunyip-domain/src"),
        ];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") && !allowed.contains(&path) {
                    let src = std::fs::read_to_string(&path).unwrap();
                    if src.contains(needle) {
                        offenders.push(path.display().to_string());
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "the organizations switch is the `organizations` feature toggle now: {offenders:?}"
        );
    }

    #[test]
    fn an_unknown_stored_key_is_not_listed() {
        let listed = entries(&[row("retired_feature", true)], &HashMap::new());
        assert!(listed.iter().all(|e| e.key != "retired_feature"));
        assert_eq!(listed.len(), Feature::ALL.len());
    }
}
