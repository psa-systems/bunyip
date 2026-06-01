//! Admin handlers
//!
//! This module contains HTTP handlers for admin management endpoints.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tokio;

use chrono::{Duration, Utc};

use crate::config::Config;
use crate::errors::AppError;
use crate::middleware::{AdminUser, AuthenticatedUser};
use crate::models::stripe::encrypt_secret;
use crate::models::{
    Application, AuditAction, CreateApplication, CreateAuditLog, CreatePasswordResetToken,
    CreateRefreshToken, DeleteApplicationRequest, MembershipStatus, StripeConfigResponse,
    SwapApplicationOrderRequest, UpdateApplication, UserResponse, ARTIFACT_SOURCE_GENERIC_PACKAGE,
};
use crate::repositories::{
    ApplicationRepository, AuditLogRepository, InviteRepository, NotificationRepository,
    StripeConfigRepository, TokenRepository, TotpRepository, UserRepository,
};
use crate::responses::{created, get_request_id, paginated, success, success_no_data};
use crate::services::{
    AppDownloadCache, AuthService, EmailService, EncryptionKeySet, JwtService, PasswordService,
    ReleaseCache, StripeConfig, StripeService, TotpService, WebhookService,
};
use crate::validation;
use bunyip_oci::services::ManifestCache;

// =============================================================================
// User Management
// =============================================================================

/// Query parameters for listing users
#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
    pub search: Option<String>,
    pub status: Option<String>,
}

/// GET /v1/admin/users
/// List all users with pagination
pub async fn list_users(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    query: web::Query<ListUsersQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let status_filter = query
        .status
        .as_ref()
        .map(|s| MembershipStatus::from(s.as_str()));

    let (users, total) = UserRepository::list_paginated(
        &pool,
        page,
        per_page,
        query.search.as_deref(),
        status_filter,
    )
    .await?;

    let user_responses: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();

    Ok(paginated(user_responses, total, page, per_page, request_id))
}

/// GET /v1/admin/users/{user_id}
/// Get a specific user
pub async fn get_user(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    let user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or(AppError::not_found("User"))?;

    Ok(success(UserResponse::from(user), request_id))
}

/// Request body for activating/deactivating user
#[derive(Debug, Deserialize)]
pub struct UpdateUserStatusRequest {
    pub active: bool,
}

/// PUT /v1/admin/users/{user_id}/status
/// Activate or deactivate a user
pub async fn update_user_status(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    oidc_provider: web::Data<Option<Arc<bunyip_oidc::services::oidc_provider::OidcProvider>>>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdateUserStatusRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    if body.active {
        // Reactivate: clear deleted_at (would need new method)
        // For now, we can't reactivate soft-deleted users through this API
        return Err(AppError::validation(
            "active",
            "Cannot reactivate deleted users through this endpoint",
        ));
    } else {
        let target_user = UserRepository::find_by_id(&pool, user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        UserRepository::soft_delete(&pool, user_id).await?;

        let audit_log = CreateAuditLog::new(AuditAction::AdminUserDeactivated)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("user", user_id)
            .with_metadata(serde_json::json!({
                "target_email": target_user.email,
            }));
        AuditLogRepository::create(&pool, audit_log).await?;

        if let Some(provider) = oidc_provider.as_ref().as_ref().cloned() {
            tokio::spawn(dispatch_lifecycle_event(provider, user_id, "user.deleted"));
        }
    }

    Ok(success_no_data(request_id))
}

/// DELETE /v1/admin/users/{user_id}
/// Delete a user (soft delete)
pub async fn delete_user(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    oidc_provider: web::Data<Option<Arc<bunyip_oidc::services::oidc_provider::OidcProvider>>>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    // Prevent self-deletion
    if admin.0.sub == user_id {
        return Err(AppError::validation(
            "user_id",
            "Cannot delete your own account",
        ));
    }

    // Check if user exists
    let target_user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or_else(|| AppError::not_found("User"))?;

    // Prevent deleting other admins (optional safety measure)
    if target_user.role == "admin" {
        return Err(AppError::validation("user_id", "Cannot delete admin users"));
    }

    UserRepository::soft_delete(&pool, user_id).await?;

    tracing::info!(
        admin_id = %admin.0.sub,
        deleted_user_id = %user_id,
        deleted_user_email = %target_user.email,
        "Admin deleted user"
    );

    let audit_log = CreateAuditLog::new(AuditAction::AdminUserDeleted)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", user_id)
        .with_metadata(serde_json::json!({
            "target_email": target_user.email,
            "target_role": target_user.role,
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    if let Some(provider) = oidc_provider.as_ref().as_ref().cloned() {
        tokio::spawn(dispatch_lifecycle_event(provider, user_id, "user.deleted"));
    }

    Ok(success_no_data(request_id))
}

/// Request body for updating user role
#[derive(Debug, Deserialize)]
pub struct UpdateUserRoleRequest {
    pub role: String,
}

/// PUT /v1/admin/users/{user_id}/role
/// Change a user's role
pub async fn update_user_role(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdateUserRoleRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    // Validate role
    let valid_roles = ["subscriber", "admin"];
    if !valid_roles.contains(&body.role.as_str()) {
        return Err(AppError::validation(
            "role",
            "Invalid role. Must be 'subscriber' or 'admin'",
        ));
    }

    // Prevent changing own role
    if admin.0.sub == user_id {
        return Err(AppError::validation(
            "user_id",
            "Cannot change your own role",
        ));
    }

    let target_user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or(AppError::not_found("User"))?;
    let old_role = target_user.role.clone();

    let updated_user = UserRepository::update_role(&pool, user_id, &body.role).await?;

    tracing::info!(
        admin_id = %admin.0.sub,
        target_user_id = %user_id,
        new_role = %body.role,
        "Admin changed user role"
    );

    let audit_log = CreateAuditLog::new(AuditAction::AdminUserRoleChanged)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", user_id)
        .with_old_values(serde_json::json!({ "role": old_role }))
        .with_new_values(serde_json::json!({ "role": &body.role }))
        .with_metadata(serde_json::json!({
            "target_email": target_user.email,
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success(UserResponse::from(updated_user), request_id))
}

// =============================================================================
// Membership Management
// =============================================================================

/// Request body for granting membership
#[derive(Debug, Deserialize)]
pub struct GrantMembershipRequest {
    pub user_id: uuid::Uuid,
    pub price_locked: Option<bool>,
    pub locked_price_amount: Option<i32>,
}

/// POST /v1/admin/memberships/grant
/// Grant a free membership to a user (permanent access, no payment required).
/// Creates a $0 Stripe subscription so the user receives invoices.
pub async fn grant_membership(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    body: web::Json<GrantMembershipRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Grant free tier — sets lifetime_member=true and subscription_status='active'
    let user =
        UserRepository::grant_free_membership(pool.get_ref(), body.user_id, admin.0.sub).await?;

    // Create $0 Stripe subscription for invoice generation
    if let Some(free_price_id) = stripe.free_price_id() {
        let customer_id = match user.stripe_customer_id {
            Some(id) => id,
            None => {
                let id = stripe.create_customer(&user.email, user.id).await?;
                UserRepository::update_stripe_customer_id(pool.get_ref(), user.id, &id).await?;
                id
            }
        };
        stripe
            .create_free_subscription(&customer_id, &free_price_id)
            .await?;
    }

    // Lock price at $0 if requested
    let price_locked = body.price_locked.unwrap_or(false);
    let locked_amount = body.locked_price_amount.unwrap_or(0);
    if price_locked {
        UserRepository::lock_price(
            pool.get_ref(),
            body.user_id,
            "price_admin_grant",
            locked_amount,
        )
        .await?;
    }

    let audit_log = CreateAuditLog::new(AuditAction::AdminMembershipGranted)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", body.user_id)
        .with_metadata(serde_json::json!({
            "tier": "free",
            "price_locked": price_locked,
            "locked_price_amount": locked_amount,
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success_no_data(request_id))
}

/// POST /v1/admin/memberships/revoke
/// Revoke a membership from a user
pub async fn revoke_membership(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    body: web::Json<GrantMembershipRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    UserRepository::update_membership_status(
        pool.get_ref(),
        body.user_id,
        MembershipStatus::Canceled,
    )
    .await?;

    // Reset tier to standard so the slot opens back up for the next user
    UserRepository::reset_subscription_tier(pool.get_ref(), body.user_id).await?;

    // Clear any grace period
    UserRepository::clear_grace_period(pool.get_ref(), body.user_id).await?;

    let audit_log = CreateAuditLog::new(AuditAction::AdminMembershipRevoked)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", body.user_id);
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success_no_data(request_id))
}

/// Query parameters for listing memberships
#[derive(Debug, Deserialize)]
pub struct ListMembershipsQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
    pub status: Option<String>,
}

/// GET /v1/admin/memberships
/// List all memberships with pagination (sourced from users table)
pub async fn list_memberships(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    query: web::Query<ListMembershipsQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = (page - 1) * per_page;

    let (memberships, total) = if let Some(ref status) = query.status {
        let rows = sqlx::query_as::<_, crate::models::AdminMembershipResponse>(
            r#"
            SELECT id AS user_id, email AS user_email, stripe_customer_id,
                   subscription_status AS status,
                   COALESCE(subscription_tier, 'standard') AS subscription_tier,
                   subscription_override_by,
                   created_at
            FROM users
            WHERE subscription_status = $3 AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(per_page)
        .bind(offset)
        .bind(status)
        .fetch_all(pool.get_ref())
        .await?;

        let total: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM users WHERE subscription_status = $1 AND deleted_at IS NULL",
        )
        .bind(status)
        .fetch_one(pool.get_ref())
        .await?;

        (rows, total.0)
    } else {
        let rows = sqlx::query_as::<_, crate::models::AdminMembershipResponse>(
            r#"
            SELECT id AS user_id, email AS user_email, stripe_customer_id,
                   subscription_status AS status,
                   COALESCE(subscription_tier, 'standard') AS subscription_tier,
                   subscription_override_by,
                   created_at
            FROM users
            WHERE subscription_status != 'none' AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(per_page)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await?;

        let total: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM users WHERE subscription_status != 'none' AND deleted_at IS NULL",
        )
        .fetch_one(pool.get_ref())
        .await?;

        (rows, total.0)
    };

    Ok(paginated(memberships, total, page, per_page, request_id))
}

// =============================================================================
// Application Management
// =============================================================================

/// GET /v1/admin/applications
/// List all applications (including inactive)
pub async fn list_all_applications(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let apps = ApplicationRepository::list_all(&pool).await?;

    Ok(success(
        serde_json::json!({ "applications": apps }),
        request_id,
    ))
}

/// PUT /v1/admin/applications/{app_id}/swap-order
/// Swap the sort order of two applications
pub async fn swap_application_order(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<SwapApplicationOrderRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let app_id = path.into_inner();

    ApplicationRepository::swap_sort_order(&pool, app_id, body.target_app_id).await?;

    let apps = ApplicationRepository::list_all(&pool).await?;

    Ok(success(
        serde_json::json!({ "applications": apps }),
        request_id,
    ))
}

/// PUT /v1/admin/applications/{app_id}
/// Update an application
#[allow(clippy::too_many_arguments)]
pub async fn update_application(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdateApplication>,
    webhook_service: web::Data<Arc<WebhookService>>,
    release_cache: web::Data<Option<Arc<ReleaseCache>>>,
    download_cache: web::Data<Option<Arc<AppDownloadCache>>>,
    manifest_cache: web::Data<Option<Arc<ManifestCache>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let app_id = path.into_inner();

    let old_app = ApplicationRepository::find_by_id(&pool, app_id)
        .await?
        .ok_or(AppError::not_found("Application"))?;

    // Validate artifact_source against the allowed set BEFORE the update, so a
    // bad value is a clean 400 instead of a DB CHECK-constraint 500.
    if let Some(source) = body.artifact_source.as_deref() {
        if !Application::valid_artifact_source(source) {
            return Err(AppError::validation(
                "artifact_source",
                "artifact_source must be 'release' or 'generic_package'",
            ));
        }
    }

    // Source-aware Forgejo download validation on merged values:
    // - release sources need owner + repo + tag
    // - generic_package sources need owner + (package or repo) + tag
    let merged_owner = body
        .forgejo_owner
        .as_ref()
        .or(old_app.forgejo_owner.as_ref());
    let merged_repo = body.forgejo_repo.as_ref().or(old_app.forgejo_repo.as_ref());
    let merged_package = body
        .forgejo_package
        .as_ref()
        .filter(|p| !p.is_empty())
        .or(old_app.forgejo_package.as_ref());
    let merged_tag = body
        .pinned_release_tag
        .as_ref()
        .or(old_app.pinned_release_tag.as_ref());
    let merged_source = body
        .artifact_source
        .as_deref()
        .unwrap_or(old_app.artifact_source.as_str());
    let is_generic_package = merged_source == ARTIFACT_SOURCE_GENERIC_PACKAGE;

    let forgejo_any = merged_owner.is_some()
        || merged_repo.is_some()
        || merged_package.is_some()
        || merged_tag.is_some();
    let forgejo_all = merged_owner.is_some()
        && merged_tag.is_some()
        && if is_generic_package {
            merged_package.is_some() || merged_repo.is_some()
        } else {
            merged_repo.is_some()
        };
    if forgejo_any && !forgejo_all {
        return Err(AppError::validation(
            "forgejo",
            if is_generic_package {
                "generic_package downloads need forgejo_owner, pinned_release_tag, and forgejo_package (or forgejo_repo) set together"
            } else {
                "forgejo_owner, forgejo_repo, and pinned_release_tag must all be set together"
            },
        ));
    }

    // All-or-nothing OCI validation on merged values
    let merged_oci_owner = body
        .oci_image_owner
        .as_ref()
        .or(old_app.oci_image_owner.as_ref());
    let merged_oci_name = body
        .oci_image_name
        .as_ref()
        .or(old_app.oci_image_name.as_ref());
    let merged_oci_tag = body
        .pinned_image_tag
        .as_ref()
        .or(old_app.pinned_image_tag.as_ref());
    let oci_any =
        merged_oci_owner.is_some() || merged_oci_name.is_some() || merged_oci_tag.is_some();
    let oci_all =
        merged_oci_owner.is_some() && merged_oci_name.is_some() && merged_oci_tag.is_some();
    if oci_any && !oci_all {
        return Err(AppError::validation(
            "oci",
            "oci_image_owner, oci_image_name, and pinned_image_tag must all be set together",
        ));
    }

    // Capture the old artifact source before update for cache invalidation
    let old_source = old_app.download_source();
    let old_pinned_image_tag = old_app.pinned_image_tag.clone();

    let app = ApplicationRepository::update(&pool, app_id, &body).await?;

    // Invalidate caches if the download source (owner/repo/package/tag) changed
    if let Some(old_source) = old_source {
        if app.download_source().as_ref() != Some(&old_source) {
            if let Some(rc) = release_cache.get_ref().as_ref() {
                rc.invalidate(app.id, &old_source).await;
            }
            if let Some(dc) = download_cache.get_ref().as_ref() {
                if let Err(e) = dc
                    .invalidate_app_version(app.id, old_source.version())
                    .await
                {
                    tracing::warn!(error = %e, "download cache invalidation failed");
                }
            }
        }
    }

    // Invalidate OCI manifest cache if the pinned image tag changed.
    // On-disk blob eviction is handled by BlobCache's async LRU.
    if old_pinned_image_tag != app.pinned_image_tag {
        if let Some(mc) = manifest_cache.get_ref().as_ref() {
            mc.invalidate_app(app.id).await;
        }
    }

    // Notify child app if maintenance mode or active status changed
    let maintenance_changed = old_app.maintenance_mode != app.maintenance_mode;
    let active_changed = old_app.is_active != app.is_active;
    if maintenance_changed || active_changed {
        let ws = webhook_service.into_inner();
        let app_clone = app.clone();
        actix_web::rt::spawn(async move {
            if maintenance_changed {
                ws.notify_maintenance_change(&app_clone).await;
            }
            if active_changed {
                ws.notify_active_change(&app_clone).await;
            }
        });
    }

    // Audit log for all application updates
    let audit_log = CreateAuditLog::new(AuditAction::ApplicationUpdated)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("application", app_id)
        .with_old_values(serde_json::json!({
            "name": old_app.name,
            "is_active": old_app.is_active,
            "maintenance_mode": old_app.maintenance_mode,
        }))
        .with_new_values(serde_json::json!({
            "name": app.name,
            "is_active": app.is_active,
            "maintenance_mode": app.maintenance_mode,
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    // Additional specific log when maintenance mode changes
    if maintenance_changed {
        let maintenance_log = CreateAuditLog::new(AuditAction::ApplicationMaintenanceToggled)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("application", app_id)
            .with_metadata(serde_json::json!({
                "application_name": app.name,
                "maintenance_mode": app.maintenance_mode,
            }));
        AuditLogRepository::create(&pool, maintenance_log).await?;
    }

    Ok(success(app, request_id))
}

/// POST /v1/admin/applications
/// Create a new application
pub async fn create_application(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    body: web::Json<CreateApplication>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Validate required fields
    if body.name.trim().is_empty() {
        return Err(AppError::validation("name", "Name is required"));
    }
    if body.slug.trim().is_empty() {
        return Err(AppError::validation("slug", "Slug is required"));
    }
    if body.display_name.trim().is_empty() {
        return Err(AppError::validation(
            "display_name",
            "Display name is required",
        ));
    }
    if body.container_name.trim().is_empty() {
        return Err(AppError::validation(
            "container_name",
            "Container name is required",
        ));
    }

    // Validate slug format
    validation::validate_slug(&body.slug).map_err(|_| {
        AppError::validation(
            "slug",
            "Slug must contain only lowercase letters, numbers, and hyphens",
        )
    })?;

    // Check slug uniqueness
    if ApplicationRepository::find_by_slug(&pool, &body.slug)
        .await?
        .is_some()
    {
        return Err(AppError::conflict(
            "An application with this slug already exists",
        ));
    }

    let app = ApplicationRepository::create(&pool, &body).await?;

    // Audit log
    let audit_log = CreateAuditLog::new(AuditAction::ApplicationCreated)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("application", app.id)
        .with_metadata(serde_json::json!({
            "application_name": app.name,
            "application_slug": app.slug,
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(created(app, request_id))
}

/// DELETE /v1/admin/applications/{app_id}
/// Delete an application (requires password + 2FA)
pub async fn delete_application(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<DeleteApplicationRequest>,
    totp_service: web::Data<Arc<TotpService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let app_id = path.into_inner();

    // Look up the admin user to get password hash
    let admin_user = UserRepository::find_by_id(&pool, admin.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    // Verify password
    let password_service = PasswordService::new();
    let password_hash = admin_user
        .password_hash
        .as_deref()
        .ok_or_else(|| AppError::validation("password", "Account has no password set"))?;
    if !password_service.verify(&body.password, password_hash)? {
        return Err(AppError::validation("password", "Invalid password"));
    }

    // Verify TOTP code (2FA must be enabled)
    let totp_valid = totp_service
        .verify_code(admin.0.sub, &body.totp_code)
        .await
        .map_err(|_| {
            AppError::validation("totp_code", "2FA must be enabled to delete applications")
        })?;
    if !totp_valid {
        return Err(AppError::validation("totp_code", "Invalid 2FA code"));
    }

    // Find the application (for audit metadata)
    let app = ApplicationRepository::find_by_id(&pool, app_id)
        .await?
        .ok_or(AppError::not_found("Application"))?;

    // Delete
    ApplicationRepository::delete(&pool, app_id).await?;

    // Audit log
    let audit_log = CreateAuditLog::new(AuditAction::ApplicationDeleted)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("application", app_id)
        .with_metadata(serde_json::json!({
            "application_name": app.name,
            "application_slug": app.slug,
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success_no_data(request_id))
}

// =============================================================================
// Audit Logs
// =============================================================================

/// Query parameters for listing audit logs
#[derive(Debug, Deserialize)]
pub struct ListAuditLogsQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
    pub user_id: Option<uuid::Uuid>,
    pub action: Option<String>,
    pub admin_only: Option<bool>,
}

/// GET /v1/admin/audit-logs
/// List audit logs with pagination
pub async fn list_audit_logs(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    query: web::Query<ListAuditLogsQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).min(100);

    let (logs, total) = AuditLogRepository::list_paginated(
        &pool,
        page,
        per_page,
        query.user_id,
        query.action.as_deref(),
        query.admin_only.unwrap_or(false),
        None, // start_date
        None, // end_date
    )
    .await?;

    Ok(paginated(logs, total, page, per_page, request_id))
}

// =============================================================================
// Dashboard Stats
// =============================================================================

/// Dashboard statistics response
#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub total_users: i64,
    pub active_members: i64,
    pub past_due_members: i64,
    pub grace_period_members: i64,
    pub total_applications: i64,
    pub active_applications: i64,
}

/// GET /v1/admin/stats
/// Get dashboard statistics
pub async fn get_dashboard_stats(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Get user counts by status
    let total_users: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL")
        .fetch_one(pool.get_ref())
        .await?;

    let active_members: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE subscription_status = 'active' AND deleted_at IS NULL",
    )
    .fetch_one(pool.get_ref())
    .await?;

    let past_due_members: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE subscription_status = 'past_due' AND deleted_at IS NULL",
    )
    .fetch_one(pool.get_ref())
    .await?;

    let grace_period_members: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE subscription_status = 'grace_period' AND deleted_at IS NULL",
    )
    .fetch_one(pool.get_ref())
    .await?;

    let total_applications: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM applications")
        .fetch_one(pool.get_ref())
        .await?;

    let active_applications: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM applications WHERE is_active = TRUE")
            .fetch_one(pool.get_ref())
            .await?;

    let stats = DashboardStats {
        total_users: total_users.0,
        active_members: active_members.0,
        past_due_members: past_due_members.0,
        grace_period_members: grace_period_members.0,
        total_applications: total_applications.0,
        active_applications: active_applications.0,
    };

    Ok(success(stats, request_id))
}

// =============================================================================
// User Actions (Reset Password, Impersonate)
// =============================================================================

/// POST /v1/admin/users/{user_id}/reset-password
/// Trigger a password reset email for a user
pub async fn admin_reset_password(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    jwt_service: web::Data<Arc<JwtService>>,
    email_service: web::Data<Arc<EmailService>>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();
    let admin_user_id = admin.0.sub;

    // Find the user
    let user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or(AppError::not_found("User"))?;

    // Generate password reset token
    let raw_token = uuid::Uuid::new_v4().to_string();
    let token_hash = jwt_service.hash_token(&raw_token);
    let expires_at = Utc::now() + Duration::hours(1);

    TokenRepository::create_password_reset_token(
        &pool,
        CreatePasswordResetToken {
            user_id,
            token_hash,
            expires_at,
            ip_address: None,
        },
    )
    .await?;

    // Send password reset email
    email_service
        .send_password_reset(&user.email, &raw_token)
        .await?;

    // Log admin action
    let audit_log = CreateAuditLog::new(AuditAction::AdminPasswordReset)
        .with_actor(admin_user_id, &admin.0.email, &admin.0.role)
        .with_resource("user", user_id)
        .with_metadata(serde_json::json!({
            "target_user_id": user_id,
            "target_email": user.email
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success_no_data(request_id))
}

/// POST /v1/admin/users/{user_id}/impersonate
/// Generate tokens to impersonate a user
pub async fn impersonate_user(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    jwt_service: web::Data<Arc<JwtService>>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let target_user_id = path.into_inner();
    let admin_user_id = admin.0.sub;

    // Prevent self-impersonation
    if admin_user_id == target_user_id {
        return Err(AppError::validation(
            "user_id",
            "Cannot impersonate yourself",
        ));
    }

    // Find the target user
    let target_user = UserRepository::find_by_id(&pool, target_user_id)
        .await?
        .ok_or(AppError::not_found("User"))?;

    // Generate access token for target user
    let access_token = jwt_service.create_access_token(&target_user)?;

    // Generate refresh token
    let (refresh_token, token_hash) = jwt_service.create_refresh_token(target_user.id)?;
    let expires_at = Utc::now() + Duration::days(30);

    TokenRepository::create_refresh_token(
        &pool,
        CreateRefreshToken {
            user_id: target_user.id,
            token_hash,
            device_info: Some("Admin impersonation".to_string()),
            ip_address: None,
            expires_at,
        },
    )
    .await?;

    // Log admin action
    let audit_log = CreateAuditLog::new(AuditAction::AdminUserImpersonated)
        .with_actor(admin_user_id, &admin.0.email, &admin.0.role)
        .with_resource("user", target_user_id)
        .with_metadata(serde_json::json!({
            "target_user_id": target_user_id,
            "target_email": target_user.email,
            "admin_id": admin_user_id
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success(
        serde_json::json!({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": UserResponse::from(target_user)
        }),
        request_id,
    ))
}

// =============================================================================
// Notifications
// =============================================================================

/// Query parameters for listing notifications
#[derive(Debug, Deserialize)]
pub struct ListNotificationsQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
    pub unread: Option<bool>,
}

/// GET /v1/admin/notifications
/// List admin notifications
pub async fn list_notifications(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    query: web::Query<ListNotificationsQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    if query.unread.unwrap_or(false) {
        let notifications = NotificationRepository::list_unread(&pool).await?;
        let total = notifications.len() as i64;
        return Ok(paginated(notifications, total, 1, 100, request_id));
    }

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);

    let (notifications, total) =
        NotificationRepository::list_paginated(&pool, page, per_page).await?;

    Ok(paginated(notifications, total, page, per_page, request_id))
}

/// POST /v1/admin/notifications/{notification_id}/read
/// Mark a notification as read
pub async fn mark_notification_read(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let notification_id = path.into_inner();

    NotificationRepository::mark_as_read(&pool, notification_id, admin.0.sub).await?;

    Ok(success_no_data(request_id))
}

/// POST /v1/admin/notifications/read-all
/// Mark all notifications as read
pub async fn mark_all_notifications_read(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    NotificationRepository::mark_all_as_read(&pool, admin.0.sub).await?;

    Ok(success_no_data(request_id))
}

// =============================================================================
// Test Email
// =============================================================================

/// POST /v1/admin/test-email
/// Send a test welcome email to the authenticated user
pub async fn send_test_email(
    req: HttpRequest,
    user: AuthenticatedUser,
    email_service: web::Data<Arc<EmailService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    email_service.send_welcome(&user.0.email, 300).await?;

    tracing::info!(email = %user.0.email, "Test email sent");

    Ok(success_no_data(request_id))
}

// =============================================================================
// System Health
// =============================================================================

/// System health response
#[derive(Debug, Serialize)]
pub struct SystemHealth {
    pub status: String,
    pub database: HealthStatus,
    pub uptime_seconds: u64,
    pub version: String,
}

/// Health status for a component
#[derive(Debug, Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub latency_ms: Option<u64>,
    pub message: Option<String>,
}

// =============================================================================
// Admin Invites
// =============================================================================

/// Request body for creating an admin invite
#[derive(Debug, Deserialize)]
pub struct CreateAdminInviteRequest {
    pub email: String,
}

/// Query parameters for listing admin invites
#[derive(Debug, Deserialize)]
pub struct ListAdminInvitesQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
}

/// POST /v1/admin/invites
/// Create an admin invite and send email
pub async fn create_admin_invite(
    req: HttpRequest,
    admin: AdminUser,
    auth_service: web::Data<Arc<AuthService>>,
    email_service: web::Data<Arc<EmailService>>,
    body: web::Json<CreateAdminInviteRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = crate::middleware::extract_client_ip(&req);

    // Validate email format
    crate::validation::validate_email(&body.email)?;

    let token = auth_service
        .create_admin_invite(
            body.email.clone(),
            admin.0.sub,
            &admin.0.email,
            &admin.0.role,
            ip_address,
        )
        .await?;

    // Send invite email (in background)
    let email = body.email.clone();
    let email_svc = email_service.get_ref().clone();
    tokio::spawn(async move {
        if let Err(e) = email_svc.send_admin_invite(&email, &token).await {
            tracing::error!(error = %e, email = %email, "Failed to send admin invite email");
        }
    });

    Ok(created(
        serde_json::json!({ "email": body.email }),
        request_id,
    ))
}

/// GET /v1/admin/invites
/// List admin invites with pagination
pub async fn list_admin_invites(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    query: web::Query<ListAdminInvitesQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);

    let (invites, total) = InviteRepository::list_all(&pool, page, per_page).await?;

    Ok(paginated(invites, total, page, per_page, request_id))
}

/// DELETE /v1/admin/invites/{invite_id}
/// Revoke a pending admin invite
pub async fn revoke_admin_invite(
    req: HttpRequest,
    admin: AdminUser,
    auth_service: web::Data<Arc<AuthService>>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let invite_id = path.into_inner();

    auth_service
        .revoke_admin_invite(invite_id, admin.0.sub, &admin.0.email, &admin.0.role)
        .await?;

    Ok(success_no_data(request_id))
}

/// GET /v1/admin/health
/// Get system health status
pub async fn get_system_health(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Check database health
    let db_start = std::time::Instant::now();
    let db_health = match sqlx::query("SELECT 1").execute(pool.get_ref()).await {
        Ok(_) => HealthStatus {
            status: "healthy".to_string(),
            latency_ms: Some(db_start.elapsed().as_millis() as u64),
            message: None,
        },
        Err(e) => HealthStatus {
            status: "unhealthy".to_string(),
            latency_ms: None,
            message: Some(e.to_string()),
        },
    };

    // Get database stats
    let db_stats: Option<(i64, i64, i64)> = sqlx::query_as(
        r#"
        SELECT
            (SELECT COUNT(*) FROM users WHERE deleted_at IS NULL) as users,
            (SELECT COUNT(*) FROM users WHERE subscription_status = 'active') as active_subs,
            (SELECT COUNT(*) FROM audit_logs WHERE created_at > NOW() - INTERVAL '1 hour') as recent_logs
        "#
    )
    .fetch_optional(pool.get_ref())
    .await
    .ok()
    .flatten();

    let overall_status = if db_health.status == "healthy" {
        "healthy"
    } else {
        "degraded"
    };

    let health = SystemHealth {
        status: overall_status.to_string(),
        database: db_health,
        uptime_seconds: 0, // Would need to track startup time
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let mut response = serde_json::json!({
        "health": health,
    });

    if let Some((users, active_members, recent_logs)) = db_stats {
        response["stats"] = serde_json::json!({
            "total_users": users,
            "active_members": active_members,
            "audit_logs_last_hour": recent_logs
        });
    }

    Ok(success(response, request_id))
}

// =============================================================================
// Stripe Config
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct UpdateStripeConfigRequest {
    pub secret_key: Option<String>,
    pub webhook_secret: Option<String>,
    pub app_tag: Option<String>,
}

/// GET /v1/admin/stripe
/// Returns the current Stripe config with secrets masked.
/// Falls back to env vars if no DB config has been saved yet.
pub async fn get_stripe_config(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    stripe_key_set: web::Data<EncryptionKeySet>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let db = StripeConfigRepository::get(&pool).await?;

    let response = if db.secret_key.is_some() || db.webhook_secret.is_some() {
        match StripeConfigResponse::from_db(&db, &stripe_key_set) {
            Ok(resp) => resp,
            Err(_) => {
                tracing::warn!(
                    "Stripe secrets could not be decrypted (encryption key may have changed). \
                     Clearing stale encrypted secrets from database."
                );
                StripeConfigRepository::clear_secrets(&pool).await?;
                StripeConfigResponse::from_env()
            }
        }
    } else {
        StripeConfigResponse::from_env()
    };

    Ok(success(response, request_id))
}

/// PUT /v1/admin/stripe
/// Updates Stripe config. Only fields with a non-empty value are written; omitted or
/// empty-string fields leave the existing DB value unchanged.
pub async fn update_stripe_config(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    stripe_key_set: web::Data<EncryptionKeySet>,
    stripe_service: web::Data<Arc<StripeService>>,
    body: web::Json<UpdateStripeConfigRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Treat empty strings the same as None — user left the field blank
    let secret_key_plain = body.secret_key.as_deref().filter(|s| !s.is_empty());
    let webhook_secret_plain = body.webhook_secret.as_deref().filter(|s| !s.is_empty());
    let app_tag = body
        .app_tag
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    // Encrypt secrets before storing
    let (secret_key_enc, secret_key_nonce, key_version) = match secret_key_plain {
        Some(sk) => {
            let (ct, nonce, ver) = encrypt_secret(&stripe_key_set, sk)?;
            (Some(ct), Some(nonce), ver)
        }
        None => (None, None, stripe_key_set.current_version),
    };
    let (webhook_secret_enc, webhook_secret_nonce) = match webhook_secret_plain {
        Some(ws) => {
            let (ct, nonce, _) = encrypt_secret(&stripe_key_set, ws)?;
            (Some(ct), Some(nonce))
        }
        None => (None, None),
    };

    let updated = StripeConfigRepository::update(
        &pool,
        secret_key_enc,
        secret_key_nonce,
        webhook_secret_enc,
        webhook_secret_nonce,
        admin.0.sub,
        key_version,
        app_tag.clone(),
    )
    .await?;

    // Hot-reload the live StripeService so new API calls use the updated keys
    match StripeConfig::from_db_model(&updated, &stripe_key_set) {
        Ok(new_config) => {
            stripe_service.reload(new_config);
            tracing::info!("Stripe service reloaded with updated config");
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to reload Stripe service after config update");
        }
    }

    let audit_log = CreateAuditLog::new(AuditAction::AdminStripeConfigUpdated)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({
            "fields_updated": {
                "secret_key": secret_key_plain.is_some(),
                "webhook_secret": webhook_secret_plain.is_some(),
                "app_tag": app_tag,
            }
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success(
        StripeConfigResponse::from_db(&updated, &stripe_key_set)?,
        request_id,
    ))
}

// =============================================================================
// Subscription Management
// =============================================================================

/// POST /v1/admin/users/{user_id}/lifetime
/// Grant lifetime membership to a user.
/// Creates a $0 Stripe subscription so the user receives invoices.
pub async fn grant_lifetime_membership(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    let user = UserRepository::grant_lifetime_membership(&pool, user_id, admin.0.sub).await?;

    // Create $0 Stripe subscription for invoice generation
    if let Some(free_price_id) = stripe.free_price_id() {
        let customer_id = match user.stripe_customer_id.clone() {
            Some(id) => id,
            None => {
                let id = stripe.create_customer(&user.email, user.id).await?;
                UserRepository::update_stripe_customer_id(pool.get_ref(), user.id, &id).await?;
                id
            }
        };
        stripe
            .create_free_subscription(&customer_id, &free_price_id)
            .await?;
    }

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminMembershipGranted)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("user", user_id)
            .with_metadata(serde_json::json!({
                "tier": "lifetime",
                "target_email": user.email,
            })),
    )
    .await?;

    Ok(success(UserResponse::from(user), request_id))
}

// =============================================================================
// Tier Configuration
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct UpdateTierConfigRequest {
    pub lifetime_slots: Option<i64>,
    pub early_adopter_slots: Option<i64>,
    pub early_adopter_trial_days: Option<i64>,
    pub standard_trial_days: Option<i64>,
    pub free_price_id: Option<String>,
    pub early_adopter_price_id: Option<String>,
    pub standard_price_id: Option<String>,
    pub lifetime_product_id: Option<String>,
    pub early_adopter_product_id: Option<String>,
    pub standard_product_id: Option<String>,
}

/// GET /v1/admin/tier-config
pub async fn get_tier_config(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    use crate::config::TierConfig;
    use crate::models::tier::TierConfigResponse;
    use crate::repositories::TierConfigRepository;

    let request_id = get_request_id(&req);

    let row = TierConfigRepository::get(&pool).await?;
    let resolved = TierConfig::from_db_row(&row);
    let source = if TierConfig::has_db_overrides(&row) {
        "database"
    } else {
        "environment"
    };

    let (lifetime_used, early_adopter_used) =
        UserRepository::count_tier_assignments(pool.get_ref()).await?;

    Ok(success(
        TierConfigResponse {
            lifetime_slots: resolved.lifetime_slots,
            early_adopter_slots: resolved.early_adopter_slots,
            early_adopter_trial_days: resolved.early_adopter_trial_days,
            standard_trial_days: resolved.standard_trial_days,
            free_price_id: resolved.free_price_id,
            early_adopter_price_id: resolved.early_adopter_price_id,
            standard_price_id: resolved.standard_price_id,
            lifetime_product_id: resolved.lifetime_product_id,
            early_adopter_product_id: resolved.early_adopter_product_id,
            standard_product_id: resolved.standard_product_id,
            source,
            lifetime_slots_used: lifetime_used,
            early_adopter_slots_used: early_adopter_used,
            updated_at: row.updated_at,
            updated_by: row.updated_by,
        },
        request_id,
    ))
}

/// PUT /v1/admin/tier-config
pub async fn update_tier_config(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    auth_service: web::Data<Arc<AuthService>>,
    body: web::Json<UpdateTierConfigRequest>,
) -> Result<HttpResponse, AppError> {
    use crate::config::TierConfig;
    use crate::models::tier::TierConfigResponse;
    use crate::repositories::TierConfigRepository;

    let request_id = get_request_id(&req);

    // Validate: all provided values must be positive
    if let Some(v) = body.lifetime_slots {
        if v < 0 {
            return Err(AppError::validation(
                "lifetime_slots",
                "Must be non-negative",
            ));
        }
    }
    if let Some(v) = body.early_adopter_slots {
        if v < 0 {
            return Err(AppError::validation(
                "early_adopter_slots",
                "Must be non-negative",
            ));
        }
    }
    if let Some(v) = body.early_adopter_trial_days {
        if v < 0 {
            return Err(AppError::validation(
                "early_adopter_trial_days",
                "Must be non-negative",
            ));
        }
    }
    if let Some(v) = body.standard_trial_days {
        if v < 0 {
            return Err(AppError::validation(
                "standard_trial_days",
                "Must be non-negative",
            ));
        }
    }

    let row = TierConfigRepository::update(
        &pool,
        body.lifetime_slots,
        body.early_adopter_slots,
        body.early_adopter_trial_days,
        body.standard_trial_days,
        body.free_price_id.clone(),
        body.early_adopter_price_id.clone(),
        body.standard_price_id.clone(),
        body.lifetime_product_id.clone(),
        body.early_adopter_product_id.clone(),
        body.standard_product_id.clone(),
        admin.0.sub,
    )
    .await?;

    // Hot-reload the AuthService with the new tier config
    let resolved = TierConfig::from_db_row(&row);
    auth_service.reload_tier_config(resolved.clone());
    tracing::info!(?resolved, "Tier config updated and hot-reloaded");

    let (lifetime_used, early_adopter_used) =
        UserRepository::count_tier_assignments(pool.get_ref()).await?;

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminTierConfigUpdated)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_metadata(serde_json::json!({
                "setting": "tier_config",
                "lifetime_slots": body.lifetime_slots,
                "early_adopter_slots": body.early_adopter_slots,
                "early_adopter_trial_days": body.early_adopter_trial_days,
                "standard_trial_days": body.standard_trial_days,
                "free_price_id": body.free_price_id,
                "early_adopter_price_id": body.early_adopter_price_id,
                "standard_price_id": body.standard_price_id,
                "lifetime_product_id": body.lifetime_product_id,
                "early_adopter_product_id": body.early_adopter_product_id,
                "standard_product_id": body.standard_product_id,
            })),
    )
    .await?;

    Ok(success(
        TierConfigResponse {
            lifetime_slots: resolved.lifetime_slots,
            early_adopter_slots: resolved.early_adopter_slots,
            early_adopter_trial_days: resolved.early_adopter_trial_days,
            standard_trial_days: resolved.standard_trial_days,
            free_price_id: resolved.free_price_id,
            early_adopter_price_id: resolved.early_adopter_price_id,
            standard_price_id: resolved.standard_price_id,
            lifetime_product_id: resolved.lifetime_product_id,
            early_adopter_product_id: resolved.early_adopter_product_id,
            standard_product_id: resolved.standard_product_id,
            source: "database",
            lifetime_slots_used: lifetime_used,
            early_adopter_slots_used: early_adopter_used,
            updated_at: row.updated_at,
            updated_by: row.updated_by,
        },
        request_id,
    ))
}

// =============================================================================
// Key Health Checks
// =============================================================================

use crate::services::encryption::decrypt_with_key;

#[derive(Debug, Serialize)]
pub struct KeyHealthCheck {
    pub status: String,
    pub has_data: bool,
    pub key_version: Option<i16>,
    pub needs_reencrypt: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Evaluate decryptability of an optional (ciphertext, nonce) pair.
fn evaluate_key_health(
    key: &[u8; 32],
    ciphertext: Option<&[u8]>,
    nonce: Option<&[u8]>,
    key_version: Option<i16>,
    current_version: i16,
) -> KeyHealthCheck {
    match (ciphertext, nonce) {
        (Some(ct), Some(n)) => match decrypt_with_key(key, ct, n) {
            Ok(_) => KeyHealthCheck {
                status: "healthy".to_string(),
                has_data: true,
                key_version,
                needs_reencrypt: key_version.map(|v| v != current_version),
                message: None,
            },
            Err(e) => KeyHealthCheck {
                status: "unhealthy".to_string(),
                has_data: true,
                key_version,
                needs_reencrypt: key_version.map(|v| v != current_version),
                message: Some(e.to_string()),
            },
        },
        _ => KeyHealthCheck {
            status: "no_data".to_string(),
            has_data: false,
            key_version: None,
            needs_reencrypt: None,
            message: None,
        },
    }
}

async fn check_stripe_key(pool: &PgPool, config: &Config) -> Result<KeyHealthCheck, AppError> {
    let db = StripeConfigRepository::get(pool).await?;
    Ok(evaluate_key_health(
        &config.stripe_encryption_key,
        db.secret_key.as_deref(),
        db.secret_key_nonce.as_deref(),
        Some(db.key_version),
        config.stripe_key_version,
    ))
}

async fn check_totp_key(pool: &PgPool, config: &Config) -> Result<KeyHealthCheck, AppError> {
    let row: Option<(Vec<u8>, Vec<u8>, i16)> =
        sqlx::query_as("SELECT encrypted_secret, nonce, key_version FROM user_totp LIMIT 1")
            .fetch_optional(pool)
            .await?;

    Ok(match row {
        Some((ct, nonce, kv)) => evaluate_key_health(
            &config.totp_encryption_key,
            Some(&ct),
            Some(&nonce),
            Some(kv),
            config.totp_key_version,
        ),
        None => evaluate_key_health(
            &config.totp_encryption_key,
            None,
            None,
            None,
            config.totp_key_version,
        ),
    })
}

/// Dispatch a key health check by key_id. To add a new key, add a match arm here
/// and a corresponding `check_*` helper above.
async fn run_key_check(
    key_id: &str,
    pool: &PgPool,
    config: &Config,
) -> Result<KeyHealthCheck, AppError> {
    match key_id {
        "stripe" => check_stripe_key(pool, config).await,
        "totp" => check_totp_key(pool, config).await,
        _ => Err(AppError::not_found(format!("Unknown key: {key_id}"))),
    }
}

/// All registered key IDs. Update this when adding a new key.
const KEY_IDS: &[&str] = &["stripe", "totp"];

/// GET /v1/admin/key-health
/// Aggregated health check for all encryption keys.
pub async fn get_key_health(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let mut checks = serde_json::Map::new();
    let mut any_unhealthy = false;

    for &key_id in KEY_IDS {
        let check = run_key_check(key_id, &pool, &config).await?;
        if check.status == "unhealthy" {
            any_unhealthy = true;
        }
        checks.insert(key_id.to_string(), serde_json::to_value(&check).unwrap());
    }

    let overall_status = if any_unhealthy { "degraded" } else { "healthy" };

    Ok(success(
        serde_json::json!({
            "status": overall_status,
            "checks": checks,
        }),
        request_id,
    ))
}

/// GET /v1/admin/key-health/{key_id}
pub async fn get_key_health_by_id(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let key_id = path.into_inner();
    let check = run_key_check(&key_id, &pool, &config).await?;
    Ok(success(check, request_id))
}

// =============================================================================
// Key Rotation
// =============================================================================

/// GET /v1/admin/key-rotation/{key_id}/status
/// Returns the rotation status for a specific key: how many records are on the
/// current version vs old versions.
pub async fn key_rotation_status(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let key_id = path.into_inner();

    match key_id.as_str() {
        "totp" => {
            let current_version = config.totp_key_version;
            let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM user_totp")
                .fetch_one(pool.as_ref())
                .await?;
            let on_current: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM user_totp WHERE key_version = $1")
                    .bind(current_version)
                    .fetch_one(pool.as_ref())
                    .await?;

            Ok(success(
                serde_json::json!({
                    "key_id": "totp",
                    "current_version": current_version,
                    "total": total.0,
                    "on_current_version": on_current.0,
                    "on_old_versions": total.0 - on_current.0,
                    "rotation_complete": total.0 == on_current.0,
                }),
                request_id,
            ))
        }
        "stripe" => {
            let current_version = config.stripe_key_version;
            let db = StripeConfigRepository::get(&pool).await?;
            let has_secrets = db.secret_key.is_some() || db.webhook_secret.is_some();
            let on_current = db.key_version == current_version;

            Ok(success(
                serde_json::json!({
                    "key_id": "stripe",
                    "current_version": current_version,
                    "total": if has_secrets { 1 } else { 0 },
                    "on_current_version": if has_secrets && on_current { 1 } else { 0 },
                    "on_old_versions": if has_secrets && !on_current { 1 } else { 0 },
                    "rotation_complete": !has_secrets || on_current,
                }),
                request_id,
            ))
        }
        _ => Err(AppError::not_found(format!("Unknown key: {key_id}"))),
    }
}

/// POST /v1/admin/key-rotation/{key_id}/reencrypt
/// Re-encrypts all records that are still on an old key version.
pub async fn reencrypt_key(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    totp_service: web::Data<Arc<TotpService>>,
    stripe_key_set: web::Data<EncryptionKeySet>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let key_id = path.into_inner();

    match key_id.as_str() {
        "totp" => {
            let key_set = totp_service.key_set();
            let current_version = key_set.current_version;

            // Fetch all TOTP records on old key versions
            let rows: Vec<(uuid::Uuid, Vec<u8>, Vec<u8>, i16)> = sqlx::query_as(
                "SELECT id, encrypted_secret, nonce, key_version FROM user_totp WHERE key_version != $1",
            )
            .bind(current_version)
            .fetch_all(pool.as_ref())
            .await?;

            let total = rows.len();
            let mut reencrypted = 0u64;

            for (id, ciphertext, nonce, old_version) in &rows {
                // Decrypt with fallback
                let plaintext = key_set.decrypt(ciphertext, nonce, *old_version)?;
                // Re-encrypt with current key
                let (new_ct, new_nonce, new_version) = key_set.encrypt(&plaintext)?;
                // Update the row
                TotpRepository::update_encryption(&pool, *id, &new_ct, &new_nonce, new_version)
                    .await?;
                reencrypted += 1;
            }

            // Audit log
            let audit_log = CreateAuditLog::new(AuditAction::AdminKeyRotation)
                .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
                .with_metadata(serde_json::json!({
                    "key_id": "totp",
                    "reencrypted": reencrypted,
                    "total": total,
                    "new_version": current_version,
                }));
            AuditLogRepository::create(&pool, audit_log).await?;

            Ok(success(
                serde_json::json!({
                    "key_id": "totp",
                    "reencrypted": reencrypted,
                    "total": total,
                    "key_version": current_version,
                }),
                request_id,
            ))
        }
        "stripe" => {
            let current_version = stripe_key_set.current_version;
            let db = StripeConfigRepository::get(&pool).await?;

            if db.key_version == current_version {
                return Ok(success(
                    serde_json::json!({
                        "key_id": "stripe",
                        "reencrypted": 0,
                        "total": 0,
                        "key_version": current_version,
                    }),
                    request_id,
                ));
            }

            // Decrypt existing secrets with fallback, re-encrypt with current key
            let new_sk = match (&db.secret_key, &db.secret_key_nonce) {
                (Some(ct), Some(nonce)) => {
                    let plain = stripe_key_set.decrypt(ct, nonce, db.key_version)?;
                    let (new_ct, new_nonce, _) = stripe_key_set.encrypt(&plain)?;
                    Some((new_ct, new_nonce))
                }
                _ => None,
            };
            let new_wh = match (&db.webhook_secret, &db.webhook_secret_nonce) {
                (Some(ct), Some(nonce)) => {
                    let plain = stripe_key_set.decrypt(ct, nonce, db.key_version)?;
                    let (new_ct, new_nonce, _) = stripe_key_set.encrypt(&plain)?;
                    Some((new_ct, new_nonce))
                }
                _ => None,
            };

            StripeConfigRepository::update_encryption(
                &pool,
                new_sk.as_ref().map(|(ct, _)| ct.clone()),
                new_sk.as_ref().map(|(_, n)| n.clone()),
                new_wh.as_ref().map(|(ct, _)| ct.clone()),
                new_wh.as_ref().map(|(_, n)| n.clone()),
                current_version,
            )
            .await?;

            // Audit log
            let audit_log = CreateAuditLog::new(AuditAction::AdminKeyRotation)
                .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
                .with_metadata(serde_json::json!({
                    "key_id": "stripe",
                    "reencrypted": 1,
                    "new_version": current_version,
                }));
            AuditLogRepository::create(&pool, audit_log).await?;

            Ok(success(
                serde_json::json!({
                    "key_id": "stripe",
                    "reencrypted": 1,
                    "total": 1,
                    "key_version": current_version,
                }),
                request_id,
            ))
        }
        _ => Err(AppError::not_found(format!("Unknown key: {key_id}"))),
    }
}

// ── Lifecycle event dispatch ──────────────────────────────────────────────────

/// Fire-and-forget helper: POST a lifecycle-event token to every registered
/// `lifecycle_event_uri` for the given `user_id`.  Called via `tokio::spawn`.
pub(crate) async fn dispatch_lifecycle_event(
    provider: Arc<bunyip_oidc::services::oidc_provider::OidcProvider>,
    user_id: uuid::Uuid,
    event_type: &'static str,
) {
    let targets = match provider.lifecycle_event_targets().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "lifecycle_event_targets query failed");
            return;
        }
    };

    if targets.is_empty() {
        return;
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    for (client_id, uri) in targets {
        match provider.mint_lifecycle_token(user_id, event_type, client_id) {
            Ok(token) => {
                if let Err(e) = http
                    .post(&uri)
                    .form(&[("lifecycle_event", &token)])
                    .send()
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        client_id = %client_id,
                        event_type,
                        "lifecycle event POST failed"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    client_id = %client_id,
                    "Failed to mint lifecycle token"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
    }

    #[actix_rt::test]
    async fn admin_update_invalidates_manifest_cache_on_pin_change() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let slug = format!("oci-upd-{}", uuid::Uuid::new_v4());
        sqlx::query(
            r#"
            INSERT INTO applications
            (name, slug, display_name, container_name,
             oci_image_owner, oci_image_name, pinned_image_tag)
            VALUES ($1, $1, $1, $1, 'a8n', 'rus', 'v1.0.0')
        "#,
        )
        .bind(&slug)
        .execute(&pool)
        .await
        .unwrap();

        let app_row: (uuid::Uuid,) = sqlx::query_as("SELECT id FROM applications WHERE slug = $1")
            .bind(&slug)
            .fetch_one(&pool)
            .await
            .unwrap();
        let app_id = app_row.0;

        let mc = Arc::new(ManifestCache::new(60));
        mc.insert(
            app_id,
            "v1.0.0",
            bunyip_oci::models::oci::CachedManifest {
                bytes: bytes::Bytes::from_static(b"{}"),
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                digest: "sha256:abc".into(),
            },
        )
        .await;
        assert!(mc.get(app_id, "v1.0.0").await.is_some());

        let update = UpdateApplication {
            display_name: None,
            description: None,
            icon_url: None,
            source_code_url: None,
            version: None,
            subdomain: None,
            container_name: None,
            health_check_url: None,
            is_active: None,
            maintenance_mode: None,
            maintenance_message: None,
            webhook_url: None,
            forgejo_owner: None,
            forgejo_repo: None,
            pinned_release_tag: None,
            artifact_source: None,
            forgejo_package: None,
            oci_image_owner: None,
            oci_image_name: None,
            pinned_image_tag: Some("v2.0.0".into()),
        };
        let _updated = crate::repositories::ApplicationRepository::update(&pool, app_id, &update)
            .await
            .unwrap();

        // Simulate the handler's invalidation path (we're not going through HTTP).
        mc.invalidate_app(app_id).await;
        assert!(mc.get(app_id, "v1.0.0").await.is_none());

        sqlx::query("DELETE FROM applications WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod key_health_tests {
    use super::*;
    use crate::services::encryption::EncryptionKeySet;

    fn test_key() -> [u8; 32] {
        [0xAA; 32]
    }

    fn test_key_set() -> EncryptionKeySet {
        EncryptionKeySet {
            current: test_key(),
            current_version: 1,
            previous: None,
        }
    }

    // ---- evaluate_key_health ----

    #[test]
    fn healthy_when_decrypt_succeeds() {
        let key = test_key();
        let ks = test_key_set();
        let (ct, nonce, _) = ks.encrypt(b"test-secret").unwrap();

        let result = evaluate_key_health(&key, Some(&ct), Some(&nonce), Some(1), 1);

        assert_eq!(result.status, "healthy");
        assert!(result.has_data);
        assert_eq!(result.key_version, Some(1));
        assert_eq!(result.needs_reencrypt, Some(false));
        assert!(result.message.is_none());
    }

    #[test]
    fn unhealthy_when_wrong_key() {
        let wrong_key = [0xBB; 32];
        let ks = test_key_set();
        let (ct, nonce, _) = ks.encrypt(b"test-secret").unwrap();

        let result = evaluate_key_health(&wrong_key, Some(&ct), Some(&nonce), Some(1), 1);

        assert_eq!(result.status, "unhealthy");
        assert!(result.has_data);
        assert!(result.message.is_some());
    }

    #[test]
    fn unhealthy_when_tampered_ciphertext() {
        let key = test_key();
        let ks = test_key_set();
        let (mut ct, nonce, _) = ks.encrypt(b"test-secret").unwrap();
        ct[0] ^= 0xFF;

        let result = evaluate_key_health(&key, Some(&ct), Some(&nonce), Some(1), 1);

        assert_eq!(result.status, "unhealthy");
        assert!(result.has_data);
        assert!(result.message.is_some());
    }

    #[test]
    fn no_data_when_both_none() {
        let key = test_key();

        let result = evaluate_key_health(&key, None, None, None, 1);

        assert_eq!(result.status, "no_data");
        assert!(!result.has_data);
        assert!(result.key_version.is_none());
        assert!(result.needs_reencrypt.is_none());
        assert!(result.message.is_none());
    }

    #[test]
    fn no_data_when_ciphertext_without_nonce() {
        let key = test_key();
        let ks = test_key_set();
        let (ct, _nonce, _) = ks.encrypt(b"test-secret").unwrap();

        let result = evaluate_key_health(&key, Some(&ct), None, Some(1), 1);

        assert_eq!(result.status, "no_data");
        assert!(!result.has_data);
    }

    #[test]
    fn no_data_when_nonce_without_ciphertext() {
        let key = test_key();
        let ks = test_key_set();
        let (_ct, nonce, _) = ks.encrypt(b"test-secret").unwrap();

        let result = evaluate_key_health(&key, None, Some(&nonce), Some(1), 1);

        assert_eq!(result.status, "no_data");
        assert!(!result.has_data);
    }

    #[test]
    fn needs_reencrypt_when_version_mismatch() {
        let key = test_key();
        let ks = test_key_set();
        let (ct, nonce, _) = ks.encrypt(b"test-secret").unwrap();

        // Record is version 1, current version is 2
        let result = evaluate_key_health(&key, Some(&ct), Some(&nonce), Some(1), 2);

        assert_eq!(result.status, "healthy");
        assert_eq!(result.needs_reencrypt, Some(true));
    }

    // ---- KEY_IDS registry ----

    #[test]
    fn key_ids_contains_stripe_and_totp() {
        assert!(KEY_IDS.contains(&"stripe"));
        assert!(KEY_IDS.contains(&"totp"));
    }

    // ---- KeyHealthCheck serialization ----

    #[test]
    fn serialization_omits_message_when_none() {
        let check = KeyHealthCheck {
            status: "healthy".to_string(),
            has_data: true,
            key_version: Some(1),
            needs_reencrypt: Some(false),
            message: None,
        };
        let json = serde_json::to_value(&check).unwrap();

        assert_eq!(json["status"], "healthy");
        assert_eq!(json["has_data"], true);
        assert_eq!(json["key_version"], 1);
        assert!(json.get("message").is_none());
    }

    #[test]
    fn serialization_includes_message_when_present() {
        let check = KeyHealthCheck {
            status: "unhealthy".to_string(),
            has_data: true,
            key_version: Some(1),
            needs_reencrypt: Some(false),
            message: Some("Decryption failed".to_string()),
        };
        let json = serde_json::to_value(&check).unwrap();

        assert_eq!(json["status"], "unhealthy");
        assert_eq!(json["has_data"], true);
        assert_eq!(json["message"], "Decryption failed");
    }
}
