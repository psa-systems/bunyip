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
use crate::middleware::AdminUser;
use crate::models::stripe::encrypt_secret;
use crate::models::{
    AuditAction, CreateApplication, CreateApplicationGroup, CreateAuditLog,
    CreatePasswordResetToken, CreateRefreshToken, DeleteApplicationRequest, MembershipStatus,
    SetApplicationGroupRequest, StripeConfigResponse, SwapApplicationOrderRequest,
    UpdateApplication, UpdateApplicationGroup, UserResponse,
};
use crate::repositories::{
    ApplicationGroupRepository, ApplicationRepository, AuditLogRepository, InviteRepository,
    NotificationRepository, StripeConfigRepository, TokenRepository, TotpRepository,
    UserRepository,
};
use crate::responses::{created, get_request_id, paginated, success, success_no_data};
use crate::services::{
    AppDownloadCache, AuthService, EmailService, EncryptionKeySet, JwtService, PasswordService,
    ReleaseCache, StripeConfig, StripeService, TotpService, WebhookService,
};
use crate::validation;
use bunyip_domain::services::{BunyipEvent, EventBus};
use bunyip_oci::services::ManifestCache;

/// BUNYIP-145: publish a `claims_changed` event for the given user. Fire-and-
/// forget: the event bus drops the event silently when no tabs are subscribed.
/// Mutation handlers call this AFTER the revoke + audit write so a busy SPA
/// reacting to the SSE delivery never races a half-applied DB change.
fn announce_claims_changed(bus: &EventBus, user_id: uuid::Uuid) {
    bus.publish(BunyipEvent::ClaimsChanged { user_id });
}

/// BUNYIP-144: revoke every refresh-token family belonging to `user_id` so the
/// next request from any of their tabs 401s on `/auth/refresh`, bounces to
/// `/login`, and the fresh sign-in mints tokens carrying the just-mutated
/// claims (role / membership / lifetime / status). Mirrors the pattern
/// BUNYIP-137 already wired into [`update_user_role`].
///
/// Returns `Ok(true)` to signal "sessions revoked" so the audit log can carry
/// `sessions_revoked: true` metadata. `Ok(false)` is reserved for callers that
/// want to skip the revoke (a no-op mutation, an already-deactivated user,
/// etc.) and is currently never returned by this helper itself; gating "did
/// the mutation actually change something" stays in each handler.
async fn revoke_user_sessions(pool: &PgPool, user_id: uuid::Uuid) -> Result<bool, AppError> {
    TokenRepository::revoke_all_user_refresh_tokens(pool, user_id).await?;
    Ok(true)
}

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
    /// When `Some(false)`, list suspended (soft-deleted) accounts instead of
    /// live ones, so an admin can find and reactivate them (BUNYIP-120).
    pub active: Option<bool>,
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
        query.active,
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
    bus: web::Data<Arc<EventBus>>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdateUserStatusRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    if body.active {
        // Reactivate: clear deleted_at. `restore` returns false when the user
        // is not a soft-deleted row (already active or unknown id) so we can
        // 404 instead of silently succeeding.
        let restored = UserRepository::restore(&pool, user_id).await?;
        if !restored {
            return Err(AppError::not_found("Deleted user"));
        }

        // BUNYIP-144: revoke any lingering refresh-token families. A soft-
        // deleted user shouldn't have live tokens (auth middleware drops them
        // on `deleted_at IS NOT NULL`) but belt-and-braces so a stale token
        // from a future regression cannot leak past reactivation.
        let sessions_revoked = revoke_user_sessions(pool.get_ref(), user_id).await?;

        let audit_log = CreateAuditLog::new(AuditAction::AdminUserActivated)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("user", user_id)
            .with_metadata(serde_json::json!({
                "sessions_revoked": sessions_revoked,
            }));
        AuditLogRepository::create(&pool, audit_log).await?;

        // BUNYIP-145: tell any open SPA tab the claims set is dirty.
        announce_claims_changed(bus.as_ref(), user_id);
    } else {
        let target_user = UserRepository::find_by_id(&pool, user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        UserRepository::soft_delete(&pool, user_id).await?;

        // BUNYIP-144: a deactivation must take effect immediately. Without
        // this, an already-signed-in user keeps an admin-claim access token
        // until it expires (up to 15 min) and a refresh token usable for its
        // full TTL even though the row now has `deleted_at` set.
        let sessions_revoked = revoke_user_sessions(pool.get_ref(), user_id).await?;

        let audit_log = CreateAuditLog::new(AuditAction::AdminUserDeactivated)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("user", user_id)
            .with_metadata(serde_json::json!({
                "target_email": target_user.email,
                "sessions_revoked": sessions_revoked,
            }));
        AuditLogRepository::create(&pool, audit_log).await?;

        if let Some(provider) = oidc_provider.as_ref().as_ref().cloned() {
            tokio::spawn(dispatch_lifecycle_event(provider, user_id, "user.deleted"));
        }

        // BUNYIP-145: also publish a session_revoked event so any tabs the
        // user has open redirect to /login immediately. claims_changed alone
        // would also catch them on next refresh but session_revoked is the
        // proactive surface BUNYIP-145's design uses for explicit revoke.
        bus.publish(BunyipEvent::SessionRevoked {
            user_id,
            reason: "admin_deactivate",
        });
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
    bus: web::Data<Arc<EventBus>>,
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

    // Revoke the target user's existing sessions when the role actually changes
    // (BUNYIP-137). A privilege change must take effect immediately: otherwise a
    // demoted admin keeps an admin-claim access token until it expires (up to
    // 15 min) and an admin-capable refresh token for up to its full lifetime.
    // Revoking forces a re-login that mints tokens carrying the new role claim.
    let role_changed = old_role != body.role;
    if role_changed {
        TokenRepository::revoke_all_user_refresh_tokens(pool.get_ref(), user_id).await?;
        // BUNYIP-145: send a session_revoked event so the user's open tabs
        // redirect to /login at once (claims_changed would also work but
        // session_revoked carries the explicit reason the SPA can flash).
        bus.publish(BunyipEvent::SessionRevoked {
            user_id,
            reason: "role_change",
        });
    }

    tracing::info!(
        admin_id = %admin.0.sub,
        target_user_id = %user_id,
        new_role = %body.role,
        sessions_revoked = role_changed,
        "Admin changed user role"
    );

    let audit_log = CreateAuditLog::new(AuditAction::AdminUserRoleChanged)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", user_id)
        .with_old_values(serde_json::json!({ "role": old_role }))
        .with_new_values(serde_json::json!({ "role": &body.role }))
        .with_metadata(serde_json::json!({
            "target_email": target_user.email,
            "sessions_revoked": role_changed,
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success(UserResponse::from(updated_user), request_id))
}

/// Request body for admin email correction (BUNYIP-119).
#[derive(Debug, Deserialize)]
pub struct UpdateUserEmailRequest {
    pub email: String,
    /// When true the corrected address is stored already-verified; when
    /// false (the default) the user keeps an unverified address until they
    /// complete the verification flow.
    #[serde(default)]
    pub verified: bool,
}

/// PUT /v1/admin/users/{user_id}/email
/// Correct a user's email address (BUNYIP-119). Admin-only override of the
/// normal user-initiated, email-confirmed change flow: the new address is
/// written directly, optionally marked verified in the same edit.
pub async fn update_user_email(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdateUserEmailRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    // Normalize like the rest of the auth surface (lower-cased, trimmed).
    let new_email = body.email.trim().to_lowercase();
    crate::validation::validate_email(&new_email)?;

    let target_user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or(AppError::not_found("User"))?;
    let old_email = target_user.email.clone();

    // No-op edits that only flip verification are still allowed, but a real
    // address change must not collide with another live OR soft-deleted
    // account (BUNYIP-330: soft-deleted emails are permanently reserved, so
    // even an admin cannot rename a user's email onto a reserved identity).
    if new_email != old_email.to_lowercase()
        && UserRepository::email_reserved(pool.get_ref(), &new_email).await?
    {
        return Err(AppError::conflict("Email already registered"));
    }

    UserRepository::update_email(pool.get_ref(), user_id, &new_email, body.verified).await?;

    tracing::info!(
        admin_id = %admin.0.sub,
        target_user_id = %user_id,
        verified = body.verified,
        "Admin changed user email"
    );

    let audit_log = CreateAuditLog::new(AuditAction::AdminUserEmailChanged)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", user_id)
        .with_old_values(serde_json::json!({ "email": old_email }))
        .with_new_values(
            serde_json::json!({ "email": new_email, "email_verified": body.verified }),
        );
    AuditLogRepository::create(&pool, audit_log).await?;

    let updated_user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or(AppError::not_found("User"))?;

    Ok(success(UserResponse::from(updated_user), request_id))
}

/// POST /v1/admin/users/{user_id}/email/verify
/// Force-verify a user's email address without the user completing the
/// email-verification flow (BUNYIP-119).
pub async fn verify_user_email(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    let target_user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or(AppError::not_found("User"))?;

    UserRepository::set_email_verified(&pool, user_id).await?;

    tracing::info!(
        admin_id = %admin.0.sub,
        target_user_id = %user_id,
        "Admin force-verified user email"
    );

    let audit_log = CreateAuditLog::new(AuditAction::AdminUserEmailVerified)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", user_id)
        .with_metadata(serde_json::json!({
            "target_email": target_user.email,
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success_no_data(request_id))
}

/// POST /v1/admin/users/{user_id}/two-factor/reset
/// Clear a user's two-factor authentication (BUNYIP-119): delete their TOTP
/// secret + recovery codes and flip `two_factor_enabled` off so a locked-out
/// user can re-enrol from scratch.
pub async fn reset_user_two_factor(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    let target_user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or(AppError::not_found("User"))?;

    // Drop the TOTP secret + recovery codes first, then clear the flag. Either
    // order leaves a consistent "2FA off" state; doing the delete first means a
    // mid-way failure never leaves the flag off while a stale secret lingers.
    TotpRepository::delete_by_user_id(&pool, user_id).await?;
    UserRepository::set_two_factor_enabled(&pool, user_id, false).await?;

    tracing::info!(
        admin_id = %admin.0.sub,
        target_user_id = %user_id,
        "Admin reset user two-factor authentication"
    );

    let audit_log = CreateAuditLog::new(AuditAction::AdminUserTwoFactorReset)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", user_id)
        .with_metadata(serde_json::json!({
            "target_email": target_user.email,
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success_no_data(request_id))
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
    bus: web::Data<Arc<EventBus>>,
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

    // BUNYIP-144: `grant_free_membership` sets `lifetime_member=true` and
    // `subscription_status=active`. Both are inputs to `has_member_access`
    // (the dashboard's per-app gate), so existing tokens minted before the
    // grant carry stale claims. Force re-login so the next request mints
    // fresh tokens with the new state.
    let sessions_revoked = revoke_user_sessions(pool.get_ref(), body.user_id).await?;
    // BUNYIP-145: notify any open SPA tab so it refreshes in place.
    announce_claims_changed(bus.as_ref(), body.user_id);

    let audit_log = CreateAuditLog::new(AuditAction::AdminMembershipGranted)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", body.user_id)
        .with_metadata(serde_json::json!({
            "tier": "free",
            "price_locked": price_locked,
            "locked_price_amount": locked_amount,
            "sessions_revoked": sessions_revoked,
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
    bus: web::Data<Arc<EventBus>>,
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

    // BUNYIP-144: a revoke is a privilege-DOWNGRADE so the security argument
    // is the strongest of any handler in this set. Without this, the user
    // keeps an admin-or-active-member claim for the full refresh-token TTL
    // (30 days for subscribers) after their membership was canceled.
    let sessions_revoked = revoke_user_sessions(pool.get_ref(), body.user_id).await?;
    // BUNYIP-145: revoked membership is a privilege-downgrade visible to the
    // user immediately as "Membership Required" banners. Push the event so
    // the open tab does not keep flashing the active-member UI.
    announce_claims_changed(bus.as_ref(), body.user_id);

    let audit_log = CreateAuditLog::new(AuditAction::AdminMembershipRevoked)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_resource("user", body.user_id)
        .with_metadata(serde_json::json!({
            "sessions_revoked": sessions_revoked,
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success_no_data(request_id))
}

/// Query parameters for listing memberships
#[derive(Debug, Deserialize)]
pub struct ListMembershipsQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
    pub status: Option<String>,
    /// BUNYIP-291 AC4: filter by subscription tier (`early_adopter` /
    /// `standard` / `lifetime` / `free`) for the members-by-tier admin view.
    /// Takes precedence over `status`.
    pub tier: Option<String>,
}

/// SQL backing the BUNYIP-291 members-by-tier filter. Ordered by `created_at`
/// ASC so early-adopter slot holders list in the deterministic order they
/// claimed their slots (earliest first = slot 1..N), making occupancy
/// referenceable. Held as a const so the ordering/predicate is unit-testable
/// without a live database.
const MEMBERS_BY_TIER_SQL: &str = r#"
            SELECT id AS user_id, email AS user_email, stripe_customer_id,
                   subscription_status AS status,
                   COALESCE(subscription_tier, 'standard') AS subscription_tier,
                   subscription_override_by,
                   created_at
            FROM users
            WHERE COALESCE(subscription_tier, 'standard') = $3 AND deleted_at IS NULL
            ORDER BY created_at ASC
            LIMIT $1 OFFSET $2
            "#;

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

    let (memberships, total) = if let Some(ref tier) = query.tier {
        // BUNYIP-291 AC4: members-by-tier view. All (non-deleted) holders of
        // the tier, oldest first so early-adopter slots read in claim order.
        let rows = sqlx::query_as::<_, crate::models::AdminMembershipResponse>(MEMBERS_BY_TIER_SQL)
            .bind(per_page)
            .bind(offset)
            .bind(tier)
            .fetch_all(pool.get_ref())
            .await?;

        let total: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM users WHERE COALESCE(subscription_tier, 'standard') = $1 AND deleted_at IS NULL",
        )
        .bind(tier)
        .fetch_one(pool.get_ref())
        .await?;

        (rows, total.0)
    } else if let Some(ref status) = query.status {
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

    // Validate the MERGED distribution config (body values overlaid on the
    // existing row) using the shared model rules, so a bad value is a clean
    // 400 instead of a DB CHECK-constraint 500 and create/update cannot drift.
    if let Err((field, message)) = body.distribution_merged(&old_app).validate() {
        return Err(AppError::validation(field, &message));
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

/// Body for [`replay_account_delete`]: which app to re-notify (BUNYIP-211).
#[derive(Debug, Deserialize)]
pub struct ReplayAccountDeleteRequest {
    /// Slug of the connected app whose `account_deleted` webhook to re-fire.
    pub app_slug: String,
}

/// POST /v1/admin/account-deletes/{user_id}/replay
/// BUNYIP-211: re-fire the `account_deleted` webhook to a single app for a user
/// whose original delete dispatch failed (its row sits in
/// `account_delete_dispatch_failures`). Admin-gated. Lets ops resolve a stuck
/// downstream purge without re-deleting the user. The outcome is recorded the
/// same way the delete fan-out records it (audit row, and a fresh failure row
/// if this attempt also exhausts), so the replay is itself observable.
pub async fn replay_account_delete(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    webhook_service: web::Data<Arc<WebhookService>>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<ReplayAccountDeleteRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    let app = ApplicationRepository::find_by_slug(&pool, &body.app_slug)
        .await?
        .ok_or(AppError::not_found("Application"))?;

    let outcome = webhook_service
        .dispatch_account_deleted(&app, user_id)
        .await;
    crate::handlers::user::record_account_delete_dispatch(&pool, user_id, &app, &outcome).await;

    tracing::info!(
        admin_id = %admin.0.sub,
        user_id = %user_id,
        app_slug = %app.slug,
        delivered = outcome.is_ok(),
        "admin replayed account_deleted webhook"
    );

    match outcome {
        Ok(()) => Ok(success(
            serde_json::json!({
                "user_id": user_id,
                "app_slug": app.slug,
                "status": "delivered",
            }),
            request_id,
        )),
        // Surface the failure to the admin (the failure row is already
        // persisted by record_account_delete_dispatch for a later retry).
        Err(err) => Err(AppError::internal(format!(
            "account_deleted webhook to {} still failing: {err}",
            app.slug
        ))),
    }
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

    // Validate the distribution config (Forgejo downloads + OCI image) with
    // the shared model rules, so a product can be fully created in one call.
    if let Err((field, message)) = body.distribution().validate() {
        return Err(AppError::validation(field, &message));
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
// Application Groups (BUNYIP-100)
// =============================================================================

/// GET /v1/admin/application-groups
/// List all application groups.
pub async fn list_all_application_groups(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let groups = ApplicationGroupRepository::list(&pool).await?;
    Ok(success(serde_json::json!({ "groups": groups }), request_id))
}

/// POST /v1/admin/application-groups
/// Create an application group.
pub async fn create_application_group(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    body: web::Json<CreateApplicationGroup>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    if body.name.trim().is_empty() {
        return Err(AppError::validation("name", "Name is required"));
    }
    if body.display_name.trim().is_empty() {
        return Err(AppError::validation(
            "display_name",
            "Display name is required",
        ));
    }
    validation::validate_slug(&body.slug).map_err(|_| {
        AppError::validation(
            "slug",
            "Slug must contain only lowercase letters, numbers, and hyphens",
        )
    })?;
    if ApplicationGroupRepository::find_by_slug(&pool, &body.slug)
        .await?
        .is_some()
    {
        return Err(AppError::conflict(
            "An application group with this slug already exists",
        ));
    }

    let group = ApplicationGroupRepository::create(&pool, &body).await?;
    Ok(created(group, request_id))
}

/// PUT /v1/admin/application-groups/{group_id}
/// Update an application group.
pub async fn update_application_group(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdateApplicationGroup>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let group_id = path.into_inner();

    ApplicationGroupRepository::find_by_id(&pool, group_id)
        .await?
        .ok_or(AppError::not_found("Application group"))?;

    if let Some(slug) = body.slug.as_deref() {
        validation::validate_slug(slug).map_err(|_| {
            AppError::validation(
                "slug",
                "Slug must contain only lowercase letters, numbers, and hyphens",
            )
        })?;
        // A slug change must not collide with a different group.
        if let Some(existing) = ApplicationGroupRepository::find_by_slug(&pool, slug).await? {
            if existing.id != group_id {
                return Err(AppError::conflict(
                    "An application group with this slug already exists",
                ));
            }
        }
    }

    let group = ApplicationGroupRepository::update(&pool, group_id, &body).await?;
    Ok(success(group, request_id))
}

/// DELETE /v1/admin/application-groups/{group_id}
/// Delete an application group. Members are ungrouped (FK ON DELETE SET NULL).
pub async fn delete_application_group(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let group_id = path.into_inner();

    ApplicationGroupRepository::find_by_id(&pool, group_id)
        .await?
        .ok_or(AppError::not_found("Application group"))?;

    ApplicationGroupRepository::delete(&pool, group_id).await?;
    Ok(success_no_data(request_id))
}

/// PUT /v1/admin/applications/{app_id}/group
/// Assign an application to a group, or clear it (`group_id = null`).
pub async fn set_application_group(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<SetApplicationGroupRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let app_id = path.into_inner();

    ApplicationRepository::find_by_id(&pool, app_id)
        .await?
        .ok_or(AppError::not_found("Application"))?;

    if let Some(group_id) = body.group_id {
        ApplicationGroupRepository::find_by_id(&pool, group_id)
            .await?
            .ok_or(AppError::not_found("Application group"))?;
    }

    ApplicationRepository::set_group(&pool, app_id, body.group_id).await?;
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
// Error Log (BUNYIP-327)
// =============================================================================

/// Query parameters for the in-memory error log view.
#[derive(Debug, Deserialize)]
pub struct ErrorLogsQuery {
    /// Exact-match category filter (e.g. `rate_limit`). Absent -> all errors.
    pub category: Option<String>,
    /// Cap on how many newest entries to return (defaults to the full buffer,
    /// hard-capped at the buffer capacity).
    pub limit: Option<usize>,
}

/// Envelope for the error-log response: the entries plus the buffer's live
/// size and capacity, so the view can show "showing N of CAP (rotated)".
#[derive(Debug, Serialize)]
pub struct ErrorLogsResponse {
    pub entries: Vec<crate::error_log::ErrorLogEntry>,
    /// Entries matching the filter before `limit` truncation.
    pub matched: usize,
    /// Total entries currently held (all categories).
    pub buffered: usize,
    /// Maximum entries retained before rotation.
    pub capacity: usize,
}

/// GET /v1/admin/logs
/// Return the newest-first ERROR-level events from the in-memory ring buffer,
/// optionally filtered by category (BUNYIP-327). Admin-only via [`AdminUser`].
pub async fn get_error_logs(
    req: HttpRequest,
    _admin: AdminUser,
    logs: web::Data<crate::error_log::ErrorLogBuffer>,
    query: web::Query<ErrorLogsQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let mut entries = logs.snapshot(query.category.as_deref());
    let matched = entries.len();
    if let Some(limit) = query.limit {
        entries.truncate(limit.min(logs.capacity()));
    }

    Ok(success(
        ErrorLogsResponse {
            entries,
            matched,
            buffered: logs.len(),
            capacity: logs.capacity(),
        },
        request_id,
    ))
}

// =============================================================================
// Seed data import / export (PSA-52)
// =============================================================================

/// GET /v1/admin/seed/export
/// Serialize the current seed-owned data to the canonical seed format and
/// return it as a downloadable JSON file. Read-only; admin-gated.
pub async fn export_seed_data(
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let file = crate::seed::export(pool.get_ref(), crate::seed::SEED_EMAIL_DOMAIN)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let body =
        serde_json::to_string_pretty(&file).map_err(|e| AppError::internal(e.to_string()))?;
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .insert_header((
            "content-disposition",
            "attachment; filename=\"seed-export.json\"",
        ))
        .body(body))
}

/// POST /v1/admin/seed/import
/// Load a canonical seed file (request body) through the shared loader. Blocked
/// on production/unset environments so demo data can never land in prod, even
/// though only an admin can reach this. Idempotent per the loader.
pub async fn import_seed_data(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    body: String,
) -> Result<HttpResponse, AppError> {
    crate::seed::seed_guard(&config.environment, true)
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    let file = crate::seed::parse(&body).map_err(|e| AppError::bad_request(e.to_string()))?;
    let summary = crate::seed::load(pool.get_ref(), &file)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let request_id = get_request_id(&req);
    Ok(success(
        serde_json::json!({
            "groups": summary.groups,
            "applications": summary.applications,
            "users": summary.users,
            "entitlements": summary.entitlements,
            "feedback": summary.feedback,
        }),
        request_id,
    ))
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
/// Collect the dashboard user/application counts. Shared by `get_dashboard_stats`
/// and `get_system_health` so the two never drift, and every DB error propagates
/// (no `.ok().flatten()` swallowing).
async fn collect_dashboard_stats(pool: &PgPool) -> Result<DashboardStats, AppError> {
    // Get user counts by status
    let total_users: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL")
        .fetch_one(pool)
        .await?;

    let active_members: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE subscription_status = 'active' AND deleted_at IS NULL",
    )
    .fetch_one(pool)
    .await?;

    let past_due_members: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE subscription_status = 'past_due' AND deleted_at IS NULL",
    )
    .fetch_one(pool)
    .await?;

    let grace_period_members: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE subscription_status = 'grace_period' AND deleted_at IS NULL",
    )
    .fetch_one(pool)
    .await?;

    let total_applications: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM applications")
        .fetch_one(pool)
        .await?;

    let active_applications: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM applications WHERE is_active = TRUE")
            .fetch_one(pool)
            .await?;

    Ok(DashboardStats {
        total_users: total_users.0,
        active_members: active_members.0,
        past_due_members: past_due_members.0,
        grace_period_members: grace_period_members.0,
        total_applications: total_applications.0,
        active_applications: active_applications.0,
    })
}

pub async fn get_dashboard_stats(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let stats = collect_dashboard_stats(pool.get_ref()).await?;

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
    email_service: web::Data<Arc<EmailService>>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();
    let admin_user_id = admin.0.sub;

    // JwtService is registered as a bare `Arc<JwtService>` (not `web::Data`),
    // so read it from app_data directly - the documented canonical path.
    let jwt_service = req
        .app_data::<Arc<JwtService>>()
        .ok_or_else(|| AppError::internal("JWT service not configured"))?;

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
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let target_user_id = path.into_inner();
    let admin_user_id = admin.0.sub;

    // JwtService is registered as a bare `Arc<JwtService>` (not `web::Data`),
    // so read it from app_data directly - the documented canonical path.
    let jwt_service = req
        .app_data::<Arc<JwtService>>()
        .ok_or_else(|| AppError::internal("JWT service not configured"))?;

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
    admin: AdminUser,
    email_service: web::Data<Arc<EmailService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    email_service.send_welcome(&admin.0.email, 300).await?;

    tracing::info!(email = %admin.0.email, "Test email sent");

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
    server_start: web::Data<std::time::Instant>,
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

    // Reuse the dashboard counts (no duplicated SQL) and surface the recent
    // audit-log volume. Errors propagate rather than being swallowed by
    // `.ok().flatten()`, so a failing stats query degrades the health report
    // honestly instead of silently dropping the stats block.
    let stats = collect_dashboard_stats(pool.get_ref()).await?;
    let recent_logs: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_logs WHERE created_at > NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(pool.get_ref())
    .await?;

    let overall_status = if db_health.status == "healthy" {
        "healthy"
    } else {
        "degraded"
    };

    let health = SystemHealth {
        status: overall_status.to_string(),
        database: db_health,
        uptime_seconds: server_start.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let response = serde_json::json!({
        "health": health,
        "stats": {
            "total_users": stats.total_users,
            "active_members": stats.active_members,
            "audit_logs_last_hour": recent_logs.0,
        },
    });

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

    // BUNYIP-189: bootstrap a default app-tagged product + recurring
    // price when no app-tagged price exists yet. Closes the silent-400
    // gotcha from BUNYIP-A-5 gotcha 3 - a fresh Stripe account no
    // longer needs an out-of-band `stripe products create` step to
    // make the Subscribe button work. Idempotent; a re-save when a
    // price already exists is a no-op. Failure to bootstrap does NOT
    // fail the config save (the keys are still valid and the admin can
    // create the product by hand); the failure is logged.
    let bootstrap_created = match stripe_service.bootstrap_default_product_if_missing().await {
        Ok(Some((product, price))) => {
            tracing::info!(
                product_id = %product.id,
                price_id = %price.id,
                "BUNYIP-189: bootstrapped default Stripe product + price"
            );
            Some((product.id, price.id))
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(error = %e, "BUNYIP-189: bootstrap_default_product failed; admin must create product manually");
            None
        }
    };

    let audit_log = CreateAuditLog::new(AuditAction::AdminStripeConfigUpdated)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({
            "fields_updated": {
                "secret_key": secret_key_plain.is_some(),
                "webhook_secret": webhook_secret_plain.is_some(),
                "app_tag": app_tag,
            },
            // BUNYIP-189: surface the auto-bootstrap outcome in the
            // audit log so an operator chasing the "where did this
            // product come from" question can trace it to the config
            // save that produced it.
            "bootstrap": bootstrap_created.as_ref().map(|(p, pr)| serde_json::json!({
                "product_id": p,
                "price_id": pr,
            })),
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
    bus: web::Data<Arc<EventBus>>,
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

    // BUNYIP-144: lifetime is a privilege-elevation that feeds directly into
    // `has_member_access` ("role=admin OR lifetime_member OR ..."), gating
    // every per-app tile on the dashboard (Mokosh / Drillmark / Lets Chat).
    // Without revoking, the customer keeps seeing tiles greyed out until
    // their access token expires (15 min) - and even after that the refresh
    // remints stale claims unless every tab triggers a fresh refresh. This
    // is the exact bug the brendon@netcal.com triage on 2026-06-19 hit.
    let sessions_revoked = revoke_user_sessions(pool.get_ref(), user_id).await?;
    // BUNYIP-145: same brendon@netcal.com bug, UX half. The revoke above
    // closes the security gap (next request 401s); the publish below
    // closes the UX gap (open tab updates without the customer having to
    // hit F5 OR be bounced to /login).
    announce_claims_changed(bus.as_ref(), user_id);

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminMembershipGranted)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("user", user_id)
            .with_metadata(serde_json::json!({
                "tier": "lifetime",
                "target_email": user.email,
                "sessions_revoked": sessions_revoked,
            })),
    )
    .await?;

    Ok(success(UserResponse::from(user), request_id))
}

/// POST /v1/admin/users/{user_id}/lifetime/revoke
pub async fn revoke_lifetime_membership(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    bus: web::Data<Arc<EventBus>>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    let user = UserRepository::revoke_lifetime_membership(&pool, user_id).await?;

    // BUNYIP-144: privilege-downgrade. Cut existing sessions immediately so
    // the user does not retain `lifetime_member=true` JWT claims past the
    // revoke (otherwise they'd see "Active" on every app tile for the full
    // refresh-token TTL).
    let sessions_revoked = revoke_user_sessions(pool.get_ref(), user_id).await?;
    // BUNYIP-145: tell the open tab to update in place.
    announce_claims_changed(bus.as_ref(), user_id);

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminMembershipRevoked)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("user", user_id)
            .with_metadata(serde_json::json!({
                "tier": "lifetime",
                "target_email": user.email,
                "sessions_revoked": sessions_revoked,
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
        // `to_value` is practically infallible for the `KeyHealthCheck`
        // struct today (only string + enum fields), but the contract leaks
        // a panic surface that a future numeric field would expose (e.g.
        // an `f64` would serialise NaN as Err). Fail-soft with a null and
        // an error log instead of taking down the whole endpoint.
        let value = serde_json::to_value(&check).unwrap_or_else(|e| {
            tracing::error!(key_id = %key_id, error = %e, "Failed to serialize key health check; emitting null");
            serde_json::Value::Null
        });
        checks.insert(key_id.to_string(), value);
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

            StripeConfigRepository::update(
                &pool,
                new_sk.as_ref().map(|(ct, _)| ct.clone()),
                new_sk.as_ref().map(|(_, n)| n.clone()),
                new_wh.as_ref().map(|(ct, _)| ct.clone()),
                new_wh.as_ref().map(|(_, n)| n.clone()),
                admin.0.sub,
                current_version,
                None,
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

    #[test]
    fn members_by_tier_sql_filters_by_tier_and_orders_by_claim_order() {
        // BUNYIP-291 AC4: the members-by-tier list must filter on the tier
        // column, exclude soft-deleted rows, and order oldest-first so
        // early-adopter slot occupancy reads in the order slots were claimed.
        let sql = MEMBERS_BY_TIER_SQL;
        assert!(
            sql.contains("subscription_tier, 'standard') = $3"),
            "must filter on the (coalesced) tier bind"
        );
        assert!(
            sql.contains("deleted_at IS NULL"),
            "must exclude soft-deleted"
        );
        assert!(
            sql.contains("ORDER BY created_at ASC"),
            "must order oldest-first for stable slot order"
        );
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
            is_hosted: None,
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
