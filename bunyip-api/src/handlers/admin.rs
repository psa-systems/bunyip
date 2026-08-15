//! Admin handlers
//!
//! This module contains HTTP handlers for admin management endpoints.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use tokio;

use chrono::{Duration, Utc};

use super::{check_rate_limit, live_free_price_id};
use crate::config::{Config, TierConfig};
use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::stripe::encrypt_secret;
use crate::models::{
    AuditAction, CreateApplication, CreateApplicationGroup, CreateAuditLog,
    CreatePasswordResetToken, CreateRefreshToken, DeleteApplicationRequest, MembershipStatus,
    MembershipTier, RateLimitConfig, ReorderApplicationsRequest, SetApplicationGroupRequest,
    StripeConfigResponse, StripePriceResponse, UpdateApplication, UpdateApplicationGroup,
    UserResponse,
};
use crate::repositories::{
    ApplicationGroupRepository, ApplicationRepository, AuditLogRepository, EmailConfigRepository,
    InviteRepository, NotificationRepository, StripeConfigRepository, TierConfigRepository,
    TokenRepository, TotpRepository, UserRepository,
};
use crate::responses::{created, get_request_id, paginated, success, success_no_data};
use crate::services::{
    stripe_err, AppDownloadCache, AppKeySet, AuthService, EmailService, JwtService,
    PasswordService, ReleaseCache, StripeService, TotpService, WebhookService,
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
    /// BUNYIP-410: filter by subscription tier (`early_adopter` / `standard` /
    /// `lifetime` / `free`). Blank / absent = all tiers.
    #[serde(default)]
    pub tier: Option<String>,
    /// BUNYIP-410: filter by email-verified status. Absent = both.
    #[serde(default)]
    pub verified: Option<bool>,
    /// BUNYIP-410 overhaul: whitelisted sort column - `email` / `tier` /
    /// `verified` / `joined`. Absent / unknown = newest-first by join date.
    #[serde(default)]
    pub sort: Option<String>,
    /// Sort direction: `asc` / `desc`. Absent = `desc` (newest first).
    #[serde(default)]
    pub dir: Option<String>,
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

    // BUNYIP-410: tier / verified filters for the consolidated users list. Blank
    // tier is treated as "no filter" so `?tier=` from an "All" selection is a
    // no-op rather than matching nothing.
    let tier_filter = query
        .tier
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    // Default direction is descending (newest-first / Z-A), so an absent `dir`
    // preserves the historical newest-first ordering.
    let sort_desc = query.dir.as_deref() != Some("asc");
    let (users, total) = UserRepository::list_paginated(
        &pool,
        page,
        per_page,
        query.search.as_deref(),
        status_filter,
        query.active,
        tier_filter,
        query.verified,
        query.sort.as_deref(),
        sort_desc,
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
    tier_config: web::Data<Arc<std::sync::RwLock<TierConfig>>>,
    bus: web::Data<Arc<EventBus>>,
    body: web::Json<GrantMembershipRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Grant free tier — sets lifetime_member=true and membership_status='active'
    let user =
        UserRepository::grant_free_membership(pool.get_ref(), body.user_id, admin.0.sub).await?;

    // Create $0 Stripe subscription for invoice generation (BUNYIP-482: the
    // price id comes from the live tier config, not from env).
    if let Some(free_price_id) = live_free_price_id(&tier_config) {
        let customer_id = match user.stripe_customer_id {
            Some(id) => id,
            None => {
                let id = stripe
                    .create_customer(&user.email, user.id)
                    .await
                    .map_err(stripe_err)?;
                UserRepository::update_stripe_customer_id(pool.get_ref(), user.id, &id).await?;
                id
            }
        };
        stripe
            .create_free_subscription(&customer_id, &free_price_id)
            .await
            .map_err(stripe_err)?;
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
    // `membership_status=active`. Both are inputs to `has_member_access`
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
    UserRepository::reset_membership_tier(pool.get_ref(), body.user_id).await?;

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
                   membership_status AS status,
                   COALESCE(membership_tier, 'standard') AS membership_tier,
                   membership_override_by,
                   created_at
            FROM users
            WHERE COALESCE(membership_tier, 'standard') = $3 AND deleted_at IS NULL
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
            "SELECT COUNT(*) FROM users WHERE COALESCE(membership_tier, 'standard') = $1 AND deleted_at IS NULL",
        )
        .bind(tier)
        .fetch_one(pool.get_ref())
        .await?;

        (rows, total.0)
    } else if let Some(ref status) = query.status {
        let rows = sqlx::query_as::<_, crate::models::AdminMembershipResponse>(
            r#"
            SELECT id AS user_id, email AS user_email, stripe_customer_id,
                   membership_status AS status,
                   COALESCE(membership_tier, 'standard') AS membership_tier,
                   membership_override_by,
                   created_at
            FROM users
            WHERE membership_status = $3 AND deleted_at IS NULL
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
            "SELECT COUNT(*) FROM users WHERE membership_status = $1 AND deleted_at IS NULL",
        )
        .bind(status)
        .fetch_one(pool.get_ref())
        .await?;

        (rows, total.0)
    } else {
        let rows = sqlx::query_as::<_, crate::models::AdminMembershipResponse>(
            r#"
            SELECT id AS user_id, email AS user_email, stripe_customer_id,
                   membership_status AS status,
                   COALESCE(membership_tier, 'standard') AS membership_tier,
                   membership_override_by,
                   created_at
            FROM users
            WHERE membership_status != 'none' AND deleted_at IS NULL
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(per_page)
        .bind(offset)
        .fetch_all(pool.get_ref())
        .await?;

        let total: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM users WHERE membership_status != 'none' AND deleted_at IS NULL",
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

/// PUT /v1/admin/applications/reorder
/// Set the display order of all applications from an explicit id list
/// (BUNYIP-473). Replaces the pairwise swap: each id's `sort_order` becomes its
/// index in the list, so positions stay distinct and reordering cannot no-op.
pub async fn reorder_applications(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    body: web::Json<ReorderApplicationsRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    ApplicationRepository::set_order(&pool, &body.ordered_ids).await?;

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

    // BUNYIP-386: retain the current pin(s) in the version history so a later bump adds a
    // version rather than losing this one. Covers both distribution paths - the OCI image
    // tag and the binary release/package tag - so binaries are retained the same way
    // images are; an app sets one of the two. Idempotent; best-effort so a history-write
    // hiccup never fails the update.
    for tag in [
        app.pinned_image_tag.as_deref(),
        app.pinned_release_tag.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if let Err(e) = ApplicationRepository::record_version(&pool, app.id, tag, None).await {
            tracing::warn!(error = %e, app_id = %app.id, tag, "application_versions record failed");
        }
    }

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

#[derive(Debug, Deserialize)]
pub struct ImportQuery {
    /// Load a named embedded template (PSA-57) instead of the request body.
    pub template: Option<String>,
}

/// One embedded template plus its section counts, for the setup picker.
#[derive(Debug, Serialize)]
pub struct SeedTemplateInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub groups: usize,
    pub applications: usize,
    pub users: usize,
    pub entitlements: usize,
    pub feedback: usize,
}

/// GET /v1/admin/seed/templates
/// List the embedded seed templates (name, description, section counts) for the
/// first-run setup picker (PSA-57). Admin-gated.
pub async fn list_seed_templates(
    req: HttpRequest,
    _admin: AdminUser,
) -> Result<HttpResponse, AppError> {
    let templates: Vec<SeedTemplateInfo> = crate::seed::SEED_TEMPLATES
        .iter()
        // A malformed embedded template is skipped rather than 500-ing the list
        // (a test asserts every one parses, so this never drops one in practice).
        .filter_map(|t| crate::seed::parse(t.json).ok().map(|f| (t, f)))
        .map(|(t, f)| SeedTemplateInfo {
            name: t.name,
            description: t.description,
            groups: f.application_groups.len(),
            applications: f.applications.len(),
            users: f.users.len(),
            entitlements: f.entitlements.len(),
            feedback: f.feedback.len(),
        })
        .collect();
    Ok(success(templates, get_request_id(&req)))
}

/// POST /v1/admin/seed/import
/// Load a canonical seed file through the shared loader. The data comes from a
/// named embedded template (`?template=<name>`, PSA-57) when given, otherwise
/// the request body. Blocked on production/unset environments so demo data can
/// never land in prod, even though only an admin can reach this. Idempotent.
pub async fn import_seed_data(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    query: web::Query<ImportQuery>,
    body: String,
) -> Result<HttpResponse, AppError> {
    crate::seed::seed_guard(&config.environment, true)
        .map_err(|e| AppError::bad_request(e.to_string()))?;
    let json: &str = match &query.template {
        Some(name) => {
            crate::seed::find_template(name)
                .ok_or_else(|| AppError::bad_request(format!("unknown seed template '{name}'")))?
                .json
        }
        None => &body,
    };
    let file = crate::seed::parse(json).map_err(|e| AppError::bad_request(e.to_string()))?;
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
        "SELECT COUNT(*) FROM users WHERE membership_status = 'active' AND deleted_at IS NULL",
    )
    .fetch_one(pool)
    .await?;

    let past_due_members: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE membership_status = 'past_due' AND deleted_at IS NULL",
    )
    .fetch_one(pool)
    .await?;

    let grace_period_members: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE membership_status = 'grace_period' AND deleted_at IS NULL",
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

    // Send password reset email. Admin-initiated, so there is no requester IP
    // and no location to show (BUNYIP-397).
    email_service
        .send_password_reset(&user.email, &raw_token, None)
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
// System Health
// =============================================================================

/// System health response
#[derive(Debug, Serialize)]
pub struct SystemHealth {
    pub status: String,
    pub database: HealthStatus,
    pub uptime_seconds: u64,
    pub version: String,
    /// BUNYIP-474: age/staleness of the offline IP datasets (IP2Location for
    /// login country, IP2Proxy for ASN/VPN enrichment), so a missed refresh is
    /// visible to an admin.
    pub datasets: Vec<DatasetHealth>,
}

/// Health status for a component
#[derive(Debug, Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub latency_ms: Option<u64>,
    pub message: Option<String>,
}

/// One offline dataset's freshness (BUNYIP-474). The `.BIN` is provisioned and
/// refreshed outside the app (see `scripts/refresh-ip2-datasets.nu`); this only
/// reports what is on disk so a stale or missing file surfaces in admin.
#[derive(Debug, Serialize)]
pub struct DatasetHealth {
    pub name: String,
    pub env_var: String,
    /// The path env var is set to a non-empty value.
    pub configured: bool,
    /// The file at that path is readable (so `age_days` is populated).
    pub present: bool,
    /// Whole days since the file's mtime, or `None` when unconfigured/unreadable.
    pub age_days: Option<i64>,
    /// Configured, present, and older than the refresh cadence allows.
    pub stale: bool,
}

/// IP2Location / IP2Proxy LITE datasets refresh about monthly, so flag one stale
/// once it is older than this. Gives a missed monthly refresh a week of grace
/// before it lights up (BUNYIP-474).
const DATASET_STALE_AFTER_DAYS: i64 = 40;

fn dataset_is_stale(age_days: Option<i64>) -> bool {
    matches!(age_days, Some(d) if d > DATASET_STALE_AFTER_DAYS)
}

/// Whole days since the mtime of the file at `path`, or `None` if it cannot be
/// read (unset path, missing file, or a future mtime from clock skew).
fn dataset_age_days(path: &str) -> Option<i64> {
    let mtime = std::fs::metadata(path).ok()?.modified().ok()?;
    let age = std::time::SystemTime::now().duration_since(mtime).ok()?;
    Some((age.as_secs() / 86_400) as i64)
}

/// Build a [`DatasetHealth`] from a configured `.BIN` path (or `None`).
fn dataset_health(name: &str, env_var: &str, path: Option<&str>) -> DatasetHealth {
    let path = path.map(str::trim).filter(|p| !p.is_empty());
    let configured = path.is_some();
    let age_days = path.and_then(dataset_age_days);
    let present = age_days.is_some();
    DatasetHealth {
        name: name.to_string(),
        env_var: env_var.to_string(),
        configured,
        present,
        age_days,
        stale: dataset_is_stale(age_days),
    }
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
    config: web::Data<Config>,
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

    // BUNYIP-474: dataset freshness. Read-only (the .BIN is refreshed out of
    // band by scripts/refresh-ip2-datasets.nu); this just reports the on-disk age.
    let datasets = vec![
        dataset_health(
            "IP2Location (login country)",
            "IP2LOCATION_DB_PATH",
            config.ip2location_db_path.as_deref(),
        ),
        dataset_health(
            "IP2Proxy (ASN / VPN enrichment)",
            "IP2PROXY_DB_PATH",
            config.ip2proxy_db_path.as_deref(),
        ),
    ];

    let health = SystemHealth {
        status: overall_status.to_string(),
        database: db_health,
        uptime_seconds: server_start.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        datasets,
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
    // BUNYIP-351: non-secret checkout knobs. Empty string == "no change".
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
    pub trial_period_days: Option<i32>,
}

/// GET /v1/admin/stripe
/// Returns the current Stripe config with secrets masked. BUNYIP-542: the
/// non-secret columns come from the DB row; the two secrets come from the store
/// `SECRETS_STORAGE` declares, so the masked hints describe what the running
/// service uses rather than what the database happens to still hold.
pub async fn get_stripe_config(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
) -> Result<HttpResponse, AppError> {
    use crate::config::GovernedSecret;

    let request_id = get_request_id(&req);

    let db = StripeConfigRepository::get(&pool).await?;
    let secret_key = crate::secrets::read_secret(
        &pool,
        &config,
        &app_key_set,
        GovernedSecret::StripeSecretKey,
    )
    .await?;
    let webhook_secret = crate::secrets::read_secret(
        &pool,
        &config,
        &app_key_set,
        GovernedSecret::StripeWebhookSecret,
    )
    .await?;

    Ok(success(
        StripeConfigResponse::from_store(
            &db,
            config.secrets_storage,
            secret_key.as_deref(),
            webhook_secret.as_deref(),
        ),
        request_id,
    ))
}

/// PUT /v1/admin/stripe
/// Updates Stripe config. Only fields with a non-empty value are written; omitted or
/// empty-string fields leave the existing DB value unchanged.
pub async fn update_stripe_config(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
    stripe_service: web::Data<Arc<StripeService>>,
    pricing_cache: web::Data<Arc<crate::handlers::PricingCache>>,
    body: web::Json<UpdateStripeConfigRequest>,
) -> Result<HttpResponse, AppError> {
    use crate::config::{GovernedSecret, SecretsStorage};

    let request_id = get_request_id(&req);

    // Treat empty strings the same as None — user left the field blank
    let secret_key_plain = body.secret_key.as_deref().filter(|s| !s.is_empty());
    let webhook_secret_plain = body.webhook_secret.as_deref().filter(|s| !s.is_empty());

    // BUNYIP-542: the two secrets are written to the ONE declared store. The
    // non-secret fields below (app tag, checkout URLs, trial length) stay
    // editable in every mode.
    let storage = config.secrets_storage;
    if !storage.is_writable() {
        if secret_key_plain.is_some() {
            return Err(crate::secrets::read_only_store_error(
                GovernedSecret::StripeSecretKey,
            ));
        }
        if webhook_secret_plain.is_some() {
            return Err(crate::secrets::read_only_store_error(
                GovernedSecret::StripeWebhookSecret,
            ));
        }
    }
    let app_tag = body
        .app_tag
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    // BUNYIP-351: checkout knobs. Empty string == "no change" (COALESCE).
    let success_url = body
        .success_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let cancel_url = body
        .cancel_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if let Some(days) = body.trial_period_days {
        if !(0..=365).contains(&days) {
            return Err(AppError::validation(
                "trial_period_days",
                "Must be between 0 and 365",
            ));
        }
    }

    // Encrypt secrets before storing, but ONLY when the database IS the
    // declared store; in `infisical` mode the ciphertext columns stay untouched.
    let db_is_the_store = storage == SecretsStorage::Database;
    let (secret_key_enc, secret_key_nonce, key_version) = match secret_key_plain {
        Some(sk) if db_is_the_store => {
            let (ct, nonce, ver) = encrypt_secret(&app_key_set, sk)?;
            (Some(ct), Some(nonce), ver)
        }
        _ => (None, None, app_key_set.current_version),
    };
    let (webhook_secret_enc, webhook_secret_nonce) = match webhook_secret_plain {
        Some(ws) if db_is_the_store => {
            let (ct, nonce, _) = encrypt_secret(&app_key_set, ws)?;
            (Some(ct), Some(nonce))
        }
        _ => (None, None),
    };

    // Infisical mode writes through FIRST, so a failed upsert aborts the save
    // with its underlying cause: no row change, no reload, no reported success.
    if storage == SecretsStorage::Infisical {
        for (secret, value) in [
            (GovernedSecret::StripeSecretKey, secret_key_plain),
            (GovernedSecret::StripeWebhookSecret, webhook_secret_plain),
        ] {
            if let Some(value) = value {
                crate::secrets::write_secret(
                    &pool,
                    &config,
                    &app_key_set,
                    storage,
                    secret,
                    value,
                    Some(admin.0.sub),
                )
                .await?;
            }
        }
    }

    let updated = StripeConfigRepository::update(
        &pool,
        secret_key_enc,
        secret_key_nonce,
        webhook_secret_enc,
        webhook_secret_nonce,
        admin.0.sub,
        key_version,
        app_tag.clone(),
        success_url,
        cancel_url,
        body.trial_period_days,
    )
    .await?;

    // Hot-reload the live StripeService so new API calls use the updated keys.
    // BUNYIP-542: the reload reads the secrets back from the declared store, so
    // `database` and `infisical` saves take effect identically.
    let new_config =
        crate::secrets::stripe_runtime_config(&pool, &config, &app_key_set, &updated).await?;
    stripe_service.reload(new_config);
    tracing::info!(
        secrets_storage = %storage,
        "Stripe service reloaded with updated config"
    );

    // BUNYIP-515: the secret key and the app tag both decide which prices
    // /pricing can see, so a save takes effect on the next load rather than
    // after the TTL.
    pricing_cache.invalidate();

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
            // BUNYIP-542: which store the secrets went to. Writing to Infisical
            // loses the row's updated_by attribution, so this entry is the
            // in-app trail for that mode.
            "secret_store": (secret_key_plain.is_some() || webhook_secret_plain.is_some())
                .then(|| storage.as_str()),
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

    let secret_key = crate::secrets::read_secret(
        &pool,
        &config,
        &app_key_set,
        GovernedSecret::StripeSecretKey,
    )
    .await?;
    let webhook_secret = crate::secrets::read_secret(
        &pool,
        &config,
        &app_key_set,
        GovernedSecret::StripeWebhookSecret,
    )
    .await?;
    Ok(success(
        StripeConfigResponse::from_store(
            &updated,
            storage,
            secret_key.as_deref(),
            webhook_secret.as_deref(),
        ),
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
    tier_config: web::Data<Arc<std::sync::RwLock<TierConfig>>>,
    bus: web::Data<Arc<EventBus>>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    let user = UserRepository::grant_lifetime_membership(&pool, user_id, admin.0.sub).await?;

    // Create $0 Stripe subscription for invoice generation (BUNYIP-482: the
    // price id comes from the live tier config, not from env).
    if let Some(free_price_id) = live_free_price_id(&tier_config) {
        let customer_id = match user.stripe_customer_id.clone() {
            Some(id) => id,
            None => {
                let id = stripe
                    .create_customer(&user.email, user.id)
                    .await
                    .map_err(stripe_err)?;
                UserRepository::update_stripe_customer_id(pool.get_ref(), user.id, &id).await?;
                id
            }
        };
        stripe
            .create_free_subscription(&customer_id, &free_price_id)
            .await
            .map_err(stripe_err)?;
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
// Admin tier change (BUNYIP-431)
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct SetUserTierRequest {
    /// One of `lifetime` | `free` | `early_adopter` | `standard`.
    pub tier: String,
    /// The acting admin's current 2FA code. Required: a tier move has billing
    /// consequences, so it is gated on a stronger check than the ordinary
    /// confirm dialog.
    pub totp_code: String,
}

/// Strictly parse a destination tier. Unlike `MembershipTier::from(&str)`
/// (which defaults anything unknown to `Standard`), an unrecognised value is a
/// client error here so a typo can never silently downgrade a member.
fn parse_admin_tier(raw: &str) -> Result<MembershipTier, AppError> {
    match raw.trim() {
        "lifetime" => Ok(MembershipTier::Lifetime),
        "free" => Ok(MembershipTier::Free),
        "early_adopter" => Ok(MembershipTier::EarlyAdopter),
        "standard" => Ok(MembershipTier::Standard),
        _ => Err(AppError::validation("tier", "Unknown subscription tier")),
    }
}

/// The side effects a tier move entails, decided purely from the 2FA result and
/// the before/after tiers so upgrade / downgrade / cancelled-2FA are unit-testable
/// without a database or Stripe. `Err` means the 2FA code failed and the caller
/// must mutate nothing (BUNYIP-431 AC6). On `Ok`, `create_lifetime_invoice` is
/// true only when NEWLY moving to lifetime (mirrors `grant_lifetime_membership`'s
/// $0 invoice subscription), and `revoke_sessions` is true for any real tier
/// change because tier flips `has_member_access` inputs on the JWT claims.
#[derive(Debug, PartialEq, Eq)]
struct TierMovePlan {
    create_lifetime_invoice: bool,
    revoke_sessions: bool,
}

fn plan_admin_tier_move(
    totp_valid: bool,
    from: &MembershipTier,
    to: &MembershipTier,
) -> Result<TierMovePlan, AppError> {
    if !totp_valid {
        return Err(AppError::validation("totp_code", "Invalid 2FA code"));
    }
    Ok(TierMovePlan {
        create_lifetime_invoice: matches!(to, MembershipTier::Lifetime)
            && !matches!(from, MembershipTier::Lifetime),
        revoke_sessions: from != to,
    })
}

/// POST /v1/admin/users/{user_id}/tier (BUNYIP-431)
/// Move any member to any configured tier, gated on the acting admin's 2FA code.
/// Slot usage is a live COUNT over `membership_tier`, so the single UPDATE in
/// `admin_set_membership_tier` debits the source tier and credits the
/// destination; no separate counter is touched.
pub async fn set_user_tier(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    bus: web::Data<Arc<EventBus>>,
    totp_service: web::Data<Arc<TotpService>>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<SetUserTierRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let user_id = path.into_inner();

    // Validate the destination tier before touching anything.
    let to_tier = parse_admin_tier(&body.tier)?;

    // The before-tier, for the audit trail and the move plan.
    let before = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or_else(|| AppError::not_found("User"))?;
    let from_tier = MembershipTier::from(before.membership_tier.as_str());

    // 2FA gate. A missing/invalid code yields Err here, BEFORE any mutation, so
    // a cancelled or wrong code leaves the tier and every slot count unchanged.
    let totp_valid = totp_service
        .verify_code(admin.0.sub, body.totp_code.trim())
        .await
        .map_err(|_| AppError::validation("totp_code", "2FA must be enabled to change a tier"))?;
    let plan = plan_admin_tier_move(totp_valid, &from_tier, &to_tier)?;

    // Trial windows come from the resolved tier settings.
    let tier_config =
        crate::config::TierConfig::from_db_row(&TierConfigRepository::get(&pool).await?);

    let user = UserRepository::admin_set_membership_tier(
        &pool,
        user_id,
        &to_tier,
        admin.0.sub,
        tier_config.early_adopter_trial_days,
        tier_config.standard_trial_days,
    )
    .await?;

    // Moving TO lifetime mirrors grant_lifetime_membership: mint the $0 invoice
    // subscription so the member keeps receiving invoices.
    // BUNYIP-482: the $0 price id comes from the tier settings resolved above
    // (freshly read from the DB), not from env.
    if plan.create_lifetime_invoice {
        if let Some(free_price_id) = tier_config.free_price_id.clone() {
            let customer_id = match user.stripe_customer_id.clone() {
                Some(id) => id,
                None => {
                    let id = stripe
                        .create_customer(&user.email, user.id)
                        .await
                        .map_err(stripe_err)?;
                    UserRepository::update_stripe_customer_id(pool.get_ref(), user.id, &id).await?;
                    id
                }
            };
            stripe
                .create_free_subscription(&customer_id, &free_price_id)
                .await
                .map_err(stripe_err)?;
        }
    }

    // Any real tier change flips has_member_access inputs, so cut existing
    // sessions (next request remints fresh claims) and nudge open tabs.
    let sessions_revoked = if plan.revoke_sessions {
        revoke_user_sessions(pool.get_ref(), user_id).await?
    } else {
        false
    };
    announce_claims_changed(bus.as_ref(), user_id);

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminTierChanged)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("user", user_id)
            .with_metadata(serde_json::json!({
                "from_tier": from_tier.as_str(),
                "to_tier": to_tier.as_str(),
                "target_email": user.email,
                "sessions_revoked": sessions_revoked,
            })),
    )
    .await?;

    Ok(success(UserResponse::from(user), request_id))
}

// =============================================================================
// Email Configuration (BUNYIP-351)
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct UpdateEmailConfigRequest {
    pub enabled: Option<bool>,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<i32>,
    pub smtp_tls: Option<String>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub from_email: Option<String>,
    pub from_name: Option<String>,
    pub admin_notification_emails: Option<String>,
}

/// Render an [`SmtpTls`](crate::config::SmtpTls) as its wire string.
fn smtp_tls_str(tls: &crate::config::SmtpTls) -> String {
    match tls {
        crate::config::SmtpTls::Implicit => "implicit".to_string(),
        crate::config::SmtpTls::Starttls => "starttls".to_string(),
    }
}

/// Build the API response from a resolved [`EmailConfig`]. BUNYIP-432: the SMTP
/// password is write-only, so the response carries only the boolean
/// `has_smtp_password`; the plaintext (and any masked/last-4 form of it) never
/// leaves the server. The client renders a fixed-length mask from the flag.
fn email_config_response(
    resolved: crate::config::EmailConfig,
    source: &'static str,
    secrets_storage: crate::config::SecretsStorage,
    updated_at: chrono::DateTime<chrono::Utc>,
    updated_by: Option<uuid::Uuid>,
) -> crate::models::email::EmailConfigResponse {
    crate::models::email::EmailConfigResponse {
        secrets_storage: secrets_storage.as_str(),
        smtp_password_editable: secrets_storage.is_writable(),
        enabled: resolved.enabled,
        smtp_host: resolved.smtp_host,
        smtp_port: resolved.smtp_port as i32,
        smtp_tls: smtp_tls_str(&resolved.smtp_tls),
        smtp_username: resolved.smtp_username,
        has_smtp_password: !resolved.smtp_password.is_empty(),
        from_email: resolved.from_email,
        from_name: resolved.from_name,
        admin_notification_emails: resolved.admin_notification_emails,
        source,
        updated_at: Some(updated_at),
        updated_by,
    }
}

/// GET /v1/admin/email
pub async fn get_email_config(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
) -> Result<HttpResponse, AppError> {
    use crate::config::EmailConfig;
    use crate::repositories::EmailConfigRepository;

    let request_id = get_request_id(&req);

    let row = EmailConfigRepository::get(&pool).await?;
    let source = if EmailConfig::has_db_overrides(&row) {
        "database"
    } else {
        "environment"
    };
    // BUNYIP-542: the non-secret settings come from the row (or the env
    // defaults); the password comes from the declared store alone, so the page
    // can never claim a password the running service does not use.
    let smtp_password = crate::secrets::read_secret(
        &pool,
        &config,
        &app_key_set,
        crate::config::GovernedSecret::SmtpPassword,
    )
    .await?;
    let resolved = EmailConfig::from_db_row(&row, smtp_password, config.is_production());

    Ok(success(
        email_config_response(
            resolved,
            source,
            config.secrets_storage,
            row.updated_at,
            row.updated_by,
        ),
        request_id,
    ))
}

/// PUT /v1/admin/email
pub async fn update_email_config(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
    email_service: web::Data<Arc<EmailService>>,
    body: web::Json<UpdateEmailConfigRequest>,
) -> Result<HttpResponse, AppError> {
    use crate::config::EmailConfig;
    use crate::models::stripe::encrypt_secret;
    use crate::repositories::EmailConfigRepository;

    let request_id = get_request_id(&req);

    // Validate the enumerated / bounded fields when provided.
    if let Some(tls) = body.smtp_tls.as_deref().filter(|s| !s.is_empty()) {
        if tls != "implicit" && tls != "starttls" {
            return Err(AppError::validation(
                "smtp_tls",
                "Must be 'implicit' or 'starttls'",
            ));
        }
    }
    if let Some(port) = body.smtp_port {
        if !(1..=65535).contains(&port) {
            return Err(AppError::validation(
                "smtp_port",
                "Must be between 1 and 65535",
            ));
        }
    }

    // Empty string == "no change" (COALESCE), matching the Stripe/tier handlers.
    let nonempty = |v: &Option<String>| {
        v.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let smtp_host = nonempty(&body.smtp_host);
    let smtp_tls = nonempty(&body.smtp_tls);
    let smtp_username = nonempty(&body.smtp_username);
    let from_email = nonempty(&body.from_email);
    let from_name = nonempty(&body.from_name);
    let admin_notification_emails = nonempty(&body.admin_notification_emails);

    // BUNYIP-542: the SMTP password is written to the ONE declared store.
    let storage = config.secrets_storage;
    let smtp_password_plain = body.smtp_password.as_deref().filter(|s| !s.is_empty());
    if smtp_password_plain.is_some() && !storage.is_writable() {
        return Err(crate::secrets::read_only_store_error(
            crate::config::GovernedSecret::SmtpPassword,
        ));
    }
    // The ciphertext columns are written ONLY when the database IS the declared
    // store; in `infisical` mode the row's secret columns are left untouched.
    let (pw_enc, pw_nonce, key_version) = match (smtp_password_plain, storage) {
        (Some(pw), crate::config::SecretsStorage::Database) => {
            let (ct, nonce, ver) = encrypt_secret(&app_key_set, pw)?;
            (Some(ct), Some(nonce), ver)
        }
        _ => (None, None, app_key_set.current_version),
    };
    // Infisical mode writes through FIRST: a failed upsert must abort the save
    // with its underlying cause, leaving the row untouched, performing no
    // reload, and reporting no success.
    if let (Some(pw), crate::config::SecretsStorage::Infisical) = (smtp_password_plain, storage) {
        crate::secrets::write_secret(
            &pool,
            &config,
            &app_key_set,
            storage,
            crate::config::GovernedSecret::SmtpPassword,
            pw,
            Some(admin.0.sub),
        )
        .await?;
    }

    let updated = EmailConfigRepository::update(
        &pool,
        body.enabled,
        smtp_host,
        body.smtp_port,
        smtp_tls,
        smtp_username,
        pw_enc,
        pw_nonce,
        key_version,
        from_email,
        from_name,
        admin_notification_emails,
        admin.0.sub,
    )
    .await?;

    // The password just written is the live one; otherwise re-read the declared
    // store so the hot reload uses exactly what the next boot will.
    let resolved_password = match smtp_password_plain {
        Some(pw) => Some(pw.to_string()),
        None => {
            crate::secrets::read_secret(
                &pool,
                &config,
                &app_key_set,
                crate::config::GovernedSecret::SmtpPassword,
            )
            .await?
        }
    };
    let resolved = EmailConfig::from_db_row(&updated, resolved_password, config.is_production());

    // BUNYIP-204/351: refuse to disable email in production, even via the DB.
    if config.is_production() && !resolved.enabled {
        return Err(AppError::validation(
            "enabled",
            "Email cannot be disabled in a production deployment",
        ));
    }

    // Hot-reload the live EmailService so subsequent sends use the new transport.
    email_service.reload(resolved.clone())?;
    tracing::info!("Email config updated and hot-reloaded");

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminEmailConfigUpdated)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_metadata(serde_json::json!({
                "setting": "email_config",
                "enabled": body.enabled,
                "smtp_host": body.smtp_host,
                "smtp_port": body.smtp_port,
                "smtp_tls": body.smtp_tls,
                "smtp_username": body.smtp_username,
                // Never log the password itself; record only that it changed,
                // and (BUNYIP-542) which store it was written to. Writing to
                // Infisical loses the row's updated_by attribution, so this
                // entry is the in-app trail for that mode.
                "password_changed": smtp_password_plain.is_some(),
                "secret": smtp_password_plain.map(|_| "SMTP_PASSWORD"),
                "secret_store": smtp_password_plain.map(|_| storage.as_str()),
                "from_email": body.from_email,
                "from_name": body.from_name,
            })),
    )
    .await?;

    Ok(success(
        email_config_response(
            resolved,
            "database",
            storage,
            updated.updated_at,
            updated.updated_by,
        ),
        request_id,
    ))
}

/// POST /v1/admin/email/test
///
/// BUNYIP-433: verify the *currently saved* SMTP settings by opening a real
/// connection, negotiating TLS, and authenticating, without sending any mail.
/// Reports the specific stage that failed (connect / tls / auth) so an admin can
/// tell a bad host from bad TLS from a rejected password. Motivated by PMS-669:
/// a rotated password silently broke delivery, and only an auth-stage probe
/// would have named it.
///
/// Rate limited per admin (`RateLimitConfig::SMTP_TEST`) so the button cannot be
/// used to hammer the configured relay. Always returns 200 with an
/// `{ ok, stage, message }` body: a failing SMTP target is a diagnostic result,
/// not an API error. Only the rate-limit trip (429) surfaces as an error.
pub async fn test_email_config(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
) -> Result<HttpResponse, AppError> {
    use crate::config::EmailConfig;
    use crate::repositories::EmailConfigRepository;

    let request_id = get_request_id(&req);

    // Keyed by the admin's user id (bare UUID, matching KeyKind::UserId so the
    // admin rate-limit view can resolve it) rather than by IP, so the cap is
    // per-operator and not shared across admins behind one NAT.
    check_rate_limit(&pool, &admin.0.sub.to_string(), &RateLimitConfig::SMTP_TEST).await?;

    // Test the saved config (not any unsaved form values): the point is to
    // verify the credential email actually sends with. The web UI tells the
    // admin to save before testing.
    let row = EmailConfigRepository::get(&pool).await?;
    let smtp_password = crate::secrets::read_secret(
        &pool,
        &config,
        &app_key_set,
        crate::config::GovernedSecret::SmtpPassword,
    )
    .await?;
    let resolved = EmailConfig::from_db_row(&row, smtp_password, config.is_production());

    let outcome = EmailService::test_connection(&resolved).await;

    let (ok, stage, message) = match &outcome {
        Ok(()) => (
            true,
            "ok",
            "SMTP connection and authentication succeeded.".to_string(),
        ),
        Err(e) => (false, e.stage.as_str(), e.message.clone()),
    };

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminEmailConnectionTested)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_metadata(serde_json::json!({
                "smtp_host": resolved.smtp_host,
                "smtp_port": resolved.smtp_port,
                "smtp_tls": resolved.smtp_tls.as_str(),
                "ok": ok,
                "stage": stage,
            })),
    )
    .await?;

    Ok(success(
        serde_json::json!({ "ok": ok, "stage": stage, "message": message }),
        request_id,
    ))
}

/// BUNYIP-508: shape a test-send outcome into the `{ ok, message }` body. The
/// generic `Internal error: ` wrapper is stripped so the banner leads with the
/// relay's own reason. Pure, so the failure path (200 carrying the relay text,
/// never a 5xx) is unit-testable without a relay or a database.
fn test_send_outcome(outcome: &Result<(), AppError>) -> (bool, String) {
    match outcome {
        Ok(()) => (
            true,
            "Test message sent to your address. Check your inbox.".to_string(),
        ),
        Err(e) => {
            let text = e.to_string();
            (
                false,
                text.strip_prefix("Internal error: ")
                    .unwrap_or(&text)
                    .to_string(),
            )
        }
    }
}

/// POST /v1/admin/email/test-send
///
/// BUNYIP-508: send a real test message through the *saved* SMTP settings so an
/// admin can prove end-to-end delivery, not just that the relay authenticates
/// (which is all `test_email_config` proves: a relay can accept AUTH and still
/// refuse or drop mail).
///
/// The recipient is the signed-in admin's own address from the verified claims.
/// There is deliberately no request body and no recipient parameter, so the
/// endpoint cannot be pointed at a third party and turned into a relay for
/// arbitrary mail.
///
/// Shares `RateLimitConfig::SMTP_TEST` with the connection probe (both hammer
/// the same relay). Always returns 200 with `{ ok, message }`: a 5xx would be
/// collapsed to a generic line by `ApiError::user_message` (BUNYIP-477), hiding
/// the one thing the admin clicked the button to see. The failure is still
/// loud: it is logged at `error`, `ok: false` is not a value a successful send
/// can produce, and the page renders a red banner.
pub async fn send_test_email_message(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    app_key_set: web::Data<AppKeySet>,
    email_service: web::Data<Arc<EmailService>>,
) -> Result<HttpResponse, AppError> {
    use crate::config::EmailConfig;
    use crate::repositories::EmailConfigRepository;

    let request_id = get_request_id(&req);

    check_rate_limit(&pool, &admin.0.sub.to_string(), &RateLimitConfig::SMTP_TEST).await?;

    // Send with the SAVED config, not unsaved form values: the point is to
    // prove the settings email actually sends with. Hot-reloaded into the live
    // service so the transport matches what was persisted.
    let row = EmailConfigRepository::get(&pool).await?;
    let smtp_password = crate::secrets::read_secret(
        &pool,
        &config,
        &app_key_set,
        crate::config::GovernedSecret::SmtpPassword,
    )
    .await?;
    let resolved = EmailConfig::from_db_row(&row, smtp_password, config.is_production());

    // A transport that will not even build is the same class of news as a relay
    // that refuses the message, so it reports through the same banner instead
    // of a 5xx the admin would only see as "an unexpected error occurred".
    let outcome = match email_service.reload(resolved.clone()) {
        Ok(()) => email_service.send_test_message(&admin.0.email).await,
        Err(e) => Err(e),
    };
    let (ok, message) = test_send_outcome(&outcome);

    if let Err(e) = &outcome {
        tracing::error!(error = %e, smtp_host = %resolved.smtp_host, "Admin test email failed to send");
    }

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminTestEmailSent)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            // BUNYIP-265: never the recipient address, only the relay facts.
            .with_metadata(serde_json::json!({
                "smtp_host": resolved.smtp_host,
                "smtp_port": resolved.smtp_port,
                "smtp_tls": resolved.smtp_tls.as_str(),
                "ok": ok,
            })),
    )
    .await?;

    Ok(success(
        serde_json::json!({ "ok": ok, "message": message }),
        request_id,
    ))
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
    /// BUNYIP-487: publish switch for the public `/pricing` page.
    pub pricing_enabled: Option<bool>,
    /// BUNYIP-527: per-tier visibility on the public `/pricing` page.
    pub lifetime_visible: Option<bool>,
    pub early_adopter_visible: Option<bool>,
    pub standard_visible: Option<bool>,
}

/// BUNYIP-517: resolve a mapped price id to the Stripe product bunyip stores for
/// webhook tier classification (`resolve_tier_for_product`). `prices` is the
/// app-tagged price list. A price that is not in the list (unknown id, or a
/// product not tagged for this app) or that is archived is refused, naming the
/// tier and the reason, rather than storing a mapping that resolves to no tier
/// when a `customer.subscription.*` event arrives. Deriving the product from the
/// price is what keeps the checkout price and the webhook classification from
/// disagreeing: there is one entered value per tier, the price.
fn derive_product_for_price(
    tier_label: &str,
    price_id: &str,
    prices: &[StripePriceResponse],
    app_tag: &str,
) -> Result<String, AppError> {
    match prices.iter().find(|p| p.id == price_id) {
        Some(p) if p.active => Ok(p.product_id.clone()),
        Some(_) => Err(AppError::validation(
            "price_id",
            format!("{tier_label}: {price_id} is archived in Stripe. Map an active price."),
        )),
        None => Err(AppError::validation(
            "price_id",
            format!(
                "{tier_label}: {price_id} is not visible under app tag `{app_tag}`. \
                 Check the id, or set that product's app_tag metadata in Stripe."
            ),
        )),
    }
}

/// GET /v1/admin/tier-config
pub async fn get_tier_config(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    use crate::config::TierConfig;
    use crate::models::tier::{TierConfigResponse, TierConfigWithPricing};
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
        TierConfigWithPricing {
            pricing_enabled: resolved.pricing_enabled,
            lifetime_visible: resolved.lifetime_visible,
            early_adopter_visible: resolved.early_adopter_visible,
            standard_visible: resolved.standard_visible,
            config: TierConfigResponse {
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
    stripe: web::Data<Arc<StripeService>>,
    pricing_cache: web::Data<Arc<crate::handlers::PricingCache>>,
    body: web::Json<UpdateTierConfigRequest>,
) -> Result<HttpResponse, AppError> {
    use crate::config::TierConfig;
    use crate::models::tier::{TierConfigResponse, TierConfigWithPricing};
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

    // BUNYIP-517 / BUNYIP-527: the catalog form sends a price per tier and no
    // product id. Each price is three-state: omitted keeps the stored mapping; an
    // explicit empty string CLEARS it (and its derived product); a non-empty id
    // sets it, and the product bunyip stores for webhook classification is derived
    // from that price so the two halves cannot disagree. Stripe is consulted only
    // when at least one price is actually being set.
    enum PriceOp<'a> {
        Keep,
        Clear,
        Set(&'a str),
    }
    fn price_op(o: &Option<String>) -> PriceOp<'_> {
        match o.as_deref().map(str::trim) {
            None => PriceOp::Keep,
            Some("") => PriceOp::Clear,
            Some(id) => PriceOp::Set(id),
        }
    }
    let ops = [
        // Free and lifetime share the $0 price, and the webhook classifies that
        // product as lifetime, so `free_price_id` derives `lifetime_product_id`.
        ("Free / lifetime", price_op(&body.free_price_id)),
        ("Early adopter", price_op(&body.early_adopter_price_id)),
        ("Standard", price_op(&body.standard_price_id)),
    ];
    let need_stripe = ops.iter().any(|(_, op)| matches!(op, PriceOp::Set(_)));
    let prices = if need_stripe {
        Some(stripe.list_prices(None).await.map_err(stripe_err)?)
    } else {
        None
    };
    let app_tag = stripe.app_tag();
    // The value passed to the repo for a price column: `None` keeps, `Some("")`
    // clears (NULL), `Some(id)` sets.
    let price_val = |op: &PriceOp| -> Option<String> {
        match op {
            PriceOp::Keep => None,
            PriceOp::Clear => Some(String::new()),
            PriceOp::Set(id) => Some(id.to_string()),
        }
    };
    // The derived product for a tier: set -> derive from Stripe; clear -> clear it
    // too (an unmapped tier has no product); keep -> whatever the caller passed
    // (the catalog form sends none, so it stays None and the row is kept).
    let derive_product = |label: &str,
                          op: &PriceOp,
                          fallback: &Option<String>|
     -> Result<Option<String>, AppError> {
        match op {
            PriceOp::Set(id) => {
                let prices = prices.as_ref().expect("prices fetched when a price is set");
                Ok(Some(derive_product_for_price(label, id, prices, &app_tag)?))
            }
            PriceOp::Clear => Ok(Some(String::new())),
            PriceOp::Keep => Ok(fallback.clone()),
        }
    };
    let lifetime_product_id = derive_product(ops[0].0, &ops[0].1, &body.lifetime_product_id)?;
    let early_adopter_product_id =
        derive_product(ops[1].0, &ops[1].1, &body.early_adopter_product_id)?;
    let standard_product_id = derive_product(ops[2].0, &ops[2].1, &body.standard_product_id)?;

    let row = TierConfigRepository::update(
        &pool,
        body.lifetime_slots,
        body.early_adopter_slots,
        body.early_adopter_trial_days,
        body.standard_trial_days,
        price_val(&ops[0].1),
        price_val(&ops[1].1),
        price_val(&ops[2].1),
        lifetime_product_id.clone(),
        early_adopter_product_id.clone(),
        standard_product_id.clone(),
        body.pricing_enabled,
        body.lifetime_visible,
        body.early_adopter_visible,
        body.standard_visible,
        admin.0.sub,
    )
    .await?;

    // Hot-reload the AuthService with the new tier config
    let resolved = TierConfig::from_db_row(&row);
    auth_service.reload_tier_config(resolved.clone());
    // BUNYIP-487: the public /pricing payload is derived from exactly this row
    // plus the Stripe price it maps to, so a save must not wait out the TTL.
    pricing_cache.invalidate();
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
                // BUNYIP-517: product ids are derived from the mapped prices, so
                // the audit records the derived values actually written.
                "lifetime_product_id": lifetime_product_id,
                "early_adopter_product_id": early_adopter_product_id,
                "standard_product_id": standard_product_id,
                "pricing_enabled": body.pricing_enabled,
                "lifetime_visible": body.lifetime_visible,
                "early_adopter_visible": body.early_adopter_visible,
                "standard_visible": body.standard_visible,
            })),
    )
    .await?;

    Ok(success(
        TierConfigWithPricing {
            pricing_enabled: resolved.pricing_enabled,
            lifetime_visible: resolved.lifetime_visible,
            early_adopter_visible: resolved.early_adopter_visible,
            standard_visible: resolved.standard_visible,
            config: TierConfigResponse {
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
        },
        request_id,
    ))
}

// =============================================================================
// Auto-ban Configuration (BUNYIP-351)
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct UpdateAutoBanConfigRequest {
    pub enabled: Option<bool>,
    pub threshold: Option<i64>,
    pub window_secs: Option<i64>,
    pub ban_duration_secs: Option<i64>,
}

/// GET /v1/admin/auto-ban-config
pub async fn get_auto_ban_config(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    use crate::config::AutoBanConfig;
    use crate::models::auto_ban::AutoBanConfigResponse;
    use crate::repositories::AutoBanConfigRepository;

    let request_id = get_request_id(&req);

    let row = AutoBanConfigRepository::get(&pool).await?;
    let resolved = AutoBanConfig::from_db_row(&row);
    let source = if AutoBanConfig::has_db_overrides(&row) {
        "database"
    } else {
        "environment"
    };

    Ok(success(
        AutoBanConfigResponse {
            enabled: resolved.enabled,
            threshold: resolved.threshold as i64,
            window_secs: resolved.window_secs as i64,
            ban_duration_secs: resolved.ban_duration_secs as i64,
            source,
            updated_at: row.updated_at,
            updated_by: row.updated_by,
        },
        request_id,
    ))
}

/// PUT /v1/admin/auto-ban-config
pub async fn update_auto_ban_config(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    auto_ban: web::Data<crate::middleware::AutoBanService>,
    body: web::Json<UpdateAutoBanConfigRequest>,
) -> Result<HttpResponse, AppError> {
    use crate::config::AutoBanConfig;
    use crate::models::auto_ban::AutoBanConfigResponse;
    use crate::repositories::AutoBanConfigRepository;

    let request_id = get_request_id(&req);

    // Validate: provided numeric values must be at least 1. A zero threshold /
    // window / duration would either ban on the first request or never expire,
    // both almost certainly operator error.
    if let Some(v) = body.threshold {
        if v < 1 {
            return Err(AppError::validation("threshold", "Must be at least 1"));
        }
    }
    if let Some(v) = body.window_secs {
        if v < 1 {
            return Err(AppError::validation("window_secs", "Must be at least 1"));
        }
    }
    if let Some(v) = body.ban_duration_secs {
        if v < 1 {
            return Err(AppError::validation(
                "ban_duration_secs",
                "Must be at least 1",
            ));
        }
    }

    let row = AutoBanConfigRepository::update(
        &pool,
        body.enabled,
        body.threshold,
        body.window_secs,
        body.ban_duration_secs,
        admin.0.sub,
    )
    .await?;

    // Hot-reload the running AutoBanService so changes apply without a restart.
    let resolved = AutoBanConfig::from_db_row(&row);
    auto_ban.reload(resolved);
    tracing::info!(?resolved, "Auto-ban config updated and hot-reloaded");

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::AdminAutoBanConfigUpdated)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_metadata(serde_json::json!({
                "setting": "auto_ban_config",
                "enabled": body.enabled,
                "threshold": body.threshold,
                "window_secs": body.window_secs,
                "ban_duration_secs": body.ban_duration_secs,
            })),
    )
    .await?;

    Ok(success(
        AutoBanConfigResponse {
            enabled: resolved.enabled,
            threshold: resolved.threshold as i64,
            window_secs: resolved.window_secs as i64,
            ban_duration_secs: resolved.ban_duration_secs as i64,
            source: "database",
            updated_at: row.updated_at,
            updated_by: row.updated_by,
        },
        request_id,
    ))
}

// =============================================================================
// Key Health Checks
// =============================================================================

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
///
/// BUNYIP-483: "healthy" means SOME key in the application set reads the value;
/// `needs_reencrypt` is true whenever it is not the current key/version, which
/// is what a row still on a retired key looks like during the consolidation
/// window (the version alone can no longer tell them apart).
fn evaluate_key_health(
    keys: &AppKeySet,
    ciphertext: Option<&[u8]>,
    nonce: Option<&[u8]>,
    key_version: Option<i16>,
) -> KeyHealthCheck {
    match (ciphertext, nonce) {
        (Some(ct), Some(n)) => {
            let version = key_version.unwrap_or(keys.current_version);
            let needs_reencrypt = Some(!keys.is_current(ct, n, version));
            match keys.decrypt(ct, n, version) {
                Ok(_) => KeyHealthCheck {
                    status: "healthy".to_string(),
                    has_data: true,
                    key_version,
                    needs_reencrypt,
                    message: None,
                },
                Err(e) => KeyHealthCheck {
                    status: "unhealthy".to_string(),
                    has_data: true,
                    key_version,
                    needs_reencrypt,
                    message: Some(e.to_string()),
                },
            }
        }
        _ => KeyHealthCheck {
            status: "no_data".to_string(),
            has_data: false,
            key_version: None,
            needs_reencrypt: None,
            message: None,
        },
    }
}

async fn check_stripe_key(pool: &PgPool, keys: &AppKeySet) -> Result<KeyHealthCheck, AppError> {
    let db = StripeConfigRepository::get(pool).await?;
    Ok(evaluate_key_health(
        keys,
        db.secret_key.as_deref(),
        db.secret_key_nonce.as_deref(),
        Some(db.key_version),
    ))
}

async fn check_totp_key(pool: &PgPool, keys: &AppKeySet) -> Result<KeyHealthCheck, AppError> {
    let row: Option<(Vec<u8>, Vec<u8>, i16)> =
        sqlx::query_as("SELECT encrypted_secret, nonce, key_version FROM user_totp LIMIT 1")
            .fetch_optional(pool)
            .await?;

    Ok(match row {
        Some((ct, nonce, kv)) => evaluate_key_health(keys, Some(&ct), Some(&nonce), Some(kv)),
        None => evaluate_key_health(keys, None, None, None),
    })
}

async fn check_email_key(pool: &PgPool, keys: &AppKeySet) -> Result<KeyHealthCheck, AppError> {
    let row = EmailConfigRepository::get(pool).await?;
    Ok(evaluate_key_health(
        keys,
        row.smtp_password.as_deref(),
        row.smtp_password_nonce.as_deref(),
        Some(row.key_version),
    ))
}

/// Dispatch a key health check by key_id. Every id now checks the SAME
/// application key (BUNYIP-483); they differ in which stored secret they read.
async fn run_key_check(
    key_id: &str,
    pool: &PgPool,
    keys: &AppKeySet,
) -> Result<KeyHealthCheck, AppError> {
    match key_id {
        "stripe" => check_stripe_key(pool, keys).await,
        "totp" => check_totp_key(pool, keys).await,
        "email" => check_email_key(pool, keys).await,
        _ => Err(AppError::not_found(format!("Unknown key: {key_id}"))),
    }
}

/// All registered key IDs. Update this when a new store is encrypted at rest.
const KEY_IDS: &[&str] = &["stripe", "totp", "email"];

/// GET /v1/admin/key-health
/// Aggregated health check for all encryption keys.
pub async fn get_key_health(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let keys = config.app_key_set();

    let mut checks = serde_json::Map::new();
    let mut any_unhealthy = false;

    for &key_id in KEY_IDS {
        let check = run_key_check(key_id, &pool, &keys).await?;
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
    let check = run_key_check(&key_id, &pool, &config.app_key_set()).await?;
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

    // BUNYIP-483: one key version for every store.
    let current_version = config.app_key_version;

    match key_id.as_str() {
        "totp" => {
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
            let db = StripeConfigRepository::get(&pool).await?;
            let has_secrets = db.secret_key.is_some() || db.webhook_secret.is_some();
            let on_current = db.key_version == current_version;

            Ok(success(
                singleton_rotation_status("stripe", current_version, has_secrets, on_current),
                request_id,
            ))
        }
        "email" => {
            let row = EmailConfigRepository::get(&pool).await?;
            let has_secrets = row.smtp_password.is_some();
            let on_current = row.key_version == current_version;

            Ok(success(
                singleton_rotation_status("email", current_version, has_secrets, on_current),
                request_id,
            ))
        }
        _ => Err(AppError::not_found(format!("Unknown key: {key_id}"))),
    }
}

/// Rotation status for a singleton config row (`stripe_config`, `email_config`):
/// zero or one encrypted record.
fn singleton_rotation_status(
    key_id: &str,
    current_version: i16,
    has_secrets: bool,
    on_current: bool,
) -> serde_json::Value {
    serde_json::json!({
        "key_id": key_id,
        "current_version": current_version,
        "total": if has_secrets { 1 } else { 0 },
        "on_current_version": if has_secrets && on_current { 1 } else { 0 },
        "on_old_versions": if has_secrets && !on_current { 1 } else { 0 },
        "rotation_complete": !has_secrets || on_current,
    })
}

/// POST /v1/admin/key-rotation/{key_id}/reencrypt
/// Re-encrypts every record that is not already on the current key (BUNYIP-483:
/// one application key, so "not current" covers both an older key version and a
/// row still written under a retired key). Delegates to the same pass the
/// `bunyip-api reencrypt-secrets` subcommand runs, and is idempotent.
pub async fn reencrypt_key(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    app_key_set: web::Data<AppKeySet>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let key_id = path.into_inner();

    let summary = match key_id.as_str() {
        "totp" => crate::reencrypt::reencrypt_totp(&pool, &app_key_set).await?,
        "stripe" => crate::reencrypt::reencrypt_stripe(&pool, &app_key_set).await?,
        "email" => crate::reencrypt::reencrypt_email(&pool, &app_key_set).await?,
        _ => return Err(AppError::not_found(format!("Unknown key: {key_id}"))),
    };

    let current_version = app_key_set.current_version;
    let total = summary.rewritten + summary.already_current + summary.undecryptable.len() as u64;

    let audit_log = CreateAuditLog::new(AuditAction::AdminKeyRotation)
        .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
        .with_metadata(serde_json::json!({
            "key_id": key_id,
            "reencrypted": summary.rewritten,
            "total": total,
            "undecryptable": summary.undecryptable.len(),
            "new_version": current_version,
        }));
    AuditLogRepository::create(&pool, audit_log).await?;

    Ok(success(
        serde_json::json!({
            "key_id": key_id,
            "reencrypted": summary.rewritten,
            "total": total,
            // Values no key in the set decrypts are reported, never cleared: the
            // operator has to supply the missing key and re-run.
            "undecryptable": summary.undecryptable,
            "key_version": current_version,
        }),
        request_id,
    ))
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

    // BUNYIP-517: deriving the tier's product id from its mapped price.

    fn price(id: &str, product_id: &str, active: bool) -> StripePriceResponse {
        StripePriceResponse {
            id: id.into(),
            product_id: product_id.into(),
            unit_amount: Some(300),
            currency: "usd".into(),
            recurring_interval: Some("month".into()),
            recurring_interval_count: Some(1),
            active,
        }
    }

    #[test]
    fn derive_product_for_price_returns_the_active_prices_product() {
        let prices = [
            price("price_std", "prod_std", true),
            price("price_ea", "prod_ea", true),
        ];
        assert_eq!(
            derive_product_for_price("Standard", "price_std", &prices, "bunyip").unwrap(),
            "prod_std"
        );
    }

    #[test]
    fn derive_product_for_price_refuses_an_archived_price_by_name() {
        let prices = [price("price_old", "prod_std", false)];
        let err = derive_product_for_price("Standard", "price_old", &prices, "bunyip").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Standard"), "names the tier: {msg}");
        assert!(msg.contains("archived"), "names the reason: {msg}");
    }

    #[test]
    fn derive_product_for_price_refuses_an_invisible_price_naming_the_app_tag() {
        let prices = [price("price_std", "prod_std", true)];
        let err = derive_product_for_price("Early adopter", "price_ghost", &prices, "bunyip")
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Early adopter"), "names the tier: {msg}");
        assert!(
            msg.contains("app tag `bunyip`"),
            "names the app tag so the admin can fix product metadata: {msg}"
        );
    }

    // BUNYIP-474: a dataset is stale only once it is past the refresh cadence;
    // an unread/unconfigured file (None age) is never "stale" (it is "not
    // present" instead, a distinct state the readout shows separately).
    #[test]
    fn dataset_staleness_tracks_the_refresh_cadence() {
        assert!(
            !dataset_is_stale(None),
            "unconfigured/unreadable is not stale"
        );
        assert!(!dataset_is_stale(Some(0)), "a fresh file is not stale");
        assert!(
            !dataset_is_stale(Some(DATASET_STALE_AFTER_DAYS)),
            "at the threshold is not yet stale"
        );
        assert!(
            dataset_is_stale(Some(DATASET_STALE_AFTER_DAYS + 1)),
            "past the threshold is stale"
        );
    }

    #[test]
    fn dataset_health_reports_unconfigured_cleanly() {
        // Unconfigured: not configured, not present, no age, not stale (never a
        // false alarm for a dataset an operator chose not to deploy).
        let d = dataset_health("X", "X_DB_PATH", None);
        assert!(!d.configured && !d.present && d.age_days.is_none() && !d.stale);
        // A configured but missing file is configured-but-not-present, still not
        // "stale" (you cannot age a file that is not there).
        let d = dataset_health("X", "X_DB_PATH", Some("/no/such/file.BIN"));
        assert!(d.configured && !d.present && d.age_days.is_none() && !d.stale);
    }

    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
    }

    // -- BUNYIP-432: SMTP password is write-only ------------------------------

    #[test]
    fn email_config_response_never_carries_the_password() {
        // The settings payload must contain no representation of the SMTP
        // password - not the plaintext, not a masked/last-4 form - only the
        // has_smtp_password boolean.
        let resp = crate::models::email::EmailConfigResponse {
            enabled: true,
            smtp_host: "smtp.example.com".into(),
            smtp_port: 587,
            smtp_tls: "starttls".into(),
            smtp_username: "postmaster@example.com".into(),
            has_smtp_password: true,
            from_email: "no-reply@example.com".into(),
            from_name: "Bunyip".into(),
            admin_notification_emails: vec!["ops@example.com".into()],
            source: "database",
            secrets_storage: "database",
            smtp_password_editable: true,
            updated_at: None,
            updated_by: None,
        };
        let body = serde_json::to_string(&resp).unwrap();
        assert!(
            body.contains("\"has_smtp_password\":true"),
            "the boolean fact is present"
        );
        assert!(
            !body.contains("smtp_password_masked"),
            "no masked-password field is serialized"
        );
        // The only `password` tokens are the two boolean keys (BUNYIP-432's
        // has_smtp_password and BUNYIP-542's smtp_password_editable); any
        // password value or masked field would add another.
        assert_eq!(
            body.matches("password").count(),
            2,
            "the only password tokens are has_smtp_password and smtp_password_editable: {body}"
        );
    }

    // -- BUNYIP-431: admin tier move ------------------------------------------

    #[test]
    fn parse_admin_tier_accepts_every_tier_and_rejects_unknown() {
        assert_eq!(
            parse_admin_tier("lifetime").unwrap(),
            MembershipTier::Lifetime
        );
        assert_eq!(parse_admin_tier("free").unwrap(), MembershipTier::Free);
        assert_eq!(
            parse_admin_tier("early_adopter").unwrap(),
            MembershipTier::EarlyAdopter
        );
        assert_eq!(
            parse_admin_tier(" standard ").unwrap(),
            MembershipTier::Standard
        );
        assert!(
            parse_admin_tier("gold").is_err(),
            "an unknown tier is a client error, never a silent downgrade to Standard"
        );
        assert!(parse_admin_tier("").is_err());
    }

    #[test]
    fn cancelled_2fa_plans_no_change() {
        // AC6: a failed 2FA code yields Err before any mutation, so the tier and
        // every slot count stay put.
        assert!(
            plan_admin_tier_move(false, &MembershipTier::Standard, &MembershipTier::Lifetime)
                .is_err()
        );
        assert!(
            plan_admin_tier_move(false, &MembershipTier::Lifetime, &MembershipTier::Standard)
                .is_err()
        );
    }

    #[test]
    fn upgrade_to_lifetime_mints_invoice_and_revokes_sessions() {
        let plan = plan_admin_tier_move(true, &MembershipTier::Standard, &MembershipTier::Lifetime)
            .unwrap();
        assert_eq!(
            plan,
            TierMovePlan {
                create_lifetime_invoice: true,
                revoke_sessions: true
            }
        );
    }

    #[test]
    fn upgrade_between_non_lifetime_tiers_revokes_sessions_without_invoice() {
        let plan = plan_admin_tier_move(
            true,
            &MembershipTier::Standard,
            &MembershipTier::EarlyAdopter,
        )
        .unwrap();
        assert_eq!(
            plan,
            TierMovePlan {
                create_lifetime_invoice: false,
                revoke_sessions: true
            }
        );
    }

    #[test]
    fn downgrade_from_lifetime_revokes_sessions_without_new_invoice() {
        let plan = plan_admin_tier_move(true, &MembershipTier::Lifetime, &MembershipTier::Standard)
            .unwrap();
        assert_eq!(
            plan,
            TierMovePlan {
                create_lifetime_invoice: false,
                revoke_sessions: true
            }
        );
    }

    #[test]
    fn same_tier_move_touches_no_sessions_and_no_invoice() {
        let plan = plan_admin_tier_move(
            true,
            &MembershipTier::EarlyAdopter,
            &MembershipTier::EarlyAdopter,
        )
        .unwrap();
        assert_eq!(
            plan,
            TierMovePlan {
                create_lifetime_invoice: false,
                revoke_sessions: false
            }
        );
    }

    #[test]
    fn members_by_tier_sql_filters_by_tier_and_orders_by_claim_order() {
        // BUNYIP-291 AC4: the members-by-tier list must filter on the tier
        // column, exclude soft-deleted rows, and order oldest-first so
        // early-adopter slot occupancy reads in the order slots were claimed.
        let sql = MEMBERS_BY_TIER_SQL;
        assert!(
            sql.contains("membership_tier, 'standard') = $3"),
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
            release_notes_url: None,
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
    use crate::services::AppKeySet;

    fn test_key() -> [u8; 32] {
        [0xAA; 32]
    }

    fn test_key_set() -> AppKeySet {
        AppKeySet {
            current: test_key(),
            current_version: 1,
            previous: Vec::new(),
        }
    }

    fn key_set_with(current: [u8; 32], version: i16, previous: Vec<[u8; 32]>) -> AppKeySet {
        AppKeySet {
            current,
            current_version: version,
            previous,
        }
    }

    // ---- evaluate_key_health ----

    #[test]
    fn healthy_when_decrypt_succeeds() {
        let ks = test_key_set();
        let (ct, nonce, _) = ks.encrypt(b"test-secret").unwrap();

        let result = evaluate_key_health(&ks, Some(&ct), Some(&nonce), Some(1));

        assert_eq!(result.status, "healthy");
        assert!(result.has_data);
        assert_eq!(result.key_version, Some(1));
        assert_eq!(result.needs_reencrypt, Some(false));
        assert!(result.message.is_none());
    }

    #[test]
    fn unhealthy_when_no_key_in_the_set_matches() {
        let ks = test_key_set();
        let (ct, nonce, _) = ks.encrypt(b"test-secret").unwrap();

        let other = key_set_with([0xBB; 32], 1, Vec::new());
        let result = evaluate_key_health(&other, Some(&ct), Some(&nonce), Some(1));

        assert_eq!(result.status, "unhealthy");
        assert!(result.has_data);
        assert!(result.message.is_some());
    }

    #[test]
    fn unhealthy_when_tampered_ciphertext() {
        let ks = test_key_set();
        let (mut ct, nonce, _) = ks.encrypt(b"test-secret").unwrap();
        ct[0] ^= 0xFF;

        let result = evaluate_key_health(&ks, Some(&ct), Some(&nonce), Some(1));

        assert_eq!(result.status, "unhealthy");
        assert!(result.has_data);
        assert!(result.message.is_some());
    }

    #[test]
    fn no_data_when_both_none() {
        let result = evaluate_key_health(&test_key_set(), None, None, None);

        assert_eq!(result.status, "no_data");
        assert!(!result.has_data);
        assert!(result.key_version.is_none());
        assert!(result.needs_reencrypt.is_none());
        assert!(result.message.is_none());
    }

    #[test]
    fn no_data_when_ciphertext_without_nonce() {
        let ks = test_key_set();
        let (ct, _nonce, _) = ks.encrypt(b"test-secret").unwrap();

        let result = evaluate_key_health(&ks, Some(&ct), None, Some(1));

        assert_eq!(result.status, "no_data");
        assert!(!result.has_data);
    }

    #[test]
    fn no_data_when_nonce_without_ciphertext() {
        let ks = test_key_set();
        let (_ct, nonce, _) = ks.encrypt(b"test-secret").unwrap();

        let result = evaluate_key_health(&ks, None, Some(&nonce), Some(1));

        assert_eq!(result.status, "no_data");
        assert!(!result.has_data);
    }

    #[test]
    fn needs_reencrypt_when_version_mismatch() {
        let ks = test_key_set();
        let (ct, nonce, _) = ks.encrypt(b"test-secret").unwrap();

        // Record is version 1, current version is 2.
        let rotated = key_set_with(test_key(), 2, Vec::new());
        let result = evaluate_key_health(&rotated, Some(&ct), Some(&nonce), Some(1));

        assert_eq!(result.status, "healthy");
        assert_eq!(result.needs_reencrypt, Some(true));
    }

    /// BUNYIP-483: a row still on a retired key reads fine (it is listed in
    /// APP_ENCRYPTION_KEY_PREV) but is flagged for the re-encrypt pass, even
    /// though its stored version matches the current one.
    #[test]
    fn healthy_but_needs_reencrypt_for_a_row_on_a_previous_key() {
        let legacy = key_set_with([0xCC; 32], 1, Vec::new());
        let (ct, nonce, _) = legacy.encrypt(b"legacy-secret").unwrap();

        let consolidated = key_set_with(test_key(), 1, vec![[0xCC; 32]]);
        let result = evaluate_key_health(&consolidated, Some(&ct), Some(&nonce), Some(1));

        assert_eq!(result.status, "healthy");
        assert_eq!(result.needs_reencrypt, Some(true));
    }

    // ---- KEY_IDS registry ----

    #[test]
    fn key_ids_cover_every_at_rest_store() {
        assert!(KEY_IDS.contains(&"stripe"));
        assert!(KEY_IDS.contains(&"totp"));
        assert!(KEY_IDS.contains(&"email"));
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

    // -- BUNYIP-508: admin "Test email" send ----------------------------------

    /// A failed send is a diagnostic result, not an API error: it stays a 200
    /// carrying `ok: false` plus the relay's own text, because a 5xx would be
    /// collapsed to a generic line before the admin ever sees it (BUNYIP-477).
    #[test]
    fn test_send_failure_reports_the_relay_reason_not_a_server_error() {
        let (ok, message) = test_send_outcome(&Ok(()));
        assert!(ok, "a completed send reports ok");
        assert!(!message.is_empty(), "success still names what happened");

        let failed: Result<(), AppError> =
            Err(AppError::internal("Email send error: connection refused"));
        let (ok, message) = test_send_outcome(&failed);
        assert!(!ok, "a failed send is never reported as ok");
        assert_eq!(
            message, "Email send error: connection refused",
            "the relay's own reason reaches the admin, without the internal wrapper"
        );
    }

    fn test_user(role: &str) -> crate::models::User {
        crate::models::User {
            id: uuid::Uuid::new_v4(),
            email: "probe@example.test".to_string(),
            email_verified: true,
            password_hash: None,
            role: role.to_string(),
            stripe_customer_id: None,
            stripe_payment_method_id: None,
            membership_status: "active".to_string(),
            price_locked: false,
            locked_price_id: None,
            locked_price_amount: None,
            grace_period_start: None,
            grace_period_end: None,
            two_factor_enabled: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login_at: None,
            last_login_country: None,
            login_location_alerts: true,
            deleted_at: None,
            membership_tier: "standard".to_string(),
            trial_ends_at: None,
            lifetime_member: false,
            membership_override_by: None,
            first_name: None,
            last_name: None,
            phone: None,
            has_used_trial: false,
            avatar_updated_at: None,
            is_super_admin: false,
        }
    }

    /// The `AdminUser` extractor is the whole admin restriction on the send
    /// endpoint: no token is a 401 and a non-admin token is a 403, both before
    /// the handler (and therefore the relay) is ever reached.
    #[actix_rt::test]
    async fn test_send_endpoint_is_admin_only() {
        use crate::services::{JwtConfig, JwtService};
        use actix_web::{test, App};

        let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
            "bunyip-508-test-secret-at-least-32-bytes-long",
            "bunyip-test",
        )));
        let token = jwt
            .create_access_token(&test_user("subscriber"))
            .expect("mint access token");

        let app = test::init_service(
            App::new()
                .app_data(jwt.clone())
                .route("/email/test-send", web::post().to(send_test_email_message)),
        )
        .await;

        let anon = test::TestRequest::post()
            .uri("/email/test-send")
            .to_request();
        assert_eq!(
            test::call_service(&app, anon).await.status().as_u16(),
            401,
            "unauthenticated callers cannot send"
        );

        let subscriber = test::TestRequest::post()
            .uri("/email/test-send")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request();
        assert_eq!(
            test::call_service(&app, subscriber).await.status().as_u16(),
            403,
            "a non-admin token cannot send"
        );
    }
}
