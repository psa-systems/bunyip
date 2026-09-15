//! BUNYIP-693 [BUNYIP-626 followup]: HTTP handlers for
//! `/v1/organization/subscription`.
//!
//! Every method gates on `orgs_enabled` inside the service. The
//! [`OrgBillingProvider`] impl in `crate::org_billing_provider` is what
//! actually calls Stripe; the handler just resolves the flag and passes
//! it plus the provider to the service, matching the shape the
//! organizations + org_pricing handlers already use.

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;
use std::sync::{Arc, RwLock};

use bunyip_domain::errors::AppError;
use bunyip_domain::middleware::AuthenticatedUser;
use bunyip_domain::services::OrgBillingService;

use crate::config::TierConfig;
use crate::org_billing_provider::StripeOrgBillingProvider;
use crate::responses::{get_request_id, success};

fn orgs_enabled(tier_config: &Arc<RwLock<TierConfig>>) -> bool {
    tier_config
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .orgs_enabled
}

pub async fn get_subscription(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let snap = OrgBillingService::get_snapshot(pool.get_ref(), flag, user.0.sub).await?;
    Ok(success(snap, request_id))
}

pub async fn subscribe(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    provider: web::Data<Arc<StripeOrgBillingProvider>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let snap = OrgBillingService::subscribe(
        pool.get_ref(),
        flag,
        provider.get_ref().as_ref(),
        user.0.sub,
    )
    .await?;
    Ok(success(snap, request_id))
}

pub async fn change_tier(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    provider: web::Data<Arc<StripeOrgBillingProvider>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let snap = OrgBillingService::change_tier(
        pool.get_ref(),
        flag,
        provider.get_ref().as_ref(),
        user.0.sub,
    )
    .await?;
    Ok(success(snap, request_id))
}

pub async fn cancel(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    tier_config: web::Data<Arc<RwLock<TierConfig>>>,
    provider: web::Data<Arc<StripeOrgBillingProvider>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let flag = orgs_enabled(tier_config.get_ref());
    let snap = OrgBillingService::cancel(
        pool.get_ref(),
        flag,
        provider.get_ref().as_ref(),
        user.0.sub,
    )
    .await?;
    Ok(success(snap, request_id))
}
