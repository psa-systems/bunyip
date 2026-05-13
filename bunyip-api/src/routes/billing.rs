use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use bunyip_mocks::{AuditLog, MembershipRole, Subscription, SubscriptionStatus, TierConfig};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::errors::AppError;
use crate::routes::auth::current_user_id;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/billing/tiers", get(list_tiers))
        .route("/v1/orgs/{slug}/billing", get(get_billing))
        .route("/v1/orgs/{slug}/billing/checkout", post(create_checkout))
        .route("/v1/orgs/{slug}/billing/portal", post(create_portal_session))
        .route("/v1/orgs/{slug}/billing/cancel", post(cancel_subscription))
        .route("/v1/orgs/{slug}/billing/uncancel", post(uncancel_subscription))
        .route("/v1/stripe/webhook", post(stripe_webhook_stub))
}

async fn list_tiers(State(state): State<AppState>) -> Json<Vec<TierConfig>> {
    let mut tiers = state.store.read().tier_config.clone();
    tiers.sort_by_key(|t| t.sort_order);
    Json(tiers)
}

#[derive(Debug, Serialize)]
pub struct BillingView {
    pub subscription: Option<Subscription>,
    pub tier: Option<TierConfig>,
}

async fn get_billing(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(slug): Path<String>,
) -> Result<Json<BillingView>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let store = state.store.read();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if store.role_in_org(uid, org.id).is_none() {
        return Err(AppError::Forbidden);
    }
    let subscription = store.subscription_for_org(org.id);
    let tier = subscription.as_ref().and_then(|s| {
        store
            .tier_config
            .iter()
            .find(|t| t.tier_key == s.tier_key)
            .cloned()
    });
    Ok(Json(BillingView { subscription, tier }))
}

#[derive(Debug, Deserialize)]
pub struct CheckoutRequest {
    pub tier_key: String,
}

#[derive(Debug, Serialize)]
pub struct CheckoutResponse {
    pub url: String,
}

async fn create_checkout(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(slug): Path<String>,
    Json(body): Json<CheckoutRequest>,
) -> Result<Json<CheckoutResponse>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if !matches!(store.role_in_org(uid, org.id), Some(MembershipRole::Owner | MembershipRole::Admin)) {
        return Err(AppError::Forbidden);
    }
    // Simulate the checkout: just upgrade the org's subscription to the requested tier.
    let now = Utc::now();
    let new_sub = Subscription {
        org_id: org.id,
        stripe_subscription_id: Some(format!("sub_mock_{}", Uuid::new_v4().simple())),
        tier_key: body.tier_key.clone(),
        status: SubscriptionStatus::Active,
        trial_end: None,
        current_period_end: Some(now + Duration::days(30)),
        cancel_at_period_end: false,
        grace_period_end: None,
        subscription_override_by: None,
    };
    if let Some(s) = store.subscriptions.iter_mut().find(|s| s.org_id == org.id) {
        *s = new_sub.clone();
    } else {
        store.subscriptions.push(new_sub.clone());
    }
    store.log_audit(AuditLog {
        id: Uuid::new_v4(),
        actor_user_id: Some(uid),
        org_id: Some(org.id),
        action: "billing.checkout.completed".to_string(),
        target: Some(body.tier_key.clone()),
        ip: None,
        user_agent: None,
        is_admin_action: false,
        ts: now,
    });
    // In MVP we just return a redirect URL to a fake Stripe page. The frontend
    // can either follow it (visual demo) or jump straight to the billing page.
    Ok(Json(CheckoutResponse {
        url: format!(
            "{}/mock-stripe/success?tier={}",
            state.config.public_base_url, body.tier_key
        ),
    }))
}

#[derive(Debug, Serialize)]
pub struct PortalResponse {
    pub url: String,
}

async fn create_portal_session(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(slug): Path<String>,
) -> Result<Json<PortalResponse>, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let store = state.store.read();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if !matches!(store.role_in_org(uid, org.id), Some(MembershipRole::Owner | MembershipRole::Admin)) {
        return Err(AppError::Forbidden);
    }
    Ok(Json(PortalResponse {
        url: format!("{}/mock-stripe/portal?org={}", state.config.public_base_url, org.slug),
    }))
}

async fn cancel_subscription(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(slug): Path<String>,
) -> Result<StatusCode, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if !matches!(store.role_in_org(uid, org.id), Some(MembershipRole::Owner | MembershipRole::Admin)) {
        return Err(AppError::Forbidden);
    }
    if let Some(s) = store.subscriptions.iter_mut().find(|s| s.org_id == org.id) {
        s.cancel_at_period_end = true;
    }
    store.log_audit(AuditLog {
        id: Uuid::new_v4(),
        actor_user_id: Some(uid),
        org_id: Some(org.id),
        action: "billing.subscription.cancel".to_string(),
        target: None,
        ip: None,
        user_agent: None,
        is_admin_action: false,
        ts: Utc::now(),
    });
    Ok(StatusCode::NO_CONTENT)
}

async fn uncancel_subscription(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(slug): Path<String>,
) -> Result<StatusCode, AppError> {
    let uid = current_user_id(&cookies).ok_or(AppError::Unauthorized)?;
    let mut store = state.store.write();
    let org = store.org_by_slug(&slug).ok_or(AppError::NotFound)?;
    if !matches!(store.role_in_org(uid, org.id), Some(MembershipRole::Owner | MembershipRole::Admin)) {
        return Err(AppError::Forbidden);
    }
    if let Some(s) = store.subscriptions.iter_mut().find(|s| s.org_id == org.id) {
        s.cancel_at_period_end = false;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn stripe_webhook_stub() -> StatusCode {
    // In production this would verify signature + dispatch events. For MVP
    // we have no real Stripe, so this endpoint just acknowledges 200.
    StatusCode::OK
}
