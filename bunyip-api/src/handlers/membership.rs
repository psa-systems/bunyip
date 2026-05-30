//! Membership handlers
//!
//! This module contains HTTP handlers for membership management endpoints.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json;
use sqlx::PgPool;
use std::sync::Arc;

use crate::config::Config;
use crate::errors::AppError;
use crate::middleware::{AuthCookies, AuthenticatedUser};
use crate::models::MembershipResponse;
use crate::repositories::UserRepository;
use crate::responses::{get_request_id, success};
use crate::services::{JwtService, StripeService};

/// Request for creating a checkout session
#[derive(Debug, Deserialize)]
pub struct CheckoutRequest {
    /// The Stripe price ID to checkout with
    pub price_id: Option<String>,
}

/// Response for checkout session creation
#[derive(Debug, Serialize)]
pub struct CheckoutResponse {
    pub checkout_url: String,
    pub session_id: String,
}

/// Response for billing portal
#[derive(Debug, Serialize)]
pub struct PortalResponse {
    pub url: String,
}

/// Payment response from Stripe invoices
#[derive(Debug, Serialize)]
pub struct StripePaymentResponse {
    pub id: String,
    pub amount: i64,
    pub currency: String,
    pub status: Option<String>,
    pub created: i64,
    pub invoice_pdf: Option<String>,
}

/// GET /v1/memberships/me
/// Get current user's membership status
pub async fn get_membership(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Get user from database for fresh data
    let db_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    // If user has a Stripe customer, fetch live subscription data
    let (current_period_end, cancel_at_period_end) =
        if let Some(ref customer_id) = db_user.stripe_customer_id {
            match stripe.get_customer_subscription(customer_id).await? {
                Some(sub) => {
                    let period_end = chrono::DateTime::from_timestamp(sub.current_period_end, 0);
                    (period_end, sub.cancel_at_period_end)
                }
                None => (None, false),
            }
        } else {
            (None, false)
        };

    let response = MembershipResponse {
        status: db_user.membership_status.clone(),
        price_locked: db_user.price_locked,
        locked_price_amount: db_user.locked_price_amount,
        current_period_end,
        cancel_at_period_end,
        grace_period_end: db_user.grace_period_end,
    };

    Ok(success(response, request_id))
}

/// POST /v1/memberships/checkout
/// Create a Stripe checkout session
pub async fn create_checkout(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    body: web::Json<CheckoutRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Lock the user row to prevent concurrent Stripe customer creation
    let mut tx = pool.begin().await?;
    let db_user = sqlx::query_as::<_, crate::models::User>(
        "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(user.0.sub)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AppError::not_found("User"))?;

    // Check if user already has active membership
    if db_user.membership_status == "active" {
        return Err(AppError::conflict("You already have an active membership"));
    }

    // Use the provided price_id, or discover the first active price from Stripe
    let price_id = match &body.price_id {
        Some(id) => id.clone(),
        None => {
            let prices = stripe.list_prices(None).await?;
            prices
                .into_iter()
                .find(|p| p.active)
                .map(|p| p.id)
                .ok_or_else(|| AppError::validation("price_id", "No active price configured"))?
        }
    };

    // Get or create Stripe customer
    let customer_id = match db_user.stripe_customer_id {
        Some(id) => id,
        None => {
            let customer_id = stripe.create_customer(&db_user.email, db_user.id).await?;
            UserRepository::update_stripe_customer_id(&mut *tx, db_user.id, &customer_id).await?;
            customer_id
        }
    };
    tx.commit().await?;

    // Create checkout session with the price
    let (session_id, checkout_url) = stripe
        .create_checkout_session(&customer_id, db_user.id, &price_id)
        .await?;

    tracing::info!(
        user_id = %db_user.id,
        price_id = %price_id,
        "Created checkout session for user"
    );

    Ok(success(
        CheckoutResponse {
            checkout_url,
            session_id,
        },
        request_id,
    ))
}

/// POST /v1/memberships/cancel
/// Cancel membership at end of current billing period
pub async fn cancel_membership(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    config: web::Data<Config>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Get jwt_service from app data
    let jwt_service = req
        .app_data::<Arc<JwtService>>()
        .ok_or_else(|| AppError::internal("JWT service not configured"))?;

    // Get current user to check status
    let db_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    if db_user.membership_status == "canceled" || db_user.membership_status == "none" {
        return Err(AppError::conflict("No active membership to cancel"));
    }

    // Cancel in Stripe (at period end so user keeps access until billing cycle ends)
    if let Some(ref customer_id) = db_user.stripe_customer_id {
        if let Some(sub) = stripe.get_customer_subscription(customer_id).await? {
            stripe.cancel_subscription(&sub.id, true).await?;
        }
    } else {
        // No Stripe customer — just update status directly
        UserRepository::update_membership_status(
            pool.get_ref(),
            user.0.sub,
            crate::models::MembershipStatus::Canceled,
        )
        .await?;
        UserRepository::reset_subscription_tier(pool.get_ref(), user.0.sub).await?;
    }

    // Fetch updated user
    let updated_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    tracing::info!(
        user_id = %updated_user.id,
        "User canceled membership"
    );

    // Create new access token with updated claims
    let access_token = jwt_service.create_access_token(&updated_user)?;

    // Determine if we should use secure cookies
    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();

    Ok(HttpResponse::Ok()
        .cookie(AuthCookies::access_token(
            &access_token,
            secure,
            cookie_domain,
        ))
        .json(crate::responses::ApiResponse {
            success: true,
            data: Some(serde_json::json!({
                "message": "Membership will be canceled at end of billing period",
                "membership_status": updated_user.membership_status
            })),
            meta: crate::responses::ResponseMeta::new(request_id),
        }))
}

/// POST /v1/memberships/cancel-now
/// Cancel membership immediately (for testing/development)
pub async fn cancel_membership_immediate(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    config: web::Data<Config>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let jwt_service = req
        .app_data::<Arc<JwtService>>()
        .ok_or_else(|| AppError::internal("JWT service not configured"))?;

    let db_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    if db_user.membership_status == "canceled" || db_user.membership_status == "none" {
        return Err(AppError::conflict("No active membership to cancel"));
    }

    // Cancel immediately in Stripe
    if let Some(ref customer_id) = db_user.stripe_customer_id {
        if let Some(sub) = stripe.get_customer_subscription(customer_id).await? {
            stripe.cancel_subscription(&sub.id, false).await?;
        }
    }

    // Update user status immediately
    UserRepository::update_membership_status(
        pool.get_ref(),
        user.0.sub,
        crate::models::MembershipStatus::Canceled,
    )
    .await?;
    UserRepository::reset_subscription_tier(pool.get_ref(), user.0.sub).await?;

    let updated_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    tracing::info!(user_id = %updated_user.id, "User canceled membership immediately");

    let access_token = jwt_service.create_access_token(&updated_user)?;
    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();

    Ok(HttpResponse::Ok()
        .cookie(AuthCookies::access_token(
            &access_token,
            secure,
            cookie_domain,
        ))
        .json(crate::responses::ApiResponse {
            success: true,
            data: Some(serde_json::json!({
                "message": "Membership canceled immediately",
                "membership_status": "canceled"
            })),
            meta: crate::responses::ResponseMeta::new(request_id),
        }))
}

/// POST /v1/memberships/reactivate
/// Reactivate a membership that's scheduled for cancellation
pub async fn reactivate_membership(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Get user to find Stripe customer
    let db_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    let customer_id = db_user
        .stripe_customer_id
        .ok_or(AppError::not_found("No billing account found"))?;

    // Get subscription from Stripe
    let sub = stripe
        .get_customer_subscription(&customer_id)
        .await?
        .ok_or(AppError::not_found("Subscription"))?;

    if !sub.cancel_at_period_end {
        return Err(AppError::conflict(
            "Membership is not scheduled for cancellation",
        ));
    }

    // Reactivate in Stripe
    stripe.reactivate_subscription(&sub.id).await?;

    Ok(crate::responses::success_no_data(request_id))
}

/// POST /v1/memberships/billing-portal
/// Get a link to the Stripe billing portal
pub async fn billing_portal(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // Get user from database
    let db_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    let customer_id = db_user
        .stripe_customer_id
        .ok_or(AppError::not_found("No billing account found"))?;

    let url = stripe.create_billing_portal_session(&customer_id).await?;

    Ok(success(PortalResponse { url }, request_id))
}

/// GET /v1/memberships/payments
/// Get payment history from Stripe
pub async fn get_payment_history(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    let db_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    let payments = if let Some(ref customer_id) = db_user.stripe_customer_id {
        let limit = query.per_page.map(|p| p.min(100).max(1) as u64);
        let invoices = stripe.list_customer_invoices(customer_id, limit).await?;
        invoices
            .into_iter()
            .map(|inv| StripePaymentResponse {
                id: inv.id,
                amount: inv.amount_paid,
                currency: inv.currency,
                status: inv.status,
                created: inv.created,
                invoice_pdf: inv.invoice_pdf,
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok(success(payments, request_id))
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
}

/// Response for subscription activation
#[derive(Debug, Serialize)]
pub struct SubscribeResponse {
    pub message: String,
    pub membership_status: String,
}

/// POST /v1/memberships/subscribe
/// Activate membership (temporary endpoint for development)
/// In production, this would be triggered by Stripe webhook after successful payment
pub async fn subscribe(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
) -> Result<HttpResponse, AppError> {
    // Get jwt_service from app data (it's registered as Arc<JwtService>)
    let jwt_service = req
        .app_data::<Arc<JwtService>>()
        .ok_or_else(|| AppError::internal("JWT service not configured"))?;
    let request_id = get_request_id(&req);

    // Activate membership in database
    let updated_user = UserRepository::activate_membership(&pool, user.0.sub).await?;

    tracing::info!(
        user_id = %updated_user.id,
        "User subscribed to membership"
    );

    // Create new access token with updated claims
    let access_token = jwt_service.create_access_token(&updated_user)?;

    // Determine if we should use secure cookies
    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();

    // Build response with the cookie
    let response_data = SubscribeResponse {
        message: "Successfully subscribed".to_string(),
        membership_status: updated_user.membership_status,
    };

    Ok(HttpResponse::Ok()
        .cookie(AuthCookies::access_token(
            &access_token,
            secure,
            cookie_domain,
        ))
        .json(crate::responses::ApiResponse {
            success: true,
            data: Some(response_data),
            meta: crate::responses::ResponseMeta::new(request_id),
        }))
}
