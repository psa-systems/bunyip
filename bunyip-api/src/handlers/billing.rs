//! Billing handlers
//!
//! This module contains HTTP handlers for invoice/billing endpoints.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::errors::AppError;
use crate::handlers::user::self_user;
use crate::middleware::extract_client_ip;
use crate::middleware::AuthenticatedUser;
use crate::models::RateLimitConfig;
use crate::repositories::RateLimitRepository;
use crate::responses::{get_request_id, success};
use crate::services::{stripe_err, AuthService, StripeService};

/// Request body for SetupIntent creation
#[derive(Debug, Deserialize)]
pub struct CreateSetupIntentRequest {
    pub email: String,
    /// BUNYIP-426 F8: the signup challenge token the register form was rendered
    /// with (from `GET /v1/auth/register-challenge`). Required: it is what binds
    /// this unauthenticated Stripe write to a real form render.
    #[serde(default)]
    pub signup_token: Option<String>,
}

/// Response for SetupIntent creation
#[derive(Debug, Serialize)]
pub struct CreateSetupIntentResponse {
    pub client_secret: String,
    pub customer_id: String,
}

/// POST /v1/billing/setup-intent
/// Create a Stripe Customer and SetupIntent for $0 card authorization at signup.
/// Unauthenticated - the user does not exist yet at this point, so the signup
/// challenge token is what stands in for a credential (BUNYIP-426 F8).
pub async fn create_setup_intent(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    auth_service: web::Data<Arc<AuthService>>,
    body: web::Json<CreateSetupIntentRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);

    // Rate-limit by IP using the same budget as registration
    let ip_key = ip_address.map(|ip| ip.to_string()).unwrap_or_default();
    let (_count, exceeded) =
        RateLimitRepository::check_and_increment(&pool, &ip_key, &RateLimitConfig::REGISTRATION)
            .await?;
    if exceeded {
        let retry_after =
            RateLimitRepository::get_retry_after(&pool, &ip_key, &RateLimitConfig::REGISTRATION)
                .await?;
        return Err(AppError::RateLimited { retry_after });
    }

    crate::validation::validate_email(&body.email)?;

    // BUNYIP-426 F8: bind the Stripe write to a real form render, so an
    // unauthenticated caller cannot mint Customers at will.
    auth_service.verify_signup_challenge(body.signup_token.as_deref())?;

    // No `find_by_email` pre-check here: a 409 for a registered email and a 200
    // for an unknown one made this endpoint a registered/not-registered oracle
    // (BUNYIP-426 F8). `/v1/auth/register` is now the single place that reports
    // the conflict, which is where it is authoritative anyway.
    let (customer_id, client_secret) = stripe
        .create_setup_intent(&body.email)
        .await
        .map_err(stripe_err)?;

    Ok(success(
        CreateSetupIntentResponse {
            client_secret,
            customer_id,
        },
        request_id,
    ))
}

/// GET /v1/billing/invoices
/// List all invoices for the authenticated user from Stripe
pub async fn list_invoices(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);

    // The row this request already read, else a query.
    let db_user = self_user(&req, &pool, user.0.sub).await?;

    let invoices = if let Some(ref customer_id) = db_user.stripe_customer_id {
        stripe
            .list_customer_invoices(customer_id, None)
            .await
            .map_err(stripe_err)?
    } else {
        Vec::new()
    };

    Ok(success(invoices, request_id))
}

/// GET /v1/billing/invoices/{invoice_id}/download
/// Redirect to the Stripe-hosted PDF for an invoice
pub async fn download_invoice(
    req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let invoice_id = path.into_inner();

    // The row this request already read, else a query.
    let db_user = self_user(&req, &pool, user.0.sub).await?;

    let customer_id = db_user
        .stripe_customer_id
        .ok_or(AppError::not_found("No billing account found"))?;

    let invoice = stripe.get_invoice(&invoice_id).await.map_err(stripe_err)?;

    // Verify the invoice belongs to this user's Stripe customer
    let invoice_customer = invoice
        .customer_id
        .as_deref()
        .ok_or(AppError::not_found("Invoice"))?;

    if invoice_customer != customer_id {
        return Err(AppError::not_found("Invoice"));
    }

    let pdf_url = invoice
        .invoice_pdf
        .ok_or(AppError::not_found("Invoice PDF"))?;

    Ok(HttpResponse::Found()
        .insert_header(("Location", pdf_url))
        .finish())
}
