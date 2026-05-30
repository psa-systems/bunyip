//! Billing handlers
//!
//! This module contains HTTP handlers for invoice/billing endpoints.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::errors::AppError;
use crate::middleware::extract_client_ip;
use crate::middleware::AuthenticatedUser;
use crate::models::RateLimitConfig;
use crate::repositories::{RateLimitRepository, UserRepository};
use crate::responses::{get_request_id, success};
use crate::services::StripeService;

/// Request body for SetupIntent creation
#[derive(Debug, Deserialize)]
pub struct CreateSetupIntentRequest {
    pub email: String,
}

/// Response for SetupIntent creation
#[derive(Debug, Serialize)]
pub struct CreateSetupIntentResponse {
    pub client_secret: String,
    pub customer_id: String,
}

/// POST /v1/billing/setup-intent
/// Create a Stripe Customer and SetupIntent for $0 card authorization at signup.
/// Unauthenticated — the user does not exist yet at this point.
pub async fn create_setup_intent(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
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

    // Reject early if the email is already registered, so the user does not
    // waste a step entering card details before discovering the conflict.
    if UserRepository::find_by_email(&pool, &body.email)
        .await?
        .is_some()
    {
        return Err(AppError::conflict("Email already registered"));
    }

    let (customer_id, client_secret) = stripe.create_setup_intent(&body.email).await?;

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

    let db_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    let invoices = if let Some(ref customer_id) = db_user.stripe_customer_id {
        stripe.list_customer_invoices(customer_id, None).await?
    } else {
        Vec::new()
    };

    Ok(success(invoices, request_id))
}

/// GET /v1/billing/invoices/{invoice_id}/download
/// Redirect to the Stripe-hosted PDF for an invoice
pub async fn download_invoice(
    _req: HttpRequest,
    user: AuthenticatedUser,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let invoice_id = path.into_inner();

    let db_user = UserRepository::find_by_id(&pool, user.0.sub)
        .await?
        .ok_or(AppError::not_found("User"))?;

    let customer_id = db_user
        .stripe_customer_id
        .ok_or(AppError::not_found("No billing account found"))?;

    let invoice = stripe.get_invoice(&invoice_id).await?;

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
