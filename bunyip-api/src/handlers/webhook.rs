//! Webhook handlers
//!
//! This module contains HTTP handlers for external webhooks (Stripe, etc.)

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;

use crate::config::TierConfig;
use crate::errors::AppError;
use crate::models::{
    AuditAction, AuditSeverity, CreateAuditLog, MembershipStatus, SubscriptionTier,
};
use crate::repositories::{AuditLogRepository, UserRepository};
use crate::services::{EmailService, StripeService};

/// POST /v1/webhooks/stripe
/// Handle Stripe webhook events
pub async fn stripe_webhook(
    req: HttpRequest,
    body: web::Bytes,
    pool: web::Data<PgPool>,
    stripe: web::Data<Arc<StripeService>>,
    email: web::Data<Arc<EmailService>>,
    tier_config: web::Data<Arc<std::sync::RwLock<TierConfig>>>,
) -> Result<HttpResponse, AppError> {
    // Get signature header
    let signature = req
        .headers()
        .get("Stripe-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    // Verify webhook signature
    stripe.verify_webhook_signature(&body, signature)?;

    // Parse the event
    let payload = String::from_utf8(body.to_vec())
        .map_err(|_| AppError::validation("body", "Invalid UTF-8"))?;

    let event: serde_json::Value =
        serde_json::from_str(&payload).map_err(|_| AppError::validation("body", "Invalid JSON"))?;

    let event_type = event["type"]
        .as_str()
        .ok_or(AppError::validation("type", "Missing event type"))?;

    tracing::info!(event_type = %event_type, "Processing Stripe webhook");

    let tc = tier_config
        .read()
        .expect("TierConfig lock poisoned")
        .clone();

    // Route to appropriate handler
    match event_type {
        "checkout.session.completed" => {
            handle_checkout_completed(&event, &pool, &email).await?;
        }
        "customer.subscription.created" => {
            handle_subscription_created(&event, &pool, &tc).await?;
        }
        "customer.subscription.updated" => {
            handle_subscription_updated(&event, &pool, &tc).await?;
        }
        "customer.subscription.deleted" => {
            handle_subscription_deleted(&event, &pool, &email).await?;
        }
        "invoice.payment_succeeded" => {
            handle_payment_succeeded(&event, &pool, &email).await?;
        }
        "invoice.payment_failed" => {
            handle_payment_failed(&event, &pool, &email).await?;
        }
        _ => {
            tracing::debug!(event_type = %event_type, "Unhandled Stripe event type");
        }
    }

    Ok(HttpResponse::Ok().finish())
}

async fn handle_checkout_completed(
    event: &serde_json::Value,
    pool: &PgPool,
    email: &EmailService,
) -> Result<(), AppError> {
    let session = &event["data"]["object"];

    // Get user ID from metadata
    let user_id_str = session["metadata"]["user_id"]
        .as_str()
        .ok_or(AppError::validation("metadata", "Missing user_id"))?;

    let user_id: uuid::Uuid = user_id_str
        .parse()
        .map_err(|_| AppError::validation("user_id", "Invalid UUID"))?;

    // Get price info
    let amount = match session["amount_total"].as_i64() {
        Some(a) => a as i32,
        None => {
            tracing::warn!(user_id = %user_id, "Missing amount_total in checkout session, defaulting to 300");
            300
        }
    };

    // Update user membership status and lock price
    UserRepository::update_membership_status(pool, user_id, MembershipStatus::Active).await?;

    // Lock the price for life
    let price_id = session["subscription"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "price_default".to_string());

    UserRepository::lock_price(pool, user_id, &price_id, amount).await?;

    tracing::info!(user_id = %user_id, "Checkout completed, membership activated");

    // Send welcome email and audit log
    if let Ok(Some(user)) = UserRepository::find_by_id(pool, user_id).await {
        if let Err(e) = email.send_welcome(&user.email, amount).await {
            tracing::error!(error = %e, user_id = %user_id, "Failed to send welcome email");
        }

        let audit_log = CreateAuditLog::new(AuditAction::MembershipCreated)
            .with_actor(user.id, &user.email, &user.role)
            .with_resource("user", user.id)
            .with_metadata(serde_json::json!({
                "source": "stripe_checkout",
                "amount": amount,
            }));
        if let Err(e) = AuditLogRepository::create(pool, audit_log).await {
            tracing::error!(error = %e, user_id = %user_id, "Failed to create audit log for checkout");
        }
    }

    Ok(())
}

async fn handle_subscription_created(
    event: &serde_json::Value,
    pool: &PgPool,
    tc: &TierConfig,
) -> Result<(), AppError> {
    let subscription = &event["data"]["object"];

    let stripe_subscription_id = subscription["id"]
        .as_str()
        .ok_or(AppError::validation("id", "Missing subscription ID"))?;

    let customer_id = subscription["customer"]
        .as_str()
        .ok_or(AppError::validation("customer", "Missing customer ID"))?;

    // Find user by customer ID
    let user = UserRepository::find_by_stripe_customer_id(pool, customer_id)
        .await?
        .ok_or(AppError::not_found("User"))?;

    let price_id = subscription["items"]["data"][0]["price"]["id"]
        .as_str()
        .unwrap_or("unknown");

    let product_id = subscription["items"]["data"][0]["price"]["product"]
        .as_str()
        .unwrap_or("unknown");

    let amount = subscription["items"]["data"][0]["price"]["unit_amount"]
        .as_i64()
        .unwrap_or(300) as i32;

    // Resolve tier from product ID mapping (None means no match — leave tier unchanged)
    let resolved_tier = resolve_tier_for_product(product_id, tc);

    let mut tx = pool.begin().await?;
    UserRepository::update_membership_status(&mut *tx, user.id, MembershipStatus::Active).await?;
    if let Some(ref tier) = resolved_tier {
        UserRepository::upgrade_subscription_tier(&mut *tx, user.id, tier).await?;
    }
    tx.commit().await?;

    tracing::info!(
        user_id = %user.id,
        stripe_subscription_id = %stripe_subscription_id,
        resolved_tier = ?resolved_tier,
        "Subscription created"
    );

    let audit_log = CreateAuditLog::new(AuditAction::MembershipCreated)
        .with_actor(user.id, &user.email, &user.role)
        .with_resource("user", user.id)
        .with_metadata(serde_json::json!({
            "stripe_subscription_id": stripe_subscription_id,
            "stripe_price_id": price_id,
            "stripe_product_id": product_id,
            "amount": amount,
            "resolved_tier": resolved_tier.as_ref().map(|t| t.as_str()),
        }));
    if let Err(e) = AuditLogRepository::create(pool, audit_log).await {
        tracing::error!(error = %e, user_id = %user.id, "Failed to create audit log for subscription created");
    }

    Ok(())
}

async fn handle_subscription_updated(
    event: &serde_json::Value,
    pool: &PgPool,
    tc: &TierConfig,
) -> Result<(), AppError> {
    let subscription = &event["data"]["object"];

    let stripe_subscription_id = subscription["id"]
        .as_str()
        .ok_or(AppError::validation("id", "Missing subscription ID"))?;

    let customer_id = subscription["customer"]
        .as_str()
        .ok_or(AppError::validation("customer", "Missing customer ID"))?;

    let status = subscription["status"].as_str().unwrap_or("active");

    let cancel_at_period_end = subscription["cancel_at_period_end"]
        .as_bool()
        .unwrap_or(false);

    let price_id = subscription["items"]["data"][0]["price"]["id"]
        .as_str()
        .unwrap_or("unknown");

    let product_id = subscription["items"]["data"][0]["price"]["product"]
        .as_str()
        .unwrap_or("unknown");

    // Find user by customer ID
    if let Some(user) = UserRepository::find_by_stripe_customer_id(pool, customer_id).await? {
        let user_status = match status {
            "active" => MembershipStatus::Active,
            "past_due" => MembershipStatus::PastDue,
            "canceled" => MembershipStatus::Canceled,
            _ => MembershipStatus::Active,
        };

        let resolved_tier = resolve_tier_for_product(product_id, tc);

        let mut tx = pool.begin().await?;
        UserRepository::update_membership_status(&mut *tx, user.id, user_status).await?;
        if let Some(ref tier) = resolved_tier {
            UserRepository::upgrade_subscription_tier(&mut *tx, user.id, tier).await?;
        }
        tx.commit().await?;

        tracing::info!(
            stripe_subscription_id = %stripe_subscription_id,
            status = %status,
            "Subscription updated"
        );

        // Audit log
        let action = if cancel_at_period_end {
            AuditAction::MembershipCanceled
        } else if status == "active" {
            AuditAction::MembershipReactivated
        } else {
            AuditAction::MembershipCanceled
        };

        let audit_log = CreateAuditLog::new(action)
            .with_actor(user.id, &user.email, &user.role)
            .with_resource("user", user.id)
            .with_metadata(serde_json::json!({
                "stripe_subscription_id": stripe_subscription_id,
                "status": status,
                "cancel_at_period_end": cancel_at_period_end,
                "stripe_price_id": price_id,
                "stripe_product_id": product_id,
                "resolved_tier": resolved_tier.as_ref().map(|t| t.as_str()),
            }));
        if let Err(e) = AuditLogRepository::create(pool, audit_log).await {
            tracing::error!(error = %e, "Failed to create audit log for subscription update");
        }
    }

    Ok(())
}

async fn handle_subscription_deleted(
    event: &serde_json::Value,
    pool: &PgPool,
    email: &EmailService,
) -> Result<(), AppError> {
    let subscription = &event["data"]["object"];

    let stripe_subscription_id = subscription["id"]
        .as_str()
        .ok_or(AppError::validation("id", "Missing subscription ID"))?;

    let customer_id = subscription["customer"]
        .as_str()
        .ok_or(AppError::validation("customer", "Missing customer ID"))?;

    // Find user by customer ID
    if let Some(user) = UserRepository::find_by_stripe_customer_id(pool, customer_id).await? {
        if user.lifetime_member {
            tracing::info!(
                user_id = %user.id,
                stripe_subscription_id = %stripe_subscription_id,
                "Subscription deleted for lifetime member — skipping tier reset"
            );
            return Ok(());
        }

        let mut tx = pool.begin().await?;
        UserRepository::update_membership_status(&mut *tx, user.id, MembershipStatus::Canceled)
            .await?;
        UserRepository::reset_subscription_tier(&mut *tx, user.id).await?;
        UserRepository::clear_grace_period(&mut *tx, user.id).await?;
        tx.commit().await?;

        tracing::info!(
            user_id = %user.id,
            stripe_subscription_id = %stripe_subscription_id,
            "Subscription deleted"
        );

        // Send cancellation email and audit log
        if let Err(e) = email
            .send_membership_canceled(&user.email, Utc::now())
            .await
        {
            tracing::error!(error = %e, user_id = %user.id, "Failed to send membership canceled email");
        }

        let audit_log = CreateAuditLog::new(AuditAction::MembershipCanceled)
            .with_actor(user.id, &user.email, &user.role)
            .with_resource("user", user.id)
            .with_metadata(serde_json::json!({
                "source": "stripe_subscription_deleted",
                "stripe_subscription_id": stripe_subscription_id,
            }));
        if let Err(e) = AuditLogRepository::create(pool, audit_log).await {
            tracing::error!(error = %e, user_id = %user.id, "Failed to create audit log for subscription deleted");
        }
    }

    Ok(())
}

async fn handle_payment_succeeded(
    event: &serde_json::Value,
    pool: &PgPool,
    email: &EmailService,
) -> Result<(), AppError> {
    let invoice = &event["data"]["object"];

    let customer_id = invoice["customer"]
        .as_str()
        .ok_or(AppError::validation("customer", "Missing customer ID"))?;

    // Find user by customer ID
    let user = match UserRepository::find_by_stripe_customer_id(pool, customer_id).await? {
        Some(u) => u,
        None => {
            tracing::warn!(customer_id = %customer_id, "User not found for payment");
            return Ok(());
        }
    };

    let amount = invoice["amount_paid"].as_i64().unwrap_or(0) as i32;

    // Clear any grace period if exists
    let had_grace_period = user.grace_period_start.is_some();
    if had_grace_period {
        let mut tx = pool.begin().await?;
        UserRepository::clear_grace_period(&mut *tx, user.id).await?;
        UserRepository::update_membership_status(&mut *tx, user.id, MembershipStatus::Active)
            .await?;
        tx.commit().await?;
    }

    tracing::info!(
        user_id = %user.id,
        amount = amount,
        "Payment succeeded"
    );

    // Audit log for payment
    let audit_log = CreateAuditLog::new(AuditAction::PaymentSucceeded)
        .with_actor(user.id, &user.email, &user.role)
        .with_resource("user", user.id)
        .with_metadata(serde_json::json!({
            "amount": amount,
            "currency": "usd",
        }));
    if let Err(e) = AuditLogRepository::create(pool, audit_log).await {
        tracing::error!(error = %e, user_id = %user.id, "Failed to create audit log for payment succeeded");
    }

    // Audit log for grace period ended
    if had_grace_period {
        let audit_log = CreateAuditLog::new(AuditAction::GracePeriodEnded)
            .with_actor(user.id, &user.email, &user.role)
            .with_resource("user", user.id);
        if let Err(e) = AuditLogRepository::create(pool, audit_log).await {
            tracing::error!(error = %e, user_id = %user.id, "Failed to create audit log for grace period ended");
        }
    }

    // Send payment receipt email
    if let Err(e) = email.send_payment_succeeded(&user.email, amount).await {
        tracing::error!(error = %e, user_id = %user.id, "Failed to send payment succeeded email");
    }

    Ok(())
}

async fn handle_payment_failed(
    event: &serde_json::Value,
    pool: &PgPool,
    email: &EmailService,
) -> Result<(), AppError> {
    let invoice = &event["data"]["object"];

    let customer_id = invoice["customer"]
        .as_str()
        .ok_or(AppError::validation("customer", "Missing customer ID"))?;

    // Find user by customer ID
    let user = match UserRepository::find_by_stripe_customer_id(pool, customer_id).await? {
        Some(u) => u,
        None => {
            tracing::warn!(customer_id = %customer_id, "User not found for failed payment");
            return Ok(());
        }
    };

    let amount = invoice["amount_due"].as_i64().unwrap_or(0) as i32;

    // Audit log for payment failure
    let audit_log = CreateAuditLog::new(AuditAction::PaymentFailed)
        .with_actor(user.id, &user.email, &user.role)
        .with_resource("user", user.id)
        .with_severity(AuditSeverity::Warning)
        .with_metadata(serde_json::json!({
            "amount": amount,
            "currency": "usd",
        }));
    if let Err(e) = AuditLogRepository::create(pool, audit_log).await {
        tracing::error!(error = %e, user_id = %user.id, "Failed to create audit log for payment failed");
    }

    // Start grace period if not already started
    if user.grace_period_start.is_none() {
        let now = Utc::now();
        let grace_end = now + Duration::days(30);

        let mut tx = pool.begin().await?;
        UserRepository::set_grace_period(&mut *tx, user.id, now, grace_end).await?;
        UserRepository::update_membership_status(&mut *tx, user.id, MembershipStatus::GracePeriod)
            .await?;
        tx.commit().await?;

        tracing::info!(
            user_id = %user.id,
            grace_period_end = %grace_end,
            "Payment failed, grace period started"
        );

        // Audit log for grace period started
        let audit_log = CreateAuditLog::new(AuditAction::GracePeriodStarted)
            .with_actor(user.id, &user.email, &user.role)
            .with_resource("user", user.id)
            .with_severity(AuditSeverity::Warning)
            .with_metadata(serde_json::json!({
                "grace_period_end": grace_end.to_rfc3339(),
            }));
        if let Err(e) = AuditLogRepository::create(pool, audit_log).await {
            tracing::error!(error = %e, user_id = %user.id, "Failed to create audit log for grace period started");
        }
    }

    // Send payment failed email
    if let Err(e) = email.send_payment_failed(&user.email, 30).await {
        tracing::error!(error = %e, user_id = %user.id, "Failed to send payment failed email");
    }

    Ok(())
}

/// Map a Stripe product ID to its corresponding `SubscriptionTier` using the current tier config.
/// Returns `None` if the product ID does not match any configured mapping, meaning tier is left
/// unchanged and only `subscription_status` is updated by the caller.
fn resolve_tier_for_product(product_id: &str, tc: &TierConfig) -> Option<SubscriptionTier> {
    if tc.lifetime_product_id.as_deref() == Some(product_id) {
        return Some(SubscriptionTier::Lifetime);
    }
    if tc.early_adopter_product_id.as_deref() == Some(product_id) {
        return Some(SubscriptionTier::EarlyAdopter);
    }
    if tc.standard_product_id.as_deref() == Some(product_id) {
        return Some(SubscriptionTier::Standard);
    }
    None
}
