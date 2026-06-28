//! Webhook handlers
//!
//! This module contains HTTP handlers for external webhooks (Stripe, etc.)

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;

use crate::config::TierConfig;
use crate::errors::AppError;
use crate::models::entitlement::entitlement_source;
use crate::models::{
    AuditAction, AuditSeverity, CreateAuditLog, MembershipStatus, SubscriptionTier,
};
use crate::repositories::{AuditLogRepository, EntitlementRepository, UserRepository};
use crate::services::{EmailService, StripeService};

/// Re-sync a user's Stripe-sourced product entitlements to match the prices on
/// their current subscription (BUNYIP-39). Revokes every prior Stripe-sourced
/// grant first, then grants the products mapped to the subscription's current
/// prices, so removing a product from a plan (downgrade) also removes access.
/// Admin-granted entitlements (source 'admin') are never touched.
///
/// Errors are PROPAGATED (not swallowed): the caller returns them from the
/// webhook so Stripe retries the delivery. Because the whole operation is
/// revoke-all-then-grant-current, a retry is idempotent and converges, so a
/// transient mid-sync failure self-heals on the next delivery rather than
/// silently leaving a paying member under-granted.
async fn sync_stripe_entitlements(
    pool: &PgPool,
    user_id: uuid::Uuid,
    subscription: &serde_json::Value,
) -> Result<(), AppError> {
    // Collect every price id across all subscription items.
    let price_ids: Vec<String> = subscription["items"]["data"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i["price"]["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    // Resolve the full target product set first, so the revoke+grant window is
    // as small as possible.
    let mut target_app_ids: Vec<uuid::Uuid> = Vec::new();
    for price_id in &price_ids {
        target_app_ids.extend(EntitlementRepository::applications_for_price(pool, price_id).await?);
    }
    target_app_ids.sort();
    target_app_ids.dedup();

    EntitlementRepository::revoke_all_for_user_by_source(pool, user_id, entitlement_source::STRIPE)
        .await?;
    for app_id in target_app_ids {
        EntitlementRepository::grant(pool, user_id, app_id, None, entitlement_source::STRIPE)
            .await?;
    }
    Ok(())
}

/// Revoke all of a user's Stripe-sourced entitlements (subscription canceled /
/// deleted or moved to a non-active status). Admin grants are preserved. Errors
/// propagate so Stripe retries.
async fn revoke_stripe_entitlements(pool: &PgPool, user_id: uuid::Uuid) -> Result<(), AppError> {
    EntitlementRepository::revoke_all_for_user_by_source(pool, user_id, entitlement_source::STRIPE)
        .await?;
    Ok(())
}

/// Outcome of trying to claim a Stripe webhook event for processing (BUNYIP-210).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventClaim {
    /// This delivery won the claim and must run the handler.
    Owned,
    /// A prior delivery already ran the handler to completion; skip it.
    AlreadyDone,
    /// Another delivery currently holds a fresh `processing` claim; let Stripe
    /// retry later rather than run the handler a second time concurrently.
    InFlight,
}

/// Pure decision for the idempotency fence (BUNYIP-210): map the claim-insert
/// outcome and the current persisted status onto an [`EventClaim`].
///
/// This is the regression-critical invariant the original fence got wrong:
/// ONLY a row that is already `done` may short-circuit a redelivery. Anything
/// else - a winning claim, a stale/in-flight `processing` row, or a row that a
/// failed handler released between the upsert and the status read - must NOT be
/// treated as already processed, so Stripe's retry re-runs the handler instead
/// of being swallowed with a bare `200`. Factored out of `claim_webhook_event`
/// so it can be unit-tested without a live database (CI runs `--lib` tests with
/// no Postgres).
fn classify_claim(won_claim: bool, existing_status: Option<&str>) -> EventClaim {
    if won_claim {
        return EventClaim::Owned;
    }
    match existing_status {
        // Finished by a prior delivery: safe to skip.
        Some("done") => EventClaim::AlreadyDone,
        // Fresh `processing` claim held by another delivery, a row released by a
        // concurrent failure, or any non-terminal status: ask Stripe to retry
        // rather than declare the event processed. Never swallow the retry.
        _ => EventClaim::InFlight,
    }
}

/// Atomically claim a Stripe webhook event for processing (BUNYIP-210).
///
/// Inserts the event as `processing`, or reclaims an existing row only when it
/// is not `done` and its claim has gone stale (the previous owner presumably
/// crashed before releasing it). A `RETURNING` row means this delivery won the
/// claim; an empty result means the row exists and is either `done` or a fresh
/// in-flight claim, which a follow-up status read disambiguates.
///
/// This replaces the old insert-then-process fence, which marked an event
/// processed up front and so silently dropped the side effect whenever the
/// handler failed (Stripe's retry saw the row and returned 200 without re-running).
async fn claim_webhook_event(
    pool: &PgPool,
    event_id: &str,
    event_type: &str,
) -> Result<EventClaim, AppError> {
    let claimed: Option<(String,)> = sqlx::query_as(
        r#"
        INSERT INTO stripe_webhook_events (event_id, event_type, status, received_at)
        VALUES ($1, $2, 'processing', NOW())
        ON CONFLICT (event_id) DO UPDATE
            SET status = 'processing',
                received_at = NOW(),
                event_type = EXCLUDED.event_type
            WHERE stripe_webhook_events.status <> 'done'
              AND stripe_webhook_events.received_at < NOW() - INTERVAL '15 minutes'
        RETURNING event_id
        "#,
    )
    .bind(event_id)
    .bind(event_type)
    .fetch_optional(pool)
    .await
    .map_err(|e| AppError::internal(format!("DB error claiming webhook event: {e}")))?;

    if claimed.is_some() {
        return Ok(EventClaim::Owned);
    }

    // No claim won: the row exists and the upsert's WHERE excluded it. Read the
    // status to tell "already finished" apart from "another delivery in flight".
    let existing: Option<(String,)> =
        sqlx::query_as("SELECT status FROM stripe_webhook_events WHERE event_id = $1")
            .bind(event_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| AppError::internal(format!("DB error reading webhook event: {e}")))?;

    Ok(classify_claim(
        false,
        existing.as_ref().map(|(status,)| status.as_str()),
    ))
}

/// Promote a claimed webhook event to `done` after its handler succeeded
/// (BUNYIP-210). Only now is the event safe to treat as already processed.
async fn finalize_webhook_event(pool: &PgPool, event_id: &str) -> Result<(), AppError> {
    sqlx::query("UPDATE stripe_webhook_events SET status = 'done' WHERE event_id = $1")
        .bind(event_id)
        .execute(pool)
        .await
        .map_err(|e| AppError::internal(format!("DB error finalizing webhook event: {e}")))?;
    Ok(())
}

/// Release a claimed webhook event after its handler FAILED so Stripe's retry
/// reprocesses it (BUNYIP-210). Best-effort: if the delete itself fails, the
/// lease in `claim_webhook_event` still lets a later delivery reclaim the row.
async fn release_webhook_event(pool: &PgPool, event_id: &str) {
    if let Err(e) = sqlx::query(
        "DELETE FROM stripe_webhook_events WHERE event_id = $1 AND status = 'processing'",
    )
    .bind(event_id)
    .execute(pool)
    .await
    {
        tracing::error!(error = %e, event_id = %event_id, "Failed to release webhook event claim; lease will reclaim it");
    }
}

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
    // Fail closed when no real webhook secret is configured (BUNYIP-203).
    // `from_env` falls back to the public `whsec_placeholder` literal when
    // `STRIPE_WEBHOOK_SECRET` is unset; verifying a signature against that
    // known constant would accept forged events (membership activation,
    // entitlement grants, tier upgrades). Reject before verifying so an
    // instance brought up without the secret never trusts an event.
    if !stripe.webhook_secret_configured() {
        tracing::error!(
            "Rejecting Stripe webhook: no webhook signing secret configured \
             (STRIPE_WEBHOOK_SECRET unset or placeholder). Set a real secret to enable webhooks."
        );
        return Err(AppError::internal("Stripe webhook secret not configured"));
    }

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

    // BUNYIP-89 / BUNYIP-210: idempotency on event.id. Stripe delivers
    // at-least-once, so without a fence every retry re-fires emails, audit-log
    // rows, and entitlement syncs. CLAIM the event before running the handler
    // and only mark it `done` AFTER the handler succeeds (see the match at the
    // end). A failed handler RELEASES the claim so the retry reprocesses,
    // instead of the original fence's behaviour of recording the event up front
    // and swallowing the side effect on any handler error.
    let event_id = event["id"]
        .as_str()
        .ok_or(AppError::validation("id", "Missing event id"))?;
    // Runtime sqlx (the rest of bunyip-api uses runtime queries; the
    // compile-time `sqlx::query!` macro lives in bunyip-oidc per
    // `.sqlx/` offline cache convention).
    match claim_webhook_event(pool.get_ref(), event_id, event_type).await? {
        EventClaim::Owned => {}
        EventClaim::AlreadyDone => {
            tracing::debug!(
                event_id = %event_id,
                event_type = %event_type,
                "Stripe event already processed; skipping handlers"
            );
            return Ok(HttpResponse::Ok().finish());
        }
        EventClaim::InFlight => {
            tracing::warn!(
                event_id = %event_id,
                event_type = %event_type,
                "Stripe event is being processed by a concurrent delivery; asking Stripe to retry"
            );
            // Non-2xx so Stripe retries after backoff rather than treating the
            // event as delivered while the other claim might still fail.
            return Ok(HttpResponse::Conflict().finish());
        }
    }

    tracing::info!(event_type = %event_type, event_id = %event_id, "Processing Stripe webhook");

    // RwLock::read() returns Err only when the lock is poisoned (a writer
    // panicked while holding it). Poisoning is just a marker: the inner
    // data is structurally intact, so recovering through `PoisonError::into_inner`
    // is safe here because this path only reads. Logging once gives ops a
    // signal that the tier-settings write path panicked, without taking
    // down every subsequent webhook delivery.
    let tc = match tier_config.read() {
        Ok(guard) => guard.clone(),
        Err(poison) => {
            tracing::error!(
                "TierConfig read lock was poisoned by a previous panic; recovering through poison"
            );
            poison.into_inner().clone()
        }
    };

    // Route to appropriate handler. Capture the result so the idempotency claim
    // is finalized on success or released on failure (BUNYIP-210).
    let outcome = match event_type {
        "checkout.session.completed" => {
            handle_checkout_completed(&event, &pool, &email, &stripe).await
        }
        "customer.subscription.created" => handle_subscription_created(&event, &pool, &tc).await,
        "customer.subscription.updated" => handle_subscription_updated(&event, &pool, &tc).await,
        "customer.subscription.deleted" => {
            handle_subscription_deleted(&event, &pool, &email, &stripe).await
        }
        "invoice.payment_succeeded" => handle_payment_succeeded(&event, &pool, &email).await,
        "invoice.payment_failed" => handle_payment_failed(&event, &pool, &email).await,
        _ => {
            tracing::debug!(event_type = %event_type, "Unhandled Stripe event type");
            Ok(())
        }
    };

    match outcome {
        Ok(()) => {
            // Handler succeeded: now it is safe to record the event as processed.
            finalize_webhook_event(pool.get_ref(), event_id).await?;
            Ok(HttpResponse::Ok().finish())
        }
        Err(e) => {
            // Release the claim so Stripe's retry reprocesses this event rather
            // than seeing a recorded row and skipping it.
            release_webhook_event(pool.get_ref(), event_id).await;
            Err(e)
        }
    }
}

async fn handle_checkout_completed(
    event: &serde_json::Value,
    pool: &PgPool,
    email: &EmailService,
    stripe: &StripeService,
) -> Result<(), AppError> {
    let session = &event["data"]["object"];

    // Get user ID from metadata. A checkout session without our `user_id`
    // metadata is not one we can act on (e.g. created outside this app); skip it
    // and return Ok so Stripe records a 2xx and stops retrying the delivery
    // forever instead of hammering this endpoint.
    let Some(user_id_str) = session["metadata"]["user_id"].as_str() else {
        tracing::warn!("checkout.session.completed missing user_id metadata; skipping");
        return Ok(());
    };

    let user_id: uuid::Uuid = user_id_str
        .parse()
        .map_err(|_| AppError::validation("user_id", "Invalid UUID"))?;

    let session_id = session["id"]
        .as_str()
        .ok_or(AppError::validation("id", "Missing checkout session id"))?;

    // Resolve the real purchased price from the Stripe API (BUNYIP-215). Stripe
    // omits `line_items` from the `checkout.session.completed` payload, so the
    // price id and amount cannot be read off the event: the old code did that
    // and silently locked the placeholder `"price_default"` with a hardcoded
    // amount. A transient API failure propagates so Stripe retries the delivery
    // (BUNYIP-210 makes that safe).
    let price = stripe.get_checkout_session_price(session_id).await?;

    // Update user membership status and lock the real price for life.
    UserRepository::update_membership_status(pool, user_id, MembershipStatus::Active).await?;

    let amount = match price {
        Some(p) => {
            let amount = p.amount as i32;
            UserRepository::lock_price(pool, user_id, &p.price_id, amount).await?;
            amount
        }
        None => {
            // Should not happen for a genuinely completed checkout. Do NOT lock
            // a placeholder; leave the price unlocked rather than persist junk,
            // and fall back to the session total only for the welcome email.
            tracing::error!(
                user_id = %user_id,
                session_id = %session_id,
                "Checkout session had no resolvable line-item price; skipping price lock"
            );
            session["amount_total"].as_i64().unwrap_or(0) as i32
        }
    };

    // BUNYIP-209: if this session carried the signup trial (tagged with
    // `trial=true` metadata at creation time), burn the one-time trial now that
    // the checkout has finalized. Doing it here (not at session creation) means
    // an abandoned checkout never consumes the trial. Idempotent on replay.
    if session["metadata"]["trial"].as_str() == Some("true") {
        UserRepository::mark_trial_used(pool, user_id).await?;
        tracing::info!(user_id = %user_id, "Signup trial consumed via checkout");
    }

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

    // Grant per-product entitlements for the subscription's prices (BUNYIP-39).
    sync_stripe_entitlements(pool, user.id, subscription).await?;

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
        // Entitlements follow ONLY a genuinely active subscription, on an
        // explicit allowlist (BUNYIP-39). The membership-status mapping above
        // falls back to Active for unknown statuses, but entitlements must not:
        // a non-paying status (unpaid, incomplete_expired, paused, ...) revokes
        // the Stripe-sourced grants rather than re-granting product access.
        let grants_access = matches!(status, "active" | "trialing" | "past_due");

        let resolved_tier = resolve_tier_for_product(product_id, tc);

        let mut tx = pool.begin().await?;
        UserRepository::update_membership_status(&mut *tx, user.id, user_status).await?;
        if let Some(ref tier) = resolved_tier {
            UserRepository::upgrade_subscription_tier(&mut *tx, user.id, tier).await?;
        }
        tx.commit().await?;

        // Re-sync the Stripe-sourced grants to the current price set (handles
        // plan add/remove) when the subscription grants access; otherwise drop
        // them. Admin grants are untouched either way.
        if grants_access {
            sync_stripe_entitlements(pool, user.id, subscription).await?;
        } else {
            revoke_stripe_entitlements(pool, user.id).await?;
        }

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
    stripe: &StripeService,
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

        // BUNYIP-225: a user can hold multiple Stripe subscriptions on the
        // same customer (cancel-with-period-end + new re-sub; or the
        // multi-subscription edge case where 3 trial subs were created
        // while webhook deliveries were 401ing). Without this check, the
        // OLD subscription's deferred deletion (when period_end finally
        // hits) flips an actively-subscribed user back to Canceled even
        // though their newer subscription is healthy. Query Stripe for
        // any OTHER currently-active or trialing subscription on the same
        // customer; if one exists, keep status Active and only log the
        // cleanup.
        match stripe
            .has_other_active_subscription(customer_id, stripe_subscription_id)
            .await
        {
            Ok(true) => {
                tracing::info!(
                    user_id = %user.id,
                    stripe_subscription_id = %stripe_subscription_id,
                    "Subscription deleted but at least one sibling sub remains active; keeping membership Active"
                );
                return Ok(());
            }
            Ok(false) => {}
            Err(e) => {
                // A Stripe API failure here MUST NOT flip the user to
                // Canceled on partial data: that is the exact regression
                // BUNYIP-225 closes. Return Err so the webhook claim is
                // released and Stripe re-delivers; the next attempt re-
                // queries cleanly. The user keeps their prior state until
                // we have authoritative sibling info.
                tracing::error!(
                    error = %e,
                    user_id = %user.id,
                    customer_id = %customer_id,
                    stripe_subscription_id = %stripe_subscription_id,
                    "Failed to query sibling subscriptions; aborting cancel-flip so Stripe retries"
                );
                return Err(e);
            }
        }

        let mut tx = pool.begin().await?;
        UserRepository::update_membership_status(&mut *tx, user.id, MembershipStatus::Canceled)
            .await?;
        UserRepository::reset_subscription_tier(&mut *tx, user.id).await?;
        UserRepository::clear_grace_period(&mut *tx, user.id).await?;
        tx.commit().await?;

        // Subscription gone: drop the Stripe-sourced entitlements (BUNYIP-39).
        revoke_stripe_entitlements(pool, user.id).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    // Regression tests for the BUNYIP-210 idempotency-fence ordering bug.
    //
    // The original fence recorded `event.id` as processed BEFORE running the
    // handler, so a handler error on first delivery left a row that made
    // Stripe's retry short-circuit to `200` without ever re-running the handler.
    // The side effect (membership activation / entitlement grant) was lost
    // permanently. The fix claims the event as `processing`, only promotes it to
    // `done` after the handler succeeds, and releases the claim on failure.
    //
    // CI has no Postgres (tests run `--lib` with SQLX_OFFLINE), so the DB SQL is
    // not exercised here. What IS exercised is the pure decision that governs
    // whether a redelivery is allowed to re-run: only a `done` row may be
    // skipped; every other state must re-process. That is exactly the invariant
    // the old fence violated.

    /// Core regression: a row that is NOT `done` must never be treated as
    /// already processed. This is the state a failed-handler delivery leaves
    /// behind (claim released back to absent, or a stale `processing` row), and
    /// it must route to a reprocess (`Owned`) or a retry (`InFlight`), never to
    /// `AlreadyDone` which would swallow the retry.
    #[test]
    fn non_done_states_never_swallow_the_retry() {
        // No row at all: a released claim from a failed handler. Per the upsert
        // contract the next delivery wins the claim, but even if classification
        // is reached it must not be AlreadyDone.
        assert_ne!(classify_claim(false, None), EventClaim::AlreadyDone);
        // A lingering in-flight / stale claim from a crashed or failed delivery.
        assert_eq!(
            classify_claim(false, Some("processing")),
            EventClaim::InFlight
        );
        // Any unexpected non-terminal status is still re-processable, never
        // silently skipped.
        assert_eq!(classify_claim(false, Some("queued")), EventClaim::InFlight);
    }

    /// Only a fully-finished (`done`) prior delivery is allowed to short-circuit
    /// a redelivery. This is the legitimate idempotency case.
    #[test]
    fn done_row_short_circuits_redelivery() {
        assert_eq!(classify_claim(false, Some("done")), EventClaim::AlreadyDone);
    }

    /// Winning the insert/upsert claim always means this delivery owns the work,
    /// regardless of any prior status the read would have seen.
    #[test]
    fn winning_the_claim_owns_the_work() {
        assert_eq!(classify_claim(true, None), EventClaim::Owned);
        assert_eq!(classify_claim(true, Some("processing")), EventClaim::Owned);
        // Defensive: even a stale `done` cannot override a won claim (the upsert
        // WHERE never reclaims a `done` row, so this branch is unreachable in
        // practice, but the decision must still favour Owned).
        assert_eq!(classify_claim(true, Some("done")), EventClaim::Owned);
    }
}
