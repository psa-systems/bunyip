//! BUNYIP-693 [BUNYIP-626 followup]: seat-based org billing.
//!
//! The owner's Stripe subscription bills per active `team_member` across
//! every team in their org. This service owns the four operations
//! documented in the parent ticket (subscribe / sync_seat_count /
//! change_tier / cancel) plus the read that returns the current state to
//! the admin card. Every method gates on `orgs_enabled` (BUNYIP-493
//! rule).
//!
//! Stripe calls are abstracted behind [`OrgBillingProvider`] so the
//! service compiles without a Stripe client and the tests can drive a
//! `MockOrgBillingProvider`. bunyip-api wires the real implementation
//! against `StripeService` and `dunite-stripe` primitives.
//!
//! Deferred to follow-up tickets (see the parent BUNYIP-693 description):
//!
//! - Stripe webhook routing for `customer.subscription.updated /
//!   .deleted` into the org path.
//! - Nightly reconciliation worker that walks every active
//!   `stripe_subscription_id` and re-syncs the seat count.
//! - Effective-entitlement resolution: `resolve_entitlement(user_id)`
//!   reading the org's tier for a covered member.
//!
//! Those are three separate concerns that ride on top of the state this
//! ticket lands and are best reviewed on their own.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::errors::AppError;
use crate::repositories::{OrgPricingRepository, OrganizationRepository};

/// The Stripe operations `OrgBillingService` needs, abstracted so tests
/// can drive a mock without a Stripe client and so a future provider
/// (PayPal Reference Transactions, another PSP) can plug in without
/// touching the service. Every method takes the fields the SDK call
/// actually needs; the service resolves them from the org row and the
/// tier catalogue before calling.
#[async_trait]
pub trait OrgBillingProvider: Send + Sync {
    /// Ensure the customer exists for this Bunyip user, returning the
    /// Stripe customer id. Idempotent: an already-existing customer id
    /// on `users.stripe_customer_id` is returned as-is by the caller.
    async fn ensure_customer(
        &self,
        pool: &PgPool,
        owner_bunyip_user_id: Uuid,
    ) -> Result<String, AppError>;

    /// Create a new subscription for `customer_id` against `price_id` at
    /// `quantity`. Returns the Stripe subscription id.
    async fn create_seat_subscription(
        &self,
        customer_id: &str,
        price_id: &str,
        quantity: i64,
    ) -> Result<String, AppError>;

    /// Update an existing subscription's quantity. Called from
    /// `sync_seat_count` on every `team_members` add/remove.
    async fn update_subscription_quantity(
        &self,
        subscription_id: &str,
        quantity: i64,
    ) -> Result<(), AppError>;

    /// Move the subscription to a new price (tier change). The provider
    /// prorates.
    async fn update_subscription_price(
        &self,
        subscription_id: &str,
        price_id: &str,
    ) -> Result<(), AppError>;

    /// Cancel a subscription. `at_period_end = true` schedules the
    /// cancel; `false` cancels immediately.
    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        at_period_end: bool,
    ) -> Result<(), AppError>;
}

/// Snapshot of the org's subscription for the admin read + REST GET.
#[derive(Debug, Clone, Serialize, FromRow, PartialEq)]
pub struct OrgSubscriptionSnapshot {
    pub organization_id: Uuid,
    pub org_tier_id: Option<Uuid>,
    pub stripe_subscription_id: Option<String>,
    pub subscription_status: Option<String>,
    pub seat_count: i32,
    pub subscription_updated_at: Option<DateTime<Utc>>,
}

pub struct OrgBillingService;

impl OrgBillingService {
    /// `GET /v1/organization/subscription` - the current state.
    pub async fn get_snapshot(
        pool: &PgPool,
        orgs_enabled: bool,
        owner_bunyip_user_id: Uuid,
    ) -> Result<OrgSubscriptionSnapshot, AppError> {
        gate(orgs_enabled)?;
        let org = OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id)
            .await?
            .ok_or_else(|| AppError::not_found("Organization"))?;
        read_snapshot(pool, org.id).await
    }

    /// `POST /v1/organization/subscription` - subscribe the org against
    /// the tier the owner picked (via BUNYIP-692's
    /// [`crate::services::OrgPricingService::set_organization_tier`]).
    /// Refuses when the tier is unset (NULL `org_tier_id`) with a 400
    /// naming what has to happen next.
    pub async fn subscribe(
        pool: &PgPool,
        orgs_enabled: bool,
        provider: &dyn OrgBillingProvider,
        owner_bunyip_user_id: Uuid,
    ) -> Result<OrgSubscriptionSnapshot, AppError> {
        gate(orgs_enabled)?;
        let org = OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id)
            .await?
            .ok_or_else(|| AppError::not_found("Organization"))?;

        // Refuse a second subscribe: the resubscribe path is
        // `change_tier` or, after `cancel`, wait for the period end and
        // subscribe again. This keeps two active subscription rows off
        // one org.
        if let Some(existing) = read_snapshot(pool, org.id).await?.stripe_subscription_id {
            return Err(AppError::conflict(format!(
                "Organization already has subscription {existing}"
            )));
        }

        let tier_id = OrgPricingRepository::get_organization_tier(pool, org.id)
            .await?
            .ok_or_else(|| {
                AppError::bad_request(
                    "Set the org's tier through PUT /v1/organization/tier before subscribing",
                )
            })?;
        let tier = OrgPricingRepository::find_by_id(pool, tier_id)
            .await?
            .ok_or_else(|| AppError::not_found("Org pricing tier"))?;

        let seat_count = live_seat_count(pool, org.id).await?;
        let customer_id = provider.ensure_customer(pool, owner_bunyip_user_id).await?;
        let subscription_id = provider
            .create_seat_subscription(&customer_id, &tier.stripe_price_id, seat_count as i64)
            .await?;

        sqlx::query(
            "UPDATE organizations SET \
                stripe_subscription_id = $1, \
                subscription_status = 'active', \
                seat_count = $2, \
                subscription_updated_at = NOW(), \
                updated_at = NOW() \
             WHERE id = $3",
        )
        .bind(&subscription_id)
        .bind(seat_count)
        .bind(org.id)
        .execute(pool)
        .await
        .map_err(AppError::from)?;

        read_snapshot(pool, org.id).await
    }

    /// `PUT /v1/organization/subscription` - move the org's subscription
    /// to a new tier. Requires the tier column to be set to the new tier
    /// FIRST through BUNYIP-692, so `change_tier` reads the tier off the
    /// org row rather than taking it in the body: one write path decides
    /// the tier.
    pub async fn change_tier(
        pool: &PgPool,
        orgs_enabled: bool,
        provider: &dyn OrgBillingProvider,
        owner_bunyip_user_id: Uuid,
    ) -> Result<OrgSubscriptionSnapshot, AppError> {
        gate(orgs_enabled)?;
        let org = OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id)
            .await?
            .ok_or_else(|| AppError::not_found("Organization"))?;
        let snap = read_snapshot(pool, org.id).await?;
        let subscription_id = snap
            .stripe_subscription_id
            .ok_or_else(|| AppError::not_found("Organization subscription"))?;
        let tier_id = OrgPricingRepository::get_organization_tier(pool, org.id)
            .await?
            .ok_or_else(|| {
                AppError::bad_request("Set the new tier through PUT /v1/organization/tier first")
            })?;
        let tier = OrgPricingRepository::find_by_id(pool, tier_id)
            .await?
            .ok_or_else(|| AppError::not_found("Org pricing tier"))?;
        provider
            .update_subscription_price(&subscription_id, &tier.stripe_price_id)
            .await?;
        sqlx::query(
            "UPDATE organizations SET subscription_updated_at = NOW(), updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(org.id)
        .execute(pool)
        .await
        .map_err(AppError::from)?;
        read_snapshot(pool, org.id).await
    }

    /// `DELETE /v1/organization/subscription` - cancel at period end.
    /// The org row and its teams stay so history is auditable.
    pub async fn cancel(
        pool: &PgPool,
        orgs_enabled: bool,
        provider: &dyn OrgBillingProvider,
        owner_bunyip_user_id: Uuid,
    ) -> Result<OrgSubscriptionSnapshot, AppError> {
        gate(orgs_enabled)?;
        let org = OrganizationRepository::find_by_owner(pool, owner_bunyip_user_id)
            .await?
            .ok_or_else(|| AppError::not_found("Organization"))?;
        let snap = read_snapshot(pool, org.id).await?;
        let subscription_id = snap
            .stripe_subscription_id
            .ok_or_else(|| AppError::not_found("Organization subscription"))?;
        provider.cancel_subscription(&subscription_id, true).await?;
        sqlx::query(
            "UPDATE organizations SET \
                subscription_status = 'canceled', \
                subscription_updated_at = NOW(), \
                updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(org.id)
        .execute(pool)
        .await
        .map_err(AppError::from)?;
        read_snapshot(pool, org.id).await
    }

    /// Convenience for the BUNYIP-672 `add_member` / `remove_member`
    /// handlers: given a `team_id`, look up its `organization_id` and
    /// delegate to [`Self::sync_seat_count`]. A no-op if the team no
    /// longer exists (a caller racing the delete).
    pub async fn sync_seat_count_for_team(
        pool: &PgPool,
        provider: &dyn OrgBillingProvider,
        team_id: Uuid,
    ) -> Result<(), AppError> {
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT organization_id FROM teams WHERE id = $1")
                .bind(team_id)
                .fetch_optional(pool)
                .await
                .map_err(AppError::from)?;
        let Some((organization_id,)) = row else {
            return Ok(());
        };
        Self::sync_seat_count(pool, provider, organization_id).await
    }

    /// Called from every `team_members` add/remove (BUNYIP-672 sites).
    /// Recomputes the live seat count and asks Stripe to match it; a
    /// no-op when the org has no subscription. `Ok(())` even on a
    /// provider error so the underlying team-membership write does not
    /// roll back (the nightly reconciliation worker is the backstop).
    pub async fn sync_seat_count(
        pool: &PgPool,
        provider: &dyn OrgBillingProvider,
        organization_id: Uuid,
    ) -> Result<(), AppError> {
        let snap = read_snapshot(pool, organization_id).await?;
        let Some(subscription_id) = snap.stripe_subscription_id else {
            return Ok(());
        };
        let seat_count = live_seat_count(pool, organization_id).await?;
        if let Err(e) = provider
            .update_subscription_quantity(&subscription_id, seat_count as i64)
            .await
        {
            // Log but do NOT propagate: the membership write must not
            // roll back on a Stripe hiccup. The nightly reconciliation
            // worker (BUNYIP-693 follow-up) is what closes the drift.
            tracing::warn!(
                error = %e,
                organization_id = %organization_id,
                subscription_id = %subscription_id,
                "sync_seat_count: Stripe update failed; nightly reconciliation will retry"
            );
            return Ok(());
        }
        sqlx::query(
            "UPDATE organizations SET seat_count = $1, subscription_updated_at = NOW() \
             WHERE id = $2",
        )
        .bind(seat_count)
        .bind(organization_id)
        .execute(pool)
        .await
        .map_err(AppError::from)?;
        Ok(())
    }
}

async fn read_snapshot(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<OrgSubscriptionSnapshot, AppError> {
    let snap = sqlx::query_as::<_, OrgSubscriptionSnapshot>(
        "SELECT id AS organization_id, org_tier_id, stripe_subscription_id, \
                subscription_status, seat_count, subscription_updated_at \
         FROM organizations WHERE id = $1",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await
    .map_err(AppError::from)?;
    Ok(snap)
}

async fn live_seat_count(pool: &PgPool, organization_id: Uuid) -> Result<i32, AppError> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM team_members \
         WHERE team_id IN (SELECT id FROM teams WHERE organization_id = $1)",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await
    .map_err(AppError::from)?;
    Ok(count as i32)
}

fn gate(orgs_enabled: bool) -> Result<(), AppError> {
    if orgs_enabled {
        Ok(())
    } else {
        Err(AppError::not_found("Organization"))
    }
}

#[cfg(test)]
pub(crate) use test_support::MockOrgBillingProvider;

#[cfg(test)]
mod test_support {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Mutex;

    /// A `OrgBillingProvider` that records every call so the assertions
    /// in `org_billing_tests.rs` can inspect them without a live Stripe
    /// server. `create_seat_subscription` fabricates a stable id so a
    /// subsequent `update_subscription_quantity` can name it.
    pub(crate) struct MockOrgBillingProvider {
        pub(crate) customer_id: String,
        pub(crate) minted_subscription_id: Mutex<Option<String>>,
        pub(crate) last_quantity: AtomicI64,
        pub(crate) last_price_id: Mutex<Option<String>>,
        pub(crate) cancels: AtomicI64,
    }

    impl MockOrgBillingProvider {
        pub(crate) fn new() -> Self {
            Self {
                customer_id: "cus_test".to_string(),
                minted_subscription_id: Mutex::new(None),
                last_quantity: AtomicI64::new(-1),
                last_price_id: Mutex::new(None),
                cancels: AtomicI64::new(0),
            }
        }
    }

    #[async_trait]
    impl OrgBillingProvider for MockOrgBillingProvider {
        async fn ensure_customer(
            &self,
            _pool: &PgPool,
            _owner_bunyip_user_id: Uuid,
        ) -> Result<String, AppError> {
            Ok(self.customer_id.clone())
        }

        async fn create_seat_subscription(
            &self,
            _customer_id: &str,
            price_id: &str,
            quantity: i64,
        ) -> Result<String, AppError> {
            *self.last_price_id.lock().unwrap() = Some(price_id.to_string());
            self.last_quantity.store(quantity, Ordering::SeqCst);
            let id = format!("sub_{}", Uuid::new_v4().simple());
            *self.minted_subscription_id.lock().unwrap() = Some(id.clone());
            Ok(id)
        }

        async fn update_subscription_quantity(
            &self,
            _subscription_id: &str,
            quantity: i64,
        ) -> Result<(), AppError> {
            self.last_quantity.store(quantity, Ordering::SeqCst);
            Ok(())
        }

        async fn update_subscription_price(
            &self,
            _subscription_id: &str,
            price_id: &str,
        ) -> Result<(), AppError> {
            *self.last_price_id.lock().unwrap() = Some(price_id.to_string());
            Ok(())
        }

        async fn cancel_subscription(
            &self,
            _subscription_id: &str,
            _at_period_end: bool,
        ) -> Result<(), AppError> {
            self.cancels.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
}
