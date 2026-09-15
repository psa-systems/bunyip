//! BUNYIP-693 [BUNYIP-626 followup]: real Stripe implementation of
//! [`bunyip_domain::services::OrgBillingProvider`].
//!
//! Delegates customer creation to `StripeService::create_customer` (the
//! same call the individual-membership path uses, so an owner who
//! already has a Stripe customer id keeps it) and issues the three
//! subscription operations directly against `stripe::Subscription`
//! because those variants (variable-quantity subscriptions, quantity /
//! price updates) are not on the shared dunite `StripeService` today.
//!
//! Constructed once per process and injected via
//! [`actix_web::web::Data`], mirroring the `StripeService` shape. It
//! holds an `Arc<stripe::Client>` built from the same secret key
//! `StripeService` runs on, so a Stripe key rotation replaces both.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use bunyip_domain::errors::AppError;
use bunyip_domain::repositories::UserRepository;
use bunyip_domain::services::{OrgBillingProvider, StripeService};

pub struct StripeOrgBillingProvider {
    stripe: Arc<StripeService>,
    client: Arc<stripe::Client>,
}

impl StripeOrgBillingProvider {
    pub fn new(stripe: Arc<StripeService>, secret_key: &str) -> Self {
        Self {
            stripe,
            client: Arc::new(stripe::Client::new(secret_key.to_string())),
        }
    }
}

#[async_trait]
impl OrgBillingProvider for StripeOrgBillingProvider {
    async fn ensure_customer(
        &self,
        pool: &PgPool,
        owner_bunyip_user_id: Uuid,
    ) -> Result<String, AppError> {
        let user = UserRepository::find_by_id(pool, owner_bunyip_user_id)
            .await?
            .ok_or_else(|| AppError::not_found("User"))?;
        if let Some(id) = user.stripe_customer_id {
            return Ok(id);
        }
        let id = self
            .stripe
            .create_customer(&user.email, owner_bunyip_user_id)
            .await
            .map_err(|e| AppError::upstream(format!("Stripe create_customer failed: {e}")))?;
        UserRepository::update_stripe_customer_id(pool, owner_bunyip_user_id, &id).await?;
        Ok(id)
    }

    async fn create_seat_subscription(
        &self,
        customer_id: &str,
        price_id: &str,
        quantity: i64,
    ) -> Result<String, AppError> {
        let cid: stripe::CustomerId = customer_id
            .parse()
            .map_err(|_| AppError::bad_request("Invalid Stripe customer id"))?;
        let pid: stripe::PriceId = price_id
            .parse()
            .map_err(|_| AppError::bad_request("Invalid Stripe price id"))?;
        let mut params = stripe::CreateSubscription::new(cid);
        params.items = Some(vec![stripe::CreateSubscriptionItems {
            price: Some(pid.to_string()),
            quantity: Some(quantity.max(0) as u64),
            ..Default::default()
        }]);
        let sub = stripe::Subscription::create(&self.client, params)
            .await
            .map_err(|e| {
                AppError::upstream(format!("Stripe create seat subscription failed: {e}"))
            })?;
        Ok(sub.id.to_string())
    }

    async fn update_subscription_quantity(
        &self,
        subscription_id: &str,
        quantity: i64,
    ) -> Result<(), AppError> {
        let sid: stripe::SubscriptionId = subscription_id
            .parse()
            .map_err(|_| AppError::bad_request("Invalid Stripe subscription id"))?;
        // Read current items so the update names the same subscription
        // item id; Stripe requires it when there is more than one item on
        // the subscription, and the org path only has one so we pick it.
        let sub = stripe::Subscription::retrieve(&self.client, &sid, &[])
            .await
            .map_err(|e| AppError::upstream(format!("Stripe retrieve subscription failed: {e}")))?;
        let item_id = sub
            .items
            .data
            .first()
            .map(|item| item.id.clone())
            .ok_or_else(|| AppError::upstream("Stripe subscription has no items"))?;
        // Stripe defaults to `create_prorations`, which is what a seat
        // change wants, so we leave `proration_behavior` unset rather
        // than name it (the async-stripe crate re-exports two enums with
        // the same simple name from different scopes).
        let params = stripe::UpdateSubscription {
            items: Some(vec![stripe::UpdateSubscriptionItems {
                id: Some(item_id.to_string()),
                quantity: Some(quantity.max(0) as u64),
                ..Default::default()
            }]),
            ..Default::default()
        };
        stripe::Subscription::update(&self.client, &sid, params)
            .await
            .map_err(|e| {
                AppError::upstream(format!("Stripe update subscription quantity failed: {e}"))
            })?;
        Ok(())
    }

    async fn update_subscription_price(
        &self,
        subscription_id: &str,
        price_id: &str,
    ) -> Result<(), AppError> {
        let sid: stripe::SubscriptionId = subscription_id
            .parse()
            .map_err(|_| AppError::bad_request("Invalid Stripe subscription id"))?;
        let sub = stripe::Subscription::retrieve(&self.client, &sid, &[])
            .await
            .map_err(|e| AppError::upstream(format!("Stripe retrieve subscription failed: {e}")))?;
        let (item_id, current_quantity) = sub
            .items
            .data
            .first()
            .map(|item| (item.id.clone(), item.quantity.unwrap_or(1)))
            .ok_or_else(|| AppError::upstream("Stripe subscription has no items"))?;
        let params = stripe::UpdateSubscription {
            items: Some(vec![stripe::UpdateSubscriptionItems {
                id: Some(item_id.to_string()),
                price: Some(price_id.to_string()),
                quantity: Some(current_quantity),
                ..Default::default()
            }]),
            ..Default::default()
        };
        stripe::Subscription::update(&self.client, &sid, params)
            .await
            .map_err(|e| {
                AppError::upstream(format!("Stripe update subscription price failed: {e}"))
            })?;
        Ok(())
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
        at_period_end: bool,
    ) -> Result<(), AppError> {
        self.stripe
            .cancel_subscription(subscription_id, at_period_end)
            .await
            .map_err(|e| AppError::upstream(format!("Stripe cancel subscription failed: {e}")))?;
        Ok(())
    }
}
