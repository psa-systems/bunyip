//! BUNYIP-693 integration tests for [`OrgBillingService`].
//!
//! Env-gated on `BUNYIP_TEST_DATABASE_URL` / `RLS_TEST_DATABASE_URL` the
//! same way `org_pricing_tests.rs` and `organizations_tests.rs` are.
//! Uses `MockOrgBillingProvider` in place of a real Stripe client so
//! the tests inspect the shape of the calls without a Stripe server.

#![cfg(test)]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::atomic::Ordering;
use uuid::Uuid;

use crate::errors::AppError;
use crate::services::org_billing::MockOrgBillingProvider;
use crate::services::{OrgBillingService, OrgPricingService, OrganizationsService, TeamsService};

use crate::models::CreateOrgPricingTierRequest;

async fn maybe_pool() -> Option<PgPool> {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"))
        .ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("../../bunyip-api/migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

async fn seed_user(pool: &PgPool, email: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, email_verified, is_active) \
         VALUES ($1, $2, 'not-real-not-used', TRUE, TRUE)",
    )
    .bind(id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed user");
    id
}

fn tier_req(name: &str) -> CreateOrgPricingTierRequest {
    CreateOrgPricingTierRequest {
        name: name.to_string(),
        stripe_price_id: format!(
            "price_{}_{}",
            name.to_ascii_lowercase(),
            Uuid::new_v4().simple()
        ),
        included_seats: 0,
        seat_cap: None,
        visibility: "public".to_string(),
        sort_order: 0,
    }
}

#[tokio::test]
async fn subscribe_refuses_when_the_tier_is_unset() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "sub-notier@example.test").await;
    OrganizationsService::create(&pool, true, owner, "Ops")
        .await
        .expect("create org");
    let provider = MockOrgBillingProvider::new();
    let result = OrgBillingService::subscribe(&pool, true, &provider, owner).await;
    assert!(matches!(result, Err(AppError::BadRequest(_))));
}

#[tokio::test]
async fn subscribe_creates_and_records_the_subscription() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "sub-create@example.test").await;
    OrganizationsService::create(&pool, true, owner, "Ops")
        .await
        .expect("create org");
    let tier = OrgPricingService::admin_create(&pool, true, tier_req("Standard"))
        .await
        .expect("create tier");
    OrgPricingService::set_organization_tier(&pool, true, owner, tier.id)
        .await
        .expect("set tier");

    let provider = MockOrgBillingProvider::new();
    let snap = OrgBillingService::subscribe(&pool, true, &provider, owner)
        .await
        .expect("subscribe");
    assert!(snap.stripe_subscription_id.is_some());
    assert_eq!(snap.subscription_status.as_deref(), Some("active"));
    assert_eq!(snap.seat_count, 0);
    assert_eq!(
        provider.last_price_id.lock().unwrap().as_deref(),
        Some(tier.stripe_price_id.as_str())
    );
    assert_eq!(provider.last_quantity.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_second_subscribe_is_409() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "sub-second@example.test").await;
    OrganizationsService::create(&pool, true, owner, "Ops")
        .await
        .expect("create org");
    let tier = OrgPricingService::admin_create(&pool, true, tier_req("Standard"))
        .await
        .expect("create tier");
    OrgPricingService::set_organization_tier(&pool, true, owner, tier.id)
        .await
        .expect("set tier");
    let provider = MockOrgBillingProvider::new();
    OrgBillingService::subscribe(&pool, true, &provider, owner)
        .await
        .expect("first subscribe");
    let second = OrgBillingService::subscribe(&pool, true, &provider, owner).await;
    assert!(
        matches!(second, Err(AppError::Conflict { .. })),
        "second subscribe must Conflict, got {second:?}"
    );
}

#[tokio::test]
async fn sync_seat_count_pushes_the_live_count_to_the_provider() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "sync-owner@example.test").await;
    let member = seed_user(&pool, "sync-member@example.test").await;
    OrganizationsService::create(&pool, true, owner, "Ops")
        .await
        .expect("create org");
    let tier = OrgPricingService::admin_create(&pool, true, tier_req("Standard"))
        .await
        .expect("create tier");
    OrgPricingService::set_organization_tier(&pool, true, owner, tier.id)
        .await
        .expect("set tier");
    let team = TeamsService::create(&pool, true, owner, "SRE", None)
        .await
        .expect("create team");
    let provider = MockOrgBillingProvider::new();
    OrgBillingService::subscribe(&pool, true, &provider, owner)
        .await
        .expect("subscribe");
    // Zero members at subscribe time.
    assert_eq!(provider.last_quantity.load(Ordering::SeqCst), 0);

    TeamsService::add_member(&pool, true, owner, team.id, member, "member")
        .await
        .expect("add member");
    OrgBillingService::sync_seat_count_for_team(&pool, &provider, team.id)
        .await
        .expect("sync after add");
    assert_eq!(provider.last_quantity.load(Ordering::SeqCst), 1);

    TeamsService::remove_member(&pool, true, owner, team.id, member)
        .await
        .expect("remove member");
    OrgBillingService::sync_seat_count_for_team(&pool, &provider, team.id)
        .await
        .expect("sync after remove");
    assert_eq!(provider.last_quantity.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn change_tier_calls_update_price_after_the_tier_column_moves() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "change-owner@example.test").await;
    OrganizationsService::create(&pool, true, owner, "Ops")
        .await
        .expect("create org");
    let a = OrgPricingService::admin_create(&pool, true, tier_req("A"))
        .await
        .expect("create A");
    let b = OrgPricingService::admin_create(&pool, true, tier_req("B"))
        .await
        .expect("create B");
    OrgPricingService::set_organization_tier(&pool, true, owner, a.id)
        .await
        .expect("set A");
    let provider = MockOrgBillingProvider::new();
    OrgBillingService::subscribe(&pool, true, &provider, owner)
        .await
        .expect("subscribe");
    // Move the tier column to B, then call change_tier.
    OrgPricingService::set_organization_tier(&pool, true, owner, b.id)
        .await
        .expect("set B");
    OrgBillingService::change_tier(&pool, true, &provider, owner)
        .await
        .expect("change_tier");
    assert_eq!(
        provider.last_price_id.lock().unwrap().as_deref(),
        Some(b.stripe_price_id.as_str())
    );
}

#[tokio::test]
async fn cancel_records_canceled_and_calls_the_provider() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "cancel-owner@example.test").await;
    OrganizationsService::create(&pool, true, owner, "Ops")
        .await
        .expect("create org");
    let tier = OrgPricingService::admin_create(&pool, true, tier_req("Standard"))
        .await
        .expect("create tier");
    OrgPricingService::set_organization_tier(&pool, true, owner, tier.id)
        .await
        .expect("set tier");
    let provider = MockOrgBillingProvider::new();
    OrgBillingService::subscribe(&pool, true, &provider, owner)
        .await
        .expect("subscribe");
    let snap = OrgBillingService::cancel(&pool, true, &provider, owner)
        .await
        .expect("cancel");
    assert_eq!(snap.subscription_status.as_deref(), Some("canceled"));
    assert_eq!(provider.cancels.load(Ordering::SeqCst), 1);
}
