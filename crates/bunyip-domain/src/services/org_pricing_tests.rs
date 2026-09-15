//! BUNYIP-692 integration tests for [`OrgPricingService`].
//!
//! Env-gated the same way the sibling `organizations_tests.rs` and
//! `mailer_relay.rs` are: with `BUNYIP_TEST_DATABASE_URL` /
//! `RLS_TEST_DATABASE_URL` unset the tests skip and stay green. Set one
//! to a throwaway database and the tests migrate + exercise the service
//! directly against the pool.
//!
//! ```sh
//! BUNYIP_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_692_test \
//!   cargo test -p bunyip-domain --lib services::org_pricing_tests
//! ```
//!
//! Covers the ticket ACs: flag-off returns [] or 404 per shape; admin
//! CRUD round-trips; `stripe_price_id` UNIQUE refuses a duplicate; a
//! hidden tier is filtered from the public payload; the org's tier is
//! set through `set_organization_tier` and cleared through
//! `clear_organization_tier`; a hidden tier is refused for a caller not
//! currently on it.

#![cfg(test)]

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{
    CreateOrgPricingTierRequest, ReorderOrgPricingTiersRequest, UpdateOrgPricingTierRequest,
};
use crate::services::{OrgPricingService, OrganizationsService};

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

/// Unique-ish Stripe price ids per test so parallel sqlx tests do not
/// clash on the `UNIQUE(stripe_price_id)` constraint.
fn price_id(label: &str) -> String {
    format!("price_{label}_{}", Uuid::new_v4().simple())
}

fn create_req(
    name: &str,
    price: &str,
    included: i32,
    cap: Option<i32>,
    visibility: &str,
) -> CreateOrgPricingTierRequest {
    CreateOrgPricingTierRequest {
        name: name.to_string(),
        stripe_price_id: price.to_string(),
        included_seats: included,
        seat_cap: cap,
        visibility: visibility.to_string(),
        sort_order: 0,
    }
}

#[tokio::test]
async fn flag_off_public_list_is_empty_and_admin_list_is_not_found() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let public = OrgPricingService::public_list(&pool, false).await.unwrap();
    assert!(
        public.is_empty(),
        "public list must be empty when flag is off"
    );

    let admin = OrgPricingService::admin_list(&pool, false).await;
    assert!(
        matches!(admin, Err(AppError::NotFound { .. })),
        "admin list must be 404 when flag is off"
    );
}

#[tokio::test]
async fn admin_create_and_list_round_trips() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let tier = OrgPricingService::admin_create(
        &pool,
        true,
        create_req("Standard", &price_id("std"), 5, Some(50), "public"),
    )
    .await
    .expect("create");
    assert_eq!(tier.name, "Standard");
    assert_eq!(tier.included_seats, 5);
    assert_eq!(tier.seat_cap, Some(50));
    assert_eq!(tier.visibility, "public");

    let all = OrgPricingService::admin_list(&pool, true)
        .await
        .expect("list");
    assert!(all.iter().any(|t| t.id == tier.id));
}

#[tokio::test]
async fn duplicate_stripe_price_id_is_409() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let price = price_id("dup");
    OrgPricingService::admin_create(&pool, true, create_req("First", &price, 0, None, "public"))
        .await
        .expect("first create");
    let second = OrgPricingService::admin_create(
        &pool,
        true,
        create_req("Second", &price, 0, None, "public"),
    )
    .await;
    assert!(
        matches!(second, Err(AppError::Conflict { .. })),
        "duplicate stripe_price_id must Conflict, got {second:?}"
    );
}

#[tokio::test]
async fn hidden_tier_is_filtered_from_the_public_catalogue() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let public_tier = OrgPricingService::admin_create(
        &pool,
        true,
        create_req("Visible", &price_id("vis"), 0, None, "public"),
    )
    .await
    .expect("create public");
    let hidden_tier = OrgPricingService::admin_create(
        &pool,
        true,
        create_req("Retired", &price_id("hid"), 0, None, "hidden"),
    )
    .await
    .expect("create hidden");

    let public_list = OrgPricingService::public_list(&pool, true).await.unwrap();
    assert!(public_list.iter().any(|t| t.id == public_tier.id));
    assert!(
        !public_list.iter().any(|t| t.id == hidden_tier.id),
        "hidden tier must not appear in the public list"
    );

    // Admin still sees it.
    let admin_list = OrgPricingService::admin_list(&pool, true).await.unwrap();
    assert!(admin_list.iter().any(|t| t.id == hidden_tier.id));
}

#[tokio::test]
async fn admin_update_touches_only_supplied_fields() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let tier = OrgPricingService::admin_create(
        &pool,
        true,
        create_req("Original", &price_id("orig"), 3, Some(10), "public"),
    )
    .await
    .expect("create");

    let renamed = OrgPricingService::admin_update(
        &pool,
        true,
        tier.id,
        UpdateOrgPricingTierRequest {
            name: Some("Renamed".to_string()),
            ..Default::default()
        },
    )
    .await
    .expect("update");
    assert_eq!(renamed.name, "Renamed");
    assert_eq!(renamed.included_seats, 3);
    assert_eq!(renamed.seat_cap, Some(10));
    assert_eq!(renamed.stripe_price_id, tier.stripe_price_id);
}

#[tokio::test]
async fn admin_update_can_clear_seat_cap_to_null_explicitly() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let tier = OrgPricingService::admin_create(
        &pool,
        true,
        create_req("Capped", &price_id("cap"), 0, Some(20), "public"),
    )
    .await
    .expect("create");

    let uncapped = OrgPricingService::admin_update(
        &pool,
        true,
        tier.id,
        UpdateOrgPricingTierRequest {
            seat_cap: Some(None),
            ..Default::default()
        },
    )
    .await
    .expect("clear cap");
    assert_eq!(uncapped.seat_cap, None);
}

#[tokio::test]
async fn admin_reorder_rewrites_sort_order_by_position() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let a = OrgPricingService::admin_create(
        &pool,
        true,
        create_req("A", &price_id("a"), 0, None, "public"),
    )
    .await
    .expect("a");
    let b = OrgPricingService::admin_create(
        &pool,
        true,
        create_req("B", &price_id("b"), 0, None, "public"),
    )
    .await
    .expect("b");
    let c = OrgPricingService::admin_create(
        &pool,
        true,
        create_req("C", &price_id("c"), 0, None, "public"),
    )
    .await
    .expect("c");

    OrgPricingService::admin_reorder(
        &pool,
        true,
        ReorderOrgPricingTiersRequest {
            ids: vec![c.id, a.id, b.id],
        },
    )
    .await
    .expect("reorder");

    let mut listed = OrgPricingService::admin_list(&pool, true)
        .await
        .expect("list");
    listed.retain(|t| [a.id, b.id, c.id].contains(&t.id));
    let ordered_ids: Vec<Uuid> = listed.iter().map(|t| t.id).collect();
    assert_eq!(ordered_ids, vec![c.id, a.id, b.id]);
}

#[tokio::test]
async fn owner_sets_and_clears_their_org_tier() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "tier-owner@example.test").await;
    OrganizationsService::create(&pool, true, owner, "Ops")
        .await
        .expect("create org");
    let tier = OrgPricingService::admin_create(
        &pool,
        true,
        create_req("Standard", &price_id("owner-std"), 5, None, "public"),
    )
    .await
    .expect("create tier");

    OrgPricingService::set_organization_tier(&pool, true, owner, tier.id)
        .await
        .expect("set tier");

    OrgPricingService::clear_organization_tier(&pool, true, owner)
        .await
        .expect("clear tier");
}

#[tokio::test]
async fn hidden_tier_refuses_a_caller_not_currently_on_it() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let owner = seed_user(&pool, "hidden-tier-owner@example.test").await;
    OrganizationsService::create(&pool, true, owner, "Ops")
        .await
        .expect("create org");
    let hidden = OrgPricingService::admin_create(
        &pool,
        true,
        create_req("Retired", &price_id("retired"), 0, None, "hidden"),
    )
    .await
    .expect("create hidden");

    let result = OrgPricingService::set_organization_tier(&pool, true, owner, hidden.id).await;
    assert!(
        matches!(result, Err(AppError::NotFound { .. })),
        "hidden tier must be refused for a caller not currently on it, got {result:?}"
    );
}
