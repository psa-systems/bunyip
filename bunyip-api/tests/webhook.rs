//! BUNYIP-941 regression test.
//!
//! A `customer.subscription.updated` webhook whose status does not grant
//! access (e.g. `canceled`) must never set `lifetime_member = true`, even
//! when the subscription's product maps to `tc.lifetime_product_id`. Before
//! this fix, `handle_subscription_updated` called `upgrade_membership_tier`
//! unconditionally, so a canceled lifetime-product subscription still
//! granted permanent free access.
//!
//! Env-gated like the other DB-backed integration tests: with
//! `BUNYIP_TEST_DATABASE_URL` / `RLS_TEST_DATABASE_URL` unset it skips and
//! stays green (bunyip CI has no Postgres service).
//!
//! ```sh
//! BUNYIP_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_941_test \
//!   cargo test -p bunyip-api --test webhook -- --nocapture
//! ```

use std::sync::{Arc, RwLock};

use actix_web::{test, web, App};
use bunyip_api::config::TierConfig;
use bunyip_api::models::{CreateUser, UserRole};
use bunyip_api::repositories::UserRepository;
use bunyip_api::services::{EmailService, StripeConfig, StripeService};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

const WEBHOOK_SECRET: &str = "whsec_bunyip_941_test_secret";
const LIFETIME_PRODUCT_ID: &str = "prod_bunyip_941_lifetime";

async fn maybe_pool() -> Option<PgPool> {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"))
        .ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()?;
    // A fresh throwaway database has no `bunyip_app` role yet, and later
    // migrations GRANT to it, so it must exist before `migrate!` runs.
    bunyip_api::db::provision_app_role(&pool, "bunyip_941_test_app_pw")
        .await
        .expect("provision bunyip_app role");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

fn configured_stripe_config() -> StripeConfig {
    StripeConfig {
        secret_key: "sk_test_bunyip_941".to_string(),
        webhook_secret: WEBHOOK_SECRET.to_string(),
        success_url: "https://example.test/success".to_string(),
        cancel_url: "https://example.test/cancel".to_string(),
        free_price_id: None,
        app_tag: "bunyip".to_string(),
        trial_period_days: 30,
    }
}

fn lifetime_tier_config() -> TierConfig {
    TierConfig {
        lifetime_slots: 100,
        early_adopter_slots: 100,
        early_adopter_trial_days: 14,
        standard_trial_days: 14,
        free_price_id: None,
        early_adopter_price_id: None,
        standard_price_id: None,
        lifetime_product_id: Some(LIFETIME_PRODUCT_ID.to_string()),
        early_adopter_product_id: None,
        standard_product_id: None,
        pricing_enabled: false,
        lifetime_visible: true,
        early_adopter_visible: true,
        standard_visible: true,
        orgs_enabled: false,
    }
}

/// Stripe's own webhook signing scheme: `t=<unix_seconds>,v1=<hex hmac-sha256
/// of "{t}.{payload}" under the webhook secret>`, matching
/// `dunite_stripe_core::verify_webhook_signature`.
fn sign(secret: &str, payload: &str) -> String {
    let timestamp = Utc::now().timestamp();
    let signed_payload = format!("{timestamp}.{payload}");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(signed_payload.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    format!("t={timestamp},v1={signature}")
}

async fn seed_customer(pool: &PgPool, customer_id: &str) -> Uuid {
    let email = format!("bunyip-941-{}@example.test", Uuid::new_v4().simple());
    let user = UserRepository::create(
        pool,
        CreateUser {
            email,
            password_hash: Some("x".to_string()),
            role: UserRole::Subscriber,
        },
    )
    .await
    .expect("seed user");
    UserRepository::update_stripe_customer_id(pool, user.id, customer_id)
        .await
        .expect("attach stripe customer id");
    user.id
}

fn subscription_updated_event(event_id: &str, customer_id: &str, status: &str) -> String {
    serde_json::json!({
        "id": event_id,
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_bunyip_941_test",
                "customer": customer_id,
                "status": status,
                "cancel_at_period_end": false,
                "items": {
                    "data": [{
                        "price": {
                            "id": "price_bunyip_941_test",
                            "product": LIFETIME_PRODUCT_ID,
                            "unit_amount": 0,
                        }
                    }]
                }
            }
        }
    })
    .to_string()
}

/// A canceled `subscription.updated` on a subscription mapped to the lifetime
/// product must leave `lifetime_member = false` and must not raise
/// `membership_tier`, matching the acceptance criteria in BUNYIP-941.
#[actix_rt::test]
async fn canceled_update_on_lifetime_product_does_not_grant_lifetime() {
    let Some(pool) = maybe_pool().await else {
        return;
    };

    let customer_id = format!("cus_bunyip_941_{}", Uuid::new_v4().simple());
    let user_id = seed_customer(&pool, &customer_id).await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(Arc::new(StripeService::new(
                configured_stripe_config(),
            ))))
            .app_data(web::Data::new(Arc::new(EmailService::new_dev())))
            .app_data(web::Data::new(Arc::new(
                RwLock::new(lifetime_tier_config()),
            )))
            .service(web::scope("/v1").configure(bunyip_api::routes::webhook::configure)),
    )
    .await;

    let event_id = format!("evt_bunyip_941_{}", Uuid::new_v4().simple());
    let payload = subscription_updated_event(&event_id, &customer_id, "canceled");
    let signature = sign(WEBHOOK_SECRET, &payload);

    let req = test::TestRequest::post()
        .uri("/v1/webhooks/stripe")
        .insert_header(("Stripe-Signature", signature))
        .insert_header(("Content-Type", "application/json"))
        .set_payload(payload)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_success(),
        "webhook delivery must succeed, got {}",
        resp.status()
    );

    let user = UserRepository::find_by_id(&pool, user_id)
        .await
        .expect("find user")
        .expect("user still exists");
    assert!(
        !user.lifetime_member,
        "a canceled subscription.updated must never set lifetime_member"
    );
    assert_eq!(
        user.membership_tier, "standard",
        "a canceled subscription.updated must not raise membership_tier"
    );
}
