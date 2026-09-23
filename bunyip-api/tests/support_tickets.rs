//! BUNYIP-725: the reply endpoint's ticket id must be obtainable from the list
//! endpoint, so the read half and the reply half of the support queue cannot be
//! split apart again.
//!
//! Env-gated like `rls_isolation.rs` / `applications_catalog.rs`: it needs a
//! throwaway Postgres to migrate. Set `BUNYIP_TEST_DATABASE_URL` (or reuse
//! `RLS_TEST_DATABASE_URL`) to a database this test may migrate; unset skips
//! the test.

use actix_web::{test, web, App};
use bunyip_api::config::AutoBanConfig;
use bunyip_api::middleware::AutoBanService;
use bunyip_api::models::{CreateUser, NewInboundMessage, UserRole};
use bunyip_api::repositories::{SupportRepository, UserRepository};
use bunyip_api::services::{EmailService, JwtConfig, JwtService};
use bunyip_api::Config;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

const JWT_SECRET: &str = "bunyip-725-test-secret-at-least-32-bytes-long";

/// A minimal `Config` built the same way `config.rs`'s own
/// `test_config_defaults` does: the handful of variables `from_env_inner`
/// needs outside production mode, so it resolves without the full startup
/// secret set. The reply handler only reads `config.email.from_email` on the
/// success path, which this test never reaches.
fn test_config() -> Config {
    std::env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
    std::env::set_var("ENVIRONMENT", "development");
    std::env::set_var("SECRETS_STORAGE", "database");
    std::env::set_var("HOST_IP", "0.0.0.0");
    std::env::set_var("APP_PORT", "4000");
    Config::from_env().expect("minimal config resolves outside production")
}

async fn test_pool(purpose: &str) -> Option<sqlx::PgPool> {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"));
    let Ok(url) = url else {
        eprintln!("BUNYIP_TEST_DATABASE_URL / RLS_TEST_DATABASE_URL unset; skipping {purpose}");
        return None;
    };
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("connect to test database");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

/// A ticket ingested into the support queue (what the poller does on a
/// successful fetch) shows up in `list_tickets`, and the id `list_tickets`
/// returns is the same id `get_ticket` (what the reply endpoint resolves its
/// path parameter against) accepts.
#[tokio::test]
async fn a_ticket_visible_in_the_list_is_the_id_the_reply_endpoint_resolves() {
    let Some(pool) = test_pool("the support ticket list/reply id test").await else {
        return;
    };

    let subject = format!("support-list-test-{}", uuid::Uuid::new_v4());
    let requester_email = format!("{}@ext.example", uuid::Uuid::new_v4());
    let created = SupportRepository::create_ticket(&pool, &subject, &requester_email, None)
        .await
        .expect("create ticket");

    let listed = SupportRepository::list_tickets(&pool, 100, 0)
        .await
        .expect("list tickets");
    let found = listed
        .iter()
        .find(|t| t.id == created.id)
        .expect("newly created ticket appears in the list endpoint's backing query");

    // The id the list endpoint hands the caller is exactly the id the reply
    // endpoint's path extractor resolves (both go through `get_ticket`).
    let resolved = SupportRepository::get_ticket(&pool, found.id)
        .await
        .expect("get_ticket")
        .expect("ticket resolves by the id the list endpoint returned");
    assert_eq!(resolved.id, created.id);
    assert_eq!(resolved.requester_email, requester_email);

    let total = SupportRepository::count_tickets(&pool)
        .await
        .expect("count tickets");
    assert!(total >= 1);
}

/// HTTP-level: ingesting a message the way the poller does (a successful
/// `ingest_inbound`) makes the ticket and its message reachable through the
/// admin-gated list and detail routes mounted in `routes::admin::configure`
/// (BUNYIP-725 AC1 and AC3).
#[actix_rt::test]
async fn an_ingested_ticket_is_readable_through_the_admin_routes() {
    let Some(pool) = test_pool("the support ticket admin-route test").await else {
        return;
    };

    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let auto_ban = Arc::new(AutoBanService::new(
        AutoBanConfig {
            enabled: true,
            threshold: 5,
            window_secs: 3600,
            ban_duration_secs: 86400,
        },
        pool.clone(),
    ));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(jwt.clone())
            .app_data(web::Data::from(auto_ban.clone()))
            .service(web::scope("/v1").configure(bunyip_api::routes::admin::configure)),
    )
    .await;

    let email = format!("gate-{}@example.test", Uuid::new_v4().simple());
    let admin = UserRepository::create(
        &pool,
        CreateUser {
            email,
            password_hash: Some("x".to_string()),
            role: UserRole::Admin,
        },
    )
    .await
    .expect("seed admin");
    let bearer = format!(
        "Bearer {}",
        jwt.create_access_token(&admin).expect("mint access token")
    );

    let requester_email = format!("{}@ext.example", Uuid::new_v4());
    let message_id = format!("msg-{}@ext.example", Uuid::new_v4());
    let ticket = SupportRepository::ingest_inbound(
        &pool,
        &NewInboundMessage {
            subject: "Need help".to_string(),
            from_email: requester_email.clone(),
            from_name: None,
            to_email: None,
            body_text: "please help".to_string(),
            body_html: None,
            message_id: Some(message_id),
            in_reply_to: None,
            references: Vec::new(),
        },
    )
    .await
    .expect("ingest inbound message");

    // The list route (AC1: AdminUser-gated, backed by list_tickets) surfaces
    // the ingested ticket.
    let req = test::TestRequest::get()
        .uri("/v1/admin/support/tickets")
        .insert_header(("authorization", bearer.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let ids: Vec<String> = body["data"]["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|t| t["id"].as_str().unwrap().to_string())
        .collect();
    assert!(
        ids.contains(&ticket.id.to_string()),
        "ingested ticket must appear in the list route"
    );

    // The detail route (AC1: backed by get_ticket + list_messages) returns the
    // same ticket id the reply route's path parameter resolves, with its
    // ingested message (AC3).
    let req = test::TestRequest::get()
        .uri(&format!("/v1/admin/support/tickets/{}", ticket.id))
        .insert_header(("authorization", bearer))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["data"]["ticket"]["id"].as_str(),
        Some(ticket.id.to_string()).as_deref()
    );
    let messages = body["data"]["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["body_text"].as_str(), Some("please help"));

    // Unauthenticated is refused, proving the gate is live and not vestigial.
    let req = test::TestRequest::get()
        .uri("/v1/admin/support/tickets")
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), 401);
}

/// BUNYIP-825: with email disabled, the reply route must not write a phantom
/// outbound message or move the ticket to `pending`, because `send_support_reply`
/// now errors instead of returning a fabricated Message-ID for a reply that
/// never left the deployment.
#[actix_rt::test]
async fn a_reply_with_email_disabled_leaves_the_ticket_unchanged() {
    let Some(pool) = test_pool("the disabled-email reply regression test").await else {
        return;
    };

    let jwt = Arc::new(JwtService::new(JwtConfig::from_secret(
        JWT_SECRET,
        "bunyip-test",
    )));
    let auto_ban = Arc::new(AutoBanService::new(
        AutoBanConfig {
            enabled: true,
            threshold: 5,
            window_secs: 3600,
            ban_duration_secs: 86400,
        },
        pool.clone(),
    ));
    let config = test_config();
    let mut email_config = config.email.clone();
    email_config.enabled = false;
    let (email_service, stub) = EmailService::new_capturing(email_config);
    let email_service = Arc::new(email_service);

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(email_service))
            .app_data(jwt.clone())
            .app_data(web::Data::from(auto_ban.clone()))
            .service(web::scope("/v1").configure(bunyip_api::routes::admin::configure)),
    )
    .await;

    let email = format!("gate-{}@example.test", Uuid::new_v4().simple());
    let admin = UserRepository::create(
        &pool,
        CreateUser {
            email,
            password_hash: Some("x".to_string()),
            role: UserRole::Admin,
        },
    )
    .await
    .expect("seed admin");
    let bearer = format!(
        "Bearer {}",
        jwt.create_access_token(&admin).expect("mint access token")
    );

    let requester_email = format!("{}@ext.example", Uuid::new_v4());
    let message_id = format!("msg-{}@ext.example", Uuid::new_v4());
    let ticket = SupportRepository::ingest_inbound(
        &pool,
        &NewInboundMessage {
            subject: "Need help".to_string(),
            from_email: requester_email,
            from_name: None,
            to_email: None,
            body_text: "please help".to_string(),
            body_html: None,
            message_id: Some(message_id),
            in_reply_to: None,
            references: Vec::new(),
        },
    )
    .await
    .expect("ingest inbound message");

    let messages_before = SupportRepository::list_messages(&pool, ticket.id)
        .await
        .expect("list messages before the reply attempt");
    let status_before = SupportRepository::get_ticket(&pool, ticket.id)
        .await
        .expect("get ticket before the reply attempt")
        .expect("ticket exists")
        .status;

    let req = test::TestRequest::post()
        .uri(&format!("/v1/admin/support/tickets/{}/reply", ticket.id))
        .insert_header(("authorization", bearer))
        .set_json(serde_json::json!({ "message": "Thanks for reaching out." }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "a reply attempt with email disabled must not report success, got {}",
        resp.status()
    );

    assert!(
        stub.messages().await.is_empty(),
        "no message may reach the transport when email is disabled"
    );

    let messages_after = SupportRepository::list_messages(&pool, ticket.id)
        .await
        .expect("list messages after the reply attempt");
    assert_eq!(
        messages_after.len(),
        messages_before.len(),
        "no outbound support_messages row may be written when the send failed"
    );

    let status_after = SupportRepository::get_ticket(&pool, ticket.id)
        .await
        .expect("get ticket after the reply attempt")
        .expect("ticket still exists")
        .status;
    assert_eq!(
        status_after, status_before,
        "the ticket must not move to pending when the reply was never sent"
    );
}
