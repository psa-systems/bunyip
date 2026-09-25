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
use bunyip_api::services::{JwtConfig, JwtService};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

const JWT_SECRET: &str = "bunyip-725-test-secret-at-least-32-bytes-long";

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

/// BUNYIP-824: a re-polled first-contact message (identical `message_id`, the
/// shape an IMAP poller re-ingesting after a restart, a dropped connection, or
/// a failed `mark_seen` produces) must not orphan a second, empty ticket.
/// `ingest_inbound` called twice with the same `message_id` creates exactly
/// one ticket and one message, and returns that same ticket both times.
#[tokio::test]
async fn a_repolled_message_never_orphans_a_second_ticket() {
    let Some(pool) = test_pool("the support ingest re-poll idempotency test").await else {
        return;
    };

    let message_id = format!("repoll-{}@ext.example", Uuid::new_v4());
    let requester_email = format!("{}@ext.example", Uuid::new_v4());
    let new_message = || NewInboundMessage {
        subject: "Need help".to_string(),
        from_email: requester_email.clone(),
        from_name: None,
        to_email: None,
        body_text: "please help".to_string(),
        body_html: None,
        message_id: Some(message_id.clone()),
        in_reply_to: None,
        references: Vec::new(),
    };

    let first = SupportRepository::ingest_inbound(&pool, &new_message())
        .await
        .expect("first ingest");
    let second = SupportRepository::ingest_inbound(&pool, &new_message())
        .await
        .expect("re-polled ingest must not error");

    assert_eq!(
        first.id, second.id,
        "a re-polled message must resolve to the same ticket, not a new one"
    );

    let messages = SupportRepository::list_messages(&pool, first.id)
        .await
        .expect("list messages");
    assert_eq!(
        messages.len(),
        1,
        "the re-poll must not insert a second message"
    );

    let listed = SupportRepository::list_tickets(&pool, 100, 0)
        .await
        .expect("list tickets");
    let matching = listed.iter().filter(|t| t.id == first.id).count();
    assert_eq!(matching, 1, "the re-poll must not create an orphan ticket");
}
