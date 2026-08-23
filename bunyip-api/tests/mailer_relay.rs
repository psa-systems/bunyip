//! BUNYIP-602 mailer relay integration test.
//!
//! Drives `POST /v1/mailer/send` through the real HTTP stack against a real
//! `oauth_clients` registration and a MOCKED SMTP transport
//! (`EmailService::new_capturing`), proving at the wire:
//!
//! - a registered calling app's credential relays a message, and the message
//!   actually reached the transport from Bunyip's own sending identity;
//! - an unauthenticated / wrongly-authenticated / unentitled caller is refused
//!   401 / 403 and nothing reaches the transport;
//! - exceeding the per-calling-app cap answers 429 with `Retry-After`, and the
//!   cap is charged per app rather than per source IP.
//!
//! Env-gated the same way the other DB-backed integration tests are: with
//! `BUNYIP_TEST_DATABASE_URL` / `RLS_TEST_DATABASE_URL` unset it skips and stays
//! green (bunyip CI has no Postgres service). The URL must point at a
//! throwaway database this test may migrate:
//!
//! ```sh
//! BUNYIP_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_602_test \
//!   cargo test -p bunyip-api --test mailer_relay -- --nocapture
//! ```

use actix_web::{test, web, App};
use base64::Engine;
use bunyip_api::config::{EmailConfig, SmtpTls};
use bunyip_api::models::RateLimitConfig;
use bunyip_api::repositories::{RateLimitConfigRepository, RateLimitRepository};
use bunyip_api::services::{AsyncStubTransport, EmailService, MailerRelay, NoSuppression};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const CLIENT_SECRET: &str = "relay-test-secret-value";

async fn maybe_pool() -> Option<PgPool> {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"))
        .ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .ok()?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

/// The sending identity every relayed message must carry.
fn relay_email_config() -> EmailConfig {
    EmailConfig {
        smtp_host: "smtp.example.test".to_string(),
        smtp_port: 587,
        smtp_tls: SmtpTls::Starttls,
        smtp_username: "relay".to_string(),
        smtp_password: "pw".to_string(),
        smtp_ehlo_name: None,
        from_email: "noreply@mail.a8n.systems".to_string(),
        from_name: "PSA Systems".to_string(),
        base_url: "https://a8n.systems".to_string(),
        enabled: true,
        log_tokens: false,
        app_name: "PSA Systems".to_string(),
        admin_notification_emails: Vec::new(),
        support_inbox_email: None,
        imap_host: String::new(),
        imap_port: 993,
        imap_username: String::new(),
        imap_mailbox: "INBOX".to_string(),
        imap_enabled: false,
        imap_poll_secs: 60,
    }
}

/// Register a confidential machine client whose secret is [`CLIENT_SECRET`].
async fn seed_client(pool: &PgPool, name: &str, grants: &[&str]) -> Uuid {
    let hash = bunyip_oidc::machine_client::hash_client_secret(CLIENT_SECRET)
        .await
        .expect("hash the client secret");

    let client_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO oauth_clients (
            client_id, client_secret_hash, client_type, name,
            redirect_uris, post_logout_redirect_uris,
            allowed_scopes, allowed_grant_types,
            token_endpoint_auth_method, require_pkce, audience
        ) VALUES ($1, $2, 'confidential', $3,
            ARRAY[]::TEXT[], ARRAY[]::TEXT[],
            ARRAY[]::TEXT[], $4,
            'client_secret_basic', TRUE, 'https://api.example.test')
        "#,
    )
    .bind(client_id)
    .bind(hash)
    .bind(name)
    .bind(grants.iter().map(|g| g.to_string()).collect::<Vec<_>>())
    .execute(pool)
    .await
    .expect("seed the machine client");
    client_id
}

fn basic(client_id: &Uuid, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"))
    )
}

/// The source address every request in this test arrives from, unless a case
/// deliberately uses another. Set explicitly so the per-IP failure brake is
/// exercised rather than skipped for want of a peer address.
const CALLER_IP: &str = "203.0.113.7:41000";
const BRUTE_IP: &str = "203.0.113.9:41000";

fn from(peer: &str) -> test::TestRequest {
    test::TestRequest::post()
        .uri("/v1/mailer/send")
        .peer_addr(peer.parse().expect("peer address"))
}

fn body() -> serde_json::Value {
    serde_json::json!({
        "to": "member@customer.test",
        "subject": "Your ticket was updated",
        "text": "Ticket 42 moved to In Progress.",
    })
}

/// Build the relay over a capturing (non-sending) transport.
fn relay() -> (Arc<MailerRelay>, AsyncStubTransport) {
    let (email, stub) = EmailService::new_capturing(relay_email_config());
    (
        Arc::new(MailerRelay::new(Arc::new(email), Arc::new(NoSuppression))),
        stub,
    )
}

#[actix_rt::test]
async fn the_relay_authenticates_throttles_and_sends() {
    let Some(pool) = maybe_pool().await else {
        eprintln!(
            "BUNYIP_TEST_DATABASE_URL / RLS_TEST_DATABASE_URL unset; skipping mailer relay test"
        );
        return;
    };

    let (mailer, stub) = relay();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(mailer.clone()))
            .service(web::scope("/v1").configure(bunyip_api::routes::mailer::configure)),
    )
    .await;

    let client_id = seed_client(&pool, "relay-test-app", &["client_credentials"]).await;
    let browser_only = seed_client(&pool, "relay-test-spa", &["authorization_code"]).await;

    // Start from a known cap: 2 sends per minute for this action, so the 429 is
    // three requests away instead of sixty-one. This also exercises the
    // persisted-override chain the enforcement path resolves (BUNYIP-413).
    RateLimitConfigRepository::upsert(&pool, "mailer_send", 2, 60, None)
        .await
        .expect("pin the relay cap");
    RateLimitConfigRepository::upsert(&pool, "mailer_auth_failures", 6, 60, None)
        .await
        .expect("pin the failure brake");
    for id in [client_id, browser_only] {
        RateLimitRepository::reset(&pool, &id.to_string(), "mailer_send")
            .await
            .expect("clear the per-app counter");
    }
    for ip in ["203.0.113.7", "203.0.113.9"] {
        RateLimitRepository::reset(&pool, ip, "mailer_auth_failures")
            .await
            .expect("clear the per-IP failure counter");
    }

    // ── Auth rejection ───────────────────────────────────────────────────────

    let req = from(CALLER_IP).set_json(body()).to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        401,
        "a request with no credential must be refused"
    );

    let req = from(CALLER_IP)
        .insert_header(("authorization", basic(&client_id, "not-the-secret")))
        .set_json(body())
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        401,
        "a wrong secret must be refused"
    );

    let req = from(CALLER_IP)
        .insert_header(("authorization", basic(&Uuid::new_v4(), CLIENT_SECRET)))
        .set_json(body())
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        401,
        "an unregistered client_id must be refused"
    );

    let req = from(CALLER_IP)
        .insert_header(("authorization", basic(&browser_only, CLIENT_SECRET)))
        .set_json(body())
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        403,
        "an authentic client not registered for client_credentials must be refused"
    );

    assert!(
        stub.messages().await.is_empty(),
        "no refused request may reach the transport"
    );

    // ── Per-IP brake on repeated failures ────────────────────────────────────
    //
    // The endpoint is exempt from the per-IP `RateLimitFloor`, so this counter
    // is what stops an unauthenticated flood from spending Argon2 CPU. It counts
    // FAILURES only, which is why the successful sends below are unaffected.
    for attempt in 1..=6 {
        let req = from(BRUTE_IP)
            .insert_header(("authorization", basic(&client_id, "not-the-secret")))
            .set_json(body())
            .to_request();
        assert_eq!(
            test::call_service(&app, req).await.status(),
            401,
            "failure {attempt} is still a plain rejection"
        );
    }
    let req = from(BRUTE_IP)
        .insert_header(("authorization", basic(&client_id, "not-the-secret")))
        .set_json(body())
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(
        res.status(),
        429,
        "past the failure cap the address is throttled, not merely refused again"
    );
    assert!(res.headers().contains_key("retry-after"));

    // ── Successful relay ─────────────────────────────────────────────────────

    let req = from(CALLER_IP)
        .insert_header(("authorization", basic(&client_id, CLIENT_SECRET)))
        .set_json(body())
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(res.status(), 200, "a registered calling app may relay");
    let payload: serde_json::Value = test::read_body_json(res).await;
    assert_eq!(payload["data"]["status"], "sent");
    let message_id = payload["data"]["message_id"]
        .as_str()
        .expect("a delivered message reports its Message-ID")
        .to_string();
    assert!(
        message_id.ends_with("@mail.a8n.systems"),
        "the Message-ID aligns with the sending domain: {message_id}"
    );

    let sent = stub.messages().await;
    assert_eq!(sent.len(), 1, "exactly one message reached the transport");
    let (envelope, raw) = &sent[0];
    assert_eq!(envelope.to()[0].to_string(), "member@customer.test");
    assert_eq!(
        envelope.from().map(|a| a.to_string()).as_deref(),
        Some("noreply@mail.a8n.systems"),
        "the relay sends from Bunyip's verified sending domain, not the caller's"
    );
    assert!(raw.contains("Ticket 42 moved to In Progress."));

    // ── Rate-limit rejection ─────────────────────────────────────────────────

    // The second send is still within the pinned cap of 2.
    let req = from(CALLER_IP)
        .insert_header(("authorization", basic(&client_id, CLIENT_SECRET)))
        .set_json(body())
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status(), 200);

    let req = from(CALLER_IP)
        .insert_header(("authorization", basic(&client_id, CLIENT_SECRET)))
        .set_json(body())
        .to_request();
    let res = test::call_service(&app, req).await;
    assert_eq!(
        res.status(),
        429,
        "the third send in the window exceeds the per-app cap"
    );
    assert!(
        res.headers().contains_key("retry-after"),
        "a 429 tells the caller when to retry"
    );
    assert_eq!(
        stub.messages().await.len(),
        2,
        "the throttled request was never handed to the transport"
    );

    // The cap is charged per calling APP, not per source IP: a second app from
    // the same connection still has its own budget.
    let other = seed_client(&pool, "relay-test-app-2", &["client_credentials"]).await;
    RateLimitRepository::reset(&pool, &other.to_string(), "mailer_send")
        .await
        .expect("clear the second app's counter");
    let req = from(CALLER_IP)
        .insert_header(("authorization", basic(&other, CLIENT_SECRET)))
        .set_json(body())
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        200,
        "one app's exhausted budget must not throttle another's"
    );

    // ── Validation ───────────────────────────────────────────────────────────

    let req = from(CALLER_IP)
        .insert_header(("authorization", basic(&other, CLIENT_SECRET)))
        .set_json(serde_json::json!({
            "to": "member@customer.test",
            "subject": "Injected\r\nBcc: everyone@customer.test",
            "text": "Body",
        }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status(),
        400,
        "a header-injecting subject is refused"
    );

    // Leave the action back on its compile-time default.
    RateLimitConfigRepository::delete(&pool, "mailer_send")
        .await
        .expect("drop the pinned cap");
    sqlx::query("DELETE FROM oauth_clients WHERE client_id = ANY($1)")
        .bind(vec![client_id, browser_only, other])
        .execute(&pool)
        .await
        .expect("clean up the seeded clients");

    assert_eq!(
        RateLimitConfig::MAILER_SEND.action,
        "mailer_send",
        "the pinned override and the preset name the same action"
    );
}
