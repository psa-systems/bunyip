//! BUNYIP-1078: `submit_feedback` must not gate its HTTP response on the
//! MX-lookup signal of the composite spam classifier. Before this change the
//! handler awaited `MxResolver::lookup` directly on the request path, so a
//! cold cache entry paid the full DNS round-trip (up to `MX_LOOKUP_TIMEOUT`)
//! before the response was built. This proves two things at the HTTP layer
//! with a resolver that is deliberately far slower than any real DNS
//! timeout: the response returns long before the resolver would, and the
//! background classification still lands the correct final `is_spam` /
//! `feedback_spam_reasons` row once it completes.
//!
//! Needs a migrated PostgreSQL named by `BUNYIP_TEST_DATABASE_URL` (or
//! `RLS_TEST_DATABASE_URL`) and skips without one:
//!
//! ```sh
//! BUNYIP_TEST_DATABASE_URL=postgres://postgres:postgres@localhost/bunyip_test \
//!   cargo test -p bunyip-api --test feedback_mx_latency -- --nocapture
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use actix_web::{test, web, App};
use async_trait::async_trait;
use bunyip_api::config::Config;
use bunyip_api::handlers::mx_check::{MxLookupOutcome, MxResolver};
use bunyip_api::services::EmailService;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

async fn test_pool() -> Option<PgPool> {
    let url = std::env::var("BUNYIP_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("RLS_TEST_DATABASE_URL"));
    let Ok(url) = url else {
        eprintln!(
            "BUNYIP_TEST_DATABASE_URL / RLS_TEST_DATABASE_URL unset; skipping BUNYIP-1078 MX latency test"
        );
        return None;
    };
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect to test database");
    // Some migrations GRANT onto the unprivileged `bunyip_app` role bunyip-api
    // normally provisions at startup; a bare test pool never runs that
    // startup path, so provision it here first (idempotent).
    bunyip_api::db::provision_app_role(&pool, "bunyip_app_test_pw")
        .await
        .expect("provision bunyip_app role");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    Some(pool)
}

fn test_config() -> Config {
    std::env::set_var("DATABASE_URL", "postgres://test:test@localhost/test");
    std::env::set_var("ENVIRONMENT", "development");
    std::env::set_var("SECRETS_STORAGE", "database");
    std::env::set_var("HOST_IP", "0.0.0.0");
    std::env::set_var("APP_PORT", "4000");
    Config::from_env().expect("minimal config resolves outside production")
}

/// A resolver far slower than any real DNS timeout (`MX_LOOKUP_TIMEOUT` is
/// 2s), so a response that comes back quickly could not possibly have
/// awaited it. `called` flips to `true` once the lookup actually runs,
/// proving the background task did not just get skipped.
struct SlowResolver {
    outcome: MxLookupOutcome,
    delay: Duration,
    called: Arc<AtomicBool>,
}

#[async_trait]
impl MxResolver for SlowResolver {
    async fn lookup(&self, _domain: &str) -> MxLookupOutcome {
        self.called.store(true, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        self.outcome
    }
}

fn multipart_body(boundary: &str, email: &str, message: &str) -> Vec<u8> {
    format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"email\"\r\n\r\n\
         {email}\r\n\
         --{boundary}\r\n\
         Content-Disposition: form-data; name=\"message\"\r\n\r\n\
         {message}\r\n\
         --{boundary}--\r\n"
    )
    .into_bytes()
}

async fn fetch_feedback(pool: &PgPool, message: &str) -> (bool, Option<String>) {
    let row = sqlx::query(
        "SELECT f.is_spam, r.reason FROM feedback f \
         LEFT JOIN feedback_spam_reasons r ON r.feedback_id = f.id \
         WHERE f.message = $1",
    )
    .bind(message)
    .fetch_one(pool)
    .await
    .expect("fetch seeded feedback row");
    (row.get("is_spam"), row.get("reason"))
}

/// Cold-cache submission whose sender domain the stub resolver reports as
/// `NoMx`: the classifier should flag it, but only after the background
/// task resolves, never on the request path.
#[actix_rt::test]
async fn submit_feedback_returns_before_a_slow_mx_lookup_resolves_and_still_flags_no_mx() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let config = test_config();
    let email_service = Arc::new(EmailService::new_dev());
    let called = Arc::new(AtomicBool::new(false));
    let mx_resolver: Arc<dyn MxResolver> = Arc::new(SlowResolver {
        outcome: MxLookupOutcome::NoMx,
        delay: Duration::from_secs(3),
        called: called.clone(),
    });

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(email_service))
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(Arc::clone(&mx_resolver)))
            .service(web::scope("/v1").configure(bunyip_api::routes::feedback::configure)),
    )
    .await;

    let tag = format!("bunyip-1078-{}", Uuid::new_v4().simple());
    let boundary = "bunyip1078boundary";
    let body = multipart_body(boundary, "reporter@no-mx-domain.test", &tag);
    let req = test::TestRequest::post()
        .uri("/v1/feedback")
        .insert_header((
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        ))
        .set_payload(body)
        .to_request();

    let start = Instant::now();
    let resp = test::call_service(&app, req).await;
    let elapsed = start.elapsed();

    if !resp.status().is_success() {
        let status = resp.status();
        let body = test::read_body(resp).await;
        panic!(
            "submission must succeed with a provisional, non-spam verdict: {status} body={}",
            String::from_utf8_lossy(&body)
        );
    }
    assert!(
        elapsed < Duration::from_secs(1),
        "the response must not wait on the 3s resolver; took {elapsed:?}"
    );

    // Give the background task time to run past the resolver's artificial
    // delay, then confirm it landed the FINAL classification the same way
    // the removed synchronous path always did.
    tokio::time::sleep(Duration::from_secs(4)).await;

    assert!(
        called.load(Ordering::SeqCst),
        "the background task must still run the MX lookup, just not on the request path"
    );
    let (is_spam, reason) = fetch_feedback(&pool, &tag).await;
    assert!(
        is_spam,
        "a NoMx sender domain must end up flagged once the background classifier resolves"
    );
    assert!(
        reason.unwrap_or_default().contains("no MX records"),
        "the spam-reason row must carry the MX signal's explanation"
    );

    sqlx::query("DELETE FROM feedback WHERE message = $1")
        .bind(&tag)
        .execute(&pool)
        .await
        .expect("cleanup seeded row");
}
