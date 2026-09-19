//! BUNYIP-765: a deactivated application's documentation must not be publicly
//! reachable through either public doc route.
//!
//! Env-gated like `rls_isolation.rs` / `applications_catalog.rs`: it needs a
//! throwaway Postgres to migrate. Set `BUNYIP_TEST_DATABASE_URL` (or reuse
//! `RLS_TEST_DATABASE_URL`) to a database this test may migrate; unset skips
//! the test.

use actix_web::{test, web, App};
use bunyip_api::models::{CreateApplication, CreateApplicationDoc};
use bunyip_api::repositories::{ApplicationDocRepository, ApplicationRepository};
use sqlx::postgres::PgPoolOptions;

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

/// A deactivated application's doc index and doc page both 404 through the
/// public `/v1/applications/{slug}/docs` and `/v1/applications/{slug}/docs/{doc_slug}`
/// routes (BUNYIP-765 AC2).
#[actix_rt::test]
async fn a_deactivated_application_s_docs_404_through_both_public_routes() {
    let Some(pool) = test_pool("the doc-route active-filter test").await else {
        return;
    };

    let slug = format!("bunyip-765-{}", uuid::Uuid::new_v4().simple());
    let app_row = ApplicationRepository::create(
        &pool,
        &CreateApplication {
            name: slug.clone(),
            slug: slug.clone(),
            display_name: "BUNYIP-765 Test App".to_string(),
            description: None,
            icon_url: None,
            container_name: slug.clone(),
            health_check_url: None,
            subdomain: None,
            webhook_url: None,
            version: None,
            source_code_url: None,
            release_notes_url: None,
            is_hosted: Some(false),
            maintenance_message: None,
            forgejo_owner: None,
            forgejo_repo: None,
            forgejo_package: None,
            pinned_release_tag: None,
            artifact_source: None,
            oci_image_owner: None,
            oci_image_name: None,
            pinned_image_tag: None,
        },
    )
    .await
    .expect("create application");

    let doc = ApplicationDocRepository::create(
        &pool,
        app_row.id,
        &CreateApplicationDoc {
            slug: "getting-started".to_string(),
            title: "Getting Started".to_string(),
            body: "body".to_string(),
            sort_order: 0,
        },
    )
    .await
    .expect("create application doc");

    // Deactivate the application (BUNYIP-765's failure condition).
    ApplicationRepository::set_active(&pool, app_row.id, false)
        .await
        .expect("deactivate application");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(web::scope("/v1").configure(bunyip_api::routes::application::configure)),
    )
    .await;

    let list_req = test::TestRequest::get()
        .uri(&format!("/v1/applications/{slug}/docs"))
        .to_request();
    let list_resp = test::call_service(&app, list_req).await;
    assert_eq!(
        list_resp.status(),
        404,
        "the doc index for a deactivated application must 404"
    );

    let get_req = test::TestRequest::get()
        .uri(&format!("/v1/applications/{slug}/docs/{}", doc.slug))
        .to_request();
    let get_resp = test::call_service(&app, get_req).await;
    assert_eq!(
        get_resp.status(),
        404,
        "a deactivated application's doc page must 404"
    );
}
