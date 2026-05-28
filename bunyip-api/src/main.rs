use std::time::Duration;

use axum::{
    http::{header, HeaderName, HeaderValue, Method},
    routing::get,
    Router,
};
use bunyip_api::config::Config;
use bunyip_api::routes;
use bunyip_api::state::AppState;
use bunyip_mocks::MockStore;
use tower_cookies::CookieManagerLayer;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,bunyip_api=debug".into()),
        )
        .init();

    let config = Config::from_env()?;
    tracing::info!(?config.bind_addr, ?config.seeds_dir, "bunyip-api starting");

    let store = MockStore::load_from_dir(&config.seeds_dir)?.into_shared();
    let state = AppState::new(config.clone(), store);

    // CORS: the SPA is served from a different origin than this API
    // (`bunyip.<host>` vs `msp-api.<host>`) and sends credentialed
    // requests. `Allow-Origin: *` is incompatible with credentials, and
    // `mirror_request()` accepts any caller's Origin (CSRF-via-CORS
    // exposure). Use an explicit allow-list driven by the `CORS_ORIGIN`
    // env per docs/cors.md in the docker repo, mirroring the
    // mokosh-server / dmarc-reporter shape. Invalid entries panic at
    // startup so misconfiguration surfaces immediately.
    let cors_origin_values: Vec<HeaderValue> = config
        .cors_origins
        .iter()
        .map(|origin| {
            HeaderValue::from_str(origin).unwrap_or_else(|e| {
                panic!("CORS_ORIGIN entry {origin:?} is not a valid header value: {e}")
            })
        })
        .collect();
    tracing::info!(cors_origins = ?config.cors_origins, "CORS configured");
    let cors_layer = CorsLayer::new()
        .allow_origin(AllowOrigin::list(cors_origin_values))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("x-requested-with"),
        ])
        .allow_credentials(true)
        .max_age(Duration::from_secs(600));

    let app = Router::new()
        .route("/healthz", get(routes::health::healthz))
        .merge(routes::version::router())
        .merge(routes::auth::router())
        .merge(routes::me::router())
        .merge(routes::orgs::router())
        .merge(routes::billing::router())
        .merge(routes::oidc::router())
        .merge(routes::admin::router())
        .merge(routes::feedback::router())
        .layer(CookieManagerLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(cors_layer)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!("listening on http://{}", config.bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}
