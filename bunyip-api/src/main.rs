use axum::{routing::get, Router};
use bunyip_api::config::Config;
use bunyip_api::routes;
use bunyip_api::state::AppState;
use bunyip_mocks::MockStore;
use tower_cookies::CookieManagerLayer;
use tower_http::{
    cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer},
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
        // The SPA is served from a different origin than this API
        // (`bunyip.<host>` vs `msp-api.<host>`) and sends credentialed
        // requests. `Allow-Origin: *` is incompatible with credentials,
        // so mirror the request origin/method/headers and allow creds -
        // the same posture mokosh-server uses.
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::mirror_request())
                .allow_methods(AllowMethods::mirror_request())
                .allow_headers(AllowHeaders::mirror_request())
                .allow_credentials(true),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!("listening on http://{}", config.bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}
