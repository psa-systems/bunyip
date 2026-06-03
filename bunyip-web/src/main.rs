mod api;
mod auth;
mod config;
mod handlers;
mod util;
mod views;
mod web;

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = config::Config::from_env();
    let api = api::Api::new(&cfg.api_url);
    let bind_addr = cfg.bind_addr.clone();
    let api_url = cfg.api_url.clone();
    let state = web::AppState {
        api,
        cfg: Arc::new(cfg),
    };

    use handlers::{auth_pages as ap, content, dashboard as dash, public};

    let app = Router::new()
        // Public / marketing
        .route("/", get(public::landing))
        .route("/pricing", get(content::pricing))
        .route("/our-story", get(content::our_story))
        .route("/terms", get(content::terms))
        .route("/privacy", get(content::privacy))
        .route(
            "/feedback",
            get(content::feedback_get).post(content::feedback_post),
        )
        // Auth
        .route("/login", get(ap::login_get).post(ap::login_post))
        .route(
            "/login/2fa",
            get(ap::twofa_verify_get).post(ap::twofa_verify_post),
        )
        .route("/logout", get(ap::logout))
        .route("/register", get(ap::register_get).post(ap::register_post))
        .route(
            "/magic-link",
            get(ap::magic_link_get).post(ap::magic_link_post),
        )
        .route(
            "/password-reset",
            get(ap::password_reset_get).post(ap::password_reset_post),
        )
        .route(
            "/password-reset/confirm",
            get(ap::password_reset_confirm_get).post(ap::password_reset_confirm_post),
        )
        .route(
            "/invite/accept",
            get(ap::invite_accept_get).post(ap::invite_accept_post),
        )
        .route("/setup", get(ap::setup_get).post(ap::setup_post))
        .route("/settings/confirm-email", get(ap::confirm_email))
        .route("/settings/verify-email", get(ap::verify_email))
        // Dashboard
        .route("/dashboard", get(dash::dashboard))
        .route("/applications", get(dash::applications))
        .route("/downloads", get(dash::downloads))
        .route("/billing", get(dash::billing))
        .route("/checkout/success", get(dash::checkout_success))
        .route("/membership-required", get(dash::membership_required))
        .route("/membership", get(dash::membership))
        .route(
            "/membership/subscribe",
            axum::routing::post(dash::membership_subscribe),
        )
        .route(
            "/membership/cancel",
            axum::routing::post(dash::membership_cancel),
        )
        .route(
            "/membership/cancel-now",
            axum::routing::post(dash::membership_cancel_now),
        )
        .route(
            "/membership/reactivate",
            axum::routing::post(dash::membership_reactivate),
        )
        .route("/settings", get(dash::settings))
        .route("/settings/email", axum::routing::post(dash::settings_email))
        .route(
            "/settings/password",
            axum::routing::post(dash::settings_password),
        )
        .route(
            "/settings/2fa/disable",
            axum::routing::post(dash::settings_disable_2fa),
        )
        .route(
            "/settings/account/delete",
            axum::routing::post(dash::settings_delete),
        )
        .route(
            "/settings/2fa/setup",
            get(dash::twofa_setup_get).post(dash::twofa_setup_post),
        )
        // Admin
        .route("/admin", get(handlers::admin::dashboard))
        .route("/admin/audit-logs", get(handlers::admin::audit_logs))
        .route("/admin/users", get(handlers::admin::users))
        .route(
            "/admin/users/{id}/role",
            axum::routing::post(handlers::admin::user_role),
        )
        .route(
            "/admin/users/{id}/delete",
            axum::routing::post(handlers::admin::user_delete),
        )
        .route("/admin/memberships", get(handlers::admin::memberships))
        .route("/admin/feedback", get(handlers::admin::feedback))
        .route(
            "/admin/feedback/{id}/status",
            axum::routing::post(handlers::admin::feedback_status),
        )
        .route("/admin/applications", get(handlers::admin::applications))
        .route(
            "/admin/applications/{id}/field",
            axum::routing::post(handlers::admin::application_field),
        )
        .route("/admin/entitlements", get(handlers::admin::entitlements))
        .route(
            "/admin/applications/{slug}/restricted-toggle",
            axum::routing::post(handlers::admin::set_app_restricted),
        )
        .route(
            "/admin/users/{user_id}/entitlements",
            get(handlers::admin::user_entitlements),
        )
        .route(
            "/admin/users/{user_id}/entitlements/grant",
            axum::routing::post(handlers::admin::grant_user_entitlement_h),
        )
        .route(
            "/admin/users/{user_id}/entitlements/revoke",
            axum::routing::post(handlers::admin::revoke_user_entitlement_h),
        )
        .route(
            "/admin/tier-settings",
            get(handlers::admin::tier_settings).post(handlers::admin::tier_settings_save),
        )
        .route(
            "/admin/stripe",
            get(handlers::admin::stripe).post(handlers::admin::stripe_save),
        )
        // Static + fallback
        .nest_service("/assets", ServeDir::new("assets"))
        .fallback(public::not_found)
        .layer(CompressionLayer::new())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("bind");

    // Startup banner (the listener is already bound at this point).
    println!();
    println!("  ===================================================");
    println!("   bunyip-web  (Bunyip · Surfaces what matters.)");
    println!("   Web listening on  http://{bind_addr}");
    println!("   API backend       {api_url}");
    println!("  ===================================================");
    println!();

    tracing::info!("bunyip-web listening on {bind_addr}");
    axum::serve(listener, app).await.expect("serve");
}
