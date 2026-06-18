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

    let cfg = Arc::new(config::Config::from_env());
    let api = api::Api::new(&cfg.api_url);
    let bind_addr = cfg.bind_addr.clone();
    let state = web::AppState {
        api,
        cfg: Arc::clone(&cfg),
    };

    use handlers::{auth_pages as ap, content, dashboard as dash, public};

    let app = Router::new()
        // Public / marketing
        .route("/", get(public::landing))
        .route("/pricing", get(content::pricing))
        .route("/our-story", get(content::our_story))
        .route("/roadmap", get(content::roadmap))
        .route("/terms", get(content::terms))
        .route("/privacy", get(content::privacy))
        .route(
            "/feedback",
            get(content::feedback_get)
                .post(content::feedback_post)
                .layer(
                    // Raise the default axum 2 MB body limit for this route only
                    // so file attachments fit. The cap matches the API's per-form
                    // ceiling (3 files × 5 MB + form overhead). Other routes stay
                    // on the default.
                    axum::extract::DefaultBodyLimit::max(content::FEEDBACK_BODY_LIMIT_BYTES),
                ),
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
        .route("/downloads/:slug/:asset", get(dash::download_asset))
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
        // BUNYIP-139
        .route(
            "/settings/profile",
            axum::routing::post(dash::settings_profile),
        )
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
            "/settings/verify-email/resend",
            axum::routing::post(dash::settings_resend_verification),
        )
        // Active sessions (BUNYIP-137). The literal `revoke-others` route is
        // distinct from `:id/revoke` (different segment count), so ordering is
        // not load-bearing here, but keep them adjacent for readability.
        .route(
            "/settings/sessions/revoke-others",
            axum::routing::post(dash::settings_revoke_other_sessions),
        )
        .route(
            "/settings/sessions/:id/revoke",
            axum::routing::post(dash::settings_revoke_session),
        )
        // Trusted devices (BUNYIP-138)
        .route(
            "/settings/trusted-devices/:id/revoke",
            axum::routing::post(dash::settings_revoke_trusted_device),
        )
        .route(
            "/settings/2fa/setup",
            get(dash::twofa_setup_get).post(dash::twofa_setup_post),
        )
        // Admin
        .route("/admin", get(handlers::admin::dashboard))
        .route("/admin/audit-logs", get(handlers::admin::audit_logs))
        .route("/admin/users", get(handlers::admin::users))
        .route("/admin/users/:id", get(handlers::admin::user_detail))
        .route(
            "/admin/users/:id/role",
            axum::routing::post(handlers::admin::user_role),
        )
        .route(
            "/admin/users/:id/email",
            axum::routing::post(handlers::admin::user_email),
        )
        .route(
            "/admin/users/:id/email/verify",
            axum::routing::post(handlers::admin::user_verify_email),
        )
        .route(
            "/admin/users/:id/two-factor/reset",
            axum::routing::post(handlers::admin::user_reset_2fa),
        )
        .route(
            "/admin/users/:id/delete",
            axum::routing::post(handlers::admin::user_delete),
        )
        .route(
            "/admin/users/:id/suspend",
            axum::routing::post(handlers::admin::user_suspend),
        )
        .route(
            "/admin/users/:id/reactivate",
            axum::routing::post(handlers::admin::user_reactivate),
        )
        .route(
            "/admin/users/:id/reset-password",
            axum::routing::post(handlers::admin::user_reset_password),
        )
        .route(
            "/admin/users/:id/lifetime",
            axum::routing::post(handlers::admin::user_grant_lifetime),
        )
        .route(
            "/admin/users/:id/lifetime/revoke",
            axum::routing::post(handlers::admin::user_revoke_lifetime),
        )
        .route("/admin/memberships", get(handlers::admin::memberships))
        .route(
            "/admin/memberships/:user_id/grant",
            axum::routing::post(handlers::admin::membership_grant),
        )
        .route(
            "/admin/memberships/:user_id/revoke",
            axum::routing::post(handlers::admin::membership_revoke),
        )
        .route("/admin/feedback", get(handlers::admin::feedback))
        .route(
            "/admin/feedback/export",
            get(handlers::admin::feedback_export),
        )
        // Tab + archive routes register BEFORE the `:id` detail route so
        // axum's matcher does not interpret the literal `closed` / `spam`
        // / `archive` as a feedback id.
        .route(
            "/admin/feedback/closed",
            get(handlers::admin::feedback_closed),
        )
        .route("/admin/feedback/spam", get(handlers::admin::feedback_spam))
        .route(
            "/admin/feedback/archive",
            get(handlers::admin::feedback_archive),
        )
        .route(
            "/admin/feedback/archive/:archive_id/restore",
            axum::routing::post(handlers::admin::feedback_restore),
        )
        .route("/admin/feedback/:id", get(handlers::admin::feedback_detail))
        .route(
            "/admin/feedback/:id/respond",
            axum::routing::post(handlers::admin::feedback_respond),
        )
        .route(
            "/admin/feedback/:id/attachments/:attachment_id",
            get(handlers::admin::feedback_attachment),
        )
        .route(
            "/admin/feedback/:id/status",
            axum::routing::post(handlers::admin::feedback_status),
        )
        .route(
            "/admin/feedback/:id/mark-spam",
            axum::routing::post(handlers::admin::feedback_mark_spam),
        )
        .route(
            "/admin/feedback/:id/unmark-spam",
            axum::routing::post(handlers::admin::feedback_unmark_spam),
        )
        .route(
            "/admin/feedback/:id/archive",
            axum::routing::post(handlers::admin::feedback_archive_action),
        )
        .route(
            "/admin/feedback/:id/delete",
            axum::routing::post(handlers::admin::feedback_delete),
        )
        .route(
            "/admin/applications",
            get(handlers::admin::applications).post(handlers::admin::application_create),
        )
        .route(
            "/admin/applications/new",
            get(handlers::admin::application_new),
        )
        .route(
            "/admin/applications/:id/edit",
            get(handlers::admin::application_edit),
        )
        .route(
            "/admin/applications/:id/distribution",
            axum::routing::post(handlers::admin::application_distribution_save),
        )
        .route(
            "/admin/applications/:id/delete",
            axum::routing::post(handlers::admin::application_delete),
        )
        .route(
            "/admin/applications/:id/field",
            axum::routing::post(handlers::admin::application_field),
        )
        .route(
            "/admin/applications/:id/group",
            axum::routing::post(handlers::admin::application_set_group),
        )
        .route(
            "/admin/applications/:id/swap-order",
            axum::routing::post(handlers::admin::application_swap_order),
        )
        // Application groups (BUNYIP-100)
        .route(
            "/admin/application-groups",
            get(handlers::admin::application_groups)
                .post(handlers::admin::application_group_create),
        )
        .route(
            "/admin/application-groups/new",
            get(handlers::admin::application_group_new),
        )
        .route(
            "/admin/application-groups/:id/edit",
            get(handlers::admin::application_group_edit),
        )
        .route(
            "/admin/application-groups/:id",
            axum::routing::post(handlers::admin::application_group_save),
        )
        .route(
            "/admin/application-groups/:id/delete",
            axum::routing::post(handlers::admin::application_group_delete),
        )
        .route("/admin/entitlements", get(handlers::admin::entitlements))
        .route(
            "/admin/applications/:slug/restricted-toggle",
            axum::routing::post(handlers::admin::set_app_restricted),
        )
        .route(
            "/admin/users/:user_id/entitlements",
            get(handlers::admin::user_entitlements),
        )
        .route(
            "/admin/users/:user_id/entitlements/grant",
            axum::routing::post(handlers::admin::grant_user_entitlement_h),
        )
        .route(
            "/admin/users/:user_id/entitlements/revoke",
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
    println!("   API backend       {}", cfg.api_url);
    println!("  ===================================================");
    println!();

    tracing::info!("bunyip-web listening on {bind_addr}");
    axum::serve(listener, app).await.expect("serve");
}
