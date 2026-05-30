//! Authentication routes

use actix_web::web;

use crate::handlers;

/// Configure authentication routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/register", web::post().to(handlers::register))
            .route("/login", web::post().to(handlers::login))
            .route("/logout", web::post().to(handlers::logout))
            .route("/logout", web::get().to(handlers::logout_redirect))
            .route("/logout-all", web::post().to(handlers::logout_all))
            .route("/refresh", web::post().to(handlers::refresh_token))
            .route("/magic-link", web::post().to(handlers::request_magic_link))
            .route(
                "/magic-link/verify",
                web::post().to(handlers::verify_magic_link),
            )
            .route(
                "/password-reset",
                web::post().to(handlers::request_password_reset),
            )
            .route(
                "/password-reset/verify",
                web::get().to(handlers::verify_password_reset_token),
            )
            .route(
                "/password-reset/confirm",
                web::post().to(handlers::confirm_password_reset),
            )
            .route("/2fa/setup", web::post().to(handlers::setup_2fa))
            .route("/2fa/confirm", web::post().to(handlers::confirm_2fa))
            .route("/2fa/verify", web::post().to(handlers::verify_2fa))
            .route("/2fa/disable", web::post().to(handlers::disable_2fa))
            .route(
                "/2fa/recovery-codes",
                web::post().to(handlers::regenerate_recovery_codes),
            )
            .route("/2fa/status", web::get().to(handlers::get_2fa_status))
            .route(
                "/invite/accept",
                web::post().to(handlers::accept_admin_invite),
            )
            .route("/redirect", web::get().to(handlers::auth_redirect))
            .route("/setup/status", web::get().to(handlers::setup_status))
            .route("/setup", web::post().to(handlers::setup_admin)),
    );
}
