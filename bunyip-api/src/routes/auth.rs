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
            // Authenticator re-key (BUNYIP-355): begin (step-up gated) stages a
            // new secret; confirm verifies a code from the new device and swaps.
            .route("/2fa/rekey", web::post().to(handlers::begin_rekey))
            .route(
                "/2fa/rekey/confirm",
                web::post().to(handlers::confirm_rekey),
            )
            .route("/2fa/status", web::get().to(handlers::get_2fa_status))
            .route(
                "/invite/accept",
                web::post().to(handlers::accept_admin_invite),
            )
            .route("/redirect", web::get().to(handlers::auth_redirect))
            // BUNYIP-290: `/setup/status` survives as a feature-flags probe
            // (email_enabled / stripe_enabled); the interactive first-admin
            // wizard (`POST /setup`) is gone - the first admin is now bootstrapped
            // from the BOOTSTRAP_ADMIN_EMAIL env var on sign-up / sign-in.
            .route("/setup/status", web::get().to(handlers::setup_status))
            // Synthetic single-tenant membership stub for the mokosh
            // SPA's tenant switcher. See the handler docstring for the
            // multi-tenant story (deferred to phase-04).
            .route("/memberships", web::get().to(handlers::get_memberships)),
    );
}
