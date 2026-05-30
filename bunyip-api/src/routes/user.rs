//! User routes

use actix_web::web;

use crate::handlers;

/// Configure user routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/me", web::get().to(handlers::get_current_user))
            .route("/me/password", web::put().to(handlers::change_password))
            .route("/me/email", web::post().to(handlers::request_email_change))
            .route(
                "/me/email/confirm",
                web::post().to(handlers::confirm_email_change),
            )
            .route(
                "/me/email/verify",
                web::post().to(handlers::request_email_verification),
            )
            .route(
                "/me/email/verify/confirm",
                web::post().to(handlers::confirm_email_verification),
            )
            .route("/me/sessions", web::get().to(handlers::list_sessions))
            .route("/me", web::delete().to(handlers::delete_account))
            .route(
                "/me/sessions/{session_id}",
                web::delete().to(handlers::revoke_session),
            ),
    );
}
