//! User routes

use actix_web::web;

use crate::handlers;

/// Configure user routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/me", web::get().to(handlers::get_current_user))
            // BUNYIP-139: optional profile fields (first_name / last_name / phone)
            .route(
                "/me/profile",
                web::put().to(handlers::update_current_user_profile),
            )
            // BUNYIP-140: OIDC scope consent grants (consent-screen POST target)
            .route("/me/consents", web::post().to(handlers::grant_consent))
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
            // Registered before the `{session_id}` route; it is a POST so it
            // would not collide with the DELETE handler regardless (BUNYIP-137).
            .route(
                "/me/sessions/revoke-others",
                web::post().to(handlers::revoke_other_sessions),
            )
            .route("/me", web::delete().to(handlers::delete_account))
            .route(
                "/me/sessions/{session_id}",
                web::delete().to(handlers::revoke_session),
            )
            // Trusted devices (BUNYIP-138)
            .route(
                "/me/trusted-devices",
                web::get().to(handlers::list_trusted_devices),
            )
            .route(
                "/me/trusted-devices/{id}/revoke",
                web::post().to(handlers::revoke_trusted_device),
            ),
    );
}
