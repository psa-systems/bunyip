//! Organization and team routes (BUNYIP-626 child 1).
//!
//! All routes stay mounted; the service layer refuses with a 404 when
//! `TierConfig::orgs_enabled` is off, matching the BUNYIP-493 pattern
//! (route mounted, feature invisible).

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/organization")
            .route("", web::get().to(handlers::get_my_organization))
            .route("", web::post().to(handlers::create_my_organization))
            .route("", web::put().to(handlers::update_my_organization))
            .route("/teams", web::get().to(handlers::list_teams))
            .route("/teams", web::post().to(handlers::create_team))
            .route("/teams/{id}", web::put().to(handlers::update_team))
            .route("/teams/{id}", web::delete().to(handlers::delete_team))
            .route(
                "/teams/{id}/members",
                web::get().to(handlers::list_team_members),
            )
            .route(
                "/teams/{id}/members",
                web::post().to(handlers::add_team_member),
            )
            .route(
                "/teams/{id}/members/{user_id}",
                web::put().to(handlers::update_team_member_role),
            )
            .route(
                "/teams/{id}/members/{user_id}",
                web::delete().to(handlers::remove_team_member),
            ),
    );
}
