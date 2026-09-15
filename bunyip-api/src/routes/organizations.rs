//! BUNYIP-672 [BUNYIP-626 child 1]: `/v1/organization/*` route configuration.
//!
//! Every route sits behind [`AuthenticatedUser`] and gates on
//! `tier_config.orgs_enabled` inside the handler. Flag-off returns the
//! 404 that BUNYIP-493's "off means INVISIBLE" rule requires.

use actix_web::web;

use crate::handlers;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/organization")
            .route(
                "",
                web::post().to(handlers::organizations::create_organization),
            )
            .route(
                "",
                web::get().to(handlers::organizations::get_own_organization),
            )
            .route(
                "",
                web::put().to(handlers::organizations::update_own_organization),
            )
            .route("/teams", web::get().to(handlers::organizations::list_teams))
            .route(
                "/teams",
                web::post().to(handlers::organizations::create_team),
            )
            .route(
                "/teams/{id}",
                web::get().to(handlers::organizations::get_team),
            )
            .route(
                "/teams/{id}",
                web::put().to(handlers::organizations::update_team),
            )
            .route(
                "/teams/{id}",
                web::delete().to(handlers::organizations::delete_team),
            )
            .route(
                "/teams/{id}/members",
                web::get().to(handlers::organizations::list_team_members),
            )
            .route(
                "/teams/{id}/members",
                web::post().to(handlers::organizations::add_team_member),
            )
            .route(
                "/teams/{team_id}/members/{bunyip_user_id}",
                web::put().to(handlers::organizations::update_team_member_role),
            )
            .route(
                "/teams/{team_id}/members/{bunyip_user_id}",
                web::delete().to(handlers::organizations::remove_team_member),
            )
            // BUNYIP-692: owner picks or clears the org's pricing tier.
            .route(
                "/tier",
                web::put().to(handlers::org_pricing::set_organization_tier),
            )
            .route(
                "/tier",
                web::delete().to(handlers::org_pricing::clear_organization_tier),
            ),
    );
}
