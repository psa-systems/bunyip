//! Application routes

use actix_web::web;

use crate::handlers;

/// Configure application routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/applications")
            .route("", web::get().to(handlers::list_applications))
            .route("/{slug}", web::get().to(handlers::get_application))
            .route(
                "/{slug}/downloads",
                web::get().to(handlers::list_app_downloads),
            )
            .route(
                "/{slug}/downloads/{asset_name}",
                web::get().to(handlers::download_asset),
            )
            // BUNYIP-386: serve a specific recorded historical release, not just the pin.
            .route(
                "/{slug}/downloads/{version}/{asset_name}",
                web::get().to(handlers::download_asset_versioned),
            )
            // BUNYIP-388: public per-application documentation.
            .route("/{slug}/docs", web::get().to(handlers::list_app_docs))
            .route(
                "/{slug}/docs/{doc_slug}",
                web::get().to(handlers::get_app_doc),
            ),
    );
    // Application groups (BUNYIP-100): display metadata for grouping the apps.
    cfg.service(
        web::scope("/application-groups")
            .route("", web::get().to(handlers::list_application_groups)),
    );
}
