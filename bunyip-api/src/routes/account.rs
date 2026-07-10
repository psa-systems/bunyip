//! Account routes (BUNYIP-353): account-level backup and restore.

use actix_web::web;

use crate::handlers;

/// Larger JSON body limit for the restore upload: an account bundle carries
/// each entitled app's backup, so it can exceed the tiny global default. 8 MiB
/// matches the feedback attachment ceiling.
const RESTORE_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// Configure account routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/account")
            .app_data(web::JsonConfig::default().limit(RESTORE_BODY_LIMIT))
            .route(
                "/backup",
                web::get().to(handlers::account_backup::download_backup),
            )
            .route(
                "/restore",
                web::post().to(handlers::account_backup::restore_backup),
            ),
    );
}
