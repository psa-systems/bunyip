//! Root-level `GET /version` - reports the running build version, git
//! revision, and (when `BUNYIP_UPDATE_CHECK_URL` is configured) whether a
//! newer release is published upstream.

use std::sync::Arc;

use actix_web::{web, HttpResponse};
use serde_json::json;

use crate::version::{self, UpdateChecker};

/// Mount `GET /version` at the application root (outside the `/v1` scope).
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/version", web::get().to(version_handler));
}

/// `GET /version` - report the running version, build revision, and whether a
/// newer release is available upstream.
async fn version_handler(checker: web::Data<Arc<UpdateChecker>>) -> HttpResponse {
    let update = checker.status().await;
    HttpResponse::Ok().json(json!({
        "version": version::current_version(),
        "revision": version::git_revision(),
        "update": update,
    }))
}
