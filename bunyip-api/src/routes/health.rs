//! Health check and status endpoints

use actix_web::{get, web, HttpResponse};
use serde::Serialize;

const SERVICE_NAME: &str = "bunyip-api";
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_TAG: &str = match option_env!("GIT_TAG") {
    Some(v) => v,
    None => "unknown",
};
const GIT_COMMIT: &str = match option_env!("GIT_COMMIT") {
    Some(v) => v,
    None => "unknown",
};
const BUILD_DATE: &str = match option_env!("BUILD_DATE") {
    Some(v) => v,
    None => "unknown",
};

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct StatusResponse {
    service: &'static str,
    version: &'static str,
    git_tag: &'static str,
    commit: &'static str,
    build_date: &'static str,
}

fn status_payload() -> StatusResponse {
    StatusResponse {
        service: SERVICE_NAME,
        version: PKG_VERSION,
        git_tag: GIT_TAG,
        commit: GIT_COMMIT,
        build_date: BUILD_DATE,
    }
}

/// Root status endpoint at /
#[get("/")]
pub async fn root_status() -> HttpResponse {
    HttpResponse::Ok().json(status_payload())
}

/// Health check endpoint at /health
#[get("/health")]
pub async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(HealthResponse {
        status: "ok",
        version: PKG_VERSION,
    })
}

/// Health check endpoint at /v1/health
#[get("/health")]
async fn health_check_v1() -> HttpResponse {
    HttpResponse::Ok().json(HealthResponse {
        status: "ok",
        version: PKG_VERSION,
    })
}

/// Version endpoint at /v1/version
#[get("/version")]
async fn version_v1() -> HttpResponse {
    HttpResponse::Ok().json(status_payload())
}

/// Configure health routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(health_check_v1);
    cfg.service(version_v1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_rt::test]
    async fn test_health_check() {
        let app = test::init_service(App::new().service(health_check)).await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_version_endpoint() {
        let app = test::init_service(App::new().service(version_v1)).await;

        let req = test::TestRequest::get().uri("/version").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }
}
