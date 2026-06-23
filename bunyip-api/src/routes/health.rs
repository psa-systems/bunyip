//! Health check and status endpoints

use actix_web::{get, web, HttpResponse};
use serde::Serialize;
use sqlx::PgPool;

use crate::repositories::UserRepository;
use crate::Config;

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

#[derive(Serialize)]
struct E2eBootstrappedResponse {
    bootstrapped: bool,
}

/// E2E readiness probe at /e2e-bootstrapped (BUNYIP-163).
///
/// Reports whether the two fixed E2E test accounts (`crate::E2E_ACCOUNT_EMAILS`)
/// both exist and are active, so the e2e workflow can skip the suite (and still
/// succeed) when staging is not bootstrapped - letting `e2e` be a required check
/// without ever locking out merges on a missing or removed seed. Unauthenticated
/// and information-minimal (one boolean about two fixed test emails) via a single
/// indexed count.
///
/// On a production `ENVIRONMENT` it returns `false` WITHOUT querying: production
/// uses manual provisioning and the suite skips there anyway, so this endpoint
/// never probes prod user rows.
#[get("/e2e-bootstrapped")]
pub async fn e2e_bootstrapped(pool: web::Data<PgPool>, config: web::Data<Config>) -> HttpResponse {
    if config.is_production() {
        return HttpResponse::Ok().json(E2eBootstrappedResponse {
            bootstrapped: false,
        });
    }

    let emails: Vec<String> = crate::E2E_ACCOUNT_EMAILS
        .iter()
        .map(|s| s.to_string())
        .collect();
    let bootstrapped = match UserRepository::count_active_by_emails(&pool, &emails).await {
        Ok(n) => n as usize == crate::E2E_ACCOUNT_EMAILS.len(),
        Err(_) => false,
    };

    HttpResponse::Ok().json(E2eBootstrappedResponse { bootstrapped })
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
