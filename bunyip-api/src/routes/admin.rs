use axum::{
    routing::{get, patch, post},
    Router,
};
use crate::state::AppState;

// Stubs - real handlers land in Phase 6.

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/admin/users", get(stub))
        .route("/v1/admin/users/{id}/soft-delete", post(stub))
        .route("/v1/admin/users/{id}/reactivate", post(stub))
        .route("/v1/admin/orgs", get(stub))
        .route("/v1/admin/orgs/{slug}/subscription/override", post(stub))
        .route("/v1/admin/tier-config", get(stub))
        .route("/v1/admin/tier-config/{tier_key}", patch(stub))
        .route("/v1/admin/stripe-config", get(stub).patch(stub))
        .route("/v1/admin/audit-logs", get(stub))
        .route("/v1/admin/rate-limits", get(stub))
        .route("/v1/admin/rate-limits/{id}/reset", post(stub))
        .route("/v1/admin/oidc-clients", get(stub).post(stub))
        .route("/v1/admin/oidc-clients/{id}", axum::routing::delete(stub))
        .route("/v1/admin/oidc-clients/{id}/rotate", post(stub))
        // /v1/admin/feedback handlers live in routes/feedback.rs
}

async fn stub() -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_IMPLEMENTED
}
