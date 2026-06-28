//! Liveness endpoint for the SSR hub (BUNYIP-149).
//!
//! Unauthenticated and DB-free: a pure liveness signal so the BUNYIP-148 e2e
//! reachability gate and uptime monitoring can confirm bunyip-web itself is
//! serving before driving browser flows (bunyip-api already exposes its own
//! `/health`; this is the hub-side equivalent). Liveness, not readiness - it
//! deliberately does not touch the API or any datastore.

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;

/// GET /healthz -> 200 `{"status":"ok"}`. No auth, no database dependency.
pub async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"status":"ok"}"#,
    )
}
