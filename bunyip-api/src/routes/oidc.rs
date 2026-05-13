use crate::state::AppState;
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

// Phase 4 fills in /oidc/authorize consent rendering + /oidc/consent handling.

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oidc/authorize", get(stub))
        .route("/oidc/consent", post(stub))
        .route("/oidc/token", post(stub))
        .route("/oidc/userinfo", get(stub))
}

async fn openid_configuration(State(state): State<AppState>) -> Json<Value> {
    let issuer = state.config.public_base_url.clone();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oidc/authorize"),
        "token_endpoint": format!("{issuer}/oidc/token"),
        "userinfo_endpoint": format!("{issuer}/oidc/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "email", "profile", "memberships"],
        "claims_supported": ["sub", "email", "name", "memberships"],
        "grant_types_supported": ["authorization_code"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
    }))
}

async fn jwks() -> Json<Value> {
    // MVP placeholder; real keys live in Mokosh Server post-MVP.
    Json(json!({"keys": []}))
}

async fn stub() -> axum::http::StatusCode {
    axum::http::StatusCode::NOT_IMPLEMENTED
}
