use axum::{extract::State, routing::get, Json, Router};
use serde_json::{json, Value};

use crate::state::AppState;
use crate::version;

pub fn router() -> Router<AppState> {
    Router::new().route("/version", get(version_handler))
}

/// `GET /version` - report the running version, build revision, and
/// whether a newer release is available upstream.
async fn version_handler(State(state): State<AppState>) -> Json<Value> {
    let update = state.updates.status().await;
    Json(json!({
        "version": version::current_version(),
        "revision": version::git_revision(),
        "update": update,
    }))
}
