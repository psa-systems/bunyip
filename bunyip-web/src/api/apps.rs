//! `/v1/auth/apps` - list OAuth clients the signed-in user can launch.
//! Powers the Bunyip app launcher.

use serde::Deserialize;

use super::{get_authed, ApiError};

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct AppView {
    pub client_id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub redirect_uri: String,
    #[serde(default)]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub is_first_party: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct AppListEnvelope {
    apps: Vec<AppView>,
}

pub async fn list_apps() -> Result<Vec<AppView>, ApiError> {
    get_authed::<AppListEnvelope>("/v1/auth/apps")
        .await
        .map(|e| e.apps)
}
