//! `GET /v1/auth/me` against mokosh-server. Adapts the wire `MeView`
//! into the SPA's `MeResponse` shape; memberships start empty and get
//! merged in by phase 04 once `/v1/auth/memberships` is wired.

use super::types::{MeResponse, MeView};
use super::{get_authed, ApiError};

pub async fn fetch_me() -> Result<MeResponse, ApiError> {
    let view: MeView = get_authed("/v1/auth/me").await?;
    Ok(view.into_me_response())
}
