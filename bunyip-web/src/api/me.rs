use super::types::MeResponse;
use super::{get_json, ApiError};

pub async fn fetch_me() -> Result<MeResponse, ApiError> {
    get_json("/v1/me").await
}
