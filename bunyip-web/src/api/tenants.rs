//! `/v1/auth/memberships` + `/v1/auth/active-tenant` - the tenant
//! switcher's two endpoints. The hub owns this surface now (per
//! docs/migration/settings-split.md); mokosh-clients's old ActiveTenantPage
//! was deleted in favour of the bunyip-side one.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::{get_authed, post_authed, ApiError};
use crate::stores::tokens::{save_tokens, Tokens};

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct MembershipView {
    pub tenant_id: String,
    pub tenant_name: String,
    pub tenant_kind: String,
    pub role: String,
    pub status: String,
    pub is_active: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct MembershipsBody {
    memberships: Vec<MembershipView>,
}

pub async fn list_memberships() -> Result<Vec<MembershipView>, ApiError> {
    get_authed::<MembershipsBody>("/v1/auth/memberships")
        .await
        .map(|b| b.memberships)
}

#[derive(Clone, Debug, Serialize)]
struct SwitchRequest<'a> {
    tenant_id: &'a str,
    client_id: &'a str,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SwitchOk {
    pub active_tenant_id: String,
    pub tokens: TokenBundle,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TokenBundle {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub scope: String,
}

/// POST `/v1/auth/active-tenant` and persist the freshly-issued token
/// bundle. The server reissues an access + id + refresh with the new
/// `mokosh_active_tenant` claim; we replace what is in localStorage so
/// every subsequent fetch carries the new tenant scope. Callers
/// typically `window.location.reload()` after this returns Ok so every
/// open page refetches under the new scope.
pub async fn switch_active_tenant(tenant_id: &str, client_id: &str) -> Result<SwitchOk, ApiError> {
    let resp: SwitchOk = post_authed(
        "/v1/auth/active-tenant",
        &SwitchRequest {
            tenant_id,
            client_id,
        },
    )
    .await?;
    let expires_at: DateTime<Utc> = Utc::now() + Duration::seconds(resp.tokens.expires_in.max(0));
    save_tokens(&Tokens {
        access_token: resp.tokens.access_token.clone(),
        id_token: resp.tokens.id_token.clone(),
        refresh_token: Some(resp.tokens.refresh_token.clone()),
        expires_at,
        scope: resp.tokens.scope.clone(),
    });
    Ok(resp)
}
