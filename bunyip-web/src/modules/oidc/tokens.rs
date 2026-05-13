//! ID-token claims parser. The `Tokens` + `StoredTokens` types live in
//! `crate::stores::tokens` so the rest of the SPA can read them without
//! pulling the OIDC module in.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::stores::tokens::Tokens;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default, rename = "mokosh_tenant_id")]
    pub tenant_id: Option<String>,
    #[serde(default, rename = "mokosh_active_tenant")]
    pub active_tenant_id: Option<String>,
    #[serde(default, rename = "mokosh_role")]
    pub role: Option<String>,
    pub exp: i64,
    pub iat: i64,
}

impl IdTokenClaims {
    /// Decode (without verification) the claims from a compact JWT.
    pub fn parse_unverified(jwt: &str) -> Result<Self, String> {
        let mut parts = jwt.split('.');
        let _header = parts.next().ok_or("malformed jwt: missing header")?;
        let payload = parts.next().ok_or("malformed jwt: missing payload")?;
        let raw = URL_SAFE_NO_PAD
            .decode(payload.as_bytes())
            .map_err(|e| format!("payload base64: {e}"))?;
        serde_json::from_slice(&raw).map_err(|e| format!("payload json: {e}"))
    }
}

pub trait TokensExt {
    fn id_claims(&self) -> Result<IdTokenClaims, String>;
}

impl TokensExt for Tokens {
    fn id_claims(&self) -> Result<IdTokenClaims, String> {
        IdTokenClaims::parse_unverified(&self.id_token)
    }
}
