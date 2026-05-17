//! OIDC token bundle + localStorage persistence.
//!
//! Storage key is `bunyip.tokens` (NOT `mokosh.tokens`) to keep the
//! hub's bundle separate from any relying party's storage. The
//! access_token is the only thing held in memory for fast access on
//! every API call; the persistent payload covers refresh-on-reload.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

const STORAGE_KEY: &str = "bunyip.tokens";

#[derive(Clone, Debug)]
pub struct Tokens {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub scope: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StoredTokens {
    pub access_token: String,
    pub id_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub scope: String,
}

impl From<&Tokens> for StoredTokens {
    fn from(t: &Tokens) -> Self {
        Self {
            access_token: t.access_token.clone(),
            id_token: t.id_token.clone(),
            refresh_token: t.refresh_token.clone(),
            expires_at: t.expires_at,
            scope: t.scope.clone(),
        }
    }
}

impl From<StoredTokens> for Tokens {
    fn from(s: StoredTokens) -> Self {
        Self {
            access_token: s.access_token,
            id_token: s.id_token,
            refresh_token: s.refresh_token,
            expires_at: s.expires_at,
            scope: s.scope,
        }
    }
}

/// In-memory mirror of the access token. The `request` helpers read
/// from here so we do not hit localStorage on every fetch.
static CURRENT_ACCESS_TOKEN: Mutex<Option<String>> = Mutex::new(None);

pub fn set_access_token(token: Option<String>) {
    if let Ok(mut g) = CURRENT_ACCESS_TOKEN.lock() {
        *g = token;
    }
}

pub fn current_access_token() -> Option<String> {
    CURRENT_ACCESS_TOKEN.lock().ok().and_then(|g| g.clone())
}

pub fn save_tokens(tokens: &Tokens) {
    set_access_token(Some(tokens.access_token.clone()));
    let stored: StoredTokens = tokens.into();
    if let Ok(s) = serde_json::to_string(&stored) {
        if let Some(storage) = local_storage() {
            let _ = storage.set_item(STORAGE_KEY, &s);
        }
    }
}

pub fn load_tokens() -> Option<Tokens> {
    let storage = local_storage()?;
    let raw = storage.get_item(STORAGE_KEY).ok().flatten()?;
    let stored: StoredTokens = serde_json::from_str(&raw).ok()?;
    let tokens: Tokens = stored.into();
    set_access_token(Some(tokens.access_token.clone()));
    Some(tokens)
}

pub fn clear_tokens() {
    set_access_token(None);
    if let Some(storage) = local_storage() {
        let _ = storage.remove_item(STORAGE_KEY);
    }
}

fn local_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}
