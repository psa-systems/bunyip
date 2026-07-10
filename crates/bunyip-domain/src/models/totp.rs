//! TOTP two-factor authentication models

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

/// User TOTP configuration
#[derive(Debug, Clone, FromRow)]
pub struct UserTotp {
    pub id: Uuid,
    pub user_id: Uuid,
    pub encrypted_secret: Vec<u8>,
    pub nonce: Vec<u8>,
    pub verified: bool,
    pub enabled_at: Option<DateTime<Utc>>,
    pub key_version: i16,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// BUNYIP-355: a re-keyed secret staged by `begin_rekey`, left NULL until an
    /// authenticator reset is in progress. `confirm_rekey` verifies a code
    /// against it and promotes it into `encrypted_secret`/`nonce`/`key_version`,
    /// so the active secret above keeps working until then.
    pub pending_encrypted_secret: Option<Vec<u8>>,
    pub pending_nonce: Option<Vec<u8>>,
    pub pending_key_version: Option<i16>,
    pub pending_created_at: Option<DateTime<Utc>>,
}

/// Recovery code for 2FA backup
#[derive(Debug, Clone, FromRow)]
pub struct RecoveryCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
