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
