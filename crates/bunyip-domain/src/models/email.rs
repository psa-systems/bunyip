//! Email / SMTP configuration models (BUNYIP-351)

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// Database row for the `email_config` singleton table.
///
/// Every tunable column is nullable: a NULL means "fall back to the
/// environment-variable default at load time" (see
/// [`EmailConfig::from_db_row`](crate::config::EmailConfig::from_db_row)). The
/// SMTP password is stored encrypted (`smtp_password` ciphertext +
/// `smtp_password_nonce`, versioned by `key_version`).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmailConfigRow {
    pub id: i32,
    pub enabled: Option<bool>,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<i32>,
    pub smtp_tls: Option<String>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<Vec<u8>>,
    pub smtp_password_nonce: Option<Vec<u8>>,
    pub key_version: i16,
    pub from_email: Option<String>,
    pub from_name: Option<String>,
    pub admin_notification_emails: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<Uuid>,
}

/// API response for email configuration. The SMTP password is never returned in
/// plaintext: only a masked hint and a `has_smtp_password` flag are surfaced,
/// mirroring the Stripe secret masking.
#[derive(Debug, Serialize)]
pub struct EmailConfigResponse {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: i32,
    /// "implicit" or "starttls".
    pub smtp_tls: String,
    pub smtp_username: String,
    pub has_smtp_password: bool,
    pub smtp_password_masked: Option<String>,
    pub from_email: String,
    pub from_name: String,
    pub admin_notification_emails: Vec<String>,
    /// Whether the resolved values come from "database" or "environment".
    pub source: &'static str,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}
