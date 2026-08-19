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
    // BUNYIP-571: inbound IMAP settings. `imap_password` is the governed secret
    // (ciphertext + nonce, versioned by the shared `key_version`); the rest are
    // regular config columns.
    pub imap_host: Option<String>,
    pub imap_port: Option<i32>,
    pub imap_username: Option<String>,
    pub imap_password: Option<Vec<u8>>,
    pub imap_password_nonce: Option<Vec<u8>>,
    pub imap_mailbox: Option<String>,
    pub imap_enabled: Option<bool>,
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
    /// BUNYIP-432: whether a password is stored - a boolean fact only. The
    /// password (and any masked/truncated form of it) is deliberately NOT in
    /// this response: the field is write-only, so no representation of the
    /// secret ever leaves the server. The client renders a fixed-length mask
    /// from this flag alone.
    pub has_smtp_password: bool,
    pub from_email: String,
    pub from_name: String,
    pub admin_notification_emails: Vec<String>,
    /// Whether the resolved values come from "database" or "environment".
    pub source: &'static str,
    /// BUNYIP-542: the declared store for the SMTP password
    /// (`SECRETS_STORAGE`): "environment", "database" or "infisical". The
    /// non-secret settings above are unaffected by it.
    pub secrets_storage: &'static str,
    /// Whether the SMTP password can be changed from the admin page. False in
    /// `environment` mode, where there is no writable store, so the field
    /// renders read-only instead of reporting a save that lands nowhere.
    pub smtp_password_editable: bool,
    /// BUNYIP-571: inbound IMAP settings. The password is write-only like the
    /// SMTP one - only `has_imap_password` is surfaced, never the value.
    pub imap_host: String,
    pub imap_port: i32,
    pub imap_username: String,
    pub imap_mailbox: String,
    pub imap_enabled: bool,
    pub has_imap_password: bool,
    pub imap_password_editable: bool,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
}
