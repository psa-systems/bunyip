//! Token models for authentication

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Refresh token database model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub device_info: Option<String>,
    pub ip_address: Option<IpNetwork>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl RefreshToken {
    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Check if the token is revoked
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Check if the token is valid (not expired and not revoked)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_revoked()
    }
}

/// Data for creating a new refresh token
#[derive(Debug, Clone)]
pub struct CreateRefreshToken {
    pub user_id: Uuid,
    pub token_hash: String,
    pub device_info: Option<String>,
    pub ip_address: Option<IpNetwork>,
    pub expires_at: DateTime<Utc>,
}

/// Session info for display to users
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: Uuid,
    pub device_info: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_current: bool,
}

impl From<RefreshToken> for SessionInfo {
    fn from(token: RefreshToken) -> Self {
        Self {
            id: token.id,
            device_info: token.device_info,
            ip_address: token.ip_address.map(|ip| ip.to_string()),
            created_at: token.created_at,
            last_used_at: token.last_used_at,
            is_current: false, // Set by caller
        }
    }
}

/// Magic link token database model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MagicLinkToken {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub ip_address: Option<IpNetwork>,
}

impl MagicLinkToken {
    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Check if the token has been used
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    /// Check if the token is valid (not expired and not used)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_used()
    }
}

/// Data for creating a new magic link token
#[derive(Debug, Clone)]
pub struct CreateMagicLinkToken {
    pub email: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<IpNetwork>,
}

/// Password reset token database model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PasswordResetToken {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub ip_address: Option<IpNetwork>,
}

impl PasswordResetToken {
    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Check if the token has been used
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    /// Check if the token is valid (not expired and not used)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_used()
    }
}

/// Data for creating a new password reset token
#[derive(Debug, Clone)]
pub struct CreatePasswordResetToken {
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<IpNetwork>,
}

/// Email change request database model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct EmailChangeRequest {
    pub id: Uuid,
    pub user_id: Uuid,
    pub new_email: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub canceled_at: Option<DateTime<Utc>>,
    pub ip_address: Option<IpNetwork>,
    pub created_at: DateTime<Utc>,
}

impl EmailChangeRequest {
    /// Check if the request is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Check if the request has been confirmed
    pub fn is_confirmed(&self) -> bool {
        self.confirmed_at.is_some()
    }

    /// Check if the request has been canceled
    pub fn is_canceled(&self) -> bool {
        self.canceled_at.is_some()
    }

    /// Check if the request is valid (not expired, confirmed, or canceled)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_confirmed() && !self.is_canceled()
    }
}

/// Data for creating a new email change request
#[derive(Debug, Clone)]
pub struct CreateEmailChangeRequest {
    pub user_id: Uuid,
    pub new_email: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<IpNetwork>,
}

/// Email verification token database model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct EmailVerificationToken {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub ip_address: Option<IpNetwork>,
}

impl EmailVerificationToken {
    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Check if the token has been used
    pub fn is_used(&self) -> bool {
        self.used_at.is_some()
    }

    /// Check if the token is valid (not expired and not used)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_used()
    }
}

/// Data for creating a new email verification token
#[derive(Debug, Clone)]
pub struct CreateEmailVerificationToken {
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<IpNetwork>,
}

/// Admin invite database model
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminInvite {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub invited_by: Uuid,
    pub role: String,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl AdminInvite {
    /// Check if the invite is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    /// Check if the invite has been accepted
    pub fn is_accepted(&self) -> bool {
        self.accepted_at.is_some()
    }

    /// Check if the invite has been revoked
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Check if the invite is valid (not expired, accepted, or revoked)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_accepted() && !self.is_revoked()
    }
}

/// Data for creating a new admin invite
#[derive(Debug, Clone)]
pub struct CreateAdminInvite {
    pub email: String,
    pub token_hash: String,
    pub invited_by: Uuid,
    pub role: String,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // -- RefreshToken --

    fn make_refresh_token(
        expires_at: DateTime<Utc>,
        revoked_at: Option<DateTime<Utc>>,
    ) -> RefreshToken {
        RefreshToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token_hash: "hash".to_string(),
            device_info: None,
            ip_address: None,
            expires_at,
            created_at: Utc::now(),
            last_used_at: None,
            revoked_at,
        }
    }

    #[test]
    fn refresh_token_valid() {
        let token = make_refresh_token(Utc::now() + Duration::hours(1), None);
        assert!(!token.is_expired());
        assert!(!token.is_revoked());
        assert!(token.is_valid());
    }

    #[test]
    fn refresh_token_expired() {
        let token = make_refresh_token(Utc::now() - Duration::hours(1), None);
        assert!(token.is_expired());
        assert!(!token.is_valid());
    }

    #[test]
    fn refresh_token_revoked() {
        let token = make_refresh_token(Utc::now() + Duration::hours(1), Some(Utc::now()));
        assert!(token.is_revoked());
        assert!(!token.is_valid());
    }

    #[test]
    fn session_info_from_refresh_token() {
        let token = make_refresh_token(Utc::now() + Duration::hours(1), None);
        let id = token.id;
        let info = SessionInfo::from(token);
        assert_eq!(info.id, id);
        assert!(!info.is_current); // default false
    }

    // -- MagicLinkToken --

    fn make_magic_link(
        expires_at: DateTime<Utc>,
        used_at: Option<DateTime<Utc>>,
    ) -> MagicLinkToken {
        MagicLinkToken {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            token_hash: "hash".to_string(),
            expires_at,
            used_at,
            created_at: Utc::now(),
            ip_address: None,
        }
    }

    #[test]
    fn magic_link_valid() {
        let token = make_magic_link(Utc::now() + Duration::hours(1), None);
        assert!(token.is_valid());
    }

    #[test]
    fn magic_link_expired() {
        let token = make_magic_link(Utc::now() - Duration::hours(1), None);
        assert!(token.is_expired());
        assert!(!token.is_valid());
    }

    #[test]
    fn magic_link_used() {
        let token = make_magic_link(Utc::now() + Duration::hours(1), Some(Utc::now()));
        assert!(token.is_used());
        assert!(!token.is_valid());
    }

    // -- PasswordResetToken --

    fn make_reset_token(
        expires_at: DateTime<Utc>,
        used_at: Option<DateTime<Utc>>,
    ) -> PasswordResetToken {
        PasswordResetToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token_hash: "hash".to_string(),
            expires_at,
            used_at,
            created_at: Utc::now(),
            ip_address: None,
        }
    }

    #[test]
    fn reset_token_valid() {
        let token = make_reset_token(Utc::now() + Duration::hours(1), None);
        assert!(token.is_valid());
    }

    #[test]
    fn reset_token_expired() {
        let token = make_reset_token(Utc::now() - Duration::hours(1), None);
        assert!(!token.is_valid());
    }

    #[test]
    fn reset_token_used() {
        let token = make_reset_token(Utc::now() + Duration::hours(1), Some(Utc::now()));
        assert!(!token.is_valid());
    }

    // -- EmailChangeRequest --

    fn make_email_change(
        expires_at: DateTime<Utc>,
        confirmed_at: Option<DateTime<Utc>>,
        canceled_at: Option<DateTime<Utc>>,
    ) -> EmailChangeRequest {
        EmailChangeRequest {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            new_email: "new@example.com".to_string(),
            token_hash: "hash".to_string(),
            expires_at,
            confirmed_at,
            canceled_at,
            ip_address: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn email_change_valid() {
        let req = make_email_change(Utc::now() + Duration::hours(1), None, None);
        assert!(req.is_valid());
    }

    #[test]
    fn email_change_expired() {
        let req = make_email_change(Utc::now() - Duration::hours(1), None, None);
        assert!(!req.is_valid());
    }

    #[test]
    fn email_change_confirmed() {
        let req = make_email_change(Utc::now() + Duration::hours(1), Some(Utc::now()), None);
        assert!(req.is_confirmed());
        assert!(!req.is_valid());
    }

    #[test]
    fn email_change_canceled() {
        let req = make_email_change(Utc::now() + Duration::hours(1), None, Some(Utc::now()));
        assert!(req.is_canceled());
        assert!(!req.is_valid());
    }

    // -- EmailVerificationToken --

    fn make_verification_token(
        expires_at: DateTime<Utc>,
        used_at: Option<DateTime<Utc>>,
    ) -> EmailVerificationToken {
        EmailVerificationToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token_hash: "hash".to_string(),
            expires_at,
            used_at,
            created_at: Utc::now(),
            ip_address: None,
        }
    }

    #[test]
    fn verification_token_valid() {
        let token = make_verification_token(Utc::now() + Duration::hours(1), None);
        assert!(token.is_valid());
    }

    #[test]
    fn verification_token_expired() {
        let token = make_verification_token(Utc::now() - Duration::hours(1), None);
        assert!(!token.is_valid());
    }

    #[test]
    fn verification_token_used() {
        let token = make_verification_token(Utc::now() + Duration::hours(1), Some(Utc::now()));
        assert!(!token.is_valid());
    }
}
