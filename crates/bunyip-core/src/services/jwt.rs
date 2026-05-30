//! JWT token service

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::User;

// JwtConfig is the generic kernel type provided by dunite-core; bunyip-core's
// JwtService (below) builds the access/refresh/2FA token logic on top of it.
// dunite-oci's OciTokenService also consumes this exact type, so it must come
// from dunite-core (not a local redefinition).
pub use dunite_core::services::JwtConfig;

/// Access token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: Uuid,
    pub email: String,
    pub role: String,
    pub membership_status: String,
    pub price_locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_id: Option<String>,
    /// True for lifetime members — access is never time-gated
    pub lifetime_member: bool,
    /// Unix timestamp when trial expires; None for lifetime members
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_ends_at: Option<i64>,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub iss: String,
}

impl AccessTokenClaims {
    /// Check if the user has active member access.
    ///
    /// Access is granted when ANY of the following are true:
    /// - User is an admin
    /// - User is a lifetime member
    /// - User has an active trial (trial_ends_at in the future)
    /// - User has an active or grace_period subscription
    pub fn has_member_access(&self) -> bool {
        Self::has_member_access_static(
            &self.role,
            self.lifetime_member,
            self.trial_ends_at,
            &self.membership_status,
        )
    }

    /// Static version of `has_member_access` for use with raw user fields
    /// (e.g. when building userinfo responses without a full `AccessTokenClaims`).
    pub fn has_member_access_static(
        role: &str,
        lifetime_member: bool,
        trial_ends_at: Option<i64>,
        membership_status: &str,
    ) -> bool {
        role == "admin"
            || lifetime_member
            || trial_ends_at.map_or(false, |ts| ts > chrono::Utc::now().timestamp())
            || membership_status == "active"
            || membership_status == "grace_period"
    }
}

/// Two-factor authentication challenge claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorChallengeClaims {
    pub sub: Uuid,
    pub purpose: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
}

/// Refresh token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: Uuid,
    pub jti: String,
    pub exp: i64,
    pub iat: i64,
}

/// JWT service for token operations
#[derive(Clone)]
pub struct JwtService {
    config: JwtConfig,
}

impl JwtService {
    pub fn new(config: JwtConfig) -> Self {
        Self { config }
    }

    /// Create access token for a user
    pub fn create_access_token(&self, user: &User) -> Result<String, AppError> {
        let now = Utc::now();
        let exp = now + self.config.access_token_expiry;

        let claims = AccessTokenClaims {
            sub: user.id,
            email: user.email.clone(),
            role: user.role.clone(),
            membership_status: user.membership_status.clone(),
            price_locked: user.price_locked,
            price_id: user.locked_price_id.clone(),
            lifetime_member: user.lifetime_member,
            trial_ends_at: user.trial_ends_at.map(|t| t.timestamp()),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            jti: format!("at_{}", Uuid::new_v4().as_simple()),
            iss: self.config.issuer.clone(),
        };

        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &self.config.encoding_key)
            .map_err(|e| AppError::internal(format!("Failed to create access token: {}", e)))?;

        Ok(token)
    }

    /// Create refresh token
    /// Returns (token, token_hash) - hash is stored in database
    pub fn create_refresh_token(&self, user_id: Uuid) -> Result<(String, String), AppError> {
        let now = Utc::now();
        let exp = now + self.config.refresh_token_expiry;
        let jti = format!("rt_{}", Uuid::new_v4().as_simple());

        let claims = RefreshTokenClaims {
            sub: user_id,
            jti: jti.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        let header = Header::new(Algorithm::HS256);
        let token = encode(&header, &claims, &self.config.encoding_key)
            .map_err(|e| AppError::internal(format!("Failed to create refresh token: {}", e)))?;

        // Hash the token for storage
        let token_hash = self.hash_token(&token);

        Ok((token, token_hash))
    }

    /// Verify access token
    pub fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, AppError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.config.issuer]);

        let token_data = decode::<AccessTokenClaims>(token, &self.config.decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
                _ => AppError::InvalidCredentials,
            })?;

        Ok(token_data.claims)
    }

    /// Verify refresh token
    pub fn verify_refresh_token(&self, token: &str) -> Result<RefreshTokenClaims, AppError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["sub", "exp"]);
        validation.validate_exp = true;

        let token_data =
            decode::<RefreshTokenClaims>(token, &self.config.decoding_key, &validation).map_err(
                |e| match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
                    _ => AppError::InvalidCredentials,
                },
            )?;

        Ok(token_data.claims)
    }

    /// Decode token without validation (for expired token handling)
    pub fn decode_without_validation(&self, token: &str) -> Result<AccessTokenClaims, AppError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.insecure_disable_signature_validation();

        let token_data = decode::<AccessTokenClaims>(token, &self.config.decoding_key, &validation)
            .map_err(|_| AppError::InvalidCredentials)?;

        Ok(token_data.claims)
    }

    /// Create a 2FA challenge token (5 min expiry)
    pub fn create_2fa_challenge_token(&self, user_id: Uuid) -> Result<String, AppError> {
        let now = Utc::now();
        let exp = now + Duration::minutes(5);

        let claims = TwoFactorChallengeClaims {
            sub: user_id,
            purpose: "2fa_challenge".to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: format!("2fa_{}", Uuid::new_v4().as_simple()),
        };

        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &self.config.encoding_key)
            .map_err(|e| AppError::internal(format!("Failed to create 2FA challenge token: {}", e)))
    }

    /// Verify a 2FA challenge token
    pub fn verify_2fa_challenge_token(
        &self,
        token: &str,
    ) -> Result<TwoFactorChallengeClaims, AppError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["sub", "exp"]);
        validation.validate_exp = true;

        let token_data =
            decode::<TwoFactorChallengeClaims>(token, &self.config.decoding_key, &validation)
                .map_err(|e| match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
                    _ => AppError::InvalidCredentials,
                })?;

        if token_data.claims.purpose != "2fa_challenge" {
            return Err(AppError::InvalidCredentials);
        }

        Ok(token_data.claims)
    }

    /// Hash a token for database storage
    pub fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_user() -> User {
        User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            email_verified: true,
            password_hash: None,
            role: "subscriber".to_string(),
            stripe_customer_id: None,
            stripe_payment_method_id: None,
            membership_status: "active".to_string(),
            price_locked: false,
            locked_price_id: None,
            locked_price_amount: None,
            grace_period_start: None,
            grace_period_end: None,
            two_factor_enabled: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login_at: None,
            deleted_at: None,
            subscription_tier: "standard".to_string(),
            trial_ends_at: None,
            lifetime_member: false,
            subscription_override_by: None,
        }
    }

    #[test]
    fn test_access_token_creation_and_verification() {
        let config = JwtConfig::from_secret("test-secret-key-12345", "localhost");
        let service = JwtService::new(config);
        let user = create_test_user();

        let token = service.create_access_token(&user).unwrap();
        let claims = service.verify_access_token(&token).unwrap();

        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.email, user.email);
        assert_eq!(claims.role, user.role);
    }

    #[test]
    fn test_refresh_token_creation() {
        let config = JwtConfig::from_secret("test-secret-key-12345", "localhost");
        let service = JwtService::new(config);
        let user_id = Uuid::new_v4();

        let (token, hash) = service.create_refresh_token(user_id).unwrap();
        let claims = service.verify_refresh_token(&token).unwrap();

        assert_eq!(claims.sub, user_id);
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_token_hashing() {
        let config = JwtConfig::from_secret("test-secret-key-12345", "localhost");
        let service = JwtService::new(config);

        let token = "test-token";
        let hash1 = service.hash_token(token);
        let hash2 = service.hash_token(token);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, token);
    }

    fn test_claims(
        membership_status: &str,
        lifetime_member: bool,
        trial_ends_at: Option<i64>,
        role: &str,
    ) -> AccessTokenClaims {
        AccessTokenClaims {
            sub: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            role: role.to_string(),
            membership_status: membership_status.to_string(),
            price_locked: false,
            price_id: None,
            lifetime_member,
            trial_ends_at,
            iat: Utc::now().timestamp(),
            exp: (Utc::now() + Duration::minutes(15)).timestamp(),
            jti: "test".to_string(),
            iss: "test".to_string(),
        }
    }

    #[test]
    fn has_member_access_admin() {
        let claims = test_claims("none", false, None, "admin");
        assert!(claims.has_member_access());
    }

    #[test]
    fn has_member_access_active_subscription() {
        let claims = test_claims("active", false, None, "subscriber");
        assert!(claims.has_member_access());
    }

    #[test]
    fn has_member_access_grace_period() {
        let claims = test_claims("grace_period", false, None, "subscriber");
        assert!(claims.has_member_access());
    }

    #[test]
    fn has_member_access_lifetime_member() {
        let claims = test_claims("none", true, None, "subscriber");
        assert!(claims.has_member_access());
    }

    #[test]
    fn has_member_access_active_trial() {
        let future = Utc::now().timestamp() + 86400; // 1 day in the future
        let claims = test_claims("none", false, Some(future), "subscriber");
        assert!(claims.has_member_access());
    }

    #[test]
    fn has_member_access_expired_trial_no_access() {
        let past = Utc::now().timestamp() - 86400; // 1 day in the past
        let claims = test_claims("none", false, Some(past), "subscriber");
        assert!(!claims.has_member_access());
    }

    #[test]
    fn has_member_access_none_no_access() {
        let claims = test_claims("none", false, None, "subscriber");
        assert!(!claims.has_member_access());
    }

    #[test]
    fn has_member_access_canceled_no_access() {
        let claims = test_claims("canceled", false, None, "subscriber");
        assert!(!claims.has_member_access());
    }

    #[test]
    fn has_member_access_past_due_no_access() {
        let claims = test_claims("past_due", false, None, "subscriber");
        assert!(!claims.has_member_access());
    }
}
