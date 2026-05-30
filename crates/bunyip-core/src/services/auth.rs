//! Authentication service

use chrono::{Duration, Utc};
use ipnetwork::IpNetwork;
use rand::RngCore;
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

use std::sync::{Arc, RwLock};

use crate::config::TierConfig;
use crate::errors::AppError;
use crate::models::{
    AuditAction, CreateAdminInvite, CreateAuditLog, CreateEmailChangeRequest,
    CreateEmailVerificationToken, CreateMagicLinkToken, CreatePasswordResetToken,
    CreateRefreshToken, CreateUser, SubscriptionTier, User, UserResponse, UserRole,
};
use crate::repositories::{
    AuditLogRepository, InviteRepository, TokenRepository, TotpRepository, UserRepository,
};
use crate::services::{JwtService, PasswordService};

/// Authentication tokens returned after login
#[derive(Debug, Clone)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

/// Result of a login attempt — either full success or 2FA challenge
pub enum LoginResult {
    Success(AuthTokens, UserResponse),
    TwoFactorRequired { challenge_token: String },
}

/// Result of magic link verification
pub enum MagicLinkResult {
    Success(AuthTokens, UserResponse, bool),
    TwoFactorRequired {
        challenge_token: String,
        is_new_user: bool,
    },
}

/// Result of accepting an admin invite
pub enum AcceptInviteResult {
    Success(AuthTokens, UserResponse),
    PasswordRequired { email: String },
}

/// Authentication service
pub struct AuthService {
    pool: PgPool,
    jwt: JwtService,
    password: PasswordService,
    tier_config: Arc<RwLock<TierConfig>>,
}

impl AuthService {
    pub fn new(pool: PgPool, jwt: JwtService, tier_config: Arc<RwLock<TierConfig>>) -> Self {
        Self {
            pool,
            jwt,
            password: PasswordService::new(),
            tier_config,
        }
    }

    /// Hot-reload the tier configuration (e.g. after admin update).
    pub fn reload_tier_config(&self, config: TierConfig) {
        let mut tc = self.tier_config.write().expect("TierConfig lock poisoned");
        *tc = config;
    }

    /// Register a new user
    pub async fn register(
        &self,
        email: String,
        password: String,
        ip_address: Option<IpAddr>,
    ) -> Result<UserResponse, AppError> {
        // Validate password strength
        self.password.validate_strength(&password)?;
        self.password
            .validate_not_contains_email(&password, &email)?;

        // Check if email already exists
        if UserRepository::find_by_email(&self.pool, &email)
            .await?
            .is_some()
        {
            return Err(AppError::conflict("Email already registered"));
        }

        // Hash password
        let password_hash = self.password.hash(&password)?;

        // Create user
        let user = UserRepository::create(
            &self.pool,
            CreateUser {
                email: email.clone(),
                password_hash: Some(password_hash),
                role: UserRole::Subscriber,
            },
        )
        .await?;

        // Create audit log
        let ip = ip_address.map(|ip| IpNetwork::from(ip));
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::UserRegistered)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip)
                .with_resource("user", user.id),
        )
        .await?;

        Ok(UserResponse::from(user))
    }

    /// Login with email and password
    pub async fn login(
        &self,
        email: String,
        password: String,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<LoginResult, AppError> {
        // Find user
        let user = UserRepository::find_by_email(&self.pool, &email)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        // Check if user is deleted
        if user.is_deleted() {
            return Err(AppError::InvalidCredentials);
        }

        // Verify password
        let password_hash = user
            .password_hash
            .as_ref()
            .ok_or(AppError::InvalidCredentials)?;

        if !self.password.verify(&password, password_hash)? {
            return Err(AppError::InvalidCredentials);
        }

        // Check if 2FA is enabled AND actually configured
        if user.two_factor_enabled {
            let totp_record = TotpRepository::find_by_user_id(&self.pool, user.id).await?;
            let has_verified_totp = totp_record.map(|r| r.verified).unwrap_or(false);

            if has_verified_totp {
                let challenge_token = self.jwt.create_2fa_challenge_token(user.id)?;
                return Ok(LoginResult::TwoFactorRequired { challenge_token });
            }

            // Flag is true but no verified TOTP exists — reset the flag so the
            // frontend can redirect to 2FA setup after login
            UserRepository::set_two_factor_enabled(&self.pool, user.id, false).await?;
        }

        // Create tokens
        let tokens = self
            .create_tokens(&user, device_info.clone(), ip_address)
            .await?;

        // Update last login
        UserRepository::update_last_login(&self.pool, user.id).await?;

        // Create audit log
        let ip = ip_address.map(|ip| IpNetwork::from(ip));
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::UserLogin)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip)
                .with_metadata(serde_json::json!({ "device_info": device_info })),
        )
        .await?;

        Ok(LoginResult::Success(tokens, UserResponse::from(user)))
    }

    /// Refresh tokens
    pub async fn refresh_tokens(
        &self,
        refresh_token: String,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<AuthTokens, AppError> {
        // Verify refresh token signature
        let claims = match self.jwt.verify_refresh_token(&refresh_token) {
            Ok(claims) => claims,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "token_refresh: JWT signature verification failed"
                );
                return Err(e);
            }
        };

        // Hash token to find in database
        let token_hash = self.jwt.hash_token(&refresh_token);

        // Find token in database
        let stored_token =
            match TokenRepository::find_refresh_token_by_hash(&self.pool, &token_hash).await? {
                Some(token) => token,
                None => {
                    // Diagnostic: check if the token exists at all (revoked/expired)
                    match TokenRepository::find_refresh_token_by_hash_any(&self.pool, &token_hash)
                        .await
                    {
                        Ok(Some(stale)) => {
                            tracing::warn!(
                                user_id = %claims.sub,
                                token_id = %claims.jti,
                                hash_prefix = %&token_hash[..8],
                                revoked_at = ?stale.revoked_at,
                                expires_at = %stale.expires_at,
                                created_at = %stale.created_at,
                                "token_refresh: token exists in DB but is revoked or expired"
                            );
                        }
                        Ok(None) => {
                            tracing::warn!(
                                user_id = %claims.sub,
                                token_id = %claims.jti,
                                hash_prefix = %&token_hash[..8],
                                "token_refresh: token hash does not exist in DB at all"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                user_id = %claims.sub,
                                token_id = %claims.jti,
                                error = %e,
                                "token_refresh: diagnostic query failed"
                            );
                        }
                    }
                    return Err(AppError::InvalidCredentials);
                }
            };

        // Check if token is valid
        if !stored_token.is_valid() {
            tracing::warn!(
                user_id = %claims.sub,
                token_id = %claims.jti,
                "token_refresh: stored token is no longer valid"
            );
            return Err(AppError::TokenExpired);
        }

        // Get user
        let user = UserRepository::find_by_id(&self.pool, claims.sub)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        // Revoke old token
        TokenRepository::revoke_refresh_token(&self.pool, stored_token.id).await?;

        // Create new tokens
        let tokens = self.create_tokens(&user, device_info, ip_address).await?;

        Ok(tokens)
    }

    /// Logout (revoke refresh token)
    pub async fn logout(
        &self,
        refresh_token: String,
        user_id: Uuid,
        ip_address: Option<IpAddr>,
    ) -> Result<(), AppError> {
        // Hash token
        let token_hash = self.jwt.hash_token(&refresh_token);

        // Revoke token
        TokenRepository::revoke_refresh_token_by_hash(&self.pool, &token_hash).await?;

        // Get user for audit log
        if let Some(user) = UserRepository::find_by_id(&self.pool, user_id).await? {
            let ip = ip_address.map(|ip| IpNetwork::from(ip));
            AuditLogRepository::create(
                &self.pool,
                CreateAuditLog::new(AuditAction::UserLogout)
                    .with_actor(user.id, &user.email, &user.role)
                    .with_ip(ip),
            )
            .await?;
        }

        Ok(())
    }

    /// Logout from all sessions
    pub async fn logout_all(
        &self,
        user_id: Uuid,
        ip_address: Option<IpAddr>,
    ) -> Result<(), AppError> {
        TokenRepository::revoke_all_user_refresh_tokens(&self.pool, user_id).await?;

        // Get user for audit log
        if let Some(user) = UserRepository::find_by_id(&self.pool, user_id).await? {
            let ip = ip_address.map(|ip| IpNetwork::from(ip));
            AuditLogRepository::create(
                &self.pool,
                CreateAuditLog::new(AuditAction::UserLogout)
                    .with_actor(user.id, &user.email, &user.role)
                    .with_ip(ip)
                    .with_metadata(serde_json::json!({ "all_sessions": true })),
            )
            .await?;
        }

        Ok(())
    }

    /// Request magic link
    pub async fn request_magic_link(
        &self,
        email: String,
        ip_address: Option<IpAddr>,
    ) -> Result<String, AppError> {
        let ip = ip_address.map(|ip| IpNetwork::from(ip));

        // Generate token
        let token = generate_secure_token(32);
        let token_hash = self.jwt.hash_token(&token);
        let expires_at = Utc::now() + Duration::minutes(15);

        // Store token
        TokenRepository::create_magic_link_token(
            &self.pool,
            CreateMagicLinkToken {
                email: email.clone(),
                token_hash,
                expires_at,
                ip_address: ip,
            },
        )
        .await?;

        // Log the request (don't reveal if email exists)
        tracing::info!(email = %email, "Magic link requested");

        // Audit log
        let audit_log =
            if let Ok(Some(user)) = UserRepository::find_by_email(&self.pool, &email).await {
                CreateAuditLog::new(AuditAction::MagicLinkRequested)
                    .with_actor(user.id, &user.email, &user.role)
                    .with_ip(ip)
                    .with_metadata(serde_json::json!({ "email_known": true }))
            } else {
                CreateAuditLog::new(AuditAction::MagicLinkRequested)
                    .with_ip(ip)
                    .with_metadata(serde_json::json!({ "email_known": false, "email": email }))
            };
        // Non-critical — don't fail the request if audit logging fails
        if let Err(e) = AuditLogRepository::create(&self.pool, audit_log).await {
            tracing::error!(error = %e, "Failed to create audit log for magic link request");
        }

        Ok(token)
    }

    /// Verify magic link and login
    ///
    /// Returns (tokens, user, is_new_user) so the caller can send
    /// an account-created email for newly registered users.
    pub async fn verify_magic_link(
        &self,
        token: String,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<MagicLinkResult, AppError> {
        let token_hash = self.jwt.hash_token(&token);

        // Find token
        let magic_token = TokenRepository::find_magic_link_token_by_hash(&self.pool, &token_hash)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if !magic_token.is_valid() {
            return Err(AppError::TokenExpired);
        }

        // Mark token as used
        TokenRepository::mark_magic_link_token_used(&self.pool, magic_token.id).await?;

        // Find or create user
        let (user, is_new_user) =
            match UserRepository::find_by_email(&self.pool, &magic_token.email).await? {
                Some(user) => {
                    // Set email as verified
                    UserRepository::set_email_verified(&self.pool, user.id).await?;
                    let user = UserRepository::find_by_id(&self.pool, user.id)
                        .await?
                        .ok_or(AppError::not_found("User"))?;
                    (user, false)
                }
                None => {
                    // Create new user (passwordless)
                    let user = UserRepository::create(
                        &self.pool,
                        CreateUser {
                            email: magic_token.email.clone(),
                            password_hash: None,
                            role: UserRole::Subscriber,
                        },
                    )
                    .await?;
                    // Set email as verified since they proved ownership via magic link
                    UserRepository::set_email_verified(&self.pool, user.id).await?;
                    let user = UserRepository::find_by_id(&self.pool, user.id)
                        .await?
                        .ok_or(AppError::not_found("User"))?;
                    (user, true)
                }
            };

        // Check if 2FA is enabled AND actually configured
        if user.two_factor_enabled {
            let totp_record = TotpRepository::find_by_user_id(&self.pool, user.id).await?;
            let has_verified_totp = totp_record.map(|r| r.verified).unwrap_or(false);

            if has_verified_totp {
                let challenge_token = self.jwt.create_2fa_challenge_token(user.id)?;
                return Ok(MagicLinkResult::TwoFactorRequired {
                    challenge_token,
                    is_new_user,
                });
            }

            // Flag is true but no verified TOTP exists — reset the flag
            UserRepository::set_two_factor_enabled(&self.pool, user.id, false).await?;
        }

        // Create tokens
        let tokens = self.create_tokens(&user, device_info, ip_address).await?;

        // Update last login
        UserRepository::update_last_login(&self.pool, user.id).await?;

        // Audit log
        let ip = ip_address.map(|ip| IpNetwork::from(ip));
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::MagicLinkUsed)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;

        Ok(MagicLinkResult::Success(
            tokens,
            UserResponse::from(user),
            is_new_user,
        ))
    }

    /// Complete 2FA login after challenge token + TOTP/recovery code verification
    pub async fn complete_2fa_login(
        &self,
        challenge_token: &str,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<(AuthTokens, UserResponse), AppError> {
        // Verify challenge token
        let claims = self.jwt.verify_2fa_challenge_token(challenge_token)?;
        let user_id = claims.sub;

        // Get user
        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if user.is_deleted() {
            return Err(AppError::InvalidCredentials);
        }

        // Create tokens
        let tokens = self
            .create_tokens(&user, device_info.clone(), ip_address)
            .await?;

        // Update last login
        UserRepository::update_last_login(&self.pool, user.id).await?;

        // Audit log
        let ip = ip_address.map(|ip| IpNetwork::from(ip));
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::UserLogin)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip)
                .with_metadata(serde_json::json!({ "method": "2fa", "device_info": device_info })),
        )
        .await?;

        Ok((tokens, UserResponse::from(user)))
    }

    /// Request password reset
    pub async fn request_password_reset(
        &self,
        email: String,
        ip_address: Option<IpAddr>,
    ) -> Result<Option<String>, AppError> {
        let ip = ip_address.map(|ip| IpNetwork::from(ip));

        // Find user
        let user = match UserRepository::find_by_email(&self.pool, &email).await? {
            Some(user) => user,
            None => return Ok(None), // Don't reveal if email exists
        };

        // Check if user has a password (not magic-link only)
        if user.password_hash.is_none() {
            return Ok(None);
        }

        // Generate token
        let token = generate_secure_token(32);
        let token_hash = self.jwt.hash_token(&token);
        let expires_at = Utc::now() + Duration::hours(1);

        // Store token
        TokenRepository::create_password_reset_token(
            &self.pool,
            CreatePasswordResetToken {
                user_id: user.id,
                token_hash,
                expires_at,
                ip_address: ip,
            },
        )
        .await?;

        // Audit log
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::PasswordResetRequested)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;

        Ok(Some(token))
    }

    /// Verify password reset token (check only, don't consume)
    pub async fn verify_reset_token(&self, token: String) -> Result<Uuid, AppError> {
        let token_hash = self.jwt.hash_token(&token);

        let reset_token =
            TokenRepository::find_password_reset_token_by_hash(&self.pool, &token_hash)
                .await?
                .ok_or(AppError::InvalidCredentials)?;

        if !reset_token.is_valid() {
            return Err(AppError::TokenExpired);
        }

        Ok(reset_token.user_id)
    }

    /// Complete password reset
    ///
    /// Returns the user's email so the caller can send a
    /// password-changed notification.
    pub async fn complete_password_reset(
        &self,
        token: String,
        new_password: String,
        ip_address: Option<IpAddr>,
    ) -> Result<String, AppError> {
        // Validate new password
        self.password.validate_strength(&new_password)?;

        let token_hash = self.jwt.hash_token(&token);

        // Find and validate token
        let reset_token =
            TokenRepository::find_password_reset_token_by_hash(&self.pool, &token_hash)
                .await?
                .ok_or(AppError::InvalidCredentials)?;

        if !reset_token.is_valid() {
            return Err(AppError::TokenExpired);
        }

        // Get user
        let user = UserRepository::find_by_id(&self.pool, reset_token.user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        // Validate password doesn't contain email
        self.password
            .validate_not_contains_email(&new_password, &user.email)?;

        // Hash new password
        let password_hash = self.password.hash(&new_password)?;

        // Update password
        UserRepository::update_password(&self.pool, user.id, &password_hash).await?;

        // Mark token as used
        TokenRepository::mark_password_reset_token_used(&self.pool, reset_token.id).await?;

        // Revoke all refresh tokens (logout everywhere)
        TokenRepository::revoke_all_user_refresh_tokens(&self.pool, user.id).await?;

        // Audit log
        let ip = ip_address.map(|ip| IpNetwork::from(ip));
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::PasswordResetCompleted)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;

        Ok(user.email)
    }

    /// Change password (for logged-in users)
    pub async fn change_password(
        &self,
        user_id: Uuid,
        current_password: String,
        new_password: String,
        ip_address: Option<IpAddr>,
    ) -> Result<(), AppError> {
        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        // Verify current password
        let password_hash = user.password_hash.as_ref().ok_or(AppError::validation(
            "password",
            "No password set for this account",
        ))?;

        if !self.password.verify(&current_password, password_hash)? {
            return Err(AppError::validation(
                "current_password",
                "Current password is incorrect",
            ));
        }

        // Validate new password
        self.password.validate_strength(&new_password)?;
        self.password
            .validate_not_contains_email(&new_password, &user.email)?;

        // Hash and update
        let new_hash = self.password.hash(&new_password)?;
        UserRepository::update_password(&self.pool, user_id, &new_hash).await?;

        // Audit log
        let ip = ip_address.map(|ip| IpNetwork::from(ip));
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::PasswordChanged)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;

        Ok(())
    }

    /// Request email change
    ///
    /// For verified users: creates a verification token and returns it.
    /// For unverified users: changes email immediately and returns None.
    /// Returns (old_email, Option<token>) so caller can send appropriate emails.
    pub async fn request_email_change(
        &self,
        user_id: Uuid,
        new_email: String,
        current_password: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<(String, Option<String>), AppError> {
        let ip = ip_address.map(|ip| IpNetwork::from(ip));

        // Get user
        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        // Check if new email is same as current
        if user.email.to_lowercase() == new_email.to_lowercase() {
            return Err(AppError::validation(
                "email",
                "New email must be different from current email",
            ));
        }

        // Check if new email is already taken
        if UserRepository::find_by_email(&self.pool, &new_email)
            .await?
            .is_some()
        {
            return Err(AppError::conflict("Email already registered"));
        }

        // If user has a password, require it for verification
        if user.password_hash.is_some() {
            let password = current_password.ok_or(AppError::validation(
                "current_password",
                "Password is required to change email",
            ))?;
            let password_hash = user.password_hash.as_ref().unwrap();
            if !self.password.verify(&password, password_hash)? {
                return Err(AppError::validation(
                    "current_password",
                    "Current password is incorrect",
                ));
            }
        }

        let old_email = user.email.clone();

        if user.email_verified {
            // Rate limit: 3 requests per hour
            let since = Utc::now() - Duration::hours(1);
            let count =
                TokenRepository::count_recent_email_change_requests(&self.pool, user_id, since)
                    .await?;
            if count >= 3 {
                return Err(AppError::RateLimited { retry_after: 3600 });
            }

            // Cancel any pending requests
            TokenRepository::cancel_pending_email_change_requests(&self.pool, user_id).await?;

            // Generate token
            let token = generate_secure_token(32);
            let token_hash = self.jwt.hash_token(&token);
            let expires_at = Utc::now() + Duration::hours(1);

            // Store request
            TokenRepository::create_email_change_request(
                &self.pool,
                CreateEmailChangeRequest {
                    user_id,
                    new_email,
                    token_hash,
                    expires_at,
                    ip_address: ip,
                },
            )
            .await?;

            // Audit log
            AuditLogRepository::create(
                &self.pool,
                CreateAuditLog::new(AuditAction::EmailChangeRequested)
                    .with_actor(user.id, &user.email, &user.role)
                    .with_ip(ip),
            )
            .await?;

            Ok((old_email, Some(token)))
        } else {
            // Unverified user: change email immediately, using a transaction
            // to prevent race conditions on the unique email constraint
            let mut tx = self.pool.begin().await?;

            // Lock the user row to prevent concurrent email changes
            sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;

            // Re-check email availability inside the transaction
            let existing: Option<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL",
            )
            .bind(&new_email)
            .fetch_optional(&mut *tx)
            .await?;
            if existing.is_some() {
                return Err(AppError::conflict("Email already registered"));
            }

            sqlx::query("UPDATE users SET email = $1, email_verified = $2, updated_at = NOW() WHERE id = $3")
                .bind(&new_email)
                .bind(false)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;

            // Revoke all refresh tokens (force re-login with new email)
            sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;

            tx.commit().await?;

            // Audit log (outside transaction, non-critical)
            AuditLogRepository::create(
                &self.pool,
                CreateAuditLog::new(AuditAction::EmailChangeCompleted)
                    .with_actor(user.id, &user.email, &user.role)
                    .with_ip(ip)
                    .with_metadata(
                        serde_json::json!({ "new_email": new_email, "immediate": true }),
                    ),
            )
            .await?;

            Ok((old_email, None))
        }
    }

    /// Confirm email change using verification token
    ///
    /// Returns (old_email, new_email) so caller can send notification.
    pub async fn confirm_email_change(
        &self,
        token: String,
        ip_address: Option<IpAddr>,
    ) -> Result<(String, String), AppError> {
        let ip = ip_address.map(|ip| IpNetwork::from(ip));
        let token_hash = self.jwt.hash_token(&token);

        // Find request (outside transaction for early rejection)
        let request = TokenRepository::find_email_change_request_by_hash(&self.pool, &token_hash)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if !request.is_valid() {
            return Err(AppError::TokenExpired);
        }

        let new_email = request.new_email.clone();

        // Use a transaction with row locking to prevent race conditions
        let mut tx = self.pool.begin().await?;

        // Lock the user row to prevent concurrent email changes
        let user: User =
            sqlx::query_as("SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE")
                .bind(request.user_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(AppError::not_found("User"))?;

        let old_email = user.email.clone();

        // Re-check email availability inside the transaction
        let existing: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL",
        )
        .bind(&new_email)
        .fetch_optional(&mut *tx)
        .await?;
        if existing.is_some() {
            return Err(AppError::conflict("Email already registered"));
        }

        // Update email (set verified since they proved ownership)
        sqlx::query(
            "UPDATE users SET email = $1, email_verified = TRUE, updated_at = NOW() WHERE id = $2",
        )
        .bind(&new_email)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;

        // Confirm the request
        sqlx::query("UPDATE email_change_requests SET confirmed_at = NOW() WHERE id = $1")
            .bind(request.id)
            .execute(&mut *tx)
            .await?;

        // Revoke all refresh tokens (force re-login)
        sqlx::query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL")
            .bind(user.id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        // Audit log (outside transaction, non-critical)
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::EmailChangeCompleted)
                .with_actor(user.id, &old_email, &user.role)
                .with_ip(ip)
                .with_metadata(
                    serde_json::json!({ "old_email": old_email, "new_email": new_email }),
                ),
        )
        .await?;

        Ok((old_email, new_email))
    }

    /// Request email verification
    ///
    /// Generates a token and returns it so the caller can send the verification email.
    /// Requires 2FA to be enabled and email to not already be verified.
    pub async fn request_email_verification(
        &self,
        user_id: Uuid,
        ip_address: Option<IpAddr>,
    ) -> Result<String, AppError> {
        let ip = ip_address.map(|ip| IpNetwork::from(ip));

        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        if user.email_verified {
            return Err(AppError::validation("email", "Email is already verified"));
        }

        if !user.two_factor_enabled {
            return Err(AppError::validation(
                "two_factor",
                "Two-factor authentication must be enabled to verify your email",
            ));
        }

        // Rate limit: 3 requests per hour
        let since = Utc::now() - Duration::hours(1);
        let count =
            TokenRepository::count_recent_email_verification_tokens(&self.pool, user_id, since)
                .await?;
        if count >= 3 {
            return Err(AppError::RateLimited { retry_after: 3600 });
        }

        // Generate token
        let token = generate_secure_token(32);
        let token_hash = self.jwt.hash_token(&token);
        let expires_at = Utc::now() + Duration::hours(1);

        // Store token
        TokenRepository::create_email_verification_token(
            &self.pool,
            CreateEmailVerificationToken {
                user_id,
                token_hash,
                expires_at,
                ip_address: ip,
            },
        )
        .await?;

        // Audit log
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::EmailVerificationRequested)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;

        Ok(token)
    }

    /// Confirm email verification using token.
    ///
    /// Returns `(user_id, email, subscription_tier)`. The tier is assigned atomically using
    /// a transaction-level advisory lock so concurrent verifications cannot race
    /// and land on the same slot count.
    pub async fn confirm_email_verification(
        &self,
        token: String,
        ip_address: Option<IpAddr>,
    ) -> Result<(Uuid, String, SubscriptionTier), AppError> {
        let ip = ip_address.map(|ip| IpNetwork::from(ip));
        let token_hash = self.jwt.hash_token(&token);

        // Find and validate token before opening the transaction
        let verification_token =
            TokenRepository::find_email_verification_token_by_hash(&self.pool, &token_hash)
                .await?
                .ok_or(AppError::InvalidCredentials)?;

        if !verification_token.is_valid() {
            return Err(AppError::TokenExpired);
        }

        let user = UserRepository::find_by_id(&self.pool, verification_token.user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        // Open a transaction to atomically assign the subscription tier.
        // The advisory lock (arbitrary fixed ID) serialises all concurrent
        // verifications so the slot count cannot be read twice for the same slot.
        let mut tx = self.pool.begin().await?;

        // Acquire transaction-level advisory lock (released on COMMIT/ROLLBACK)
        sqlx::query("SELECT pg_advisory_xact_lock(9999999)")
            .execute(&mut *tx)
            .await?;

        // Count how many users have been assigned each tier while holding the lock.
        // This ensures slots are filled based on actual assignments, not total user count.
        let (lifetime_count, early_adopter_count) =
            UserRepository::count_tier_assignments(&mut *tx).await?;

        // Snapshot tier config under the lock so values are consistent
        let tc = self
            .tier_config
            .read()
            .expect("TierConfig lock poisoned")
            .clone();

        let tier = if lifetime_count < tc.lifetime_slots {
            SubscriptionTier::Lifetime
        } else if early_adopter_count < tc.early_adopter_slots {
            SubscriptionTier::EarlyAdopter
        } else {
            SubscriptionTier::Standard
        };

        // Mark token as used
        TokenRepository::mark_email_verification_token_used(&mut *tx, verification_token.id)
            .await?;

        // Set email_verified and assign tier in the same transaction
        sqlx::query("UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1")
            .bind(user.id)
            .execute(&mut *tx)
            .await?;

        UserRepository::assign_subscription_tier(
            &mut *tx,
            user.id,
            &tier,
            tc.early_adopter_trial_days,
            tc.standard_trial_days,
        )
        .await?;

        tx.commit().await?;

        // Audit log (outside transaction — non-critical)
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::EmailVerified)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip)
                .with_metadata(serde_json::json!({ "subscription_tier": tier.as_str() })),
        )
        .await?;

        Ok((user.id, user.email, tier))
    }

    /// Create an admin invite
    pub async fn create_admin_invite(
        &self,
        email: String,
        admin_id: Uuid,
        admin_email: &str,
        admin_role: &str,
        ip_address: Option<IpAddr>,
    ) -> Result<String, AppError> {
        let ip = ip_address.map(IpNetwork::from);

        // Check if user is already an admin
        if let Some(user) = UserRepository::find_by_email(&self.pool, &email).await? {
            if user.role == "admin" {
                return Err(AppError::conflict("User is already an admin"));
            }
        }

        // Revoke any pending invites for this email
        InviteRepository::revoke_pending_by_email(&self.pool, &email).await?;

        // Generate token
        let token = generate_secure_token(32);
        let token_hash = self.jwt.hash_token(&token);
        let expires_at = Utc::now() + Duration::days(7);

        // Store invite
        let invite = InviteRepository::create(
            &self.pool,
            CreateAdminInvite {
                email: email.clone(),
                token_hash,
                invited_by: admin_id,
                role: "admin".to_string(),
                expires_at,
            },
        )
        .await?;

        // Audit log
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::AdminInviteCreated)
                .with_actor(admin_id, admin_email, admin_role)
                .with_ip(ip)
                .with_resource("admin_invite", invite.id)
                .with_metadata(serde_json::json!({ "invited_email": email })),
        )
        .await?;

        Ok(token)
    }

    /// Accept an admin invite
    pub async fn accept_admin_invite(
        &self,
        token: String,
        password: Option<String>,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<AcceptInviteResult, AppError> {
        let ip = ip_address.map(IpNetwork::from);
        let token_hash = self.jwt.hash_token(&token);

        // Find invite
        let invite = InviteRepository::find_valid_by_token_hash(&self.pool, &token_hash)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if !invite.is_valid() {
            return Err(AppError::TokenExpired);
        }

        // Check if user exists
        match UserRepository::find_by_email(&self.pool, &invite.email).await? {
            Some(user) if user.role == "admin" => {
                // Already an admin — stale invite
                return Err(AppError::conflict("User is already an admin"));
            }
            Some(user) => {
                // Existing non-admin user — upgrade to admin
                InviteRepository::mark_accepted(&self.pool, invite.id).await?;
                let updated_user =
                    UserRepository::update_role(&self.pool, user.id, "admin").await?;
                UserRepository::set_email_verified(&self.pool, user.id).await?;

                // Create auth tokens
                let tokens = self
                    .create_tokens(&updated_user, device_info, ip_address)
                    .await?;
                UserRepository::update_last_login(&self.pool, user.id).await?;

                // Audit log
                AuditLogRepository::create(
                    &self.pool,
                    CreateAuditLog::new(AuditAction::AdminInviteAccepted)
                        .with_actor(user.id, &user.email, "admin")
                        .with_ip(ip)
                        .with_resource("admin_invite", invite.id)
                        .with_metadata(serde_json::json!({
                            "existing_user": true,
                            "previous_role": user.role,
                        })),
                )
                .await?;

                let refreshed = UserRepository::find_by_id(&self.pool, updated_user.id)
                    .await?
                    .ok_or(AppError::not_found("User"))?;

                Ok(AcceptInviteResult::Success(
                    tokens,
                    UserResponse::from(refreshed),
                ))
            }
            None => {
                // New user — need password
                let password = match password {
                    Some(p) => p,
                    None => {
                        return Ok(AcceptInviteResult::PasswordRequired {
                            email: invite.email.clone(),
                        });
                    }
                };

                // Validate password
                self.password.validate_strength(&password)?;
                self.password
                    .validate_not_contains_email(&password, &invite.email)?;
                let password_hash = self.password.hash(&password)?;

                // Create user as admin
                let user = UserRepository::create(
                    &self.pool,
                    CreateUser {
                        email: invite.email.clone(),
                        password_hash: Some(password_hash),
                        role: UserRole::Admin,
                    },
                )
                .await?;
                UserRepository::set_email_verified(&self.pool, user.id).await?;

                // Mark invite accepted
                InviteRepository::mark_accepted(&self.pool, invite.id).await?;

                // Create auth tokens
                let tokens = self.create_tokens(&user, device_info, ip_address).await?;
                UserRepository::update_last_login(&self.pool, user.id).await?;

                // Audit log
                AuditLogRepository::create(
                    &self.pool,
                    CreateAuditLog::new(AuditAction::AdminInviteAccepted)
                        .with_actor(user.id, &invite.email, "admin")
                        .with_ip(ip)
                        .with_resource("admin_invite", invite.id)
                        .with_metadata(serde_json::json!({
                            "existing_user": false,
                            "new_user_id": user.id,
                        })),
                )
                .await?;

                let refreshed = UserRepository::find_by_id(&self.pool, user.id)
                    .await?
                    .ok_or(AppError::not_found("User"))?;

                Ok(AcceptInviteResult::Success(
                    tokens,
                    UserResponse::from(refreshed),
                ))
            }
        }
    }

    /// Revoke an admin invite
    pub async fn revoke_admin_invite(
        &self,
        invite_id: Uuid,
        admin_id: Uuid,
        admin_email: &str,
        admin_role: &str,
    ) -> Result<(), AppError> {
        InviteRepository::mark_revoked(&self.pool, invite_id).await?;

        // Audit log
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::AdminInviteRevoked)
                .with_actor(admin_id, admin_email, admin_role)
                .with_resource("admin_invite", invite_id),
        )
        .await?;

        Ok(())
    }

    /// Helper to create auth tokens
    async fn create_tokens(
        &self,
        user: &User,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<AuthTokens, AppError> {
        let access_token = self.jwt.create_access_token(user)?;
        let (refresh_token, token_hash) = self.jwt.create_refresh_token(user.id)?;

        let ip = ip_address.map(|ip| IpNetwork::from(ip));
        let expires_at = Utc::now() + Duration::days(30);

        // Store refresh token
        TokenRepository::create_refresh_token(
            &self.pool,
            CreateRefreshToken {
                user_id: user.id,
                token_hash,
                device_info,
                ip_address: ip,
                expires_at,
            },
        )
        .await?;

        Ok(AuthTokens {
            access_token,
            refresh_token,
            expires_in: 900, // 15 minutes in seconds
        })
    }
}

/// Generate a cryptographically secure random token
pub(crate) fn generate_secure_token(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_secure_token_correct_length() {
        // 32 bytes base64url-encoded = 43 chars (no padding)
        let token = generate_secure_token(32);
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn generate_secure_token_unique() {
        let token1 = generate_secure_token(32);
        let token2 = generate_secure_token(32);
        assert_ne!(token1, token2);
    }

    #[test]
    fn generate_secure_token_url_safe() {
        let token = generate_secure_token(64);
        // URL-safe base64 only contains [A-Za-z0-9_-]
        assert!(token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
    }

    #[test]
    fn generate_secure_token_various_lengths() {
        for len in [1, 8, 16, 32, 64] {
            let token = generate_secure_token(len);
            assert!(!token.is_empty());
            // Decode back to verify it's valid base64
            let decoded =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &token)
                    .unwrap();
            assert_eq!(decoded.len(), len);
        }
    }
}
