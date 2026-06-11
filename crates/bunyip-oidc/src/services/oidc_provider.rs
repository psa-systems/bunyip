//! OIDC Authorization Server / OpenID Provider business logic.
//!
//! Handles:
//! - PKCE validation
//! - Authorization code issuance and consumption
//! - Access token minting (RFC 9068 `at+jwt`, EdDSA)
//! - ID token minting (OIDC Core 1.0)
//! - Refresh token rotation with reuse detection (RFC 6819 §5.2.2.3)
//! - Back-channel logout token minting
//! - Op-session management

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, Header};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::config::OidcConfig;
use crate::errors::AppError;
use crate::models::User;
use crate::services::oidc_keys::OidcKeySet;

// ── Access token claims (RFC 9068) ────────────────────────────────────────────

/// Claims for an RFC 9068 JWT access token (`typ: at+jwt`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub scope: String,
    pub jti: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub auth_time: i64,
    pub acr: String,
    pub amr: Vec<String>,
    /// The user's Bunyip system role (`UserRole::as_str()`: `subscriber` |
    /// `admin`). Identity-level, emitted on every mint regardless of scope.
    /// Resource servers translate this to their own authorization model
    /// (BUNYIP-66); Bunyip exposes only its own role, never a consumer's.
    ///
    /// `#[serde(default)]` so verifying an at+jwt minted by a pre-BUNYIP-66
    /// build (which lacks this claim) does not fail deserialization during a
    /// rolling deploy; mint always populates it, so emission is unaffected.
    #[serde(default)]
    pub bunyip_role: String,
}

impl AtClaims {
    /// Assemble the RFC 9068 access-token claim set. Pure (no signing, keys, or
    /// DB) so the claim mapping - notably `bunyip_role` from the user's role
    /// (BUNYIP-66) - is unit-testable; `mint_access_token` signs the result.
    #[allow(clippy::too_many_arguments)]
    fn build(
        issuer: &str,
        user: &User,
        client: &OAuthClient,
        scope: &[String],
        now: DateTime<Utc>,
        exp: DateTime<Utc>,
        auth_time: DateTime<Utc>,
        acr: &str,
        amr: &[String],
    ) -> Self {
        AtClaims {
            iss: issuer.to_string(),
            sub: user.id.to_string(),
            aud: client.audience.clone(),
            client_id: client.client_id.to_string(),
            scope: scope.join(" "),
            jti: Uuid::new_v4().to_string(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: exp.timestamp(),
            auth_time: auth_time.timestamp(),
            acr: acr.to_string(),
            amr: amr.to_vec(),
            // Identity-level: the user's Bunyip role string straight from the
            // DB column (already constrained to UserRole::as_str() values).
            bunyip_role: user.role.clone(),
        }
    }
}

// ── ID token claims ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    /// audience = client_id
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    pub nonce: String,
    pub azp: String,
    pub at_hash: String,
    // Profile claims (conditional on scopes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    // Membership access — convenience claim for RPs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_member_access: Option<bool>,
    /// The user's Bunyip system role (`subscriber` | `admin`), mirrored from
    /// the access token's `bunyip_role` (BUNYIP-66) so a relying party that
    /// only reads the ID token can display / translate the role without an
    /// extra userinfo call. Emitted on every mint regardless of scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bunyip_role: Option<String>,
}

impl IdTokenClaims {
    /// Assemble the ID-token claim set. Pure (no signing, keys, or DB) so the
    /// claim mapping - notably `bunyip_role` from the user's role - is
    /// unit-testable; `mint_id_token` computes `at_hash`, calls this, and signs.
    /// Profile claims are gated on the `email` scope; `bunyip_role` is not.
    #[allow(clippy::too_many_arguments)]
    fn build(
        issuer: &str,
        user: &User,
        client: &OAuthClient,
        scope: &[String],
        nonce: &str,
        now: DateTime<Utc>,
        exp: DateTime<Utc>,
        auth_time: DateTime<Utc>,
        at_hash: String,
    ) -> Self {
        let include_profile = scope.iter().any(|s| s == "email");
        IdTokenClaims {
            iss: issuer.to_string(),
            sub: user.id.to_string(),
            aud: client.client_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            auth_time: auth_time.timestamp(),
            nonce: nonce.to_string(),
            azp: client.client_id.to_string(),
            at_hash,
            email: include_profile.then(|| user.email.clone()),
            email_verified: include_profile.then_some(user.email_verified),
            membership_status: include_profile.then(|| user.membership_status.clone()),
            has_member_access: include_profile.then(|| user.is_access_allowed()),
            // Identity-level: the user's Bunyip role string straight from the
            // DB column, mirroring the access token's `bunyip_role`.
            bunyip_role: Some(user.role.clone()),
        }
    }
}

// ── Lifecycle event token claims ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleSubject {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleEventPayload {
    pub subject: LifecycleSubject,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTokenClaims {
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub jti: String,
    pub events: std::collections::HashMap<String, LifecycleEventPayload>,
}

// ── Logout token claims ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub jti: String,
    pub events: serde_json::Value,
    pub sub: String,
    pub sid: String,
}

// ── OidcProvider ─────────────────────────────────────────────────────────────

/// The OIDC Authorization Server / OpenID Provider.
///
/// Thread-safe; shared via `Arc<OidcProvider>`.
pub struct OidcProvider {
    pub config: OidcConfig,
    pub keys: Arc<OidcKeySet>,
    pub pool: PgPool,
}

impl OidcProvider {
    pub fn new(config: OidcConfig, keys: Arc<OidcKeySet>, pool: PgPool) -> Self {
        Self { config, keys, pool }
    }

    /// Whether the OIDC feature is enabled.
    pub fn enabled(&self) -> bool {
        self.config.enabled()
    }

    pub fn issuer(&self) -> &str {
        self.config.issuer.as_deref().unwrap_or_default()
    }

    // ── Op-session ────────────────────────────────────────────────────────────

    /// Create a new IdP session for a user (after successful authentication).
    pub async fn create_op_session(
        &self,
        user_id: Uuid,
        user_agent: Option<&str>,
        ip: Option<std::net::IpAddr>,
        acr: &str,
        amr: &[String],
    ) -> Result<OpSession, AppError> {
        let sid = generate_opaque_token(32);
        let now = Utc::now();
        let expires_at = now + Duration::days(7);
        let ip_str: Option<String> = ip.map(|a| a.to_string());

        let row = sqlx::query_as!(
            OpSession,
            r#"
            INSERT INTO op_sessions
                (id, sid, user_id, created_at, last_active_at, expires_at,
                 user_agent, ip, acr, amr)
            VALUES
                (gen_random_uuid(), $1, $2, NOW(), NOW(), $3, $4, $5::inet, $6, $7)
            RETURNING
                id, sid, user_id, created_at, last_active_at, expires_at,
                revoked_at, user_agent,
                ip::TEXT as "ip: String",
                acr, amr
            "#,
            sid,
            user_id,
            expires_at,
            user_agent,
            ip_str as Option<String>,
            acr,
            amr as &[String],
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to create op_session: {e}")))?;

        Ok(row)
    }

    /// Load an active op-session by its opaque sid value.
    pub async fn load_op_session(&self, sid: &str) -> Result<Option<OpSession>, AppError> {
        sqlx::query_as!(
            OpSession,
            r#"
            SELECT id, sid, user_id, created_at, last_active_at, expires_at,
                   revoked_at, user_agent,
                   ip::TEXT as "ip: String",
                   acr, amr
            FROM op_sessions
            WHERE sid = $1
              AND revoked_at IS NULL
              AND expires_at > NOW()
            "#,
            sid
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to load op_session: {e}")))
    }

    // ── OAuth client lookup ───────────────────────────────────────────────────

    /// Load an active OAuth client by its UUID client_id.
    pub async fn load_client(&self, client_id: Uuid) -> Result<Option<OAuthClient>, AppError> {
        sqlx::query_as!(
            OAuthClient,
            r#"
            SELECT
                id, client_id, client_secret_hash, client_type, name,
                redirect_uris, post_logout_redirect_uris,
                backchannel_logout_uri, lifecycle_event_uri,
                allowed_scopes, allowed_grant_types,
                token_endpoint_auth_method, require_pkce,
                access_token_ttl_seconds, refresh_token_ttl_seconds,
                refresh_idle_ttl_seconds, audience,
                dpop_bound, created_at, disabled_at
            FROM oauth_clients
            WHERE client_id = $1 AND disabled_at IS NULL
            "#,
            client_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to load oauth_client: {e}")))
    }

    // ── Authorization code ────────────────────────────────────────────────────

    /// Issue an authorization code.  Returns the raw opaque code (never stored).
    pub async fn issue_authorization_code(
        &self,
        client: &OAuthClient,
        user_id: Uuid,
        op_session_id: Uuid,
        redirect_uri: &str,
        scope: &[String],
        code_challenge: &str,
        nonce: &str,
        auth_time: DateTime<Utc>,
        acr: &str,
        amr: &[String],
    ) -> Result<String, AppError> {
        let raw = generate_opaque_token(32);
        let code_hash = sha256_bytes(raw.as_bytes());
        let expires_at = Utc::now() + Duration::seconds(self.config.code_ttl_secs as i64);

        sqlx::query!(
            r#"
            INSERT INTO oauth_authorization_codes
                (code_hash, client_id, user_id, op_session_id, redirect_uri,
                 scope, code_challenge, code_challenge_method, nonce,
                 auth_time, acr, amr, issued_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'S256', $8, $9, $10, $11, NOW(), $12)
            "#,
            code_hash as Vec<u8>,
            client.client_id,
            user_id,
            op_session_id,
            redirect_uri,
            scope as &[String],
            code_challenge,
            nonce,
            auth_time,
            acr,
            amr as &[String],
            expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to insert authorization code: {e}")))?;

        Ok(raw)
    }

    /// Consume an authorization code after verifying PKCE.
    ///
    /// Returns the code row on success.  Consuming an already-used code revokes
    /// the entire token family (if tokens were already issued from it) and
    /// returns `invalid_grant`.
    pub async fn consume_authorization_code(
        &self,
        raw_code: &str,
        client_id: Uuid,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<AuthCodeRow, AppError> {
        let code_hash = sha256_bytes(raw_code.as_bytes());

        // Load the row — single round-trip, we'll mark consumed after verification.
        let row = sqlx::query_as!(
            AuthCodeRow,
            r#"
            SELECT
                code_hash, client_id, user_id, op_session_id, redirect_uri,
                scope, code_challenge, nonce, auth_time, acr, amr,
                issued_at, expires_at, consumed_at, revoked_at
            FROM oauth_authorization_codes
            WHERE code_hash = $1
            "#,
            code_hash.clone() as Vec<u8>,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("DB error loading auth code: {e}")))?
        .ok_or(AppError::OidcInvalidGrant(
            "unknown authorization code".into(),
        ))?;

        // Already consumed — revoke the family if tokens were issued.
        if row.consumed_at.is_some() || row.revoked_at.is_some() {
            return Err(AppError::OidcInvalidGrant(
                "authorization code already used".into(),
            ));
        }

        // Expiry
        if row.expires_at < Utc::now() {
            return Err(AppError::OidcInvalidGrant(
                "authorization code expired".into(),
            ));
        }

        // client_id binding
        if row.client_id != client_id {
            return Err(AppError::OidcInvalidGrant("client_id mismatch".into()));
        }

        // redirect_uri binding
        if row.redirect_uri != redirect_uri {
            return Err(AppError::OidcInvalidGrant("redirect_uri mismatch".into()));
        }

        // PKCE S256: SHA-256(verifier) == code_challenge
        let challenge_computed = {
            let mut h = Sha256::new();
            h.update(code_verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(h.finalize())
        };
        if challenge_computed != row.code_challenge {
            return Err(AppError::OidcInvalidGrant(
                "PKCE verification failed".into(),
            ));
        }

        // Mark consumed
        sqlx::query!(
            "UPDATE oauth_authorization_codes SET consumed_at = NOW() WHERE code_hash = $1",
            code_hash as Vec<u8>,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to mark code consumed: {e}")))?;

        Ok(row)
    }

    // ── Access token ──────────────────────────────────────────────────────────

    /// Mint a signed RFC 9068 JWT access token.
    pub fn mint_access_token(
        &self,
        user: &User,
        client: &OAuthClient,
        scope: &[String],
        auth_time: DateTime<Utc>,
        acr: &str,
        amr: &[String],
    ) -> Result<(String, DateTime<Utc>), AppError> {
        let now = Utc::now();
        let ttl = Duration::seconds(client.access_token_ttl_seconds as i64);
        let exp = now + ttl;

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.keys.active_kid.clone());
        header.typ = Some("at+jwt".to_string());

        let claims = AtClaims::build(
            self.issuer(),
            user,
            client,
            scope,
            now,
            exp,
            auth_time,
            acr,
            amr,
        );

        let token = jsonwebtoken::encode(&header, &claims, &self.keys.encoding_key)
            .map_err(|e| AppError::internal(format!("Failed to mint access token: {e}")))?;

        Ok((token, exp))
    }

    // ── ID token ──────────────────────────────────────────────────────────────

    /// Mint an OIDC ID token.
    ///
    /// `at_hash` is computed from the bound access token.
    pub fn mint_id_token(
        &self,
        user: &User,
        client: &OAuthClient,
        scope: &[String],
        nonce: &str,
        auth_time: DateTime<Utc>,
        access_token: &str,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(client.access_token_ttl_seconds as i64);

        // at_hash: left half of SHA-256 of ASCII(access_token), base64url-encoded.
        let mut h = Sha256::new();
        h.update(access_token.as_bytes());
        let full_hash = h.finalize();
        let at_hash = URL_SAFE_NO_PAD.encode(&full_hash[..16]);

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.keys.active_kid.clone());
        // typ defaults to "JWT" for ID tokens

        let claims = IdTokenClaims::build(
            self.issuer(),
            user,
            client,
            scope,
            nonce,
            now,
            exp,
            auth_time,
            at_hash,
        );

        jsonwebtoken::encode(&header, &claims, &self.keys.encoding_key)
            .map_err(|e| AppError::internal(format!("Failed to mint ID token: {e}")))
    }

    // ── Refresh token ─────────────────────────────────────────────────────────

    /// Issue the first refresh token in a new family (called after code exchange).
    pub async fn issue_refresh_token(
        &self,
        client: &OAuthClient,
        user_id: Uuid,
        op_session_id: Uuid,
        scope: &[String],
        ip: Option<std::net::IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<(String, Uuid), AppError> {
        // Create the family
        let family_id = sqlx::query_scalar!(
            r#"
            INSERT INTO refresh_token_families (client_id, user_id, op_session_id)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
            client.client_id,
            user_id,
            op_session_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to create refresh token family: {e}")))?;

        let (raw, token_id) = self
            .insert_refresh_token(client, user_id, family_id, None, scope, ip, user_agent)
            .await?;
        Ok((raw, token_id))
    }

    /// Rotate a refresh token — returns the new (raw token, token_id).
    ///
    /// Runs in a SERIALIZABLE transaction.  If the old token has already been
    /// used (replay), the entire family is revoked and `OidcInvalidGrant` is
    /// returned.
    pub async fn rotate_refresh_token(
        &self,
        raw_old: &str,
        client_id: Uuid,
        requested_scope: Option<&[String]>,
        ip: Option<std::net::IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<RotatedTokens, AppError> {
        let old_hash = sha256_bytes(raw_old.as_bytes());

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::internal(format!("Failed to begin transaction: {e}")))?;

        // Set SERIALIZABLE isolation to prevent concurrent rotation races.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(format!("Failed to set isolation level: {e}")))?;

        // Load the old token with a row-level lock.
        let old = sqlx::query!(
            r#"
            SELECT id, family_id, client_id, user_id, scope, used_at, revoked_at,
                   idle_expires_at, absolute_expires_at
            FROM refresh_tokens_v2
            WHERE token_hash = $1
            FOR UPDATE
            "#,
            old_hash as Vec<u8>,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::internal(format!("DB error loading refresh token: {e}")))?
        .ok_or(AppError::OidcInvalidGrant("unknown refresh token".into()))?;

        // Replay detection: already used → revoke whole family.
        if old.used_at.is_some() || old.revoked_at.is_some() {
            sqlx::query!(
                "UPDATE refresh_token_families SET revoked_at = NOW(), revoke_reason = 'reuse_detected' WHERE id = $1",
                old.family_id,
            )
            .execute(&mut *tx)
            .await
            .ok(); // best-effort; don't mask the primary error
            tx.commit().await.ok();

            // BUNYIP-88: emit a Critical audit-log row for the replay so
            // the security event is queryable through /admin/audit-logs
            // instead of only living in stdout. Best-effort: if the
            // insert fails we still return the InvalidGrant to the
            // caller; a tracing::warn! gives ops a single line to
            // correlate against.
            // Set actor_id directly so /admin/audit-logs?actor_id=... can
            // surface the affected user; do not look up the email + role
            // (an extra DB hit in a security-event hot path), the metadata
            // already carries enough triage context.
            let mut audit = crate::models::CreateAuditLog::new(
                crate::models::AuditAction::AuthRefreshReuseDetected,
            )
            .with_resource("refresh_token_family", old.family_id)
            .with_metadata(serde_json::json!({
                "client_id": old.client_id,
                "jti_used_at": old.used_at,
                "jti_revoked_at": old.revoked_at,
            }))
            .with_severity(crate::models::AuditSeverity::Critical);
            audit.actor_id = Some(old.user_id);
            if let Err(e) = crate::repositories::AuditLogRepository::create(&self.pool, audit).await
            {
                tracing::warn!(
                    error = %e,
                    family_id = %old.family_id,
                    user_id = %old.user_id,
                    "Failed to write auth_refresh_reuse_detected audit log; security event was still enforced",
                );
            }
            return Err(AppError::OidcInvalidGrant(
                "refresh token already used — possible replay attack".into(),
            ));
        }

        // client_id binding
        if old.client_id != client_id {
            return Err(AppError::OidcInvalidGrant("client_id mismatch".into()));
        }

        // Expiry checks
        let now = Utc::now();
        let idle_exp: DateTime<Utc> = old.idle_expires_at;
        let abs_exp: DateTime<Utc> = old.absolute_expires_at;
        if now > idle_exp || now > abs_exp {
            return Err(AppError::OidcInvalidGrant("refresh token expired".into()));
        }

        // Family must not be revoked
        let family_revoked: Option<bool> = sqlx::query_scalar!(
            "SELECT revoked_at IS NOT NULL FROM refresh_token_families WHERE id = $1",
            old.family_id,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::internal(format!("DB error checking family: {e}")))?
        .flatten();

        if family_revoked.unwrap_or(true) {
            return Err(AppError::OidcInvalidGrant("token family revoked".into()));
        }

        // Scope narrowing only
        let effective_scope: Vec<String> = match requested_scope {
            Some(req) if !req.is_empty() => {
                let orig: std::collections::HashSet<&str> =
                    old.scope.iter().map(|s| s.as_str()).collect();
                req.iter()
                    .filter(|s| orig.contains(s.as_str()))
                    .cloned()
                    .collect()
            }
            _ => old.scope.clone(),
        };

        // Mark old token used
        sqlx::query!(
            "UPDATE refresh_tokens_v2 SET used_at = NOW() WHERE id = $1",
            old.id,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::internal(format!("Failed to mark refresh token used: {e}")))?;

        // Load client for TTL values
        let client = sqlx::query_as!(
            OAuthClient,
            r#"
            SELECT id, client_id, client_secret_hash, client_type, name,
                   redirect_uris, post_logout_redirect_uris,
                   backchannel_logout_uri, lifecycle_event_uri,
                   allowed_scopes, allowed_grant_types,
                   token_endpoint_auth_method, require_pkce,
                   access_token_ttl_seconds, refresh_token_ttl_seconds,
                   refresh_idle_ttl_seconds, audience,
                   dpop_bound, created_at, disabled_at
            FROM oauth_clients
            WHERE client_id = $1 AND disabled_at IS NULL
            "#,
            old.client_id,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::internal(format!("Failed to load client during rotation: {e}")))?
        .ok_or(AppError::OidcInvalidGrant(
            "client not found or disabled".into(),
        ))?;

        // Issue new refresh token
        let raw_new = generate_opaque_token(32);
        let new_hash = sha256_bytes(raw_new.as_bytes());
        let ip_str: Option<String> = ip.map(|a| a.to_string());
        let idle_ttl = Duration::seconds(client.refresh_idle_ttl_seconds as i64);
        let abs_ttl = Duration::seconds(client.refresh_token_ttl_seconds as i64);
        let new_idle_exp = now + idle_ttl;
        let new_abs_exp = now + abs_ttl;

        let new_token_id = sqlx::query_scalar!(
            r#"
            INSERT INTO refresh_tokens_v2
                (token_hash, family_id, parent_id, client_id, user_id, scope,
                 issued_at, idle_expires_at, absolute_expires_at, ip, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8, $9::inet, $10)
            RETURNING id
            "#,
            new_hash as Vec<u8>,
            old.family_id,
            old.id,
            old.client_id,
            old.user_id,
            &effective_scope as &[String],
            new_idle_exp,
            new_abs_exp,
            ip_str as Option<String>,
            user_agent,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::internal(format!("Failed to insert new refresh token: {e}")))?;

        tx.commit().await.map_err(|e| {
            AppError::internal(format!("Failed to commit rotation transaction: {e}"))
        })?;

        Ok(RotatedTokens {
            raw_refresh: raw_new,
            token_id: new_token_id,
            user_id: old.user_id,
            scope: effective_scope,
            client,
        })
    }

    // ── Logout token ──────────────────────────────────────────────────────────

    /// Mint an OIDC Back-Channel Logout token for a specific (user, session, client).
    pub fn mint_logout_token(
        &self,
        user_id: Uuid,
        sid: &str,
        client_id: Uuid,
    ) -> Result<String, AppError> {
        let now = Utc::now();

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.keys.active_kid.clone());
        header.typ = Some("logout+jwt".to_string());

        let claims = LogoutTokenClaims {
            iss: self.issuer().to_string(),
            aud: client_id.to_string(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            events: serde_json::json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
            sub: user_id.to_string(),
            sid: sid.to_string(),
        };

        jsonwebtoken::encode(&header, &claims, &self.keys.encoding_key)
            .map_err(|e| AppError::internal(format!("Failed to mint logout token: {e}")))
    }

    // ── Back-channel logout ───────────────────────────────────────────────────

    /// Revoke all active op-sessions for a user, cascade-revoke their refresh
    /// token families, and return `(client_id, backchannel_logout_uri, sid)`
    /// for every client that registered a back-channel logout URI.
    ///
    /// Call this before redirecting the user away from the logout endpoint so
    /// the caller can fire-and-forget the POST notifications.
    pub async fn revoke_sessions_for_backchannel(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, String, String)>, AppError> {
        // Collect clients that need notification before revoking.
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT
                oc.client_id,
                oc.backchannel_logout_uri AS "backchannel_logout_uri!",
                ops.sid
            FROM op_sessions ops
            JOIN refresh_token_families rtf
                ON rtf.op_session_id = ops.id AND rtf.revoked_at IS NULL
            JOIN oauth_clients oc
                ON oc.client_id = rtf.client_id
            WHERE ops.user_id = $1
              AND ops.revoked_at IS NULL
              AND oc.backchannel_logout_uri IS NOT NULL
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            AppError::internal(format!("Failed to query sessions for backchannel: {e}"))
        })?;

        // Revoke all active op-sessions (refresh families cascade via FK).
        sqlx::query!(
            "UPDATE op_sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
            user_id,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to revoke op_sessions: {e}")))?;

        sqlx::query!(
            r#"
            UPDATE refresh_token_families
               SET revoked_at = NOW(), revoke_reason = 'logout'
             WHERE user_id = $1 AND revoked_at IS NULL
            "#,
            user_id,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to revoke refresh families: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|r| (r.client_id, r.backchannel_logout_uri, r.sid))
            .collect())
    }

    // ── Lifecycle events ──────────────────────────────────────────────────────

    /// Mint a signed lifecycle-event JWT for a specific (user, event_type, client).
    pub fn mint_lifecycle_token(
        &self,
        user_id: Uuid,
        event_type: &str,
        client_id: Uuid,
    ) -> Result<String, AppError> {
        let now = Utc::now();

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.keys.active_kid.clone());
        header.typ = Some("lifecycle-event+jwt".to_string());

        let mut events = std::collections::HashMap::new();
        events.insert(
            self.config.lifecycle_event_key.clone(),
            LifecycleEventPayload {
                subject: LifecycleSubject {
                    id: user_id.to_string(),
                },
                event_type: event_type.to_string(),
                reason: None,
            },
        );

        let claims = LifecycleTokenClaims {
            iss: self.issuer().to_string(),
            aud: client_id.to_string(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            events,
        };

        jsonwebtoken::encode(&header, &claims, &self.keys.encoding_key)
            .map_err(|e| AppError::internal(format!("Failed to mint lifecycle token: {e}")))
    }

    /// Query all clients with a `lifecycle_event_uri` and return
    /// `(client_id, lifecycle_event_uri)` pairs.
    pub async fn lifecycle_event_targets(&self) -> Result<Vec<(Uuid, String)>, AppError> {
        let rows = sqlx::query!(
            r#"
            SELECT client_id, lifecycle_event_uri AS "lifecycle_event_uri!"
            FROM oauth_clients
            WHERE lifecycle_event_uri IS NOT NULL AND disabled_at IS NULL
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to query lifecycle event targets: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|r| (r.client_id, r.lifecycle_event_uri))
            .collect())
    }

    // ── Entitlement check ─────────────────────────────────────────────────────

    /// Returns true if the user has an active entitlement to the given client.
    pub async fn has_entitlement(&self, user_id: Uuid, client_id: Uuid) -> Result<bool, AppError> {
        let row = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) FROM user_application_access
            WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL
            "#,
            user_id,
            client_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to check entitlement: {e}")))?;

        Ok(row.unwrap_or(0) > 0)
    }

    /// Grant entitlement for a user to a client (used during JIT provisioning or admin grant).
    pub async fn grant_entitlement(
        &self,
        user_id: Uuid,
        client_id: Uuid,
        scopes: &[String],
    ) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            INSERT INTO user_application_access
                (user_id, client_id, granted_scopes, granted_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (user_id, client_id)
            DO UPDATE SET granted_scopes = EXCLUDED.granted_scopes, revoked_at = NULL
            "#,
            user_id,
            client_id,
            scopes as &[String],
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to grant entitlement: {e}")))?;

        Ok(())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    async fn insert_refresh_token(
        &self,
        client: &OAuthClient,
        user_id: Uuid,
        family_id: Uuid,
        parent_id: Option<Uuid>,
        scope: &[String],
        ip: Option<std::net::IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<(String, Uuid), AppError> {
        let raw = generate_opaque_token(32);
        let token_hash = sha256_bytes(raw.as_bytes());
        let now = Utc::now();
        let idle_exp = now + Duration::seconds(client.refresh_idle_ttl_seconds as i64);
        let abs_exp = now + Duration::seconds(client.refresh_token_ttl_seconds as i64);
        let ip_str: Option<String> = ip.map(|a| a.to_string());

        let token_id = sqlx::query_scalar!(
            r#"
            INSERT INTO refresh_tokens_v2
                (token_hash, family_id, parent_id, client_id, user_id, scope,
                 issued_at, idle_expires_at, absolute_expires_at, ip, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8, $9::inet, $10)
            RETURNING id
            "#,
            token_hash as Vec<u8>,
            family_id,
            parent_id,
            client.client_id,
            user_id,
            scope as &[String],
            idle_exp,
            abs_exp,
            ip_str as Option<String>,
            user_agent,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to insert refresh token: {e}")))?;

        Ok((raw, token_id))
    }
}

// ── Supporting structs ────────────────────────────────────────────────────────

/// Loaded OAuth client row.
#[derive(Debug, Clone)]
pub struct OAuthClient {
    pub id: Uuid,
    pub client_id: Uuid,
    pub client_secret_hash: Option<String>,
    pub client_type: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub backchannel_logout_uri: Option<String>,
    pub lifecycle_event_uri: Option<String>,
    pub allowed_scopes: Vec<String>,
    pub allowed_grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub require_pkce: bool,
    pub access_token_ttl_seconds: i32,
    pub refresh_token_ttl_seconds: i32,
    pub refresh_idle_ttl_seconds: i32,
    pub audience: String,
    pub dpop_bound: bool,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
}

/// Active IdP session row.
pub struct OpSession {
    pub id: Uuid,
    pub sid: String,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
}

/// Authorization code row (consumed view).
pub struct AuthCodeRow {
    pub code_hash: Vec<u8>,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub op_session_id: Uuid,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub code_challenge: String,
    pub nonce: String,
    pub auth_time: DateTime<Utc>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Result of a successful refresh token rotation.
pub struct RotatedTokens {
    pub raw_refresh: String,
    pub token_id: Uuid,
    pub user_id: Uuid,
    pub scope: Vec<String>,
    pub client: OAuthClient,
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

/// Generate a cryptographically random opaque token, base64url-encoded.
pub fn generate_opaque_token(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// SHA-256 of bytes → raw bytes (stored in DB as BYTEA).
fn sha256_bytes(input: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().to_vec()
}

// ── at+jwt verification (BUNYIP-55) ──────────────────────────────────────────

impl OidcProvider {
    /// Verify an `at+jwt` access token's signature, type, issuer, and
    /// expiry, then return its full RFC 9068 claim set.
    ///
    /// Used by:
    /// - The OIDC userinfo handler (resolves `sub` -> user lookup).
    /// - The [`AtJwtVerifier`] impl below (resolves `sub` -> user
    ///   lookup -> [`AccessTokenClaims`] for the actix extractors).
    ///
    /// Rejects:
    /// - JWT header `typ` != `"at+jwt"` (RFC 9068 §2.1).
    /// - Missing or unknown `kid` (no matching public key in the JWKS).
    /// - Wrong `iss` (must match this OP's issuer).
    /// - Expired `exp` (30s leeway, same as the existing userinfo
    ///   verifier the legacy `verify_at_jwt_get_sub` helper used).
    ///
    /// Does not check `aud` — the access token is bunyip-scoped (an
    /// inbound RP token is meant to authenticate to bunyip's own API),
    /// so any client_id under this issuer is acceptable. Per-handler
    /// authorization stays the handler's job.
    pub fn verify_at_jwt_claims(&self, token: &str) -> Result<AtClaims, AppError> {
        use jsonwebtoken::{Algorithm, Validation};

        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| AppError::OidcInvalidToken("malformed JWT header".into()))?;

        if header.typ.as_deref() != Some("at+jwt") {
            return Err(AppError::OidcInvalidToken("JWT typ must be at+jwt".into()));
        }

        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| AppError::OidcInvalidToken("JWT header missing kid".into()))?;

        let decoding_key = self
            .keys
            .decoding_key(kid)
            .ok_or_else(|| AppError::OidcInvalidToken(format!("unknown kid: {kid}")))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer()]);
        validation.validate_exp = true;
        validation.leeway = 30;
        // RFC 9068 does not require an `aud` check on inbound bunyip-API
        // calls; we rely on the issuer + signature + expiry guarantees.
        validation.validate_aud = false;

        let data =
            jsonwebtoken::decode::<AtClaims>(token, decoding_key, &validation).map_err(|e| {
                AppError::OidcInvalidToken(format!("access token verification failed: {e}"))
            })?;

        Ok(data.claims)
    }
}

#[async_trait::async_trait]
impl bunyip_domain::middleware::auth::AtJwtVerifier for OidcProvider {
    async fn verify_and_resolve(
        &self,
        token: &str,
    ) -> Result<bunyip_domain::services::AccessTokenClaims, AppError> {
        let claims = self.verify_at_jwt_claims(token)?;
        let user = bunyip_domain::middleware::auth::resolve_user_for_atjwt(&self.pool, &claims.sub)
            .await?;
        Ok(
            bunyip_domain::services::AccessTokenClaims::from_atjwt_and_user(
                &claims.iss,
                claims.iat,
                claims.exp,
                &claims.jti,
                &user,
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user(role: &str) -> User {
        User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            email_verified: true,
            password_hash: Some("hash".to_string()),
            role: role.to_string(),
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

    fn test_client() -> OAuthClient {
        OAuthClient {
            id: Uuid::new_v4(),
            client_id: Uuid::new_v4(),
            client_secret_hash: None,
            client_type: "public".to_string(),
            name: "test-client".to_string(),
            redirect_uris: vec!["https://app.example.com/callback".to_string()],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            lifecycle_event_uri: None,
            allowed_scopes: vec!["openid".to_string()],
            allowed_grant_types: vec!["authorization_code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: true,
            access_token_ttl_seconds: 600,
            refresh_token_ttl_seconds: 2_592_000,
            refresh_idle_ttl_seconds: 1_209_600,
            audience: "https://api.example.com".to_string(),
            dpop_bound: false,
            created_at: Utc::now(),
            disabled_at: None,
        }
    }

    fn build_claims_for(role: &str) -> AtClaims {
        let now = Utc::now();
        AtClaims::build(
            "https://issuer.example.com",
            &test_user(role),
            &test_client(),
            &["openid".to_string()],
            now,
            now + Duration::seconds(600),
            now,
            "urn:mace:incommon:iap:silver",
            &["pwd".to_string()],
        )
    }

    // BUNYIP-66: the at+jwt carries the user's Bunyip system role verbatim,
    // on every mint, regardless of requested scope.
    #[test]
    fn at_claims_carry_admin_bunyip_role() {
        assert_eq!(build_claims_for("admin").bunyip_role, "admin");
    }

    #[test]
    fn at_claims_carry_subscriber_bunyip_role() {
        assert_eq!(build_claims_for("subscriber").bunyip_role, "subscriber");
    }

    #[test]
    fn bunyip_role_emitted_without_any_scope() {
        let now = Utc::now();
        let claims = AtClaims::build(
            "https://issuer.example.com",
            &test_user("admin"),
            &test_client(),
            &[],
            now,
            now + Duration::seconds(600),
            now,
            "urn:mace:incommon:iap:silver",
            &[],
        );
        assert!(claims.scope.is_empty());
        assert_eq!(claims.bunyip_role, "admin");
    }

    // The claim must serialize under the literal key `bunyip_role` so the
    // mokosh RS parses it (PMS-172).
    #[test]
    fn bunyip_role_serializes_under_expected_key() {
        let json = serde_json::to_value(build_claims_for("admin")).unwrap();
        assert_eq!(json["bunyip_role"], "admin");
    }

    // Backward compatibility: an at+jwt minted by a pre-BUNYIP-66 build has no
    // `bunyip_role` claim; verifying it must still deserialize (default "")
    // rather than fail, so a rolling deploy does not 401 in-flight tokens.
    #[test]
    fn at_claims_deserialize_without_bunyip_role() {
        let legacy = serde_json::json!({
            "iss": "https://issuer.example.com",
            "sub": Uuid::new_v4().to_string(),
            "aud": "https://api.example.com",
            "client_id": Uuid::new_v4().to_string(),
            "scope": "openid",
            "jti": Uuid::new_v4().to_string(),
            "iat": 0, "nbf": 0, "exp": 0, "auth_time": 0,
            "acr": "urn:mace:incommon:iap:silver",
            "amr": ["pwd"],
        });
        let claims: AtClaims = serde_json::from_value(legacy).unwrap();
        assert_eq!(claims.bunyip_role, "");
    }

    fn build_id_claims_for(role: &str, scope: &[String]) -> IdTokenClaims {
        let now = Utc::now();
        IdTokenClaims::build(
            "https://issuer.example.com",
            &test_user(role),
            &test_client(),
            scope,
            "nonce-123",
            now,
            now + Duration::seconds(600),
            now,
            "at_hash_value".to_string(),
        )
    }

    // The ID token mirrors the access token's `bunyip_role`, on every mint,
    // regardless of scope, so an RP reading only the ID token sees the role.
    #[test]
    fn id_token_carries_bunyip_role() {
        assert_eq!(
            build_id_claims_for("admin", &["openid".to_string()]).bunyip_role,
            Some("admin".to_string())
        );
    }

    #[test]
    fn id_token_bunyip_role_emitted_without_email_scope() {
        let claims = build_id_claims_for("subscriber", &["openid".to_string()]);
        // No `email` scope: profile claims are absent, but the role is not.
        assert!(claims.email.is_none());
        assert_eq!(claims.bunyip_role, Some("subscriber".to_string()));
    }

    #[test]
    fn id_token_bunyip_role_serializes_under_expected_key() {
        let json = serde_json::to_value(build_id_claims_for("admin", &[])).unwrap();
        assert_eq!(json["bunyip_role"], "admin");
    }

    // Backward compatibility: an ID token without the claim still deserializes
    // (to `None`) rather than failing.
    #[test]
    fn id_token_deserializes_without_bunyip_role() {
        let legacy = serde_json::json!({
            "iss": "https://issuer.example.com",
            "sub": Uuid::new_v4().to_string(),
            "aud": Uuid::new_v4().to_string(),
            "exp": 0, "iat": 0, "auth_time": 0,
            "nonce": "n", "azp": Uuid::new_v4().to_string(),
            "at_hash": "h",
        });
        let claims: IdTokenClaims = serde_json::from_value(legacy).unwrap();
        assert_eq!(claims.bunyip_role, None);
    }
}
