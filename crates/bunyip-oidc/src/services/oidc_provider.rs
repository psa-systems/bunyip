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
use std::collections::BTreeMap;
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
    /// BUNYIP-63: per-client extension claims. Today this carries the
    /// tenant claim emitted under the name configured on
    /// `oauth_clients.tenant_claim_name` (e.g. `mokosh_tenant_id`).
    /// `#[serde(flatten)]` lifts each entry to a top-level claim in
    /// the JWT JSON; `skip_serializing_if = "BTreeMap::is_empty"` keeps
    /// the wire shape byte-identical to pre-BUNYIP-63 for any client
    /// whose tenant_claim_name is NULL. Verifiers consume the well-
    /// known fields via the named struct fields and ignore extras
    /// they do not recognise.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl AtClaims {
    /// Assemble the RFC 9068 access-token claim set. Pure (no signing, keys, or
    /// DB) so the claim mapping - notably `bunyip_role` from the user's role
    /// (BUNYIP-66) and the per-client tenant claim (BUNYIP-63) - is
    /// unit-testable; `mint_access_token` signs the result.
    ///
    /// `selected_tenant_id` is the tenant the user picked at /authorize
    /// (BUNYIP-62); `client.tenant_claim_name` is the per-client name
    /// (e.g. `mokosh_tenant_id`) under which it lands in `extra`.
    /// Both must be Some for the claim to appear; either being None
    /// leaves `extra` empty and the wire shape byte-identical to a
    /// legacy single-tenant client.
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
        selected_tenant_id: Option<Uuid>,
    ) -> Self {
        let mut extra = BTreeMap::new();
        if let (Some(name), Some(tid)) = (client.tenant_claim_name.as_deref(), selected_tenant_id) {
            extra.insert(name.to_string(), serde_json::Value::String(tid.to_string()));
        }
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
            extra,
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
    /// BUNYIP-63: per-client extension claims (e.g. `mokosh_tenant_id`).
    /// Mirrored from the access token so an SPA reading only the id_token
    /// can display "you're in tenant X" without an extra `at+jwt`
    /// introspection. `#[serde(flatten)]` + `skip_serializing_if` keeps
    /// the wire shape byte-identical for clients with no tenant claim.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl IdTokenClaims {
    /// Assemble the ID-token claim set. Pure (no signing, keys, or DB) so the
    /// claim mapping - notably `bunyip_role` from the user's role and the
    /// per-client tenant claim (BUNYIP-63) - is unit-testable; `mint_id_token`
    /// computes `at_hash`, calls this, and signs. `email` / `email_verified`
    /// / `membership_status` / `has_member_access` ride the `email` scope;
    /// BUNYIP-140 adds `given_name` / `family_name` on the `profile` scope
    /// and `phone_number` on the `phone` scope (NULL columns omit the key
    /// rather than emitting empty strings). `bunyip_role` and the tenant
    /// claim are unconditional.
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
        selected_tenant_id: Option<Uuid>,
    ) -> Self {
        let include_profile = scope.iter().any(|s| s == "email");
        let mut extra = BTreeMap::new();
        if let (Some(name), Some(tid)) = (client.tenant_claim_name.as_deref(), selected_tenant_id) {
            extra.insert(name.to_string(), serde_json::Value::String(tid.to_string()));
        }
        // BUNYIP-140 standard profile / phone claims. Each gates on (a) the
        // scope being in the at+jwt's scope set and (b) the source column
        // being non-NULL + non-empty. NULL columns serialize as absent
        // claims (no empty strings).
        if scope.iter().any(|s| s == "profile") {
            if let Some(v) = user.first_name.as_deref().filter(|s| !s.is_empty()) {
                extra.insert("given_name".into(), serde_json::Value::String(v.into()));
            }
            if let Some(v) = user.last_name.as_deref().filter(|s| !s.is_empty()) {
                extra.insert("family_name".into(), serde_json::Value::String(v.into()));
            }
        }
        if scope.iter().any(|s| s == "phone") {
            if let Some(v) = user.phone.as_deref().filter(|s| !s.is_empty()) {
                extra.insert("phone_number".into(), serde_json::Value::String(v.into()));
            }
        }
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
            extra,
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

    /// Load an active OAuth client by its UUID client_id. Runtime
    /// `query_as` so this query does not need a `.sqlx/` cache
    /// regeneration every time the `oauth_clients` table gains a new
    /// column (BUNYIP-61 added `tenant_claim_name` here; further
    /// columns land the same way).
    pub async fn load_client(&self, client_id: Uuid) -> Result<Option<OAuthClient>, AppError> {
        sqlx::query_as::<_, OAuthClient>(
            r#"
            SELECT
                id, client_id, client_secret_hash, client_type, name,
                redirect_uris, post_logout_redirect_uris,
                backchannel_logout_uri, lifecycle_event_uri,
                allowed_scopes,
                access_token_ttl_seconds, refresh_token_ttl_seconds,
                refresh_idle_ttl_seconds, audience,
                created_at, disabled_at,
                tenant_claim_name
            FROM oauth_clients
            WHERE client_id = $1 AND disabled_at IS NULL
            "#,
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to load oauth_client: {e}")))
    }

    // ── Authorization code ────────────────────────────────────────────────────

    /// Issue an authorization code. Returns the raw opaque code (never stored).
    /// `selected_tenant_id` is BUNYIP-62: when the client has a non-null
    /// `tenant_claim_name`, this is the tenant the user chose (auto-selected
    /// for one-assignment users, picker-chosen for multi). NULL otherwise.
    /// /token reads it in BUNYIP-63 to emit the tenant claim.
    #[allow(clippy::too_many_arguments)]
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
        selected_tenant_id: Option<Uuid>,
    ) -> Result<String, AppError> {
        let raw = generate_opaque_token(32);
        let code_hash = sha256_bytes(raw.as_bytes());
        let expires_at = Utc::now() + Duration::seconds(self.config.code_ttl_secs as i64);

        // Runtime query so we do not have to regenerate the `.sqlx/`
        // cache when the auth-code shape grows (selected_tenant_id is
        // the first such growth; future per-RP fields land the same
        // way).
        sqlx::query(
            r#"
            INSERT INTO oauth_authorization_codes
                (code_hash, client_id, user_id, op_session_id, redirect_uri,
                 scope, code_challenge, code_challenge_method, nonce,
                 auth_time, acr, amr, issued_at, expires_at, selected_tenant_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'S256', $8, $9, $10, $11, NOW(), $12, $13)
            "#,
        )
        .bind(code_hash)
        .bind(client.client_id)
        .bind(user_id)
        .bind(op_session_id)
        .bind(redirect_uri)
        .bind(scope)
        .bind(code_challenge)
        .bind(nonce)
        .bind(auth_time)
        .bind(acr)
        .bind(amr)
        .bind(expires_at)
        .bind(selected_tenant_id)
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

        // BUNYIP-199: redemption must be atomic so two concurrent token
        // requests bearing the same code cannot both succeed (double-spend /
        // code-replay race). Load the row under a row-level lock inside a
        // SERIALIZABLE transaction, verify, then mark consumed and commit,
        // exactly as `rotate_refresh_token` does. The `FOR UPDATE` lock plus
        // SERIALIZABLE isolation serialise concurrent redemptions of the same
        // code: the loser blocks on the lock, then sees `consumed_at` set and
        // loses the race.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::internal(format!("Failed to begin transaction: {e}")))?;

        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::internal(format!("Failed to set isolation level: {e}")))?;

        // Load the row with a row-level lock. Runtime query so the BUNYIP-62
        // `selected_tenant_id` column does not force a `.sqlx/` cache regen here.
        let row = sqlx::query_as::<_, AuthCodeRow>(
            r#"
            SELECT
                code_hash, client_id, user_id, op_session_id, redirect_uri,
                scope, code_challenge, nonce, auth_time, acr, amr,
                issued_at, expires_at, consumed_at, revoked_at,
                selected_tenant_id
            FROM oauth_authorization_codes
            WHERE code_hash = $1
            FOR UPDATE
            "#,
        )
        .bind(code_hash.clone())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::internal(format!("DB error loading auth code: {e}")))?
        .ok_or(AppError::OidcInvalidGrant(
            "unknown authorization code".into(),
        ))?;

        // Already consumed — the lost race. Revoke the token family if tokens
        // were already issued from this code, mirroring the refresh-token
        // reuse-detection behaviour, then return invalid_grant.
        if row.consumed_at.is_some() || row.revoked_at.is_some() {
            // Best-effort family revocation: any refresh-token family minted
            // from a session whose auth code is now being replayed is revoked.
            sqlx::query(
                r#"
                UPDATE refresh_token_families
                SET revoked_at = NOW(), revoke_reason = 'reuse_detected'
                WHERE op_session_id = $1 AND revoked_at IS NULL
                "#,
            )
            .bind(row.op_session_id)
            .execute(&mut *tx)
            .await
            .ok(); // best-effort; don't mask the primary invalid_grant
            tx.commit().await.ok();
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

        // PKCE S256: SHA-256(verifier) == code_challenge. BUNYIP-263:
        // constant-time compare so a timing oracle cannot leak the stored
        // code_challenge byte-by-byte to an attacker who can submit many
        // forged code_verifiers. Both sides are same-length base64url so
        // ct_eq() is well-defined.
        let challenge_computed = {
            let mut h = Sha256::new();
            h.update(code_verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(h.finalize())
        };
        let challenge_match: bool = subtle::ConstantTimeEq::ct_eq(
            challenge_computed.as_bytes(),
            row.code_challenge.as_bytes(),
        )
        .into();
        if !challenge_match {
            return Err(AppError::OidcInvalidGrant(
                "PKCE verification failed".into(),
            ));
        }

        // Mark consumed under the held lock. Guard on `consumed_at IS NULL` as
        // defence-in-depth: if a concurrent transaction slipped through, the
        // zero-rows-affected result is treated as a lost race. Runtime query to
        // keep the BUNYIP-62 column addition off the `.sqlx/` regen path.
        let consumed = sqlx::query(
            "UPDATE oauth_authorization_codes SET consumed_at = NOW() WHERE code_hash = $1 AND consumed_at IS NULL",
        )
        .bind(code_hash)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::internal(format!("Failed to mark code consumed: {e}")))?;

        if consumed.rows_affected() == 0 {
            return Err(AppError::OidcInvalidGrant(
                "authorization code already used".into(),
            ));
        }

        tx.commit()
            .await
            .map_err(|e| AppError::internal(format!("Failed to commit code redemption: {e}")))?;

        Ok(row)
    }

    // ── Access token ──────────────────────────────────────────────────────────

    /// Mint a signed RFC 9068 JWT access token. `selected_tenant_id` is
    /// the tenant the user picked at /authorize (BUNYIP-62), carried
    /// forward on the auth-code row and through refresh-token
    /// rotation. When both this AND `client.tenant_claim_name` are
    /// Some, the at+jwt carries the tenant under that claim name
    /// (BUNYIP-63). Either being None leaves the claim off and the
    /// wire shape unchanged from pre-BUNYIP-63.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_access_token(
        &self,
        user: &User,
        client: &OAuthClient,
        scope: &[String],
        auth_time: DateTime<Utc>,
        acr: &str,
        amr: &[String],
        selected_tenant_id: Option<Uuid>,
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
            selected_tenant_id,
        );

        let token = jsonwebtoken::encode(&header, &claims, &self.keys.encoding_key)
            .map_err(|e| AppError::internal(format!("Failed to mint access token: {e}")))?;

        Ok((token, exp))
    }

    // ── ID token ──────────────────────────────────────────────────────────────

    /// Mint an OIDC ID token.
    ///
    /// `at_hash` is computed from the bound access token.
    /// `selected_tenant_id` is mirrored from the matching at+jwt so an
    /// SPA reading only the id_token can display tenant context
    /// without an extra round-trip (BUNYIP-63).
    #[allow(clippy::too_many_arguments)]
    pub fn mint_id_token(
        &self,
        user: &User,
        client: &OAuthClient,
        scope: &[String],
        nonce: &str,
        auth_time: DateTime<Utc>,
        access_token: &str,
        selected_tenant_id: Option<Uuid>,
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
            selected_tenant_id,
        );

        jsonwebtoken::encode(&header, &claims, &self.keys.encoding_key)
            .map_err(|e| AppError::internal(format!("Failed to mint ID token: {e}")))
    }

    // ── Refresh token ─────────────────────────────────────────────────────────

    /// Issue the first refresh token in a new family (called after code exchange).
    /// BUNYIP-63: `selected_tenant_id` is carried on every row in the family
    /// so the rotated at+jwt always emits the original tenant claim.
    ///
    /// BUNYIP-257: `acr` and `amr` are persisted on the family row so
    /// every rotation carries the ORIGINAL login's authentication
    /// method-reference set forward instead of the hardcoded `pwd`
    /// default. Without this the rotated at+jwt lies about MFA / OTP
    /// to RPs that gate step-up auth on `amr`.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_refresh_token(
        &self,
        client: &OAuthClient,
        user_id: Uuid,
        op_session_id: Uuid,
        scope: &[String],
        acr: &str,
        amr: &[String],
        ip: Option<std::net::IpAddr>,
        user_agent: Option<&str>,
        selected_tenant_id: Option<Uuid>,
    ) -> Result<(String, Uuid), AppError> {
        // Create the family. Runtime query so the BUNYIP-257 `acr` /
        // `amr` column additions do not force a `.sqlx/` offline-cache
        // regeneration.
        let family_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO refresh_token_families (client_id, user_id, op_session_id, acr, amr)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(client.client_id)
        .bind(user_id)
        .bind(op_session_id)
        .bind(acr)
        .bind(amr)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to create refresh token family: {e}")))?;

        let (raw, token_id) = self
            .insert_refresh_token(
                client,
                user_id,
                family_id,
                None,
                scope,
                ip,
                user_agent,
                selected_tenant_id,
            )
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

        // Load the old token with a row-level lock. Runtime query so
        // the BUNYIP-63 `selected_tenant_id` column addition does not
        // force a `.sqlx/` cache regen. `RefreshTokenRow` is an ad-hoc
        // struct local to this rotation; mapped via FromRow below.
        // BUNYIP-257: JOIN the family to read the persisted `acr` / `amr`.
        let old = sqlx::query_as::<_, RefreshTokenRotationRow>(
            r#"
            SELECT rt.id, rt.family_id, rt.client_id, rt.user_id, rt.scope,
                   rt.used_at, rt.revoked_at, rt.idle_expires_at,
                   rt.absolute_expires_at, rt.selected_tenant_id,
                   fam.acr, fam.amr
            FROM refresh_tokens_v2 rt
            JOIN refresh_token_families fam ON fam.id = rt.family_id
            WHERE rt.token_hash = $1
            FOR UPDATE OF rt
            "#,
        )
        .bind(old_hash)
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

        // Load client for TTL values. Reuse `load_client()` instead of
        // duplicating the column list: the client config is read-only here and
        // not part of the rotation's atomicity (it reads outside the tx on the
        // pool), so a single source of truth for the SELECT is preferable.
        let client = self
            .load_client(old.client_id)
            .await?
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
        // Cap the absolute expiry at the family's original deadline: rotation
        // refreshes the idle window but must never push the absolute TTL out, or
        // a token refreshed before each idle expiry would live forever. Take the
        // earlier of the inherited deadline and a fresh `now + abs_ttl` (the
        // latter only matters if the client's configured TTL shrank).
        let new_abs_exp = old.absolute_expires_at.min(now + abs_ttl);

        // Runtime query: the BUNYIP-63 `selected_tenant_id` column is
        // mirrored from `old` so every row in the family carries the
        // tenant the user picked at /authorize, and the next /token
        // rotation mints an at+jwt with the same tenant claim.
        let new_token_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO refresh_tokens_v2
                (token_hash, family_id, parent_id, client_id, user_id, scope,
                 issued_at, idle_expires_at, absolute_expires_at, ip, user_agent,
                 selected_tenant_id)
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8, $9::inet, $10, $11)
            RETURNING id
            "#,
        )
        .bind(new_hash)
        .bind(old.family_id)
        .bind(old.id)
        .bind(old.client_id)
        .bind(old.user_id)
        .bind(&effective_scope)
        .bind(new_idle_exp)
        .bind(new_abs_exp)
        .bind(ip_str)
        .bind(user_agent)
        .bind(old.selected_tenant_id)
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
            selected_tenant_id: old.selected_tenant_id,
            acr: old.acr,
            amr: old.amr,
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

    /// BUNYIP-140: load the granted_scopes set for an (user, client) pair.
    /// Returns an empty Vec if no row exists yet OR the row is revoked. The
    /// authorize handler computes `requested - granted` and renders the
    /// consent screen when that delta is non-empty.
    ///
    /// Runtime-only query (not `query_scalar!`) so this method does not need
    /// a `.sqlx/` offline-cache regen.
    pub async fn get_granted_scopes(
        &self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> Result<Vec<String>, AppError> {
        let row: Option<Vec<String>> = sqlx::query_scalar(
            r#"
            SELECT granted_scopes FROM user_application_access
            WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to read granted scopes: {e}")))?;

        Ok(row.unwrap_or_default())
    }

    /// BUNYIP-140: persist the consent grant. If the row exists, the new
    /// scopes are unioned into the existing `granted_scopes` set; if not,
    /// a new row is inserted with the supplied scopes. Idempotent for any
    /// (user, client) pair.
    ///
    /// Runtime-only query (not `query!`) so this method does not need a
    /// `.sqlx/` offline-cache regen.
    pub async fn add_scopes_to_grant(
        &self,
        user_id: Uuid,
        client_id: Uuid,
        new_scopes: &[String],
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO user_application_access
                (user_id, client_id, granted_scopes, granted_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (user_id, client_id)
            DO UPDATE SET
                granted_scopes = ARRAY(
                    SELECT DISTINCT unnest(
                        user_application_access.granted_scopes || EXCLUDED.granted_scopes
                    )
                ),
                revoked_at = NULL
            "#,
        )
        .bind(user_id)
        .bind(client_id)
        .bind(new_scopes)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to persist consent: {e}")))?;

        Ok(())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    async fn insert_refresh_token(
        &self,
        client: &OAuthClient,
        user_id: Uuid,
        family_id: Uuid,
        parent_id: Option<Uuid>,
        scope: &[String],
        ip: Option<std::net::IpAddr>,
        user_agent: Option<&str>,
        selected_tenant_id: Option<Uuid>,
    ) -> Result<(String, Uuid), AppError> {
        let raw = generate_opaque_token(32);
        let token_hash = sha256_bytes(raw.as_bytes());
        let now = Utc::now();
        let idle_exp = now + Duration::seconds(client.refresh_idle_ttl_seconds as i64);
        let abs_exp = now + Duration::seconds(client.refresh_token_ttl_seconds as i64);
        let ip_str: Option<String> = ip.map(|a| a.to_string());

        // Runtime query (BUNYIP-63 added selected_tenant_id; keep this
        // off the workspace `.sqlx/` regen path).
        let token_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO refresh_tokens_v2
                (token_hash, family_id, parent_id, client_id, user_id, scope,
                 issued_at, idle_expires_at, absolute_expires_at, ip, user_agent,
                 selected_tenant_id)
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8, $9::inet, $10, $11)
            RETURNING id
            "#,
        )
        .bind(token_hash)
        .bind(family_id)
        .bind(parent_id)
        .bind(client.client_id)
        .bind(user_id)
        .bind(scope)
        .bind(idle_exp)
        .bind(abs_exp)
        .bind(ip_str)
        .bind(user_agent)
        .bind(selected_tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::internal(format!("Failed to insert refresh token: {e}")))?;

        Ok((raw, token_id))
    }
}

// ── Supporting structs ────────────────────────────────────────────────────────

/// Loaded OAuth client row. The `sqlx::FromRow` derive lets
/// `load_client` issue a runtime `query_as` against the `oauth_clients`
/// table without re-registering this struct in the workspace's
/// compile-time `.sqlx/` cache every time a column lands. The single
/// callsite is `load_client`.
#[derive(Debug, Clone, sqlx::FromRow)]
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
    pub access_token_ttl_seconds: i32,
    pub refresh_token_ttl_seconds: i32,
    pub refresh_idle_ttl_seconds: i32,
    pub audience: String,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    /// BUNYIP-61: when non-null, /authorize gates on
    /// `oauth_client_user_tenants` for this client and /token emits
    /// the selected tenant_id on the at+jwt and id_token under this
    /// claim name. NULL = legacy single-tenant behaviour: no claim, no
    /// gate, no picker. Per-client so multi-RP OPs can keep claim
    /// namespaces from colliding (mokosh_tenant_id vs. letschat_tenant_id).
    pub tenant_claim_name: Option<String>,
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

/// Authorization code row (consumed view). `sqlx::FromRow` so
/// `consume_authorization_code` can pull every column with a runtime
/// query without re-registering the struct in the workspace `.sqlx/`
/// cache every time the table grows (BUNYIP-62 added
/// `selected_tenant_id`; future per-RP fields land the same way).
#[derive(sqlx::FromRow)]
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
    /// BUNYIP-62: the tenant the user picked at /authorize (or
    /// auto-selected for single-assignment users). NULL for clients
    /// whose `oauth_clients.tenant_claim_name` is NULL. /token reads
    /// this in BUNYIP-63 to emit the tenant claim on at+jwt + id_token.
    pub selected_tenant_id: Option<Uuid>,
}

/// Result of a successful refresh token rotation.
pub struct RotatedTokens {
    pub raw_refresh: String,
    pub token_id: Uuid,
    pub user_id: Uuid,
    pub scope: Vec<String>,
    pub client: OAuthClient,
    /// BUNYIP-63: the tenant the user picked at the original
    /// `/authorize`, carried forward on every refresh-token rotation.
    /// `handle_refresh_grant` feeds this into the next at+jwt mint so
    /// the rotated token emits the same tenant claim.
    pub selected_tenant_id: Option<Uuid>,
    /// BUNYIP-257: original-login acr + amr, persisted on the family
    /// row and carried forward on every rotation so the rotated at+jwt
    /// reports the truthful auth-method-reference set per OIDC Core
    /// §3.1.3.7 instead of the hardcoded `pwd` default.
    pub acr: String,
    pub amr: Vec<String>,
}

/// Ad-hoc row used by the rotation transaction. Only fields the
/// rotation reads are mapped; columns the rest of the system uses
/// (`token_hash`, `parent_id`, `cnf_jkt`, `issued_at`, `ip`,
/// `user_agent`) are intentionally absent so a future column
/// addition does not force a struct change here.
#[derive(sqlx::FromRow)]
struct RefreshTokenRotationRow {
    id: Uuid,
    family_id: Uuid,
    client_id: Uuid,
    user_id: Uuid,
    scope: Vec<String>,
    used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    idle_expires_at: DateTime<Utc>,
    absolute_expires_at: DateTime<Utc>,
    selected_tenant_id: Option<Uuid>,
    /// BUNYIP-257: persisted on `refresh_token_families` at the initial
    /// token issue. Joined into this row so the rotation carries the
    /// original login's acr/amr forward to the next at+jwt mint.
    acr: String,
    amr: Vec<String>,
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

/// Generate a cryptographically random opaque token, base64url-encoded.
pub fn generate_opaque_token(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// SHA-256 of bytes → raw bytes (stored in DB as BYTEA).
pub(crate) fn sha256_bytes(input: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().to_vec()
}

// ── at+jwt verification (BUNYIP-55) ──────────────────────────────────────────

impl OidcProvider {
    /// BUNYIP-252: Resource-Server flavour of [`verify_at_jwt_claims`] that
    /// pins `aud` to the bunyip-API audience (`OidcConfig::rs_audience`).
    ///
    /// The plain `verify_at_jwt_claims` deliberately leaves `aud` unchecked
    /// because the OIDC userinfo endpoint MUST accept any at+jwt this OP
    /// issued (per OIDC Core §5.3). Every OTHER bunyip-API surface (the
    /// `/v1/*` family wired through the `AtJwtVerifier` trait) is a
    /// Resource Server and per RFC 9068 §4 MUST refuse a token whose `aud`
    /// does not name it. This method enforces that bind: an at+jwt minted
    /// for mokosh / drillmark / lets-chat / any future RP is rejected with
    /// `OidcInvalidToken` when presented as a Bearer credential to
    /// bunyip-API's own resources.
    fn verify_at_jwt_for_rs(&self, token: &str) -> Result<AtClaims, AppError> {
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
        validation.set_audience(&[self.config.rs_audience.as_str()]);
        validation.validate_exp = true;
        validation.leeway = 30;

        let data =
            jsonwebtoken::decode::<AtClaims>(token, decoding_key, &validation).map_err(|e| {
                AppError::OidcInvalidToken(format!("access token verification failed: {e}"))
            })?;

        Ok(data.claims)
    }

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
        // BUNYIP-263: defense in depth - if an at+jwt arrives with a
        // future `nbf` (clock-skew replay, mint-side bug), refuse to
        // honour it before its intended start time. The 30s leeway
        // already absorbs normal clock drift; anything beyond that is
        // a real signal worth blocking.
        validation.validate_nbf = true;
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

impl OidcProvider {
    /// BUNYIP-260: verify a self-issued id_token used as a logout hint
    /// (per OIDC RP-Initiated Logout 1.0 §3) and return the `client_id`
    /// the token was issued to. Unlike at+jwt verification, `exp` is NOT
    /// enforced because RPs commonly pass an EXPIRED id_token as the
    /// hint - they only kept it locally to identify themselves at
    /// logout, not to authenticate. Signature + issuer + the existence
    /// of a `kid` from the OP's JWKS are required; that combination is
    /// enough to identify the client unambiguously.
    pub async fn verify_id_token_client(&self, id_token_hint: &str) -> Result<Uuid, AppError> {
        use jsonwebtoken::{Algorithm, Validation};

        let header = jsonwebtoken::decode_header(id_token_hint)
            .map_err(|_| AppError::OidcInvalidToken("malformed id_token header".into()))?;

        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| AppError::OidcInvalidToken("id_token missing kid".into()))?;

        let decoding_key = self
            .keys
            .decoding_key(kid)
            .ok_or_else(|| AppError::OidcInvalidToken(format!("unknown kid: {kid}")))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer()]);
        validation.validate_exp = false; // hint may be expired (spec)
        validation.validate_aud = false; // we read aud ourselves
        validation.leeway = 30;

        let data = jsonwebtoken::decode::<IdTokenClaims>(id_token_hint, decoding_key, &validation)
            .map_err(|e| {
                AppError::OidcInvalidToken(format!("id_token_hint verification failed: {e}"))
            })?;

        Uuid::parse_str(&data.claims.aud)
            .map_err(|_| AppError::OidcInvalidToken("id_token aud is not a client_id".into()))
    }
}

#[async_trait::async_trait]
impl bunyip_domain::middleware::auth::AtJwtVerifier for OidcProvider {
    async fn verify_and_resolve(
        &self,
        token: &str,
    ) -> Result<bunyip_domain::services::AccessTokenClaims, AppError> {
        // BUNYIP-252: enforce aud == OidcConfig::rs_audience on the RS path.
        // The userinfo endpoint keeps the permissive `verify_at_jwt_claims`
        // because the OIDC spec REQUIRES it to accept any at+jwt this OP
        // issued; the bunyip-API `/v1/*` family is a Resource Server and
        // must refuse cross-RP tokens.
        let claims = self.verify_at_jwt_for_rs(token)?;
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
            first_name: None,
            last_name: None,
            phone: None,
            has_used_trial: false,
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
            access_token_ttl_seconds: 600,
            refresh_token_ttl_seconds: 2_592_000,
            refresh_idle_ttl_seconds: 1_209_600,
            audience: "https://api.example.com".to_string(),
            created_at: Utc::now(),
            disabled_at: None,
            tenant_claim_name: None,
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
            None,
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
            None,
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
            None,
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
