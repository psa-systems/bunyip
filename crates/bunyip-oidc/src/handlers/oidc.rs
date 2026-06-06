//! OIDC / OAuth 2.0 Authorization Server handlers.
//!
//! Implements:
//!   GET  /.well-known/openid-configuration   — OIDC Discovery
//!   GET  /.well-known/jwks.json              — JWKS
//!   GET  /oauth2/authorize                   — Authorization endpoint
//!   POST /oauth2/token                       — Token endpoint
//!   GET  /oauth2/userinfo                    — Userinfo endpoint
//!   POST /oauth2/revoke                      — Revocation endpoint (RFC 7009)
//!   GET  /oauth2/logout                      — RP-Initiated Logout

use actix_web::{web, HttpRequest, HttpResponse};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio;
use uuid::Uuid;

use crate::errors::AppError;
use crate::middleware::auth::OptionalUser;
use crate::repositories::UserRepository;
use crate::services::oidc_provider::{OAuthClient, OidcProvider};

/// Unwrap `Option<Arc<OidcProvider>>` from `web::Data`, returning 404 when absent.
/// Yields `&OidcProvider`.
macro_rules! require_provider {
    ($opt:expr) => {
        match $opt.as_ref().as_ref() {
            // p: &Arc<OidcProvider>; &**p: &OidcProvider
            Some(p) => &**p,
            None => return Ok(HttpResponse::NotFound().finish()),
        }
    };
    // variant for handlers that return HttpResponse directly (not Result)
    ($opt:expr, plain) => {
        match $opt.as_ref().as_ref() {
            Some(p) => &**p,
            None => return HttpResponse::NotFound().finish(),
        }
    };
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn oidc_error(error: &str, description: &str) -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({
        "error": error,
        "error_description": description,
    }))
}

#[allow(dead_code)]
fn oidc_unauthorized(error: &str, description: &str) -> HttpResponse {
    HttpResponse::Unauthorized().json(serde_json::json!({
        "error": error,
        "error_description": description,
    }))
}

// ── Discovery ─────────────────────────────────────────────────────────────────

/// GET /.well-known/openid-configuration
pub async fn discovery(provider: web::Data<Option<Arc<OidcProvider>>>) -> HttpResponse {
    let provider = require_provider!(provider, plain);
    let issuer = match provider.config.issuer.as_deref() {
        Some(i) if !i.is_empty() => i.to_string(),
        _ => return HttpResponse::NotFound().finish(),
    };

    let doc = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "userinfo_endpoint": format!("{issuer}/oauth2/userinfo"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "revocation_endpoint": format!("{issuer}/oauth2/revoke"),
        "end_session_endpoint": format!("{issuer}/oauth2/logout"),
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic", "private_key_jwt", "none"
        ],
        "scopes_supported": [
            "openid", "email", "offline_access",
            "dmarc:read", "dmarc:write"
        ],
        "claims_supported": [
            "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "azp",
            "email", "email_verified", "membership_status", "has_member_access"
        ],
        "code_challenge_methods_supported": ["S256"],
        "require_pkce": true,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
    });

    HttpResponse::Ok()
        .content_type("application/json")
        .append_header(("Cache-Control", "public, max-age=300"))
        .json(doc)
}

// ── JWKS ──────────────────────────────────────────────────────────────────────

/// GET /.well-known/jwks.json
pub async fn jwks(provider: web::Data<Option<Arc<OidcProvider>>>) -> HttpResponse {
    let provider = require_provider!(provider, plain);

    HttpResponse::Ok()
        .content_type("application/json")
        .append_header(("Cache-Control", "public, max-age=300"))
        .json(&provider.keys.jwks)
}

// ── Authorization endpoint ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[serde(default)]
    pub prompt: Option<String>,
}

/// GET /oauth2/authorize
///
/// If no SaaS session exists, redirects to the SaaS login page with the full
/// authorize URL as `?redirect=` so the user is sent back after authenticating.
/// On success, redirects to the client's redirect_uri with code and state.
pub async fn authorize(
    req: HttpRequest,
    provider: web::Data<Option<Arc<OidcProvider>>>,
    _pool: web::Data<sqlx::PgPool>,
    query: web::Query<AuthorizeQuery>,
    config: web::Data<crate::config::Config>,
) -> Result<HttpResponse, AppError> {
    let provider = require_provider!(provider);

    // Authentication is gated on a server-validated OP session, NOT on the
    // stateless hub access_token. logout revokes the op_sessions row, so a
    // surviving/replayed access_token cookie can no longer mint a code.
    let op_session = match req.cookie(crate::middleware::auth::AuthCookies::OP_SESSION_COOKIE) {
        Some(c) => provider.load_op_session(c.value()).await?,
        None => None,
    };
    let session = match op_session {
        Some(s) => s,
        None => {
            let authorize_url = format!("{}{}", provider.issuer(), req.uri());
            tracing::info!(
                has_op_session = req
                    .cookie(crate::middleware::auth::AuthCookies::OP_SESSION_COOKIE)
                    .is_some(),
                has_access_token = req.cookie("access_token").is_some(),
                "authorize: no active OP session, redirecting to login",
            );
            // Use web_origin (single absolute URL of bunyip-web) rather than
            // cors_origin (which is now a comma-list once multiple RPs are
            // registered; concatenating that onto `/login` produces garbage).
            let login_url = format!(
                "{}/login?redirect={}&checked=1",
                config.web_origin.trim_end_matches('/'),
                urlencoding::encode(&authorize_url),
            );
            return Ok(HttpResponse::Found()
                .insert_header(("Location", login_url))
                .finish());
        }
    };

    let q = &query.0;

    // Basic parameter validation
    if q.response_type != "code" {
        return Ok(oidc_error(
            "unsupported_response_type",
            "only response_type=code is supported",
        ));
    }
    if q.code_challenge_method != "S256" {
        return Ok(oidc_error(
            "invalid_request",
            "code_challenge_method must be S256",
        ));
    }
    if q.code_challenge.is_empty() {
        return Ok(oidc_error("invalid_request", "code_challenge is required"));
    }
    if q.state.is_empty() {
        return Ok(oidc_error("invalid_request", "state is required"));
    }
    if q.nonce.is_empty() {
        return Ok(oidc_error("invalid_request", "nonce is required"));
    }
    if !q.scope.split_whitespace().any(|s| s == "openid") {
        return Ok(oidc_error("invalid_scope", "scope must include openid"));
    }

    // Parse client_id
    let client_id = Uuid::parse_str(&q.client_id)
        .map_err(|_| AppError::bad_request("invalid client_id UUID"))?;

    // Load client
    let client = provider
        .load_client(client_id)
        .await?
        .ok_or_else(|| AppError::bad_request("unknown client_id"))?;

    // Validate redirect_uri (exact match)
    if !client.redirect_uris.iter().any(|u| {
        // For loopback clients, match scheme+host ignoring port
        if u == "http://127.0.0.1" || u == "http://localhost" {
            q.redirect_uri.starts_with("http://127.0.0.1:")
                || q.redirect_uri.starts_with("http://localhost:")
                || q.redirect_uri == *u
        } else {
            *u == q.redirect_uri
        }
    }) {
        return Ok(oidc_error("invalid_request", "redirect_uri not registered"));
    }

    // Validate scopes
    let requested_scopes: Vec<String> = q
        .scope
        .split_whitespace()
        .filter(|s| client.allowed_scopes.iter().any(|a| a.as_str() == *s))
        .map(|s| s.to_string())
        .collect();

    // Auto-grant entitlement on first login (JIT provisioning)
    if !provider.has_entitlement(session.user_id, client_id).await? {
        provider
            .grant_entitlement(session.user_id, client_id, &client.allowed_scopes)
            .await?;
    }

    // Reuse the existing OP session established at login; auth_time/acr/amr come
    // from that session rather than being re-minted per authorize request.
    let acr = session.acr.as_deref().unwrap_or("urn:bunyip:loa:pwd");
    let amr = session
        .amr
        .clone()
        .unwrap_or_else(|| vec!["pwd".to_string()]);

    // Issue authorization code
    let code = provider
        .issue_authorization_code(
            &client,
            session.user_id,
            session.id,
            &q.redirect_uri,
            &requested_scopes,
            &q.code_challenge,
            &q.nonce,
            session.created_at,
            acr,
            &amr,
        )
        .await?;

    let redirect = format!(
        "{}?code={}&state={}",
        q.redirect_uri,
        urlencoding::encode(&code),
        urlencoding::encode(&q.state),
    );

    Ok(HttpResponse::Found()
        .append_header(("Location", redirect))
        .finish())
}

// ── Token endpoint ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    // authorization_code fields
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    // refresh_token fields
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    // client auth (also comes via Basic auth header)
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

/// POST /oauth2/token
pub async fn token(
    req: HttpRequest,
    provider: web::Data<Option<Arc<OidcProvider>>>,
    pool: web::Data<sqlx::PgPool>,
    form: web::Form<TokenRequest>,
) -> Result<HttpResponse, AppError> {
    let provider = require_provider!(provider);

    let body = &form.0;

    // Extract client credentials (Basic auth header or form params)
    let (client_id_str, client_secret_opt) = extract_client_credentials(&req, body)?;
    let client_id = Uuid::parse_str(&client_id_str)
        .map_err(|_| AppError::OidcInvalidClient("invalid client_id format".into()))?;

    let client = provider
        .load_client(client_id)
        .await?
        .ok_or_else(|| AppError::OidcInvalidClient("unknown client".into()))?;

    // Authenticate the client
    authenticate_client(&client, client_secret_opt.as_deref())?;

    let ip = extract_ip(&req);
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match body.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(
                provider,
                &pool,
                &req,
                body,
                &client,
                ip,
                user_agent.as_deref(),
            )
            .await
        }
        "refresh_token" => {
            handle_refresh_grant(
                provider,
                &pool,
                &req,
                body,
                &client,
                ip,
                user_agent.as_deref(),
            )
            .await
        }
        other => Ok(oidc_error(
            "unsupported_grant_type",
            &format!("unsupported grant_type: {other}"),
        )),
    }
}

async fn handle_authorization_code_grant(
    provider: &OidcProvider,
    pool: &sqlx::PgPool,
    _req: &HttpRequest,
    body: &TokenRequest,
    client: &OAuthClient,
    ip: Option<std::net::IpAddr>,
    user_agent: Option<&str>,
) -> Result<HttpResponse, AppError> {
    let code = body.code.as_deref().ok_or_else(|| {
        AppError::OidcInvalidRequest("code is required for authorization_code grant".into())
    })?;
    let redirect_uri = body
        .redirect_uri
        .as_deref()
        .ok_or_else(|| AppError::OidcInvalidRequest("redirect_uri is required".into()))?;
    let code_verifier = body
        .code_verifier
        .as_deref()
        .ok_or_else(|| AppError::OidcInvalidRequest("code_verifier is required (PKCE)".into()))?;

    let code_row = provider
        .consume_authorization_code(code, client.client_id, redirect_uri, code_verifier)
        .await?;

    // Load user
    let user = UserRepository::find_by_id(pool, code_row.user_id)
        .await?
        .ok_or_else(|| AppError::OidcInvalidGrant("user not found".into()))?;

    // Re-check entitlement
    if !provider.has_entitlement(user.id, client.client_id).await? {
        return Ok(oidc_error(
            "access_denied",
            "user not entitled to this client",
        ));
    }

    // Mint tokens
    let (access_token, at_exp) = provider.mint_access_token(
        &user,
        client,
        &code_row.scope,
        code_row.auth_time,
        code_row.acr.as_deref().unwrap_or("urn:bunyip:loa:pwd"),
        &code_row.amr.unwrap_or_default(),
    )?;

    let id_token = provider.mint_id_token(
        &user,
        client,
        &code_row.scope,
        &code_row.nonce,
        code_row.auth_time,
        &access_token,
    )?;

    let (raw_refresh, _) = provider
        .issue_refresh_token(
            client,
            user.id,
            code_row.op_session_id,
            &code_row.scope,
            ip,
            user_agent,
        )
        .await?;

    let expires_in = (at_exp - chrono::Utc::now()).num_seconds();

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token: Some(raw_refresh),
        scope: code_row.scope.join(" "),
        id_token: Some(id_token),
    }))
}

async fn handle_refresh_grant(
    provider: &OidcProvider,
    pool: &sqlx::PgPool,
    _req: &HttpRequest,
    body: &TokenRequest,
    client: &OAuthClient,
    ip: Option<std::net::IpAddr>,
    user_agent: Option<&str>,
) -> Result<HttpResponse, AppError> {
    let raw_refresh = body
        .refresh_token
        .as_deref()
        .ok_or_else(|| AppError::OidcInvalidRequest("refresh_token is required".into()))?;

    let requested_scope: Option<Vec<String>> = body
        .scope
        .as_ref()
        .map(|s| s.split_whitespace().map(String::from).collect());

    let rotated = provider
        .rotate_refresh_token(
            raw_refresh,
            client.client_id,
            requested_scope.as_deref(),
            ip,
            user_agent,
        )
        .await?;

    // Load user
    let user = UserRepository::find_by_id(pool, rotated.user_id)
        .await?
        .ok_or_else(|| AppError::OidcInvalidGrant("user not found".into()))?;

    // Re-check entitlement at every rotation
    if !provider.has_entitlement(user.id, client.client_id).await? {
        return Ok(oidc_error(
            "access_denied",
            "user not entitled to this client",
        ));
    }

    let (access_token, at_exp) = provider.mint_access_token(
        &user,
        &rotated.client,
        &rotated.scope,
        chrono::Utc::now(), // auth_time not re-established on refresh
        "urn:bunyip:loa:pwd",
        &["pwd".to_string()],
    )?;

    let expires_in = (at_exp - chrono::Utc::now()).num_seconds();

    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token: Some(rotated.raw_refresh),
        scope: rotated.scope.join(" "),
        id_token: None, // not re-issued on refresh
    }))
}

// ── Userinfo endpoint ─────────────────────────────────────────────────────────

/// GET /oauth2/userinfo
///
/// Accepts an `Authorization: Bearer <at+jwt>` token.
/// Returns the standard OIDC userinfo claims for the subject.
pub async fn userinfo(
    req: HttpRequest,
    provider: web::Data<Option<Arc<OidcProvider>>>,
    pool: web::Data<sqlx::PgPool>,
) -> Result<HttpResponse, AppError> {
    let provider = require_provider!(provider);

    let token_str = extract_bearer_token(&req)
        .ok_or_else(|| AppError::OidcInvalidToken("missing Bearer token".into()))?;

    let at_claims = provider.verify_at_jwt_claims(&token_str)?;
    let user_id = Uuid::parse_str(&at_claims.sub)
        .map_err(|_| AppError::OidcInvalidToken("invalid sub in access token".into()))?;

    let user = UserRepository::find_by_id(&pool, user_id)
        .await?
        .ok_or_else(|| AppError::OidcInvalidToken("user not found".into()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "sub": user.id.to_string(),
        "email": user.email,
        "email_verified": user.email_verified,
        "membership_status": user.membership_status,
        "has_member_access": crate::services::jwt::AccessTokenClaims::has_member_access_static(
            &user.role,
            user.lifetime_member,
            user.trial_ends_at.map(|t| t.timestamp()),
            &user.membership_status,
        ),
    })))
}

// ── Revocation endpoint ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

/// POST /oauth2/revoke (RFC 7009)
///
/// Revokes a refresh token (and its entire family) or adds a JTI to the
/// access-token blocklist.  Returns 200 regardless of whether the token
/// was found (per spec).
pub async fn revoke(
    _req: HttpRequest,
    provider: web::Data<Option<Arc<OidcProvider>>>,
    form: web::Form<RevokeRequest>,
) -> Result<HttpResponse, AppError> {
    let provider = require_provider!(provider);

    // RFC 7009 §2.2: respond 200 regardless
    let _ = do_revoke(provider, &form.token).await;
    Ok(HttpResponse::Ok().finish())
}

async fn do_revoke(provider: &OidcProvider, raw_token: &str) -> Result<(), AppError> {
    use sha2::{Digest, Sha256};

    let token_hash = {
        let mut h = Sha256::new();
        h.update(raw_token.as_bytes());
        h.finalize().to_vec()
    };

    // Try refresh token first
    let result = sqlx::query_scalar!(
        "SELECT family_id FROM refresh_tokens_v2 WHERE token_hash = $1",
        token_hash as Vec<u8>,
    )
    .fetch_optional(&provider.pool)
    .await;

    if let Ok(Some(family_id)) = result {
        sqlx::query!(
            "UPDATE refresh_token_families SET revoked_at = NOW(), revoke_reason = 'client_revocation' WHERE id = $1",
            family_id,
        )
        .execute(&provider.pool)
        .await?;
    }

    Ok(())
}

// ── RP-Initiated Logout ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LogoutQuery {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// GET /oauth2/logout
pub async fn logout(
    provider: web::Data<Option<Arc<OidcProvider>>>,
    query: web::Query<LogoutQuery>,
    user: OptionalUser,
    config: web::Data<crate::config::Config>,
) -> Result<HttpResponse, AppError> {
    // Clone the Arc so we can move it into the background task.
    let provider_arc: Arc<OidcProvider> = match provider.as_ref().as_ref() {
        Some(p) => Arc::clone(p),
        None => return Ok(HttpResponse::NotFound().finish()),
    };

    let redirect = match &query.post_logout_redirect_uri {
        Some(uri) if !uri.is_empty() => uri.clone(),
        _ => "/".to_string(),
    };

    if let Some(claims) = user.0 {
        let user_id = claims.sub; // already Uuid
        match provider_arc.revoke_sessions_for_backchannel(user_id).await {
            Ok(targets) if !targets.is_empty() => {
                let provider_arc = Arc::clone(&provider_arc);
                tokio::spawn(async move {
                    let http = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(5))
                        .build()
                        .unwrap_or_default();
                    for (client_id, uri, sid) in targets {
                        match provider_arc.mint_logout_token(user_id, &sid, client_id) {
                            Ok(token) => {
                                if let Err(e) = http
                                    .post(&uri)
                                    .form(&[("logout_token", &token)])
                                    .send()
                                    .await
                                {
                                    tracing::warn!(
                                        %uri, %client_id, error = %e,
                                        "Backchannel logout delivery failed"
                                    );
                                } else {
                                    tracing::info!(
                                        %uri, %client_id,
                                        "Backchannel logout delivered"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    %client_id, error = %e,
                                    "Failed to mint logout token"
                                );
                            }
                        }
                    }
                });
            }
            Ok(_) => {} // no clients with backchannel URIs
            Err(e) => {
                tracing::warn!(error = %e, "Failed to revoke sessions for backchannel logout");
            }
        }
    }

    let secure = config.is_production();
    let cookie_domain = config.cookie_domain.as_deref();
    let mut response = HttpResponse::Found();
    response.append_header(("Location", redirect));
    for cookie in crate::middleware::auth::AuthCookies::clear(secure, cookie_domain) {
        response.cookie(cookie);
    }
    Ok(response.finish())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Extract (client_id, client_secret) from either HTTP Basic auth or form body.
fn extract_client_credentials(
    req: &HttpRequest,
    body: &TokenRequest,
) -> Result<(String, Option<String>), AppError> {
    // Try HTTP Basic auth first
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                    if let Ok(cred_str) = String::from_utf8(decoded) {
                        if let Some((id, secret)) = cred_str.split_once(':') {
                            return Ok((
                                urlencoding::decode(id).unwrap_or_default().into_owned(),
                                Some(urlencoding::decode(secret).unwrap_or_default().into_owned()),
                            ));
                        }
                    }
                }
            }
        }
    }

    // Fall back to form body
    let client_id = body
        .client_id
        .as_deref()
        .ok_or_else(|| AppError::OidcInvalidClient("client_id is required".into()))?
        .to_string();
    Ok((client_id, body.client_secret.clone()))
}

/// Verify the client secret (for confidential clients).
fn authenticate_client(
    client: &OAuthClient,
    provided_secret: Option<&str>,
) -> Result<(), AppError> {
    if client.client_type == "public" {
        // Public clients have no secret.
        return Ok(());
    }

    let expected_hash = client
        .client_secret_hash
        .as_deref()
        .ok_or_else(|| AppError::OidcInvalidClient("client has no secret configured".into()))?;

    let secret = provided_secret.ok_or_else(|| {
        AppError::OidcInvalidClient("client_secret required for confidential client".into())
    })?;

    // Verify Argon2id hash
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    let parsed = PasswordHash::new(expected_hash)
        .map_err(|_| AppError::OidcInvalidClient("malformed client secret hash".into()))?;
    Argon2::default()
        .verify_password(secret.as_bytes(), &parsed)
        .map_err(|_| AppError::OidcInvalidClient("invalid client_secret".into()))
}

/// Extract `Authorization: Bearer <token>` from the request.
fn extract_bearer_token(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").map(|t| t.to_string()))
}

/// Extract the client IP from the request (X-Forwarded-For or peer addr).
fn extract_ip(req: &HttpRequest) -> Option<std::net::IpAddr> {
    req.headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| req.peer_addr().map(|addr| addr.ip()))
}
