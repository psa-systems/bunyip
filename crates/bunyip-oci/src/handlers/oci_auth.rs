//! Registry bearer-token handler (`GET /auth/token`).
//!
//! Docker clients call this with basic auth (email:password) after
//! getting a 401+WWW-Authenticate from `/v2/`.

use actix_web::{web, HttpRequest, HttpResponse};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::{Arc, OnceLock};

use crate::errors::OciError;
use crate::middleware::extract_client_ip;
use crate::models::{AuditAction, CreateAuditLog, RateLimitConfig};
use crate::repositories::{
    ApplicationRepository, AuditLogRepository, EntitlementRepository, RateLimitConfigRepository,
    RateLimitRepository, UserRepository,
};
use crate::services::{argon2_offload, OciTokenService, PasswordService};

#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub access_token: String,
    pub expires_in: u64,
    pub issued_at: String,
}

/// A pre-hashed Argon2id string used to perform constant-time verification
/// on the "user not found" branch, preventing email enumeration via timing.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        PasswordService::new()
            .hash("unused-password-for-timing-mitigation")
            .expect("failed to compute dummy hash")
    })
}

/// Timing padding for the branches that have no real hash to check.
///
/// The boolean is false by construction (the candidate is checked against a
/// hash of a fixed string), so it is discarded; what matters is that the branch
/// costs what a real verify costs. Runs on the blocking pool like every other
/// Argon2 call, and `dummy_hash()`'s one-off lazy init happens inside the same
/// task, so neither lands on an actix worker (BUNYIP-553).
async fn dummy_verify(password: &str) {
    let password = password.to_string();
    let outcome = argon2_offload::offload("oci dummy verify", move || {
        PasswordService::new().verify(&password, dummy_hash())
    })
    .await;
    if let Err(e) = outcome {
        tracing::error!(error = %e, "oci dummy password verify failed");
    }
}

/// GET /auth/token
pub async fn issue_token(
    req: HttpRequest,
    query: web::Query<TokenQuery>,
    pool: web::Data<PgPool>,
    token_svc: web::Data<Arc<OciTokenService>>,
) -> Result<HttpResponse, OciError> {
    let ip = extract_client_ip(&req).map(IpNetwork::from);
    let (email, password) = parse_basic_auth(&req).ok_or(OciError::Unauthorized)?;
    let rate_key = email.to_lowercase();

    // BUNYIP-40: Docker requests a fresh bearer token per repository per
    // operation, so a single `docker compose pull` of N images is N token
    // requests in seconds. Rate-limiting EVERY request at the login cap (5/min)
    // throttled legitimate pulls. Instead:
    //   1. Block when too many FAILED verifications have accrued for this email
    //      or this source IP (the credential-stuffing signal) - read-only, so a
    //      request that may succeed does not consume the failure budget.
    //   2. Bound total throughput per email at a generous cap purely to cap
    //      Argon2 CPU.
    // Only genuine credential failures (below, via fail_credential) increment
    // the failure counters. These are cheap indexed lookups; they run before
    // the ~100ms Argon2 verify, which dominates the request cost.
    let ip_key = ip.map(|net| net.ip().to_string());

    // Per-email failure cap. `check` reads without incrementing, so compare the
    // read count directly (`>=`); do NOT switch this to the repo's
    // increment-oriented `exceeded` (`>`), which would allow one extra guess.
    if failures_at_cap(
        pool.get_ref(),
        &rate_key,
        &RateLimitConfig::OCI_TOKEN_FAILURES,
    )
    .await?
    {
        return Err(too_many(
            pool.get_ref(),
            &rate_key,
            &RateLimitConfig::OCI_TOKEN_FAILURES,
            &email,
            ip,
            "rate_limited",
        )
        .await);
    }

    // Per-IP failure cap (distributed-guessing brake). Skipped when no client
    // IP could be determined.
    if let Some(ip_key) = ip_key.as_deref() {
        if failures_at_cap(
            pool.get_ref(),
            ip_key,
            &RateLimitConfig::OCI_TOKEN_IP_FAILURES,
        )
        .await?
        {
            return Err(too_many(
                pool.get_ref(),
                ip_key,
                &RateLimitConfig::OCI_TOKEN_IP_FAILURES,
                &email,
                ip,
                "rate_limited_ip",
            )
            .await);
        }
    }

    let (_throughput, throughput_exceeded) = RateLimitRepository::check_and_increment(
        pool.get_ref(),
        &rate_key,
        &RateLimitConfig::OCI_TOKEN_THROUGHPUT,
    )
    .await
    .map_err(|_| OciError::Internal)?;
    if throughput_exceeded {
        return Err(too_many(
            pool.get_ref(),
            &rate_key,
            &RateLimitConfig::OCI_TOKEN_THROUGHPUT,
            &email,
            ip,
            "rate_limited_throughput",
        )
        .await);
    }

    let user = UserRepository::find_by_email(pool.get_ref(), &email)
        .await
        .map_err(|_| OciError::Internal)?;

    let user = match user {
        Some(u) => u,
        None => {
            // Perform dummy verification on the "user not found" path to mitigate
            // email enumeration attacks via response-time analysis.
            dummy_verify(&password).await;
            return Err(
                fail_credential(pool.get_ref(), &rate_key, &email, ip, "user_not_found").await,
            );
        }
    };

    if user.deleted_at.is_some() {
        audit_failed(pool.get_ref(), &email, ip, "inactive_user").await;
        return Err(OciError::Unauthorized);
    }

    // Passwordless accounts (magic-link only) cannot use the registry. Still
    // perform a dummy verify to keep timing indistinguishable from the
    // password-check branch.
    let Some(password_hash) = user.password_hash.clone() else {
        dummy_verify(&password).await;
        return Err(fail_credential(pool.get_ref(), &rate_key, &email, ip, "no_password").await);
    };

    let password_ok = argon2_offload::verify_password(password, password_hash)
        .await
        .map_err(|_| OciError::Internal)?;
    if !password_ok {
        return Err(fail_credential(pool.get_ref(), &rate_key, &email, ip, "bad_password").await);
    }

    if !user.is_access_allowed() {
        audit_failed(pool.get_ref(), &email, ip, "no_active_membership").await;
        return Err(OciError::Unauthorized);
    }

    // Scope validation: if provided, the target app must exist + be pullable.
    let mut scope_str = String::new();
    let mut scope_app_id: Option<uuid::Uuid> = None;
    if let Some(raw_scope) = &query.scope {
        let slug = parse_repository_pull_scope(raw_scope).ok_or(OciError::Denied)?;
        let app = ApplicationRepository::find_active_by_slug(pool.get_ref(), &slug)
            .await
            .map_err(|_| OciError::Internal)?
            .ok_or(OciError::NameUnknown)?;
        if !app.is_pullable() {
            return Err(OciError::NameUnknown);
        }
        // Per-product entitlement (BUNYIP-39), via the shared decision. Denial
        // surfaces as NameUnknown (404), matching the not-pullable branch, so
        // restricted-product existence does not leak by status code.
        let allowed =
            EntitlementRepository::is_allowed(pool.get_ref(), user.id, user.is_admin(), &app)
                .await
                .map_err(|_| OciError::Internal)?;
        if !allowed {
            audit_failed(pool.get_ref(), &email, ip, "no_entitlement").await;
            return Err(OciError::NameUnknown);
        }
        scope_app_id = Some(app.id);
        scope_str = format!("repository:{slug}:pull");
    }

    let token = token_svc.issue(user.id, &scope_str)?;
    let now = Utc::now();

    // Audit token issuance with the user AND the target application (when the
    // scope names one), so per-product pull activity is traceable from the
    // audit log without joining on per-blob requests.
    let mut log = CreateAuditLog::new(AuditAction::OciLoginSucceeded)
        .with_actor(user.id, &user.email, &user.role)
        .with_ip(ip)
        .with_metadata(serde_json::json!({ "scope": scope_str }));
    if let Some(app_id) = scope_app_id {
        log = log.with_resource("application", app_id);
    }
    if let Err(e) = AuditLogRepository::create(pool.get_ref(), log).await {
        tracing::warn!(?e, "oci audit log write failed");
    }

    Ok(HttpResponse::Ok().json(TokenResponse {
        token: token.clone(),
        access_token: token,
        expires_in: token_svc.ttl_secs(),
        issued_at: now.to_rfc3339(),
    }))
}

fn parse_basic_auth(req: &HttpRequest) -> Option<(String, String)> {
    let header = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let b64 = header.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(b64).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (email, password) = decoded.split_once(':')?;
    Some((email.to_string(), password.to_string()))
}

fn parse_repository_pull_scope(scope: &str) -> Option<String> {
    // Docker sends scopes like "repository:my-app:pull" (possibly comma-separated).
    // We accept only single-repo pull scopes.
    let (kind, rest) = scope.split_once(':')?;
    if kind != "repository" {
        return None;
    }
    let (slug, action) = rest.rsplit_once(':')?;
    if action != "pull" {
        return None;
    }
    Some(slug.to_string())
}

async fn audit_failed(pool: &PgPool, email: &str, ip: Option<IpNetwork>, reason: &str) {
    let log = CreateAuditLog::new(AuditAction::OciLoginFailed)
        .with_ip(ip)
        .with_metadata(serde_json::json!({ "email": email, "reason": reason }));
    if let Err(e) = AuditLogRepository::create(pool, log).await {
        tracing::warn!(?e, "oci audit log write failed");
    }
}

/// Read (without incrementing) a failure counter and report whether it is at or
/// over its cap. Uses `>=` against the read count deliberately: the failures
/// are counted on the failure paths (`fail_credential`), not here, so the
/// boundary value must block. A DB read error fails closed (propagates 500).
async fn failures_at_cap(
    pool: &PgPool,
    key: &str,
    config: &RateLimitConfig,
) -> Result<bool, OciError> {
    // BUNYIP-413: the cap in force may be a persisted override, so resolve it
    // rather than comparing against the caller's compile-time preset.
    let config = RateLimitConfigRepository::effective(pool, config)
        .await
        .map_err(|_| OciError::Internal)?;
    let (count, _) = RateLimitRepository::check(pool, key, &config)
        .await
        .map_err(|_| OciError::Internal)?;
    Ok(count >= config.max_requests)
}

/// Build a 429 for an exceeded limit: look up the reset window, audit, and
/// return the error. `key` is the counter key that tripped (email or IP);
/// `config` is the limit that tripped (failures / IP-failures / throughput);
/// `email`/`ip` are for the audit record.
async fn too_many(
    pool: &PgPool,
    key: &str,
    config: &RateLimitConfig,
    email: &str,
    ip: Option<IpNetwork>,
    reason: &str,
) -> OciError {
    // `get_retry_after` reads the window row keyed by (key, config.action), so it
    // MUST get the config that actually tripped. Passing a fixed FAILURES config
    // for a throughput or per-IP denial looked up the wrong (key, action) pair,
    // found no row, and returned Retry-After: 0.
    let retry_after = RateLimitRepository::get_retry_after(pool, key, config)
        .await
        .unwrap_or(60);
    audit_failed(pool, email, ip, reason).await;
    OciError::TooManyRequests {
        retry_after_secs: Some(retry_after),
    }
}

/// A credential-verification failure (wrong/absent password, unknown email):
/// the credential-stuffing signal (BUNYIP-40). Increments BOTH the per-email
/// and per-IP failure counters that gate the endpoint, audits, and returns 401.
/// Authorization failures (deleted user, no membership, no entitlement) happen
/// AFTER a successful password check and so are NOT counted here. `rate_key` is
/// the lowercased email used as the per-email counter key.
async fn fail_credential(
    pool: &PgPool,
    rate_key: &str,
    email: &str,
    ip: Option<IpNetwork>,
    reason: &str,
) -> OciError {
    // Best-effort: a counter write failure must not change the auth outcome,
    // but log it because it means the credential-stuffing guard is degrading
    // open (failures stop being counted) under DB stress.
    if let Err(e) = RateLimitRepository::check_and_increment(
        pool,
        rate_key,
        &RateLimitConfig::OCI_TOKEN_FAILURES,
    )
    .await
    {
        tracing::warn!(?e, "oci failure-counter increment failed (email)");
    }
    if let Some(net) = ip {
        let ip_key = net.ip().to_string();
        if let Err(e) = RateLimitRepository::check_and_increment(
            pool,
            &ip_key,
            &RateLimitConfig::OCI_TOKEN_IP_FAILURES,
        )
        .await
        {
            tracing::warn!(?e, "oci failure-counter increment failed (ip)");
        }
    }
    audit_failed(pool, email, ip, reason).await;
    OciError::Unauthorized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope_accepts_repository_pull() {
        assert_eq!(
            parse_repository_pull_scope("repository:my-app:pull"),
            Some("my-app".into())
        );
        assert_eq!(
            parse_repository_pull_scope("repository:complex/slug:pull"),
            Some("complex/slug".into())
        );
        assert!(parse_repository_pull_scope("repository:my-app:push").is_none());
        assert!(parse_repository_pull_scope("registry:catalog:*").is_none());
        assert!(parse_repository_pull_scope("repository:my-app").is_none());
    }

    #[test]
    fn parse_basic_auth_decodes_header() {
        let req = actix_web::test::TestRequest::default()
            .insert_header((
                "Authorization",
                format!("Basic {}", STANDARD.encode("me@example.com:hunter2")),
            ))
            .to_http_request();
        assert_eq!(
            parse_basic_auth(&req),
            Some(("me@example.com".into(), "hunter2".into()))
        );
    }
}
