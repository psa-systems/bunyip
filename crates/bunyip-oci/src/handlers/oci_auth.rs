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

use crate::errors::{OciError, OciErrorContext};
use crate::middleware::extract_client_ip;
use crate::models::{AuditAction, CreateAuditLog, RateLimitConfig};
use crate::repositories::{
    ApplicationRepository, AuditLogRepository, EntitlementRepository, RateLimitConfigRepository,
    RateLimitRepository, UserRepository,
};
use crate::services::{argon2_offload, OciTokenService, PasswordService};

// SPEC-6.3.3: service is accepted and ignored; scope is parsed after authentication
#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

// SPEC-6.7.1: token and access_token carry the same bearer so both Docker client styles work
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub access_token: String,
    pub expires_in: u64,
    pub issued_at: String,
}

// SPEC-6.5.1, SPEC-6.5.3: fixed Argon2id hash so an unknown email costs a real verify
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

// SPEC-6.5.4, SPEC-6.5.5: timing padding runs on the blocking pool; failure is logged, not fatal
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

// SPEC-6.3.2, SPEC-6.3.4, SPEC-6.7.1: GET /auth/token: Basic credentials in, bearer out
/// GET /auth/token
pub async fn issue_token(
    req: HttpRequest,
    query: web::Query<TokenQuery>,
    pool: web::Data<PgPool>,
    token_svc: web::Data<Arc<OciTokenService>>,
) -> Result<HttpResponse, OciError> {
    let ip = extract_client_ip(&req).map(IpNetwork::from);
    // SPEC-6.3.2, SPEC-6.3.4: no usable Basic header is a 401 before any counter or lookup
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
    // SPEC-6.4.1: per-email failure brake runs before the Argon2 verify
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
    // SPEC-6.4.2: per-IP failure brake; skipped only when no client IP is known
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

    // SPEC-6.4.4, SPEC-6.4.6: throughput cap bounds Argon2 CPU; a counter error fails the request
    let (_throughput, throughput_exceeded) = RateLimitRepository::check_and_increment(
        pool.get_ref(),
        &rate_key,
        &RateLimitConfig::OCI_TOKEN_THROUGHPUT,
    )
    .await
    .internal_ctx(|| "count a token request against the throughput cap")?;
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
        .internal_ctx(|| "look up the account behind a registry token request")?;

    // SPEC-6.5.1: unknown email: dummy verify, then a counted credential failure
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

    // SPEC-6.6.1: authorization failure after the password check, not counted as a guess
    if user.deleted_at.is_some() {
        audit_failed(pool.get_ref(), &email, ip, "inactive_user").await;
        return Err(OciError::Unauthorized);
    }

    // Passwordless accounts (magic-link only) cannot use the registry. Still
    // perform a dummy verify to keep timing indistinguishable from the
    // password-check branch.
    // SPEC-6.5.2: passwordless account: dummy verify keeps timing equal
    let Some(password_hash) = user.password_hash.clone() else {
        dummy_verify(&password).await;
        return Err(fail_credential(pool.get_ref(), &rate_key, &email, ip, "no_password").await);
    };

    // SPEC-6.5.4, SPEC-6.5.7: a verify that cannot run is a logged 500, not a bad password
    let password_ok = argon2_offload::verify_password(password, password_hash)
        .await
        .internal_ctx(|| format!("verify the registry password of user {}", user.id))?;
    // SPEC-6.5.6: wrong password is a counted credential failure
    if !password_ok {
        return Err(fail_credential(pool.get_ref(), &rate_key, &email, ip, "bad_password").await);
    }

    // SPEC-6.6.2: valid password without registry access is a 401, not counted
    if !user.is_access_allowed() {
        audit_failed(pool.get_ref(), &email, ip, "no_active_membership").await;
        return Err(OciError::Unauthorized);
    }

    // Scope validation: if provided, the target app must exist + be pullable.
    // SPEC-6.3.5, SPEC-6.6.3, SPEC-6.6.5, SPEC-6.6.6:
    //  scope is optional; when given the app must exist and be pullable
    let mut scope_str = String::new();
    let mut scope_app_id: Option<uuid::Uuid> = None;
    if let Some(raw_scope) = &query.scope {
        let slug = parse_repository_pull_scope(raw_scope).ok_or(OciError::Denied)?;
        let app = ApplicationRepository::find_active_by_slug(pool.get_ref(), &slug)
            .await
            .internal_ctx(|| format!("load the application for token scope slug {slug}"))?
            .ok_or(OciError::NameUnknown)?;
        if !app.is_pullable() {
            return Err(OciError::NameUnknown);
        }
        // Per-product entitlement (BUNYIP-39), via the shared decision. Denial
        // surfaces as NameUnknown (404), matching the not-pullable branch, so
        // restricted-product existence does not leak by status code.
        // SPEC-6.6.4: denial is NAME_UNKNOWN so a restricted product does not leak by status
        let allowed =
            EntitlementRepository::is_allowed(pool.get_ref(), user.id, user.is_admin(), &app)
                .await
                .internal_ctx(|| {
                    format!(
                        "check user {}'s entitlement to application {}",
                        user.id, app.slug
                    )
                })?;
        if !allowed {
            audit_failed(pool.get_ref(), &email, ip, "no_entitlement").await;
            return Err(OciError::NameUnknown);
        }
        scope_app_id = Some(app.id);
        scope_str = format!("repository:{slug}:pull");
    }

    // SPEC-6.7.2: subject is the user id; scope is the granted repository:<slug>:pull
    let token = token_svc.issue(user.id, &scope_str)?;
    let now = Utc::now();

    // Audit token issuance with the user AND the target application (when the
    // scope names one), so per-product pull activity is traceable from the
    // audit log without joining on per-blob requests.
    // SPEC-6.7.3: issuance is audited with the target application when scoped
    let mut log = CreateAuditLog::new(AuditAction::OciLoginSucceeded)
        .with_actor(user.id, &user.email, &user.role)
        .with_ip(ip)
        .with_metadata(serde_json::json!({ "scope": scope_str }));
    if let Some(app_id) = scope_app_id {
        log = log.with_resource("application", app_id);
    }
    // SPEC-6.7.4, SPEC-6.16.3: audit loss is logged and never changes the outcome
    if let Err(e) = AuditLogRepository::create(pool.get_ref(), log).await {
        tracing::warn!(?e, "oci audit log write failed");
    }

    // SPEC-6.7.1: success body
    Ok(HttpResponse::Ok().json(TokenResponse {
        token: token.clone(),
        access_token: token,
        expires_in: token_svc.ttl_secs(),
        issued_at: now.to_rfc3339(),
    }))
}

// SPEC-6.3.1, SPEC-6.3.2: split at the first colon so a password may contain colons
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

// SPEC-6.3.5: only single-repository pull scopes are accepted
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

// SPEC-6.4.8, SPEC-6.16.1, SPEC-6.16.2, SPEC-6.16.3:
//  oci_login_failed with email and reason; write errors are only logged
async fn audit_failed(pool: &PgPool, email: &str, ip: Option<IpNetwork>, reason: &str) {
    let log = CreateAuditLog::new(AuditAction::OciLoginFailed)
        .with_ip(ip)
        .with_metadata(serde_json::json!({ "email": email, "reason": reason }));
    if let Err(e) = AuditLogRepository::create(pool, log).await {
        tracing::warn!(?e, "oci audit log write failed");
    }
}

// SPEC-6.4.1, SPEC-6.4.3, SPEC-6.4.5, SPEC-6.4.6: read-only, >= so the boundary blocks; DB errors fail closed
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
        .internal_ctx(|| format!("resolve the effective {} limit", config.action))?;
    let (count, _) = RateLimitRepository::check(pool, key, &config)
        .await
        .internal_ctx(|| format!("read the {} failure counter", config.action))?;
    Ok(count >= config.max_requests)
}

// SPEC-6.4.7, SPEC-6.4.8: Retry-After comes from the counter that tripped; lookup failure advertises 60s
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
    // A read failure keeps the 429 (the denial is already decided), but the
    // advertised window is then a guess, so log it rather than pass it off.
    let retry_after = RateLimitRepository::get_retry_after(pool, key, config)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                error = %e,
                action = config.action,
                "oci retry-after lookup failed; advertising the 60s default"
            );
            60
        });
    audit_failed(pool, email, ip, reason).await;
    OciError::TooManyRequests {
        retry_after_secs: Some(retry_after),
    }
}

// SPEC-6.5.8, SPEC-6.5.9, SPEC-6.5.10:
//  only credential failures feed the stuffing counters; increment errors are logged
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
