//! /v2/* handlers for the OCI registry server.

use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::StreamExt;
use ipnetwork::IpNetwork;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tokio_util::codec::{BytesCodec, FramedRead};
use uuid::Uuid;

use crate::errors::{internal_fault, OciError, OciErrorContext};
use crate::middleware::{extract_client_ip, OciBearerUser};
use crate::models::oci::CachedManifest;
use crate::models::{AuditAction, CreateAuditLog};
use crate::repositories::{
    ApplicationRepository, AuditLogRepository, EntitlementRepository, OciBlobCacheRepository,
    OciPullDailyCountRepository,
};
use crate::services::{
    BlobCache, BlobCacheError, ForgejoRegistryClient, ManifestCache, OciLimitDenial, OciLimiter,
    RegistryError,
};

/// The blob cache, parameterised over Bunyip's Postgres blob-cache store.
type AppBlobCache = BlobCache<OciBlobCacheRepository>;

// SPEC-6.10.12: one digest rule for the pull path and the admin refresh path
/// Resolve a manifest's content digest, computing the sha256 fallback over the
/// raw bytes when the upstream response omitted a digest. Single source for
/// both the member pull path and the admin cache-refresh path.
pub(crate) fn resolve_manifest_digest(digest: String, bytes: &[u8]) -> String {
    if digest.is_empty() {
        format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
    } else {
        digest
    }
}

// SPEC-6.10.7: used only when the client sends no Accept header
const DEFAULT_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json";

// SPEC-6.9.1, SPEC-6.9.2: auth-only probe; any extraction failure arrives as None and is a 401
/// GET /v2/  - version probe. Requires auth but no scope.
pub async fn version_probe(user: Option<OciBearerUser>) -> Result<HttpResponse, OciError> {
    match user {
        Some(_) => Ok(HttpResponse::Ok()
            .append_header(("Docker-Distribution-API-Version", "registry/2.0"))
            .finish()),
        None => Err(OciError::Unauthorized),
    }
}

// SPEC-6.10.1, SPEC-6.10.9: GET/HEAD manifest: scope, app, entitlement, reference, metering, cache
/// GET/HEAD /v2/{slug}/manifests/{reference}
pub async fn get_manifest(
    req: HttpRequest,
    user: OciBearerUser,
    path: web::Path<(String, String)>,
    pool: web::Data<PgPool>,
    client: web::Data<Option<Arc<ForgejoRegistryClient>>>,
    manifest_cache: web::Data<Option<Arc<ManifestCache>>>,
    limiter: web::Data<Arc<OciLimiter>>,
    counter: web::Data<Arc<OciPullDailyCountRepository>>,
) -> Result<HttpResponse, OciError> {
    let (slug, reference) = path.into_inner();
    // SPEC-6.10.1: scope mismatch is audited and answered DENIED
    if user.assert_scope(&slug).is_err() {
        audit_denied_scope(pool.get_ref(), &req, &user, &slug).await;
        return Err(OciError::Denied);
    }

    // SPEC-6.10.2: no upstream client means the registry is off for this app (404)
    let client = client
        .as_ref()
        .as_ref()
        .ok_or(OciError::NameUnknown)?
        .clone();
    let cache = manifest_cache
        .as_ref()
        .as_ref()
        .ok_or_else(|| internal_fault("resolve the manifest cache from the app data"))?
        .clone();

    // SPEC-6.10.3, SPEC-6.10.6: inactive or non-pullable apps are NAME_UNKNOWN
    let app = ApplicationRepository::find_active_by_slug(pool.get_ref(), &slug)
        .await
        .internal_ctx(|| format!("load the application for manifest slug {slug}"))?
        .ok_or(OciError::NameUnknown)?;
    if !app.is_pullable() {
        return Err(OciError::NameUnknown);
    }
    // SPEC-6.10.4: entitlement gate precedes cache and upstream
    assert_entitled(pool.get_ref(), &req, &user, &app).await?;
    let pinned = app
        .pinned_image_tag
        .clone()
        .ok_or(OciError::ManifestUnknown)?;

    // Reference must be the pinned tag or a sha256 digest. Child manifests
    // (multi-arch) are fetched via digest references and hash-verified by
    // upstream; we allow them through.
    // BUNYIP-386: allow the pinned tag, any sha256 digest, OR any recorded
    // non-yanked historical version (application_versions), so a pin bump no
    // longer makes older tags unpullable through the proxy.
    // SPEC-6.10.5, SPEC-6.10.6: pinned tag, any digest, or a recorded non-yanked version
    let is_digest = reference.starts_with("sha256:");
    if !is_digest
        && reference != pinned
        && !ApplicationRepository::is_pullable_version(pool.get_ref(), app.id, &reference)
            .await
            .internal_ctx(|| {
                format!(
                    "check the recorded versions of application {} for reference {reference}",
                    app.id
                )
            })?
    {
        return Err(OciError::ManifestUnknown);
    }

    // Meter (daily pull cap + concurrency) only TAG-addressed manifest requests
    // (BUNYIP-43). A logical `docker pull` resolves the tag (HEAD and/or GET by
    // tag) and then fetches the platform manifest by DIGEST; counting the
    // digest follow-ups made one multi-arch pull consume 3+ of the daily
    // allowance (default 50 yielded ~16 real pulls). Digest-addressed requests
    // are still served, just not metered. Note: a client that does both HEAD
    // and GET by tag meters twice; one that resolves via HEAD-by-tag then GETs
    // by digest meters once. Either way a pull never exceeds the tag requests,
    // and digest follow-ups are free.
    //
    // Digest-addressed requests are still concurrency-bounded via a
    // concurrency-only acquire (PSA-42), so a multi-arch pull's by-digest
    // platform-manifest follow-ups stay within concurrent_manifests_per_user
    // without counting toward the daily cap.
    // SPEC-6.11.1: only tag-addressed requests count toward the daily cap
    let is_head = req.method() == actix_web::http::Method::HEAD;
    let counts_as_pull = should_meter(&reference);
    // Every request holds a concurrency slot for the duration of the fetch;
    // only tag-addressed (metered) requests also count toward the daily cap.
    // SPEC-6.11.2, SPEC-6.11.4, SPEC-6.11.5, SPEC-6.11.6:
    //  tag requests take a slot and the daily cap; denials are audited 429s
    let _guard = if counts_as_pull {
        match limiter
            .acquire(counter.get_ref().as_ref(), user.claims.sub)
            .await
            .internal_ctx(|| format!("meter the daily pull cap for user {}", user.claims.sub))?
        {
            Ok(g) => g,
            Err(OciLimitDenial::Concurrency) => {
                audit_denied(pool.get_ref(), &req, &user, &app.id, "concurrency", None).await;
                return Err(OciError::TooManyRequests {
                    retry_after_secs: None,
                });
            }
            Err(OciLimitDenial::DailyCap { reset_in_secs }) => {
                let secs_u64 = reset_in_secs.max(0) as u64;
                audit_denied(
                    pool.get_ref(),
                    &req,
                    &user,
                    &app.id,
                    "daily_cap",
                    Some(secs_u64),
                )
                .await;
                return Err(OciError::TooManyRequests {
                    retry_after_secs: Some(secs_u64),
                });
            }
        }
    } else {
        // Not metered (digest-addressed), but still take a concurrency slot so
        // the by-digest follow-ups of a multi-arch pull stay bounded (PSA-42).
        // SPEC-6.11.3: digest follow-ups stay concurrency-bounded without using the cap
        match limiter.acquire_concurrency_only(user.claims.sub) {
            Ok(g) => g,
            Err(OciLimitDenial::Concurrency) => {
                audit_denied(pool.get_ref(), &req, &user, &app.id, "concurrency", None).await;
                return Err(OciError::TooManyRequests {
                    retry_after_secs: None,
                });
            }
            // acquire_concurrency_only never touches the daily counter.
            Err(OciLimitDenial::DailyCap { .. }) => {
                unreachable!("acquire_concurrency_only cannot return DailyCap")
            }
        }
    };

    // SPEC-6.10.13: recorded before the cache or upstream is consulted
    audit_requested(pool.get_ref(), &req, &user, &app.id, &reference).await;

    // SPEC-6.10.7: client Accept wins; otherwise the default media-type list
    let accept = req
        .headers()
        .get(actix_web::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(DEFAULT_ACCEPT)
        .to_string();

    // SPEC-6.10.8, SPEC-6.10.10, SPEC-6.10.11:
    //  cache miss fetches upstream; NotFound is 404, other failures 502 and audited
    let manifest: Arc<CachedManifest> = if let Some(hit) = cache.get(app.id, &reference).await {
        hit
    } else {
        let owner = app
            .oci_image_owner
            .as_deref()
            .ok_or(OciError::NameUnknown)?;
        let name = app.oci_image_name.as_deref().ok_or(OciError::NameUnknown)?;
        let mr = match client.get_manifest(owner, name, &reference, &accept).await {
            Ok(mr) => mr,
            Err(e) => {
                let mapped = map_reg_err(&e);
                if matches!(mapped, OciError::Upstream) {
                    audit_failed_upstream(
                        pool.get_ref(),
                        &req,
                        &user,
                        &app.id,
                        "manifest",
                        &reference,
                        &format!("{e:?}"),
                    )
                    .await;
                }
                return Err(mapped);
            }
        };
        let digest = resolve_manifest_digest(mr.digest, &mr.bytes);
        cache
            .insert(
                app.id,
                &reference,
                CachedManifest {
                    bytes: mr.bytes,
                    media_type: mr.media_type,
                    digest,
                },
            )
            .await
    };

    // BUNYIP-386 (option b): self-heal the version history on the serve path. A
    // tag that reached here is already allowed (the pinned tag or a recorded
    // non-yanked version), so recording it guarantees the pinned tag is always
    // in the history even if the admin-bump append missed it, and it fills the
    // resolved digest. Best-effort: a history write never fails a pull. Digest
    // references are not versions, so skip them.
    // SPEC-6.12.1, SPEC-6.12.2: self-heal the version history; a failed write never fails the pull
    if !is_digest {
        if let Err(e) = ApplicationRepository::record_version(
            pool.get_ref(),
            app.id,
            &reference,
            Some(&manifest.digest),
        )
        .await
        {
            tracing::warn!(error = %e, app_id = %app.id, tag = %reference, "application_versions self-heal record failed");
        }
    }

    // SPEC-6.10.13: completion record carries the resolved digest
    audit_completed(
        pool.get_ref(),
        &req,
        &user,
        &app.id,
        &reference,
        &manifest.digest,
    )
    .await;
    // Release the concurrency slot (held by every request) before cloning the
    // response bytes, so a slow client read does not hold it.
    // SPEC-6.11.7: free the slot before building the response so slow readers do not hold it
    drop(_guard);

    // SPEC-6.10.9: headers always; body only for GET
    let mut resp = HttpResponse::Ok();
    resp.insert_header(("Content-Type", manifest.media_type.clone()));
    resp.insert_header(("Docker-Content-Digest", manifest.digest.clone()));
    resp.insert_header(("Content-Length", manifest.bytes.len().to_string()));
    if is_head {
        Ok(resp.finish())
    } else {
        Ok(resp.body(manifest.bytes.clone()))
    }
}

// SPEC-6.13.1, SPEC-6.13.3, SPEC-6.13.4: GET/HEAD blob: same gates as manifests, no pinned-tag allow-list
/// GET/HEAD /v2/{slug}/blobs/{digest}
pub async fn get_blob(
    req: HttpRequest,
    user: OciBearerUser,
    path: web::Path<(String, String)>,
    pool: web::Data<PgPool>,
    blob_cache: web::Data<Option<Arc<AppBlobCache>>>,
) -> Result<HttpResponse, OciError> {
    let (slug, digest) = path.into_inner();
    // SPEC-6.13.1: same scope check and audit as the manifest endpoint
    if user.assert_scope(&slug).is_err() {
        audit_denied_scope(pool.get_ref(), &req, &user, &slug).await;
        return Err(OciError::Denied);
    }
    // SPEC-6.13.2: a missing blob cache is a wiring fault: logged 500
    let blob_cache = blob_cache
        .as_ref()
        .as_ref()
        .ok_or_else(|| internal_fault("resolve the blob cache from the app data"))?
        .clone();

    // SPEC-6.13.1: same active and pullable lookup as the manifest endpoint
    let app = ApplicationRepository::find_active_by_slug(pool.get_ref(), &slug)
        .await
        .internal_ctx(|| format!("load the application for blob slug {slug}"))?
        .ok_or(OciError::NameUnknown)?;
    if !app.is_pullable() {
        return Err(OciError::NameUnknown);
    }
    // SPEC-6.13.1: same entitlement gate as the manifest endpoint
    assert_entitled(pool.get_ref(), &req, &user, &app).await?;
    let owner = app
        .oci_image_owner
        .as_deref()
        .ok_or(OciError::NameUnknown)?;
    let name = app.oci_image_name.as_deref().ok_or(OciError::NameUnknown)?;

    // SPEC-6.13.3, SPEC-6.13.6: engine classifies the failure; non-404 failures are logged and audited
    let handle = match blob_cache.get_or_fetch(owner, name, &digest).await {
        Ok(h) => h,
        Err(e) => {
            // The OCI status classification (BlobUnknown / Upstream / Internal)
            // lives in dunite-oci next to the error types (PSA-35); this
            // handler adds only Bunyip's logging and audit policy.
            if let BlobCacheError::Registry(RegistryError::Upstream(status @ (401 | 403))) = &e {
                log_forgejo_credential_rejection(*status);
            }
            let mapped = OciError::from(&e);
            if !matches!(mapped, OciError::BlobUnknown) {
                tracing::error!(
                    error = ?e,
                    slug = %slug,
                    digest = %digest,
                    "blob fetch failed; see error for the upstream/filesystem cause"
                );
                audit_failed_upstream(
                    pool.get_ref(),
                    &req,
                    &user,
                    &app.id,
                    "blob",
                    &digest,
                    &format!("{e:?}"),
                )
                .await;
            }
            return Err(mapped);
        }
    };

    // SPEC-6.13.4: HEAD sends headers only
    let is_head = req.method() == actix_web::http::Method::HEAD;
    let mut resp = HttpResponse::Ok();
    resp.insert_header(("Docker-Content-Digest", handle.digest.clone()));
    resp.insert_header(("Content-Length", handle.size_bytes.to_string()));
    if let Some(mt) = &handle.media_type {
        resp.insert_header(("Content-Type", mt.clone()));
    }
    if is_head {
        return Ok(resp.finish());
    }

    // SPEC-6.13.7: open failure after a successful fetch is a logged 500
    let file = tokio::fs::File::open(&handle.path)
        .await
        .internal_ctx(|| format!("open the cached blob {digest} at {}", handle.path.display()))?;
    // SPEC-6.13.5, SPEC-6.13.8: chunked streaming; mid-stream errors can only be logged
    let stream = FramedRead::new(file, BytesCodec::new()).map(move |r| {
        r.map(|b: bytes::BytesMut| b.freeze()).map_err(|e| {
            // Mid-stream, so the status is already sent: the log line is the
            // only report the operator gets.
            tracing::error!(error = %e, slug = %slug, digest = %digest, "oci blob stream read failed");
            actix_web::error::ErrorInternalServerError("io")
        })
    });
    Ok(resp.streaming(stream))
}

// SPEC-6.14.1: read-only registry: every write verb is 405
/// Any non-GET/HEAD under /v2/* returns 405 per OCI "read-only" stance.
pub async fn push_not_supported() -> Result<HttpResponse, OciError> {
    Err(OciError::Unsupported)
}

// SPEC-6.15.3: operator-facing diagnosis; the member only sees UPSTREAM
/// 401/403 from Forgejo means OUR service credentials were rejected, not the
/// member's. Surface a precise operator diagnostic; the member still sees a
/// generic upstream error. Shared by the manifest and blob paths so the
/// guidance cannot drift between them.
fn log_forgejo_credential_rejection(status: u16) {
    tracing::error!(
        status,
        "upstream Forgejo rejected the registry service credentials; \
         verify FORGEJO_API_TOKEN is valid and has the read:package scope \
         for the configured owner/image"
    );
}

// SPEC-6.11.1: digest-addressed requests are free so one pull is not billed several times
/// Whether a manifest request should be metered toward the daily pull cap +
/// concurrency limit (BUNYIP-43). Only TAG-addressed requests count as a
/// logical pull; digest-addressed requests are the multi-arch platform-manifest
/// follow-ups within a pull (or a direct by-digest pull) and are not metered.
fn should_meter(reference: &str) -> bool {
    !reference.starts_with("sha256:")
}

// SPEC-6.10.10, SPEC-6.15.3: NotFound is 404; every other upstream failure is 502
fn map_reg_err(e: &RegistryError) -> OciError {
    match e {
        RegistryError::NotFound => OciError::ManifestUnknown,
        RegistryError::Upstream(status @ (401 | 403)) => {
            log_forgejo_credential_rejection(*status);
            OciError::Upstream
        }
        _ => OciError::Upstream,
    }
}

// SPEC-6.10.13, SPEC-6.16.1, SPEC-6.16.2, SPEC-6.16.3: oci_pull_requested; write errors are only logged
async fn audit_requested(
    pool: &PgPool,
    req: &HttpRequest,
    user: &OciBearerUser,
    app_id: &Uuid,
    reference: &str,
) {
    let log = CreateAuditLog::new(AuditAction::OciPullRequested)
        .with_actor(user.claims.sub, &user.email, &user.role)
        .with_ip(extract_client_ip(req).map(IpNetwork::from))
        .with_resource("application", *app_id)
        .with_metadata(serde_json::json!({ "reference": reference }));
    if let Err(e) = AuditLogRepository::create(pool, log).await {
        tracing::warn!(?e, "oci pull_requested audit log failed");
    }
}

// SPEC-6.10.13, SPEC-6.16.1, SPEC-6.16.2, SPEC-6.16.3: oci_pull_completed with reference and digest
async fn audit_completed(
    pool: &PgPool,
    req: &HttpRequest,
    user: &OciBearerUser,
    app_id: &Uuid,
    reference: &str,
    digest: &str,
) {
    let log = CreateAuditLog::new(AuditAction::OciPullCompleted)
        .with_actor(user.claims.sub, &user.email, &user.role)
        .with_ip(extract_client_ip(req).map(IpNetwork::from))
        .with_resource("application", *app_id)
        .with_metadata(serde_json::json!({ "reference": reference, "digest": digest }));
    if let Err(e) = AuditLogRepository::create(pool, log).await {
        tracing::warn!(?e, "oci pull_completed audit log failed");
    }
}

// SPEC-6.11.4, SPEC-6.11.5, SPEC-6.16.1, SPEC-6.16.2: oci_pull_denied_rate_limit with reason and reset seconds
async fn audit_denied(
    pool: &PgPool,
    req: &HttpRequest,
    user: &OciBearerUser,
    app_id: &Uuid,
    reason: &str,
    reset_in_secs: Option<u64>,
) {
    let log = CreateAuditLog::new(AuditAction::OciPullDeniedRateLimit)
        .with_actor(user.claims.sub, &user.email, &user.role)
        .with_ip(extract_client_ip(req).map(IpNetwork::from))
        .with_resource("application", *app_id)
        .with_metadata(serde_json::json!({ "reason": reason, "reset_in_secs": reset_in_secs }));
    if let Err(e) = AuditLogRepository::create(pool, log).await {
        tracing::warn!(?e, "oci pull_denied audit log failed");
    }
}

// SPEC-6.10.1, SPEC-6.16.1, SPEC-6.16.2: oci_pull_denied_scope with requested slug and token scope
async fn audit_denied_scope(
    pool: &PgPool,
    req: &HttpRequest,
    user: &OciBearerUser,
    requested_slug: &str,
) {
    let log = CreateAuditLog::new(AuditAction::OciPullDeniedScope)
        .with_actor(user.claims.sub, &user.email, &user.role)
        .with_ip(extract_client_ip(req).map(IpNetwork::from))
        .with_metadata(serde_json::json!({
            "requested_slug": requested_slug,
            "token_scope": user.claims.scope,
        }));
    if let Err(e) = AuditLogRepository::create(pool, log).await {
        tracing::warn!(?e, "oci pull_denied_scope audit log failed");
    }
}

// SPEC-6.10.11, SPEC-6.13.6, SPEC-6.16.1, SPEC-6.16.2: oci_pull_failed_upstream with kind, reference and error
async fn audit_failed_upstream(
    pool: &PgPool,
    req: &HttpRequest,
    user: &OciBearerUser,
    app_id: &Uuid,
    kind: &str,
    reference: &str,
    error: &str,
) {
    let log = CreateAuditLog::new(AuditAction::OciPullFailedUpstream)
        .with_actor(user.claims.sub, &user.email, &user.role)
        .with_ip(extract_client_ip(req).map(IpNetwork::from))
        .with_resource("application", *app_id)
        .with_metadata(serde_json::json!({
            "kind": kind,
            "reference": reference,
            "error": error,
        }));
    if let Err(e) = AuditLogRepository::create(pool, log).await {
        tracing::warn!(?e, "oci pull_failed_upstream audit log failed");
    }
}

// SPEC-6.15.1, SPEC-6.15.2: denial is audited and disguised as NAME_UNKNOWN; lookup errors are 500s
/// Entitlement gate for a restricted product (BUNYIP-39). The decision is the
/// shared `EntitlementRepository::is_allowed` (open products and admins pass
/// without a DB hit). Denials are audited and surface as `NameUnknown` (404),
/// the same code as a non-pullable product, so an unentitled member cannot
/// distinguish "restricted product exists" from "no such product" by status.
async fn assert_entitled(
    pool: &PgPool,
    req: &HttpRequest,
    user: &OciBearerUser,
    app: &crate::models::Application,
) -> Result<(), OciError> {
    let allowed = EntitlementRepository::is_allowed(pool, user.claims.sub, user.is_admin(), app)
        .await
        .internal_ctx(|| {
            format!(
                "check user {}'s entitlement to application {}",
                user.claims.sub, app.slug
            )
        })?;
    if allowed {
        return Ok(());
    }
    let log = CreateAuditLog::new(AuditAction::OciPullDeniedEntitlement)
        .with_actor(user.claims.sub, &user.email, &user.role)
        .with_resource("application", app.id)
        .with_ip(extract_client_ip(req).map(IpNetwork::from))
        .with_metadata(serde_json::json!({ "slug": app.slug }));
    if let Err(e) = AuditLogRepository::create(pool, log).await {
        tracing::warn!(?e, "oci pull_denied_entitlement audit log failed");
    }
    Err(OciError::NameUnknown)
}

#[cfg(test)]
mod tests {
    use super::should_meter;

    #[test]
    fn should_meter_tag_but_not_digest() {
        // Tag-addressed requests are logical pulls -> metered.
        assert!(should_meter("v0.1.1"));
        assert!(should_meter("latest"));
        // Digest-addressed requests are multi-arch follow-ups / by-digest pulls
        // -> not metered (BUNYIP-43: prevents one pull burning 3+ of the cap).
        assert!(!should_meter(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }
}
