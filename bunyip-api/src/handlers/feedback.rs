//! Feedback handlers

use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use serde::Deserialize;
use sqlx::PgPool;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use crate::config::Config;
use crate::errors::AppError;
use crate::middleware::{extract_client_ip, AdminUser};
use crate::models::{
    AuditAction, CreateAdminNotification, CreateAuditLog, CreateFeedback, FeedbackStatus,
    FeedbackSubmissionResponse, NotificationType, RateLimitConfig, RespondToFeedback,
    RespondToFeedbackRequest, UpdateFeedbackStatusRequest,
};
use crate::repositories::{
    AuditLogRepository, FeedbackRepository, NotificationRepository, UserRepository,
};
use crate::responses::{created, get_request_id, paginated, success};
use crate::services::EmailService;

const MAX_ATTACHMENT_SIZE: usize = 5 * 1024 * 1024;
const MAX_ATTACHMENTS: usize = 3;
const ALLOWED_MIME_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
    "text/plain",
];

/// Filename length cap (BUNYIP-90). Belt-and-suspenders alongside the
/// control-character rejection: a 5000-character filename would survive
/// the basename strip and end up in the DB row + admin UI + log lines.
const MAX_FILENAME_LEN: usize = 200;

/// Maximum decoded image dimension in pixels (BUNYIP-90). The byte size
/// cap already rejects most decompression bombs, but a 5 MB PNG can
/// declare a billion-pixel dimension that blows up the admin browser
/// when it tries to render the thumbnail. 10000 covers any plausible
/// real-world screenshot (typical 4K is 3840px wide); anything beyond
/// is hostile.
const MAX_IMAGE_DIMENSION: usize = 10000;

/// Validate `filename` for length and absence of control characters
/// (BUNYIP-90). Returns the trimmed-to-basename filename on success.
/// NULL bytes and other control characters can break logging, CSV
/// export, and downstream callers' shell-command boundaries; we reject
/// at the front door instead of patching every consumer.
fn validate_filename(fname: &str) -> Result<String, AppError> {
    let safe = std::path::Path::new(fname)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("attachment")
        .to_string();
    if safe.is_empty() {
        return Err(AppError::validation("attachment", "Empty filename"));
    }
    if safe.len() > MAX_FILENAME_LEN {
        return Err(AppError::validation(
            "attachment",
            "Filename exceeds 200 characters",
        ));
    }
    if safe.chars().any(|c| c.is_control()) {
        return Err(AppError::validation(
            "attachment",
            "Filename contains control characters",
        ));
    }
    Ok(safe)
}

/// Sniff `bytes` for a known file signature and derive the canonical
/// MIME (BUNYIP-90). For files whose magic bytes are recognised, the
/// returned MIME OVERRIDES whatever the browser sent in the multipart
/// part's Content-Type - the sniffer is authoritative. For files with
/// no magic-byte signature (text), the only accepted shape is a UTF-8
/// blob declared as text/plain by the browser; everything else is
/// rejected so an attacker cannot smuggle a binary in by claiming
/// text/plain.
fn derive_canonical_mime(bytes: &[u8], declared_mime: &str) -> Result<String, AppError> {
    if let Some(kind) = infer::get(bytes) {
        let sniffed = kind.mime_type();
        if !ALLOWED_MIME_TYPES.contains(&sniffed) {
            tracing::warn!(
                declared_mime = %declared_mime,
                sniffed_mime = %sniffed,
                "Feedback attachment rejected: sniffed MIME not in allowlist"
            );
            return Err(AppError::validation(
                "attachment",
                "File content is not an allowed type",
            ));
        }
        return Ok(sniffed.to_string());
    }
    // No magic bytes recognized. Only `text/plain` is allowed here; the
    // payload must also be valid UTF-8 so an attacker can't ship a
    // binary by claiming text/plain.
    if declared_mime != "text/plain" {
        tracing::warn!(
            declared_mime = %declared_mime,
            "Feedback attachment rejected: could not verify file type from content"
        );
        return Err(AppError::validation(
            "attachment",
            "Could not verify file type from content",
        ));
    }
    if std::str::from_utf8(bytes).is_err() {
        return Err(AppError::validation(
            "attachment",
            "text/plain attachment is not valid UTF-8",
        ));
    }
    Ok("text/plain".to_string())
}

/// Reject decompression-bomb images by reading just the header
/// (BUNYIP-90). `imagesize::blob_size` parses dimensions without
/// decoding any pixels, so a billion-pixel "PNG" fails here before any
/// rendering ever happens. No-op for non-image MIMEs.
fn enforce_image_dimensions(mime: &str, bytes: &[u8]) -> Result<(), AppError> {
    if !mime.starts_with("image/") {
        return Ok(());
    }
    let size = imagesize::blob_size(bytes).map_err(|e| {
        tracing::warn!(mime = %mime, error = %e, "Feedback image rejected: could not parse dimensions");
        AppError::validation("attachment", "Could not parse image dimensions")
    })?;
    if size.width > MAX_IMAGE_DIMENSION || size.height > MAX_IMAGE_DIMENSION {
        tracing::warn!(
            mime = %mime,
            width = size.width,
            height = size.height,
            "Feedback image rejected: dimensions exceed limit"
        );
        return Err(AppError::validation(
            "attachment",
            "Image dimensions exceed limit",
        ));
    }
    Ok(())
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn validate_length(field: &str, value: &str, max: usize) -> Result<(), AppError> {
    if value.len() > max {
        return Err(AppError::validation(
            field,
            format!("{field} must be at most {max} characters"),
        ));
    }
    Ok(())
}

fn normalize_tags(tags: &[String]) -> Result<Vec<String>, AppError> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    for tag in tags {
        let trimmed = tag.trim();
        if trimmed.is_empty() {
            continue;
        }

        let canonical = match trimmed.to_ascii_lowercase().as_str() {
            "bug" | "bugs" => "Bug",
            "feature" | "features" | "missing feature" | "missing features" => "Feature",
            "flow" | "rough edge" | "rough edges" => "Flow",
            "idea" | "ideas" => "Idea",
            _ => {
                return Err(AppError::validation(
                    "tags",
                    format!("Unsupported feedback tag: {trimmed}"),
                ))
            }
        };

        if seen.insert(canonical) {
            normalized.push(canonical.to_string());
        }
    }

    Ok(normalized)
}

async fn check_feedback_rate_limit(pool: &PgPool, key: &str) -> Result<(), AppError> {
    super::check_rate_limit(pool, key, &RateLimitConfig::FEEDBACK_SUBMIT).await
}

/// BUNYIP-270: whether a freshly submitted feedback row should raise an
/// admin notification + email. The admin Active triage queue is backed by
/// a list query that filters `is_spam = FALSE`, so a honeypot-flagged spam
/// row never appears there. Notifying on spam therefore emailed admins
/// about a submission they could not find in the Active tab. This predicate
/// keeps the "admin was pinged" set aligned with the "row is in Active" set
/// and is factored out so the invariant is unit-testable without a database
/// or email service.
fn should_notify_admins_of_feedback(is_spam: bool) -> bool {
    !is_spam
}

/// BUNYIP-411: normalize a forwarded `User-Agent` before it is persisted and
/// audited. The BFF already caps the header at 512 chars; we store at most 256
/// (matching the session-row UA cap) and treat blank / whitespace as absent, so
/// a missing header does not persist an empty string.
fn bounded_user_agent(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(256).collect())
}

/// BUNYIP-411: the audit-log metadata recorded for a feedback submission. Kept
/// as a pure builder so the recorded shape (crucially, that it carries the
/// source IP and User-Agent) is unit-testable without a database or the HTTP
/// layer. Mirrors the request metadata also persisted on the feedback row.
fn feedback_audit_metadata(
    status: &str,
    has_email: bool,
    page_path: Option<&str>,
    submitter_ip: Option<std::net::IpAddr>,
    user_agent: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "has_email": has_email,
        "page_path": page_path,
        "ip": submitter_ip.map(|ip| ip.to_string()),
        "user_agent": user_agent,
    })
}

pub async fn submit_feedback(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    email_service: web::Data<Arc<EmailService>>,
    config: web::Data<Config>,
    mut payload: Multipart,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_address = extract_client_ip(&req);
    let ip_key = ip_address
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    // BUNYIP-411: the BFF forwards the end-user's browser User-Agent (the
    // server-to-server call would otherwise carry the HTTP-client UA). Capture
    // it for spam tracing alongside the resolved client IP.
    let user_agent = bounded_user_agent(
        req.headers()
            .get(actix_web::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    );
    check_feedback_rate_limit(&pool, &ip_key).await?;

    // Parse multipart fields
    let mut name_raw: Option<String> = None;
    let mut email_raw: Option<String> = None;
    let mut subject_raw: Option<String> = None;
    let mut tags_raw: Vec<String> = Vec::new();
    let mut message_raw: Option<String> = None;
    let mut page_path_raw: Option<String> = None;
    let mut website_raw: Option<String> = None;
    let mut attachment_parts: Vec<(String, String, Vec<u8>)> = Vec::new();

    while let Some(mut field) = payload
        .try_next()
        .await
        .map_err(|_| AppError::validation("attachment", "Invalid multipart data"))?
    {
        let content_disposition = field.content_disposition().cloned();
        let field_name = content_disposition
            .as_ref()
            .and_then(|value| value.get_name())
            .unwrap_or("")
            .to_string();
        let filename = content_disposition
            .as_ref()
            .and_then(|value| value.get_filename())
            .map(|value| value.to_string());

        // Collect field bytes
        let mut bytes = Vec::new();
        while let Some(chunk) = field
            .try_next()
            .await
            .map_err(|_| AppError::validation("attachment", "Failed to read field"))?
        {
            bytes.extend_from_slice(&chunk);
            if filename.is_some() && bytes.len() > MAX_ATTACHMENT_SIZE {
                return Err(AppError::validation(
                    "attachment",
                    "File exceeds 5 MB limit",
                ));
            }
        }

        if let Some(fname) = filename {
            // File field. BUNYIP-90 hardening: every check runs against
            // file CONTENT, never the declared MIME or claimed filename:
            //  - count + size: see byte-chunk loop above
            //  - filename: length + control-char guard (rejects NULL,
            //    newline, tab, etc. that would break logging / CSV)
            //  - MIME: magic-byte sniff overrides the browser's claim;
            //    only the sniffed type ends up stored. text/plain has
            //    no magic and is accepted only when the bytes parse as
            //    UTF-8
            //  - image dimensions: header-only parse via imagesize so
            //    we never instantiate a decoder against adversarial
            //    input. Blocks 1000000x1000000 "PNG" bombs.
            if attachment_parts.len() >= MAX_ATTACHMENTS {
                return Err(AppError::validation(
                    "attachment",
                    "Maximum 3 attachments allowed",
                ));
            }
            let safe_name = validate_filename(&fname)?;
            let declared_mime = field
                .content_type()
                .map(|m| m.to_string())
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let canonical_mime = derive_canonical_mime(&bytes, &declared_mime)?;
            enforce_image_dimensions(&canonical_mime, &bytes)?;
            attachment_parts.push((safe_name, canonical_mime, bytes));
        } else {
            // Text field
            let value = String::from_utf8_lossy(&bytes).to_string();
            match field_name.as_str() {
                "name" => name_raw = Some(value),
                "email" => email_raw = Some(value),
                "subject" => subject_raw = Some(value),
                "tags[]" | "tags" => tags_raw.push(value),
                "message" => message_raw = Some(value),
                "page_path" => page_path_raw = Some(value),
                "website" => website_raw = Some(value),
                _ => {}
            }
        }
    }

    let name = normalize_optional(name_raw);
    let email = normalize_optional(email_raw);
    let subject = normalize_optional(subject_raw);
    let tags = normalize_tags(&tags_raw)?;
    let page_path = normalize_optional(page_path_raw);
    let message = message_raw.unwrap_or_default().trim().to_string();
    let honeypot = website_raw
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    let is_spam = !honeypot.is_empty();

    if let Some(name) = &name {
        validate_length("name", name, 100)?;
    }
    if let Some(email) = &email {
        crate::validation::validate_email(email)?;
    }
    if let Some(subject) = &subject {
        validate_length("subject", subject, 200)?;
    }
    if let Some(page_path) = &page_path {
        validate_length("page_path", page_path, 255)?;
        if !page_path.starts_with('/') {
            return Err(AppError::validation(
                "page_path",
                "Page path must be a relative path",
            ));
        }
    }
    if message.is_empty() {
        return Err(AppError::validation("message", "Message is required"));
    }
    validate_length("message", &message, 5000)?;

    let feedback = FeedbackRepository::create(
        &pool,
        CreateFeedback {
            name,
            email,
            subject,
            tags,
            message,
            page_path,
            is_spam,
            submitter_ip: ip_address.map(ipnetwork::IpNetwork::from),
            user_agent: user_agent.clone(),
        },
    )
    .await?;

    if !attachment_parts.is_empty() {
        FeedbackRepository::save_attachments(&pool, feedback.id, attachment_parts).await?;
    }

    // BUNYIP-411: mirror the request metadata into the audit log so feedback
    // spam is traceable there too. `actor_ip_address` (INET) carries the
    // resolved external client IP; the User-Agent rides in the metadata JSON
    // (the audit schema has no dedicated UA column).
    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::FeedbackSubmitted)
            .with_resource("feedback", feedback.id)
            .with_ip(ip_address.map(ipnetwork::IpNetwork::from))
            .with_metadata(feedback_audit_metadata(
                &feedback.status,
                feedback.email.is_some(),
                feedback.page_path.as_deref(),
                ip_address,
                user_agent.as_deref(),
            )),
    )
    .await?;

    // BUNYIP-270: only ping admins for submissions that actually land in
    // the Active triage queue. Honeypot-flagged spam (is_spam = TRUE) is
    // filtered out of the Active tab by the list query
    // (`WHERE is_spam = FALSE ...`), so notifying/emailing on it produced
    // the reported symptom: admins received a "new feedback" email but
    // opened `/admin/feedback` to an empty Active queue (the row was only
    // reachable under the Spam tab). Suppressing the admin notification +
    // email for spam ties "admin was emailed" to "row is in Active". The
    // row is still stored and audit-logged above, and remains visible in
    // the Spam tab for review.
    if should_notify_admins_of_feedback(feedback.is_spam) {
        NotificationRepository::create(
            &pool,
            CreateAdminNotification {
                notification_type: NotificationType::NewFeedback,
                title: "New feedback submitted".to_string(),
                message: format!(
                    "Feedback #{} is ready for review in the admin panel.",
                    feedback.id
                ),
                metadata: Some(serde_json::json!({
                    "feedback_id": feedback.id,
                    "path": format!("{}/admin/feedback", config.email.base_url),
                    "status": feedback.status,
                })),
                user_id: None,
            },
        )
        .await?;

        let email_svc = email_service.get_ref().clone();
        let feedback_id = feedback.id;
        let admin_url = format!(
            "{}/admin/feedback?id={}",
            config.email.base_url, feedback_id
        );
        let admin_emails = UserRepository::find_admin_emails(&pool)
            .await
            .unwrap_or_default();
        tokio::spawn(async move {
            if let Err(e) = email_svc
                .send_admin_feedback_notification(&admin_url, &admin_emails)
                .await
            {
                tracing::error!(error = %e, feedback_id = %feedback_id, "Failed to send feedback notification email");
            }
        });
    }

    Ok(created(
        FeedbackSubmissionResponse {
            id: feedback.id,
            message: "Feedback submitted".to_string(),
        },
        request_id,
    ))
}

#[derive(Debug, Deserialize)]
pub struct ListFeedbackQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
    /// Legacy single-status filter kept for compatibility; ignored when
    /// `bucket` is set. New callers should use `bucket` instead so
    /// is_spam filtering and "everything except closed" are reachable
    /// in one parameter.
    pub status: Option<String>,
    /// BUNYIP-92: tab-aware filtering. Accepts `active` / `closed` /
    /// `spam`. The repository layer maps each value to a static SQL
    /// predicate; unknown values produce an unfiltered list (preserves
    /// pre-BUNYIP-92 behaviour for any caller that does not yet pass
    /// it). The `archive` view has its own endpoint and does not enter
    /// here.
    pub bucket: Option<String>,
}

pub async fn list_feedback(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    query: web::Query<ListFeedbackQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);

    if let Some(status) = query.status.as_deref() {
        FeedbackStatus::from_str(status)
            .map_err(|_| AppError::validation("status", "Invalid feedback status"))?;
    }

    // Validate the bucket value against the known set so we can hand it
    // straight through to the repository; an unknown value here would
    // silently fall through to the no-filter branch and re-expose the
    // pre-BUNYIP-92 spam-in-active-queue bug.
    if let Some(b) = query.bucket.as_deref() {
        match b {
            "active" | "closed" | "spam" => {}
            _ => {
                return Err(AppError::validation(
                    "bucket",
                    "Bucket must be one of active|closed|spam",
                ));
            }
        }
    }

    let (feedback, total) =
        FeedbackRepository::list_paginated(&pool, page, per_page, query.bucket.as_deref()).await?;

    let items = feedback
        .into_iter()
        .map(|item| item.to_admin_summary())
        .collect();

    Ok(paginated(items, total, page, per_page, request_id))
}

pub async fn get_feedback(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let feedback = FeedbackRepository::find_by_id(&pool, path.into_inner())
        .await?
        .ok_or_else(|| AppError::not_found("Feedback"))?;

    let attachments = FeedbackRepository::find_attachments(&pool, feedback.id).await?;
    Ok(success(feedback.to_admin_detail(attachments), request_id))
}

pub async fn respond_to_feedback(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    email_service: web::Data<Arc<EmailService>>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<RespondToFeedbackRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let feedback_id = path.into_inner();
    let existing = FeedbackRepository::find_by_id(&pool, feedback_id)
        .await?
        .ok_or_else(|| AppError::not_found("Feedback"))?;

    let response = body.response.trim().to_string();
    if response.is_empty() {
        return Err(AppError::validation("response", "Response is required"));
    }
    validate_length("response", &response, 5000)?;

    let status = body
        .status
        .as_deref()
        .map(|value| {
            FeedbackStatus::from_str(value)
                .map_err(|_| AppError::validation("status", "Invalid feedback status"))
        })
        .transpose()?
        .unwrap_or(FeedbackStatus::Responded);

    let updated = FeedbackRepository::respond(
        &pool,
        feedback_id,
        RespondToFeedback {
            status,
            admin_response: response.clone(),
            responded_by: admin.0.sub,
        },
    )
    .await?;

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::FeedbackResponded)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("feedback", updated.id)
            .with_metadata(serde_json::json!({
                "previous_status": existing.status,
                "new_status": updated.status,
            })),
    )
    .await?;

    if let Some(email) = updated.email.clone() {
        // BUNYIP-94: await the send instead of fire-and-forget. The
        // previous tokio::spawn detached the task so any SMTP / config
        // / template failure ended up in a different tracing span from
        // the surrounding request and was invisible to admins
        // confirming "did my reply go out." Awaiting keeps the error on
        // the same request_id; the response is still considered
        // successful even if email send fails because the row is
        // already in the DB with admin_response set.
        if let Err(e) = email_service
            .get_ref()
            .send_feedback_response(&email, &updated)
            .await
        {
            tracing::error!(
                error = %e,
                feedback_id = %updated.id,
                recipient = %email,
                "Failed to send feedback response email"
            );
        }
    }

    let attachments = FeedbackRepository::find_attachments(&pool, updated.id).await?;
    Ok(success(updated.to_admin_detail(attachments), request_id))
}

pub async fn update_feedback_status(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdateFeedbackStatusRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let feedback_id = path.into_inner();

    let existing = FeedbackRepository::find_by_id(&pool, feedback_id)
        .await?
        .ok_or_else(|| AppError::not_found("Feedback"))?;

    let status = FeedbackStatus::from_str(&body.status)
        .map_err(|_| AppError::validation("status", "Invalid feedback status"))?;

    let updated = FeedbackRepository::update_status(&pool, feedback_id, status).await?;

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::FeedbackResponded)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("feedback", updated.id)
            .with_metadata(serde_json::json!({
                "previous_status": existing.status,
                "new_status": updated.status,
            })),
    )
    .await?;

    let attachments = FeedbackRepository::find_attachments(&pool, updated.id).await?;
    Ok(success(updated.to_admin_detail(attachments), request_id))
}

pub async fn delete_feedback(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let feedback_id = path.into_inner();

    // DEV-516: the shared repository returns `false` when no row matched; raise
    // the not-found here (the crate stays error-agnostic).
    if !FeedbackRepository::delete(&pool, feedback_id).await? {
        return Err(AppError::not_found("Feedback"));
    }

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::FeedbackDeleted)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("feedback", feedback_id),
    )
    .await?;

    Ok(success(serde_json::json!({}), request_id))
}

/// POST /v1/admin/feedback/{id}/mark-spam
///
/// Flip `is_spam` to TRUE so the row leaves the admin's active queue
/// and lands in the Spam tab. Writes a `FeedbackMarkedSpam` audit log;
/// reversible via `unmark_feedback_spam`. The auto-spam path on intake
/// (the honeypot field on submission) is independent of this manual
/// flag and uses the same column.
pub async fn mark_feedback_spam(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let feedback_id = path.into_inner();

    let updated = FeedbackRepository::set_is_spam(&pool, feedback_id, true).await?;

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::FeedbackMarkedSpam)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("feedback", feedback_id),
    )
    .await?;

    let attachments = FeedbackRepository::find_attachments(&pool, updated.id).await?;
    Ok(success(updated.to_admin_detail(attachments), request_id))
}

/// POST /v1/admin/feedback/{id}/archive
///
/// Move a single feedback row out of `feedback` and into
/// `feedback_archive` (BUNYIP-93). The same end-state the batch
/// 90-day `archive_and_purge_closed` job produces, but on demand.
/// Restore happens through the existing
/// `POST /admin/feedback/archive/{archive_id}/restore` route.
pub async fn archive_feedback(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let feedback_id = path.into_inner();

    // DEV-516: shared repository returns `false` when no row matched.
    if !FeedbackRepository::archive_one(&pool, feedback_id).await? {
        return Err(AppError::not_found("Feedback"));
    }

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::FeedbackArchived)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("feedback", feedback_id),
    )
    .await?;

    Ok(success(serde_json::json!({}), request_id))
}

/// POST /v1/admin/feedback/{id}/unmark-spam
///
/// Reverse `mark_feedback_spam`. False-positive recovery for the case
/// where the admin flagged a real row by mistake.
pub async fn unmark_feedback_spam(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let feedback_id = path.into_inner();

    let updated = FeedbackRepository::set_is_spam(&pool, feedback_id, false).await?;

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::FeedbackUnmarkedSpam)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("feedback", feedback_id),
    )
    .await?;

    let attachments = FeedbackRepository::find_attachments(&pool, updated.id).await?;
    Ok(success(updated.to_admin_detail(attachments), request_id))
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_opt(value: &Option<String>) -> String {
    value.as_deref().map(csv_field).unwrap_or_default()
}

pub async fn export_feedback(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let feedback = FeedbackRepository::list_all(&pool).await?;

    let mut csv = String::from(
        "id,name,email,subject,tags,message,page_path,status,admin_response,responded_at,is_spam,created_at,updated_at\r\n",
    );

    for item in &feedback {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{}\r\n",
            item.id,
            csv_opt(&item.name),
            csv_opt(&item.email),
            csv_opt(&item.subject),
            csv_field(&item.tags.join("|")),
            csv_field(&item.message),
            csv_opt(&item.page_path),
            csv_field(&item.status),
            csv_opt(&item.admin_response),
            item.responded_at
                .map(|t| t.to_rfc3339())
                .unwrap_or_default(),
            item.is_spam,
            item.created_at.to_rfc3339(),
            item.updated_at.to_rfc3339(),
        ));
    }

    Ok(HttpResponse::Ok()
        .content_type("text/csv; charset=utf-8")
        .insert_header((
            "Content-Disposition",
            "attachment; filename=\"feedback.csv\"",
        ))
        .insert_header(("x-request-id", request_id))
        .body(csv))
}

#[derive(Debug, Deserialize)]
pub struct ListArchiveQuery {
    pub page: Option<i32>,
    pub per_page: Option<i32>,
}

pub async fn list_feedback_archive(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    query: web::Query<ListArchiveQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);

    let (items, total) = FeedbackRepository::list_archived(&pool, page, per_page).await?;

    Ok(paginated(items, total, page, per_page, request_id))
}

pub async fn restore_feedback(
    req: HttpRequest,
    admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<uuid::Uuid>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let archive_id = path.into_inner();

    let feedback = FeedbackRepository::restore_from_archive(&pool, archive_id).await?;

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::FeedbackRestored)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("feedback", feedback.id),
    )
    .await?;

    let attachments = FeedbackRepository::find_attachments(&pool, feedback.id).await?;
    Ok(success(feedback.to_admin_detail(attachments), request_id))
}

pub async fn get_attachment(
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    path: web::Path<(uuid::Uuid, uuid::Uuid)>,
) -> Result<HttpResponse, AppError> {
    let (feedback_id, attachment_id) = path.into_inner();

    let (meta, data) = FeedbackRepository::get_attachment_data(&pool, attachment_id)
        .await?
        .ok_or_else(|| AppError::not_found("Attachment"))?;

    if meta.feedback_id != feedback_id {
        return Err(AppError::not_found("Attachment"));
    }

    let disposition = format!(
        "inline; filename=\"{}\"",
        meta.filename.replace('"', "\\\"")
    );

    Ok(HttpResponse::Ok()
        .content_type(meta.mime_type.clone())
        .insert_header(("Content-Disposition", disposition))
        .body(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    // BUNYIP-270: the admin feedback notification + email must fire only for
    // rows that reach the Active triage queue. The Active tab list query
    // filters `is_spam = FALSE`, so spam is invisible there; pinging admins
    // about it reproduced "received the email, opened /admin/feedback, saw
    // nothing". These guard the notify-decision against regressing back to
    // an unconditional ping.
    #[test]
    fn notifies_admins_for_non_spam_feedback() {
        assert!(should_notify_admins_of_feedback(false));
    }

    #[test]
    fn suppresses_admin_notification_for_spam_feedback() {
        assert!(!should_notify_admins_of_feedback(true));
    }

    // -- BUNYIP-411: request metadata capture --------------------------------

    use std::net::IpAddr;

    #[test]
    fn bounded_user_agent_trims_blanks_and_caps_length() {
        assert_eq!(bounded_user_agent(None), None);
        assert_eq!(bounded_user_agent(Some("   ")), None);
        assert_eq!(
            bounded_user_agent(Some("  Mozilla/5.0  ")),
            Some("Mozilla/5.0".to_string())
        );
        let long = "a".repeat(500);
        assert_eq!(
            bounded_user_agent(Some(&long)).unwrap().chars().count(),
            256
        );
    }

    #[test]
    fn audit_metadata_carries_ip_and_user_agent() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let meta =
            feedback_audit_metadata("new", true, Some("/pricing"), Some(ip), Some("Mozilla/5.0"));
        assert_eq!(meta["ip"], "203.0.113.7");
        assert_eq!(meta["user_agent"], "Mozilla/5.0");
        assert_eq!(meta["status"], "new");
        assert_eq!(meta["has_email"], true);
        assert_eq!(meta["page_path"], "/pricing");
    }

    #[test]
    fn audit_metadata_omits_absent_ip_and_user_agent() {
        let meta = feedback_audit_metadata("new", false, None, None, None);
        assert!(meta["ip"].is_null());
        assert!(meta["user_agent"].is_null());
        assert!(meta["page_path"].is_null());
    }

    /// Behind a trusted proxy the handler passes the resolved EXTERNAL client
    /// IP (from `extract_client_ip`, whose trusted-proxy resolution is proven by
    /// `client_ip_uses_forwarded_for_when_peer_is_trusted_proxy` in the
    /// bunyip-domain middleware and `resolve_forwarded_ip` in bunyip-web). This
    /// asserts that resolved external IP - never the Docker-internal peer - is
    /// what lands in the recorded metadata.
    #[test]
    fn metadata_captures_external_ip_behind_trusted_proxy() {
        // The value `extract_client_ip` yields for a request forwarded by the
        // trusted proxy (first X-Forwarded-For entry), not the internal peer.
        let external: IpAddr = "203.0.113.7".parse().unwrap();
        let internal: IpAddr = "10.1.2.3".parse().unwrap();
        let meta = feedback_audit_metadata("new", false, None, Some(external), None);
        assert_eq!(meta["ip"], "203.0.113.7");
        assert_ne!(
            meta["ip"],
            internal.to_string(),
            "must record the external client IP, not the internal proxy peer"
        );
    }
}
