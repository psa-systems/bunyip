//! Feedback handlers

use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use serde::Deserialize;
use sqlx::PgPool;
use std::collections::HashSet;
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
    AuditLogRepository, FeedbackRepository, NotificationRepository, RateLimitRepository,
    UserRepository,
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
    let config = RateLimitConfig {
        action: "feedback_submit",
        max_requests: 5,
        window_seconds: 3600,
    };
    let (_count, exceeded) = RateLimitRepository::check_and_increment(pool, key, &config).await?;
    if exceeded {
        let retry_after = RateLimitRepository::get_retry_after(pool, key, &config).await?;
        return Err(AppError::RateLimited { retry_after });
    }
    Ok(())
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
            // File field
            if attachment_parts.len() >= MAX_ATTACHMENTS {
                return Err(AppError::validation(
                    "attachment",
                    "Maximum 3 attachments allowed",
                ));
            }
            let mime = field
                .content_type()
                .map(|m| m.to_string())
                .unwrap_or_else(|| "application/octet-stream".to_string());
            if !ALLOWED_MIME_TYPES.contains(&mime.as_str()) {
                return Err(AppError::validation(
                    "attachment",
                    "Only PNG, JPEG, WebP, GIF, and plain text files are allowed",
                ));
            }
            // Sanitize filename: keep only the basename, strip path separators
            let safe_name = std::path::Path::new(&fname)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("attachment")
                .to_string();
            attachment_parts.push((safe_name, mime, bytes));
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
        },
    )
    .await?;

    if !attachment_parts.is_empty() {
        FeedbackRepository::save_attachments(&pool, feedback.id, attachment_parts).await?;
    }

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::FeedbackSubmitted)
            .with_resource("feedback", feedback.id)
            .with_metadata(serde_json::json!({
                "status": feedback.status.clone(),
                "has_email": feedback.email.is_some(),
                "page_path": feedback.page_path.clone(),
            })),
    )
    .await?;

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
    pub page_size: Option<i32>,
    pub status: Option<String>,
}

pub async fn list_feedback(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    query: web::Query<ListFeedbackQuery>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.or(query.page_size).unwrap_or(20).min(100);

    if let Some(status) = query.status.as_deref() {
        FeedbackStatus::from_str(status)
            .ok_or_else(|| AppError::validation("status", "Invalid feedback status"))?;
    }

    let (feedback, total) =
        FeedbackRepository::list_paginated(&pool, page, per_page, query.status.as_deref()).await?;

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
                .ok_or_else(|| AppError::validation("status", "Invalid feedback status"))
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
        let email_svc = email_service.get_ref().clone();
        let detail = updated.clone();
        tokio::spawn(async move {
            if let Err(e) = email_svc.send_feedback_response(&email, &detail).await {
                tracing::error!(error = %e, feedback_id = %detail.id, "Failed to send feedback response email");
            }
        });
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
        .ok_or_else(|| AppError::validation("status", "Invalid feedback status"))?;

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

    FeedbackRepository::delete(&pool, feedback_id).await?;

    AuditLogRepository::create(
        &pool,
        CreateAuditLog::new(AuditAction::FeedbackDeleted)
            .with_actor(admin.0.sub, &admin.0.email, &admin.0.role)
            .with_resource("feedback", feedback_id),
    )
    .await?;

    Ok(success(serde_json::json!({}), request_id))
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
    let _ = get_request_id(&req);
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
