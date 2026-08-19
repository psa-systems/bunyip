//! Support-queue handlers (BUNYIP-571): the app-composed threaded reply.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;

use crate::config::Config;
use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::models::{MessageDirection, NewMessage, TicketStatus};
use crate::repositories::SupportRepository;
use crate::responses::{get_request_id, success};
use crate::services::EmailService;

/// The admin's reply body for a support ticket.
#[derive(Debug, Deserialize)]
pub struct SupportReplyRequest {
    pub message: String,
}

/// Strip the angle brackets from stored Message-IDs (they are kept bare so
/// inbound, header and sent ids all compare in one form).
fn strip_brackets(id: &str) -> String {
    id.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

/// POST /v1/admin/support/tickets/{id}/reply
///
/// Send an app-composed reply to the ticket's requester, threaded onto the
/// latest message via In-Reply-To / References, and record it as an outbound
/// support message. Moves the ticket to `pending` (awaiting the requester).
pub async fn reply_to_support_ticket(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    email_service: web::Data<Arc<EmailService>>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<SupportReplyRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ticket_id = path.into_inner();
    let message = body.message.trim().to_string();
    if message.is_empty() {
        return Err(AppError::validation(
            "message",
            "A reply message is required",
        ));
    }

    let ticket = SupportRepository::get_ticket(&pool, ticket_id)
        .await?
        .ok_or_else(|| AppError::not_found("Support ticket not found"))?;

    // Thread onto the latest message: In-Reply-To its id, References its chain
    // plus itself. Stored ids are bare; the mail headers use the <...> form.
    let latest = SupportRepository::latest_message(&pool, ticket_id).await?;
    let in_reply_to = latest
        .as_ref()
        .and_then(|m| m.message_id.as_deref())
        .map(|id| format!("<{}>", id));
    let references = latest
        .as_ref()
        .map(|m| {
            let mut ids: Vec<String> = Vec::new();
            if let Some(refs) = &m.mail_references {
                ids.extend(refs.split_whitespace().map(|s| format!("<{}>", s)));
            }
            if let Some(id) = &m.message_id {
                ids.push(format!("<{}>", id));
            }
            ids.join(" ")
        })
        .filter(|s| !s.is_empty());

    let subject = if ticket.subject.to_lowercase().starts_with("re:") {
        ticket.subject.clone()
    } else {
        format!("Re: {}", ticket.subject)
    };

    let sent_id = email_service
        .send_support_reply(
            &ticket.requester_email,
            &subject,
            &message,
            in_reply_to,
            references.clone(),
        )
        .await?;

    // Record the outbound message (bare ids) and move the ticket to pending.
    let stored_in_reply_to = latest.as_ref().and_then(|m| m.message_id.clone());
    let stored_references = references.map(|r| {
        r.split_whitespace()
            .map(strip_brackets)
            .collect::<Vec<_>>()
            .join(" ")
    });
    SupportRepository::add_message(
        &pool,
        ticket_id,
        &NewMessage {
            direction: MessageDirection::Outbound,
            from_email: config.email.from_email.clone(),
            to_email: Some(ticket.requester_email.clone()),
            body_text: message,
            body_html: None,
            message_id: Some(sent_id),
            in_reply_to: stored_in_reply_to,
            mail_references: stored_references,
        },
    )
    .await?;
    SupportRepository::set_status(&pool, ticket_id, TicketStatus::Pending).await?;

    Ok(success(serde_json::json!({ "status": "sent" }), request_id))
}
