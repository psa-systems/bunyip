//! Support queue repository (BUNYIP-571). Storage for mail-sourced support
//! tickets and their threaded messages; the inbound poller (slice 3) and the
//! app-composed reply (slice 4) are the callers.

use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{
    MessageDirection, NewInboundMessage, NewMessage, SupportMessage, SupportTicket, TicketStatus,
};

pub struct SupportRepository;

impl SupportRepository {
    /// Open a new ticket in the `open` state.
    pub async fn create_ticket(
        pool: &PgPool,
        subject: &str,
        requester_email: &str,
        requester_name: Option<&str>,
    ) -> Result<SupportTicket, AppError> {
        let ticket = sqlx::query_as::<_, SupportTicket>(
            r#"
            INSERT INTO support_tickets (subject, requester_email, requester_name, status)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(subject)
        .bind(requester_email)
        .bind(requester_name)
        .bind(TicketStatus::Open.as_str())
        .fetch_one(pool)
        .await?;
        Ok(ticket)
    }

    /// Append a message to a ticket and bump its activity timestamps in one
    /// transaction, so `last_message_at` can never drift from the message set.
    pub async fn add_message(
        pool: &PgPool,
        ticket_id: Uuid,
        msg: &NewMessage,
    ) -> Result<SupportMessage, AppError> {
        let mut tx = pool.begin().await?;
        let message = sqlx::query_as::<_, SupportMessage>(
            r#"
            INSERT INTO support_messages
                (ticket_id, direction, from_email, to_email, body_text, body_html,
                 message_id, in_reply_to, mail_references)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(ticket_id)
        .bind(msg.direction.as_str())
        .bind(&msg.from_email)
        .bind(msg.to_email.as_deref())
        .bind(&msg.body_text)
        .bind(msg.body_html.as_deref())
        .bind(msg.message_id.as_deref())
        .bind(msg.in_reply_to.as_deref())
        .bind(msg.mail_references.as_deref())
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE support_tickets
            SET last_message_at = NOW(), updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(ticket_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(message)
    }

    /// Find the ticket a reply belongs to by matching any candidate mail
    /// Message-ID (the reply's `In-Reply-To` plus its `References` chain) against
    /// a message already stored. Returns the newest match's ticket, or `None`
    /// when nothing threads.
    pub async fn find_ticket_by_message_ids(
        pool: &PgPool,
        candidate_ids: &[String],
    ) -> Result<Option<Uuid>, AppError> {
        if candidate_ids.is_empty() {
            return Ok(None);
        }
        let row: Option<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT ticket_id
            FROM support_messages
            WHERE message_id = ANY($1)
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(candidate_ids)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|r| r.0))
    }

    /// Ingest a parsed inbound message: thread it onto the ticket its headers
    /// point at, or open a new ticket when nothing matches. Returns the ticket
    /// the message landed on.
    pub async fn ingest_inbound(
        pool: &PgPool,
        msg: &NewInboundMessage,
    ) -> Result<SupportTicket, AppError> {
        // In-Reply-To (the direct parent) first, then the References chain.
        let mut candidates: Vec<String> = Vec::new();
        if let Some(irt) = &msg.in_reply_to {
            candidates.push(irt.clone());
        }
        candidates.extend(msg.references.iter().cloned());

        let ticket = match Self::find_ticket_by_message_ids(pool, &candidates).await? {
            Some(ticket_id) => Self::get_ticket(pool, ticket_id)
                .await?
                .ok_or_else(|| AppError::internal("matched support ticket vanished"))?,
            None => {
                Self::create_ticket(
                    pool,
                    &msg.subject,
                    &msg.from_email,
                    msg.from_name.as_deref(),
                )
                .await?
            }
        };

        let mail_references = if msg.references.is_empty() {
            None
        } else {
            Some(msg.references.join(" "))
        };
        Self::add_message(
            pool,
            ticket.id,
            &NewMessage {
                direction: MessageDirection::Inbound,
                from_email: msg.from_email.clone(),
                to_email: msg.to_email.clone(),
                body_text: msg.body_text.clone(),
                body_html: msg.body_html.clone(),
                message_id: msg.message_id.clone(),
                in_reply_to: msg.in_reply_to.clone(),
                mail_references,
            },
        )
        .await?;

        Ok(ticket)
    }

    /// Fetch a ticket by id.
    pub async fn get_ticket(pool: &PgPool, id: Uuid) -> Result<Option<SupportTicket>, AppError> {
        let ticket =
            sqlx::query_as::<_, SupportTicket>("SELECT * FROM support_tickets WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await?;
        Ok(ticket)
    }

    /// All messages on a ticket, oldest first (thread order).
    pub async fn list_messages(
        pool: &PgPool,
        ticket_id: Uuid,
    ) -> Result<Vec<SupportMessage>, AppError> {
        let messages = sqlx::query_as::<_, SupportMessage>(
            r#"
            SELECT * FROM support_messages
            WHERE ticket_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(ticket_id)
        .fetch_all(pool)
        .await?;
        Ok(messages)
    }

    /// Tickets by most recent activity, for the admin queue (BUNYIP-572).
    pub async fn list_tickets(
        pool: &PgPool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SupportTicket>, AppError> {
        let tickets = sqlx::query_as::<_, SupportTicket>(
            r#"
            SELECT * FROM support_tickets
            ORDER BY last_message_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        Ok(tickets)
    }

    /// Change a ticket's status.
    pub async fn set_status(pool: &PgPool, id: Uuid, status: TicketStatus) -> Result<(), AppError> {
        sqlx::query("UPDATE support_tickets SET status = $1, updated_at = NOW() WHERE id = $2")
            .bind(status.as_str())
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
