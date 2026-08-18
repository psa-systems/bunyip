//! Support queue: tickets and their threaded messages (BUNYIP-571).
//!
//! A [`SupportTicket`] is one conversation with an external sender; each
//! [`SupportMessage`] is an inbound reply from that sender or an outbound reply
//! composed in the app, threaded by mail Message-ID. Storage only: the IMAP
//! poller (slice 3) produces [`NewInboundMessage`], the app-composed reply
//! (slice 4) produces a [`NewMessage`], and the admin surface is BUNYIP-572.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Lifecycle of a support ticket, stored as the lowercase VARCHAR in
/// `support_tickets.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    /// Awaiting a reply from the team.
    Open,
    /// Replied to; awaiting the requester.
    Pending,
    /// Resolved.
    Closed,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TicketStatus::Open => "open",
            TicketStatus::Pending => "pending",
            TicketStatus::Closed => "closed",
        }
    }

    /// Parse a stored value; an unknown string falls back to `Open` so a row is
    /// never undisplayable.
    pub fn from_str_lenient(s: &str) -> Self {
        match s {
            "pending" => TicketStatus::Pending,
            "closed" => TicketStatus::Closed,
            _ => TicketStatus::Open,
        }
    }
}

/// Which way a message flowed: an inbound reply from the requester, or an
/// outbound reply composed in the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    Inbound,
    Outbound,
}

impl MessageDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            MessageDirection::Inbound => "inbound",
            MessageDirection::Outbound => "outbound",
        }
    }
}

/// One support conversation with an external sender. `status` is the raw
/// column; interpret it through [`TicketStatus::from_str_lenient`].
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SupportTicket {
    pub id: Uuid,
    pub subject: String,
    pub requester_email: String,
    pub requester_name: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_message_at: DateTime<Utc>,
}

/// One message in a ticket thread (an inbound reply or an app-composed reply).
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SupportMessage {
    pub id: Uuid,
    pub ticket_id: Uuid,
    pub direction: String,
    pub from_email: String,
    pub to_email: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub mail_references: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// A parsed inbound message ready to ingest, produced by the IMAP poller
/// (slice 3). `references` is the split References chain; the repository joins
/// it for storage and uses it (with `in_reply_to`) to thread onto a ticket.
#[derive(Debug, Clone)]
pub struct NewInboundMessage {
    pub subject: String,
    pub from_email: String,
    pub from_name: Option<String>,
    pub to_email: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
}

/// Fields for inserting one message onto an existing ticket. Built by the
/// ingest path from a [`NewInboundMessage`], and by the reply endpoint
/// (slice 4) for an outbound message.
#[derive(Debug, Clone)]
pub struct NewMessage {
    pub direction: MessageDirection,
    pub from_email: String,
    pub to_email: Option<String>,
    pub body_text: String,
    pub body_html: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub mail_references: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_status_round_trips_and_defaults_open() {
        for status in [
            TicketStatus::Open,
            TicketStatus::Pending,
            TicketStatus::Closed,
        ] {
            assert_eq!(TicketStatus::from_str_lenient(status.as_str()), status);
        }
        assert_eq!(
            TicketStatus::from_str_lenient("nonsense"),
            TicketStatus::Open,
            "an unknown stored status is displayable as Open"
        );
    }

    #[test]
    fn message_direction_as_str() {
        assert_eq!(MessageDirection::Inbound.as_str(), "inbound");
        assert_eq!(MessageDirection::Outbound.as_str(), "outbound");
    }
}
