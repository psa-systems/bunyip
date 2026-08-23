//! Send-only mailer relay for the other apps in the suite (BUNYIP-602).
//!
//! Bunyip owns one verified sending domain (DKIM/SPF/DMARC configured on the
//! address in `EmailConfig::from_email`), so an app that relays through here
//! inherits that deliverability instead of holding its own SMTP credentials.
//! The caller supplies only the recipient, the subject and the body; the
//! sending identity is always this deployment's.
//!
//! The suppression check runs BEFORE anything is handed to the transport.
//! Today the list is empty ([`NoSuppression`]); BUNYIP-603 feeds it from
//! bounce/complaint webhooks and only has to swap the implementation wired in
//! `main.rs`, not restructure this path.

use std::sync::Arc;

use async_trait::async_trait;

use crate::errors::AppError;
use crate::services::EmailService;

/// Longest accepted subject. RFC 5322 §2.1.1 caps an unfolded header line at
/// 998 octets; the rest of the line is the `Subject: ` prefix.
pub const MAX_SUBJECT_LEN: usize = 900;

/// Longest accepted body, per part. Bounds what one relayed request can push
/// through the transport; well above any transactional message.
pub const MAX_BODY_LEN: usize = 256 * 1024;

/// Longest accepted recipient address (RFC 5321 §4.5.3.1.3).
pub const MAX_ADDRESS_LEN: usize = 256;

/// A validated, compose-ready message accepted by the relay.
///
/// Constructing one is the only way to reach [`MailerRelay::relay`], so every
/// relayed message has been through [`RelayMessage::new`]'s checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMessage {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
}

impl RelayMessage {
    /// Validate a caller-supplied message.
    ///
    /// Rejects header injection outright: a CR or LF anywhere in the recipient
    /// or the subject would let a caller append its own headers (a second
    /// `Bcc:`, a forged `From:`) to a message sent from Bunyip's own verified
    /// domain, so those characters are refused rather than stripped.
    pub fn new(to: &str, subject: &str, text: &str, html: Option<&str>) -> Result<Self, AppError> {
        let to = to.trim();
        let subject = subject.trim();

        if to.is_empty() {
            return Err(AppError::validation(
                "to",
                "A recipient address is required",
            ));
        }
        if to.len() > MAX_ADDRESS_LEN {
            return Err(AppError::validation(
                "to",
                format!("Recipient address exceeds {MAX_ADDRESS_LEN} characters"),
            ));
        }
        if has_header_break(to) {
            return Err(AppError::validation(
                "to",
                "Recipient address must not contain line breaks",
            ));
        }
        // One recipient per request: the relay is transactional, and a comma
        // list would let one call fan out to an address set the audit line does
        // not name.
        if to.contains(',') {
            return Err(AppError::validation(
                "to",
                "Exactly one recipient address per request",
            ));
        }

        if subject.is_empty() {
            return Err(AppError::validation("subject", "A subject is required"));
        }
        if subject.chars().count() > MAX_SUBJECT_LEN {
            return Err(AppError::validation(
                "subject",
                format!("Subject exceeds {MAX_SUBJECT_LEN} characters"),
            ));
        }
        if has_header_break(subject) {
            return Err(AppError::validation(
                "subject",
                "Subject must not contain line breaks",
            ));
        }

        if text.trim().is_empty() {
            return Err(AppError::validation(
                "text",
                "A plain-text body is required",
            ));
        }
        if text.len() > MAX_BODY_LEN {
            return Err(AppError::validation(
                "text",
                format!("Body exceeds {MAX_BODY_LEN} bytes"),
            ));
        }
        if let Some(html) = html {
            if html.len() > MAX_BODY_LEN {
                return Err(AppError::validation(
                    "html",
                    format!("HTML body exceeds {MAX_BODY_LEN} bytes"),
                ));
            }
        }

        Ok(Self {
            to: to.to_string(),
            subject: subject.to_string(),
            text: text.to_string(),
            html: html.filter(|h| !h.trim().is_empty()).map(str::to_string),
        })
    }
}

/// Whether `value` carries a CR or LF, i.e. can break out of its header.
fn has_header_break(value: &str) -> bool {
    value.contains('\r') || value.contains('\n')
}

/// What the relay did with a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Handed to the transport; carries the bare Message-ID.
    Sent { message_id: String },
    /// Not sent: the recipient is on the suppression list.
    Suppressed,
}

/// Addresses the relay must not send to.
///
/// The seam BUNYIP-603 fills: it replaces the wiring in `main.rs` with a
/// bounce/complaint-fed implementation and touches nothing else in this path.
#[async_trait]
pub trait SuppressionList: Send + Sync {
    /// Whether `address` must not be relayed to. An error here is NOT a
    /// suppression decision: the caller surfaces it rather than guessing, so a
    /// broken list never silently turns into "send everything".
    async fn is_suppressed(&self, address: &str) -> Result<bool, AppError>;
}

/// The list until BUNYIP-603 lands: nothing is suppressed.
pub struct NoSuppression;

#[async_trait]
impl SuppressionList for NoSuppression {
    async fn is_suppressed(&self, _address: &str) -> Result<bool, AppError> {
        Ok(false)
    }
}

/// The relay: suppression check, then hand off to the SMTP transport.
pub struct MailerRelay {
    email: Arc<EmailService>,
    suppression: Arc<dyn SuppressionList>,
}

impl MailerRelay {
    pub fn new(email: Arc<EmailService>, suppression: Arc<dyn SuppressionList>) -> Self {
        Self { email, suppression }
    }

    /// Relay `message` on behalf of `client_name`, which is logged so a
    /// delivery can be attributed to the app that asked for it.
    pub async fn relay(
        &self,
        message: &RelayMessage,
        client_name: &str,
    ) -> Result<RelayOutcome, AppError> {
        if self.suppression.is_suppressed(&message.to).await? {
            tracing::warn!(
                client = %client_name,
                "mailer relay skipped: recipient is suppressed"
            );
            return Ok(RelayOutcome::Suppressed);
        }

        let message_id = self
            .email
            .send_relay(
                &message.to,
                &message.subject,
                &message.text,
                message.html.as_deref(),
            )
            .await?;

        tracing::info!(
            client = %client_name,
            message_id = %message_id,
            "mailer relay delivered a message"
        );
        Ok(RelayOutcome::Sent { message_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EmailConfig, SmtpTls};

    fn relay_config() -> EmailConfig {
        EmailConfig {
            smtp_host: "smtp.example.test".to_string(),
            smtp_port: 587,
            smtp_tls: SmtpTls::Starttls,
            smtp_username: "relay".to_string(),
            smtp_password: "pw".to_string(),
            smtp_ehlo_name: None,
            from_email: "noreply@mail.a8n.systems".to_string(),
            from_name: "PSA Systems".to_string(),
            base_url: "https://a8n.systems".to_string(),
            enabled: true,
            log_tokens: false,
            app_name: "PSA Systems".to_string(),
            admin_notification_emails: Vec::new(),
            support_inbox_email: None,
            imap_host: String::new(),
            imap_port: 993,
            imap_username: String::new(),
            imap_mailbox: "INBOX".to_string(),
            imap_enabled: false,
            imap_poll_secs: 60,
        }
    }

    /// Everything on the suppression list.
    struct SuppressAll;

    #[async_trait]
    impl SuppressionList for SuppressAll {
        async fn is_suppressed(&self, _address: &str) -> Result<bool, AppError> {
            Ok(true)
        }
    }

    /// A list that cannot answer.
    struct BrokenList;

    #[async_trait]
    impl SuppressionList for BrokenList {
        async fn is_suppressed(&self, _address: &str) -> Result<bool, AppError> {
            Err(AppError::internal("suppression store unavailable"))
        }
    }

    fn relay_with(
        config: EmailConfig,
        suppression: Arc<dyn SuppressionList>,
    ) -> (MailerRelay, lettre::transport::stub::AsyncStubTransport) {
        let (email, stub) = EmailService::new_capturing(config);
        (MailerRelay::new(Arc::new(email), suppression), stub)
    }

    #[tokio::test]
    async fn a_relayed_message_reaches_the_transport_from_bunyips_sending_identity() {
        let (relay, stub) = relay_with(relay_config(), Arc::new(NoSuppression));
        let message = RelayMessage::new(
            "member@customer.test",
            "Your ticket was updated",
            "Ticket 42 moved to In Progress.",
            None,
        )
        .expect("valid message");

        let outcome = relay.relay(&message, "mokosh-server").await.expect("relay");
        let RelayOutcome::Sent { message_id } = outcome else {
            panic!("expected the message to be sent");
        };

        let sent = stub.messages().await;
        assert_eq!(sent.len(), 1, "exactly one message reached the transport");
        let (envelope, raw) = &sent[0];
        assert_eq!(
            envelope.to().len(),
            1,
            "the envelope carries the one recipient"
        );
        assert_eq!(envelope.to()[0].to_string(), "member@customer.test");
        // The envelope sender is Bunyip's verified sending address, never
        // anything the calling app supplied.
        assert_eq!(
            envelope.from().map(|a| a.to_string()).as_deref(),
            Some("noreply@mail.a8n.systems")
        );
        assert!(raw.contains("From: \"PSA Systems\" <noreply@mail.a8n.systems>"));
        assert!(raw.contains("Ticket 42 moved to In Progress."));
        assert!(
            message_id.ends_with("@mail.a8n.systems"),
            "the Message-ID domain aligns with the From domain: {message_id}"
        );
    }

    #[tokio::test]
    async fn an_html_body_is_relayed_as_the_alternative_part() {
        let (relay, stub) = relay_with(relay_config(), Arc::new(NoSuppression));
        let message = RelayMessage::new(
            "member@customer.test",
            "Invoice ready",
            "Invoice 7 is ready.",
            Some("<p>Invoice 7 is ready.</p>"),
        )
        .expect("valid message");

        relay.relay(&message, "mokosh-server").await.expect("relay");

        let sent = stub.messages().await;
        let raw = &sent[0].1;
        assert!(raw.contains("multipart/alternative"));
        assert!(raw.contains("<p>Invoice 7 is ready.</p>"));
    }

    #[tokio::test]
    async fn a_suppressed_recipient_is_never_handed_to_the_transport() {
        let (relay, stub) = relay_with(relay_config(), Arc::new(SuppressAll));
        let message =
            RelayMessage::new("bounced@customer.test", "Hello", "Body", None).expect("valid");

        let outcome = relay.relay(&message, "mokosh-server").await.expect("relay");
        assert_eq!(outcome, RelayOutcome::Suppressed);
        assert!(
            stub.messages().await.is_empty(),
            "a suppressed recipient reaches no transport"
        );
    }

    #[tokio::test]
    async fn an_unreadable_suppression_list_fails_the_send_rather_than_relaying() {
        let (relay, stub) = relay_with(relay_config(), Arc::new(BrokenList));
        let message = RelayMessage::new("member@customer.test", "Hello", "Body", None).expect("ok");

        let err = relay
            .relay(&message, "mokosh-server")
            .await
            .expect_err("a list that cannot answer must not be read as 'not suppressed'");
        assert!(matches!(err, AppError::InternalError { .. }));
        assert!(stub.messages().await.is_empty());
    }

    #[tokio::test]
    async fn a_deployment_without_smtp_reports_a_failure_instead_of_a_silent_drop() {
        let mut config = relay_config();
        config.enabled = false;
        let (email, _stub) = EmailService::new_capturing(config);
        let relay = MailerRelay::new(Arc::new(email), Arc::new(NoSuppression));
        let message = RelayMessage::new("member@customer.test", "Hello", "Body", None).expect("ok");

        let err = relay
            .relay(&message, "mokosh-server")
            .await
            .expect_err("an unconfigured relay must not answer success");
        assert!(matches!(err, AppError::Upstream { .. }));
    }

    #[test]
    fn header_injection_is_refused_in_the_recipient_and_the_subject() {
        for to in [
            "victim@customer.test\nBcc: everyone@customer.test",
            "victim@customer.test\r\nBcc: everyone@customer.test",
        ] {
            assert!(
                RelayMessage::new(to, "Subject", "Body", None).is_err(),
                "a line break in the recipient must be refused: {to:?}"
            );
        }
        assert!(RelayMessage::new(
            "member@customer.test",
            "Hello\r\nBcc: everyone@customer.test",
            "Body",
            None,
        )
        .is_err());
    }

    #[test]
    fn empty_and_oversized_fields_are_refused() {
        assert!(RelayMessage::new("  ", "Subject", "Body", None).is_err());
        assert!(RelayMessage::new("member@customer.test", " ", "Body", None).is_err());
        assert!(RelayMessage::new("member@customer.test", "Subject", "  ", None).is_err());
        assert!(RelayMessage::new(
            "member@customer.test",
            &"s".repeat(MAX_SUBJECT_LEN + 1),
            "Body",
            None,
        )
        .is_err());
        assert!(RelayMessage::new(
            "member@customer.test",
            "Subject",
            &"b".repeat(MAX_BODY_LEN + 1),
            None,
        )
        .is_err());
        assert!(RelayMessage::new(
            "member@customer.test",
            "Subject",
            "Body",
            Some(&"h".repeat(MAX_BODY_LEN + 1)),
        )
        .is_err());
        assert!(RelayMessage::new(
            "one@customer.test,two@customer.test",
            "Subject",
            "Body",
            None,
        )
        .is_err());
    }

    #[test]
    fn a_blank_html_body_is_treated_as_absent() {
        let message =
            RelayMessage::new("member@customer.test", "Subject", "Body", Some("   ")).expect("ok");
        assert_eq!(message.html, None);
    }

    #[tokio::test]
    async fn an_unparseable_recipient_fails_before_the_transport() {
        // `RelayMessage` bounds shape and length; address syntax is lettre's
        // call, and it must surface as a 400-shaped validation error rather
        // than a 500.
        let (relay, stub) = relay_with(relay_config(), Arc::new(NoSuppression));
        let message = RelayMessage::new("not-an-address", "Subject", "Body", None).expect("shaped");
        let err = relay
            .relay(&message, "mokosh-server")
            .await
            .expect_err("an unparseable address cannot be relayed");
        assert!(matches!(err, AppError::ValidationError { .. }));
        assert!(stub.messages().await.is_empty());
    }
}
