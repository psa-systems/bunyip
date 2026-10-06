//! Send-only mailer relay for the other apps in the suite (BUNYIP-602).
//!
//! Bunyip owns one verified sending domain (DKIM/SPF/DMARC configured on the
//! address in `EmailConfig::from_email`), so an app that relays through here
//! inherits that deliverability instead of holding its own SMTP credentials.
//! The caller supplies only the recipient, the subject and the body; the
//! sending identity is always this deployment's.
//!
//! The suppression check runs BEFORE anything is handed to the transport. The
//! list is the shared `mailer_suppressions` table ([`DbSuppressionList`]), fed
//! by the bounce/complaint feedback webhook (BUNYIP-603).
//!
//! The suppression trait, the reason enum, the no-suppression zero-impl, the
//! validated `RelayMessage` type and the outcome enum now live in the shared
//! `dunite_mailer` leaf (DUNITE-24). This file keeps the two pieces that tie
//! those generic primitives to bunyip's own transport and schema:
//!
//! - [`DbSuppressionList`] - adapter that implements `dunite_mailer::SuppressionList`
//!   over `MailerSuppressionRepository` on the `mailer_suppressions` table.
//! - [`MailerRelay`] - the three-line orchestration that composes the trait
//!   with `EmailService::send_relay`.

use std::sync::Arc;

use async_trait::async_trait;
use dunite_mailer::{
    RelayMessage, RelayOutcome, SuppressionError, SuppressionList, SuppressionReason,
};
use sqlx::PgPool;

use crate::errors::AppError;
use crate::repositories::MailerSuppressionRepository;
use crate::services::EmailService;

/// The production suppression list: the shared `mailer_suppressions` table.
///
/// Thin adapter around [`MailerSuppressionRepository`]. The repository returns
/// `AppError` for its own admin-surface uses (`count`, `list`, `delete`), and
/// its `is_suppressed` / `upsert` methods stay returning `AppError` because
/// bunyip's own code paths want them that way; this impl adapts those to the
/// leaf-owned [`SuppressionError`] the trait requires (DEV-515). Both halves
/// go through the repository's `normalize_address` so the send-path read and
/// the webhook-path write fold case identically.
pub struct DbSuppressionList {
    pool: PgPool,
}

impl DbSuppressionList {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SuppressionList for DbSuppressionList {
    async fn is_suppressed(&self, address: &str) -> Result<bool, SuppressionError> {
        MailerSuppressionRepository::is_suppressed(&self.pool, address)
            .await
            .map_err(|e| SuppressionError::Unavailable(e.to_string()))
    }

    async fn suppress(
        &self,
        address: &str,
        reason: SuppressionReason,
        detail: Option<&str>,
    ) -> Result<(), SuppressionError> {
        MailerSuppressionRepository::upsert(&self.pool, address, reason.as_str(), detail)
            .await
            .map_err(|e| SuppressionError::Unavailable(e.to_string()))
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
    ///
    /// A broken suppression store surfaces as [`AppError::internal`]: this is
    /// the invariant [`SuppressionList::is_suppressed`] documents (never
    /// silently turn a store failure into "not suppressed"). The three
    /// classified `SuppressionError` variants are collapsed to one internal
    /// error here so no store-shape detail leaks to the caller.
    pub async fn relay(
        &self,
        message: &RelayMessage,
        client_name: &str,
    ) -> Result<RelayOutcome, AppError> {
        let is_suppressed = self
            .suppression
            .is_suppressed(&message.to)
            .await
            .map_err(|e| AppError::internal(format!("Suppression store unavailable: {e}")))?;
        if is_suppressed {
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
    use dunite_mailer::NoSuppression;

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
        async fn is_suppressed(&self, _address: &str) -> Result<bool, SuppressionError> {
            Ok(true)
        }

        async fn suppress(
            &self,
            _address: &str,
            _reason: SuppressionReason,
            _detail: Option<&str>,
        ) -> Result<(), SuppressionError> {
            Ok(())
        }
    }

    /// A list that cannot answer.
    struct BrokenList;

    #[async_trait]
    impl SuppressionList for BrokenList {
        async fn is_suppressed(&self, _address: &str) -> Result<bool, SuppressionError> {
            Err(SuppressionError::Unavailable(
                "suppression store unavailable".to_string(),
            ))
        }

        async fn suppress(
            &self,
            _address: &str,
            _reason: SuppressionReason,
            _detail: Option<&str>,
        ) -> Result<(), SuppressionError> {
            Err(SuppressionError::Unavailable(
                "suppression store unavailable".to_string(),
            ))
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
