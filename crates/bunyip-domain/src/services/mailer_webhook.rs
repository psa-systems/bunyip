//! Inbound bounce/complaint feedback ingestion for the mailer relay (BUNYIP-603).
//!
//! The SMTP provider (or a thin shim that normalizes its payload) POSTs a signed
//! feedback event whenever a relayed message hard-bounces or is marked as spam.
//! Bunyip verifies the signature, then records the recipient on the shared
//! suppression list so the relay (BUNYIP-602) stops sending to it.
//!
//! The signature scheme is the same HMAC-SHA256-hex over the exact body bytes
//! that `dunite_webhook` uses for OUTBOUND dispatches, carried in
//! `X-Webhook-Signature`. Reusing one scheme in both directions means the shared
//! secret and the header contract are identical whichever way a webhook flows.
//!
//! Provider-neutral by design: the wire shape is a normalized
//! `{ "event", "recipient", "detail" }`, not any one vendor's envelope. Which
//! SMTP provider is adopted, and the thin adapter that maps its payload onto
//! this shape, is deliberately out of scope here (the ticket leaves the provider
//! "decided during implementation"); the trust boundary is the signed body.

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::errors::AppError;
use crate::repositories::mailer_suppression::normalize_address;
use crate::services::mailer_relay::{SuppressionList, SuppressionReason, MAX_ADDRESS_LEN};

type HmacSha256 = Hmac<Sha256>;

/// The header carrying the HMAC-SHA256 hex digest of the request body, matching
/// the outbound `dunite_webhook` sender.
pub const SIGNATURE_HEADER: &str = "X-Webhook-Signature";

/// A normalized bounce/complaint feedback event. `event` is `bounce` or
/// `complaint`; `recipient` is the affected address; `detail` is the provider's
/// own description, kept for an operator inspecting the suppression later.
#[derive(Debug, Deserialize)]
pub struct FeedbackEvent {
    pub event: String,
    pub recipient: String,
    #[serde(default)]
    pub detail: Option<String>,
}

/// What an accepted feedback event did, for the caller's audit log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackOutcome {
    /// The normalized address that was suppressed.
    pub address: String,
    pub reason: SuppressionReason,
}

/// Verify an `X-Webhook-Signature` HMAC-SHA256 hex digest over the exact body
/// bytes, in constant time.
///
/// A missing, malformed, or wrong signature is [`AppError::Unauthorized`], never
/// a decision to trust the body. `verify_slice` compares in constant time, so
/// the check leaks nothing about how close a forged signature was.
pub fn verify_signature(secret: &str, body: &[u8], signature_hex: &str) -> Result<(), AppError> {
    let provided = hex::decode(signature_hex.trim()).map_err(|_| AppError::Unauthorized)?;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(body);
    mac.verify_slice(&provided)
        .map_err(|_| AppError::Unauthorized)
}

/// Verify, parse, and apply one signed feedback event: on success the recipient
/// is on the shared suppression list and the returned [`FeedbackOutcome`] names
/// what changed.
///
/// The order is deliberate: the signature is checked BEFORE the body is parsed,
/// so an unauthenticated caller never reaches the parser or the store. A body
/// that verifies but names an unknown event type or a blank recipient is a 400
/// (`ValidationError`), distinct from the 401 an unsigned call gets.
pub async fn ingest_feedback(
    store: &dyn SuppressionList,
    secret: &str,
    body: &[u8],
    signature_hex: &str,
) -> Result<FeedbackOutcome, AppError> {
    verify_signature(secret, body, signature_hex)?;

    let event: FeedbackEvent = serde_json::from_slice(body)
        .map_err(|_| AppError::validation("body", "Invalid feedback event JSON"))?;

    let reason = SuppressionReason::parse(&event.event).ok_or_else(|| {
        AppError::validation(
            "event",
            "Unknown feedback event; expected bounce or complaint",
        )
    })?;

    let address = normalize_address(&event.recipient);
    if address.is_empty() {
        return Err(AppError::validation(
            "recipient",
            "A recipient address is required",
        ));
    }
    if address.len() > MAX_ADDRESS_LEN {
        return Err(AppError::validation(
            "recipient",
            format!("Recipient address exceeds {MAX_ADDRESS_LEN} characters"),
        ));
    }

    store
        .suppress(&address, reason, event.detail.as_deref())
        .await?;

    Ok(FeedbackOutcome { address, reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::mailer_relay::NoSuppression;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory suppression store: the AC's integrated test needs the write and
    /// read halves to share one store without a database (CI runs `--lib` with
    /// no Postgres). Normalizes on both sides exactly as the repository does.
    #[derive(Default)]
    struct MemoryStore {
        entries: Mutex<HashMap<String, SuppressionReason>>,
    }

    #[async_trait]
    impl SuppressionList for MemoryStore {
        async fn is_suppressed(&self, address: &str) -> Result<bool, AppError> {
            Ok(self
                .entries
                .lock()
                .unwrap()
                .contains_key(&normalize_address(address)))
        }

        async fn suppress(
            &self,
            address: &str,
            reason: SuppressionReason,
            _detail: Option<&str>,
        ) -> Result<(), AppError> {
            self.entries
                .lock()
                .unwrap()
                .insert(normalize_address(address), reason);
            Ok(())
        }
    }

    const SECRET: &str = "shared-feedback-secret";

    fn sign(body: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(body.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn a_valid_signature_verifies_and_a_tampered_body_does_not() {
        let body = r#"{"event":"bounce","recipient":"a@b.test"}"#;
        let sig = sign(body);
        assert!(verify_signature(SECRET, body.as_bytes(), &sig).is_ok());
        // Wrong secret, tampered body, and a non-hex signature all fail closed.
        assert!(verify_signature("other-secret", body.as_bytes(), &sig).is_err());
        assert!(verify_signature(SECRET, b"{\"event\":\"bounce\"}", &sig).is_err());
        assert!(verify_signature(SECRET, body.as_bytes(), "not-hex").is_err());
    }

    #[tokio::test]
    async fn a_mis_signed_event_is_rejected_before_it_reaches_the_store() {
        let store = MemoryStore::default();
        let body = r#"{"event":"bounce","recipient":"a@b.test"}"#;
        let err = ingest_feedback(&store, SECRET, body.as_bytes(), "deadbeef")
            .await
            .expect_err("a wrong signature must be refused");
        assert!(matches!(err, AppError::Unauthorized));
        assert!(
            store.entries.lock().unwrap().is_empty(),
            "nothing is stored when the signature does not verify"
        );
    }

    #[tokio::test]
    async fn an_unknown_event_type_is_a_validation_error_not_a_silent_suppression() {
        let store = MemoryStore::default();
        let body = r#"{"event":"delivered","recipient":"a@b.test"}"#;
        let err = ingest_feedback(&store, SECRET, body.as_bytes(), &sign(body))
            .await
            .expect_err("an unknown event type is refused");
        assert!(matches!(err, AppError::ValidationError { .. }));
        assert!(store.entries.lock().unwrap().is_empty());
    }

    /// The AC's end-to-end shape, DB-free: a signed bounce is ingested, the same
    /// address is then suppressed, and an unrelated address still is not.
    #[tokio::test]
    async fn ingestion_suppresses_the_reported_address_and_leaves_others_sendable() {
        let store = MemoryStore::default();
        let body = r#"{"event":"complaint","recipient":"Bounced@Customer.TEST","detail":"user marked as spam"}"#;

        let outcome = ingest_feedback(&store, SECRET, body.as_bytes(), &sign(body))
            .await
            .expect("a signed feedback event is ingested");
        assert_eq!(outcome.reason, SuppressionReason::Complaint);
        // Stored normalized, so a differently-cased send to the same address hits.
        assert_eq!(outcome.address, "bounced@customer.test");

        assert!(store.is_suppressed("bounced@customer.test").await.unwrap());
        assert!(store.is_suppressed("BOUNCED@customer.test").await.unwrap());
        assert!(
            !store
                .is_suppressed("someone-else@customer.test")
                .await
                .unwrap(),
            "an unrelated recipient is untouched and still sendable"
        );
    }

    #[tokio::test]
    async fn no_suppression_store_accepts_a_write_as_a_noop() {
        // The fallback store never suppresses, so ingestion succeeds but the
        // address stays sendable; this documents the degenerate wiring.
        let store = NoSuppression;
        let body = r#"{"event":"bounce","recipient":"a@b.test"}"#;
        let outcome = ingest_feedback(&store, SECRET, body.as_bytes(), &sign(body))
            .await
            .expect("ingestion succeeds");
        assert_eq!(outcome.reason, SuppressionReason::Bounce);
        assert!(!store.is_suppressed("a@b.test").await.unwrap());
    }
}
