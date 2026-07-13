//! Webhook service for outbound notifications to child apps

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{error, info};
use uuid::Uuid;

use crate::models::Application;

type HmacSha256 = Hmac<Sha256>;

/// Delivery attempts for an irreversible account-delete dispatch (BUNYIP-211):
/// the first attempt plus two retries. An account delete cannot be replayed by
/// re-deleting the user, so the dispatch tries harder than the fire-and-forget
/// single-shot used for the maintenance / active toggles.
const ACCOUNT_DELETE_MAX_ATTEMPTS: u32 = 3;

pub struct WebhookService {
    client: reqwest::Client,
    signing_secret: String,
}

impl WebhookService {
    pub fn new(signing_secret: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build webhook HTTP client");

        Self {
            client,
            signing_secret,
        }
    }

    /// Notify a child app that its maintenance mode has changed.
    pub async fn notify_maintenance_change(&self, app: &Application) {
        let payload = serde_json::json!({
            "event": "maintenance_mode_changed",
            "slug": app.slug,
            "maintenance_mode": app.maintenance_mode,
            "maintenance_message": app.maintenance_message,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.send(app, payload).await;
    }

    /// Notify a child app that its active status has changed.
    pub async fn notify_active_change(&self, app: &Application) {
        let payload = serde_json::json!({
            "event": "active_changed",
            "slug": app.slug,
            "is_active": app.is_active,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.send(app, payload).await;
    }

    /// Build the `account_deleted` webhook payload (BUNYIP-211). Shared by the
    /// fire-and-forget notifier and the retrying dispatch so the wire shape -
    /// and therefore the HMAC the receiver verifies - cannot drift between
    /// the two paths.
    fn account_deleted_payload(user_id: Uuid) -> serde_json::Value {
        serde_json::json!({
            "event": "account_deleted",
            "user_id": user_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Notify a child app that a bunyip account was deleted (BUNYIP-211).
    /// Fire-and-forget, mirroring the existing notifiers. The delete handler
    /// uses [`Self::dispatch_account_deleted`] instead, which retries and
    /// surfaces the outcome so an exhausted delivery can be persisted for
    /// replay; this method exists for callers that only want best-effort
    /// notification (e.g. the in-process replay of an already-recorded delete).
    pub async fn notify_account_deleted(&self, app: &Application, user_id: Uuid) {
        self.send(app, Self::account_deleted_payload(user_id)).await;
    }

    /// Deliver the `account_deleted` webhook to one app with bounded retries
    /// and exponential backoff (BUNYIP-211). Returns `Ok(())` on the first 2xx
    /// response, or `Err(last_error)` after [`ACCOUNT_DELETE_MAX_ATTEMPTS`]
    /// failed attempts so the caller can persist a replayable failure row.
    ///
    /// An app with no `webhook_url` is a no-op success: there is nothing to
    /// notify, which is not a delivery failure.
    pub async fn dispatch_account_deleted(
        &self,
        app: &Application,
        user_id: Uuid,
    ) -> Result<(), String> {
        let webhook_url = match &app.webhook_url {
            Some(url) if !url.is_empty() => url.clone(),
            _ => return Ok(()),
        };

        // Sign once: the payload (including its timestamp) is fixed for the
        // whole retry sequence so every attempt carries an identical body and
        // signature, and a downstream idempotency key stays stable.
        let body =
            serde_json::to_string(&Self::account_deleted_payload(user_id)).unwrap_or_default();
        let signature = self.sign(&body);

        let mut last_error = String::new();
        for attempt in 1..=ACCOUNT_DELETE_MAX_ATTEMPTS {
            match self
                .client
                .post(&webhook_url)
                .header("Content-Type", "application/json")
                .header("X-Webhook-Signature", &signature)
                .body(body.clone())
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    info!(
                        app_slug = %app.slug,
                        webhook_url = %webhook_url,
                        attempt,
                        "account_deleted webhook delivered"
                    );
                    return Ok(());
                }
                Ok(response) => {
                    last_error = format!("non-success status {}", response.status());
                }
                Err(e) => {
                    last_error = e.to_string();
                }
            }

            error!(
                app_slug = %app.slug,
                webhook_url = %webhook_url,
                attempt,
                error = %last_error,
                "account_deleted webhook attempt failed"
            );

            // Backoff between attempts only (250ms, 500ms); no sleep after the
            // final attempt since we are about to return the error.
            if attempt < ACCOUNT_DELETE_MAX_ATTEMPTS {
                let backoff_ms = 250u64 * 2u64.pow(attempt - 1);
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
            }
        }

        Err(last_error)
    }

    /// Send a signed JSON payload to the app's webhook URL.
    /// Fires and forgets — logs success/failure but never errors out.
    async fn send(&self, app: &Application, payload: serde_json::Value) {
        let webhook_url = match &app.webhook_url {
            Some(url) if !url.is_empty() => url,
            _ => return,
        };

        let body = serde_json::to_string(&payload).unwrap_or_default();
        let signature = self.sign(&body);

        match self
            .client
            .post(webhook_url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Signature", &signature)
            .body(body)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    info!(
                        app_slug = %app.slug,
                        webhook_url = %webhook_url,
                        status = %status,
                        "Webhook notification delivered"
                    );
                } else {
                    error!(
                        app_slug = %app.slug,
                        webhook_url = %webhook_url,
                        status = %status,
                        "Webhook notification failed with non-success status"
                    );
                }
            }
            Err(e) => {
                error!(
                    app_slug = %app.slug,
                    webhook_url = %webhook_url,
                    error = %e,
                    "Webhook notification delivery failed"
                );
            }
        }
    }

    fn sign(&self, payload: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(self.signing_secret.as_bytes())
            .expect("HMAC accepts any key size");
        mac.update(payload.as_bytes());
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_produces_deterministic_hex_output() {
        let service = WebhookService::new("test-secret".to_string());
        let sig1 = service.sign("{\"event\":\"test\"}");
        let sig2 = service.sign("{\"event\":\"test\"}");

        assert_eq!(sig1, sig2);
        // SHA256 HMAC produces 64 hex characters
        assert_eq!(sig1.len(), 64);
        // Should be valid hex
        assert!(sig1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_different_payloads_produce_different_signatures() {
        let service = WebhookService::new("test-secret".to_string());
        let sig1 = service.sign("payload1");
        let sig2 = service.sign("payload2");

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn sign_different_secrets_produce_different_signatures() {
        let service1 = WebhookService::new("secret-1".to_string());
        let service2 = WebhookService::new("secret-2".to_string());
        let sig1 = service1.sign("same payload");
        let sig2 = service2.sign("same payload");

        assert_ne!(sig1, sig2);
    }

    use chrono::Utc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Minimal `Application` with a webhook URL for the dispatch tests.
    fn app_with_webhook(webhook_url: Option<String>) -> Application {
        Application {
            id: Uuid::new_v4(),
            name: "mokosh".to_string(),
            slug: "mokosh".to_string(),
            display_name: "Mokosh".to_string(),
            description: None,
            icon_url: None,
            is_active: true,
            is_hosted: true,
            requires_entitlement: false,
            maintenance_mode: false,
            maintenance_message: None,
            subdomain: None,
            container_name: "mokosh".to_string(),
            health_check_url: None,
            webhook_url,
            version: None,
            source_code_url: None,
            release_notes_url: None,
            forgejo_owner: None,
            forgejo_repo: None,
            pinned_release_tag: None,
            artifact_source: "release".to_string(),
            forgejo_package: None,
            oci_image_owner: None,
            oci_image_name: None,
            pinned_image_tag: None,
            sort_order: 0,
            group_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn dispatch_account_deleted_delivers_payload_with_valid_signature() {
        // Stand in for the mokosh `/v1/webhooks/bunyip/account-deleted` receiver.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let service = WebhookService::new("shared-signing-secret".to_string());
        let app = app_with_webhook(Some(format!("{}/hook", server.uri())));
        let user_id = Uuid::new_v4();

        let result = service.dispatch_account_deleted(&app, user_id).await;
        assert!(result.is_ok(), "first 2xx should succeed: {result:?}");

        let requests = server.received_requests().await.expect("recorded requests");
        assert_eq!(requests.len(), 1, "one delivery on first success");
        let req = &requests[0];

        // The receiver sees the documented event shape and user_id.
        let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
        assert_eq!(body["event"], "account_deleted");
        assert_eq!(body["user_id"], serde_json::json!(user_id));
        assert!(body["timestamp"].is_string());

        // The X-Webhook-Signature is a valid HMAC over the exact bytes sent,
        // so the receiver verifying against the shared secret accepts it.
        let sig = req
            .headers
            .get("X-Webhook-Signature")
            .expect("signature header")
            .to_str()
            .unwrap();
        let body_str = std::str::from_utf8(&req.body).unwrap();
        assert_eq!(sig, service.sign(body_str), "signature matches body HMAC");
    }

    #[tokio::test]
    async fn dispatch_account_deleted_retries_then_reports_exhaustion() {
        // Receiver is permanently down: every attempt 500s.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(ACCOUNT_DELETE_MAX_ATTEMPTS as u64)
            .mount(&server)
            .await;

        let service = WebhookService::new("secret".to_string());
        let app = app_with_webhook(Some(format!("{}/hook", server.uri())));

        let result = service.dispatch_account_deleted(&app, Uuid::new_v4()).await;
        assert!(result.is_err(), "exhausted dispatch returns the last error");
        assert!(result.unwrap_err().contains("500"));

        // `expect(3)` is asserted on drop: exactly ACCOUNT_DELETE_MAX_ATTEMPTS
        // deliveries were made.
        drop(server);
    }

    #[tokio::test]
    async fn dispatch_account_deleted_without_webhook_url_is_noop_success() {
        let service = WebhookService::new("secret".to_string());
        let app = app_with_webhook(None);
        assert!(service
            .dispatch_account_deleted(&app, Uuid::new_v4())
            .await
            .is_ok());
    }
}
