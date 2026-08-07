//! Webhook service for outbound notifications to child apps.
//!
//! DEV-527: the transport (HMAC-SHA256 signing, fire-and-forget delivery, and
//! the bounded-retry account-delete dispatch) moved to the shared
//! `dunite-webhook` crate. This wrapper keeps the bunyip-specific surface: it
//! builds each event payload from an [`Application`] and pulls the destination
//! from `app.webhook_url`, delegating the actual send to [`WebhookSender`].

use dunite_webhook::WebhookSender;
use uuid::Uuid;

use crate::models::Application;

/// Delivery attempts for an irreversible account-delete dispatch (BUNYIP-211):
/// the first attempt plus two retries. An account delete cannot be replayed by
/// re-deleting the user, so the dispatch tries harder than the fire-and-forget
/// single-shot used for the maintenance / active toggles.
const ACCOUNT_DELETE_MAX_ATTEMPTS: u32 = 3;

pub struct WebhookService {
    sender: WebhookSender,
}

impl WebhookService {
    pub fn new(signing_secret: String) -> Self {
        Self {
            sender: WebhookSender::new(signing_secret),
        }
    }

    /// Notify a child app that its maintenance mode has changed.
    pub async fn notify_maintenance_change(&self, app: &Application) {
        let Some(url) = webhook_url(app) else { return };
        let payload = serde_json::json!({
            "event": "maintenance_mode_changed",
            "slug": app.slug,
            "maintenance_mode": app.maintenance_mode,
            "maintenance_message": app.maintenance_message,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.sender.send(url, &payload).await;
    }

    /// Notify a child app that its active status has changed.
    pub async fn notify_active_change(&self, app: &Application) {
        let Some(url) = webhook_url(app) else { return };
        let payload = serde_json::json!({
            "event": "active_changed",
            "slug": app.slug,
            "is_active": app.is_active,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        self.sender.send(url, &payload).await;
    }

    /// Notify a child app that a bunyip account was deleted (BUNYIP-211).
    /// Fire-and-forget, mirroring the other notifiers. The delete handler uses
    /// [`Self::dispatch_account_deleted`] instead, which retries and surfaces
    /// the outcome so an exhausted delivery can be persisted for replay; this
    /// method exists for callers that only want best-effort notification.
    pub async fn notify_account_deleted(&self, app: &Application, user_id: Uuid) {
        let Some(url) = webhook_url(app) else { return };
        self.sender
            .send(url, &account_deleted_payload(user_id))
            .await;
    }

    /// Deliver the `account_deleted` webhook to one app with bounded retries
    /// (BUNYIP-211). Returns `Ok(())` on the first 2xx response - or when the
    /// app has no `webhook_url`, since there is nothing to notify - or
    /// `Err(last_error)` after [`ACCOUNT_DELETE_MAX_ATTEMPTS`] failed attempts
    /// so the caller can persist a replayable failure row.
    pub async fn dispatch_account_deleted(
        &self,
        app: &Application,
        user_id: Uuid,
    ) -> Result<(), String> {
        let Some(url) = webhook_url(app) else {
            return Ok(());
        };
        // Serialize once so every retry attempt carries an identical body and
        // signature (a stable downstream idempotency key).
        let body = serde_json::to_string(&account_deleted_payload(user_id)).unwrap_or_default();
        self.sender
            .dispatch_with_retries(url, &body, ACCOUNT_DELETE_MAX_ATTEMPTS)
            .await
    }
}

/// The app's webhook URL if it is set and non-empty; `None` is a no-op.
fn webhook_url(app: &Application) -> Option<&str> {
    app.webhook_url.as_deref().filter(|u| !u.is_empty())
}

/// Build the `account_deleted` webhook payload (BUNYIP-211). Shared by the
/// fire-and-forget notifier and the retrying dispatch so the wire shape - and
/// therefore the HMAC the receiver verifies - cannot drift between the two.
fn account_deleted_payload(user_id: Uuid) -> serde_json::Value {
    serde_json::json!({
        "event": "account_deleted",
        "user_id": user_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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

    // The wrapper builds the documented `account_deleted` payload from the
    // Application + user_id and delegates delivery. Signature correctness is
    // dunite-webhook's tested responsibility; here we assert the payload shape
    // and that the signed header is attached.
    #[tokio::test]
    async fn dispatch_account_deleted_delivers_expected_payload() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let service = WebhookService::new("shared-signing-secret".to_string());
        let app = app_with_webhook(Some(format!("{}/hook", server.uri())));
        let user_id = Uuid::new_v4();

        assert!(service
            .dispatch_account_deleted(&app, user_id)
            .await
            .is_ok());

        let requests = server.received_requests().await.expect("recorded requests");
        assert_eq!(requests.len(), 1, "one delivery on first success");
        let req = &requests[0];
        let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json body");
        assert_eq!(body["event"], "account_deleted");
        assert_eq!(body["user_id"], serde_json::json!(user_id));
        assert!(body["timestamp"].is_string());
        assert!(
            req.headers.get("X-Webhook-Signature").is_some(),
            "signed header attached"
        );
    }

    #[tokio::test]
    async fn dispatch_account_deleted_retries_then_reports_exhaustion() {
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
