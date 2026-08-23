//! Mailer relay: send-only transactional mail for the other apps in the suite
//! (BUNYIP-602).
//!
//! `POST /v1/mailer/send` takes a compose-ready message from a calling app and
//! relays it through Bunyip's own SMTP infrastructure and verified sending
//! domain, so an app in the hosted SaaS needs no SMTP credential of its own.
//!
//! The caller authenticates with its `oauth_clients` machine credential over
//! HTTP Basic (see [`bunyip_oidc::machine_client`]); the throttle is per
//! calling app, not per IP, because the suite's apps share egress.

use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use bunyip_oidc::machine_client;

use crate::errors::AppError;
use crate::middleware::extract_client_ip;
use crate::models::RateLimitConfig;
use crate::repositories::{RateLimitConfigRepository, RateLimitRepository};
use crate::responses::{get_request_id, success};
use crate::services::{MailerRelay, RelayMessage, RelayOutcome};

/// A relay request. Every field is required except `html`; a request struct in
/// bunyip-api keeps its required inputs required so a malformed call still
/// 400s rather than silently relaying a blank message.
#[derive(Debug, Deserialize)]
pub struct RelaySendRequest {
    pub to: String,
    pub subject: String,
    pub text: String,
    #[serde(default)]
    pub html: Option<String>,
}

/// What the relay did. `message_id` is present only for a delivered message.
#[derive(Debug, Serialize)]
pub struct RelaySendResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

impl RelaySendResponse {
    fn from_outcome(outcome: RelayOutcome) -> Self {
        match outcome {
            RelayOutcome::Sent { message_id } => Self {
                status: "sent",
                message_id: Some(message_id),
            },
            RelayOutcome::Suppressed => Self {
                status: "suppressed",
                message_id: None,
            },
        }
    }
}

/// Whether this source IP has already accrued its failed-authentication budget.
///
/// Read-only (`check`, not `check_and_increment`), so a request that may
/// succeed never spends the failure budget; compare with `>=` for the same
/// reason the OCI token endpoint does (the increment-oriented `exceeded` would
/// allow one extra guess).
async fn auth_failures_at_cap(pool: &PgPool, ip_key: &str) -> Result<bool, AppError> {
    let config =
        RateLimitConfigRepository::effective(pool, &RateLimitConfig::MAILER_AUTH_FAILURES).await?;
    let (count, _) = RateLimitRepository::check(pool, ip_key, &config).await?;
    Ok(count >= config.max_requests)
}

/// Count one failed client authentication against the source IP.
///
/// A failure to record is logged at `error`, never swallowed: losing the
/// counter silently removes the only brake in front of the Argon2 verify.
async fn record_auth_failure(pool: &PgPool, ip_key: Option<&str>) {
    let Some(ip_key) = ip_key else { return };
    if let Err(e) = RateLimitRepository::check_and_increment(
        pool,
        ip_key,
        &RateLimitConfig::MAILER_AUTH_FAILURES,
    )
    .await
    {
        tracing::error!(
            error = %e,
            "mailer relay could not record a failed client authentication"
        );
    }
}

/// POST /v1/mailer/send
pub async fn relay_send(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    relay: web::Data<Arc<MailerRelay>>,
    body: web::Json<RelaySendRequest>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let ip_key = extract_client_ip(&req).map(|ip| ip.to_string());

    // Per-IP FAILURE brake, ahead of the ~100 ms Argon2 verify. `/v1/mailer/send`
    // is exempt from the per-IP `RateLimitFloor` (a shared-egress app would
    // otherwise throttle its neighbours), so this is what bounds an
    // unauthenticated flood.
    if let Some(ip) = ip_key.as_deref() {
        if auth_failures_at_cap(&pool, ip).await? {
            // A `Retry-After` we could not read falls back to the whole window,
            // which is the conservative answer, but the read failure is logged
            // rather than substituted silently.
            let retry_after = match RateLimitRepository::get_retry_after(
                &pool,
                ip,
                &RateLimitConfig::MAILER_AUTH_FAILURES,
            )
            .await
            {
                Ok(secs) => secs,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "mailer relay could not read the failure window; reporting the full window"
                    );
                    RateLimitConfig::MAILER_AUTH_FAILURES.window_seconds.max(0) as u64
                }
            };
            tracing::error!(
                category = "rate_limit",
                client = %ip,
                action = RateLimitConfig::MAILER_AUTH_FAILURES.action,
                "mailer relay: too many failed client authentications from this address"
            );
            return Err(AppError::RateLimited { retry_after });
        }
    }

    let Some((client_id, secret)) = machine_client::basic_credentials(&req) else {
        record_auth_failure(&pool, ip_key.as_deref()).await;
        tracing::warn!(
            ip = ip_key.as_deref().unwrap_or("unknown"),
            "mailer relay rejected: no HTTP Basic client credential was presented"
        );
        return Err(AppError::OidcInvalidClient(
            "HTTP Basic client credentials are required".into(),
        ));
    };

    let client = match machine_client::load_machine_client(&pool, &client_id).await {
        Ok(client) => client,
        Err(e) => {
            record_auth_failure(&pool, ip_key.as_deref()).await;
            tracing::warn!(
                ip = ip_key.as_deref().unwrap_or("unknown"),
                client_id = %client_id,
                error = %e,
                "mailer relay rejected: unknown or disabled client"
            );
            return Err(e);
        }
    };

    if let Err(e) = machine_client::verify_machine_client(&client, &secret).await {
        record_auth_failure(&pool, ip_key.as_deref()).await;
        tracing::warn!(
            ip = ip_key.as_deref().unwrap_or("unknown"),
            client_id = %client.client_id,
            client = %client.name,
            error = %e,
            "mailer relay rejected: client authentication failed"
        );
        return Err(e);
    }

    // Per-calling-app throughput cap. Keyed by the client id, so one app's
    // burst can never spend another's budget, and a 429 names the app.
    super::check_rate_limit(
        &pool,
        &client.client_id.to_string(),
        &RateLimitConfig::MAILER_SEND,
    )
    .await?;

    let message = RelayMessage::new(&body.to, &body.subject, &body.text, body.html.as_deref())?;
    let outcome = relay.relay(&message, &client.name).await?;

    Ok(success(
        RelaySendResponse::from_outcome(outcome),
        request_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outcome_is_reported_verbatim_and_never_as_a_bare_success() {
        // A suppressed message was NOT delivered; the caller has to be able to
        // tell that apart from a relayed one, so the two answers differ in both
        // the status and the presence of a Message-ID.
        let sent = RelaySendResponse::from_outcome(RelayOutcome::Sent {
            message_id: "abc@mail.example".into(),
        });
        assert_eq!(sent.status, "sent");
        assert_eq!(sent.message_id.as_deref(), Some("abc@mail.example"));

        let suppressed = RelaySendResponse::from_outcome(RelayOutcome::Suppressed);
        assert_eq!(suppressed.status, "suppressed");
        assert_eq!(suppressed.message_id, None);
    }

    #[test]
    fn an_exceeded_relay_cap_answers_429_with_a_retry_after() {
        // The per-app cap and the per-IP failure brake both surface through
        // `AppError::RateLimited`, which is the 429 the calling app branches on.
        let err = AppError::RateLimited { retry_after: 42 };
        assert_eq!(
            actix_web::ResponseError::status_code(&err),
            actix_web::http::StatusCode::TOO_MANY_REQUESTS
        );
    }

    /// The relay's two throttles must stay resolvable by `action` string, or the
    /// admin rate-limit page cannot show (or override) them (BUNYIP-413).
    #[test]
    fn both_relay_limits_are_registered_presets() {
        let send = RateLimitConfig::by_action("mailer_send").expect("mailer_send preset");
        assert_eq!(send.key_kind, crate::models::KeyKind::ClientId);
        let failures = RateLimitConfig::by_action("mailer_auth_failures")
            .expect("mailer_auth_failures preset");
        assert_eq!(failures.key_kind, crate::models::KeyKind::Ip);
    }

    /// Regression guard (BUNYIP-602): `EmailService::new_capturing` builds a
    /// transport that RECORDS messages instead of sending them. It exists for
    /// the relay tests and must never be wired into a running deployment, where
    /// it would swallow every email while reporting success.
    #[test]
    fn no_binary_wires_the_capturing_transport() {
        for (name, src) in [
            ("bunyip-api/src/main.rs", include_str!("../main.rs")),
            ("bunyip-api/src/lib.rs", include_str!("../lib.rs")),
        ] {
            assert!(
                !src.contains("new_capturing"),
                "{name} wires the capturing (non-sending) mail transport"
            );
        }
    }
}
