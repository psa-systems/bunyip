//! BUNYIP-1096 Option E: break-glass password-reset CLI body, factored out of
//! `main.rs` so an integration test can drive it against a real database.
//!
//! The subcommand mints a one-time password-reset token for the named user and
//! prints its URL to stdout. It exists for the SMTP-outage case: when the
//! primary + fallback relays are both down (or disabled) and a user cannot
//! receive a magic link or admin-initiated reset through email, an operator
//! can share the URL out-of-band (phone, Signal, in-person). The URL is a
//! bearer credential; the subcommand's `--i-understand` gate exists so this
//! cannot be invoked accidentally.
//!
//! Audited as [`AuditAction::BreakGlassPasswordReset`] with
//! `actor_email = "break-glass-cli"`, `actor_role = "system"`, `actor_id = NULL`.
//! An incident review can tell this path apart from the normal
//! admin-initiated reset at `POST /v1/admin/users/{id}/reset-password`.

use chrono::Utc;
use sqlx::PgPool;

use bunyip_domain::config::Config;
use bunyip_domain::errors::AppError;
use bunyip_domain::models::{
    normalize_email, AuditAction, CreateAuditLog, CreatePasswordResetToken,
};
use bunyip_domain::repositories::{AuditLogRepository, TokenRepository, UserRepository};
use bunyip_domain::services::{JwtConfig, JwtService};

/// Output of the subcommand: the URL to print to stdout, the user's email for
/// the operator-facing stderr line, and the expiry so the test can assert
/// retention.
#[derive(Debug, Clone)]
pub struct BreakGlassOutcome {
    pub url: String,
    pub target_email: String,
    pub expires_at: chrono::DateTime<Utc>,
}

/// Mint the token, insert the audit row, and return the outcome. Pure of I/O
/// beyond the pool and the audit sink: the caller prints the URL. Called from
/// `main.rs` and the integration test alike.
pub async fn mint_break_glass_reset(
    pool: &PgPool,
    config: &Config,
    email: &str,
    jwt_secret: &str,
) -> Result<BreakGlassOutcome, AppError> {
    let normalised = normalize_email(email);
    let user = UserRepository::find_by_email(pool, &normalised)
        .await?
        .ok_or_else(|| AppError::not_found(format!("User {normalised}")))?;

    let jwt_cfg = JwtConfig::from_secret(jwt_secret, &config.app_name);
    let jwt_service = JwtService::new(jwt_cfg);
    let raw_token = uuid::Uuid::new_v4().to_string();
    let token_hash = jwt_service.hash_token(&raw_token);
    let expires_at = Utc::now() + chrono::Duration::hours(1);
    TokenRepository::create_password_reset_token(
        pool,
        CreatePasswordResetToken {
            user_id: user.id,
            token_hash,
            expires_at,
            ip_address: None,
        },
    )
    .await?;

    let audit = CreateAuditLog::new(AuditAction::BreakGlassPasswordReset)
        .with_system_actor("break-glass-cli", "system")
        .with_resource("user", user.id)
        .with_metadata(serde_json::json!({
            "target_user_id": user.id,
            "target_email": user.email,
            "expires_at": expires_at,
        }));
    AuditLogRepository::create(pool, audit).await?;

    let url = format!(
        "{}/reset-password?token={}",
        config.email.base_url.trim_end_matches('/'),
        raw_token
    );
    Ok(BreakGlassOutcome {
        url,
        target_email: user.email,
        expires_at,
    })
}
