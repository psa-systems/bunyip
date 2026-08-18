//! Email service with Lettre and Tera templates

use chrono::{DateTime, Datelike, Utc};
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
// BUNYIP-433: lower-level SMTP client pieces for the "Test connection" probe,
// which drives the handshake by hand (connect -> TLS -> AUTH -> QUIT) so it can
// report the specific stage that failed instead of a generic send error.
use lettre::transport::smtp::authentication::Mechanism;
use lettre::transport::smtp::client::{AsyncSmtpConnection, TlsParameters};
use std::time::Duration;
use tera::{Context, Tera};

use crate::config::{EmailConfig, SmtpTls};
use crate::errors::AppError;
use crate::models::Feedback;

/// Reloadable SMTP transport + config, swapped on admin update (BUNYIP-351).
struct EmailRuntime {
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    config: EmailConfig,
}

/// BUNYIP-433: which stage of the SMTP handshake a `test_connection` probe
/// reached before it failed. Lets the admin UI say *what* is wrong (the host,
/// the TLS layer, or the credentials) instead of a single generic error, which
/// is the whole point of the Test connection button: PMS-669 was a rotated
/// password that silently broke delivery, and only the Auth stage names that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTestStage {
    /// TCP reach to `host:port` (host unreachable / connection refused / DNS).
    Connect,
    /// TLS negotiation: the implicit wrapper, or the STARTTLS upgrade.
    Tls,
    /// SMTP AUTH: the username/password was rejected by the relay.
    Auth,
}

impl SmtpTestStage {
    /// Stable machine-readable slug for the wire response / logs.
    pub fn as_str(self) -> &'static str {
        match self {
            SmtpTestStage::Connect => "connect",
            SmtpTestStage::Tls => "tls",
            SmtpTestStage::Auth => "auth",
        }
    }
}

/// BUNYIP-433: a failed SMTP connection test - the stage that failed plus an
/// admin-facing reason. `Ok(())` from `test_connection` means connect + TLS +
/// (when a username is set) authentication all succeeded.
#[derive(Debug, Clone)]
pub struct SmtpTestError {
    pub stage: SmtpTestStage,
    pub message: String,
}

/// Email service for sending transactional emails
pub struct EmailService {
    /// Reloadable SMTP transport + config, swapped on admin update (BUNYIP-351).
    runtime: std::sync::RwLock<EmailRuntime>,
    /// Template engine (immutable; unaffected by config reloads).
    templates: Tera,
    /// BUNYIP-561: the admin-managed branding record. Every subject and the
    /// `app_name` template value read the product name from here rather than
    /// from the `APP_NAME` baked into `EmailConfig` at construction, so an
    /// admin rename reaches the next email without a restart. `None` before
    /// `main` attaches it (and in the dev/test constructors), where the
    /// `EmailConfig` value stands.
    branding: std::sync::RwLock<Option<std::sync::Arc<crate::models::BrandingCache>>>,
}

impl EmailService {
    /// Build the SMTP transport from config, or `None` when email is disabled.
    ///
    /// Host/port/tls/credentials are baked into the transport at build time, so
    /// this is reused by both `new()` and `reload()` to (re)construct it.
    fn build_transport(
        config: &EmailConfig,
    ) -> Result<Option<AsyncSmtpTransport<Tokio1Executor>>, AppError> {
        if !config.enabled {
            return Ok(None);
        }

        let creds = Credentials::new(config.smtp_username.clone(), config.smtp_password.clone());

        // BUNYIP-507: announce the operator-controlled name, not lettre's
        // default (the OS hostname = the container id). Logged here so the
        // operator sees it on start and on every reload without reading the
        // relay's log.
        let hello = config.ehlo_name();
        tracing::info!(ehlo_name = %hello, "SMTP transport built");

        let transport = match config.smtp_tls {
            SmtpTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
                .map_err(|e| AppError::internal(format!("SMTP connection error: {}", e)))?
                .port(config.smtp_port)
                .credentials(creds)
                .hello_name(hello)
                .tls(lettre::transport::smtp::client::Tls::Wrapper(
                    lettre::transport::smtp::client::TlsParameters::new(config.smtp_host.clone())
                        .map_err(|e| AppError::internal(format!("TLS error: {}", e)))?,
                ))
                .build(),
            SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
                .map_err(|e| AppError::internal(format!("SMTP connection error: {}", e)))?
                .port(config.smtp_port)
                .credentials(creds)
                .hello_name(hello)
                .build(),
        };

        Ok(Some(transport))
    }

    /// BUNYIP-433: verify SMTP settings by opening a real connection,
    /// negotiating TLS, and authenticating, WITHOUT sending a message (it
    /// issues QUIT after AUTH). Returns the specific [`SmtpTestStage`] that
    /// failed so the admin can tell a bad host from bad TLS from a rejected
    /// password - the failure PMS-669 hit, where a rotated password broke
    /// delivery while everything still "looked" configured.
    ///
    /// Callers pass the currently *saved* config; no mail is delivered to any
    /// recipient. `config.enabled` is intentionally ignored: the point is to
    /// validate the credentials even before (or while) sending is switched on.
    pub async fn test_connection(config: &EmailConfig) -> Result<(), SmtpTestError> {
        // Bound every network step so an unresponsive relay cannot hang the
        // request (and, with the endpoint's rate limit, cannot be used to tie
        // up connections against a third-party host).
        const TIMEOUT: Duration = Duration::from_secs(10);

        let host = config.smtp_host.trim();
        if host.is_empty() {
            return Err(SmtpTestError {
                stage: SmtpTestStage::Connect,
                message: "SMTP host is not configured.".to_string(),
            });
        }

        // Stage 1: plain TCP reach, done first even for implicit TLS. A combined
        // connect+TLS call would surface an unreachable host and a TLS handshake
        // failure through the same error; probing the socket first lets us
        // report "connection failure" distinctly from "TLS negotiation failed".
        match tokio::time::timeout(
            TIMEOUT,
            tokio::net::TcpStream::connect((host, config.smtp_port)),
        )
        .await
        {
            Err(_) => {
                return Err(SmtpTestError {
                    stage: SmtpTestStage::Connect,
                    message: format!("Timed out connecting to {host}:{}.", config.smtp_port),
                })
            }
            Ok(Err(e)) => {
                return Err(SmtpTestError {
                    stage: SmtpTestStage::Connect,
                    message: format!("Could not connect to {host}:{}: {e}", config.smtp_port),
                })
            }
            Ok(Ok(stream)) => drop(stream),
        }

        let hello = config.ehlo_name();
        let tls_params = TlsParameters::new(host.to_string()).map_err(|e| SmtpTestError {
            stage: SmtpTestStage::Tls,
            message: format!("Could not build TLS parameters for {host}: {e}"),
        })?;

        // Stage 2: establish the SMTP connection with TLS. Implicit TLS wraps
        // the socket during connect; STARTTLS connects plaintext then upgrades.
        // Because the TCP reach already succeeded above, a failure here is a TLS
        // problem (implicit) or a greeting/STARTTLS problem (explicit).
        let mut conn = match config.smtp_tls {
            SmtpTls::Implicit => AsyncSmtpConnection::connect_tokio1(
                (host, config.smtp_port),
                Some(TIMEOUT),
                &hello,
                Some(tls_params),
                None,
            )
            .await
            .map_err(|e| SmtpTestError {
                stage: SmtpTestStage::Tls,
                message: format!("TLS negotiation failed: {e}"),
            })?,
            SmtpTls::Starttls => {
                let mut conn = AsyncSmtpConnection::connect_tokio1(
                    (host, config.smtp_port),
                    Some(TIMEOUT),
                    &hello,
                    None,
                    None,
                )
                .await
                .map_err(|e| SmtpTestError {
                    stage: SmtpTestStage::Connect,
                    message: format!("SMTP greeting failed: {e}"),
                })?;
                conn.starttls(tls_params, &hello)
                    .await
                    .map_err(|e| SmtpTestError {
                        stage: SmtpTestStage::Tls,
                        message: format!("STARTTLS negotiation failed: {e}"),
                    })?;
                conn
            }
        };

        // Stage 3: authenticate, only when a username is configured (an open
        // relay has none). This is the check that catches the rotated/rejected
        // password. No message is sent - QUIT closes the session either way.
        let auth = if config.smtp_username.is_empty() {
            Ok(())
        } else {
            Self::authenticate(&mut conn, &config.smtp_username, &config.smtp_password).await
        };
        let _ = conn.quit().await;
        auth
    }

    /// BUNYIP-433: run SMTP AUTH on an already-connected session and classify a
    /// rejection as [`SmtpTestStage::Auth`]. Split out from `test_connection` so
    /// the success and authentication-failure paths are unit-testable against an
    /// in-process mock relay without standing up TLS.
    async fn authenticate(
        conn: &mut AsyncSmtpConnection,
        username: &str,
        password: &str,
    ) -> Result<(), SmtpTestError> {
        let creds = Credentials::new(username.to_string(), password.to_string());
        conn.auth(&[Mechanism::Plain, Mechanism::Login], &creds)
            .await
            .map(|_| ())
            .map_err(|e| SmtpTestError {
                stage: SmtpTestStage::Auth,
                message: format!("Authentication failed: {e}"),
            })
    }

    /// BUNYIP-561: attach the process-wide branding cache. Called once from
    /// `main` before the listener binds; safe to call again (it replaces).
    pub fn set_branding_cache(&self, cache: std::sync::Arc<crate::models::BrandingCache>) {
        *self.branding.write().unwrap_or_else(|e| e.into_inner()) = Some(cache);
    }

    /// Snapshot the current config (cheap clone under a short read lock; never held across .await).
    ///
    /// BUNYIP-561: `app_name` is overridden from the branding record when one
    /// is attached, so every subject and the template context follow the admin
    /// panel rather than the `APP_NAME` fixed at construction.
    fn config(&self) -> EmailConfig {
        let mut config = self
            .runtime
            .read()
            .expect("EmailService lock poisoned")
            .config
            .clone();
        if let Some(cache) = self
            .branding
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            config.app_name = cache.brand_name();
        }
        config
    }

    /// Snapshot the current transport (lettre transports are Clone = cheap Arc bump).
    fn transport(&self) -> Option<AsyncSmtpTransport<Tokio1Executor>> {
        self.runtime
            .read()
            .expect("EmailService lock poisoned")
            .transport
            .clone()
    }

    /// Hot-reload the SMTP transport + config (e.g. after an admin update). Rebuilds
    /// the transport because host/port/tls/credentials are baked into it at build time.
    pub fn reload(&self, config: EmailConfig) -> Result<(), AppError> {
        let transport = Self::build_transport(&config)?;
        let mut rt = self.runtime.write().expect("EmailService lock poisoned");
        rt.transport = transport;
        rt.config = config;
        Ok(())
    }

    /// Create a new email service
    pub fn new(config: EmailConfig) -> Result<Self, AppError> {
        let transport = Self::build_transport(&config)?;

        // Initialize Tera templates with inline templates
        let mut templates = Tera::default();

        // Register base template
        templates
            .add_raw_template(
                "base.html",
                include_str!("../../templates/emails/base.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template("base.txt", include_str!("../../templates/emails/base.txt"))
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        // Register email templates
        templates
            .add_raw_template(
                "magic_link.html",
                include_str!("../../templates/emails/magic_link.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "magic_link.txt",
                include_str!("../../templates/emails/magic_link.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "password_reset.html",
                include_str!("../../templates/emails/password_reset.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "password_reset.txt",
                include_str!("../../templates/emails/password_reset.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "welcome.html",
                include_str!("../../templates/emails/welcome.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "welcome.txt",
                include_str!("../../templates/emails/welcome.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "account_created.html",
                include_str!("../../templates/emails/account_created.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "account_created.txt",
                include_str!("../../templates/emails/account_created.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "payment_failed.html",
                include_str!("../../templates/emails/payment_failed.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "payment_failed.txt",
                include_str!("../../templates/emails/payment_failed.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "grace_period_reminder.html",
                include_str!("../../templates/emails/grace_period_reminder.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "grace_period_reminder.txt",
                include_str!("../../templates/emails/grace_period_reminder.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "membership_canceled.html",
                include_str!("../../templates/emails/membership_canceled.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "membership_canceled.txt",
                include_str!("../../templates/emails/membership_canceled.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "payment_succeeded.html",
                include_str!("../../templates/emails/payment_succeeded.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "payment_succeeded.txt",
                include_str!("../../templates/emails/payment_succeeded.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "password_changed.html",
                include_str!("../../templates/emails/password_changed.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "password_changed.txt",
                include_str!("../../templates/emails/password_changed.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "new_login_location.html",
                include_str!("../../templates/emails/new_login_location.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "new_login_location.txt",
                include_str!("../../templates/emails/new_login_location.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "login_approval.html",
                include_str!("../../templates/emails/login_approval.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "login_approval.txt",
                include_str!("../../templates/emails/login_approval.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "email_change_verify.html",
                include_str!("../../templates/emails/email_change_verify.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "email_change_verify.txt",
                include_str!("../../templates/emails/email_change_verify.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "email_change_notification.html",
                include_str!("../../templates/emails/email_change_notification.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "email_change_notification.txt",
                include_str!("../../templates/emails/email_change_notification.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "email_verify.html",
                include_str!("../../templates/emails/email_verify.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "email_verify.txt",
                include_str!("../../templates/emails/email_verify.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "admin_feedback_notification.html",
                include_str!("../../templates/emails/admin_feedback_notification.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "admin_feedback_notification.txt",
                include_str!("../../templates/emails/admin_feedback_notification.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "feedback_response.html",
                include_str!("../../templates/emails/feedback_response.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "feedback_response.txt",
                include_str!("../../templates/emails/feedback_response.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        templates
            .add_raw_template(
                "admin_invite.html",
                include_str!("../../templates/emails/admin_invite.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "admin_invite.txt",
                include_str!("../../templates/emails/admin_invite.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        // BUNYIP-508: the admin "Test email" probe. Deliberately its own
        // template: reusing `welcome` would state a price and account status
        // that are fabricated for the test.
        templates
            .add_raw_template(
                "smtp_test.html",
                include_str!("../../templates/emails/smtp_test.html"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;
        templates
            .add_raw_template(
                "smtp_test.txt",
                include_str!("../../templates/emails/smtp_test.txt"),
            )
            .map_err(|e| AppError::internal(format!("Template error: {}", e)))?;

        Ok(Self {
            runtime: std::sync::RwLock::new(EmailRuntime { transport, config }),
            templates,
            branding: std::sync::RwLock::new(None),
        })
    }

    /// Create a new email service with default configuration (dev mode)
    pub fn new_dev() -> Self {
        let config = EmailConfig {
            smtp_host: "localhost".to_string(),
            smtp_port: 587,
            smtp_tls: SmtpTls::Starttls,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_ehlo_name: None,
            from_email: "noreply@localhost".to_string(),
            from_name: "localhost".to_string(),
            base_url: "http://localhost:5173".to_string(),
            enabled: false,
            log_tokens: false,
            app_name: "localhost".to_string(),
            admin_notification_emails: Vec::new(),
        };

        // Create with minimal template setup for dev
        let templates = Tera::default();

        Self {
            runtime: std::sync::RwLock::new(EmailRuntime {
                transport: None,
                config,
            }),
            templates,
            branding: std::sync::RwLock::new(None),
        }
    }

    /// Build an RFC 5322 message ready for the transport.
    ///
    /// BUNYIP-334: every message carries exactly one `Message-ID` header,
    /// `<uuid@domain>`, with `domain` derived from `config.from_email` so it
    /// aligns with the `From:` / DKIM `d=` domain. Gmail (and other RFC-strict
    /// receivers) reject messages that arrive without a `Message-ID`
    /// (`550 5.7.1 RfcMessageNonCompliant`). lettre's builder synthesizes a
    /// `Date` but never a `Message-ID`, so we set it explicitly here rather
    /// than at each call site, since every send routes through this method.
    fn build_message(
        &self,
        config: &EmailConfig,
        to: &str,
        subject: &str,
        html_body: String,
        text_body: String,
    ) -> Result<Message, AppError> {
        let from = format!("{} <{}>", config.from_name, config.from_email);

        let domain = config
            .from_email
            .rsplit('@')
            .next()
            .filter(|d| !d.is_empty())
            .unwrap_or("a8n.run");
        let message_id = format!("<{}@{}>", uuid::Uuid::new_v4(), domain);

        Message::builder()
            .from(
                from.parse()
                    .map_err(|e| AppError::internal(format!("Invalid from address: {}", e)))?,
            )
            .to(to
                .parse()
                .map_err(|e| AppError::internal(format!("Invalid to address: {}", e)))?)
            .subject(subject)
            .message_id(Some(message_id))
            .multipart(
                lettre::message::MultiPart::alternative()
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text_body),
                    )
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html_body),
                    ),
            )
            .map_err(|e| AppError::internal(format!("Email build error: {}", e)))
    }

    /// Send an email
    async fn send_email(
        &self,
        config: &EmailConfig,
        to: &str,
        subject: &str,
        html_body: String,
        text_body: String,
    ) -> Result<(), AppError> {
        let transport = self.transport();
        if let Some(transport) = transport {
            let email = self.build_message(config, to, subject, html_body, text_body)?;

            // BUNYIP-309: log the handoff to the transport so an attempt is
            // visible even when the send below fails. Pairs with the
            // "Email sent successfully" line to bracket every delivery.
            tracing::info!(to = %to, subject = %subject, "Email queued for delivery");

            transport
                .send(email)
                .await
                .map_err(|e| AppError::internal(format!("Email send error: {}", e)))?;

            tracing::info!(to = %to, subject = %subject, "Email sent successfully");
        } else {
            tracing::info!(
                to = %to,
                subject = %subject,
                "Email not sent (dev mode)"
            );
        }

        Ok(())
    }

    /// Render a template
    fn render_template(&self, name: &str, context: &Context) -> Result<(String, String), AppError> {
        let html = self
            .templates
            .render(&format!("{}.html", name), context)
            .map_err(|e| AppError::internal(format!("Template render error: {}", e)))?;
        let text = self
            .templates
            .render(&format!("{}.txt", name), context)
            .map_err(|e| AppError::internal(format!("Template render error: {}", e)))?;
        Ok((html, text))
    }

    /// Get base context with common variables
    fn base_context(&self, config: &EmailConfig) -> Context {
        let mut context = Context::new();
        context.insert("base_url", &config.base_url);
        context.insert("app_name", &config.app_name);
        context.insert("year", &Utc::now().year());
        context
    }

    /// Send magic link email
    pub async fn send_magic_link(&self, email: &str, token: &str) -> Result<(), AppError> {
        let config = self.config();
        let magic_link_url = format!("{}/magic-link?token={}", config.base_url, token);

        if !config.enabled {
            // Never log the token (or any URL containing it) at INFO: the
            // single-use token is a bearer credential and this path also runs
            // in production deployments without SMTP (BUNYIP-204).
            tracing::info!(email = %email, "Magic link (dev mode) - token suppressed");
            if config.log_tokens {
                tracing::debug!(email = %email, link = %magic_link_url, "Magic link URL (EMAIL_LOG_TOKENS)");
            }
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("magic_link_url", &magic_link_url);

        let (html, text) = self.render_template("magic_link", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Sign in to {}", config.app_name),
            html,
            text,
        )
        .await
    }

    /// Send password reset email. `country` is the full name of the country the
    /// request came from (BUNYIP-397), or `None` when it could not be resolved
    /// (admin-initiated reset, a local IP, or no GeoIP DB); the template shows
    /// the "(from ...)" clause only when it is present.
    pub async fn send_password_reset(
        &self,
        email: &str,
        token: &str,
        country: Option<&str>,
    ) -> Result<(), AppError> {
        let config = self.config();
        let reset_url = format!("{}/password-reset/confirm?token={}", config.base_url, token);

        if !config.enabled {
            tracing::info!(email = %email, "Password reset link (dev mode) - token suppressed");
            if config.log_tokens {
                tracing::debug!(email = %email, link = %reset_url, "Password reset URL (EMAIL_LOG_TOKENS)");
            }
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("reset_url", &reset_url);
        // Empty string when absent so the Tera `{% if country %}` guard is false.
        context.insert("country", &country.unwrap_or(""));

        let (html, text) = self.render_template("password_reset", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Reset your {} password", config.app_name),
            html,
            text,
        )
        .await
    }

    /// Send account creation email
    pub async fn send_account_created(&self, email: &str) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled {
            tracing::info!(email = %email, "Account created email (dev mode - not sending)");
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("dashboard_url", &format!("{}/dashboard", config.base_url));

        let (html, text) = self.render_template("account_created", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Welcome to {}!", config.app_name),
            html,
            text,
        )
        .await
    }

    /// Send password changed notification email
    pub async fn send_password_changed(&self, email: &str) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled {
            tracing::info!(email = %email, "Password changed email (dev mode - not sending)");
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("dashboard_url", &format!("{}/dashboard", config.base_url));

        let (html, text) = self.render_template("password_changed", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Your {} password was changed", config.app_name),
            html,
            text,
        )
        .await
    }

    /// BUNYIP-366: alert the user that a sign-in came from a country they have
    /// not signed in from before. Best-effort at the call site (login must never
    /// fail if this does not send).
    pub async fn send_new_login_location(
        &self,
        email: &str,
        country: &str,
        ip: &str,
        when: &str,
        user_agent: &str,
    ) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled {
            tracing::info!(email = %email, country = %country, "New-login-location email (dev mode - not sending)");
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("country", &country);
        context.insert("ip", &ip);
        context.insert("when", &when);
        context.insert("user_agent", &user_agent);
        context.insert("dashboard_url", &format!("{}/dashboard", config.base_url));

        let (html, text) = self.render_template("new_login_location", &context)?;
        self.send_email(
            &config,
            email,
            &format!("New sign-in to your {} account", config.app_name),
            html,
            text,
        )
        .await
    }

    /// BUNYIP-373: email a one-time code to approve a suspicious sign-in. The
    /// code is a bearer credential, so like the magic link it is never logged at
    /// INFO and is emitted at DEBUG only under EMAIL_LOG_TOKENS. Best-effort at
    /// the call site (login must never fail if this does not send).
    pub async fn send_login_approval_code(
        &self,
        email: &str,
        code: &str,
        location: &str,
    ) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled {
            tracing::info!(email = %email, "Login approval code (dev mode) - code suppressed");
            if config.log_tokens {
                tracing::debug!(email = %email, code = %code, "Login approval code (EMAIL_LOG_TOKENS)");
            }
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("code", &code);
        context.insert("location", &location);
        // Cosmetic: keep in sync with LOGIN_APPROVAL_TTL_MINUTES in auth.rs.
        context.insert("ttl_minutes", &15);
        context.insert("dashboard_url", &format!("{}/dashboard", config.base_url));

        let (html, text) = self.render_template("login_approval", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Approve your sign-in to {}", config.app_name),
            html,
            text,
        )
        .await
    }

    /// Send welcome email after membership activation
    pub async fn send_welcome(&self, email: &str, price_cents: i32) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled {
            tracing::info!(email = %email, price = price_cents, "Welcome email (dev mode)");
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("dashboard_url", &format!("{}/dashboard", config.base_url));
        context.insert("price", &format!("{:.2}", price_cents as f64 / 100.0));

        let (html, text) = self.render_template("welcome", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Welcome to {}!", config.app_name),
            html,
            text,
        )
        .await
    }

    /// Send payment failed email
    pub async fn send_payment_failed(
        &self,
        email: &str,
        days_remaining: i32,
    ) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled {
            tracing::info!(
                email = %email,
                days = days_remaining,
                "Payment failed email (dev mode)"
            );
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert(
            "billing_url",
            &format!("{}/dashboard/membership", config.base_url),
        );
        context.insert("days_remaining", &days_remaining);

        let (html, text) = self.render_template("payment_failed", &context)?;
        self.send_email(
            &config,
            email,
            "Action required: Payment failed",
            html,
            text,
        )
        .await
    }

    /// Send grace period reminder email
    pub async fn send_grace_period_reminder(
        &self,
        email: &str,
        days_remaining: i32,
    ) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled {
            tracing::info!(
                email = %email,
                days = days_remaining,
                "Grace period reminder email (dev mode)"
            );
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert(
            "billing_url",
            &format!("{}/dashboard/membership", config.base_url),
        );
        context.insert("days_remaining", &days_remaining);

        let (html, text) = self.render_template("grace_period_reminder", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Only {} days left to update payment", days_remaining),
            html,
            text,
        )
        .await
    }

    /// Send membership canceled email
    pub async fn send_membership_canceled(
        &self,
        email: &str,
        end_date: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled {
            tracing::info!(email = %email, end_date = %end_date, "Membership canceled email (dev mode)");
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("end_date", &end_date.format("%B %d, %Y").to_string());
        context.insert("resubscribe_url", &format!("{}/pricing", config.base_url));

        let (html, text) = self.render_template("membership_canceled", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Your {} membership has been canceled", config.app_name),
            html,
            text,
        )
        .await
    }

    /// Send email change verification email (to new address)
    pub async fn send_email_change_verify(&self, email: &str, token: &str) -> Result<(), AppError> {
        let config = self.config();
        let verify_url = format!("{}/settings/confirm-email?token={}", config.base_url, token);

        if !config.enabled {
            tracing::info!(email = %email, "Email change verify link (dev mode) - token suppressed");
            if config.log_tokens {
                tracing::debug!(email = %email, link = %verify_url, "Email change verify URL (EMAIL_LOG_TOKENS)");
            }
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("verify_url", &verify_url);

        let (html, text) = self.render_template("email_change_verify", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Verify your new {} email address", config.app_name),
            html,
            text,
        )
        .await
    }

    /// Send email change notification (to old address)
    pub async fn send_email_change_notification(
        &self,
        old_email: &str,
        new_email: &str,
    ) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled {
            tracing::info!(old_email = %old_email, new_email = %new_email, "Email change notification (dev mode - not sending)");
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("new_email", new_email);
        context.insert("dashboard_url", &format!("{}/dashboard", config.base_url));

        let (html, text) = self.render_template("email_change_notification", &context)?;
        self.send_email(
            &config,
            old_email,
            &format!("Your {} email address was changed", config.app_name),
            html,
            text,
        )
        .await
    }

    /// Send email verification link
    pub async fn send_email_verify(&self, email: &str, token: &str) -> Result<(), AppError> {
        let config = self.config();
        let verify_url = format!("{}/settings/verify-email?token={}", config.base_url, token);

        if !config.enabled {
            tracing::info!(
                email = %email,
                link = %verify_url,
                "Email verify link (dev mode - not sending email)"
            );
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("verify_url", &verify_url);

        let (html, text) = self.render_template("email_verify", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Verify your {} email address", config.app_name),
            html,
            text,
        )
        .await
    }

    /// Send payment succeeded (receipt) email
    pub async fn send_payment_succeeded(
        &self,
        email: &str,
        amount_cents: i32,
    ) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled {
            tracing::info!(email = %email, amount = amount_cents, "Payment succeeded email (dev mode)");
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("amount", &format!("{:.2}", amount_cents as f64 / 100.0));
        context.insert("dashboard_url", &format!("{}/dashboard", config.base_url));

        let (html, text) = self.render_template("payment_succeeded", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Payment received - {}", config.app_name),
            html,
            text,
        )
        .await
    }

    /// Notify admins about newly submitted feedback
    pub async fn send_admin_feedback_notification(
        &self,
        admin_url: &str,
        recipients: &[String],
    ) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled || recipients.is_empty() {
            tracing::info!(
                recipients = recipients.len(),
                "Feedback notification email skipped"
            );
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("admin_url", admin_url);

        let (html, text) = self.render_template("admin_feedback_notification", &context)?;
        for recipient in recipients {
            self.send_email(
                &config,
                recipient,
                &format!("New feedback received - {}", config.app_name),
                html.clone(),
                text.clone(),
            )
            .await?;
        }

        Ok(())
    }

    /// Send a feedback response to the original submitter
    pub async fn send_feedback_response(
        &self,
        email: &str,
        feedback: &Feedback,
    ) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled {
            tracing::info!(feedback_id = %feedback.id, email = %email, "Feedback response email skipped");
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert(
            "subject_line",
            &feedback.subject.as_deref().unwrap_or("Your feedback"),
        );
        context.insert("original_message", &feedback.message);
        context.insert(
            "response_message",
            &feedback.admin_response.as_deref().unwrap_or(""),
        );

        let (html, text) = self.render_template("feedback_response", &context)?;
        self.send_email(
            &config,
            email,
            &format!("Response to your feedback - {}", config.app_name),
            html,
            text,
        )
        .await
    }

    /// Send admin invite email
    pub async fn send_admin_invite(&self, email: &str, token: &str) -> Result<(), AppError> {
        let config = self.config();
        let invite_url = format!("{}/invite/accept?token={}", config.base_url, token);

        if !config.enabled {
            tracing::info!(
                email = %email,
                link = %invite_url,
                "Admin invite link (dev mode - not sending email)"
            );
            return Ok(());
        }

        let mut context = self.base_context(&config);
        context.insert("invite_url", &invite_url);

        let (html, text) = self.render_template("admin_invite", &context)?;
        self.send_email(
            &config,
            email,
            &format!(
                "You've been invited to join {} as an admin",
                config.app_name
            ),
            html,
            text,
        )
        .await
    }

    /// BUNYIP-508: send the admin "Test email" probe to `to` (always the
    /// signed-in admin's own address) through the live transport.
    ///
    /// Unlike every other sender, a disabled email service is an error here
    /// rather than a silent no-op: the operator clicked this to learn whether
    /// mail actually leaves, so "nothing was sent" must never read as success.
    pub async fn send_test_message(&self, to: &str) -> Result<(), AppError> {
        let config = self.config();
        if !config.enabled || self.transport().is_none() {
            return Err(AppError::internal(
                "Email sending is disabled, so no test message was sent.",
            ));
        }

        let mut context = self.base_context(&config);
        context.insert("smtp_host", &config.smtp_host);
        context.insert(
            "sent_at",
            &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );

        let (html, text) = self.render_template("smtp_test", &context)?;
        self.send_email(
            &config,
            to,
            &format!("{} SMTP test message", config.app_name),
            html,
            text,
        )
        .await
    }
}

impl Default for EmailService {
    fn default() -> Self {
        Self::new_dev()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fully-templated service (every template parses through
    /// `EmailService::new`) for palette/rendering assertions.
    fn service_all_templates() -> EmailService {
        EmailService::new(EmailConfig {
            smtp_host: "localhost".to_string(),
            smtp_port: 587,
            smtp_tls: SmtpTls::Starttls,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_ehlo_name: None,
            from_email: "noreply@a8n.run".to_string(),
            from_name: "PSA Staging".to_string(),
            base_url: "http://localhost:5173".to_string(),
            enabled: false,
            log_tokens: false,
            app_name: "PSA Staging".to_string(),
            admin_notification_emails: Vec::new(),
        })
        .expect("email service builds and all templates parse")
    }

    /// BUNYIP-569: transactional emails render on a layered dark palette, not a
    /// single black fill. The shared shell gives three visually distinct tones
    /// (outer page, raised card, footer panel) and keeps green for accents and
    /// CTAs only, so body copy never renders green-on-near-black. Covers the
    /// welcome, the login-location alert, and the new-device (login approval)
    /// email per the acceptance criteria.
    #[test]
    fn transactional_emails_use_the_layered_palette() {
        let service = service_all_templates();
        let config = service.config();

        // Palette tokens locked by BUNYIP-569. Update these only when the
        // palette is deliberately revised (they are the redesign's contract).
        const PAGE_BG: &str = "#0c0f0c";
        const CARD_BG: &str = "#232b22";
        const FOOTER_BG: &str = "#141a13";
        const ACCENT_GREEN: &str = "#74c47c";
        // Retired by BUNYIP-569: the flat near-black card fill and the
        // a8n-tools blue heading that leaked in from the visual reference.
        const RETIRED_CARD_BG: &str = "#1c211c";
        const RETIRED_BLUE: &str = "#e0e0e8";

        let welcome = {
            let mut ctx = service.base_context(&config);
            ctx.insert("price", &"29.00");
            ctx.insert("dashboard_url", &"http://localhost:5173/dashboard");
            service
                .render_template("welcome", &ctx)
                .expect("welcome renders")
                .0
        };
        let login_location = {
            let mut ctx = service.base_context(&config);
            ctx.insert("country", &"Germany");
            ctx.insert("ip", &"203.0.113.7");
            ctx.insert("when", &"2026-08-18 14:00 UTC");
            ctx.insert("user_agent", &"Firefox on Linux");
            ctx.insert("dashboard_url", &"http://localhost:5173/dashboard");
            service
                .render_template("new_login_location", &ctx)
                .expect("login-location renders")
                .0
        };
        let login_approval = {
            let mut ctx = service.base_context(&config);
            ctx.insert("code", &"482913");
            ctx.insert("location", &"Germany");
            ctx.insert("ttl_minutes", &15);
            ctx.insert("dashboard_url", &"http://localhost:5173/dashboard");
            service
                .render_template("login_approval", &ctx)
                .expect("login-approval renders")
                .0
        };

        for (name, html) in [
            ("welcome", &welcome),
            ("new_login_location", &login_location),
            ("login_approval", &login_approval),
        ] {
            // Three visually distinct layer tones, not a single black fill.
            assert!(html.contains(PAGE_BG), "{name}: outer page tone present");
            assert!(html.contains(CARD_BG), "{name}: raised card tone present");
            assert!(html.contains(FOOTER_BG), "{name}: footer tone present");
            // Green kept for accents/CTAs.
            assert!(html.contains(ACCENT_GREEN), "{name}: accent green present");
            // The retired flat palette and the a8n-tools blue are gone.
            assert!(
                !html.contains(RETIRED_CARD_BG),
                "{name}: flat near-black card retired"
            );
            assert!(
                !html.contains(RETIRED_BLUE),
                "{name}: a8n-tools blue heading retired"
            );
        }

        // Sanity: the three layer tones are actually distinct from one another.
        assert_ne!(PAGE_BG, CARD_BG);
        assert_ne!(CARD_BG, FOOTER_BG);
        assert_ne!(PAGE_BG, FOOTER_BG);
    }

    fn service_with_from(from_email: &str) -> EmailService {
        let config = EmailConfig {
            smtp_host: "localhost".to_string(),
            smtp_port: 587,
            smtp_tls: SmtpTls::Starttls,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_ehlo_name: None,
            from_email: from_email.to_string(),
            from_name: "PSA Staging".to_string(),
            base_url: "http://localhost:5173".to_string(),
            enabled: false,
            log_tokens: false,
            app_name: "PSA Staging".to_string(),
            admin_notification_emails: Vec::new(),
        };

        EmailService {
            runtime: std::sync::RwLock::new(EmailRuntime {
                transport: None,
                config,
            }),
            templates: Tera::default(),
            branding: std::sync::RwLock::new(None),
        }
    }

    /// BUNYIP-561: subjects and the template `app_name` follow the branding
    /// record, not the `APP_NAME` fixed at construction. An empty record keeps
    /// the bootstrap default, so an unbranded deployment is unchanged.
    #[test]
    fn subjects_follow_the_branding_record() {
        use crate::models::branding::{BrandingCache, BrandingRow};

        let service = service_with_from("noreply@a8n.run");
        assert_eq!(
            service.config().app_name,
            "PSA Staging",
            "no cache attached: the EmailConfig value stands"
        );

        let cache = std::sync::Arc::new(BrandingCache::new("PSA Staging"));
        service.set_branding_cache(std::sync::Arc::clone(&cache));
        assert_eq!(
            service.config().app_name,
            "PSA Staging",
            "an empty record resolves to the bootstrap default"
        );

        cache.store(&BrandingRow {
            id: 1,
            brand_name: "Acme".to_string(),
            tagline: String::new(),
            meta_description: String::new(),
            og_image_url: String::new(),
            theme_css: String::new(),
            theme_color_light: String::new(),
            theme_color_dark: String::new(),
            mark_updated_at: None,
            favicon_updated_at: None,
            mascot_updated_at: None,
            updated_at: Utc::now(),
            updated_by: None,
        });
        let config = service.config();
        assert_eq!(
            config.app_name, "Acme",
            "an admin rename reaches the subject"
        );
        assert_eq!(
            format!("Welcome to {}!", config.app_name),
            "Welcome to Acme!"
        );
        let ctx = service.base_context(&config);
        assert_eq!(
            ctx.get("app_name").and_then(|v| v.as_str()),
            Some("Acme"),
            "the template context carries the branded name too"
        );
    }

    /// Extract the `Message-ID` header lines from a built message's wire form.
    fn message_id_lines(email: &Message) -> Vec<String> {
        let formatted = String::from_utf8(email.formatted()).expect("message is valid UTF-8");
        formatted
            .split("\r\n")
            .filter(|line| line.starts_with("Message-ID:"))
            .map(|line| line.to_string())
            .collect()
    }

    /// BUNYIP-334: every message carries exactly one RFC 5322-compliant
    /// `Message-ID` header whose domain matches `config.from_email`.
    #[test]
    fn build_message_sets_single_message_id_with_from_domain() {
        let service = service_with_from("dmarc-reporter-staging@a8n.run");
        let config = service.config();
        let email = service
            .build_message(
                &config,
                "recipient@gmail.com",
                "Verify your PSA Staging email address",
                "<p>hello</p>".to_string(),
                "hello".to_string(),
            )
            .expect("message builds");

        let ids = message_id_lines(&email);
        assert_eq!(
            ids.len(),
            1,
            "expected exactly one Message-ID header, got {ids:?}"
        );

        // Header value: `Message-ID: <local@domain>` per RFC 5322 msg-id.
        let value = ids[0]
            .strip_prefix("Message-ID:")
            .expect("prefix present")
            .trim();
        assert!(
            value.starts_with('<'),
            "msg-id must start with '<': {value}"
        );
        assert!(value.ends_with('>'), "msg-id must end with '>': {value}");
        let inner = &value[1..value.len() - 1];
        let (local, domain) = inner.split_once('@').expect("msg-id has an '@'");
        assert!(!local.is_empty(), "local part is non-empty: {value}");
        assert_eq!(domain, "a8n.run", "domain aligns with from_email: {value}");
        // UUID-based local part is globally unique.
        uuid::Uuid::parse_str(local).expect("local part is a UUID");
    }

    /// Two sends produce distinct Message-IDs (globally unique per send).
    #[test]
    fn build_message_generates_unique_message_ids() {
        let service = service_with_from("noreply@a8n.run");
        let config = service.config();
        let first = message_id_lines(
            &service
                .build_message(&config, "a@example.com", "s", "h".into(), "t".into())
                .unwrap(),
        );
        let second = message_id_lines(
            &service
                .build_message(&config, "b@example.com", "s", "h".into(), "t".into())
                .unwrap(),
        );
        assert_ne!(first[0], second[0], "Message-IDs must differ per send");
    }

    /// BUNYIP-397: the reset email drops the alarming "Someone asked" wording and
    /// shows the request country only when one is provided. Building the service
    /// through `EmailService::new` also proves the reworded templates parse (Tera
    /// compiles every template there).
    #[test]
    fn password_reset_email_wording_and_country_clause() {
        let service = EmailService::new(EmailConfig {
            smtp_host: "localhost".to_string(),
            smtp_port: 587,
            smtp_tls: SmtpTls::Starttls,
            smtp_username: String::new(),
            smtp_password: String::new(),
            smtp_ehlo_name: None,
            from_email: "reset@a8n.run".to_string(),
            from_name: "PSA Staging".to_string(),
            base_url: "http://localhost:5173".to_string(),
            enabled: false,
            log_tokens: false,
            app_name: "PSA Staging".to_string(),
            admin_notification_emails: Vec::new(),
        })
        .expect("email service builds and all templates parse");
        let config = service.config();

        // With a resolved country: the "(from <country>)" clause appears.
        let mut ctx = service.base_context(&config);
        ctx.insert("reset_url", &"http://localhost/reset?token=abc");
        ctx.insert("country", &"United States");
        let (html, text) = service
            .render_template("password_reset", &ctx)
            .expect("renders with country");
        for body in [&html, &text] {
            assert!(body.contains("A password reset was requested"));
            assert!(!body.contains("Someone asked"));
            assert!(body.contains("United States"));
        }

        // Without a country (empty string): no location clause, still reworded.
        let mut ctx = service.base_context(&config);
        ctx.insert("reset_url", &"http://localhost/reset?token=abc");
        ctx.insert("country", &"");
        let (html, text) = service
            .render_template("password_reset", &ctx)
            .expect("renders without country");
        for body in [&html, &text] {
            assert!(body.contains("A password reset was requested"));
            assert!(!body.contains("Someone asked"));
            assert!(!body.contains("(from"));
        }
    }

    // ---- BUNYIP-433: SMTP "Test connection" ---------------------------------

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
    use tokio::net::TcpListener;

    fn config_with_smtp(host: &str, port: u16, tls: SmtpTls) -> EmailConfig {
        EmailConfig {
            smtp_host: host.to_string(),
            smtp_port: port,
            smtp_tls: tls,
            smtp_username: "user@example.com".to_string(),
            smtp_password: "pw".to_string(),
            smtp_ehlo_name: None,
            from_email: "noreply@a8n.run".to_string(),
            from_name: "PSA".to_string(),
            base_url: "http://localhost".to_string(),
            enabled: true,
            log_tokens: false,
            app_name: "PSA".to_string(),
            admin_notification_emails: Vec::new(),
        }
    }

    /// Minimal in-process SMTP relay: greets, answers EHLO with an AUTH
    /// advertisement, then accepts (235) or rejects (535) the first AUTH
    /// command before QUIT. Plaintext, so the tests exercise the AUTH
    /// classification in `authenticate` without standing up TLS. The receiver
    /// yields the EHLO command line as the relay saw it (BUNYIP-507).
    async fn spawn_mock_smtp(
        accept_auth: bool,
    ) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock smtp");
        let addr = listener.local_addr().expect("mock smtp addr");
        let (ehlo_tx, ehlo_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept mock smtp");
            let (read_half, mut write_half) = socket.into_split();
            let mut reader = TokioBufReader::new(read_half);
            let mut line = String::new();

            write_half
                .write_all(b"220 mock.local ESMTP\r\n")
                .await
                .unwrap();

            // EHLO -> multiline 250 advertising AUTH.
            reader.read_line(&mut line).await.unwrap();
            // Best-effort: the test may have dropped the receiver.
            let _ = ehlo_tx.send(line.trim().to_string());
            write_half
                .write_all(b"250-mock.local greets you\r\n250 AUTH PLAIN LOGIN\r\n")
                .await
                .unwrap();

            // First AUTH command -> accept or reject.
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let reply: &[u8] = if accept_auth {
                b"235 2.7.0 Authentication successful\r\n"
            } else {
                b"535 5.7.8 Authentication credentials invalid\r\n"
            };
            write_half.write_all(reply).await.unwrap();

            // Best-effort QUIT.
            line.clear();
            let _ = reader.read_line(&mut line).await;
            let _ = write_half.write_all(b"221 2.0.0 Bye\r\n").await;
        });
        (addr, ehlo_rx)
    }

    #[test]
    fn smtp_test_stage_as_str_is_stable() {
        assert_eq!(SmtpTestStage::Connect.as_str(), "connect");
        assert_eq!(SmtpTestStage::Tls.as_str(), "tls");
        assert_eq!(SmtpTestStage::Auth.as_str(), "auth");
    }

    /// An unconfigured host is a Connect-stage failure, not a panic or a hang.
    #[tokio::test]
    async fn test_connection_reports_connect_stage_for_empty_host() {
        let config = config_with_smtp("", 587, SmtpTls::Starttls);
        let err = EmailService::test_connection(&config)
            .await
            .expect_err("empty host must fail");
        assert_eq!(err.stage, SmtpTestStage::Connect);
        assert!(err.message.contains("not configured"), "{}", err.message);
    }

    /// AC: "An unreachable host reports a connection failure specifically."
    /// Bind then drop to get a loopback port with nothing listening.
    #[tokio::test]
    async fn test_connection_reports_connect_stage_for_unreachable_host() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let config = config_with_smtp(&addr.ip().to_string(), addr.port(), SmtpTls::Starttls);
        let err = EmailService::test_connection(&config)
            .await
            .expect_err("closed port must fail");
        assert_eq!(err.stage, SmtpTestStage::Connect);
    }

    /// AC: "A correct configuration reports success." The relay accepts AUTH.
    #[tokio::test]
    async fn authenticate_succeeds_when_relay_accepts() {
        let (addr, _ehlo) = spawn_mock_smtp(true).await;
        let hello =
            config_with_smtp(&addr.ip().to_string(), addr.port(), SmtpTls::Starttls).ehlo_name();
        let mut conn = AsyncSmtpConnection::connect_tokio1(
            addr,
            Some(Duration::from_secs(5)),
            &hello,
            None,
            None,
        )
        .await
        .expect("connect to mock relay");
        let result = EmailService::authenticate(&mut conn, "user@example.com", "correct").await;
        let _ = conn.quit().await;
        assert!(result.is_ok(), "expected auth success, got {result:?}");
    }

    /// AC: "A wrong password reports an authentication failure specifically."
    #[tokio::test]
    async fn authenticate_reports_auth_stage_when_relay_rejects() {
        let (addr, _ehlo) = spawn_mock_smtp(false).await;
        let hello =
            config_with_smtp(&addr.ip().to_string(), addr.port(), SmtpTls::Starttls).ehlo_name();
        let mut conn = AsyncSmtpConnection::connect_tokio1(
            addr,
            Some(Duration::from_secs(5)),
            &hello,
            None,
            None,
        )
        .await
        .expect("connect to mock relay");
        let err = EmailService::authenticate(&mut conn, "user@example.com", "wrong")
            .await
            .expect_err("expected auth rejection");
        let _ = conn.quit().await;
        assert_eq!(err.stage, SmtpTestStage::Auth);
        assert!(
            err.message.contains("Authentication failed"),
            "{}",
            err.message
        );
    }

    /// BUNYIP-507: the configured name reaches the relay on the wire, rather
    /// than the container hostname lettre would pick by default.
    #[tokio::test]
    async fn ehlo_announces_the_configured_name_on_the_wire() {
        let (addr, ehlo) = spawn_mock_smtp(true).await;
        let mut config = config_with_smtp(&addr.ip().to_string(), addr.port(), SmtpTls::Starttls);
        config.smtp_ehlo_name = Some("mail.example.com".to_string());

        let hello = config.ehlo_name();
        let mut conn = AsyncSmtpConnection::connect_tokio1(
            addr,
            Some(Duration::from_secs(5)),
            &hello,
            None,
            None,
        )
        .await
        .expect("connect to mock relay");
        let _ = conn.quit().await;

        let line = ehlo.await.expect("mock relay recorded the EHLO command");
        assert_eq!(line, "EHLO mail.example.com");
    }

    /// BUNYIP-507 regression guard: every SMTP session this file opens
    /// announces the resolved [`EmailConfig::ehlo_name`]. lettre's default
    /// client id is the OS hostname (the container id inside a container), so
    /// it belongs only in that resolver's last fallback, never here.
    #[test]
    fn no_smtp_session_falls_back_to_the_container_hostname() {
        let src = include_str!("email.rs");
        // Split so this assertion cannot match its own needle.
        let needle = concat!("ClientId", "::default()");
        assert!(
            !src.contains(needle),
            "{needle} reappeared in email.rs: use EmailConfig::ehlo_name() instead"
        );

        // Both transport arms announce it, so every relay builder is covered.
        // Each needle also matches itself once here, which keeps the counts
        // balanced.
        assert_eq!(
            src.matches(".hello_name(").count(),
            src.matches("::relay(").count(),
            "every SMTP relay builder must announce the resolved EHLO name"
        );
    }
}
