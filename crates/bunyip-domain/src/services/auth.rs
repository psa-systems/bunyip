//! Authentication service

use chrono::{DateTime, Duration, Utc};
use ipnetwork::IpNetwork;
use rand::{Rng, RngCore};
use sqlx::PgPool;
use std::net::IpAddr;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use std::sync::{Arc, RwLock};

use crate::config::TierConfig;
use crate::errors::AppError;
use crate::models::{
    AuditAction, CreateAdminInvite, CreateAuditLog, CreateEmailChangeRequest,
    CreateEmailVerificationToken, CreateLoginApprovalCode, CreateMagicLinkToken,
    CreatePasswordResetToken, CreateRefreshToken, CreateTrustedDevice, CreateUser,
    SubscriptionTier, User, UserResponse, UserRole,
};
use crate::repositories::{
    AuditLogRepository, InviteRepository, TokenRepository, TotpRepository, TrustedDeviceRepository,
    UserRepository,
};
use crate::services::{EmailService, GeoIpService, JwtService, PasswordService};

/// Authentication tokens returned after login
#[derive(Debug, Clone)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

// The three result enums below carry a full UserResponse in their Success
// variant, which dwarfs the alternative variants. That is fine: each value is
// a transient per-request return, matched exactly once and never stored in a
// collection, so the size imbalance costs nothing (and boxing would add a
// pointless per-login heap allocation).

/// Result of a login attempt: full success, a 2FA challenge, or (BUNYIP-373) a
/// suspicious-login approval challenge that withholds tokens until the user
/// confirms an emailed code.
#[allow(clippy::large_enum_variant)]
pub enum LoginResult {
    Success(AuthTokens, UserResponse),
    TwoFactorRequired {
        challenge_token: String,
    },
    /// BUNYIP-373: login looked suspicious (new country or new device); an
    /// approval code was emailed. The client re-submits it with this challenge
    /// token to `complete_login_approval`.
    ApprovalRequired {
        challenge_token: String,
    },
}

/// Result of magic link verification
#[allow(clippy::large_enum_variant)]
pub enum MagicLinkResult {
    Success(AuthTokens, UserResponse, bool),
    TwoFactorRequired {
        challenge_token: String,
        is_new_user: bool,
    },
    /// BUNYIP-373: same suspicious-login gate as the password path. A gated
    /// magic-link login is always an existing user (new users have no baseline
    /// to deviate from), so no `is_new_user` is carried here.
    ApprovalRequired {
        challenge_token: String,
    },
}

/// Result of accepting an admin invite
#[allow(clippy::large_enum_variant)]
pub enum AcceptInviteResult {
    Success(AuthTokens, UserResponse),
    PasswordRequired { email: String },
}

// --- session-lifetime policy (BUNYIP-381) -----------------------------------
//
// Uniform across roles: a refresh token lasts 1 day, or 30 days when the user
// selected "remember me" at login. The deadline is set at login and carried
// verbatim across refresh rotation (see `create_tokens`), so it is a true
// absolute ceiling on session age. BUNYIP-381 removed the BUNYIP-137 admin-only
// short leash (30-min idle / 12h absolute) and the idle cap entirely; see that
// issue for the accepted privileged-session tradeoff.

/// Absolute refresh-token lifetime: 30 days with "remember me", else 1 day.
/// Applied at login; `create_tokens` carries the resulting deadline across
/// rotation rather than recomputing it, so the ceiling does not roll forward.
fn refresh_absolute_ttl(remember: bool) -> Duration {
    if remember {
        Duration::days(30)
    } else {
        Duration::days(1)
    }
}

// --- email resend rate-limit policy (BUNYIP-313) ---------------------------

/// Rolling window, in seconds, over which email-verify and email-change resend
/// requests are counted. Single source of truth shared by both limiters and
/// reusable by the admin read path (BUNYIP-315).
pub const RESEND_LIMIT_WINDOW_SECS: i64 = 3600;

/// Maximum resend requests permitted within [`RESEND_LIMIT_WINDOW_SECS`]; the
/// next request past this count is throttled. Shared source of truth for both
/// limiters and the admin read path (BUNYIP-315).
pub const RESEND_LIMIT_MAX: i64 = 3;

/// Seconds until a throttled user may resend, given the oldest in-window
/// request's `created_at`. The window frees up one window-length after that
/// request, so `retry_after = oldest + window - now`. Clamped to `>= 1` so a
/// just-expired window still reports a truthful, positive `Retry-After`
/// (BUNYIP-313). Pure and unit-testable: no clock or DB dependency. Also reused
/// by the admin read path (BUNYIP-315) to report `retry_after` for the two
/// email-resend limiters consistently with what the enforcement path returns.
pub fn resend_retry_after_secs(oldest: DateTime<Utc>, now: DateTime<Utc>) -> u64 {
    (oldest + Duration::seconds(RESEND_LIMIT_WINDOW_SECS) - now)
        .num_seconds()
        .max(1) as u64
}

// --- trusted-device policy (BUNYIP-138) -------------------------------------

/// How long a remembered device may skip the login TOTP prompt. Using the
/// device does not extend this; the deadline is fixed at creation.
const TRUSTED_DEVICE_TTL_DAYS: i64 = 30;

/// Whether a presented trusted device permits skipping the login TOTP prompt.
/// Pure decision (unit-testable): only subscribers may skip, and only when a
/// valid (non-revoked, non-expired, owner-matched) device row was found.
/// Admins always complete full 2FA.
fn trusted_device_allows_skip(role: &str, has_valid_device: bool) -> bool {
    has_valid_device && role == UserRole::Subscriber.as_str()
}

// --- suspicious-login approval policy (BUNYIP-373) --------------------------

/// How long an emailed login-approval code stays valid before the user must
/// restart login to get a fresh one.
const LOGIN_APPROVAL_TTL_MINUTES: i64 = 15;

/// Wrong-code attempts tolerated against a single approval challenge before it
/// is dead. Bounds brute force on the 6-digit (1e6-space) code; combined with
/// the 15-minute TTL and single-use rows the guessing budget is negligible.
const LOGIN_APPROVAL_MAX_ATTEMPTS: i32 = 5;

/// BUNYIP-373: outcome of assessing a login for suspicious signals. `flagged`
/// is the gate decision (withhold tokens, email a code); `country` and
/// `device_hash` are the resolved context, carried so a clean login can record
/// the device and a gated login can persist both as the new baseline on
/// completion, all without re-deriving them.
struct LoginRisk {
    flagged: bool,
    country: Option<String>,
    device_hash: Option<String>,
}

// --- signup anti-bot policy (BUNYIP-377) ------------------------------------

/// How long a signup timing-challenge token stays valid; the register form must
/// be submitted within this window of being rendered.
const SIGNUP_CHALLENGE_MAX_AGE_MINUTES: i64 = 30;

/// Minimum seconds a human plausibly takes to fill the register form. A submit
/// faster than this is treated as automated.
const SIGNUP_MIN_FILL_SECONDS: i64 = 2;

/// BUNYIP-377: true when a register submit arrived sooner than a human could
/// plausibly have filled the form (a bot signal). Pure for unit testing.
fn signup_submitted_too_fast(issued_at: i64, now: i64) -> bool {
    now - issued_at < SIGNUP_MIN_FILL_SECONDS
}

/// BUNYIP-377: the single, uniform rejection for every signup bot-guard failure
/// (a filled honeypot, or a missing / forged / expired / too-fast timing token)
/// so none of the checks becomes an oracle a bot could tune against.
fn signup_rejected() -> AppError {
    AppError::bad_request(
        "We couldn't complete your registration. Please reload the page and try again.",
    )
}

/// BUNYIP-290: the first-admin bootstrap predicate, pulled out as a pure,
/// DB-free function so every branch is unit-testable. Returns true only when
/// ALL hold: a bootstrap email is configured; it equals `user_email`
/// (case-insensitive - `bootstrap_admin_email` is already normalized to
/// lowercase in `Config`); the user is not already an admin; and no admin
/// currently exists (`any_admin_exists == false`). The zero-admin gate is what
/// scopes the env var to the FIRST admin only - once any admin exists it is
/// inert - and what makes it self-healing if every admin is later removed.
fn bootstrap_promotion_needed(
    bootstrap_admin_email: Option<&str>,
    user_email: &str,
    user_role: &str,
    any_admin_exists: bool,
) -> bool {
    matches!(
        bootstrap_admin_email,
        Some(bootstrap)
            if !any_admin_exists
                && user_role != UserRole::Admin.as_str()
                && user_email.to_lowercase() == bootstrap
    )
}

/// BUNYIP-221: which side of the dual gate (email-verify vs name-save)
/// triggered the initial-tier grant. Emitted as the `trigger` field on the
/// `InitialTierGranted` audit row so the timeline shows which event was the
/// closer of the funnel.
#[derive(Debug, Clone, Copy)]
pub enum TierGrantTrigger {
    EmailVerified,
    ProfileCompleted,
}

impl TierGrantTrigger {
    pub fn as_str(&self) -> &'static str {
        match self {
            TierGrantTrigger::EmailVerified => "email_verified",
            TierGrantTrigger::ProfileCompleted => "profile_completed",
        }
    }
}

/// Authentication service
pub struct AuthService {
    pool: PgPool,
    jwt: JwtService,
    password: PasswordService,
    tier_config: Arc<RwLock<TierConfig>>,
    /// BUNYIP-290: the trimmed + lowercased bootstrap admin email, if
    /// configured. Drives the zero-admin first-admin promotion on sign-up /
    /// sign-in (see `ensure_bootstrap_admin`).
    bootstrap_admin_email: Option<String>,
    /// BUNYIP-366: email sender for the new-login-location alert.
    email_service: Arc<EmailService>,
    /// BUNYIP-366: IP -> country resolver; `None` when `IP2LOCATION_DB_PATH` is
    /// unset (login-location alerts disabled).
    geoip: Option<Arc<GeoIpService>>,
    /// BUNYIP-373: master switch for the suspicious-login notify-and-approve
    /// gate. Off by default (from `Config::login_approval_enabled`); when off,
    /// login behaves exactly as before (BUNYIP-366 alert only).
    login_approval_enabled: bool,
}

impl AuthService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PgPool,
        jwt: JwtService,
        tier_config: Arc<RwLock<TierConfig>>,
        bootstrap_admin_email: Option<String>,
        email_service: Arc<EmailService>,
        geoip: Option<Arc<GeoIpService>>,
        login_approval_enabled: bool,
    ) -> Self {
        Self {
            pool,
            jwt,
            password: PasswordService::new(),
            tier_config,
            bootstrap_admin_email,
            email_service,
            geoip,
            login_approval_enabled,
        }
    }

    /// BUNYIP-366: on a genuine login, compare the resolved country of the
    /// client IP to the last country recorded for this user. On a change (and
    /// only when the user has not opted out via `login_location_alerts`) email a
    /// "new sign-in from <country>" alert, then persist the new country. The
    /// first login we can attribute to a country records it silently. Entirely
    /// best-effort: every failure is logged and swallowed so it can never block
    /// a login, and the whole check no-ops when no IP2Location DB is configured.
    async fn check_login_location(
        &self,
        user: &User,
        ip_address: Option<IpAddr>,
        device_info: Option<&str>,
    ) {
        let Some(geoip) = self.geoip.as_ref() else {
            return;
        };
        let Some(ip) = ip_address else {
            return;
        };
        // Private / loopback / link-local / unspecified addresses never map to a
        // public country and only show up behind a misconfigured proxy or in
        // dev; skip them so they cannot spuriously "change country".
        if Self::is_non_public_ip(&ip) {
            return;
        }
        let Some(country) = geoip.country_code(ip) else {
            return;
        };

        match login_location_decision(user.last_login_country.as_deref(), &country) {
            // Same country as last time: nothing to do.
            LoginLocationDecision::Unchanged => {}
            // First login we can attribute to a country: record it, no alert.
            LoginLocationDecision::Record => {
                if let Err(e) =
                    UserRepository::set_last_login_country(&self.pool, user.id, Some(&country))
                        .await
                {
                    tracing::warn!(user_id = %user.id, error = %e, "Failed to record initial login country");
                }
            }
            // Country changed: alert (unless opted out), then persist the new one.
            LoginLocationDecision::Alert => {
                let previous = user.last_login_country.as_deref().unwrap_or("?");
                if user.login_location_alerts {
                    let when = Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
                    let ua = device_info.unwrap_or("unknown");
                    if let Err(e) = self
                        .email_service
                        .send_new_login_location(&user.email, &country, &ip.to_string(), &when, ua)
                        .await
                    {
                        tracing::warn!(user_id = %user.id, error = %e, "Failed to send new-login-location email");
                    }
                }
                tracing::info!(user_id = %user.id, from = %previous, to = %country, "Login country changed");
                if let Err(e) =
                    UserRepository::set_last_login_country(&self.pool, user.id, Some(&country))
                        .await
                {
                    tracing::warn!(user_id = %user.id, error = %e, "Failed to update login country");
                }
            }
        }
    }

    /// True for addresses that can never map to a public country: loopback,
    /// RFC1918 / unique-local, link-local, unspecified, broadcast. BUNYIP-366
    /// skips these so a request arriving without a real client IP does not
    /// register as a country change.
    fn is_non_public_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
            }
        }
    }

    /// BUNYIP-373: decide whether a login is suspicious enough to withhold
    /// tokens pending email approval. Suspicious = a new sign-in country (the
    /// same signal the BUNYIP-366 alert uses) OR a device not seen for this user
    /// before (only once the user already has a baseline device on record).
    /// Resolves the country and device hash once and returns them so the caller
    /// can persist them without re-deriving. Never errors: any lookup failure
    /// degrades to "not flagged" so the gate can only fail open, never lock a
    /// user out on infrastructure trouble. Callers gate on this only when
    /// `login_approval_enabled` is set.
    async fn assess_login(
        &self,
        user: &User,
        ip_address: Option<IpAddr>,
        device_id: Option<&str>,
    ) -> LoginRisk {
        // Resolve the country (best-effort). Mirror check_login_location's
        // filters: no geoip DB, no IP, or a non-public IP all yield None.
        let country = match (self.geoip.as_ref(), ip_address) {
            (Some(geoip), Some(ip)) if !Self::is_non_public_ip(&ip) => geoip.country_code(ip),
            _ => None,
        };
        let country_is_new = matches!(
            country
                .as_deref()
                .map(|c| login_location_decision(user.last_login_country.as_deref(), c)),
            Some(LoginLocationDecision::Alert)
        );

        // Device signal: a hash we have not seen for this user, but only once a
        // baseline device already exists. The first device is recorded silently
        // (mirrors the first-country behavior), so a user's very first login
        // after the feature is enabled is never gated on the device signal.
        // A blank device id carries no signal - a client that sends "" must not
        // register an "empty" device that every such client would then share -
        // so it degrades to None (country-only), same as an absent id.
        let device_hash = device_id
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(|d| self.jwt.hash_token(d));
        let device_is_new = match device_hash.as_deref() {
            Some(hash) => match TokenRepository::find_login_device(&self.pool, user.id, hash).await
            {
                Ok(Some(_)) => false, // already a known device
                Ok(None) => TokenRepository::count_login_devices(&self.pool, user.id)
                    .await
                    .map(|n| n > 0)
                    .unwrap_or(false),
                Err(e) => {
                    tracing::warn!(user_id = %user.id, error = %e, "Login device lookup failed; not flagging on device");
                    false
                }
            },
            None => false,
        };

        LoginRisk {
            flagged: country_is_new || device_is_new,
            country,
            device_hash,
        }
    }

    /// BUNYIP-373: a flagged login mints no tokens. Instead generate a 6-digit
    /// code, store its hash bound to a short-lived challenge (with the resolved
    /// country/device so completion can persist them), email the code, and
    /// return the challenge token the client re-submits with the code. The
    /// email is best-effort like the location alert: a mail failure is logged
    /// but never turns the login into a 500 (the user can retry login for a
    /// fresh code).
    async fn begin_login_approval(
        &self,
        user: &User,
        risk: &LoginRisk,
        ip_address: Option<IpAddr>,
        device_info: Option<&str>,
    ) -> Result<String, AppError> {
        let (challenge_token, challenge_jti) =
            self.jwt.create_login_approval_challenge_token(user.id)?;
        let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));
        let code_hash = self.jwt.hash_token(&code);
        let expires_at = Utc::now() + Duration::minutes(LOGIN_APPROVAL_TTL_MINUTES);

        TokenRepository::create_login_approval_code(
            &self.pool,
            CreateLoginApprovalCode {
                user_id: user.id,
                code_hash,
                challenge_jti,
                country: risk.country.clone(),
                ip_address: ip_address.map(IpNetwork::from),
                device_hash: risk.device_hash.clone(),
                device_info: device_info.map(|s| s.to_string()),
                expires_at,
            },
        )
        .await?;

        let location = risk
            .country
            .as_deref()
            .unwrap_or("an unrecognized location");
        // BUNYIP-375: fail closed on a send failure. Returning the challenge
        // anyway would leave the client waiting for a code that never arrives
        // (stuck until the TTL); instead surface a retryable error so the UI can
        // prompt a fresh attempt. The abandoned challenge row expires via TTL and
        // is swept by cleanup_expired_tokens.
        if let Err(e) = self
            .email_service
            .send_login_approval_code(&user.email, &code, location)
            .await
        {
            tracing::warn!(user_id = %user.id, error = %e, "Failed to send login approval code");
            return Err(AppError::upstream(
                "Could not send your sign-in approval code. Please try again.",
            ));
        }
        tracing::info!(user_id = %user.id, "Login withheld pending email approval (BUNYIP-373)");

        Ok(challenge_token)
    }

    /// BUNYIP-373: remember the device that just completed a login so a later
    /// login from it is not treated as new. No-ops when the client sent no
    /// device id. Best-effort: a write failure is logged but must not fail the
    /// login that already succeeded.
    async fn record_login_device(
        &self,
        user: &User,
        device_hash: Option<&str>,
        device_info: Option<&str>,
    ) {
        let Some(hash) = device_hash else {
            return;
        };
        if let Err(e) =
            TokenRepository::record_login_device(&self.pool, user.id, hash, device_info).await
        {
            tracing::warn!(user_id = %user.id, error = %e, "Failed to record login device");
        }
    }

    /// BUNYIP-373: finish a login that was withheld pending email approval.
    /// Verify the challenge token and the emailed code, then mint tokens exactly
    /// as a normal login would and persist the approved country/device as the
    /// new baseline so the next login from here is not flagged again. Mirrors
    /// `complete_2fa_login`'s shape (challenge token in, tokens out).
    pub async fn complete_login_approval(
        &self,
        challenge_token: &str,
        code: &str,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<(AuthTokens, UserResponse), AppError> {
        let claims = self
            .jwt
            .verify_login_approval_challenge_token(challenge_token)?;
        let user_id = claims.sub;

        // BUNYIP-375: resolve the exact row this challenge token was minted for
        // (by jti), not merely the user's newest pending code.
        let approval = TokenRepository::find_valid_login_approval_code_by_jti(
            &self.pool,
            user_id,
            &claims.jti,
        )
        .await?
        .ok_or(AppError::InvalidCredentials)?;

        // Fast reject for a challenge already at its attempt budget. This is a
        // non-authoritative pre-check; the atomic ops below are what actually
        // enforce the cap and single-use under concurrent verify requests.
        if approval.attempts >= LOGIN_APPROVAL_MAX_ATTEMPTS {
            return Err(AppError::InvalidCredentials);
        }

        let code = code.trim().replace(' ', "");
        // BUNYIP-375: constant-time comparison. Defense-in-depth only - both
        // sides are already SHA-256 hashes, so a timing leak would expose a hash
        // prefix that still needs a preimage to yield the code - but comparing
        // secret-derived material in constant time is cheap hygiene.
        let submitted = self.jwt.hash_token(&code);
        if submitted
            .as_bytes()
            .ct_eq(approval.code_hash.as_bytes())
            .unwrap_u8()
            != 1
        {
            // Atomic capped increment: concurrent wrong guesses cannot push the
            // counter past the cap (the `attempts < max` guard runs inside one
            // serialized UPDATE, not a read-modify-write here).
            TokenRepository::increment_login_approval_attempts(
                &self.pool,
                approval.id,
                LOGIN_APPROVAL_MAX_ATTEMPTS,
            )
            .await?;
            return Err(AppError::validation("code", "Invalid approval code"));
        }

        // Correct code: atomically claim the challenge (single-use + re-assert
        // the cap in one statement). A lost claim - a concurrent success, an
        // already-used or expired row, or one that just hit the cap - rejects
        // without minting, so exactly one login can complete from a challenge
        // even if the same code is submitted twice at once.
        if !TokenRepository::claim_login_approval_code(
            &self.pool,
            approval.id,
            LOGIN_APPROVAL_MAX_ATTEMPTS,
        )
        .await?
        {
            return Err(AppError::InvalidCredentials);
        }

        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        let tokens = self
            .create_tokens(&user, device_info.clone(), ip_address, None)
            .await?;
        UserRepository::update_last_login(&self.pool, user.id).await?;

        // Persist the approved context as the new baseline. Both best-effort:
        // the login has succeeded, so a bookkeeping write failure must not fail
        // it (it would only mean the next login is flagged again).
        if let Some(country) = approval.country.as_deref() {
            if let Err(e) =
                UserRepository::set_last_login_country(&self.pool, user.id, Some(country)).await
            {
                tracing::warn!(user_id = %user.id, error = %e, "Failed to record approved login country");
            }
        }
        self.record_login_device(
            &user,
            approval.device_hash.as_deref(),
            approval.device_info.as_deref(),
        )
        .await;

        let ip = ip_address.map(IpNetwork::from);
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::UserLogin)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip)
                .with_metadata(serde_json::json!({ "method": "login_approval" })),
        )
        .await?;

        Ok((tokens, UserResponse::from(user)))
    }

    /// Hash a raw refresh token the same way it is stored, so callers (e.g.
    /// the active-sessions endpoint) can match a presented refresh-token cookie
    /// to its stored row without reaching into the private JWT service
    /// (BUNYIP-137).
    pub fn hash_token(&self, token: &str) -> String {
        self.jwt.hash_token(token)
    }

    /// Hot-reload the tier configuration (e.g. after admin update).
    pub fn reload_tier_config(&self, config: TierConfig) {
        let mut tc = self.tier_config.write().expect("TierConfig lock poisoned");
        *tc = config;
    }

    /// BUNYIP-290: promote `user` to `admin` when it is the configured
    /// bootstrap admin and no admin currently exists. Called from the auth
    /// paths (sign-up and sign-in) BEFORE any session / JWT is minted, and
    /// mutates `user` in place on promotion so the freshly-issued token carries
    /// `role = "admin"` with no second login required.
    ///
    /// The gate is "zero admins exist", so the bootstrap email only ever seeds
    /// the FIRST admin: once any admin exists this is inert, and every further
    /// admin change goes through the admin-invite and role-management flows. It
    /// is also self-healing - if every admin is later removed, the bootstrap
    /// email can re-establish the first admin on its next authentication.
    ///
    /// Concurrency: two simultaneous bootstrap authentications could both
    /// observe zero admins, but `update_role` to "admin" is idempotent so the
    /// outcome is still a single admin; no extra locking is required (the
    /// removed `setup_admin` had the same accepted race). Returns true when a
    /// promotion happened.
    async fn ensure_bootstrap_admin(&self, user: &mut User) -> Result<bool, AppError> {
        let bootstrap = self.bootstrap_admin_email.as_deref();
        // Cheap pre-filter so the admin-count query runs only for the bootstrap
        // email while it is not yet an admin - the actual bootstrap window. Any
        // other user (or a repeat auth of the already-promoted admin) returns
        // here with no DB round-trip. Mirrors the final predicate minus the
        // zero-admin gate, which is the only part that needs a query.
        if bootstrap.is_none()
            || user.role == UserRole::Admin.as_str()
            || Some(user.email.to_lowercase().as_str()) != bootstrap
        {
            return Ok(false);
        }
        let any_admin_exists = !UserRepository::find_admin_emails(&self.pool)
            .await?
            .is_empty();
        if !bootstrap_promotion_needed(bootstrap, &user.email, &user.role, any_admin_exists) {
            return Ok(false);
        }
        // BUNYIP-265: user_id only, raw email is PII.
        let updated =
            UserRepository::update_role(&self.pool, user.id, UserRole::Admin.as_str()).await?;
        tracing::info!(user_id = %user.id, "BUNYIP-290: bootstrap admin promoted to admin");
        *user = updated;
        Ok(true)
    }

    /// BUNYIP-377: mint a signup timing-challenge token for a freshly-rendered
    /// register form (served by `GET /v1/auth/register-challenge`).
    pub fn create_signup_challenge(&self) -> Result<String, AppError> {
        self.jwt
            .create_signup_challenge_token(Duration::minutes(SIGNUP_CHALLENGE_MAX_AGE_MINUTES))
    }

    /// BUNYIP-377: reject a registration that looks automated. `honeypot` is a
    /// hidden form field a human leaves empty; `token` is the timing challenge
    /// the form was rendered with. Fails uniformly (via `signup_rejected`) when
    /// the honeypot is filled, or the token is missing / forged / expired, or the
    /// form was submitted faster than a human could fill it. Gated by the caller
    /// on `Config::signup_bot_guard_enabled`.
    pub fn verify_signup_not_bot(
        &self,
        honeypot: Option<&str>,
        token: Option<&str>,
    ) -> Result<(), AppError> {
        if honeypot.map(|h| !h.trim().is_empty()).unwrap_or(false) {
            return Err(signup_rejected());
        }
        let token = token.ok_or_else(signup_rejected)?;
        let claims = self
            .jwt
            .verify_signup_challenge_token(token)
            .map_err(|_| signup_rejected())?;
        if signup_submitted_too_fast(claims.iat, Utc::now().timestamp()) {
            return Err(signup_rejected());
        }
        Ok(())
    }

    /// Register a new user
    pub async fn register(
        &self,
        email: String,
        password: String,
        ip_address: Option<IpAddr>,
    ) -> Result<UserResponse, AppError> {
        // Validate password strength
        self.password.validate_strength(&password)?;
        self.password
            .validate_not_contains_email(&password, &email)?;

        // BUNYIP-253: server-side HIBP backstop. The /register SPA shipped
        // BUNYIP-240 with a client-side breach check; this matches it on
        // the server so any non-browser POST (curl, automation, a
        // forged fetch) cannot land a breached password in the DB.
        // `is_breached` fails open on HIBP outage (logged at warn).
        if crate::services::password_breach::is_breached(&password).await {
            return Err(AppError::validation(
                "password",
                "Password has appeared in a known data breach - pick a different one.",
            ));
        }

        // BUNYIP-330: block re-registration of a soft-deleted email. The
        // reservation is permanent - a deleted user's email can't be reused
        // by anyone else, matching the belt-and-braces posture that keeps a
        // fresh bunyip account from reaching the previous owner's mokosh
        // data through a shared identity. `email_reserved` drops the
        // `deleted_at IS NULL` gate that `find_by_email` applies. The
        // conflict copy is intentionally identical to the pre-330 message so
        // a caller can't enumerate soft-deleted-vs-active accounts.
        if UserRepository::email_reserved(&self.pool, &email).await? {
            return Err(AppError::conflict("Email already registered"));
        }

        // Hash password
        let password_hash = self.password.hash(&password)?;

        // Create user. Everyone registers as a subscriber; the bootstrap-admin
        // promotion below (BUNYIP-290) is the sole path that upgrades the first
        // admin, and it is gated on zero admins so it fires at most once.
        let mut user = UserRepository::create(
            &self.pool,
            CreateUser {
                email: email.clone(),
                password_hash: Some(password_hash),
                role: UserRole::Subscriber,
            },
        )
        .await?;

        // BUNYIP-290: if this is the bootstrap admin and no admin exists yet,
        // promote before the audit log records the actor role. The subsequent
        // login the handler performs will observe an admin already present and
        // no-op, so the issued session already carries `role = "admin"`.
        self.ensure_bootstrap_admin(&mut user).await?;

        // Create audit log
        let ip = ip_address.map(IpNetwork::from);
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::UserRegistered)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip)
                .with_resource("user", user.id),
        )
        .await?;

        Ok(UserResponse::from(user))
    }

    /// Login with email and password
    #[allow(clippy::too_many_arguments)]
    pub async fn login(
        &self,
        email: String,
        password: String,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
        trusted_device_token: Option<String>,
        device_id: Option<String>,
        remember: bool,
    ) -> Result<LoginResult, AppError> {
        // BUNYIP-381: absolute refresh-session deadline chosen here from
        // `remember` (1 day, or 30 days), then carried across rotation by
        // `create_tokens`. Both mint paths below (trusted-device skip and the
        // normal 2FA-cleared path) use it.
        let refresh_deadline = Some(Utc::now() + refresh_absolute_ttl(remember));
        // Find user
        let mut user = UserRepository::find_by_email(&self.pool, &email)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        // Check if user is deleted
        if user.is_deleted() {
            return Err(AppError::InvalidCredentials);
        }

        // Verify password
        let password_hash = user
            .password_hash
            .as_ref()
            .ok_or(AppError::InvalidCredentials)?;

        if !self.password.verify(&password, password_hash)? {
            return Err(AppError::InvalidCredentials);
        }

        // BUNYIP-290: promote the bootstrap admin now - after the password is
        // verified, before any 2FA branch or token mint - so every downstream
        // path (trusted-device skip, 2FA challenge, normal login) reflects the
        // updated role and the issued JWT carries `role = "admin"`. No-op once
        // an admin exists or for any non-bootstrap email.
        self.ensure_bootstrap_admin(&mut user).await?;

        // Check if 2FA is enabled AND actually configured
        if user.two_factor_enabled {
            let totp_record = TotpRepository::find_by_user_id(&self.pool, user.id).await?;
            let has_verified_totp = totp_record.map(|r| r.verified).unwrap_or(false);

            if has_verified_totp {
                // Trusted-device skip (BUNYIP-138): the password has already
                // been verified above; a subscriber presenting a valid trusted-
                // device cookie may skip the SECOND factor only. The opaque
                // cookie value is hashed and matched to a non-revoked, non-
                // expired, owner-matched row. Admins never skip.
                if let Some(token) = trusted_device_token.as_deref() {
                    let hash = self.jwt.hash_token(token);
                    if let Some(device) =
                        TrustedDeviceRepository::find_valid_by_hash(&self.pool, &hash).await?
                    {
                        if device.user_id == user.id && trusted_device_allows_skip(&user.role, true)
                        {
                            TrustedDeviceRepository::touch_last_used(&self.pool, device.id).await?;
                            let tokens = self
                                .create_tokens(
                                    &user,
                                    device_info.clone(),
                                    ip_address,
                                    refresh_deadline,
                                )
                                .await?;
                            UserRepository::update_last_login(&self.pool, user.id).await?;
                            self.check_login_location(&user, ip_address, device_info.as_deref())
                                .await;
                            let ip = ip_address.map(IpNetwork::from);
                            AuditLogRepository::create(
                                &self.pool,
                                CreateAuditLog::new(AuditAction::UserLogin)
                                    .with_actor(user.id, &user.email, &user.role)
                                    .with_ip(ip)
                                    .with_metadata(serde_json::json!({
                                        "method": "trusted_device",
                                        "device_info": device_info,
                                    })),
                            )
                            .await?;
                            return Ok(LoginResult::Success(tokens, UserResponse::from(user)));
                        }
                    }
                }

                let challenge_token = self.jwt.create_2fa_challenge_token(user.id)?;
                return Ok(LoginResult::TwoFactorRequired { challenge_token });
            }

            // Flag is true but no verified TOTP exists — reset the flag so the
            // frontend can redirect to 2FA setup after login
            UserRepository::set_two_factor_enabled(&self.pool, user.id, false).await?;
        }

        // BUNYIP-373: suspicious-login notify-and-approve gate. Only non-2FA
        // logins reach here (2FA accounts returned above), and those are already
        // second-factor protected. When enabled and this login looks suspicious
        // (new country or new device), withhold tokens and email a one-time
        // approval code instead of completing the login.
        let device_risk = if self.login_approval_enabled {
            let risk = self
                .assess_login(&user, ip_address, device_id.as_deref())
                .await;
            if risk.flagged {
                let challenge_token = self
                    .begin_login_approval(&user, &risk, ip_address, device_info.as_deref())
                    .await?;
                return Ok(LoginResult::ApprovalRequired { challenge_token });
            }
            Some(risk)
        } else {
            None
        };

        // Create tokens
        let tokens = self
            .create_tokens(&user, device_info.clone(), ip_address, refresh_deadline)
            .await?;

        // Update last login
        UserRepository::update_last_login(&self.pool, user.id).await?;
        self.check_login_location(&user, ip_address, device_info.as_deref())
            .await;
        // BUNYIP-373: remember this device on a clean login so it is a known
        // device (not a "new device" signal) next time.
        if let Some(risk) = &device_risk {
            self.record_login_device(&user, risk.device_hash.as_deref(), device_info.as_deref())
                .await;
        }

        // Create audit log
        let ip = ip_address.map(IpNetwork::from);
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::UserLogin)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip)
                .with_metadata(serde_json::json!({ "device_info": device_info })),
        )
        .await?;

        Ok(LoginResult::Success(tokens, UserResponse::from(user)))
    }

    /// Refresh tokens
    pub async fn refresh_tokens(
        &self,
        refresh_token: String,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<AuthTokens, AppError> {
        // Verify refresh token signature
        let claims = match self.jwt.verify_refresh_token(&refresh_token) {
            Ok(claims) => claims,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "token_refresh: JWT signature verification failed"
                );
                return Err(e);
            }
        };

        // Hash token to find in database
        let token_hash = self.jwt.hash_token(&refresh_token);

        // Find token in database
        let stored_token =
            match TokenRepository::find_refresh_token_by_hash(&self.pool, &token_hash).await? {
                Some(token) => token,
                None => {
                    // Diagnostic: check if the token exists at all (revoked/expired)
                    match TokenRepository::find_refresh_token_by_hash_any(&self.pool, &token_hash)
                        .await
                    {
                        Ok(Some(stale)) => {
                            tracing::warn!(
                                user_id = %claims.sub,
                                token_id = %claims.jti,
                                hash_prefix = %&token_hash[..8],
                                revoked_at = ?stale.revoked_at,
                                expires_at = %stale.expires_at,
                                created_at = %stale.created_at,
                                "token_refresh: token exists in DB but is revoked or expired"
                            );
                        }
                        Ok(None) => {
                            tracing::warn!(
                                user_id = %claims.sub,
                                token_id = %claims.jti,
                                hash_prefix = %&token_hash[..8],
                                "token_refresh: token hash does not exist in DB at all"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                user_id = %claims.sub,
                                token_id = %claims.jti,
                                error = %e,
                                "token_refresh: diagnostic query failed"
                            );
                        }
                    }
                    return Err(AppError::InvalidCredentials);
                }
            };

        // Check if token is valid
        if !stored_token.is_valid() {
            tracing::warn!(
                user_id = %claims.sub,
                token_id = %claims.jti,
                "token_refresh: stored token is no longer valid"
            );
            return Err(AppError::TokenExpired);
        }

        // Get user
        let user = UserRepository::find_by_id(&self.pool, claims.sub)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        // BUNYIP-381: no idle-timeout revocation. A refresh token lives for its
        // absolute deadline (1 day, or 30 days for "remember me"), carried across
        // rotation below rather than rolling forward.

        // Revoke old token
        TokenRepository::revoke_refresh_token(&self.pool, stored_token.id).await?;

        // Create new tokens, carrying the rotated-out token's absolute deadline
        // so the session ceiling (set at login) does not reset on every refresh.
        let tokens = self
            .create_tokens(
                &user,
                device_info,
                ip_address,
                Some(stored_token.expires_at),
            )
            .await?;

        Ok(tokens)
    }

    /// Logout (revoke refresh token)
    pub async fn logout(
        &self,
        refresh_token: String,
        user_id: Uuid,
        ip_address: Option<IpAddr>,
    ) -> Result<(), AppError> {
        // Hash token
        let token_hash = self.jwt.hash_token(&refresh_token);

        // Revoke token
        TokenRepository::revoke_refresh_token_by_hash(&self.pool, &token_hash).await?;

        // Get user for audit log
        if let Some(user) = UserRepository::find_by_id(&self.pool, user_id).await? {
            let ip = ip_address.map(IpNetwork::from);
            AuditLogRepository::create(
                &self.pool,
                CreateAuditLog::new(AuditAction::UserLogout)
                    .with_actor(user.id, &user.email, &user.role)
                    .with_ip(ip),
            )
            .await?;
        }

        Ok(())
    }

    /// Logout from all sessions
    pub async fn logout_all(
        &self,
        user_id: Uuid,
        ip_address: Option<IpAddr>,
    ) -> Result<(), AppError> {
        TokenRepository::revoke_all_user_refresh_tokens(&self.pool, user_id).await?;
        // "Log out everywhere" also drops trusted devices (BUNYIP-138).
        TrustedDeviceRepository::revoke_all_for_user(&self.pool, user_id).await?;

        // Get user for audit log
        if let Some(user) = UserRepository::find_by_id(&self.pool, user_id).await? {
            let ip = ip_address.map(IpNetwork::from);
            AuditLogRepository::create(
                &self.pool,
                CreateAuditLog::new(AuditAction::UserLogout)
                    .with_actor(user.id, &user.email, &user.role)
                    .with_ip(ip)
                    .with_metadata(serde_json::json!({ "all_sessions": true })),
            )
            .await?;
        }

        Ok(())
    }

    /// Request magic link
    pub async fn request_magic_link(
        &self,
        email: String,
        ip_address: Option<IpAddr>,
    ) -> Result<String, AppError> {
        let ip = ip_address.map(IpNetwork::from);

        // Generate token
        let token = generate_secure_token(32);
        let token_hash = self.jwt.hash_token(&token);
        let expires_at = Utc::now() + Duration::minutes(15);

        // Store token
        TokenRepository::create_magic_link_token(
            &self.pool,
            CreateMagicLinkToken {
                email: email.clone(),
                token_hash,
                expires_at,
                ip_address: ip,
            },
        )
        .await?;

        // Log the request (don't reveal if email exists)
        tracing::info!(email = %email, "Magic link requested");

        // Audit log
        let audit_log =
            if let Ok(Some(user)) = UserRepository::find_by_email(&self.pool, &email).await {
                CreateAuditLog::new(AuditAction::MagicLinkRequested)
                    .with_actor(user.id, &user.email, &user.role)
                    .with_ip(ip)
                    .with_metadata(serde_json::json!({ "email_known": true }))
            } else {
                CreateAuditLog::new(AuditAction::MagicLinkRequested)
                    .with_ip(ip)
                    .with_metadata(serde_json::json!({ "email_known": false, "email": email }))
            };
        // Non-critical — don't fail the request if audit logging fails
        if let Err(e) = AuditLogRepository::create(&self.pool, audit_log).await {
            tracing::error!(error = %e, "Failed to create audit log for magic link request");
        }

        Ok(token)
    }

    /// Verify magic link and login
    ///
    /// Returns (tokens, user, is_new_user) so the caller can send
    /// an account-created email for newly registered users.
    pub async fn verify_magic_link(
        &self,
        token: String,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
        device_id: Option<String>,
    ) -> Result<MagicLinkResult, AppError> {
        let token_hash = self.jwt.hash_token(&token);

        // Find token
        let magic_token = TokenRepository::find_magic_link_token_by_hash(&self.pool, &token_hash)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if !magic_token.is_valid() {
            return Err(AppError::TokenExpired);
        }

        // Mark token as used
        TokenRepository::mark_magic_link_token_used(&self.pool, magic_token.id).await?;

        // Find or create user
        let (user, is_new_user) =
            match UserRepository::find_by_email(&self.pool, &magic_token.email).await? {
                Some(user) => {
                    // Set email as verified
                    UserRepository::set_email_verified(&self.pool, user.id).await?;
                    let user = UserRepository::find_by_id(&self.pool, user.id)
                        .await?
                        .ok_or(AppError::not_found("User"))?;
                    (user, false)
                }
                None => {
                    // BUNYIP-330: a soft-deleted email is permanently
                    // reserved. `find_by_email` above skipped past a
                    // tombstoned row, but we must not silently create a new
                    // account under the same address. Refuse with the same
                    // conflict copy the /register endpoint uses so the
                    // signup path can't be used to enumerate deleted users.
                    if UserRepository::email_reserved(&self.pool, &magic_token.email).await? {
                        return Err(AppError::conflict("Email already registered"));
                    }
                    // Create new user (passwordless)
                    let user = UserRepository::create(
                        &self.pool,
                        CreateUser {
                            email: magic_token.email.clone(),
                            password_hash: None,
                            role: UserRole::Subscriber,
                        },
                    )
                    .await?;
                    // Set email as verified since they proved ownership via magic link
                    UserRepository::set_email_verified(&self.pool, user.id).await?;
                    let user = UserRepository::find_by_id(&self.pool, user.id)
                        .await?
                        .ok_or(AppError::not_found("User"))?;
                    (user, true)
                }
            };

        // Check if 2FA is enabled AND actually configured
        if user.two_factor_enabled {
            let totp_record = TotpRepository::find_by_user_id(&self.pool, user.id).await?;
            let has_verified_totp = totp_record.map(|r| r.verified).unwrap_or(false);

            if has_verified_totp {
                let challenge_token = self.jwt.create_2fa_challenge_token(user.id)?;
                return Ok(MagicLinkResult::TwoFactorRequired {
                    challenge_token,
                    is_new_user,
                });
            }

            // Flag is true but no verified TOTP exists — reset the flag
            UserRepository::set_two_factor_enabled(&self.pool, user.id, false).await?;
        }

        // BUNYIP-373: same suspicious-login gate as the password path. Reaches
        // here only for non-2FA accounts (2FA magic-link logins returned above).
        // A gated attempt is always an existing user - a brand-new magic-link
        // account has no baseline country/device to deviate from, so assess_login
        // never flags it.
        let device_risk = if self.login_approval_enabled {
            let risk = self
                .assess_login(&user, ip_address, device_id.as_deref())
                .await;
            if risk.flagged {
                let challenge_token = self
                    .begin_login_approval(&user, &risk, ip_address, device_info.as_deref())
                    .await?;
                return Ok(MagicLinkResult::ApprovalRequired { challenge_token });
            }
            Some(risk)
        } else {
            None
        };

        // Create tokens
        let tokens = self
            .create_tokens(&user, device_info.clone(), ip_address, None)
            .await?;

        // Update last login
        UserRepository::update_last_login(&self.pool, user.id).await?;
        self.check_login_location(&user, ip_address, device_info.as_deref())
            .await;
        // BUNYIP-373: remember this device on a clean login.
        if let Some(risk) = &device_risk {
            self.record_login_device(&user, risk.device_hash.as_deref(), device_info.as_deref())
                .await;
        }

        // Audit log
        let ip = ip_address.map(IpNetwork::from);
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::MagicLinkUsed)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;

        Ok(MagicLinkResult::Success(
            tokens,
            UserResponse::from(user),
            is_new_user,
        ))
    }

    /// Complete 2FA login after challenge token + TOTP/recovery code verification
    ///
    /// When `trust_device` is set and the account is a subscriber, a trusted
    /// device is created and its opaque secret is returned as the third tuple
    /// element so the handler can set the `bunyip_trusted_device` cookie. It is
    /// `None` for admins (who never skip 2FA) and when the flag is unset.
    pub async fn complete_2fa_login(
        &self,
        challenge_token: &str,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
        trust_device: bool,
    ) -> Result<(AuthTokens, UserResponse, Option<String>), AppError> {
        // Verify challenge token
        let claims = self.jwt.verify_2fa_challenge_token(challenge_token)?;
        let user_id = claims.sub;

        // Get user
        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if user.is_deleted() {
            return Err(AppError::InvalidCredentials);
        }

        // Create tokens
        let tokens = self
            .create_tokens(&user, device_info.clone(), ip_address, None)
            .await?;

        // Issue a trusted device only for subscribers who opted in (BUNYIP-138).
        let trusted_token = if trust_device && trusted_device_allows_skip(&user.role, true) {
            Some(
                self.issue_trusted_device(user.id, device_info.clone(), ip_address)
                    .await?,
            )
        } else {
            None
        };

        // Update last login
        UserRepository::update_last_login(&self.pool, user.id).await?;
        self.check_login_location(&user, ip_address, device_info.as_deref())
            .await;

        // Audit log
        let ip = ip_address.map(IpNetwork::from);
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::UserLogin)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip)
                .with_metadata(serde_json::json!({ "method": "2fa", "device_info": device_info })),
        )
        .await?;

        Ok((tokens, UserResponse::from(user), trusted_token))
    }

    /// Create a trusted device for a user and return the opaque cookie secret
    /// (the caller sets it as the `bunyip_trusted_device` cookie). Only the
    /// SHA-256 hash of the secret is stored (BUNYIP-138).
    pub async fn issue_trusted_device(
        &self,
        user_id: Uuid,
        label: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<String, AppError> {
        let token = generate_secure_token(32);
        let token_hash = self.jwt.hash_token(&token);
        let expires_at = Utc::now() + Duration::days(TRUSTED_DEVICE_TTL_DAYS);
        let ip = ip_address.map(IpNetwork::from);
        TrustedDeviceRepository::create(
            &self.pool,
            CreateTrustedDevice {
                user_id,
                token_hash,
                label,
                ip_address: ip,
                expires_at,
            },
        )
        .await?;
        Ok(token)
    }

    /// Revoke all of a user's trusted devices. Called on credential and 2FA
    /// changes so the TOTP prompt is re-armed on every device.
    pub async fn revoke_trusted_devices(&self, user_id: Uuid) -> Result<(), AppError> {
        TrustedDeviceRepository::revoke_all_for_user(&self.pool, user_id).await?;
        Ok(())
    }

    /// Request password reset
    pub async fn request_password_reset(
        &self,
        email: String,
        ip_address: Option<IpAddr>,
    ) -> Result<Option<String>, AppError> {
        let ip = ip_address.map(IpNetwork::from);

        // Find user
        let user = match UserRepository::find_by_email(&self.pool, &email).await? {
            Some(user) => user,
            None => return Ok(None), // Don't reveal if email exists
        };

        // Check if user has a password (not magic-link only)
        if user.password_hash.is_none() {
            return Ok(None);
        }

        // BUNYIP-256: invalidate any still-valid prior reset tokens for
        // this user before issuing a fresh one. Keeps the live-token
        // surface at exactly one per user, eliminates the "three reset
        // emails in my inbox, which one works?" confusion, and matches
        // the common UX where the latest link is the only working one.
        let cleared = TokenRepository::revoke_pending_password_reset_tokens(&self.pool, user.id)
            .await
            .unwrap_or(0);
        if cleared > 0 {
            tracing::info!(
                user_id = %user.id,
                cleared,
                "password reset: revoked prior pending tokens"
            );
        }

        // Generate token
        let token = generate_secure_token(32);
        let token_hash = self.jwt.hash_token(&token);
        let expires_at = Utc::now() + Duration::hours(1);

        // Store token
        TokenRepository::create_password_reset_token(
            &self.pool,
            CreatePasswordResetToken {
                user_id: user.id,
                token_hash,
                expires_at,
                ip_address: ip,
            },
        )
        .await?;

        // Audit log
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::PasswordResetRequested)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;

        Ok(Some(token))
    }

    /// Verify password reset token (check only, don't consume)
    pub async fn verify_reset_token(&self, token: String) -> Result<Uuid, AppError> {
        let token_hash = self.jwt.hash_token(&token);

        let reset_token =
            TokenRepository::find_password_reset_token_by_hash(&self.pool, &token_hash)
                .await?
                .ok_or(AppError::InvalidCredentials)?;

        if !reset_token.is_valid() {
            return Err(AppError::TokenExpired);
        }

        Ok(reset_token.user_id)
    }

    /// Complete password reset
    ///
    /// Returns the user's email so the caller can send a
    /// password-changed notification.
    pub async fn complete_password_reset(
        &self,
        token: String,
        new_password: String,
        ip_address: Option<IpAddr>,
    ) -> Result<String, AppError> {
        // Validate new password
        self.password.validate_strength(&new_password)?;

        // BUNYIP-253: server-side HIBP backstop on reset (mirror of the
        // register check). The /reset-password SPA shipped BUNYIP-240
        // with a client-side breach check; this closes the bypass for
        // non-browser POSTs.
        if crate::services::password_breach::is_breached(&new_password).await {
            return Err(AppError::validation(
                "new_password",
                "Password has appeared in a known data breach - pick a different one.",
            ));
        }

        let token_hash = self.jwt.hash_token(&token);

        // Find and validate token
        let reset_token =
            TokenRepository::find_password_reset_token_by_hash(&self.pool, &token_hash)
                .await?
                .ok_or(AppError::InvalidCredentials)?;

        if !reset_token.is_valid() {
            return Err(AppError::TokenExpired);
        }

        // Get user
        let user = UserRepository::find_by_id(&self.pool, reset_token.user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        // Validate password doesn't contain email
        self.password
            .validate_not_contains_email(&new_password, &user.email)?;

        // Hash new password
        let password_hash = self.password.hash(&new_password)?;

        // Update password
        UserRepository::update_password(&self.pool, user.id, &password_hash).await?;

        // Mark token as used
        TokenRepository::mark_password_reset_token_used(&self.pool, reset_token.id).await?;

        // Revoke all refresh tokens (logout everywhere)
        TokenRepository::revoke_all_user_refresh_tokens(&self.pool, user.id).await?;
        // A password reset also drops trusted devices (BUNYIP-138).
        TrustedDeviceRepository::revoke_all_for_user(&self.pool, user.id).await?;

        // Audit log
        let ip = ip_address.map(IpNetwork::from);
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::PasswordResetCompleted)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;

        Ok(user.email)
    }

    /// Change password (for logged-in users)
    pub async fn change_password(
        &self,
        user_id: Uuid,
        current_password: String,
        new_password: String,
        ip_address: Option<IpAddr>,
    ) -> Result<(), AppError> {
        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        // Verify current password
        let password_hash = user.password_hash.as_ref().ok_or(AppError::validation(
            "password",
            "No password set for this account",
        ))?;

        if !self.password.verify(&current_password, password_hash)? {
            return Err(AppError::validation(
                "current_password",
                "Current password is incorrect",
            ));
        }

        // Validate new password
        self.password.validate_strength(&new_password)?;
        self.password
            .validate_not_contains_email(&new_password, &user.email)?;

        // BUNYIP-253: server-side HIBP backstop on password change (mirror
        // of register + reset). Closes the bypass for non-browser POSTs.
        if crate::services::password_breach::is_breached(&new_password).await {
            return Err(AppError::validation(
                "new_password",
                "Password has appeared in a known data breach - pick a different one.",
            ));
        }

        // Hash and update
        let new_hash = self.password.hash(&new_password)?;
        UserRepository::update_password(&self.pool, user_id, &new_hash).await?;

        // Revoke every outstanding refresh token (legacy + OIDC) so a changed
        // password logs the user out everywhere, matching the password-reset
        // path. revoke_all_user_refresh_tokens unifies both surfaces.
        TokenRepository::revoke_all_user_refresh_tokens(&self.pool, user_id).await?;
        // A password change also drops trusted devices (BUNYIP-138).
        TrustedDeviceRepository::revoke_all_for_user(&self.pool, user_id).await?;

        // Audit log
        let ip = ip_address.map(IpNetwork::from);
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::PasswordChanged)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;

        Ok(())
    }

    /// Request email change
    ///
    /// For verified users: creates a verification token and returns it.
    /// For unverified users: changes email immediately and returns None.
    /// Returns (old_email, Option<token>) so caller can send appropriate emails.
    pub async fn request_email_change(
        &self,
        user_id: Uuid,
        new_email: String,
        current_password: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<(String, Option<String>), AppError> {
        let ip = ip_address.map(IpNetwork::from);

        // Get user
        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        // Check if new email is same as current
        if user.email.to_lowercase() == new_email.to_lowercase() {
            return Err(AppError::validation(
                "email",
                "New email must be different from current email",
            ));
        }

        // Check if new email is already taken. BUNYIP-330: also refuse
        // soft-deleted emails so a renamed account can't gain access to the
        // reserved identity of a previously-deleted user.
        if UserRepository::email_reserved(&self.pool, &new_email).await? {
            return Err(AppError::conflict("Email already registered"));
        }

        // If user has a password, require it for verification
        if let Some(password_hash) = &user.password_hash {
            let password = current_password.ok_or(AppError::validation(
                "current_password",
                "Password is required to change email",
            ))?;
            if !self.password.verify(&password, password_hash)? {
                return Err(AppError::validation(
                    "current_password",
                    "Current password is incorrect",
                ));
            }
        }

        let old_email = user.email.clone();

        if user.email_verified {
            // Rate limit: RESEND_LIMIT_MAX requests per rolling window.
            let since = Utc::now() - Duration::seconds(RESEND_LIMIT_WINDOW_SECS);
            let count =
                TokenRepository::count_recent_email_change_requests(&self.pool, user_id, since)
                    .await?;
            if count >= RESEND_LIMIT_MAX {
                // Report the real time until the oldest in-window request ages
                // out, not a hardcoded full window (BUNYIP-313).
                let oldest =
                    TokenRepository::oldest_recent_email_change_request(&self.pool, user_id, since)
                        .await?
                        .unwrap_or_else(Utc::now);
                let retry_after = resend_retry_after_secs(oldest, Utc::now());
                // BUNYIP-327: attributable rate-limit trip for the admin log view.
                tracing::error!(
                    category = "rate_limit",
                    client = %user_id,
                    action = "email_change_resend",
                    retry_after,
                    "email change resend rate limit exceeded"
                );
                return Err(AppError::RateLimited { retry_after });
            }

            // Cancel any pending requests
            TokenRepository::cancel_pending_email_change_requests(&self.pool, user_id).await?;

            // Generate token
            let token = generate_secure_token(32);
            let token_hash = self.jwt.hash_token(&token);
            let expires_at = Utc::now() + Duration::hours(1);

            // Store request
            TokenRepository::create_email_change_request(
                &self.pool,
                CreateEmailChangeRequest {
                    user_id,
                    new_email,
                    token_hash,
                    expires_at,
                    ip_address: ip,
                },
            )
            .await?;

            // Audit log
            AuditLogRepository::create(
                &self.pool,
                CreateAuditLog::new(AuditAction::EmailChangeRequested)
                    .with_actor(user.id, &user.email, &user.role)
                    .with_ip(ip),
            )
            .await?;

            Ok((old_email, Some(token)))
        } else {
            // Unverified user: change email immediately, using a transaction
            // to prevent race conditions on the unique email constraint
            let mut tx = self.pool.begin().await?;

            // Lock the user row to prevent concurrent email changes
            UserRepository::lock_for_update(&mut *tx, user_id).await?;

            // Re-check email availability inside the transaction. BUNYIP-330:
            // `email_reserved` also blocks soft-deleted rows so an unverified
            // user can't rename to a reserved identity mid-transaction.
            if UserRepository::email_reserved(&mut *tx, &new_email).await? {
                return Err(AppError::conflict("Email already registered"));
            }

            UserRepository::update_email(&mut *tx, user_id, &new_email, false).await?;

            // Revoke all refresh tokens (force re-login with new email)
            TokenRepository::revoke_all_user_refresh_tokens(&mut *tx, user_id).await?;

            tx.commit().await?;

            // Audit log (outside transaction, non-critical)
            AuditLogRepository::create(
                &self.pool,
                CreateAuditLog::new(AuditAction::EmailChangeCompleted)
                    .with_actor(user.id, &user.email, &user.role)
                    .with_ip(ip)
                    .with_metadata(
                        serde_json::json!({ "new_email": new_email, "immediate": true }),
                    ),
            )
            .await?;

            Ok((old_email, None))
        }
    }

    /// Confirm email change using verification token
    ///
    /// Returns (old_email, new_email) so caller can send notification.
    pub async fn confirm_email_change(
        &self,
        token: String,
        ip_address: Option<IpAddr>,
    ) -> Result<(String, String), AppError> {
        let ip = ip_address.map(IpNetwork::from);
        let token_hash = self.jwt.hash_token(&token);

        // Find request (outside transaction for early rejection)
        let request = TokenRepository::find_email_change_request_by_hash(&self.pool, &token_hash)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if !request.is_valid() {
            return Err(AppError::TokenExpired);
        }

        let new_email = request.new_email.clone();

        // Use a transaction with row locking to prevent race conditions
        let mut tx = self.pool.begin().await?;

        // Lock the user row to prevent concurrent email changes
        let user: User = UserRepository::find_by_id_for_update(&mut *tx, request.user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        let old_email = user.email.clone();

        // Re-check email availability inside the transaction. BUNYIP-330:
        // `email_reserved` also blocks soft-deleted rows, closing the race
        // where an email becomes reserved between request and confirmation.
        if UserRepository::email_reserved(&mut *tx, &new_email).await? {
            return Err(AppError::conflict("Email already registered"));
        }

        // Update email (set verified since they proved ownership)
        UserRepository::update_email(&mut *tx, user.id, &new_email, true).await?;

        // Confirm the request
        TokenRepository::confirm_email_change_request(&mut *tx, request.id).await?;

        // Revoke all refresh tokens (force re-login)
        TokenRepository::revoke_all_user_refresh_tokens(&mut *tx, user.id).await?;

        tx.commit().await?;

        // Audit log (outside transaction, non-critical)
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::EmailChangeCompleted)
                .with_actor(user.id, &old_email, &user.role)
                .with_ip(ip)
                .with_metadata(
                    serde_json::json!({ "old_email": old_email, "new_email": new_email }),
                ),
        )
        .await?;

        Ok((old_email, new_email))
    }

    /// Request email verification
    ///
    /// Generates a token and returns it so the caller can send the verification email.
    /// Requires email to not already be verified.
    pub async fn request_email_verification(
        &self,
        user_id: Uuid,
        ip_address: Option<IpAddr>,
    ) -> Result<String, AppError> {
        let ip = ip_address.map(IpNetwork::from);

        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        if user.email_verified {
            return Err(AppError::validation("email", "Email is already verified"));
        }

        // Rate limit: RESEND_LIMIT_MAX requests per rolling window.
        let since = Utc::now() - Duration::seconds(RESEND_LIMIT_WINDOW_SECS);
        let count =
            TokenRepository::count_recent_email_verification_tokens(&self.pool, user_id, since)
                .await?;
        if count >= RESEND_LIMIT_MAX {
            // Report the real time until the oldest in-window request ages out,
            // not a hardcoded full window (BUNYIP-313).
            let oldest =
                TokenRepository::oldest_recent_email_verification_token(&self.pool, user_id, since)
                    .await?
                    .unwrap_or_else(Utc::now);
            let retry_after = resend_retry_after_secs(oldest, Utc::now());
            // BUNYIP-327: attributable rate-limit trip for the admin log view.
            tracing::error!(
                category = "rate_limit",
                client = %user_id,
                action = "email_verify_resend",
                retry_after,
                "email verification resend rate limit exceeded"
            );
            return Err(AppError::RateLimited { retry_after });
        }

        // Generate token
        let token = generate_secure_token(32);
        let token_hash = self.jwt.hash_token(&token);
        let expires_at = Utc::now() + Duration::hours(1);

        // Store token
        TokenRepository::create_email_verification_token(
            &self.pool,
            CreateEmailVerificationToken {
                user_id,
                token_hash,
                expires_at,
                ip_address: ip,
            },
        )
        .await?;

        // Audit log
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::EmailVerificationRequested)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;

        Ok(token)
    }

    /// Confirm email verification using token.
    ///
    /// Returns `(user_id, email, Option<SubscriptionTier>)`. The tier is
    /// returned as `Some(...)` only when the verify also crossed the BUNYIP-221
    /// dual-condition threshold (email verified AND first / last name
    /// present), i.e. when this verify is the side that actually unlocks the
    /// trial. A verify that happens before the user has saved a name returns
    /// `Ok((..., None))`; the tier is granted later from
    /// `update_current_user_profile` once the names land. Either order wins.
    pub async fn confirm_email_verification(
        &self,
        token: String,
        ip_address: Option<IpAddr>,
    ) -> Result<(Uuid, String, Option<SubscriptionTier>), AppError> {
        let ip = ip_address.map(IpNetwork::from);
        let token_hash = self.jwt.hash_token(&token);

        // Find and validate token before opening the transaction
        let verification_token =
            TokenRepository::find_email_verification_token_by_hash(&self.pool, &token_hash)
                .await?
                .ok_or(AppError::InvalidCredentials)?;

        if !verification_token.is_valid() {
            return Err(AppError::TokenExpired);
        }

        let user = UserRepository::find_by_id(&self.pool, verification_token.user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        // Flip email_verified + consume the token in one tx. Tier assignment
        // is no longer part of this tx (BUNYIP-221): it now depends on the
        // user also having a first / last name, which is independent of the
        // verify click. The grant runs through `maybe_grant_initial_tier`
        // below, which handles the dual-condition gate + slot-count race via
        // its own advisory-locked tx.
        let mut tx = self.pool.begin().await?;

        TokenRepository::mark_email_verification_token_used(&mut *tx, verification_token.id)
            .await?;

        sqlx::query("UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1")
            .bind(user.id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        // Audit the verify itself. Tier metadata (when applicable) is logged
        // separately by `maybe_grant_initial_tier` via `InitialTierGranted` so
        // the timeline reads cleanly even when verify and grant are minutes
        // (or days) apart.
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::EmailVerified)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip),
        )
        .await?;

        let granted = self
            .maybe_grant_initial_tier(user.id, ip_address, TierGrantTrigger::EmailVerified)
            .await?;

        Ok((user.id, user.email, granted))
    }

    /// BUNYIP-221: grant the initial subscription tier (Lifetime / EarlyAdopter
    /// / Standard) when, and only when, both gate conditions are true:
    ///
    /// 1. `email_verified = true`.
    /// 2. `first_name` and `last_name` are both present (non-empty post-trim).
    ///
    /// Idempotent: a no-op for users who already have `trial_ends_at`
    /// populated or who already have a non-`standard` tier assigned (i.e. tier
    /// already granted, possibly under the pre-BUNYIP-221 verify-only flow).
    /// Returns `Ok(Some(tier))` when this call performed the grant,
    /// `Ok(None)` when either gate failed or the grant was already done.
    ///
    /// Called from `confirm_email_verification` (after the verify commits) and
    /// from `update_current_user_profile` (after a successful name save) so
    /// either order between "verify" and "fill in name" produces the grant.
    pub async fn maybe_grant_initial_tier(
        &self,
        user_id: Uuid,
        ip_address: Option<IpAddr>,
        trigger: TierGrantTrigger,
    ) -> Result<Option<SubscriptionTier>, AppError> {
        let ip = ip_address.map(IpNetwork::from);
        let user = UserRepository::find_by_id(&self.pool, user_id)
            .await?
            .ok_or(AppError::not_found("User"))?;

        // Gate 1: email verified.
        if !user.email_verified {
            return Ok(None);
        }
        // Gate 2: both names present (non-empty post-trim).
        let name_ok = |s: &Option<String>| s.as_deref().is_some_and(|v| !v.trim().is_empty());
        if !name_ok(&user.first_name) || !name_ok(&user.last_name) {
            return Ok(None);
        }
        // Idempotency: any signal that a prior grant happened means skip.
        // The "never granted" sentinel is exactly: `subscription_tier =
        // 'standard'` AND `trial_ends_at IS NULL` AND `lifetime_member =
        // false`. Anything else is "granted" (by this method, by the
        // pre-BUNYIP-221 verify-only path, or by an admin grant of `free` /
        // `lifetime`).
        if user.lifetime_member
            || user.trial_ends_at.is_some()
            || user.subscription_tier != "standard"
        {
            return Ok(None);
        }

        // Open a transaction to atomically assign the tier. Advisory lock
        // serialises concurrent grants so the slot count cannot be read twice
        // for the same slot (the same race the pre-BUNYIP-221 verify path
        // protected against). The lock id matches the one the verify path
        // used so the two never race against each other either.
        let mut tx = self.pool.begin().await?;

        sqlx::query("SELECT pg_advisory_xact_lock(9999999)")
            .execute(&mut *tx)
            .await?;

        // Re-read under the lock so a parallel call that already granted
        // between our pre-lock check and the lock acquisition does not
        // produce a duplicate write.
        let locked = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::not_found("User"))?;
        if locked.lifetime_member
            || locked.trial_ends_at.is_some()
            || locked.subscription_tier != "standard"
        {
            tx.commit().await?;
            return Ok(None);
        }

        let (lifetime_count, early_adopter_count) =
            UserRepository::count_tier_assignments(&mut *tx).await?;

        let tc = self
            .tier_config
            .read()
            .expect("TierConfig lock poisoned")
            .clone();

        let tier = SubscriptionTier::select(
            lifetime_count,
            early_adopter_count,
            tc.lifetime_slots,
            tc.early_adopter_slots,
        );

        UserRepository::assign_subscription_tier(
            &mut *tx,
            user_id,
            &tier,
            tc.early_adopter_trial_days,
            tc.standard_trial_days,
        )
        .await?;

        tx.commit().await?;

        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::InitialTierGranted)
                .with_actor(user.id, &user.email, &user.role)
                .with_ip(ip)
                .with_metadata(serde_json::json!({
                    "trigger": trigger.as_str(),
                    "subscription_tier": tier.as_str(),
                    // BUNYIP-291 AC2: record the applied trial explicitly so the
                    // early-adopter (90-day) vs standard (30-day) grant is
                    // labeled at signup rather than inferred from the tier.
                    "trial_days": tier.trial_days(tc.early_adopter_trial_days, tc.standard_trial_days),
                    "trial_label": tier.trial_label(tc.early_adopter_trial_days, tc.standard_trial_days),
                })),
        )
        .await?;

        Ok(Some(tier))
    }

    /// Create an admin invite
    pub async fn create_admin_invite(
        &self,
        email: String,
        admin_id: Uuid,
        admin_email: &str,
        admin_role: &str,
        ip_address: Option<IpAddr>,
    ) -> Result<String, AppError> {
        let ip = ip_address.map(IpNetwork::from);

        // Check if user is already an admin
        if let Some(user) = UserRepository::find_by_email(&self.pool, &email).await? {
            if user.role == "admin" {
                return Err(AppError::conflict("User is already an admin"));
            }
        }

        // Revoke any pending invites for this email
        InviteRepository::revoke_pending_by_email(&self.pool, &email).await?;

        // Generate token
        let token = generate_secure_token(32);
        let token_hash = self.jwt.hash_token(&token);
        let expires_at = Utc::now() + Duration::days(7);

        // Store invite
        let invite = InviteRepository::create(
            &self.pool,
            CreateAdminInvite {
                email: email.clone(),
                token_hash,
                invited_by: admin_id,
                role: "admin".to_string(),
                expires_at,
            },
        )
        .await?;

        // Audit log
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::AdminInviteCreated)
                .with_actor(admin_id, admin_email, admin_role)
                .with_ip(ip)
                .with_resource("admin_invite", invite.id)
                .with_metadata(serde_json::json!({ "invited_email": email })),
        )
        .await?;

        Ok(token)
    }

    /// Accept an admin invite
    pub async fn accept_admin_invite(
        &self,
        token: String,
        password: Option<String>,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<AcceptInviteResult, AppError> {
        let ip = ip_address.map(IpNetwork::from);
        let token_hash = self.jwt.hash_token(&token);

        // Find invite
        let invite = InviteRepository::find_valid_by_token_hash(&self.pool, &token_hash)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if !invite.is_valid() {
            return Err(AppError::TokenExpired);
        }

        // Check if user exists
        match UserRepository::find_by_email(&self.pool, &invite.email).await? {
            Some(user) if user.role == "admin" => {
                // Already an admin — stale invite
                Err(AppError::conflict("User is already an admin"))
            }
            Some(user) => {
                // Existing non-admin user — upgrade to admin
                InviteRepository::mark_accepted(&self.pool, invite.id).await?;
                let updated_user =
                    UserRepository::update_role(&self.pool, user.id, "admin").await?;
                UserRepository::set_email_verified(&self.pool, user.id).await?;

                // Create auth tokens
                let tokens = self
                    .create_tokens(&updated_user, device_info.clone(), ip_address, None)
                    .await?;
                UserRepository::update_last_login(&self.pool, user.id).await?;
                self.check_login_location(&updated_user, ip_address, device_info.as_deref())
                    .await;

                // Audit log
                AuditLogRepository::create(
                    &self.pool,
                    CreateAuditLog::new(AuditAction::AdminInviteAccepted)
                        .with_actor(user.id, &user.email, "admin")
                        .with_ip(ip)
                        .with_resource("admin_invite", invite.id)
                        .with_metadata(serde_json::json!({
                            "existing_user": true,
                            "previous_role": user.role,
                        })),
                )
                .await?;

                let refreshed = UserRepository::find_by_id(&self.pool, updated_user.id)
                    .await?
                    .ok_or(AppError::not_found("User"))?;

                Ok(AcceptInviteResult::Success(
                    tokens,
                    UserResponse::from(refreshed),
                ))
            }
            None => {
                // BUNYIP-330: `find_by_email` skipped past a tombstoned row.
                // An admin invite that lands on a soft-deleted email must
                // NOT auto-provision a fresh user under that reserved
                // identity. Refuse with the same conflict copy the register
                // path uses.
                if UserRepository::email_reserved(&self.pool, &invite.email).await? {
                    return Err(AppError::conflict("Email already registered"));
                }

                // New user — need password
                let password = match password {
                    Some(p) => p,
                    None => {
                        return Ok(AcceptInviteResult::PasswordRequired {
                            email: invite.email.clone(),
                        });
                    }
                };

                // Validate password
                self.password.validate_strength(&password)?;
                self.password
                    .validate_not_contains_email(&password, &invite.email)?;
                let password_hash = self.password.hash(&password)?;

                // Create user as admin
                let user = UserRepository::create(
                    &self.pool,
                    CreateUser {
                        email: invite.email.clone(),
                        password_hash: Some(password_hash),
                        role: UserRole::Admin,
                    },
                )
                .await?;
                UserRepository::set_email_verified(&self.pool, user.id).await?;

                // Mark invite accepted
                InviteRepository::mark_accepted(&self.pool, invite.id).await?;

                // Create auth tokens
                let tokens = self
                    .create_tokens(&user, device_info.clone(), ip_address, None)
                    .await?;
                UserRepository::update_last_login(&self.pool, user.id).await?;
                self.check_login_location(&user, ip_address, device_info.as_deref())
                    .await;

                // Audit log
                AuditLogRepository::create(
                    &self.pool,
                    CreateAuditLog::new(AuditAction::AdminInviteAccepted)
                        .with_actor(user.id, &invite.email, "admin")
                        .with_ip(ip)
                        .with_resource("admin_invite", invite.id)
                        .with_metadata(serde_json::json!({
                            "existing_user": false,
                            "new_user_id": user.id,
                        })),
                )
                .await?;

                let refreshed = UserRepository::find_by_id(&self.pool, user.id)
                    .await?
                    .ok_or(AppError::not_found("User"))?;

                Ok(AcceptInviteResult::Success(
                    tokens,
                    UserResponse::from(refreshed),
                ))
            }
        }
    }

    /// Revoke an admin invite
    pub async fn revoke_admin_invite(
        &self,
        invite_id: Uuid,
        admin_id: Uuid,
        admin_email: &str,
        admin_role: &str,
    ) -> Result<(), AppError> {
        InviteRepository::mark_revoked(&self.pool, invite_id).await?;

        // Audit log
        AuditLogRepository::create(
            &self.pool,
            CreateAuditLog::new(AuditAction::AdminInviteRevoked)
                .with_actor(admin_id, admin_email, admin_role)
                .with_resource("admin_invite", invite_id),
        )
        .await?;

        Ok(())
    }

    /// Helper to create auth tokens.
    ///
    /// `refresh_expires_at` carries an existing session's absolute deadline
    /// across a refresh rotation. On a fresh login it is `None` and the
    /// deadline is computed from the role's absolute TTL. On refresh the caller
    /// passes the rotated-out token's `expires_at`: for admins the deadline is
    /// the STRICTER of that existing value and a fresh admin TTL, so the
    /// 12-hour ceiling is not reset every refresh (a true absolute cap) and a
    /// deadline that was somehow issued under a looser policy (e.g. a 30-day
    /// subscriber window that escaped role-change revocation) can only ever be
    /// tightened, never extended, once the account is an admin. For subscribers
    /// the deadline is recomputed (rolling 30-day window, the historical
    /// behavior) so subscriber sessions are unchanged (BUNYIP-137).
    async fn create_tokens(
        &self,
        user: &User,
        device_info: Option<String>,
        ip_address: Option<IpAddr>,
        refresh_expires_at: Option<DateTime<Utc>>,
    ) -> Result<AuthTokens, AppError> {
        let access_token = self.jwt.create_access_token(user)?;
        let (refresh_token, token_hash) = self.jwt.create_refresh_token(user.id)?;

        let ip = ip_address.map(IpNetwork::from);
        // BUNYIP-381: the absolute refresh deadline is chosen at login (from
        // `remember`, via `refresh_absolute_ttl`) and carried verbatim across
        // rotation. A mint with no carried deadline (magic-link, 2FA / approval
        // completion, invite acceptance) defaults to the 1-day non-remember cap.
        let expires_at = refresh_expires_at.unwrap_or_else(|| Utc::now() + Duration::days(1));

        // Store refresh token
        TokenRepository::create_refresh_token(
            &self.pool,
            CreateRefreshToken {
                user_id: user.id,
                token_hash,
                device_info,
                ip_address: ip,
                expires_at,
            },
        )
        .await?;

        Ok(AuthTokens {
            access_token,
            refresh_token,
            expires_in: 900, // 15 minutes in seconds
        })
    }
}

/// Generate a cryptographically secure random token
pub(crate) fn generate_secure_token(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &bytes)
}

/// BUNYIP-366: the action to take for a resolved login country, given the
/// country recorded at the user's previous login. Kept pure (no DB, no mailer)
/// so the branch logic is unit-testable in isolation.
#[derive(Debug, PartialEq, Eq)]
enum LoginLocationDecision {
    /// No prior country on record: store this one silently, no alert.
    Record,
    /// Same country as last time: do nothing.
    Unchanged,
    /// Country differs from last time: alert the user, then store the new one.
    Alert,
}

/// Decide what to do for the `current` login country given the `previous` one.
fn login_location_decision(previous: Option<&str>, current: &str) -> LoginLocationDecision {
    match previous {
        None => LoginLocationDecision::Record,
        Some(prev) if prev == current => LoginLocationDecision::Unchanged,
        Some(_) => LoginLocationDecision::Alert,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_absolute_ttl_is_remember_based() {
        // BUNYIP-381: uniform across roles - 30 days with "remember me", else 1 day.
        assert_eq!(refresh_absolute_ttl(true), Duration::days(30));
        assert_eq!(refresh_absolute_ttl(false), Duration::days(1));
    }

    // ── BUNYIP-377: signup submit-timing guard ─────────────────────────────
    #[test]
    fn signup_rejects_submits_faster_than_min_fill() {
        let now = Utc::now().timestamp();
        // A submit at the same instant the form was issued is a bot.
        assert!(signup_submitted_too_fast(now, now));
        // Just under the minimum fill time: still too fast.
        assert!(signup_submitted_too_fast(
            now - (SIGNUP_MIN_FILL_SECONDS - 1),
            now
        ));
        // At or past the minimum fill time: a plausible human, allowed.
        assert!(!signup_submitted_too_fast(
            now - SIGNUP_MIN_FILL_SECONDS,
            now
        ));
        assert!(!signup_submitted_too_fast(now - 30, now));
    }

    // ── BUNYIP-290: first-admin bootstrap predicate ────────────────────────
    // Covers the five promotion scenarios from the issue. The predicate is the
    // pure core of `ensure_bootstrap_admin`; the DB side (find_admin_emails /
    // update_role) is the caller's `any_admin_exists` argument and the actual
    // role write, both idempotent.

    const BOOTSTRAP: &str = "admin@bunyip.local";

    #[test]
    fn bootstrap_promotes_matching_email_when_no_admin_exists() {
        // Sign-up OR sign-in: bootstrap email, subscriber role, zero admins.
        assert!(bootstrap_promotion_needed(
            Some(BOOTSTRAP),
            "admin@bunyip.local",
            "subscriber",
            false,
        ));
    }

    #[test]
    fn bootstrap_matches_email_case_insensitively() {
        // Config lowercases the env value; the stored email is normalized too,
        // but compare case-insensitively so a mixed-case DB row still matches.
        assert!(bootstrap_promotion_needed(
            Some(BOOTSTRAP),
            "Admin@Bunyip.Local",
            "subscriber",
            false,
        ));
    }

    #[test]
    fn bootstrap_does_not_promote_a_non_bootstrap_email() {
        // A different user signing up/in stays a subscriber.
        assert!(!bootstrap_promotion_needed(
            Some(BOOTSTRAP),
            "someone-else@bunyip.local",
            "subscriber",
            false,
        ));
    }

    #[test]
    fn bootstrap_is_inert_once_an_admin_exists() {
        // The bootstrap email itself cannot mint a SECOND admin once one exists.
        assert!(!bootstrap_promotion_needed(
            Some(BOOTSTRAP),
            "admin@bunyip.local",
            "subscriber",
            true,
        ));
        // ...and a non-bootstrap user certainly cannot become admin this way.
        assert!(!bootstrap_promotion_needed(
            Some(BOOTSTRAP),
            "someone-else@bunyip.local",
            "subscriber",
            true,
        ));
    }

    #[test]
    fn bootstrap_does_not_re_promote_an_existing_admin() {
        // Repeat auth of the already-promoted bootstrap admin is a no-op even
        // with zero OTHER admins counted, so it never churns the role.
        assert!(!bootstrap_promotion_needed(
            Some(BOOTSTRAP),
            "admin@bunyip.local",
            "admin",
            false,
        ));
    }

    #[test]
    fn bootstrap_unset_never_promotes() {
        // No BOOTSTRAP_ADMIN_EMAIL: the site comes up admin-less and functional.
        assert!(!bootstrap_promotion_needed(
            None,
            "admin@bunyip.local",
            "subscriber",
            false
        ));
    }

    #[test]
    fn trusted_device_skip_only_for_subscriber_with_valid_device() {
        // Subscriber with a valid device skips; admins never skip; no valid
        // device never skips (BUNYIP-138).
        assert!(trusted_device_allows_skip("subscriber", true));
        assert!(!trusted_device_allows_skip("admin", true));
        assert!(!trusted_device_allows_skip("subscriber", false));
        assert!(!trusted_device_allows_skip("admin", false));
    }

    #[test]
    fn retry_after_is_small_when_oldest_request_near_expiry() {
        // Oldest in-window request was made 59m59s ago, so it ages out of the
        // 1-hour window in ~1s: retry_after must be small, not a full window.
        let now = Utc::now();
        let oldest = now - Duration::seconds(RESEND_LIMIT_WINDOW_SECS - 1);
        let retry = resend_retry_after_secs(oldest, now);
        assert!(retry <= 2, "expected small retry_after, got {retry}");
        assert!(
            retry >= 1,
            "retry_after must be clamped to >= 1, got {retry}"
        );
    }

    #[test]
    fn retry_after_is_near_full_window_when_oldest_just_made() {
        // Oldest request made just now: the window frees up in ~1 hour.
        let now = Utc::now();
        let retry = resend_retry_after_secs(now, now);
        assert_eq!(retry, RESEND_LIMIT_WINDOW_SECS as u64);
    }

    #[test]
    fn retry_after_clamps_to_one_for_expired_window() {
        // Oldest request already older than the window (edge race): still
        // reports a truthful, positive Retry-After rather than 0 or negative.
        let now = Utc::now();
        let oldest = now - Duration::seconds(RESEND_LIMIT_WINDOW_SECS + 120);
        assert_eq!(resend_retry_after_secs(oldest, now), 1);
    }

    #[test]
    fn generate_secure_token_correct_length() {
        // 32 bytes base64url-encoded = 43 chars (no padding)
        let token = generate_secure_token(32);
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn generate_secure_token_unique() {
        let token1 = generate_secure_token(32);
        let token2 = generate_secure_token(32);
        assert_ne!(token1, token2);
    }

    #[test]
    fn generate_secure_token_url_safe() {
        let token = generate_secure_token(64);
        // URL-safe base64 only contains [A-Za-z0-9_-]
        assert!(token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
    }

    #[test]
    fn generate_secure_token_various_lengths() {
        for len in [1, 8, 16, 32, 64] {
            let token = generate_secure_token(len);
            assert!(!token.is_empty());
            // Decode back to verify it's valid base64
            let decoded =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &token)
                    .unwrap();
            assert_eq!(decoded.len(), len);
        }
    }

    // BUNYIP-366: only genuinely public client IPs may drive a country-change
    // alert; loopback / RFC1918 / link-local / unspecified must be ignored.
    #[test]
    fn non_public_ip_detection() {
        let non_public = [
            "127.0.0.1",     // loopback v4
            "10.1.2.3",      // RFC1918
            "192.168.1.1",   // RFC1918
            "172.16.0.1",    // RFC1918
            "169.254.10.10", // link-local v4
            "0.0.0.0",       // unspecified v4
            "::1",           // loopback v6
            "::",            // unspecified v6
            "fd00::1",       // unique-local v6
            "fe80::1",       // link-local v6
        ];
        for ip in non_public {
            assert!(
                AuthService::is_non_public_ip(&ip.parse().unwrap()),
                "{ip} should be treated as non-public"
            );
        }

        let public = ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"];
        for ip in public {
            assert!(
                !AuthService::is_non_public_ip(&ip.parse().unwrap()),
                "{ip} should be treated as public"
            );
        }
    }

    // BUNYIP-366: the None -> Record / same -> Unchanged / differ -> Alert
    // decision that drives whether a login sends the new-location email.
    #[test]
    fn login_location_decision_branches() {
        assert_eq!(
            login_location_decision(None, "US"),
            LoginLocationDecision::Record
        );
        assert_eq!(
            login_location_decision(Some("US"), "US"),
            LoginLocationDecision::Unchanged
        );
        assert_eq!(
            login_location_decision(Some("US"), "GB"),
            LoginLocationDecision::Alert
        );
    }
}
