//! Rate limiting models

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

/// Rate limit database model
#[derive(Debug, Clone, FromRow)]
pub struct RateLimit {
    pub id: Uuid,
    pub key: String,
    pub action: String,
    pub count: i32,
    pub window_start: DateTime<Utc>,
}

/// Rate limit configuration
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub action: &'static str,
    pub max_requests: i32,
    pub window_seconds: i64,
}

impl RateLimitConfig {
    /// Login: 5 requests per minute per email
    pub const LOGIN: Self = Self {
        action: "login",
        max_requests: 5,
        window_seconds: 60,
    };

    /// Magic link: 3 requests per 10 minutes per email
    pub const MAGIC_LINK: Self = Self {
        action: "magic_link",
        max_requests: 3,
        window_seconds: 600,
    };

    /// Password reset: 3 requests per hour per email
    pub const PASSWORD_RESET: Self = Self {
        action: "password_reset",
        max_requests: 3,
        window_seconds: 3600,
    };

    /// API (authenticated): 100 requests per minute per user
    pub const API_AUTH: Self = Self {
        action: "api_auth",
        max_requests: 100,
        window_seconds: 60,
    };

    /// API (unauthenticated): 20 requests per minute per IP
    pub const API_UNAUTH: Self = Self {
        action: "api_unauth",
        max_requests: 20,
        window_seconds: 60,
    };

    /// Registration: 3 requests per hour per IP
    pub const REGISTRATION: Self = Self {
        action: "registration",
        max_requests: 3,
        window_seconds: 3600,
    };

    /// OCI token endpoint, FAILED credential verifications: 5 per minute per
    /// email (BUNYIP-40). Only credential-guessing failures count toward this
    /// cap, so a chatty but VALID `docker compose pull` (one token per image
    /// per op) is never throttled, while credential stuffing is still capped at
    /// the same rate as `/v1/auth/login`.
    pub const OCI_TOKEN_FAILURES: Self = Self {
        action: "oci_token_failures",
        max_requests: 5,
        window_seconds: 60,
    };

    /// OCI token endpoint, ALL requests: 60 per minute per email (BUNYIP-40).
    /// A generous throughput cap that bounds Argon2 CPU (each verify is ~100ms)
    /// so a flood of valid-credential requests cannot exhaust the server, while
    /// staying far above any real multi-image pull.
    pub const OCI_TOKEN_THROUGHPUT: Self = Self {
        action: "oci_token_throughput",
        max_requests: 60,
        window_seconds: 60,
    };

    /// 2FA verify endpoint, FAILED code attempts per ACCOUNT: 5 per 15 minutes,
    /// keyed by `2fa_verify_user:{user_id}` (BUNYIP-201). The endpoint's only
    /// other throttle is per source IP, which does nothing against an attacker
    /// who rotates cheap proxy IPs against one victim's challenge token. This
    /// per-account cap is independent of source IP, so the aggregate guessing
    /// budget against a single account is bounded no matter how many IPs are
    /// used. Only failed code attempts increment it and a success resets it, so
    /// a legitimate user is never throttled; once the cap is hit the account's
    /// 2FA verification is locked for the rest of the window (even a correct
    /// code is refused), forcing the attacker to wait or the user to retry
    /// later / re-authenticate.
    pub const TWO_FACTOR_VERIFY_FAILURES: Self = Self {
        action: "two_factor_verify_failures",
        max_requests: 5,
        window_seconds: 900,
    };

    /// OCI token endpoint, FAILED verifications per source IP: 20 per minute
    /// (BUNYIP-40 optional hardening). The per-email failure cap alone lets one
    /// host spray a few guesses each across many accounts (each email has its
    /// own budget); this per-IP cap bounds that distributed-guessing shape. It
    /// counts only failures, so legitimate users behind a shared NAT/gateway
    /// (who rarely fail) are unaffected.
    pub const OCI_TOKEN_IP_FAILURES: Self = Self {
        action: "oci_token_ip_failures",
        max_requests: 20,
        window_seconds: 60,
    };
}
