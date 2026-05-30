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
}
