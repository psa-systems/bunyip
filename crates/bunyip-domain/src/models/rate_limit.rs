//! Rate limiting models

use chrono::{DateTime, Duration, Utc};
use sqlx::FromRow;
use std::collections::HashMap;
use std::sync::OnceLock;
use uuid::Uuid;

/// Prefix on the `rate_limits.key` for the per-account 2FA failure counter
/// (BUNYIP-201). Single source of truth shared by the enforcement path
/// (`bunyip-api` totp handler) and the admin read path (BUNYIP-315), which
/// strips it to recover the `user_id`.
pub const TWO_FACTOR_KEY_PREFIX: &str = "2fa_verify_user:";

/// Rate limit database model
#[derive(Debug, Clone, FromRow)]
pub struct RateLimit {
    pub id: Uuid,
    pub key: String,
    pub action: String,
    pub count: i32,
    pub window_start: DateTime<Utc>,
}

impl RateLimit {
    /// If this row is an *active* throttle under `config` at `now`, return the
    /// seconds until its window elapses (`retry_after`). A throttle is active
    /// when its window has not yet elapsed AND its count is at or over the cap
    /// (BUNYIP-315). Returns `None` for a stale window or an under-cap count.
    /// Pure and clock-free (the caller passes `now`) so it is unit-testable.
    pub fn active_retry_after(&self, config: &RateLimitConfig, now: DateTime<Utc>) -> Option<u64> {
        let window_end = self.window_start + Duration::seconds(config.window_seconds);
        if now < window_end && self.count >= config.max_requests {
            Some((window_end - now).num_seconds().max(0) as u64)
        } else {
            None
        }
    }
}

/// How a `rate_limits.key` should be interpreted for a given action, so the
/// admin read path can resolve it to a user where possible (BUNYIP-315).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// The key is the user's email address.
    Email,
    /// The key is the user's UUID.
    UserId,
    /// The key is `2fa_verify_user:{user_id}` (BUNYIP-201).
    TwoFactorUserId,
    /// The key is a source IP address; there is no user to resolve.
    Ip,
}

/// The resolved subject a `rate_limits.key` points at, once interpreted per its
/// action's [`KeyKind`] (BUNYIP-315).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySubject {
    /// Email-keyed: resolve the user via `find_by_email`.
    Email(String),
    /// User-id-keyed: resolve the user via `find_by_id`.
    UserId(Uuid),
    /// IP-keyed: expose the IP, no user to resolve.
    Ip(String),
    /// The action is unknown, or the key did not parse as expected; expose the
    /// raw key and resolve no user.
    Unknown(String),
}

/// Rate limit configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub action: &'static str,
    pub max_requests: i32,
    pub window_seconds: i64,
    /// How this action's `rate_limits.key` is shaped, so the admin read path
    /// can resolve it to a user where possible (BUNYIP-315).
    pub key_kind: KeyKind,
}

impl RateLimitConfig {
    /// Login: 5 requests per minute per email
    pub const LOGIN: Self = Self {
        action: "login",
        max_requests: 5,
        window_seconds: 60,
        key_kind: KeyKind::Email,
    };

    /// Magic link: 3 requests per 10 minutes per email
    pub const MAGIC_LINK: Self = Self {
        action: "magic_link",
        max_requests: 3,
        window_seconds: 600,
        key_kind: KeyKind::Email,
    };

    /// Password reset: 3 requests per hour per email
    pub const PASSWORD_RESET: Self = Self {
        action: "password_reset",
        max_requests: 3,
        window_seconds: 3600,
        key_kind: KeyKind::Email,
    };

    /// API (authenticated): 100 requests per minute per user
    pub const API_AUTH: Self = Self {
        action: "api_auth",
        max_requests: 100,
        window_seconds: 60,
        key_kind: KeyKind::UserId,
    };

    /// API (unauthenticated): 20 requests per minute per IP
    pub const API_UNAUTH: Self = Self {
        action: "api_unauth",
        max_requests: 20,
        window_seconds: 60,
        key_kind: KeyKind::Ip,
    };

    /// Registration: 3 requests per hour per IP.
    ///
    /// One cap for every environment (BUNYIP-601): the enforcement path resolves
    /// the value actually in force through the const -> env -> persisted chain
    /// (see [`with_env_defaults`] / `RateLimitConfigRepository::effective`), so a
    /// non-production instance loosens it by setting
    /// `RATE_LIMIT_REGISTRATION_MAX_REQUESTS` (the deployed-instance e2e suite
    /// self-provisions disposable accounts from one CI egress IP and would trip
    /// the 3/hour production cap). The handler no longer branches on
    /// `Config::is_production()` to pick a second preset; there is only this one.
    pub const REGISTRATION: Self = Self {
        action: "registration",
        max_requests: 3,
        window_seconds: 3600,
        key_kind: KeyKind::Ip,
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
        key_kind: KeyKind::Email,
    };

    /// OCI token endpoint, ALL requests: 60 per minute per email (BUNYIP-40).
    /// A generous throughput cap that bounds Argon2 CPU (each verify is ~100ms)
    /// so a flood of valid-credential requests cannot exhaust the server, while
    /// staying far above any real multi-image pull.
    pub const OCI_TOKEN_THROUGHPUT: Self = Self {
        action: "oci_token_throughput",
        max_requests: 60,
        window_seconds: 60,
        key_kind: KeyKind::Email,
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
        key_kind: KeyKind::TwoFactorUserId,
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
        key_kind: KeyKind::Ip,
    };

    /// BUNYIP-264: `/oauth2/token` per-IP cap. The token endpoint is the
    /// brute-force surface for `client_secret_basic` (and for code-reuse
    /// attempts before consume detection kicks in). 60/min covers the
    /// p99 of legitimate SPA refresh cycles (1 access token per 15 min
    /// per app, hub + RPs combined) with significant headroom.
    pub const OAUTH_TOKEN: Self = Self {
        action: "oauth_token",
        max_requests: 60,
        window_seconds: 60,
        key_kind: KeyKind::Ip,
    };

    /// BUNYIP-264: `/oauth2/authorize` per-IP cap. Legitimate browser
    /// flow fires several authorize round-trips per session (initial
    /// sign-in + per-app silent SSO + tenant picker re-entry); 120/min
    /// covers a power user juggling multiple apps + tabs.
    pub const OAUTH_AUTHORIZE: Self = Self {
        action: "oauth_authorize",
        max_requests: 120,
        window_seconds: 60,
        key_kind: KeyKind::Ip,
    };

    /// BUNYIP-264: `/oauth2/userinfo` per-IP cap. Silent-SSO + RP profile
    /// hydrations call userinfo regularly; 240/min covers multi-app
    /// browsers without throttling.
    pub const OAUTH_USERINFO: Self = Self {
        action: "oauth_userinfo",
        max_requests: 240,
        window_seconds: 60,
        key_kind: KeyKind::Ip,
    };

    /// BUNYIP-264: `/oauth2/revoke` per-IP cap. Logout fires this on
    /// most sessions; legitimate ceiling is well under 60/min per IP.
    pub const OAUTH_REVOKE: Self = Self {
        action: "oauth_revoke",
        max_requests: 60,
        window_seconds: 60,
        key_kind: KeyKind::Ip,
    };

    /// BUNYIP-264: `/.well-known/jwks.json` + discovery per-IP cap. RPs
    /// cache aggressively; abuse is the only reason for sustained traffic.
    /// 120/min lets a legitimate fleet of RPs refresh cache + a few stale
    /// peers retry without bumping into the limit.
    pub const OAUTH_DISCOVERY: Self = Self {
        action: "oauth_discovery",
        max_requests: 120,
        window_seconds: 60,
        key_kind: KeyKind::Ip,
    };

    /// Feedback submission: 5 per hour per IP. Promoted to a preset (BUNYIP-315)
    /// so the admin read path can resolve its cap/window from one place instead
    /// of the value being trapped in a handler-local literal.
    pub const FEEDBACK_SUBMIT: Self = Self {
        action: "feedback_submit",
        max_requests: 5,
        window_seconds: 3600,
        key_kind: KeyKind::Ip,
    };

    /// BUNYIP-433: SMTP "Test connection" button, 6 attempts per 5 minutes per
    /// admin (keyed by the admin's user id). Each attempt opens a real
    /// connect + TLS + AUTH handshake to the configured relay, so this bounds
    /// how often that probe can fire and stops the button being used to hammer
    /// (or slow-loris) the SMTP host.
    pub const SMTP_TEST: Self = Self {
        action: "smtp_test",
        max_requests: 6,
        window_seconds: 300,
        key_kind: KeyKind::UserId,
    };

    /// Every preset, so the admin read path can look one up by its stored
    /// `action` string (BUNYIP-315). Keep in lock-step with the consts above.
    pub const ALL: &'static [Self] = &[
        Self::LOGIN,
        Self::MAGIC_LINK,
        Self::PASSWORD_RESET,
        Self::API_AUTH,
        Self::API_UNAUTH,
        Self::REGISTRATION,
        Self::OCI_TOKEN_FAILURES,
        Self::OCI_TOKEN_THROUGHPUT,
        Self::TWO_FACTOR_VERIFY_FAILURES,
        Self::OCI_TOKEN_IP_FAILURES,
        Self::OAUTH_TOKEN,
        Self::OAUTH_AUTHORIZE,
        Self::OAUTH_USERINFO,
        Self::OAUTH_REVOKE,
        Self::OAUTH_DISCOVERY,
        Self::FEEDBACK_SUBMIT,
        Self::SMTP_TEST,
    ];

    /// Look up the preset for a stored `rate_limits.action` string. Returns
    /// `None` for an action with no matching preset (BUNYIP-315), so the caller
    /// can skip a row whose cap/window it cannot resolve rather than guessing.
    ///
    /// The returned preset carries the env-var bootstrap defaults already
    /// applied (BUNYIP-413), so no caller ever sees a bare compile-time const.
    pub fn by_action(action: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|c| c.action == action)
            .copied()
            .map(Self::with_env_defaults)
    }

    /// The bootstrap default for this action: the compile-time const with the
    /// `RATE_LIMIT_{ACTION}_MAX_REQUESTS` / `RATE_LIMIT_{ACTION}_WINDOW_SECONDS`
    /// env vars applied when set (BUNYIP-413). This is what a fresh install
    /// enforces; a persisted `rate_limit_configs` row overrides it per action.
    /// The env map is read once per process (see [`env_defaults`]).
    pub fn with_env_defaults(self) -> Self {
        match env_defaults().get(self.action) {
            Some(o) => self.with_overrides(o.max_requests, o.window_seconds),
            None => self,
        }
    }

    /// Apply an override layer: each `Some` replaces the corresponding field,
    /// `None` keeps the current value. Pure, so the const -> env -> persisted
    /// precedence chain is unit-testable without env or a database.
    pub fn with_overrides(
        mut self,
        max_requests: Option<i32>,
        window_seconds: Option<i64>,
    ) -> Self {
        if let Some(m) = max_requests {
            self.max_requests = m;
        }
        if let Some(w) = window_seconds {
            self.window_seconds = w;
        }
        self
    }

    /// The env-var names carrying this action's bootstrap default.
    pub fn env_var_names(action: &str) -> (String, String) {
        let upper = action.to_uppercase();
        (
            format!("RATE_LIMIT_{upper}_MAX_REQUESTS"),
            format!("RATE_LIMIT_{upper}_WINDOW_SECONDS"),
        )
    }

    /// Interpret a `rate_limits.key` per this config's [`KeyKind`] into the
    /// subject it identifies (BUNYIP-315). Email/UserId subjects are resolvable
    /// to a user; IP is exposed as-is; an unparseable user-id key falls back to
    /// [`KeySubject::Unknown`] carrying the raw key.
    pub fn subject(&self, key: &str) -> KeySubject {
        match self.key_kind {
            KeyKind::Email => KeySubject::Email(key.to_string()),
            KeyKind::UserId => match Uuid::parse_str(key) {
                Ok(id) => KeySubject::UserId(id),
                Err(_) => KeySubject::Unknown(key.to_string()),
            },
            KeyKind::TwoFactorUserId => match key
                .strip_prefix(TWO_FACTOR_KEY_PREFIX)
                .and_then(|rest| Uuid::parse_str(rest).ok())
            {
                Some(id) => KeySubject::UserId(id),
                None => KeySubject::Unknown(key.to_string()),
            },
            KeyKind::Ip => KeySubject::Ip(key.to_string()),
        }
    }
}

/// One action's env-var bootstrap default (BUNYIP-413). Either field may be
/// absent, so an operator can raise a cap without restating the window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RateLimitEnvDefault {
    pub max_requests: Option<i32>,
    pub window_seconds: Option<i64>,
}

/// Read the env-var bootstrap defaults for every preset action, once per
/// process. Values that are absent, unparseable, or non-positive are ignored,
/// so a typo degrades to the compile-time const rather than disabling a limit.
fn env_defaults() -> &'static HashMap<&'static str, RateLimitEnvDefault> {
    static DEFAULTS: OnceLock<HashMap<&'static str, RateLimitEnvDefault>> = OnceLock::new();
    DEFAULTS.get_or_init(|| read_env_defaults(|name| std::env::var(name).ok()))
}

/// Pure core of [`env_defaults`]: builds the map from an arbitrary env reader
/// so the parsing and validation rules are unit-testable.
fn read_env_defaults(
    get: impl Fn(&str) -> Option<String>,
) -> HashMap<&'static str, RateLimitEnvDefault> {
    let mut map = HashMap::new();
    for cfg in RateLimitConfig::ALL {
        let (max_var, window_var) = RateLimitConfig::env_var_names(cfg.action);
        let max_requests = get(&max_var)
            .and_then(|v| v.trim().parse::<i32>().ok())
            .filter(|m| *m > 0);
        let window_seconds = get(&window_var)
            .and_then(|v| v.trim().parse::<i64>().ok())
            .filter(|w| *w > 0);
        if max_requests.is_some() || window_seconds.is_some() {
            map.insert(
                cfg.action,
                RateLimitEnvDefault {
                    max_requests,
                    window_seconds,
                },
            );
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(action: &str, key: &str, count: i32, window_start: DateTime<Utc>) -> RateLimit {
        RateLimit {
            id: Uuid::nil(),
            key: key.to_string(),
            action: action.to_string(),
            count,
            window_start,
        }
    }

    #[test]
    fn by_action_covers_every_preset_and_misses_unknown() {
        for cfg in RateLimitConfig::ALL {
            let found = RateLimitConfig::by_action(cfg.action).expect("preset resolvable");
            assert_eq!(found.action, cfg.action);
            assert_eq!(found.max_requests, cfg.max_requests);
            assert_eq!(found.window_seconds, cfg.window_seconds);
        }
        assert!(RateLimitConfig::by_action("no_such_action").is_none());
    }

    /// BUNYIP-413: an env var raises the cap for one action only, and a bad or
    /// non-positive value is ignored so the compile-time const still applies.
    #[test]
    fn env_defaults_override_only_valid_values() {
        let env = HashMap::from([
            ("RATE_LIMIT_LOGIN_MAX_REQUESTS", "25"),
            ("RATE_LIMIT_REGISTRATION_WINDOW_SECONDS", "not-a-number"),
            ("RATE_LIMIT_API_AUTH_MAX_REQUESTS", "0"),
        ]);
        let defaults = read_env_defaults(|n| env.get(n).map(|v| v.to_string()));

        assert_eq!(
            defaults.get("login").copied(),
            Some(RateLimitEnvDefault {
                max_requests: Some(25),
                window_seconds: None,
            })
        );
        // Unparseable and non-positive values leave the action untouched.
        assert_eq!(defaults.get("registration"), None);
        assert_eq!(defaults.get("api_auth"), None);
        assert_eq!(defaults.get("magic_link"), None);
    }

    /// BUNYIP-413: the precedence chain is const -> env -> persisted, each layer
    /// replacing only the fields it sets.
    #[test]
    fn overrides_layer_over_the_const_default() {
        let base = RateLimitConfig::LOGIN;
        assert_eq!((base.max_requests, base.window_seconds), (5, 60));

        // Env layer: cap only.
        let env = base.with_overrides(Some(25), None);
        assert_eq!((env.max_requests, env.window_seconds), (25, 60));

        // Persisted layer on top: both fields.
        let persisted = env.with_overrides(Some(10), Some(300));
        assert_eq!(
            (persisted.max_requests, persisted.window_seconds),
            (10, 300)
        );

        // An empty layer changes nothing.
        assert_eq!(persisted.with_overrides(None, None), persisted);
    }

    #[test]
    fn env_var_names_follow_the_action() {
        assert_eq!(
            RateLimitConfig::env_var_names("oci_token_failures"),
            (
                "RATE_LIMIT_OCI_TOKEN_FAILURES_MAX_REQUESTS".to_string(),
                "RATE_LIMIT_OCI_TOKEN_FAILURES_WINDOW_SECONDS".to_string(),
            )
        );
    }

    #[test]
    fn subject_resolves_email_keyed_action() {
        // login keys by email (one email-keyed action, per BUNYIP-315 AC).
        let cfg = RateLimitConfig::by_action("login").unwrap();
        assert_eq!(
            cfg.subject("user@example.com"),
            KeySubject::Email("user@example.com".to_string())
        );
    }

    #[test]
    fn subject_resolves_ip_keyed_action() {
        // registration keys by IP (one IP-keyed action, per BUNYIP-315 AC).
        let cfg = RateLimitConfig::by_action("registration").unwrap();
        assert_eq!(
            cfg.subject("203.0.113.7"),
            KeySubject::Ip("203.0.113.7".to_string())
        );
    }

    #[test]
    fn subject_strips_two_factor_prefix_to_user_id() {
        // two_factor_verify_failures keys by `2fa_verify_user:{user_id}`
        // (the prefix case, per BUNYIP-315 AC).
        let cfg = RateLimitConfig::by_action("two_factor_verify_failures").unwrap();
        let id = Uuid::from_u128(0x1234);
        let key = format!("{TWO_FACTOR_KEY_PREFIX}{id}");
        assert_eq!(cfg.subject(&key), KeySubject::UserId(id));

        // A malformed key (missing/garbled uuid) degrades to Unknown, never a panic.
        assert_eq!(
            cfg.subject("2fa_verify_user:not-a-uuid"),
            KeySubject::Unknown("2fa_verify_user:not-a-uuid".to_string())
        );
    }

    #[test]
    fn active_retry_after_gates_on_window_and_count() {
        let now = DateTime::from_timestamp(1_000_000, 0).unwrap();
        let cfg = RateLimitConfig::LOGIN; // cap 5, window 60s

        // In-window, at the cap -> active, retry_after = remaining window.
        let start = now - Duration::seconds(20);
        assert_eq!(
            row("login", "e", 5, start).active_retry_after(&cfg, now),
            Some(40)
        );

        // In-window, over the cap -> still active.
        assert_eq!(
            row("login", "e", 9, start).active_retry_after(&cfg, now),
            Some(40)
        );

        // In-window but under the cap -> not active.
        assert_eq!(
            row("login", "e", 4, start).active_retry_after(&cfg, now),
            None
        );

        // Window already elapsed -> not active even at the cap.
        let stale = now - Duration::seconds(120);
        assert_eq!(
            row("login", "e", 5, stale).active_retry_after(&cfg, now),
            None
        );
    }
}
