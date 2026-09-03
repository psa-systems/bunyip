//! Rate limiting models.
//!
//! The cap and window in force for an action are NOT these compile-time consts:
//! they are the const resolved through the declared configuration providers
//! (`database` > `file` > `environment`, BUNYIP-643/645), which is what
//! [`RateLimitConfig::resolve`] does. This module owns the variable family that
//! makes that possible ([`rate_limit_vars`]), because the names are built from
//! the action; `RateLimitConfigRepository::effective` owns the database layer.

use chrono::{DateTime, Duration, Utc};
use sqlx::FromRow;
use std::sync::OnceLock;
use uuid::Uuid;

use crate::config_providers::ConfigStack;

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
    /// The key is an `oauth_clients.client_id` UUID: a calling app's machine
    /// identity, not a person (BUNYIP-602). There is no user to resolve.
    ClientId,
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
    /// Client-id-keyed (BUNYIP-602): a calling app's machine identity. Expose
    /// the client id; there is no user to resolve.
    ClientId(Uuid),
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
    /// the value actually in force through the declared configuration providers
    /// (see [`Self::resolve`] / `RateLimitConfigRepository::effective`), so a
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

    /// BUNYIP-602: the mailer relay, ALL requests, 60 per minute per CALLING
    /// APP (keyed by its `oauth_clients.client_id`). Per app, not per IP: the
    /// suite's apps sit behind shared egress, so an IP-keyed cap would make one
    /// app's burst throttle another's mail. `/v1/mailer/send` is exempt from the
    /// per-IP `RateLimitFloor` for the same reason, so this cap and
    /// [`Self::MAILER_AUTH_FAILURES`] are the whole control on that endpoint.
    pub const MAILER_SEND: Self = Self {
        action: "mailer_send",
        max_requests: 60,
        window_seconds: 60,
        key_kind: KeyKind::ClientId,
    };

    /// BUNYIP-602: mailer relay, FAILED client authentications per source IP,
    /// 10 per minute. Shaped on [`Self::OCI_TOKEN_IP_FAILURES`]: the relay
    /// verifies an Argon2 client secret (~100 ms of CPU) before it knows which
    /// app is calling, so an unauthenticated flood cannot be charged to a
    /// per-app cap. Counting only FAILURES leaves a legitimate app, which never
    /// fails, entirely unaffected by it.
    pub const MAILER_AUTH_FAILURES: Self = Self {
        action: "mailer_auth_failures",
        max_requests: 10,
        window_seconds: 60,
        key_kind: KeyKind::Ip,
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
        Self::MAILER_SEND,
        Self::MAILER_AUTH_FAILURES,
    ];

    /// Look up the preset for a stored `rate_limits.action` string. Returns
    /// `None` for an action with no matching preset (BUNYIP-315), so the caller
    /// can skip a row whose cap/window it cannot resolve rather than guessing.
    ///
    /// The returned preset carries the deployment providers already applied
    /// (BUNYIP-413/645), so no caller ever sees a bare compile-time const.
    pub fn by_action(action: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|c| c.action == action)
            .copied()
            .map(Self::with_deployment_defaults)
    }

    /// This action's cap and window resolved through `stack` (BUNYIP-645).
    ///
    /// The declared provider order decides which one serves each half, and this
    /// compile-time const is the built-in default that stands when none holds a
    /// usable value. A held value that does not parse, or is not positive, is
    /// not a value: the next provider serves it, and a `warn!` names both.
    pub fn resolve(self, stack: &ConfigStack) -> Self {
        let Some(vars) = Self::vars_for(self.action) else {
            return self;
        };
        self.with_overrides(
            stack.get_parsed_where::<i32>(vars.max_requests, |max| *max > 0),
            stack.get_parsed_where::<i64>(vars.window_seconds, |window| *window > 0),
        )
    }

    /// [`Self::resolve`] through the deployment providers alone (the file
    /// provider, then the environment): the bootstrap default a fresh install
    /// enforces, resolvable with no pool. `RateLimitConfigRepository::effective`
    /// is what adds the `rate_limit_configs` database provider on top of these.
    pub fn with_deployment_defaults(self) -> Self {
        self.resolve(ConfigStack::deployment_cached())
    }

    /// The variables carrying this action's cap and window, or `None` for an
    /// action with no preset (which therefore has no declared key either).
    pub fn vars_for(action: &str) -> Option<&'static RateLimitVars> {
        rate_limit_vars().iter().find(|vars| vars.action == action)
    }

    /// Apply an override layer: each `Some` replaces the corresponding field,
    /// `None` keeps the current value. Pure, so a provider's contribution is
    /// unit-testable without env, a file or a database.
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

    /// The variable names carrying this action's cap and window. The generator
    /// [`rate_limit_vars`] materializes them for the whole preset list; a caller
    /// wanting one action's pair as `&'static str` uses [`Self::vars_for`].
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
            KeyKind::ClientId => match Uuid::parse_str(key) {
                Ok(id) => KeySubject::ClientId(id),
                Err(_) => KeySubject::Unknown(key.to_string()),
            },
        }
    }
}

/// One action's pair of `RATE_LIMIT_*` variable names, with the operator-facing
/// sentence for each (BUNYIP-645).
///
/// Both registries that must declare the family read it from here, so the
/// variable name an operator sets, the key `config-status` reports and the
/// `ENV_INVENTORY` entry that classifies it can never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitVars {
    /// The action these variables configure.
    pub action: &'static str,
    /// `RATE_LIMIT_{ACTION}_MAX_REQUESTS`.
    pub max_requests: &'static str,
    /// What the cap variable configures.
    pub max_requests_setting: &'static str,
    /// `RATE_LIMIT_{ACTION}_WINDOW_SECONDS`.
    pub window_seconds: &'static str,
    /// What the window variable configures.
    pub window_seconds_setting: &'static str,
}

/// The whole `RATE_LIMIT_*` variable family, generated once per process from
/// [`RateLimitConfig::ALL`] (BUNYIP-645).
///
/// The names are built from the action rather than written down anywhere, which
/// is why the caps were left out of the configuration providers: a registry of
/// `&'static str` cannot hold a name that only exists at runtime. Leaking these
/// once at first use is what makes them `&'static`, and the set is bounded by
/// the preset list (four short strings per action, once per process), so it is a
/// one-off materialization rather than a leak that grows.
pub fn rate_limit_vars() -> &'static [RateLimitVars] {
    static VARS: OnceLock<Vec<RateLimitVars>> = OnceLock::new();
    VARS.get_or_init(|| {
        RateLimitConfig::ALL
            .iter()
            .map(|cfg| {
                let (max_requests, window_seconds) = RateLimitConfig::env_var_names(cfg.action);
                RateLimitVars {
                    action: cfg.action,
                    max_requests: max_requests.leak(),
                    max_requests_setting: format!(
                        "the {} rate-limit cap, in requests per window",
                        cfg.action
                    )
                    .leak(),
                    window_seconds: window_seconds.leak(),
                    window_seconds_setting: format!(
                        "the {} rate-limit window, in seconds",
                        cfg.action
                    )
                    .leak(),
                }
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_providers::{ConfigProvider, ConfigProviderKind};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A provider holding exactly what the test gives it, so the resolution is
    /// exercised without the process environment, a directory or a database.
    #[derive(Debug)]
    struct Fixed {
        kind: ConfigProviderKind,
        values: HashMap<String, String>,
    }

    impl Fixed {
        fn provider(kind: ConfigProviderKind, pairs: &[(&str, &str)]) -> Arc<dyn ConfigProvider> {
            Arc::new(Self {
                kind,
                values: pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            })
        }

        fn stack(kind: ConfigProviderKind, pairs: &[(&str, &str)]) -> ConfigStack {
            ConfigStack::new(vec![Self::provider(kind, pairs)])
        }
    }

    impl ConfigProvider for Fixed {
        fn kind(&self) -> ConfigProviderKind {
            self.kind
        }
        fn get(&self, key: &str) -> Option<String> {
            self.values.get(key).cloned()
        }
    }

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

    /// BUNYIP-645: a held value raises the cap for the one action and the one
    /// field it names, and a value the key cannot use (unparseable, or
    /// non-positive) leaves the compile-time const in force. Same rules the
    /// env-only chain applied before, now the provider stack's.
    #[test]
    fn a_held_value_overrides_only_the_action_and_field_it_names() {
        let stack = Fixed::stack(
            ConfigProviderKind::Environment,
            &[
                ("RATE_LIMIT_LOGIN_MAX_REQUESTS", "25"),
                ("RATE_LIMIT_REGISTRATION_WINDOW_SECONDS", "not-a-number"),
                ("RATE_LIMIT_API_AUTH_MAX_REQUESTS", "0"),
            ],
        );

        // The cap alone moves; the window keeps the const.
        let login = RateLimitConfig::LOGIN.resolve(&stack);
        assert_eq!((login.max_requests, login.window_seconds), (25, 60));

        // Unparseable, non-positive and unheld all leave the const in force.
        assert_eq!(
            RateLimitConfig::REGISTRATION.resolve(&stack),
            RateLimitConfig::REGISTRATION
        );
        assert_eq!(
            RateLimitConfig::API_AUTH.resolve(&stack),
            RateLimitConfig::API_AUTH
        );
        assert_eq!(
            RateLimitConfig::MAGIC_LINK.resolve(&stack),
            RateLimitConfig::MAGIC_LINK
        );
    }

    /// AC1 (BUNYIP-645): the cap resolves through the declared provider order,
    /// not through an order written into one function. The `rate_limit_configs`
    /// row is the database provider, so it still wins, and the file provider
    /// now sits between it and the environment.
    #[test]
    fn the_declared_provider_order_decides_the_cap() {
        let stack = ConfigStack::new(vec![
            Fixed::provider(
                ConfigProviderKind::Environment,
                &[
                    ("RATE_LIMIT_LOGIN_MAX_REQUESTS", "7"),
                    ("RATE_LIMIT_LOGIN_WINDOW_SECONDS", "70"),
                ],
            ),
            Fixed::provider(
                ConfigProviderKind::File,
                &[("RATE_LIMIT_LOGIN_MAX_REQUESTS", "8")],
            ),
            Fixed::provider(
                ConfigProviderKind::Database,
                &[("RATE_LIMIT_LOGIN_MAX_REQUESTS", "9")],
            ),
        ]);
        let login = RateLimitConfig::LOGIN.resolve(&stack);
        // database cap, and the window from the environment because neither
        // higher provider holds one.
        assert_eq!((login.max_requests, login.window_seconds), (9, 70));

        let without_database = ConfigStack::new(vec![
            Fixed::provider(
                ConfigProviderKind::Environment,
                &[("RATE_LIMIT_LOGIN_MAX_REQUESTS", "7")],
            ),
            Fixed::provider(
                ConfigProviderKind::File,
                &[("RATE_LIMIT_LOGIN_MAX_REQUESTS", "8")],
            ),
        ]);
        assert_eq!(
            RateLimitConfig::LOGIN
                .resolve(&without_database)
                .max_requests,
            8
        );
    }

    /// AC2 (BUNYIP-645): every preset has a generated variable pair, and the
    /// generated names are exactly what the formatter builds, so an action added
    /// to `ALL` is declared in both registries with no second edit.
    #[test]
    fn every_preset_has_a_generated_variable_pair() {
        assert_eq!(rate_limit_vars().len(), RateLimitConfig::ALL.len());
        for cfg in RateLimitConfig::ALL {
            let vars = RateLimitConfig::vars_for(cfg.action)
                .unwrap_or_else(|| panic!("{} has no generated variables", cfg.action));
            let (max_requests, window_seconds) = RateLimitConfig::env_var_names(cfg.action);
            assert_eq!(vars.max_requests, max_requests);
            assert_eq!(vars.window_seconds, window_seconds);
            assert!(!vars.max_requests_setting.is_empty());
            assert!(!vars.window_seconds_setting.is_empty());
        }
        assert!(RateLimitConfig::vars_for("no_such_action").is_none());
    }

    /// The removal this issue turns on (BUNYIP-645): the caps read no provider
    /// of their own. `with_env_defaults` and its `env_defaults` map were the
    /// environment layer of a chain only this file could see, so a `std::env`
    /// read reappearing in the rate-limit path would be that undeclared source
    /// again.
    #[test]
    fn the_rate_limit_path_reads_no_provider_of_its_own() {
        let sources = [
            ("models/rate_limit.rs", include_str!("rate_limit.rs")),
            (
                "repositories/rate_limit_config.rs",
                include_str!("../repositories/rate_limit_config.rs"),
            ),
            (
                "repositories/rate_limit.rs",
                include_str!("../repositories/rate_limit.rs"),
            ),
        ];
        let mut offenders = Vec::new();
        for (name, source) in sources {
            // Everything from `#[cfg(test)]` on is test scaffolding, which is
            // where this guard's own message lives.
            let production = match source.find("#[cfg(test)]") {
                Some(idx) => &source[..idx],
                None => source,
            };
            for (number, line) in production.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                // Spelled in two pieces so this needle is not itself an
                // `env::var("...")` literal for the BUNYIP-537 inventory scan
                // (bunyip-api/tests/env_inventory.rs) to find and fail on.
                for banned in [
                    concat!("env", "::var("),
                    "with_env_defaults",
                    "env_defaults()",
                ] {
                    if line.contains(banned) {
                        offenders.push(format!("{name}:{} ({banned})", number + 1));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "the rate-limit caps resolve through the declared configuration providers \
             (BUNYIP-645): read them with RateLimitConfig::resolve through a ConfigStack instead \
             of reintroducing a private environment layer: {offenders:#?}"
        );
    }

    /// The layering itself: each layer replaces only the fields it sets.
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
