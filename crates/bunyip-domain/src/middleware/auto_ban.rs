//! Auto-ban middleware
//!
//! Tracks suspicious requests per IP and automatically bans IPs that exceed
//! a configurable threshold. Inspired by Stalwart's auto-ban approach.
//!
//! Suspicious patterns are matched by string prefix/suffix/exact checks (no regex needed).
//! Bans are held in-memory for fast O(1) lookups and persisted to PostgreSQL asynchronously.

use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use std::{
    collections::{HashMap, HashSet},
    future::{ready, Future, Ready},
    net::IpAddr,
    pin::Pin,
    rc::Rc,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::AutoBanConfig;
use crate::middleware::auth::extract_client_ip;

// ── Pattern matching ────────────────────────────────────────────────────────

/// Compiled suspicious-path patterns (all static strings, no regex).
pub(crate) struct SuspiciousPatterns {
    suffixes: Vec<&'static str>,
    prefixes: Vec<&'static str>,
    exact: HashSet<&'static str>,
    contains: Vec<&'static str>,
}

impl SuspiciousPatterns {
    /// Build the default set of suspicious patterns.
    pub(crate) fn default_patterns() -> Self {
        Self {
            suffixes: vec![
                // Server-side scripting extensions
                ".php", ".phtml", ".phar", ".asp", ".aspx", ".ashx", ".asmx", ".jsp", ".jspx",
                ".do", ".action", ".cgi", ".pl", ".cfm", ".cfc",
                // Backup / config / archive files
                ".bak", ".backup", ".save", ".old", ".orig", ".swp", ".tmp", ".sql", ".sql.gz",
                ".log", ".conf", ".ini", ".yml", ".yaml", ".toml", ".xml", ".sh", ".bash", ".bat",
                ".cmd", ".tar", ".tar.gz", ".tgz", ".zip", ".rar", ".7z", ".gz", ".bz2",
            ],
            prefixes: vec![
                // CMS probes
                "/wp-",
                "/wordpress/",
                "/blog/wp-",
                "/joomla/",
                "/administrator/",
                "/drupal/",
                "/magento/",
                "/downloader/",
                "/cms/",
                // Admin panel / DB probes
                "/phpmyadmin/",
                "/pma/",
                "/myadmin/",
                "/mysql/",
                "/dbadmin/",
                "/phpMyAdmin/",
                // Credential / config probes
                "/aws-credentials",
                "/credentials",
                "/config.php",
                // Debug / dev probes
                "/api/swagger",
                "/swagger",
                "/api-docs",
                "/actuator",
                "/jolokia/",
                "/console/",
                "/manager/",
                "/host-manager/",
                "/debug",
                "/dump",
                // Directory probes
                "/node_modules/",
                "/test/",
                "/tmp/",
                "/backup/",
                "/backups/",
                "/src/",
            ],
            exact: HashSet::from([
                "/server-info",
                "/server-status",
                "/xmlrpc.php",
                "/database.yml",
                "/secrets.json",
                "/secrets.yml",
                "/docker.sh",
                "/Dockerfile",
                "/package.json",
                "/package-lock.json",
                "/api/info",
                "/api/config",
                "/api/debug",
                "/api/env",
                "/graphql",
                "/trace",
                "/test",
            ]),
            contains: vec![
                // Path traversal
                "../",
            ],
        }
    }

    /// Returns `true` if the path matches any suspicious pattern.
    pub(crate) fn matches(&self, path: &str) -> bool {
        // Normalise: lowercase for extension matching only
        let lower = path.to_ascii_lowercase();

        if self.exact.contains(path) {
            return true;
        }
        for prefix in &self.prefixes {
            if path.starts_with(prefix) {
                return true;
            }
        }
        for suffix in &self.suffixes {
            if lower.ends_with(suffix) {
                return true;
            }
        }
        for needle in &self.contains {
            if path.contains(needle) {
                return true;
            }
        }
        false
    }
}

// ── In-memory state ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct BanEntry {
    reason: String,
    expires_at: DateTime<Utc>,
}

/// A currently-active IP ban as surfaced by [`AutoBanService::list_bans`].
#[derive(Debug, Clone)]
pub struct BanInfo {
    pub ip: IpAddr,
    pub reason: String,
    pub strikes: u32,
    pub banned_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct StrikeEntry {
    count: u32,
    first_seen: DateTime<Utc>,
}

// ── AutoBanService ──────────────────────────────────────────────────────────

/// Shared auto-ban state: in-memory maps protected by `RwLock` + async DB persistence.
pub struct AutoBanService {
    banned: RwLock<HashMap<IpAddr, BanEntry>>,
    strikes: RwLock<HashMap<IpAddr, StrikeEntry>>,
    patterns: SuspiciousPatterns,
    config: AutoBanConfig,
    pool: PgPool,
}

impl AutoBanService {
    /// Create a new `AutoBanService`.
    pub fn new(config: AutoBanConfig, pool: PgPool) -> Self {
        Self {
            banned: RwLock::new(HashMap::new()),
            strikes: RwLock::new(HashMap::new()),
            patterns: SuspiciousPatterns::default_patterns(),
            config,
            pool,
        }
    }

    /// Returns `true` if the given IP is currently banned.
    ///
    /// Expired entries are evicted on read so the map stays bounded by the live
    /// ban set rather than growing until the periodic 5-minute sweep.
    pub async fn is_banned(&self, ip: &IpAddr) -> bool {
        let now = Utc::now();

        // Fast path: shared read lock covers the common cases (still banned, or
        // not in the map at all) without contending for the write lock.
        {
            let map = self.banned.read().await;
            match map.get(ip) {
                Some(entry) if now < entry.expires_at => return true,
                None => return false,
                Some(_) => {} // expired: fall through to evict under a write lock
            }
        }

        // Slow path: the entry is expired. Take the write lock and remove it,
        // re-checking expiry in case a concurrent ban refreshed it meanwhile.
        let mut map = self.banned.write().await;
        if let Some(entry) = map.get(ip) {
            if now >= entry.expires_at {
                map.remove(ip);
            }
        }
        false
    }

    /// Returns `true` if the path matches suspicious patterns.
    pub fn is_suspicious(&self, path: &str) -> bool {
        self.patterns.matches(path)
    }

    /// Record a strike for the IP. Returns `true` if the IP was **newly** banned.
    pub async fn record_strike(&self, ip: &IpAddr, path: &str) -> bool {
        let now = Utc::now();
        let window = chrono::Duration::seconds(self.config.window_secs as i64);

        let mut strikes = self.strikes.write().await;
        let entry = strikes.entry(*ip).or_insert(StrikeEntry {
            count: 0,
            first_seen: now,
        });

        // Reset strikes if outside the window
        if now - entry.first_seen > window {
            entry.count = 0;
            entry.first_seen = now;
        }

        entry.count += 1;

        if entry.count >= self.config.threshold {
            let reason = format!(
                "Auto-banned after {} suspicious requests (last: {})",
                entry.count, path
            );
            let expires_at = now + chrono::Duration::seconds(self.config.ban_duration_secs as i64);

            // Remove strikes — no longer needed
            strikes.remove(ip);
            // Release lock before acquiring banned lock
            drop(strikes);

            // Insert into banned map
            {
                let mut banned = self.banned.write().await;
                banned.insert(
                    *ip,
                    BanEntry {
                        reason: reason.clone(),
                        expires_at,
                    },
                );
            }

            // Persist ban to DB asynchronously
            let pool = self.pool.clone();
            let ip_owned = *ip;
            let reason_owned = reason.clone();
            let count = self.config.threshold;
            tokio::spawn(async move {
                if let Err(e) =
                    persist_ban(&pool, &ip_owned, &reason_owned, count, expires_at).await
                {
                    tracing::error!(error = %e, ip = %ip_owned, "Failed to persist IP ban to database");
                }
            });

            warn!(ip = %ip, reason = %reason, "IP auto-banned");
            return true;
        }

        false
    }

    /// Remove expired bans and stale strike entries.
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();

        // Clean expired bans
        {
            let mut banned = self.banned.write().await;
            banned.retain(|_, entry| entry.expires_at > now);
        }

        // Clean stale strikes
        {
            let window = chrono::Duration::seconds(self.config.window_secs as i64);
            let mut strikes = self.strikes.write().await;
            strikes.retain(|_, entry| now - entry.first_seen <= window);
        }
    }

    /// Populate in-memory ban map from database rows.
    pub async fn load_bans(&self, bans: Vec<IpBanRow>) {
        let mut map = self.banned.write().await;
        for ban in bans {
            let ip = ban.ip_address.ip();
            map.insert(
                ip,
                BanEntry {
                    reason: ban.reason,
                    expires_at: ban.expires_at,
                },
            );
        }
        info!(count = map.len(), "Loaded IP bans from database");
    }

    /// Lift a ban for `ip` immediately and durably.
    ///
    /// Removes the IP from the in-memory `banned` map (the map the request path
    /// actually checks in [`is_banned`](Self::is_banned)), clears any
    /// accumulated `strikes`, and deletes the persisted `ip_bans` row so the
    /// ban does not reappear on the next restart. All three are done in one
    /// call, so the very next request from that IP is allowed without waiting
    /// for expiry or a process restart.
    ///
    /// The in-memory removals happen before the awaited `DELETE`, so the
    /// enforcement effect (the IP is no longer banned) holds even if the
    /// database delete errors; the error is then propagated to the caller.
    ///
    /// Returns `true` if a ban was actually present (in the in-memory map or in
    /// the `ip_bans` table), `false` if the IP was not banned.
    pub async fn unban(&self, ip: &IpAddr) -> Result<bool, sqlx::Error> {
        let removed_from_map = {
            let mut banned = self.banned.write().await;
            banned.remove(ip).is_some()
        };
        {
            let mut strikes = self.strikes.write().await;
            strikes.remove(ip);
        }

        let network = ipnetwork::IpNetwork::from(*ip);
        let result = sqlx::query("DELETE FROM ip_bans WHERE ip_address = $1")
            .bind(network)
            .execute(&self.pool)
            .await?;

        let removed = removed_from_map || result.rows_affected() > 0;
        if removed {
            info!(ip = %ip, "IP ban lifted");
        }
        Ok(removed)
    }

    /// List all currently-active bans.
    ///
    /// Merges the persisted `ip_bans` rows (the source of `strikes` and
    /// `banned_at` metadata) with the in-memory `banned` map (authoritative for
    /// enforcement). Entries present only in memory - e.g. a freshly promoted
    /// ban whose asynchronous persist has not landed yet - derive `banned_at`
    /// from `expires_at` and report `strikes` as the configured threshold.
    /// Expired entries are excluded.
    pub async fn list_bans(&self) -> Result<Vec<BanInfo>, sqlx::Error> {
        let now = Utc::now();
        let mut by_ip: HashMap<IpAddr, BanInfo> = HashMap::new();

        for row in load_active_bans(&self.pool).await? {
            let ip = row.ip_address.ip();
            by_ip.insert(
                ip,
                BanInfo {
                    ip,
                    reason: row.reason,
                    strikes: row.strikes.max(0) as u32,
                    banned_at: row.banned_at,
                    expires_at: row.expires_at,
                },
            );
        }

        let ban_duration = chrono::Duration::seconds(self.config.ban_duration_secs as i64);
        let banned = self.banned.read().await;
        for (ip, entry) in banned.iter() {
            if entry.expires_at <= now {
                continue; // expired but not yet swept out of the map
            }
            by_ip.entry(*ip).or_insert_with(|| BanInfo {
                ip: *ip,
                reason: entry.reason.clone(),
                strikes: self.config.threshold,
                banned_at: entry.expires_at - ban_duration,
                expires_at: entry.expires_at,
            });
        }

        Ok(by_ip.into_values().collect())
    }

    /// Whether auto-banning is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Row returned from `SELECT * FROM ip_bans`.
#[derive(Debug, FromRow)]
pub struct IpBanRow {
    pub ip_address: ipnetwork::IpNetwork,
    pub reason: String,
    pub strikes: i32,
    pub banned_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Persist a ban to the database (upsert).
async fn persist_ban(
    pool: &PgPool,
    ip: &IpAddr,
    reason: &str,
    strikes: u32,
    expires_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let network = ipnetwork::IpNetwork::from(*ip);
    sqlx::query(
        r#"
        INSERT INTO ip_bans (ip_address, reason, strikes, expires_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (ip_address) DO UPDATE
            SET reason = EXCLUDED.reason,
                strikes = EXCLUDED.strikes,
                banned_at = NOW(),
                expires_at = EXCLUDED.expires_at
        "#,
    )
    .bind(network)
    .bind(reason)
    .bind(strikes as i32)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete expired bans from the database.
pub async fn cleanup_expired_bans(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM ip_bans WHERE expires_at < NOW()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Load active bans from the database.
pub async fn load_active_bans(pool: &PgPool) -> Result<Vec<IpBanRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, IpBanRow>(
        "SELECT ip_address, reason, strikes, banned_at, expires_at FROM ip_bans WHERE expires_at > NOW()",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

// ── Actix middleware ────────────────────────────────────────────────────────

/// Actix middleware factory for auto-banning.
pub struct AutoBanMiddleware {
    service: Arc<AutoBanService>,
}

impl AutoBanMiddleware {
    pub fn new(service: Arc<AutoBanService>) -> Self {
        Self { service }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AutoBanMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AutoBanMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AutoBanMiddlewareService {
            service: Rc::new(service),
            auto_ban: self.service.clone(),
        }))
    }
}

pub struct AutoBanMiddlewareService<S> {
    service: Rc<S>,
    auto_ban: Arc<AutoBanService>,
}

impl<S, B> Service<ServiceRequest> for AutoBanMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auto_ban = self.auto_ban.clone();
        let service = Rc::clone(&self.service);

        // If auto-ban is disabled, pass through immediately
        if !auto_ban.is_enabled() {
            let fut = service.call(req);
            return Box::pin(async move { fut.await.map(|res| res.map_into_left_body()) });
        }

        let ip = extract_client_ip(req.request());
        let path = req.path().to_string();

        Box::pin(async move {
            if let Some(ref ip) = ip {
                // Check if already banned
                if auto_ban.is_banned(ip).await {
                    let res = HttpResponse::Forbidden().finish();
                    return Ok(req.into_response(res).map_into_right_body());
                }

                // Check if the path is suspicious
                if auto_ban.is_suspicious(&path) {
                    let newly_banned = auto_ban.record_strike(ip, &path).await;
                    if newly_banned {
                        info!(ip = %ip, path = %path, "Suspicious request triggered auto-ban");
                    } else {
                        info!(ip = %ip, path = %path, "Suspicious request recorded as strike");
                    }
                    let res = HttpResponse::Forbidden().finish();
                    return Ok(req.into_response(res).map_into_right_body());
                }
            }

            // Clean request — pass through to inner service
            service.call(req).await.map(|res| res.map_into_left_body())
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::env_lock;

    #[test]
    fn test_suspicious_patterns_scripting_extensions() {
        let patterns = SuspiciousPatterns::default_patterns();
        assert!(patterns.matches("/index.php"));
        assert!(patterns.matches("/admin/login.asp"));
        assert!(patterns.matches("/app/main.jsp"));
        assert!(patterns.matches("/test.cgi"));
        assert!(patterns.matches("/script.pl"));
        assert!(patterns.matches("/page.phtml"));
        assert!(patterns.matches("/UPPER.PHP")); // case-insensitive suffix
    }

    #[test]
    fn test_suspicious_patterns_backup_files() {
        let patterns = SuspiciousPatterns::default_patterns();
        assert!(patterns.matches("/config.bak"));
        assert!(patterns.matches("/db.sql"));
        assert!(patterns.matches("/dump.sql.gz"));
        assert!(patterns.matches("/site.tar.gz"));
        assert!(patterns.matches("/archive.zip"));
        assert!(patterns.matches("/data.log"));
    }

    #[test]
    fn test_suspicious_patterns_cms_probes() {
        let patterns = SuspiciousPatterns::default_patterns();
        assert!(patterns.matches("/wp-config.php"));
        assert!(patterns.matches("/wp-admin"));
        assert!(patterns.matches("/wp-login.php"));
        assert!(patterns.matches("/wordpress/readme.html"));
        assert!(patterns.matches("/joomla/administrator"));
        assert!(patterns.matches("/administrator/index.php"));
        assert!(patterns.matches("/xmlrpc.php"));
    }

    #[test]
    fn test_suspicious_patterns_admin_probes() {
        let patterns = SuspiciousPatterns::default_patterns();
        assert!(patterns.matches("/server-info"));
        assert!(patterns.matches("/server-status"));
        assert!(patterns.matches("/phpmyadmin/index.php"));
        assert!(patterns.matches("/pma/setup"));
    }

    #[test]
    fn test_suspicious_patterns_credential_probes() {
        let patterns = SuspiciousPatterns::default_patterns();
        assert!(patterns.matches("/aws-credentials.txt"));
        assert!(patterns.matches("/credentials.json"));
        assert!(patterns.matches("/config.php.bak"));
        assert!(patterns.matches("/database.yml"));
        assert!(patterns.matches("/secrets.json"));
        assert!(patterns.matches("/Dockerfile"));
        assert!(patterns.matches("/package.json"));
    }

    #[test]
    fn test_suspicious_patterns_debug_probes() {
        let patterns = SuspiciousPatterns::default_patterns();
        assert!(patterns.matches("/api/info"));
        assert!(patterns.matches("/api/config"));
        assert!(patterns.matches("/api/debug"));
        assert!(patterns.matches("/api/env"));
        assert!(patterns.matches("/api/swagger/ui"));
        assert!(patterns.matches("/swagger/index.html"));
        assert!(patterns.matches("/graphql"));
        assert!(patterns.matches("/actuator/health"));
        assert!(patterns.matches("/debug/pprof"));
    }

    #[test]
    fn test_suspicious_patterns_path_traversal() {
        let patterns = SuspiciousPatterns::default_patterns();
        assert!(patterns.matches("/../../etc/passwd"));
        assert!(patterns.matches("/app/../config"));
    }

    #[test]
    fn test_suspicious_patterns_directory_probes() {
        let patterns = SuspiciousPatterns::default_patterns();
        assert!(patterns.matches("/node_modules/package/index.js"));
        assert!(patterns.matches("/src/app.js"));
        assert!(patterns.matches("/tmp/upload.txt"));
        assert!(patterns.matches("/backup/db.sql"));
    }

    #[test]
    fn test_clean_paths_not_flagged() {
        let patterns = SuspiciousPatterns::default_patterns();
        // SPA routes
        assert!(!patterns.matches("/"));
        assert!(!patterns.matches("/login"));
        assert!(!patterns.matches("/dashboard"));
        assert!(!patterns.matches("/settings"));
        assert!(!patterns.matches("/admin"));
        assert!(!patterns.matches("/pricing"));
        // Static assets
        assert!(!patterns.matches("/assets/index-abc123.js"));
        assert!(!patterns.matches("/assets/style-def456.css"));
        assert!(!patterns.matches("/config.js"));
        assert!(!patterns.matches("/health"));
        // API paths
        assert!(!patterns.matches("/v1/auth/login"));
        assert!(!patterns.matches("/v1/users/me"));
        assert!(!patterns.matches("/v1/admin/users"));
    }

    #[tokio::test]
    async fn test_record_strike_triggers_ban() {
        // A lazy pool never actually connects, so this stays a pure in-memory
        // unit test. The async DB-persist task spawned on ban promotion fails
        // to connect and logs, but that does not touch the in-memory ban
        // promotion this test exercises.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bunyip_autoban_test")
            .expect("lazy pool construction never connects");
        let config = AutoBanConfig {
            enabled: true,
            threshold: 3,
            window_secs: 3600,
            ban_duration_secs: 86400,
        };
        let service = AutoBanService::new(config, pool);
        let ip: IpAddr = "203.0.113.10".parse().unwrap();

        // Strikes below the threshold accumulate without banning.
        assert!(!service.record_strike(&ip, "/wp-login.php").await);
        assert!(!service.is_banned(&ip).await);
        assert!(!service.record_strike(&ip, "/phpmyadmin/").await);
        assert!(!service.is_banned(&ip).await);

        // The threshold strike promotes the IP to a ban.
        assert!(
            service.record_strike(&ip, "/xmlrpc.php").await,
            "threshold strike should return newly-banned = true"
        );
        assert!(service.is_banned(&ip).await, "IP should be banned now");
    }

    #[tokio::test]
    async fn test_unban_lifts_in_memory_ban() {
        // Lazy pool never connects: the DELETE inside `unban` errors, but the
        // in-memory map/strike removals run first, which is exactly what the
        // request path (`is_banned`) checks. We assert that enforcement effect
        // regardless of the DB error, proving a subsequent request is not
        // 403-ed after an unban.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bunyip_autoban_test")
            .expect("lazy pool construction never connects");
        let config = AutoBanConfig {
            enabled: true,
            threshold: 3,
            window_secs: 3600,
            ban_duration_secs: 86400,
        };
        let service = AutoBanService::new(config, pool);
        let ip: IpAddr = "203.0.113.20".parse().unwrap();

        // Drive the IP to a ban.
        service.record_strike(&ip, "/wp-login.php").await;
        service.record_strike(&ip, "/phpmyadmin/").await;
        assert!(service.record_strike(&ip, "/xmlrpc.php").await);
        assert!(service.is_banned(&ip).await, "IP should be banned");

        // The DB delete errors on the lazy pool; the in-memory removal precedes
        // it, so the ban is lifted for the request path.
        let _ = service.unban(&ip).await;
        assert!(
            !service.is_banned(&ip).await,
            "IP must no longer be banned after unban"
        );
    }

    #[tokio::test]
    async fn test_unban_clears_accumulated_strikes() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/bunyip_autoban_test")
            .expect("lazy pool construction never connects");
        let config = AutoBanConfig {
            enabled: true,
            threshold: 3,
            window_secs: 3600,
            ban_duration_secs: 86400,
        };
        let service = AutoBanService::new(config, pool);
        let ip: IpAddr = "203.0.113.21".parse().unwrap();

        // Two strikes: below the threshold of 3, so no ban yet.
        assert!(!service.record_strike(&ip, "/wp-login.php").await);
        assert!(!service.record_strike(&ip, "/phpmyadmin/").await);

        // Unban clears the strike counter (in memory; the DB delete errors on
        // the lazy pool but runs after the strike removal).
        let _ = service.unban(&ip).await;

        // If strikes were still at 2, one more would ban immediately. Because
        // they were cleared, a single fresh strike stays below the threshold.
        assert!(
            !service.record_strike(&ip, "/xmlrpc.php").await,
            "strikes must reset after unban, so one strike does not ban"
        );
        assert!(!service.is_banned(&ip).await);
    }

    /// DB-backed tests. Skipped when `DATABASE_URL` is unset (matches the
    /// convention in the repository crates).
    async fn maybe_pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        PgPool::connect(&url).await.ok()
    }

    #[tokio::test]
    async fn test_unban_reports_presence_and_deletes_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let ip: IpAddr = "203.0.113.55".parse().unwrap();
        let network = ipnetwork::IpNetwork::from(ip);
        sqlx::query("DELETE FROM ip_bans WHERE ip_address = $1")
            .bind(network)
            .execute(&pool)
            .await
            .unwrap();

        let config = AutoBanConfig {
            enabled: true,
            threshold: 3,
            window_secs: 3600,
            ban_duration_secs: 86400,
        };
        let service = AutoBanService::new(config, pool.clone());

        // No ban present -> unban reports false.
        assert!(!service.unban(&ip).await.unwrap());

        // Persist a ban and load it into memory, then unban.
        persist_ban(
            &pool,
            &ip,
            "test-ban",
            3,
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
        service
            .load_bans(load_active_bans(&pool).await.unwrap())
            .await;
        assert!(service.is_banned(&ip).await);

        // Present ban -> unban reports true and removes the persisted row.
        assert!(service.unban(&ip).await.unwrap());
        assert!(!service.is_banned(&ip).await);
        let (remaining,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM ip_bans WHERE ip_address = $1")
                .bind(network)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 0, "ip_bans row must be deleted");
    }

    #[tokio::test]
    async fn test_list_bans_includes_persisted_ban() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let ip: IpAddr = "203.0.113.66".parse().unwrap();
        let network = ipnetwork::IpNetwork::from(ip);
        sqlx::query("DELETE FROM ip_bans WHERE ip_address = $1")
            .bind(network)
            .execute(&pool)
            .await
            .unwrap();
        persist_ban(
            &pool,
            &ip,
            "list-test",
            4,
            Utc::now() + chrono::Duration::hours(1),
        )
        .await
        .unwrap();

        let config = AutoBanConfig {
            enabled: true,
            threshold: 5,
            window_secs: 3600,
            ban_duration_secs: 86400,
        };
        let service = AutoBanService::new(config, pool.clone());

        let bans = service.list_bans().await.unwrap();
        let found = bans
            .iter()
            .find(|b| b.ip == ip)
            .expect("persisted ban must be listed");
        assert_eq!(found.reason, "list-test");
        assert_eq!(found.strikes, 4);

        // cleanup
        sqlx::query("DELETE FROM ip_bans WHERE ip_address = $1")
            .bind(network)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn test_auto_ban_config_defaults() {
        // AUTO_BAN_* is also read by Config::from_env (config.rs tests), so
        // mutating it requires the crate-wide env lock.
        let _env = env_lock();
        // Clear env vars to test defaults
        std::env::remove_var("AUTO_BAN_ENABLED");
        std::env::remove_var("AUTO_BAN_THRESHOLD");
        std::env::remove_var("AUTO_BAN_WINDOW_SECS");
        std::env::remove_var("AUTO_BAN_DURATION_SECS");

        let config = AutoBanConfig::from_env();
        assert!(config.enabled);
        assert_eq!(config.threshold, 5);
        assert_eq!(config.window_secs, 3600);
        assert_eq!(config.ban_duration_secs, 86400);
    }

    #[test]
    fn test_auto_ban_config_struct() {
        let config = AutoBanConfig {
            enabled: false,
            threshold: 10,
            window_secs: 600,
            ban_duration_secs: 7200,
        };
        assert!(!config.enabled);
        assert_eq!(config.threshold, 10);
        assert_eq!(config.window_secs, 600);
        assert_eq!(config.ban_duration_secs, 7200);
    }
}
