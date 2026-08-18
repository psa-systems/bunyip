//! Database pool observability (BUNYIP-559 F10).
//!
//! The pool sizing question ("is `max_connections` the throughput ceiling?")
//! cannot be answered from code, so this module makes the three numbers that
//! answer it readable while the api is under load:
//!
//! - `size()`   - connections the pool currently owns (idle + checked out).
//! - `num_idle()` - of those, how many are free right now.
//! - the acquire-timeout count - how many requests waited out
//!   `acquire_timeout` and got a 500 instead of a connection. This is the
//!   symptom of exhaustion; a saturated-but-coping pool shows `num_idle() == 0`
//!   with the count flat, an exhausted one shows the count climbing.
//!
//! Sampling is off unless `DB_POOL_METRICS_INTERVAL_SECS` is set, so an
//! ordinary deployment pays nothing and a load run turns it on for the run.
//! The acquire-timeout counter is always live: it is a bare atomic increment on
//! an already-failing request, and a count that is only collected when someone
//! remembered to enable it is not evidence.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sqlx::PgPool;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Process-wide count of database acquisitions that timed out waiting for a
/// free connection.
static ACQUIRE_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// How many acquisitions have timed out since the process started.
pub fn acquire_timeouts() -> u64 {
    ACQUIRE_TIMEOUTS.load(Ordering::Relaxed)
}

/// sqlx's `Display` for `Error::PoolTimedOut` is
/// `"pool timed out while waiting for an open connection"`, and
/// `dunite_core`'s `From<sqlx::Error> for AppError` logs it verbatim as the
/// `error` field of its ERROR event. Matching that substring is what makes a
/// timeout countable from outside the conversion; `sqlx_pool_timeout_still_
/// renders_the_signature` fails the build if sqlx ever rewords it.
pub const ACQUIRE_TIMEOUT_SIGNATURE: &str = "pool timed out";

/// Whether a rendered error string is a pool acquire timeout.
pub fn is_acquire_timeout(rendered: &str) -> bool {
    rendered.contains(ACQUIRE_TIMEOUT_SIGNATURE)
}

/// Counts pool acquire timeouts as they cross the error path.
///
/// `sqlx::Error` is converted to `AppError` inside `dunite-core`, which bunyip
/// consumes as a git dependency, so there is no bunyip-owned choke point on the
/// conversion itself. The conversion does emit one ERROR event carrying the
/// underlying error, and this layer counts the ones that are acquire timeouts.
pub struct AcquireTimeoutLayer;

impl<S: Subscriber> Layer<S> for AcquireTimeoutLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if *event.metadata().level() != Level::ERROR {
            return;
        }
        let mut visitor = AcquireTimeoutVisitor::default();
        event.record(&mut visitor);
        if visitor.matched {
            ACQUIRE_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Sets `matched` when any field of the event renders the timeout signature.
#[derive(Default)]
struct AcquireTimeoutVisitor {
    matched: bool,
}

impl Visit for AcquireTimeoutVisitor {
    fn record_str(&mut self, _field: &Field, value: &str) {
        self.matched |= is_acquire_timeout(value);
    }

    fn record_debug(&mut self, _field: &Field, value: &dyn std::fmt::Debug) {
        self.matched |= is_acquire_timeout(&format!("{value:?}"));
    }
}

/// The sampling interval from `DB_POOL_METRICS_INTERVAL_SECS`, or `None` when
/// the variable is unset, empty, unparseable or `0` (all mean "off").
///
/// A value that is present but unusable (non-UTF-8, or not a whole number) is
/// reported at `warn` rather than silently treated as off, so a typo during a
/// load run is visible in the same log the samples would have gone to. Only a
/// genuinely absent variable is silent, because that is the normal posture.
pub fn sampling_interval() -> Option<Duration> {
    let raw = match std::env::var("DB_POOL_METRICS_INTERVAL_SECS") {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return None,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "DB_POOL_METRICS_INTERVAL_SECS is set but unreadable; pool sampling stays off"
            );
            return None;
        }
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    match raw.parse::<u64>() {
        Ok(0) => None,
        Ok(secs) => Some(Duration::from_secs(secs)),
        Err(e) => {
            tracing::warn!(
                value = %raw,
                error = %e,
                "DB_POOL_METRICS_INTERVAL_SECS is not a whole number of seconds; pool sampling stays off"
            );
            None
        }
    }
}

/// One sample line per pool, plus the shared acquire-timeout count.
pub fn log_sample(label: &str, pool: &PgPool) {
    let size = pool.size();
    let idle = pool.num_idle();
    tracing::info!(
        pool = label,
        size,
        idle,
        in_use = (size as usize).saturating_sub(idle),
        acquire_timeouts = acquire_timeouts(),
        "database pool sample"
    );
}

/// Spawn the sampler when `DB_POOL_METRICS_INTERVAL_SECS` asks for it.
///
/// `pools` is `(label, pool)`; the RLS pool falls back to a clone of the
/// primary when `APP_DATABASE_URL` is unset, in which case the caller passes it
/// once.
pub fn spawn_sampler(pools: Vec<(&'static str, PgPool)>) {
    let Some(interval) = sampling_interval() else {
        return;
    };
    tracing::info!(
        interval_secs = interval.as_secs(),
        pools = pools.len(),
        "Database pool sampling enabled (DB_POOL_METRICS_INTERVAL_SECS)"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            for (label, pool) in &pools {
                log_sample(label, pool);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use tracing::subscriber::with_default;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;

    /// The counter is process-wide, so a test asserts on a delta, never on an
    /// absolute value.
    fn delta(f: impl FnOnce()) -> u64 {
        let before = acquire_timeouts();
        f();
        acquire_timeouts() - before
    }

    /// The load-bearing assumption: sqlx still renders `PoolTimedOut` with the
    /// substring the layer matches. Provoked from a real pool, exactly as
    /// dunite-core's own pool-classification tests do (the variant is
    /// `#[non_exhaustive]` and cannot be constructed).
    #[tokio::test]
    async fn sqlx_pool_timeout_still_renders_the_signature() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(500))
            .connect_lazy("postgres://user:pw@127.0.0.1:1/none")
            .expect("lazy pool builds without connecting");
        let err = pool
            .acquire()
            .await
            .expect_err("acquire against a dead host must fail");
        assert!(
            matches!(err, sqlx::Error::PoolTimedOut),
            "expected PoolTimedOut, got: {err:?}"
        );
        assert!(
            is_acquire_timeout(&err.to_string()),
            "sqlx reworded PoolTimedOut; update ACQUIRE_TIMEOUT_SIGNATURE: {err}"
        );
        pool.close().await;
    }

    #[test]
    fn the_layer_counts_a_pool_timeout_and_nothing_else() {
        let subscriber = Registry::default().with(AcquireTimeoutLayer);
        let counted = delta(|| {
            with_default(subscriber, || {
                // The shape dunite-core emits on the conversion.
                tracing::error!(
                    error = "pool timed out while waiting for an open connection",
                    "Database error"
                );
                tracing::error!(
                    error = "syntax error at or near \"selct\"",
                    "Database error"
                );
                // A warning carrying the same text is not an error path.
                tracing::warn!(error = "pool timed out while waiting", "not an error");
            });
        });
        assert_eq!(counted, 1, "only the ERROR-level pool timeout is counted");
    }

    #[test]
    fn sampling_is_off_unless_the_interval_asks_for_it() {
        // The reads go through the process environment, so keep them in one
        // test rather than racing sibling tests on the same variable.
        for (value, expected) in [
            ("", None),
            ("0", None),
            ("   ", None),
            ("not-a-number", None),
            ("30", Some(Duration::from_secs(30))),
        ] {
            std::env::set_var("DB_POOL_METRICS_INTERVAL_SECS", value);
            assert_eq!(sampling_interval(), expected, "value {value:?}");
        }
        std::env::remove_var("DB_POOL_METRICS_INTERVAL_SECS");
        assert_eq!(sampling_interval(), None, "unset means off");
    }
}
