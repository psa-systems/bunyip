//! Argon2 off the request future (BUNYIP-553).
//!
//! An Argon2id hash or verify at the password preset (64 MiB, t=3, p=4) costs
//! roughly 100 ms of CPU and 64 MiB of resident memory, and the `argon2` crate
//! is built without the `parallel` feature, so all four lanes run on the
//! calling thread. actix-web pins a connection to one worker arbiter and never
//! moves its futures elsewhere, so hashing inline stalls every other request on
//! that arbiter, `/v1/health` included. Every request-path hash and verify goes
//! through this module instead, which moves the work to the blocking pool.
//!
//! The parameters are deliberately untouched: the cost is the point of the
//! algorithm, only where it is paid was wrong.
//!
//! BUNYIP-827: `spawn_blocking` alone bounds nothing but tokio's default
//! blocking-thread pool (512 threads), an implicit, undocumented limit that
//! every other blocking operation in the process also draws from. A burst of
//! valid-looking requests spread across enough distinct IPs and emails, each
//! individually within its own rate limit, could still schedule hundreds of
//! concurrent 64 MiB Argon2 hashes. A `tokio::sync::Semaphore` sized by
//! `ARGON2_MAX_CONCURRENT` (default 32) bounds concurrent Argon2 work
//! independently of that pool; a caller that cannot acquire a permit within
//! `ARGON2_PERMIT_TIMEOUT_SECS` (default 5) fails closed through the same
//! `internal` error path as a panicked task, never `Ok(false)`.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::errors::AppError;
use crate::services::PasswordService;

const DEFAULT_MAX_CONCURRENT: usize = 32;
const DEFAULT_PERMIT_TIMEOUT_SECS: u64 = 5;

/// One shared service for every call site. It holds only the Argon2 parameter
/// set (the 64 MiB is allocated per hash, not here), and a `&'static` borrow is
/// `Send`, so the blocking closures need no `Arc` and no clone.
fn service() -> &'static PasswordService {
    static SERVICE: OnceLock<PasswordService> = OnceLock::new();
    SERVICE.get_or_init(PasswordService::new)
}

/// The semaphore bounding concurrent in-flight Argon2 operations, sized once
/// from `ARGON2_MAX_CONCURRENT` (default `DEFAULT_MAX_CONCURRENT`).
fn permits() -> &'static Arc<Semaphore> {
    static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    PERMITS.get_or_init(|| {
        let max = std::env::var("ARGON2_MAX_CONCURRENT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_MAX_CONCURRENT);
        Arc::new(Semaphore::new(max))
    })
}

/// How long a caller waits for a permit before failing closed, from
/// `ARGON2_PERMIT_TIMEOUT_SECS` (default `DEFAULT_PERMIT_TIMEOUT_SECS`).
fn permit_timeout() -> Duration {
    static TIMEOUT: OnceLock<Duration> = OnceLock::new();
    *TIMEOUT.get_or_init(|| {
        let secs = std::env::var("ARGON2_PERMIT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_PERMIT_TIMEOUT_SECS);
        Duration::from_secs(secs)
    })
}

/// Run one Argon2 unit of work on the blocking pool, gated by `semaphore` with
/// a wait bounded by `timeout`. The process-wide `offload` below is the only
/// production caller; tests call this directly with a local semaphore and
/// timeout so they stay deterministic and independent of each other despite
/// `permits()` and `permit_timeout()` being one-time-initialized globals.
///
/// A panicked or cancelled task, and a request that times out waiting for a
/// permit, are both internal failures and are logged as one. Neither must ever
/// collapse into `Ok(false)`, which would report a broken or overloaded server
/// as a wrong password.
async fn offload_bounded<T, F>(
    operation: &'static str,
    semaphore: &Arc<Semaphore>,
    timeout: Duration,
    work: F,
) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    let permit = match tokio::time::timeout(timeout, semaphore.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => unreachable!("the semaphore is never closed"),
        Err(_) => {
            tracing::error!(
                operation,
                "Argon2 concurrency limit reached; timed out waiting for a permit"
            );
            return Err(AppError::internal("Password hashing is overloaded"));
        }
    };

    // The permit moves into the blocking task, so a cancelled caller cannot free
    // it while the hash still runs.
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, operation, "Argon2 task failed to join");
            Err(AppError::internal("Password hashing task failed"))
        }
    }
}

/// Run one Argon2 unit of work on the blocking pool, gated by the process-wide
/// concurrency semaphore above.
pub async fn offload<T, F>(operation: &'static str, work: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    offload_bounded(operation, permits(), permit_timeout(), work).await
}

/// Hash a password on the blocking pool.
pub async fn hash_password(password: String) -> Result<String, AppError> {
    offload("hash", move || service().hash(&password)).await
}

/// Verify a password against a stored hash on the blocking pool.
pub async fn verify_password(password: String, hash: String) -> Result<bool, AppError> {
    offload("verify", move || service().verify(&password, &hash)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_and_verify_round_trip_off_the_worker() {
        let hash = hash_password("SecurePassword123!".to_string())
            .await
            .unwrap();
        assert!(
            verify_password("SecurePassword123!".to_string(), hash.clone())
                .await
                .unwrap()
        );
        assert!(!verify_password("wrong-password".to_string(), hash)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn a_panicked_task_is_an_internal_error_not_a_failed_check() {
        let result: Result<bool, AppError> = offload("panic", || panic!("boom")).await;
        assert!(matches!(result, Err(AppError::InternalError { .. })));
    }

    /// BUNYIP-827: a load of concurrent calls well past a small configured
    /// limit never runs more of them at once than that limit allows, measured
    /// with an in-test high-water-mark counter rather than by timing.
    #[tokio::test]
    async fn concurrent_offloads_stay_bounded_by_the_semaphore() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        const LIMIT: usize = 4;
        const CALLERS: usize = 20;

        let semaphore = Arc::new(Semaphore::new(LIMIT));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let high_water = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..CALLERS {
            let semaphore = semaphore.clone();
            let in_flight = in_flight.clone();
            let high_water = high_water.clone();
            handles.push(tokio::spawn(async move {
                offload_bounded("load-test", &semaphore, Duration::from_secs(5), move || {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    high_water.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(50));
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    Ok::<(), AppError>(())
                })
                .await
            }));
        }

        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        let peak = high_water.load(Ordering::SeqCst);
        assert!(
            peak <= LIMIT,
            "observed {peak} concurrent Argon2 operations against a configured limit of {LIMIT}"
        );
        assert!(
            peak >= 2,
            "the test never observed meaningful concurrency (peak {peak}), so it proves nothing"
        );
    }

    /// The invariant `offload` documents (a broken task never reports
    /// `Ok(false)`) extends to a request that times out waiting for a permit:
    /// it fails closed through the internal-error path, not a wrong-password
    /// result.
    #[tokio::test]
    async fn a_request_that_times_out_waiting_for_a_permit_fails_closed() {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = semaphore.acquire().await.unwrap();

        let result: Result<bool, AppError> = offload_bounded(
            "permit-timeout",
            &semaphore,
            Duration::from_millis(50),
            || Ok(false),
        )
        .await;

        assert!(matches!(result, Err(AppError::InternalError { .. })));
        drop(held);
    }

    /// A caller cancelled mid-hash must not release its permit early: the
    /// blocking work keeps running, so the permit stays held until it ends.
    #[tokio::test]
    async fn a_cancelled_caller_keeps_its_permit_until_the_work_ends() {
        let semaphore = Arc::new(Semaphore::new(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        let sem = semaphore.clone();
        let caller = tokio::spawn(async move {
            offload_bounded("cancel", &sem, Duration::from_secs(5), move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                Ok::<(), AppError>(())
            })
            .await
        });
        started_rx.await.unwrap();
        caller.abort();
        let _ = caller.await;

        assert_eq!(
            semaphore.available_permits(),
            0,
            "the permit must stay held while the blocking work still runs"
        );
        release_tx.send(()).unwrap();
        let _permit = tokio::time::timeout(Duration::from_secs(5), semaphore.acquire())
            .await
            .expect("the permit is returned once the work ends")
            .unwrap();
    }

    /// The property BUNYIP-553 is about, on the runtime shape that makes it
    /// matter: an actix worker arbiter is a current-thread runtime, so a hash
    /// computed on the request future stops every other future on that arbiter,
    /// `/v1/health` included. Drive a 1 ms ticker beside a hash and require it
    /// to keep ticking. Hashing inline lets the ticker run at most once (the
    /// whole ~100 ms passes with the thread occupied); offloading leaves it free
    /// to tick for the duration.
    #[tokio::test(flavor = "current_thread")]
    async fn an_offloaded_hash_leaves_the_arbiter_free() {
        let hashing = tokio::spawn(hash_password("SecurePassword123!".to_string()));

        let mut ticks = 0u32;
        while !hashing.is_finished() {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            ticks += 1;
        }
        hashing.await.unwrap().unwrap();

        assert!(
            ticks > 5,
            "the arbiter only made progress {ticks} time(s) while Argon2 ran, \
             so the hash is back on the request future"
        );
    }
}
