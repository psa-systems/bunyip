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

use std::sync::OnceLock;

use crate::errors::AppError;
use crate::services::PasswordService;

/// One shared service for every call site. It holds only the Argon2 parameter
/// set (the 64 MiB is allocated per hash, not here), and a `&'static` borrow is
/// `Send`, so the blocking closures need no `Arc` and no clone.
fn service() -> &'static PasswordService {
    static SERVICE: OnceLock<PasswordService> = OnceLock::new();
    SERVICE.get_or_init(PasswordService::new)
}

/// Run one Argon2 unit of work on the blocking pool.
///
/// A panicked or cancelled task is an internal failure and is logged as one. It
/// must never collapse into `Ok(false)`, which would report a broken server as
/// a wrong password.
pub async fn offload<T, F>(operation: &'static str, work: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, operation, "Argon2 task failed to join");
            Err(AppError::internal("Password hashing task failed"))
        }
    }
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
