//! Argon2 off the request future (BUNYIP-553, BUNYIP-827).
//!
//! Thin AppError-shaped shim over `dunite_argon2_offload::offload` (DUNITE-20).
//! Every function in this module preserves the public shape callers already
//! use (`offload`, `hash_password`, `verify_password`); the mechanism they
//! previously held locally (semaphore-bounded `spawn_blocking` with a
//! fail-closed permit timeout) now lives in the shared leaf, so a8n Tools
//! and anyone else that adopts the leaf gets the same guarantees without a
//! second copy.
//!
//! ## Env var rename
//!
//! The two environment variables that size the semaphore and the permit
//! timeout moved with the mechanism and keep the dunite leaf's names:
//!
//! - `ARGON2_MAX_CONCURRENT`        → `DUNITE_ARGON2_MAX_CONCURRENT`   (default 32)
//! - `ARGON2_PERMIT_TIMEOUT_SECS`   → `DUNITE_ARGON2_PERMIT_TIMEOUT_SECS` (default 5)
//!
//! Deploys that pin either of the old names must update their env, otherwise
//! the leaf picks its documented defaults and the previous ceiling is lost.
//! The PR body enumerates the deploy diff.

use dunite_argon2_offload::OffloadError;

use crate::errors::AppError;
use crate::services::PasswordService;

/// Map the leaf's two failure branches to the AppError the request path
/// expects. Both are internal faults (overloaded or broken server), never a
/// wrong-answer `Ok(false)` on the verify path.
fn map_offload_error(e: OffloadError) -> AppError {
    match e {
        OffloadError::PermitTimeout => AppError::internal("Password hashing is overloaded"),
        OffloadError::JoinError => AppError::internal("Password hashing task failed"),
    }
}

/// Run one Argon2 unit of work on the blocking pool, gated by the shared
/// concurrency semaphore in `dunite_argon2_offload`.
///
/// `work` returns `Result<T, AppError>` so a hash/verify failure rides out
/// as its own error without being conflated with a semaphore or join
/// failure. The leaf returns `Result<Result<T, AppError>, OffloadError>`;
/// the `?` below unwraps the leaf's error into AppError, and `work`'s own
/// `Result` is still returned to the caller.
pub async fn offload<T, F>(operation: &'static str, work: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    dunite_argon2_offload::offload(operation, work)
        .await
        .map_err(map_offload_error)?
}

/// Hash a password on the blocking pool.
pub async fn hash_password(password: String) -> Result<String, AppError> {
    offload("hash", move || PasswordService::new().hash(&password)).await
}

/// Verify a password against a stored hash on the blocking pool.
pub async fn verify_password(password: String, hash: String) -> Result<bool, AppError> {
    offload("verify", move || PasswordService::new().verify(&password, &hash)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn offload_roundtrips_a_result() {
        let out: Result<u8, AppError> = offload("test-ok", || Ok::<u8, AppError>(7)).await;
        assert_eq!(out.unwrap(), 7);
    }

    #[tokio::test]
    async fn offload_lets_the_inner_error_pass_through() {
        let out: Result<u8, AppError> =
            offload("test-err", || Err::<u8, AppError>(AppError::internal("boom"))).await;
        assert!(matches!(out, Err(AppError::InternalError { .. })));
    }

    #[tokio::test]
    async fn hash_and_verify_round_trip() {
        let hash = hash_password("pw".to_string()).await.unwrap();
        assert!(verify_password("pw".to_string(), hash.clone()).await.unwrap());
        assert!(!verify_password("wrong".to_string(), hash).await.unwrap());
    }

    /// A panicked task maps to an InternalError, never to an Ok(false) on
    /// a verify path.
    #[tokio::test]
    async fn a_panicked_task_maps_to_internal_error() {
        let out: Result<bool, AppError> = offload("test-panic", || panic!("boom")).await;
        assert!(matches!(out, Err(AppError::InternalError { .. })));
    }
}
