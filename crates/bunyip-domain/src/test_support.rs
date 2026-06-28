//! Shared test utilities (compiled only for `cfg(test)`).

use std::sync::{Mutex, MutexGuard};

/// Serializes tests that mutate process-global environment variables.
///
/// cargo test runs tests on parallel threads inside one process, so two tests
/// touching the same env var (or calling `Config::from_env`, which reads every
/// sub-config's vars, including `AUTO_BAN_*`) race and fail intermittently
/// (BUNYIP-36). Every test in this crate that calls
/// `env::set_var`/`env::remove_var` must hold this lock, regardless of which
/// module it lives in. Poisoning is recovered so one failed test does not
/// cascade into unrelated env-test failures.
static ENV_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
