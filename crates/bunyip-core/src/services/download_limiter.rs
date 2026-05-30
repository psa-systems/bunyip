//! Per-user concurrency and daily-count download limiter.
//!
//! # TODO (follow-up)
//! Replace the in-process concurrency map with a Postgres row + heartbeat
//! when the API is deployed multi-instance. The map here is correct only for
//! a single-process deployment.

use chrono::Utc;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::errors::AppError;
use crate::repositories::DownloadDailyCountRepository;

#[derive(Debug, PartialEq)]
pub enum LimitDenial {
    Concurrency,
    DailyCap { reset_in_secs: i64 },
}

#[derive(Clone)]
pub struct DownloadLimiter {
    concurrency_per_user: u32,
    daily_limit: u32,
    inflight: Arc<Mutex<HashMap<Uuid, u32>>>,
}

/// RAII guard that decrements the in-flight counter on drop.
pub struct DownloadGuard {
    user_id: Uuid,
    inflight: Arc<Mutex<HashMap<Uuid, u32>>>,
    released: bool,
}

impl Drop for DownloadGuard {
    fn drop(&mut self) {
        if !self.released {
            let mut m = self.inflight.lock().unwrap();
            if let Some(n) = m.get_mut(&self.user_id) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    m.remove(&self.user_id);
                }
            }
        }
    }
}

impl DownloadLimiter {
    pub fn new(concurrency_per_user: u32, daily_limit: u32) -> Self {
        Self {
            concurrency_per_user,
            daily_limit,
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Attempt to acquire a slot. On success returns a guard + the new daily count.
    /// On denial returns the reason.
    pub async fn acquire(
        &self,
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Result<DownloadGuard, LimitDenial>, AppError> {
        {
            let mut m = self.inflight.lock().unwrap();
            let entry = m.entry(user_id).or_insert(0);
            if *entry >= self.concurrency_per_user {
                return Ok(Err(LimitDenial::Concurrency));
            }
            *entry += 1;
        }

        let today = Utc::now().date_naive();
        let count = match DownloadDailyCountRepository::increment(pool, user_id, today).await {
            Ok(n) => n,
            Err(e) => {
                // Increment failed; release the inflight slot we just took.
                release_slot(&self.inflight, user_id);
                return Err(e);
            }
        };
        if (count as u32) > self.daily_limit {
            // Release the inflight slot BEFORE touching the DB again so a
            // failing decrement can't leak the slot permanently.
            release_slot(&self.inflight, user_id);
            if let Err(e) = DownloadDailyCountRepository::decrement(pool, user_id, today).await {
                tracing::warn!(error = %e, "failed to roll back daily count after exceeding cap");
            }
            let now = Utc::now();
            let tomorrow = (now.date_naive() + chrono::Duration::days(1))
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc();
            let reset_in_secs = (tomorrow - now).num_seconds().max(0);
            return Ok(Err(LimitDenial::DailyCap { reset_in_secs }));
        }

        Ok(Ok(DownloadGuard {
            user_id,
            inflight: self.inflight.clone(),
            released: false,
        }))
    }
}

fn release_slot(inflight: &Arc<Mutex<HashMap<Uuid, u32>>>, user_id: Uuid) {
    let mut m = inflight.lock().unwrap();
    if let Some(n) = m.get_mut(&user_id) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            m.remove(&user_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_decrements_on_drop() {
        let limiter = DownloadLimiter::new(2, 50);
        let user_id = Uuid::new_v4();

        {
            let mut m = limiter.inflight.lock().unwrap();
            m.insert(user_id, 2);
        }
        let guard = DownloadGuard {
            user_id,
            inflight: limiter.inflight.clone(),
            released: false,
        };
        drop(guard);
        let m = limiter.inflight.lock().unwrap();
        assert_eq!(m.get(&user_id).copied().unwrap_or(0), 1);
    }

    #[test]
    fn guard_decrements_on_panic() {
        let limiter = DownloadLimiter::new(2, 50);
        let user_id = Uuid::new_v4();
        {
            let mut m = limiter.inflight.lock().unwrap();
            m.insert(user_id, 1);
        }
        let inflight = limiter.inflight.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = DownloadGuard {
                user_id,
                inflight: inflight.clone(),
                released: false,
            };
            panic!("boom");
        }));
        assert!(result.is_err());
        let m = limiter.inflight.lock().unwrap();
        assert!(m.get(&user_id).is_none());
    }
}
