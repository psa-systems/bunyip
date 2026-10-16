//! Feedback repository.
//!
//! DEV-516: extracted to the shared `dunite-feedback` crate (consumed by
//! a8n-tools too) and re-exported here. The repository is error-agnostic - it
//! returns `sqlx::Error`, which bunyip's `?` maps through `From<sqlx::Error> for
//! AppError`. `delete` and `archive_one` now return `bool` (`false` = no row
//! matched); their callers in the bunyip-api feedback handlers raise
//! `AppError::not_found("Feedback")` on `false`.

pub use dunite_feedback::FeedbackRepository;

/// Count the feedback rows that still need an admin's attention: `status = 'new'`
/// and not spam (BUNYIP-919). Owned here, next to the `dunite_feedback`
/// re-export, rather than added to the pinned `FeedbackRepository`, so the
/// admin-sidebar count needs no dunite `rev` bump across all four dunite crates
/// (BUNYIP-426 F6). Runtime query (not the `sqlx::query!` macro), so it needs no
/// `.sqlx/` cache entry, matching the rest of this repository. The admin sidebar
/// renders this as a bubble on the Feedback item.
pub async fn count_new_feedback(pool: &sqlx::PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM feedback WHERE status = 'new' AND is_spam = FALSE",
    )
    .fetch_one(pool)
    .await
}
