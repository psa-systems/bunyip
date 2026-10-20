//! BUNYIP-934: joinable per-feedback record of why the composite spam
//! classifier flagged a row. Separate table because the `Feedback` /
//! `CreateFeedback` structs live in dunite-feedback (git dep) and growing
//! them means a dunite PR; this stays bunyip-owned.

use chrono::{DateTime, Utc};
use sqlx::{types::Uuid, FromRow, PgPool};

use crate::errors::AppError;

/// One row of `feedback_spam_reasons`. `reason` is a human-readable
/// summary joined by `; ` of each signal that fired.
#[derive(Debug, Clone, FromRow)]
pub struct FeedbackSpamReason {
    pub feedback_id: Uuid,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}

pub struct FeedbackSpamReasonsRepository;

impl FeedbackSpamReasonsRepository {
    /// Record the classifier verdict for one feedback row. Upsert on
    /// `(feedback_id)` keeps the admin UI stable if a replay (e.g. a demo
    /// seed) re-submits the same id.
    pub async fn insert(
        pool: &PgPool,
        feedback_id: Uuid,
        reason: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO feedback_spam_reasons (feedback_id, reason) \
             VALUES ($1, $2) \
             ON CONFLICT (feedback_id) DO UPDATE SET reason = EXCLUDED.reason",
        )
        .bind(feedback_id)
        .bind(reason)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Fetch the reason for one feedback row. `None` for a row that was
    /// honeypot-flagged (no classifier reason) or manually marked by an
    /// admin.
    pub async fn find(
        pool: &PgPool,
        feedback_id: Uuid,
    ) -> Result<Option<FeedbackSpamReason>, AppError> {
        let row = sqlx::query_as::<_, FeedbackSpamReason>(
            "SELECT feedback_id, reason, created_at \
             FROM feedback_spam_reasons \
             WHERE feedback_id = $1",
        )
        .bind(feedback_id)
        .fetch_optional(pool)
        .await?;
        Ok(row)
    }
}
