//! Feedback repository.
//!
//! DEV-516: extracted to the shared `dunite-feedback` crate (consumed by
//! a8n-tools too) and re-exported here. The repository is error-agnostic - it
//! returns `sqlx::Error`, which bunyip's `?` maps through `From<sqlx::Error> for
//! AppError`. `delete` and `archive_one` now return `bool` (`false` = no row
//! matched); their callers in the bunyip-api feedback handlers raise
//! `AppError::not_found("Feedback")` on `false`.

pub use dunite_feedback::FeedbackRepository;
