//! Feedback repository.
//!
//! DEV-516: extracted to the shared `dunite-feedback` crate (consumed by
//! a8n-tools too) and re-exported here. The repository is error-agnostic - it
//! returns `sqlx::Error`, which bunyip's `?` maps through `From<sqlx::Error> for
//! AppError`. `delete` and `archive_one` now return `bool` (`false` = no row
//! matched); their callers in the bunyip-api feedback handlers raise
//! `AppError::not_found("Feedback")` on `false`.

pub use dunite_feedback::FeedbackRepository;

/// BUNYIP-938: filter parameters the admin feedback list carries beyond
/// the bucket (tab). Grouped so adding a filter does not reshape every
/// caller. All optional; empty strings should be filtered to `None` by
/// the caller.
#[derive(Debug, Default, Clone)]
pub struct FeedbackFilters<'a> {
    pub tag: Option<&'a str>,
    pub has_attachment: Option<bool>,
    pub has_response: Option<bool>,
    /// Free-text search over subject, message, and email. 128-char cap
    /// enforced by the caller.
    pub search: Option<&'a str>,
}

/// BUNYIP-938: paginated feedback list with the extended filter set.
///
/// Owned here rather than added to the pinned `dunite_feedback::FeedbackRepository`,
/// matching the `count_new_feedback` precedent above: avoids a dunite
/// `rev` bump across all four dunite crates (BUNYIP-426 F6). The bucket
/// semantics mirror dunite's `list_paginated` byte-for-byte so callers
/// swapping between the two see the same tab behaviour.
pub async fn list_paginated_filtered(
    pool: &sqlx::PgPool,
    page: i32,
    per_page: i32,
    bucket: Option<&str>,
    filters: FeedbackFilters<'_>,
) -> Result<(Vec<dunite_feedback::models::Feedback>, i64), sqlx::Error> {
    use sqlx::QueryBuilder;

    // BUNYIP-995: compute the offset in i64 and saturate, mirroring
    // BUNYIP-946 F14, so a page value large enough to overflow an i32
    // multiply cannot panic (debug) or wrap to a negative OFFSET (release).
    let offset = (page as i64 - 1).saturating_mul(per_page as i64).max(0);
    let bucket_predicate: Option<&'static str> = match bucket.unwrap_or("active") {
        "active" => Some("is_spam = FALSE AND status <> 'closed'"),
        "closed" => Some("is_spam = FALSE AND status = 'closed'"),
        "spam" => Some("is_spam = TRUE"),
        _ => None,
    };

    fn push_where<'a>(
        qb: &mut QueryBuilder<'a, sqlx::Postgres>,
        bucket_predicate: Option<&'static str>,
        filters: &FeedbackFilters<'a>,
    ) {
        let mut sep = " WHERE ";
        if let Some(p) = bucket_predicate {
            qb.push(sep).push(p);
            sep = " AND ";
        }
        if let Some(tag) = filters.tag {
            qb.push(sep).push_bind(tag).push(" = ANY(tags)");
            sep = " AND ";
        }
        match filters.has_attachment {
            Some(true) => {
                qb.push(sep).push(
                    "EXISTS (SELECT 1 FROM feedback_attachments fa WHERE fa.feedback_id = feedback.id)",
                );
                sep = " AND ";
            }
            Some(false) => {
                qb.push(sep).push(
                    "NOT EXISTS (SELECT 1 FROM feedback_attachments fa WHERE fa.feedback_id = feedback.id)",
                );
                sep = " AND ";
            }
            None => {}
        }
        match filters.has_response {
            Some(true) => {
                qb.push(sep)
                    .push("admin_response IS NOT NULL AND trim(admin_response) <> ''");
                sep = " AND ";
            }
            Some(false) => {
                qb.push(sep)
                    .push("(admin_response IS NULL OR trim(admin_response) = '')");
                sep = " AND ";
            }
            None => {}
        }
        if let Some(search) = filters.search {
            let pattern = format!("%{search}%");
            qb.push(sep)
                .push("(subject ILIKE ")
                .push_bind(pattern.clone())
                .push(" OR message ILIKE ")
                .push_bind(pattern.clone())
                .push(" OR email ILIKE ")
                .push_bind(pattern)
                .push(")");
        }
    }

    let mut q = QueryBuilder::new("SELECT * FROM feedback");
    push_where(&mut q, bucket_predicate, &filters);
    q.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);

    let mut c = QueryBuilder::new("SELECT COUNT(*)::BIGINT FROM feedback");
    push_where(&mut c, bucket_predicate, &filters);

    let feedback = q
        .build_query_as::<dunite_feedback::models::Feedback>()
        .fetch_all(pool)
        .await?;
    let total: (i64,) = c.build_query_as().fetch_one(pool).await?;
    Ok((feedback, total.0))
}

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
