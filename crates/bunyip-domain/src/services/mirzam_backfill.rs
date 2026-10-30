//! Putting the accounts that existed before the Mirzam integration on its two
//! lists (BUNYIP-999).
//!
//! `bunyip-api mirzam-backfill` walks every live account with a verified
//! address and makes the same "email verified" calls the sync makes
//! ([`add_account`]): product updates with `keep_unsubscribed`, so nobody who
//! left it is put back, and notices without it. Mirzam answers `409` for an
//! address already on a list, so a second run changes nothing.
//!
//! The calls are sequential and paced: one account at a time, with a pause
//! between accounts, so a backfill of every account stays well under Mirzam's
//! per-token rate limit. A failure is counted and the run goes on.

use std::fmt;
use std::time::Duration;

use sqlx::PgPool;

use crate::errors::AppError;
use crate::repositories::UserRepository;
use crate::services::mirzam_sync::{
    account_display_name, add_account, AccountAdd, AddOutcome, MirzamClient, MirzamLists,
};

/// The pause between two accounts. Each account is two calls, so this keeps a
/// run near 8 requests a second, under Mirzam's 600 a minute per token.
pub const MIRZAM_BACKFILL_PACE: Duration = Duration::from_millis(250);

/// What the backfill did for one account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackfillResult {
    /// Newly put on at least one list.
    Added,
    /// Already on both lists.
    AlreadyOn,
    /// Had left product updates, and was left as it is.
    LeftAlone,
    /// A call failed for good.
    Failed,
}

impl BackfillResult {
    /// A failure outranks a kept unsubscribe, which outranks an add: the count
    /// an operator reads first is the one that needs them.
    pub fn of(add: &AccountAdd) -> Self {
        let answers = [&add.updates, &add.notices];
        if answers.iter().any(|a| a.is_err()) {
            Self::Failed
        } else if answers.contains(&&Ok(AddOutcome::LeftAlone)) {
            Self::LeftAlone
        } else if answers.contains(&&Ok(AddOutcome::Added)) {
            Self::Added
        } else {
            Self::AlreadyOn
        }
    }
}

/// The counts a run prints, one per account, and the failed calls, which name
/// the account's user id and never its address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackfillReport {
    pub added: usize,
    pub already_on: usize,
    pub left_alone: usize,
    pub failed: usize,
    pub failures: Vec<String>,
}

impl BackfillReport {
    fn record(&mut self, add: AccountAdd) {
        match BackfillResult::of(&add) {
            BackfillResult::Added => self.added += 1,
            BackfillResult::AlreadyOn => self.already_on += 1,
            BackfillResult::LeftAlone => self.left_alone += 1,
            BackfillResult::Failed => {
                self.failed += 1;
                self.failures.extend(add.errors());
            }
        }
    }
}

impl fmt::Display for BackfillReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "mirzam-backfill: added {}, already on {}, left alone (unsubscribed) {}, failed {}",
            self.added, self.already_on, self.left_alone, self.failed
        )?;
        for failure in &self.failures {
            writeln!(f, "  {failure}")?;
        }
        Ok(())
    }
}

/// Make the "email verified" calls for every live verified account, one
/// account at a time with `pace` between them.
pub async fn backfill(
    pool: &PgPool,
    client: &MirzamClient,
    lists: &MirzamLists,
    delays: &[Duration],
    pace: Duration,
) -> Result<BackfillReport, AppError> {
    let users = UserRepository::list_verified(pool).await?;
    let mut report = BackfillReport::default();
    for (i, user) in users.iter().enumerate() {
        if i > 0 && !pace.is_zero() {
            tokio::time::sleep(pace).await;
        }
        let name = account_display_name(user);
        let add = add_account(client, lists, delays, user.id, &user.email, name.as_deref()).await;
        report.record(add);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(updates: Result<AddOutcome, &str>, notices: Result<AddOutcome, &str>) -> AccountAdd {
        AccountAdd {
            updates: updates.map_err(str::to_string),
            notices: notices.map_err(str::to_string),
        }
    }

    #[test]
    fn each_account_counts_once_failure_first_then_left_alone_then_added() {
        use AddOutcome::{Added, AlreadyOn, LeftAlone};
        let cases = [
            (add(Ok(Added), Ok(Added)), BackfillResult::Added),
            (add(Ok(AlreadyOn), Ok(Added)), BackfillResult::Added),
            (add(Ok(AlreadyOn), Ok(AlreadyOn)), BackfillResult::AlreadyOn),
            (add(Ok(LeftAlone), Ok(Added)), BackfillResult::LeftAlone),
            (add(Ok(LeftAlone), Ok(AlreadyOn)), BackfillResult::LeftAlone),
            (add(Err("down"), Ok(Added)), BackfillResult::Failed),
            (add(Ok(LeftAlone), Err("down")), BackfillResult::Failed),
        ];
        for (answer, expected) in cases {
            assert_eq!(BackfillResult::of(&answer), expected, "{answer:?}");
        }
    }

    #[test]
    fn the_report_counts_and_lists_only_the_failed_calls() {
        let mut report = BackfillReport::default();
        report.record(add(Ok(AddOutcome::Added), Ok(AddOutcome::Added)));
        report.record(add(Ok(AddOutcome::LeftAlone), Ok(AddOutcome::AlreadyOn)));
        report.record(add(Err("first"), Err("second")));
        assert_eq!(
            report.to_string(),
            "mirzam-backfill: added 1, already on 0, left alone (unsubscribed) 1, failed 1\n  \
             first\n  second\n"
        );
    }
}
