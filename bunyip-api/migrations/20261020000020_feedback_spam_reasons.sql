-- BUNYIP-934: reasons the composite spam classifier flagged a feedback row.
--
-- Separate table (not a column on `feedback`) because the `Feedback` /
-- `CreateFeedback` structs live in the `dunite-feedback` git-dep crate and
-- extending them means a dunite PR + bump + rev pin. A joinable auxiliary
-- table is bunyip-owned, so the one-reader-one-writer property stays here
-- and the dunite contract is unchanged.
--
-- One row per flagged feedback: a `(feedback_id)` PRIMARY KEY, so adding
-- the same reason twice is a no-op and the admin reads one record. `reason`
-- is a free-text summary (`"sender domain mimics recipient", "URL + 3+ tags",
-- "hosting-range IP"` joined by `; `) rendered inline on the admin detail
-- page so the WHY is visible before an admin reverses it.
--
-- Rows survive `unmark_feedback_spam`: an admin reversing the call keeps
-- the reason record for later audit. A later admin re-reading the row sees
-- "the classifier flagged this for X; an admin unflagged it anyway". The
-- `is_spam` boolean is the live verdict, this is the history.

CREATE TABLE IF NOT EXISTS feedback_spam_reasons (
    feedback_id uuid PRIMARY KEY REFERENCES feedback(id) ON DELETE CASCADE,
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW()
);

-- The admin detail page reads by feedback_id (point lookup), already
-- indexed by PK. No secondary index.
