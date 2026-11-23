# Feedback classifier

The feedback form on a bunyip-authenticated site collects user feedback and runs it through a four-signal spam classifier before it reaches the admin review queue. This page covers the operator view: what the classifier checks, how a false positive is corrected, and what the admin review flow looks like.

## The four signals

A submitted feedback row is classified by four weak signals, evaluated in order. The first signal that matches wins; the row is marked spam and the remaining signals do not run.

1. **Honeypot field.** The form carries a field a human never sees or types in. A submission that fills it is spam.
2. **Time to submit.** A submission that arrives too fast after the form is rendered is bot-shaped. The threshold is calibrated against observed human submissions and is documented in the internal invariants.
3. **URL density.** A body with many URLs for its length is spam. The exact ratio is tuned per deployment.
4. **Author history.** A submitter with a prior-marked-spam row is marked spam by default. Admin marks override this, so a false positive stays corrected.

A match on any signal writes the row with `spam=true` and does not notify. A row that passes all four writes with `spam=false` and surfaces on the admin review queue.

Weak signals are chosen deliberately: each one alone has a tolerable false-positive rate, and "first match wins" means a tuning change to one signal cannot amplify another.

## The admin review

The admin Feedback page lists non-spam rows by default; a filter shows the spam queue separately. Each row shows the submitter (when signed-in), the body, the originating IP, the user agent, the trigger signal (when spam) and the timestamp.

Two actions per row:

- **Mark spam.** A human-authored row that reads as spam is downgraded. The row moves to the spam queue, and the author's prior-marked-spam count increments (which feeds signal 4).
- **Unmark spam.** A classifier false positive is promoted. The row moves back to the review queue; the author's prior-marked-spam count decrements. Unmarking is the correction path for a legitimate submitter whose first attempt tripped the time-to-submit threshold.

Both actions are admin-only and land in the audit log.

## What the classifier does not do

- It does not CAPTCHA. A persistent abuser gets rate-limited by the per-IP floor; CAPTCHA is not part of the submit path.
- It does not learn. Adding a signal is an explicit code change, not a machine-learning cycle.
- It does not notify. A classifier match is silent; a human admin sees the queue.

## Related

- [Audit log](audit-log.md) carries every `feedback.spam_marked` and `feedback.spam_unmarked` event.
- The feedback endpoints are listed in [API](../api.md).
