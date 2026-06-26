-- BUNYIP-209: one-time 30-day free trial on signup.
--
-- `has_used_trial` records whether a user has ever been issued a Stripe
-- Checkout session that carried a trial. The first time a user starts
-- checkout (and the flag is FALSE) we attach `trial_period_days` to the
-- subscription; the `checkout.session.completed` webhook then flips this to
-- TRUE so the trial cannot be re-granted on a later subscribe. Defaulting to
-- FALSE means every existing row is treated as trial-eligible on their next
-- checkout, which is the desired behaviour: nobody who has not yet paid loses
-- a trial, and anyone already `active` is gated out earlier in the flow.
ALTER TABLE users
    ADD COLUMN has_used_trial BOOLEAN NOT NULL DEFAULT FALSE;
