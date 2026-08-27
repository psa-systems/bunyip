-- BUNYIP-603: shared suppression list for the mailer relay (BUNYIP-602).
--
-- One row per recipient address that hard-bounced or filed a spam complaint,
-- learned from the SMTP provider's bounce/complaint feedback webhook. The list
-- is shared across every calling app on purpose: it protects the reputation of
-- the ONE sending domain every app relays through, not any single app's state,
-- so a bounce reported for one app suppresses that address for all of them.
--
-- `address` is stored already normalized (trimmed, lowercased) by the writer, so
-- it is the natural primary key and a lookup is a single index probe on the send
-- path. `reason` is 'bounce' or 'complaint'; `detail` keeps the provider's own
-- description for an operator who later inspects why an address was suppressed.
CREATE TABLE mailer_suppressions (
    address    TEXT PRIMARY KEY,
    reason     TEXT NOT NULL,
    detail     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
