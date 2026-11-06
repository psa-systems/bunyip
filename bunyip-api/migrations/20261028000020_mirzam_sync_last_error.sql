-- BUNYIP-998: the last failed call bunyip made to Mirzam while keeping account
-- holders on its two lists. Runtime state, not a setting: written when a call
-- runs out of attempts, cleared by the next call that succeeds, shown on the
-- admin Mirzam page and in the integration status, and left out of the
-- settings archive. The text names the operation, the list, the account's user
-- id and Mirzam's answer; it never carries the API token or the address.
ALTER TABLE mirzam_config
    ADD COLUMN last_error    TEXT,
    ADD COLUMN last_error_at TIMESTAMPTZ;
