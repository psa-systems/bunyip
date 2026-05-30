-- Replace the absolute unique constraint on email with a partial unique index
-- that only enforces uniqueness among non-deleted users. This allows soft-deleted
-- users to re-register with the same email address.

ALTER TABLE users DROP CONSTRAINT users_email_key;

CREATE UNIQUE INDEX users_email_unique_active ON users (email) WHERE deleted_at IS NULL;
