-- BUNYIP-408: uploadable profile avatars.
--
-- Storage mirrors the feedback_attachments precedent (BUNYIP-90): the image
-- bytes live in a Postgres BYTEA, never on a filesystem or a static mount, and
-- are served back only through an authenticated bunyip-api handler that sets an
-- explicit image Content-Type + `Content-Disposition: inline`. bunyip-api has
-- no static file mount, so a stored avatar can never be served from an origin
-- where it could execute - which is the security constraint the ticket calls
-- out. One row per user (user_id is the primary key); a re-upload replaces the
-- row via UPSERT.
CREATE TABLE user_avatars (
    user_id     UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    mime_type   TEXT        NOT NULL,
    -- Bounded to 2 MiB, matching MAX_AVATAR_SIZE in
    -- bunyip-api/src/handlers/avatar.rs so a bypassed app-layer check can never
    -- store an unbounded blob.
    size_bytes  INTEGER     NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 2097152),
    data        BYTEA       NOT NULL,
    -- Keep the stored payload size in lock-step with the recorded size_bytes;
    -- this also caps the BYTEA itself at 2 MiB.
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_avatars_data_size CHECK (octet_length(data) = size_bytes)
);

-- Denormalized "an avatar exists, and this is its version" marker on the users
-- row. Nullable: NULL means no avatar (render the initials/icon fallback). Set
-- to NOW() on every upload and cleared on removal, in the same transaction that
-- writes user_avatars, so the two never drift. Kept on users (not read from the
-- avatars table) so the hot `SELECT * FROM users` / `/users/me` path learns
-- whether to show an avatar - and gets a cache-busting timestamp for the <img>
-- URL - without ever transferring the BYTEA.
ALTER TABLE users
    ADD COLUMN avatar_updated_at TIMESTAMPTZ;
