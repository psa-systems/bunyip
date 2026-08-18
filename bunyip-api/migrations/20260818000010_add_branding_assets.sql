-- BUNYIP-560: the brand-carrying ASSETS and the palette join the branding
-- record, so a deployment gets its own mark, favicon, mascot and colour ramp
-- from the admin panel rather than from the image it was built into.
--
-- Every column ships EMPTY / NULL for the same reason the BUNYIP-561 columns
-- do: a migration is committed code, and seeding a palette here would freeze
-- one product's colours in the repo permanently.
ALTER TABLE branding
    -- Raw CSS custom-property declarations emitted into the `:root` block
    -- (the brand ramp). Empty falls back to bunyip-web's BRAND_THEME_CSS,
    -- which is a bootstrap default only and is removed in 0.16.0.
    ADD COLUMN theme_css         TEXT NOT NULL DEFAULT '',
    -- The two `<meta name="theme-color">` values. Empty means the meta is
    -- OMITTED, never substituted with a literal.
    ADD COLUMN theme_color_light TEXT NOT NULL DEFAULT '',
    ADD COLUMN theme_color_dark  TEXT NOT NULL DEFAULT '',
    -- Denormalized "this asset exists, and this is its version" markers,
    -- mirroring users.avatar_updated_at (BUNYIP-408): NULL means no asset (the
    -- committed fallback under bunyip-web/assets/ is used, or in the mascot's
    -- case nothing renders). Written in the same transaction as the
    -- branding_assets rows, so the two never drift, and read by the hot
    -- `GET /v1/branding` path without ever transferring a BYTEA.
    ADD COLUMN mark_updated_at    TIMESTAMPTZ,
    ADD COLUMN favicon_updated_at TIMESTAMPTZ,
    ADD COLUMN mascot_updated_at  TIMESTAMPTZ;

-- Storage mirrors user_avatars (BUNYIP-408) and feedback_attachments
-- (BUNYIP-90): the image bytes live in a Postgres BYTEA, never on a filesystem
-- or a static mount, and come back only through a handler that sets an explicit
-- image Content-Type. One row per asset key; a re-upload replaces the row.
--
-- The keys are `mark`, `mascot`, `favicon-source` (what the admin uploaded) and
-- the derived favicon set (`favicon-16`, `favicon-32`, `favicon-48`,
-- `favicon-192`, `favicon-512`, `apple-touch-icon`, `favicon-ico`), all written
-- from the one source in a single transaction.
CREATE TABLE branding_assets (
    kind        TEXT        PRIMARY KEY,
    mime_type   TEXT        NOT NULL,
    -- Bounded to 2 MiB, matching ImagePolicy::avatar()'s max_bytes (the policy
    -- the upload handler enforces) so a bypassed app-layer check can never
    -- store an unbounded blob.
    size_bytes  INTEGER     NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 2097152),
    data        BYTEA       NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Keep the stored payload size in lock-step with the recorded size_bytes;
    -- this also caps the BYTEA itself at 2 MiB.
    CONSTRAINT branding_assets_data_size CHECK (octet_length(data) = size_bytes)
);
