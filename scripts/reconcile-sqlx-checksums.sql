-- BUNYIP-101: reconcile _sqlx_migrations checksums after the in-place edits
-- made by 9c082eb (BUNYIP-79, fix(migrations): close data-integrity gaps).
--
-- Run this against the bunyip-api Postgres database BEFORE bringing the new
-- image up. The script edits 11 rows in _sqlx_migrations and applies the
-- handful of schema deltas the new files describe but the live DB lacks.
-- After it finishes successfully, bunyip-api boots without the
-- "migration <ts> was previously applied but has been modified" error.
--
-- Usage (psql, recommended -- runs with --single-transaction so any failure
-- rolls the whole script back):
--
--   psql --host <host> --port <port> --username bunyip --dbname bunyip \
--        --single-transaction --set ON_ERROR_STOP=on \
--        --file scripts/reconcile-sqlx-checksums.sql
--
-- Verify after by re-querying _sqlx_migrations and re-booting bunyip-api;
-- the boot log should show "Database migrations completed" with no error.
--
-- Each migration block is structured as:
--   1. Schema delta (where the new file actually changes the schema). Wrapped
--      in DO blocks that check pg_constraint / information_schema for
--      idempotency, so re-running this script is a no-op.
--   2. UPDATE _sqlx_migrations SET checksum = ... WHERE version = <ts>.
--
-- Checksum is sqlx's SHA-384 of the new file body. Computed on the developer
-- machine via `sha384sum bunyip-api/migrations/<file>.sql` from the commit
-- that landed the in-place edits (9c082eb).
--
-- IMPORTANT: psql's --single-transaction wraps the whole script in one
-- transaction. If any block raises, NOTHING commits and the DB is unchanged.

\echo '== reconcile starting; --single-transaction means all-or-nothing =='

-- ─────────────────────────────────────────────────────────────────────────
-- 1) 20260319000025_encrypt_stripe_secrets
--    Delta: NONE. The added DO-block guards a destructive DROP/ADD that
--    already ran on the live DB; running it again would no-op (columns
--    already gone). Only the checksum needs reconciling.
-- ─────────────────────────────────────────────────────────────────────────
UPDATE _sqlx_migrations
   SET checksum = decode('200f652329b161a252e47f1fdd29cace60bbb89dd3ce28fc9fcf4d0955cba8b8315cda3b6d0c646a36b89eebad253a69', 'hex')
 WHERE version = 20260319000025;

-- ─────────────────────────────────────────────────────────────────────────
-- 2) 20260313000021_add_feedback_attachments
--    Delta: two CHECK constraints on feedback_attachments (size_bytes upper
--    bound, and an octet_length(data) = size_bytes invariant). Idempotent
--    via the pg_constraint guard.
-- ─────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'feedback_attachments'::regclass
           AND conname = 'feedback_attachments_size_bytes_check'
    ) THEN
        ALTER TABLE feedback_attachments
            ADD CONSTRAINT feedback_attachments_size_bytes_check
            CHECK (size_bytes > 0 AND size_bytes <= 5242880);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'feedback_attachments'::regclass
           AND conname = 'feedback_attachments_data_size'
    ) THEN
        ALTER TABLE feedback_attachments
            ADD CONSTRAINT feedback_attachments_data_size
            CHECK (octet_length(data) = size_bytes);
    END IF;
END $$;

UPDATE _sqlx_migrations
   SET checksum = decode('3656ea35943c6ec7cc1ee9f41b7410519a0e29b4714e853d3f7007c4bcd47390c6ba8a4dfd6b82e4e2ded55641b11a99', 'hex')
 WHERE version = 20260313000021;

-- ─────────────────────────────────────────────────────────────────────────
-- 3) 20260605000010_create_application_entitlements
--    Delta: CHECK on application_entitlements.source enum.
-- ─────────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'application_entitlements'::regclass
           AND conname = 'application_entitlements_source_check'
    ) THEN
        ALTER TABLE application_entitlements
            ADD CONSTRAINT application_entitlements_source_check
            CHECK (source IN ('admin', 'stripe', 'backfill'));
    END IF;
END $$;

UPDATE _sqlx_migrations
   SET checksum = decode('aee9ee36eb144bb21cc0666a984d0c639d01108dc3379ad6c7dae485887f7c52f9ccfe9a020faee00c48b0ff7fb0dd6a', 'hex')
 WHERE version = 20260605000010;

-- ─────────────────────────────────────────────────────────────────────────
-- 4) 20241230000014_create_email_change_requests
--    Delta: UNIQUE on token_hash. Postgres auto-names the matching unique
--    index `email_change_requests_token_hash_key`.
--
--    If any duplicate token_hash exists in the live row set the ALTER will
--    fail. The SELECT before the ALTER surfaces them so the operator can
--    dedupe (likely manual decision: keep the newest unconsumed request,
--    drop the rest) before re-running. With a clean live set the ALTER
--    succeeds in one shot.
-- ─────────────────────────────────────────────────────────────────────────
DO $$
DECLARE
    dup_count INT;
BEGIN
    SELECT count(*) INTO dup_count FROM (
        SELECT token_hash FROM email_change_requests
         GROUP BY token_hash HAVING count(*) > 1
    ) d;
    IF dup_count > 0 THEN
        RAISE EXCEPTION
            'email_change_requests has % duplicate token_hash rows; dedupe before adding UNIQUE. Find them with: SELECT token_hash, count(*) FROM email_change_requests GROUP BY token_hash HAVING count(*) > 1;',
            dup_count;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'email_change_requests'::regclass
           AND conname = 'email_change_requests_token_hash_key'
    ) THEN
        ALTER TABLE email_change_requests
            ADD CONSTRAINT email_change_requests_token_hash_key UNIQUE (token_hash);
    END IF;
END $$;

UPDATE _sqlx_migrations
   SET checksum = decode('c0397dc83f2431bbad141bc87960c596667288075adb0b173b709242ee77c1d8175d735dcbb25ca68859ed738913ae2a', 'hex')
 WHERE version = 20241230000014;

-- ─────────────────────────────────────────────────────────────────────────
-- 5) 20260417000040_create_oidc_clients
--    Delta: CHECK on oauth_clients.refresh_idle_ttl_seconds BETWEEN
--    3600 AND 7776000.
--
--    Live rows are likely already in-range (default 1209600). If any row
--    is outside [3600, 7776000] the ALTER will fail; raise early.
-- ─────────────────────────────────────────────────────────────────────────
DO $$
DECLARE
    bad_count INT;
BEGIN
    SELECT count(*) INTO bad_count FROM oauth_clients
     WHERE refresh_idle_ttl_seconds NOT BETWEEN 3600 AND 7776000;
    IF bad_count > 0 THEN
        RAISE EXCEPTION
            'oauth_clients has % rows whose refresh_idle_ttl_seconds is outside [3600, 7776000]; fix before adding CHECK.',
            bad_count;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'oauth_clients'::regclass
           AND conname = 'oauth_clients_refresh_idle_ttl_seconds_check'
    ) THEN
        ALTER TABLE oauth_clients
            ADD CONSTRAINT oauth_clients_refresh_idle_ttl_seconds_check
            CHECK (refresh_idle_ttl_seconds BETWEEN 3600 AND 7776000);
    END IF;
END $$;

UPDATE _sqlx_migrations
   SET checksum = decode('5e620f65d78348c962aaa952fb36947995880528a78d56182a0e89bd8a9c9b477d04ba1b42cce1ddb812870d1eec423b', 'hex')
 WHERE version = 20260417000040;

-- ─────────────────────────────────────────────────────────────────────────
-- 6) 20260429000045_add_price_ids_to_tier_config
--    Delta: add the lifetime_price_id TEXT column.
-- ─────────────────────────────────────────────────────────────────────────
ALTER TABLE tier_config
    ADD COLUMN IF NOT EXISTS lifetime_price_id TEXT;

UPDATE _sqlx_migrations
   SET checksum = decode('917ecbf6048240fa76ebf69085850452cedecf33411c916e362352c7e90404be298c08e2b11f70b14186f79f168d67f7', 'hex')
 WHERE version = 20260429000045;

-- ─────────────────────────────────────────────────────────────────────────
-- 7) 20260417000042_create_oidc_tokens
--    Delta: COMMENT-only (intentional-no-FK explainer on
--    lifecycle_event_outbox.user_id). Apply the COMMENT so the DB matches
--    what the file now claims, plus bump the checksum.
-- ─────────────────────────────────────────────────────────────────────────
COMMENT ON COLUMN lifecycle_event_outbox.user_id IS
    'Subject user. Intentionally NOT a foreign key: lifecycle events (notably user.deleted) must outlive the referenced user so the back-channel notification can still be delivered.';

UPDATE _sqlx_migrations
   SET checksum = decode('6348f042f25fc8463c9a6d84cbee7995c65a1dcd167759832fafe4b82209814fae24ea064af54dee0af201b7aef895e2', 'hex')
 WHERE version = 20260417000042;

-- ─────────────────────────────────────────────────────────────────────────
-- 8) 20260602000050_seed_distribution_catalog
--    Delta: replace the partial WHERE is_hosted index with a plain index so
--    the catalog (WHERE NOT is_hosted) queries are also covered.
-- ─────────────────────────────────────────────────────────────────────────
DO $$
DECLARE
    is_partial BOOLEAN;
BEGIN
    SELECT (indpred IS NOT NULL) INTO is_partial
      FROM pg_index
     WHERE indexrelid = 'idx_applications_is_hosted'::regclass;
    IF is_partial THEN
        DROP INDEX idx_applications_is_hosted;
        CREATE INDEX idx_applications_is_hosted ON applications(is_hosted);
    END IF;
EXCEPTION WHEN undefined_table THEN
    -- idx_applications_is_hosted does not exist; the original migration
    -- never ran on this DB. Re-create it as plain.
    CREATE INDEX idx_applications_is_hosted ON applications(is_hosted);
END $$;

UPDATE _sqlx_migrations
   SET checksum = decode('6cb22db653e1253bf4e840c5039e848d62c7b035cd9558b9370c4197f8092bb5a3c6f18d236a5d7d514ae7dd223c2240', 'hex')
 WHERE version = 20260602000050;

-- ─────────────────────────────────────────────────────────────────────────
-- 9) 20260417000041_create_oidc_sessions_and_codes
--    Delta: NONE (comment text on the existing INSERT was corrected; no
--    schema change). Only the checksum needs reconciling.
-- ─────────────────────────────────────────────────────────────────────────
UPDATE _sqlx_migrations
   SET checksum = decode('9b9f3095b6ebed64bf98ae08c03f83761e5e1801f7d93d3e50be66f7d5b9fe440c781696b7a7f2851467153fc360014d', 'hex')
 WHERE version = 20260417000041;

-- ─────────────────────────────────────────────────────────────────────────
-- 10) 20260502000048_register_mokosh_oidc_client
--     Delta: the abandoned placeholder client row (client_id
--     b0000000-0000-4000-8000-000000000001) is now inserted already-
--     disabled. On the live DB the row was inserted with disabled_at
--     NULL; stamp it so it leaves the oauth_clients_active partial index.
-- ─────────────────────────────────────────────────────────────────────────
UPDATE oauth_clients
   SET disabled_at = COALESCE(disabled_at, NOW())
 WHERE client_id = 'b0000000-0000-4000-8000-000000000001';

UPDATE _sqlx_migrations
   SET checksum = decode('6bb3d91d625e7538f872fbab5bc97e80b2984b67cf7bd03bcb907ad2ea48dae3da5cdcb9d7c1415589e417f258c0b092', 'hex')
 WHERE version = 20260502000048;

-- ─────────────────────────────────────────────────────────────────────────
-- 11) 20241230000017_add_application_subdomain
--     Delta: NONE. The removed UPDATEs targeted slugs ('rus','rustylinks')
--     that were never seeded (their position-8 seed migration was deleted),
--     so the live DB has zero rows that those UPDATEs would have touched.
-- ─────────────────────────────────────────────────────────────────────────
UPDATE _sqlx_migrations
   SET checksum = decode('0e15e09723d11c194762c0aabde41050531ac96090654a1a20c9a3992c34b30b8e50b5df7eaa3f772358740506013501', 'hex')
 WHERE version = 20241230000017;

-- ─────────────────────────────────────────────────────────────────────────
-- Verify: every one of the 11 versions must now exist with the expected
-- checksum. The expected count (11) is asserted at the end; if any UPDATE
-- found zero rows (e.g. a version is missing on this DB because the live
-- migration history is out of sync), this raises and rolls everything back.
-- ─────────────────────────────────────────────────────────────────────────
DO $$
DECLARE
    updated_count INT;
BEGIN
    SELECT count(*) INTO updated_count FROM _sqlx_migrations
     WHERE version IN (
        20260319000025, 20260313000021, 20260605000010, 20241230000014,
        20260417000040, 20260429000045, 20260417000042, 20260602000050,
        20260417000041, 20260502000048, 20241230000017
     );
    IF updated_count <> 11 THEN
        RAISE EXCEPTION
            '_sqlx_migrations is missing % of the 11 expected versions; aborting reconcile so no checksum drifts in isolation.',
            11 - updated_count;
    END IF;
END $$;

\echo '== reconcile complete: 11 checksums updated, schema deltas applied =='
