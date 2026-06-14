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
   SET checksum = decode('e22c60e6c8a9a572c341b933d5c14c797a5125e69cb8faee4bfdbd8d8bfb7af992266365adafa6532e63f602b4a1cfc2', 'hex')
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
   SET checksum = decode('fe758aa402cf20c74c080d353ea17f4f8ce59efd0fb871d4007d3178e8a1b2cbe0baaa4eb383aa9766465792fe388d6a', 'hex')
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
   SET checksum = decode('14fddc4a09df80aef5d7269d72f607f4fa5d829d374b72cfe62347b66765413c593dedee3a91e33a18cfd3a51a92bb04', 'hex')
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
   SET checksum = decode('fad39fb3656fd2cc6f1e2fb5fcd8d4ac008d970dd16d356252a3744790fd954ed3b3146f4cdbdea4add856a724c05cd9', 'hex')
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
   SET checksum = decode('b1d9250685ac0713e3c611d1543b953e5e5d92684254f401dcac2b8c021fe3e01a7a87b8ed14c184ed8d11eed7c4e315', 'hex')
 WHERE version = 20260417000040;

-- ─────────────────────────────────────────────────────────────────────────
-- 6) 20260429000045_add_price_ids_to_tier_config
--    Delta: add the lifetime_price_id TEXT column.
-- ─────────────────────────────────────────────────────────────────────────
ALTER TABLE tier_config
    ADD COLUMN IF NOT EXISTS lifetime_price_id TEXT;

UPDATE _sqlx_migrations
   SET checksum = decode('65feb61908e7a4d0e8a128f5faed23264ad18c159ef64554bc8e5ebb1461ba57a03e86bca2a8e69d32230014e58fb1df', 'hex')
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
   SET checksum = decode('d6b8b6e871c334b30199729c52ac6cb6c694f4ad1c2d80c9dbcae055229ea9b0b276361097679f94573ddcd7df4d1b7f', 'hex')
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
   SET checksum = decode('1b105a3b6cf5401bb7329fb7d29003b1e52c363ad008e1a21be6d2bd8cd5686df30fd6ddf4ab13ad381757b6feacbe6b', 'hex')
 WHERE version = 20260602000050;

-- ─────────────────────────────────────────────────────────────────────────
-- 9) 20260417000041_create_oidc_sessions_and_codes
--    Delta: NONE (comment text on the existing INSERT was corrected; no
--    schema change). Only the checksum needs reconciling.
-- ─────────────────────────────────────────────────────────────────────────
UPDATE _sqlx_migrations
   SET checksum = decode('eeabf66beb4eacd5facf23d8c796b49d2074073db55fc0b8734a44374f42aa3f02867435b0ec815cff7578444c3609d5', 'hex')
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
   SET checksum = decode('7def758bb5f82900f679b9acd796eaaf0d8c22f5042a4322b6e57efaed0b1063434879ab08d05beb1dc73b74a881269c', 'hex')
 WHERE version = 20260502000048;

-- ─────────────────────────────────────────────────────────────────────────
-- 11) 20241230000017_add_application_subdomain
--     Delta: NONE. The removed UPDATEs targeted slugs ('rus','rustylinks')
--     that were never seeded (their position-8 seed migration was deleted),
--     so the live DB has zero rows that those UPDATEs would have touched.
-- ─────────────────────────────────────────────────────────────────────────
UPDATE _sqlx_migrations
   SET checksum = decode('31faddfdffa04e5a2b318078dc3760a65101ca01e059f99031ab25f62e83d269fcca12af524066e39d843a122668b5fc', 'hex')
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
