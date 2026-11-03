-- BUNYIP-1011: the per-client allow-list for the host-CONFIG route, the
-- configuration twin of 20261028000030's secrets one.
--
-- A second column rather than a second use of `allowed_secret_keys`, because
-- BUNYIP-855 D9 settled that the two credentials stay separate: a calling app
-- that may read a non-secret suite fact is not thereby allowed to read a
-- secret, and a leak of the configuration credential must not widen into the
-- secrets. A reading app registers twice if it wants both, each registration
-- carrying its own one-list entitlement.
--
-- Default empty and NOT NULL, the same default-deny: every registration that
-- exists today, and every one made without naming a config key, reads nothing
-- from that route.
ALTER TABLE oauth_clients
    ADD COLUMN allowed_config_keys TEXT[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN oauth_clients.allowed_config_keys IS
    'BUNYIP-1011: host-config keys this registration may read at GET /v1/host/config/{KEY}. Empty means none, which is every registration that does not name one. Separate from allowed_secret_keys on purpose (BUNYIP-855 D9).';
