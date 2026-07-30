-- BUNYIP-411: record request metadata on feedback submissions so spam can be
-- traced and blocked. Feedback needs no authenticated user, so the source IP
-- and browser User-Agent are the only identifying signals available.
--
-- submitter_ip is the EXTERNAL client IP resolved through the trusted-proxy
-- chain (Traefik -> bunyip-web -> bunyip-api), not the Docker-internal peer;
-- see bunyip-web/src/client_ip.rs and bunyip-api extract_client_ip. Both
-- columns are nullable: dev / direct-hit submissions resolve no forwarded IP,
-- and a client may send no User-Agent. Rows predating this migration keep NULL.
ALTER TABLE feedback
    ADD COLUMN submitter_ip INET,
    ADD COLUMN user_agent   TEXT;
