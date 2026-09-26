-- BUNYIP-636 PR 4 of 5: register mokosh-apps' back-channel logout URI so
-- bunyip's `revoke_sessions_for_backchannel` fan-out notifies mokosh-server
-- when a session ends.
--
-- The mokosh-server Resource Server accepts the notification at
-- `POST /api/v1/bunyip/oauth2/backchannel-logout` (PMS-998, merged). The
-- SPA's audience row (registered in `20260603000010_register_mokosh_apps_and_drillmark_oidc_clients.sql`)
-- names `https://api.msp.a8n.systems` as the RS host, which is the origin
-- the receiver lives on.
--
-- With this URI set, an OP session revoked by any of the paths
-- `revoke_sessions_for_backchannel` covers (POST /v1/auth/logout,
-- `revoke_op_sessions`, an in-flight rotation past the PR 2/3 gate) fires
-- a one-shot HMAC-signed POST to the RS with a `logout_token` carrying
-- the session's `sid`. The RS then refuses every subsequent at+jwt for
-- that `sid`, closing the window between the session ending on the OP
-- and the access token's 600-second TTL expiring on the RS.
--
-- Failure to deliver is a `tracing::warn!` and NEVER fails the logout
-- itself (`revoke_sessions_for_backchannel` already spawns delivery
-- best-effort, per BUNYIP-53 / BUNYIP-88); the RS also honours the
-- short access-token TTL as an outer bound, so a lost notification is
-- at worst 10 minutes stale.

UPDATE oauth_clients
SET backchannel_logout_uri = 'https://api.msp.a8n.systems/api/v1/bunyip/oauth2/backchannel-logout'
WHERE client_id = 'b0000000-0000-4000-8000-000000000002'
  AND backchannel_logout_uri IS NULL;
