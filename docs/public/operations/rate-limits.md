# Rate limits

Bunyip puts a baseline cap under every api route via `RateLimitFloor`. The floor is a per-IP counter per route. Individual routes may add tighter per-user caps on top; the floor never raises them.

## The floor

`RateLimitFloor` is a cached snapshot read once per request. Two reasons it is a cache:

- Hitting the database on every request to decide if a request is allowed is unacceptable at the fleet's rate.
- The whitelist check also needs to be fast, so a snapshot carries both the per-route caps and the whitelist together.

The snapshot refreshes on a short interval. A change on the admin page becomes effective within one refresh window, not instantly.

## Per-route overrides

The admin Rate limits page lists every route bunyip exposes and the current cap for each. A row sets a tighter cap by moving the number down; the UI refuses to raise a cap above the floor.

Three kinds of cap per route:

- **Per-IP** (always on). The floor counts hits from one IP per route per window.
- **Per-user** (opt-in). A route that is tied to a logged-in user can carry a per-user cap in addition to the per-IP cap. Both must pass.
- **Per-client** (machine clients). A route that admits a machine client can carry a per-client-id cap.

A caller that trips a cap is answered `429 Too Many Requests` with the standard `Retry-After` header. The api does not drop the connection or silently stall.

## The whitelist

Some callers are internal and need not be rate-limited: the fleet's monitoring poll, a scheduled job that fans out through a known subnet. Add a CIDR to the whitelist on the admin page; requests from an IP inside the CIDR bypass the floor.

The whitelist check is cached alongside the floor, so adding an entry becomes effective within one refresh window. A whitelisted caller is still subject to per-user caps on routes that carry one; the whitelist bypasses per-IP only.

## Credential checks: failures count, not successes

Credential-check routes (login, two-factor, password reset, setup token, API login) count only failures against the rate limiter. A successful credential clears its email+IP bucket and does not count. This stops a user from locking themselves out with a long run of correct sign-ins and still catches a brute-force attempt.

Side-effect throttles (sign-up recovery flows, login-approval claim polls) count every attempt.

## Tuning

Every cap in the registry carries a sensible default. Tuning procedure, when a cap turns out to be wrong for a deployment:

1. Watch the logs for `429` on the route.
2. Decide whether the caller is misbehaving (keep the cap, maybe tighten) or whether the caller is legitimate and the default is wrong (loosen on the admin page).
3. Make the edit; the change becomes effective within the refresh window.

A deployment that is seeing widespread `429` after a release should check whether a cap was lowered in release notes, not tune blindly.

## What the floor does NOT do

- It is not a DDoS defence. A deployment that needs to survive a flooding attack puts a rate-limiting layer at the edge; bunyip's floor lives downstream and assumes the edge has shed the obvious load.
- It does not CAPTCHA. The floor is a count, not a challenge.
- It does not shape bandwidth. Every request takes its usual time; the cap decides whether the request runs at all, not how fast it runs.
