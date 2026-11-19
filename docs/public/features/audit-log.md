# Audit log

Every mutating admin action lands in the audit log. The admin Audit page is the only way to read it today. This page covers the filter surface the UI exposes and the shape of a row.

## Row shape

Each row carries:

- `actor_user_id` or `actor_machine_client_id`: who did it. Never both.
- `action`: the enum value, e.g. `two_factor_reset`, `feedback_spam_marked`, `oidc_client_created`, `user_deactivated`.
- `severity`: `info`, `notice`, `warn` or `critical`. The classifier is fixed in code; an operator cannot tune it.
- `target_user_id` / `target_resource_id` / `target_tenant_id` / similar: what the action was against.
- `metadata`: a JSON object the write site chose. Shape is per-action.
- `recorded_at`: the UTC time of the write.
- `request_id`: the id that correlates with the api log line for the same request.

Severities are not configurable. A deployment that wants a particular action at `critical` must change the enforcement site.

## Filters

The audit page carries a fixed filter set, so an operator does not get a search form that admits arbitrary queries:

- **User filter** (`user_id`). Scopes the view to one actor or one target.
- **Since filter**. One of `1h`, `24h`, `7d`, `30d`. Shorter windows render fast.
- **Severity filter**. Chips for `info`, `notice`, `warn`, `critical`. Multi-select.
- **Action filter**. Chips for the predefined action list the UI exposes. A chip for an action the current page has not loaded is still visible.
- **Free-text search** (`q`). Searches the metadata JSON for a substring. Trimmed and bounded.

The chip option lists are declared once and audited against the write sites, so a new action that ships without a chip option would be invisible on the filter row.

## What is NOT in the audit log

- **Read access.** A user reading their own account page does not write an audit row. A super-admin reading the audit itself does not log the read.
- **Successful sign-ins to downstream RPs.** The audit lives on bunyip; a downstream RP writes its own audit for its own API usage.
- **Failed logins per se.** The `AuthRateLimiter` tracks these for the rate-limit decision; the audit log records a row only when the rate limit trips or a login-approval event fires.

## Retention

The audit table is not pruned by bunyip. A deployment that needs retention policy applies one from outside: a scheduled DELETE against the table with a retention window, or a read-and-archive job to object storage.

## Related

- [Authentication](../authentication.md) names the auth events written to the audit log.
- [API](../api.md): there is no `GET` route for audit today; the admin page is the only reader.
