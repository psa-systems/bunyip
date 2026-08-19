# IP geolocation: what is derived, stored, and why (BUNYIP-581)

bunyip derives a **country** from the client IP address that is already present in every request for security logging. This note bounds that use so a future change cannot quietly widen it.

## What is derived

- The **ISO 3166-1 alpha-2 country code** (and, for one email, the country name) of the request IP, via IP2Location (`dunite-geoip`).
- Nothing finer: no city, region, postal code, latitude/longitude, or ISP-level location reaches the application or storage.

This is a **server-side derivation from an IP the request already carries** for security logging, not client geolocation. There is no browser geolocation prompt, because a consent prompt would misrepresent what is happening.

## Where it is stored, and for how long

- `users.last_login_country` - the coarse country of the last sign-in, used only to detect a **new-country sign-in** and send the "new sign-in location" alert (BUNYIP-366). Overwritten on the next sign-in; no history is kept.
- **Audit log** - security events record the country code where relevant. Assume a 90-day audit-log retention; revise here if that changes.
- The password-reset email includes the request country as informational context; it is not persisted beyond the sent message.

The country allow/deny gate (below) reads the country to make a permit/refuse decision and does **not** persist it.

## Purpose

1. **Security**: alert a user to a sign-in from a new country (BUNYIP-366) and feed the suspicious-login risk signal (BUNYIP-373).
2. **Spam prevention**: a configurable country **allow/deny** list refuses sign-in from unwanted regions (BUNYIP-581), set in the system-config YAML layer (`country_access.allow` / `country_access.deny`, see [configuration.md](configuration.md)).

It is never used for marketing, profiling, or attaching a location to the user profile beyond the single coarse security-alert country above.

## Every IP-to-location call site (audit)

| Call site (`crates/bunyip-domain/src/services/auth.rs`) | What the resolved country is used for |
| --- | --- |
| `check_login_location` | new-country security alert; records `last_login_country` |
| `assess_login` | suspicious-login risk signal (country is new) |
| `country_name_for_ip` | request country shown in the password-reset email |
| `login` (country gate, BUNYIP-581) | the allow/deny sign-in decision; not persisted |

`bunyip-api/src/handlers/admin_ip_enrichment.rs` resolves ASN / VPN / proxy signals (IP2Proxy), not a country, and is advisory only.

Each site above is either a security alert, a security risk signal, or the allow/deny decision. None persists finer-grained location, and none attaches location to the user profile.
