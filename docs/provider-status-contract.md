# The suite provider-status contract (BUNYIP-634)

Bunyip aggregates a live view of which configuration/secret providers every
application in the suite is actually using: its own state (from the existing
`secrets-status` / `config-status` surveys), Mokosh's (PMS-989), and
Drillmark's (DMARC-41), on one admin page (`GET /admin/providers/status` in
bunyip-web, backed by `GET /v1/admin/providers/status` in bunyip-api). This is
the wire contract every application serves so that page can render one shape
for all three, defined here and consumed by the Rust type
`bunyip_domain::services::provider_status::ProviderStatusEnvelope`.

## Envelope

```json
{
  "schema_version": "1",
  "generated_at": "2026-09-10T00:00:00Z",
  "report": { ... }
}
```

`schema_version` is checked before anything else is parsed. An aggregator
that does not recognise the version shows the application as a version
mismatch rather than attempting to parse `report`, so an application on an
older or newer contract never reads as silently broken.

## Report

| Field                     | Type                          | Notes                                                              |
|---------------------------|--------------------------------|---------------------------------------------------------------------|
| `hosting_profile`         | string                          | A static per-application identifier (Mokosh: `self-hosted`/`saas`; Drillmark and Bunyip: one fixed string each). |
| `deviations`               | array                          | Optional; only meaningful for an application with a real hosting-profile concept (Mokosh today). |
| `configuration_generation` | object or absent                | `{number, resolved_at, actor}`; optional. |
| `kinds`                    | array of [kind](#kind)          | One entry per provider kind the application has. A kind it does not have is simply absent. |
| `collected_at`             | timestamp or absent             | When this collection ran. |

## Kind

| Field         | Type                     | Notes |
|---------------|--------------------------|-------|
| `kind`        | string                   | e.g. `configuration`, `secrets_application`. |
| `enabled`     | array of `{name, priority, reachable, unreachable_reason}` | Every provider enabled for this kind, in priority order (0 = highest). |
| `serving`     | string or `null`          | The provider actually serving this kind, if any. |
| `keys`        | array of [key](#key)      | Per-key provenance. Empty for a kind with no per-key concept. |
| `enumeration` | `{"Supported": [...]}` \| `"Unsupported"` \| absent | Whether the kind's providers can list their keys. |

## Key

| Field                  | Type            | Notes |
|------------------------|-----------------|-------|
| `key`                  | string          | The declared key name. |
| `feature`              | string or absent | What stops working when nobody holds this key. |
| `recorded_served_by`   | string or `null` | The provider that resolved this key at the last generation/read. |
| `live_holds`           | bool            | Live presence at collection time. |
| `state`                | string          | `unchanged` / `appeared` / `disappeared` / `changed_provider` when tracked, else empty. |
| `providers`            | array of string, default `[]` | **Bunyip extension**: every provider observed to hold this key, when the reporting application tracks full per-key membership. PMS-989 and DMARC-41 report only `recorded_served_by`/`live_holds` (a single provider) today and may leave this empty; the aggregator degrades its "present in more than one provider" detection to a coarser, kind-level signal (more than one entry in `enabled`) when it is. |

Every field beyond `kind` / `hosting_profile` / `schema_version` carries a
tolerant default on the Bunyip side (`#[serde(default)]`), so an application
on an older contract version, or one that simply does not track a field,
parses cleanly rather than failing.

## No values, ever

Every field above is a name, a boolean, a small integer, or a timestamp.
Nothing in this contract is or carries a secret, password, token, or
connection string; that is the whole point of the report existing separately
from the configuration or secret itself.

## Authentication

Bunyip calls each application's endpoint with the machine credential it
already issues for application-to-application calls (`oauth_clients`,
`bunyip_oidc::machine_client`, the same mechanism the mailer relay uses,
BUNYIP-602), presented as HTTP Basic. Mokosh's and Drillmark's shipped
endpoints today gate on their own admin-session check
(`RequireAdmin`/`RequireAdminAccess`) rather than that credential, a deferral
both tickets recorded explicitly pending this document; swapping their gate to
accept the machine credential is tracked as a follow-up
(`BUNYIP-634`'s subtask). Until that swap ships, Bunyip's aggregator reaches
them, is rejected, and correctly shows each as `Unauthenticated` rather than
omitting the row or reporting it as healthy: that outcome is expected, not a
bug in the aggregator.

## The three discrepancy flags

Computed by `bunyip_domain::services::provider_status::discrepancies_for`,
over every application whose fetch resolved to `Ok`:

1. **A declared provider holds nothing.** A key's `recorded_served_by` is
   `null` and `providers` is empty (or absent): nobody holds a value this
   deployment is supposed to read.
2. **A value is present in more than one provider.** A key's `providers` has
   more than one entry, or (when per-key membership is not tracked) a kind's
   `enabled` names more than one provider.
3. **The original incident.** A key's `recorded_served_by` differs from its
   kind's `serving` provider: the highest-priority provider does not hold the
   value, but a lower one does.

## Reference implementations

- Bunyip's own: `bunyip-api/src/provider_status.rs`, built from
  `bunyip-api/src/secrets.rs` (`secrets-status`) and
  `bunyip-api/src/config_status.rs` (`config-status`); no parallel survey.
- Mokosh: `src/providers/status/mod.rs` (PMS-989).
- Drillmark: `dmarc-reporter-backend/src/providers/status/mod.rs` (DMARC-41).
