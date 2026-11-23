# Features

The feature surfaces bunyip renders in its own admin and the audit it emits as a result. One page per feature, from the UI angle rather than the API angle. If a feature is behind a toggle, the page says so and names the row.

- [Feedback classifier](feedback.md). Four-signal spam filter on `/feedback` with an admin review flow.
- [OCI registry](oci-registry.md). The internal registry endpoints under `/v2/*` and the push/pull scopes that gate them.
- [Audit log](audit-log.md). Every mutating admin action, with the fixed filter chips the UI exposes.
