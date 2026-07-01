# Changelog

Internal, name-free history for bunyip. Point-in-time working docs (milestone handoffs, audit reports, codebase-state snapshots) are distilled here as they are retired, so the tree keeps only forward-useful reference material. Entries are newest-first and vary in depth by how much still matters.

## 2026-07-01 - Docs reorganization and history sanitization

- Markdown docs consolidated under `docs/` (public / how-to) and `docs/dev-docs/` (internal working notes); `README.md` and `CLAUDE.md` stay at the repo root, and README files stay colocated with their code. Path references in config, the justfile, source comments, and the subscriptions admin string were updated to match.
- Point-in-time docs (the 2026-06-06 platform audit tree and the 2026-05-15 milestone-1 handoff) were removed from the tree and distilled into the entries below.
- Contributor names were removed from commit-message text and the local-only `For AI/` scratch directory was purged from history. Git author/committer fields were intentionally left unchanged.

## 2026-06-06 - Multi-repo platform audit (distilled)

A file-granularity audit read every source file across bunyip, mokosh-apps, and mokosh-server (~580 files) with git-forensic reconstruction (commit counts, branch divergence, merge-graph, revert tracing) and a cross-repo contract check on the apps-to-server boundary. Every high and critical finding was adversarially verified against live source before being scored. Nothing was modified by the audit itself; findings were filed as remediation issues.

Baseline (2026-06-06), with re-verification through 2026-06-10:

- 409 total findings: 3 critical, 37 high, 197 medium, 172 low; 11 rejected on verification.
- By theme: 146 correctness, 19 cross-repo contract drift, 82 "too many cooks" (parallel branches on shared files), 131 dead/unused, 31 infra/CI.
- Re-verification closed roughly 8 distinct findings (a role-parser high/medium, two list-filter correctness wirings, two contract-drift forms, several dead stub pages). All 3 criticals and all top-10 highs remained open as of 2026-06-10.

Headline findings that concerned bunyip specifically:

- RP-Initiated Logout open redirect: `post_logout_redirect_uri` was taken from the query and used without validating against the client's registered URIs. Fix: validate against `client.post_logout_redirect_uris`, fall back to `/`.
- Auto-ban IP spoofing: the first `X-Forwarded-For` address was trusted unconditionally, so bans were evadable and a user could ban a victim by spoofing their IP. Fix: trust XFF only from a configured trusted-proxy CIDR and key bans off the real socket address.
- Authorization-code double-spend: fetch, in-memory consumed check, then a separate unconditional update, with no transaction or `RETURNING` guard. Fix: a single atomic `UPDATE ... WHERE consumed_at IS NULL RETURNING *`, rejecting on zero rows.
- Migration sequencing had no guard: multiple files collided on the same numeric suffixes.

Cross-cutting themes (all repos): the count-query / WHERE-placeholder bug recurred wherever a SELECT-plus-COUNT idiom was copied without a filtered-list test; duplicated helpers and parallel paginated-envelope types proliferated instead of shared code; half-merged refactors left orphaned modules and hotfix chains. Full per-finding detail lived in the audit tree that this entry replaces; the remediation issues carry the actionable items forward.

## 2026-05 - Milestone 1: foundation (distilled)

Milestone 1 stood up bunyip as the PSA Systems SaaS shell at the apex domain (onboarding, account/org management, subscription UI, in-app feedback, platform admin), shipped as one Cargo workspace in two containers: `bunyip-api` (Axum) and `bunyip-web` (SPA served by Caddy). In this milestone bunyip-api was a thin seed-JSON backend, deliberately temporary pending real auth/orgs/billing endpoints.

- CI publishing moved to the `psa-systems-private` registry, with per-image tag scripts and a policy that only a push to `main` publishes a package (feature-branch and tag-only pushes do not).
- Distribution (BUNYIP-3): a self-host reference deployment (`compose.yml` + edge Caddy) distinct from the internal Traefik topology; an operator update check (`GET /version` reporting running version, build revision, and whether a newer release exists, with no auto-update); release automation that tags `vX.Y.Z` and publishes a Forgejo release on a version bump to main; and multi-arch build capability gated on an arm64 runner.
- Binary distribution (BUNYIP-25): a release job extracts artifacts via a `FROM scratch AS export` stage and publishes a musl-static `bunyip-api` tarball, a static `bunyip-web` bundle, and `SHA256SUMS` to the generic-packages registry; uploads are idempotent (201 first, 409 on retry treated as success).
- bunyip-api CORS moved from permissive to mirror-origin with credentials to support the cross-origin credentialed SPA in the self-host topology.
