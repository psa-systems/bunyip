# Specification roadmap

`docs/specification.md` is being converted from an overview document into a normative, numbered requirement set
(BUNYIP-1023). The conversion is split by module group into one issue per group, because a requirement for one
module tends to cross several files. The groups below were written in parallel and landed together in one PR.

This page holds the durable plan and the links between the sections and the issues that write them. It does not
restate status: current progress lives on the issues themselves, not here.

## Section ownership

| Section | Title | Issue |
|---|---|---|
| 1 | Purpose and non-goals | BUNYIP-1024 |
| 2 | Architecture and process model | BUNYIP-1024 |
| 3 | CI, scripts and end-to-end tests | BUNYIP-1025 |
| 4 | Data model and migrations | BUNYIP-1026 |
| 5-6 | OIDC and OCI crates | BUNYIP-1027 |
| 7 | Domain crate core (root, models, repositories, middleware) | BUNYIP-1028 |
| 8 | Domain crate services | BUNYIP-1029 |
| 9 | API application core (root, binaries, routes) | BUNYIP-1030 |
| 10 | API handlers | BUNYIP-1031 |
| 11 | Web application core (root, api client, routes, skin, views) | BUNYIP-1032 |
| 12 | Web handlers | BUNYIP-1033 |
| 13-14 | Shared web UI crate, packaging and final reconciliation | BUNYIP-1034 |

Every section issue is a subtask of the parent epic, BUNYIP-1023, which tracks the conversion as a whole.

## Sequencing

Sections 1-2 come first because every later section cites the id scheme and the workspace/process-model facts they
establish. The remaining sections have no ordering constraint between them: a module group's requirements only need
its own files plus whatever sections 1-2 fixed.

## Convention

New requirements are cited at their implementing site with a `// SPEC-<id>: <why, if non-obvious>` comment; see
[Specification citations](invariants/build-ci.md#specification-citations-bunyip-1023) in `CLAUDE.md`'s critical
conventions for the full rule.
