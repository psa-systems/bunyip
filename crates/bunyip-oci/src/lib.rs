//! bunyip-oci - OCI registry vertical for Bunyip (PSA Systems).
//!
//! **SCAFFOLD - intentionally empty.** Structural placeholder mirroring
//! `menkent-oci`. When filled it will wire the generic, storage-agnostic
//! `dunite-oci` engine (on-disk blob cache, manifest cache, per-user rate
//! limiting, bearer-token issuance) to Bunyip's database (the `store`
//! traits: `BlobStore`, `PullCounter`) and to actix-web handlers/routes
//! (`/v2/*`, `/auth/token`, admin cache-refresh), building on `bunyip-core`.
//!
//! Empty until upstream stabilizes - see
//! `dev-docs/bunyip-on-dunite-scaffold.md`.
