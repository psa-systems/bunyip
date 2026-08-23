//! bunyip-oci - OCI registry vertical for Bunyip (PSA Systems).
//!
//! Implements the read-only, Forgejo-backed OCI registry: bearer-token auth,
//! `/v2/*` manifest and blob endpoints, on-disk blob caching, per-user rate
//! limiting, and the admin cache-refresh endpoint.
//!
//! Unlike a monolithic crate, the registry *mechanism* (blob caching, manifest
//! caching, rate limiting, token issuance, the Forgejo client) lives in the
//! generic, storage-agnostic [`dunite_oci`] engine. This crate is the
//! consumer-side wiring: it implements the engine's [`dunite_oci::store`]
//! traits against Bunyip's Postgres schema and exposes actix-web
//! handlers/routes built on top of the engine.
//!
//! ## Module layout
//!
//! The internal layout mirrors the layered domain crate (`errors`, `models`,
//! `repositories`, `services`, `middleware`, `handlers`). Each module
//! glob-re-exports its `bunyip_domain` counterpart (the domain) AND the matching
//! pieces of the `dunite_oci` engine, so the ported OCI sources keep using
//! `crate::errors::{AppError, OciError}`, `crate::models::oci::*`,
//! `crate::services::{BlobCache, OciTokenService, ...}`, etc. unchanged.

pub use bunyip_domain::{config, responses};

pub mod errors;

pub mod models {
    //! Domain models from bunyip-domain plus the OCI wire/cache types from the
    //! dunite-oci engine (under `models::oci`).
    pub use bunyip_domain::models::*;

    pub use dunite_oci::models::oci;
}

pub mod services {
    //! Domain services from bunyip-domain plus the generic OCI registry engine
    //! services from dunite-oci (BlobCache, ManifestCache, OciLimiter,
    //! OciTokenService, ForgejoRegistryClient).
    pub use bunyip_domain::services::*;

    pub use dunite_oci::services::{
        BlobCache, BlobCacheError, ForgejoRegistryClient, ManifestCache, OciLimitDenial,
        OciLimiter, OciTokenService, RegistryError, RegistryTokenClaims,
    };
}

pub mod repositories {
    //! Domain repositories from bunyip-domain plus the OCI persistence adapters
    //! that implement the dunite-oci `store` traits against Bunyip's schema.
    pub use bunyip_domain::repositories::*;

    pub mod oci_blob_cache;
    pub mod oci_pull_daily_counts;

    pub use oci_blob_cache::OciBlobCacheRepository;
    pub use oci_pull_daily_counts::OciPullDailyCountRepository;
}

pub mod middleware {
    //! Domain middleware from bunyip-domain plus the OCI bearer-token extractor
    //! and the `WWW-Authenticate` response middleware.
    pub use bunyip_domain::middleware::*;

    pub mod oci_auth;
    pub mod oci_www_authenticate;

    pub use oci_auth::OciBearerUser;
    pub use oci_www_authenticate::OciWwwAuthenticate;
}

pub mod handlers {
    pub mod admin_oci;
    pub mod oci_auth;
    pub mod oci_registry;
}

pub mod routes;
