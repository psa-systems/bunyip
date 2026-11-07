//! Route configuration for the OCI registry server (the registry subdomain).
//!
//! Intentionally separate from the main API `configure()` - this module is
//! mounted on a dedicated `App` in the binary so that the OCI server can run
//! on its own port and subdomain.

use actix_web::web;

use crate::handlers::{oci_auth, oci_registry};

// SPEC-6.2.1, SPEC-6.2.2, SPEC-6.2.3, SPEC-6.2.4, SPEC-6.2.5:
//  registry route table; every non-GET/HEAD verb under /v2 is rejected
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/auth/token").route(web::get().to(oci_auth::issue_token)))
        .service(
            web::scope("/v2")
                .service(web::resource("").route(web::get().to(oci_registry::version_probe)))
                .service(web::resource("/").route(web::get().to(oci_registry::version_probe)))
                .service(
                    web::resource("/{slug}/manifests/{reference}")
                        .route(web::get().to(oci_registry::get_manifest))
                        .route(web::head().to(oci_registry::get_manifest)),
                )
                .service(
                    web::resource("/{slug}/blobs/{digest}")
                        .route(web::get().to(oci_registry::get_blob))
                        .route(web::head().to(oci_registry::get_blob)),
                )
                // SPEC-1.2: every write verb is rejected here, never stored.
                // Push-catchall: any non-GET/HEAD under /v2/* → 405.
                .service(
                    web::resource("/{tail:.*}")
                        .route(web::post().to(oci_registry::push_not_supported))
                        .route(web::put().to(oci_registry::push_not_supported))
                        .route(web::patch().to(oci_registry::push_not_supported))
                        .route(web::delete().to(oci_registry::push_not_supported)),
                ),
        );
}
