//! Route configuration for the API
//!
//! This module organizes all API routes and their handlers.

pub mod admin;
pub mod application;
pub mod auth;
pub mod billing;
pub mod download;
pub mod feedback;
pub mod health;
pub mod membership;
pub mod user;
pub mod version;
pub mod webhook;

use actix_web::web;

/// Configure all application routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    // V1 API routes
    cfg.service(
        web::scope("/v1")
            .configure(health::configure)
            .configure(auth::configure)
            .configure(user::configure)
            .configure(download::configure)
            .configure(application::configure)
            .configure(billing::configure)
            .configure(feedback::configure)
            .configure(membership::configure)
            .configure(webhook::configure)
            .configure(admin::configure),
    );

    // Root-level endpoints
    cfg.service(health::root_status);
    cfg.service(health::health_check);

    // Root-level `/version` update-check endpoint (bunyip-specific).
    version::configure(cfg);

    // OIDC / OAuth 2.1 endpoints (root-level, outside /v1) — provided by the
    // dunite-oidc vertical crate.
    bunyip_oidc::routes::oidc::configure_well_known(cfg);
    bunyip_oidc::routes::oidc::configure_oauth2(cfg);
}
