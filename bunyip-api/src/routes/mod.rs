//! Route configuration for the API
//!
//! This module organizes all API routes and their handlers.

pub mod account;
pub mod admin;
pub mod application;
pub mod auth;
pub mod billing;
pub mod branding;
pub mod download;
pub mod events;
pub mod feedback;
pub mod health;
pub mod host;
pub mod mailer;
pub mod membership;
pub mod pricing;
pub mod user;
pub mod version;
pub mod webhook;

use actix_web::web;

// SPEC-9.20.1, SPEC-9.20.5, SPEC-2.4.1: the one /v1 scope; no introspection or registration route
/// Configure all application routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    // V1 API routes
    cfg.service(
        web::scope("/v1")
            .configure(health::configure)
            .configure(host::configure)
            .configure(auth::configure)
            .configure(user::configure)
            .configure(account::configure)
            .configure(download::configure)
            .configure(events::configure)
            .configure(application::configure)
            .configure(billing::configure)
            .configure(feedback::configure)
            .configure(mailer::configure)
            .configure(membership::configure)
            .configure(pricing::configure)
            .configure(branding::configure)
            .configure(webhook::configure)
            .configure(admin::configure),
    );

    // SPEC-9.20.2: probes live outside /v1
    // Root-level endpoints
    cfg.service(health::root_status);
    cfg.service(health::health_check);
    // E2E seed readiness (BUNYIP-163): lets the e2e workflow skip-and-pass when
    // staging is not bootstrapped, so `e2e` can be a required check.
    cfg.service(health::e2e_bootstrapped);

    // SPEC-9.20.3: update-check endpoint at the root
    // Root-level `/version` update-check endpoint (bunyip-specific).
    version::configure(cfg);

    // SPEC-9.20.4: provided by the OIDC crate, mounted outside /v1
    // OIDC / OAuth 2.1 endpoints (root-level, outside /v1) - provided by the
    // dunite-oidc vertical crate.
    bunyip_oidc::routes::oidc::configure_well_known(cfg);
    bunyip_oidc::routes::oidc::configure_oauth2(cfg);
}
