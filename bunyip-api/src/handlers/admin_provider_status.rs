//! Admin: the suite provider-status aggregate (BUNYIP-634).
//!
//! `GET /v1/admin/providers/status` shows a Bunyip admin the live provider
//! state of every application in the suite on one page: Bunyip's own (built
//! from the EXISTING `secrets.rs` / `config_status.rs` surveys, per
//! `crate::provider_status::own_report`, never a parallel implementation),
//! plus Mokosh's and Drillmark's, fetched over HTTP with the machine
//! credential Bunyip presents (the mailer-relay shape, BUNYIP-602, reversed).
//!
//! Reading is enough: there is no write path here, and none is planned by this
//! issue. Every application appears in the response, healthy or not; an
//! unreachable, unauthenticated, or version-mismatched application is a row,
//! never an omission.

use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::PgPool;

use bunyip_domain::config::SecretsProvider;
use bunyip_domain::services::provider_status::{aggregate, fetch_remote, AppStatusRow};

use crate::config::Config;
use crate::errors::AppError;
use crate::middleware::AdminUser;
use crate::responses::{get_request_id, success};
use crate::secrets::InfisicalProbe;

/// GET /v1/admin/providers/status
pub async fn get_provider_status(
    req: HttpRequest,
    _admin: AdminUser,
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
) -> Result<HttpResponse, AppError> {
    let request_id = get_request_id(&req);
    let key_set = config.app_key_set();

    let probe = if config.infisical.enabled || config.secrets_provider == SecretsProvider::Infisical
    {
        InfisicalProbe::Inspect
    } else {
        InfisicalProbe::Skip
    };

    let secrets_survey = crate::secrets::survey(&pool, &config, &key_set, probe).await?;
    let config_stack = crate::config_status::survey(&pool).await?;
    let own_report = crate::provider_status::own_report(&secrets_survey, &config_stack);

    let mut rows = vec![AppStatusRow {
        app: crate::provider_status::HOSTING_PROFILE.to_string(),
        status: bunyip_domain::services::provider_status::AppProviderStatus::Ok {
            report: own_report,
        },
    }];

    for remote in crate::provider_status::remote_apps() {
        let status = fetch_remote(&remote).await;
        rows.push(AppStatusRow {
            app: remote.name,
            status,
        });
    }

    let aggregated = aggregate(rows);
    Ok(success(aggregated, request_id))
}

#[cfg(test)]
mod tests {
    /// The route is admin-gated: `AdminUser` is an extractor argument on the
    /// handler, so an unauthenticated or non-admin caller never reaches the
    /// survey/fetch logic. This is a source-scan guard against the signature
    /// regressing to a public handler.
    #[test]
    fn the_handler_signature_requires_an_admin_user() {
        const SRC: &str = include_str!("admin_provider_status.rs");
        let (before, _tests) = SRC.split_once("#[cfg(test)]").expect("has a tests module");
        assert!(
            before.contains("_admin: AdminUser"),
            "get_provider_status must take an AdminUser extractor"
        );
    }
}
