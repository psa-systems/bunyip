//! BUNYIP-643: the configuration half of the status contract.
//!
//! `bunyip-api config-status` is to configuration what `bunyip-api
//! secrets-status` (`crate::secrets`) is to the governed secrets: the
//! non-destructive survey an operator runs on a HEALTHY deployment to see which
//! provider is serving each value, and which providers hold a value that is
//! ignored today and becomes live if the higher one is cleared.
//!
//! [`survey`] is the only IO here: it reads the three admin-managed singleton
//! rows and folds them into ONE database provider, so the report covers every
//! declared key in one stack. Everything below it - the classification, the
//! report and its rendering - is pure and lives in
//! [`bunyip_domain::config_providers`], which is what BUNYIP-634 serves to the
//! rest of the suite alongside the secrets survey.
//!
//! No configuration VALUE enters the report, for the same reason no secret value
//! enters the secrets one.

use bunyip_domain::config::{AutoBanConfig, EmailConfig, TierConfig};
use bunyip_domain::config_providers::{ConfigStack, DatabaseProvider};
use bunyip_domain::errors::AppError;
use bunyip_domain::repositories::{AutoBanConfigRepository, EmailConfigRepository};
use sqlx::PgPool;
use tracing::error;

/// Build the full provider stack: the merged database provider over the file and
/// environment providers.
///
/// A row that cannot be read is reported at `error` and contributes nothing, so
/// the report says "the environment serves this" rather than silently claiming
/// the database holds nothing. A Group-1 key in a row is returned as the startup
/// error naming it, exactly as it is at boot.
pub async fn survey(pool: &PgPool) -> Result<ConfigStack, AppError> {
    let mut database = DatabaseProvider::new();

    match EmailConfigRepository::get(pool).await {
        Ok(row) => database.merge(EmailConfig::database_provider(&row).map_err(to_app_error)?),
        Err(e) => {
            error!(error = %e, "email_config could not be read; it contributes nothing to config-status")
        }
    }
    match bunyip_domain::repositories::TierConfigRepository::get(pool).await {
        Ok(row) => database.merge(TierConfig::database_provider(&row).map_err(to_app_error)?),
        Err(e) => {
            error!(error = %e, "tier_config could not be read; it contributes nothing to config-status")
        }
    }
    match AutoBanConfigRepository::get(pool).await {
        Ok(row) => database.merge(AutoBanConfig::database_provider(&row).map_err(to_app_error)?),
        Err(e) => {
            error!(error = %e, "auto_ban_config could not be read; it contributes nothing to config-status")
        }
    }

    Ok(ConfigStack::with_database(database))
}

/// A refused key is an operator-facing configuration error, not an internal one.
fn to_app_error(failure: bunyip_domain::config::ConfigFailure) -> AppError {
    AppError::BadRequest(format!(
        "{} is not usable - {}. {}",
        failure.var, failure.reason, failure.remedy
    ))
}
