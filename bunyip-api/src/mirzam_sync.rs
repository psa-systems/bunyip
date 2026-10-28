//! Wiring for the Mirzam account sync (BUNYIP-998) and its backfill
//! (BUNYIP-999).
//!
//! The sync itself is `bunyip_domain::services::mirzam_sync`. The one thing it
//! cannot do from the domain crate is read the API token, because the
//! governed-secret providers live here (`crate::secrets`). This module supplies
//! that read and builds the handle `main.rs` shares with the auth service and
//! the handlers.

use std::sync::Arc;

use async_trait::async_trait;
use bunyip_domain::config::{Config, GovernedSecret};
use bunyip_domain::repositories::MirzamConfigRepository;
use bunyip_domain::services::mirzam_backfill::{self, BackfillReport};
use bunyip_domain::services::mirzam_sync::{
    active_lists, MirzamClient, MirzamSync, MirzamTokenSource,
};
use bunyip_domain::services::AppKeySet;
use sqlx::PgPool;

/// `MIRZAM_API_TOKEN` from the ONE provider `SECRETS_STORAGE` declares, read
/// per sync so a token saved on the admin page applies at once.
struct GovernedMirzamToken {
    pool: PgPool,
    config: Config,
    key_set: AppKeySet,
}

#[async_trait]
impl MirzamTokenSource for GovernedMirzamToken {
    async fn token(&self) -> Result<Option<String>, String> {
        crate::secrets::read_secret(
            &self.pool,
            &self.config,
            &self.key_set,
            GovernedSecret::MirzamApiToken,
        )
        .await
        .map_err(|e| e.to_string())
    }
}

/// The sync handle, reading its token through the governed-secret providers.
pub fn mirzam_sync(pool: PgPool, config: Config, key_set: AppKeySet) -> MirzamSync {
    MirzamSync::new(
        pool.clone(),
        Arc::new(GovernedMirzamToken {
            pool,
            config,
            key_set,
        }),
    )
}

/// Hand `change` to the sync a handler extracted. Handlers take the handle as
/// `Option<web::Data<MirzamSync>>`, so an app built without one (most handler
/// tests) sends nothing rather than failing the request.
pub fn notify(
    sync: &Option<actix_web::web::Data<MirzamSync>>,
    change: bunyip_domain::services::mirzam_sync::AccountChange,
) {
    if let Some(sync) = sync {
        sync.notify(change);
    }
}

/// `bunyip-api mirzam-backfill` (BUNYIP-999): put every live verified account
/// on Mirzam's two lists with the saved settings and token. An integration
/// that is off, incomplete or without a token is an error naming what is
/// missing, so the command exits non-zero without calling Mirzam.
pub async fn backfill(
    pool: &PgPool,
    config: &Config,
    key_set: &AppKeySet,
    delays: &[std::time::Duration],
    pace: std::time::Duration,
) -> anyhow::Result<BackfillReport> {
    let row = MirzamConfigRepository::get(pool).await?;
    if !row.enabled {
        anyhow::bail!(
            "the Mirzam integration is switched off; switch it on on the admin Mirzam page first"
        );
    }
    let Some(lists) = active_lists(&row) else {
        anyhow::bail!(
            "the Mirzam integration is incomplete; set the address and both list slugs on the admin Mirzam page"
        );
    };
    let token = crate::secrets::read_secret(pool, config, key_set, GovernedSecret::MirzamApiToken)
        .await?
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "MIRZAM_API_TOKEN is not set in the {} provider",
                config.secrets_provider.as_str()
            )
        })?;
    let client = MirzamClient::new(&row.base_url, &token).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(mirzam_backfill::backfill(pool, &client, &lists, delays, pace).await?)
}
