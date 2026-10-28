//! Wiring for the Mirzam account sync (BUNYIP-998).
//!
//! The sync itself is `bunyip_domain::services::mirzam_sync`. The one thing it
//! cannot do from the domain crate is read the API token, because the
//! governed-secret providers live here (`crate::secrets`). This module supplies
//! that read and builds the handle `main.rs` shares with the auth service and
//! the handlers.

use std::sync::Arc;

use async_trait::async_trait;
use bunyip_domain::config::{Config, GovernedSecret};
use bunyip_domain::services::mirzam_sync::{MirzamSync, MirzamTokenSource};
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
