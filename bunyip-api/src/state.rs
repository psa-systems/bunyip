use std::sync::Arc;

use crate::config::Config;
use crate::version::UpdateChecker;
use bunyip_mocks::SharedMockStore;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub store: SharedMockStore,
    /// Shared update-availability checker (caches upstream lookups).
    pub updates: Arc<UpdateChecker>,
}

impl AppState {
    pub fn new(config: Config, store: SharedMockStore) -> Self {
        let updates = Arc::new(UpdateChecker::new(
            config.update_check_url.clone(),
            config.update_check_token.clone(),
        ));
        Self {
            config,
            store,
            updates,
        }
    }
}
