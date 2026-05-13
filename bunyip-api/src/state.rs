use crate::config::Config;
use bunyip_mocks::SharedMockStore;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub store: SharedMockStore,
}

impl AppState {
    pub fn new(config: Config, store: SharedMockStore) -> Self {
        Self { config, store }
    }
}
