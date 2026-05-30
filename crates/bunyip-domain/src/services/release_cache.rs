//! TTL cache for Forgejo release metadata.

use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::models::download::ReleaseMetadata;
use crate::services::forgejo::{ForgejoClient, ForgejoError};

#[derive(Clone)]
pub struct ReleaseCache {
    client: Arc<ForgejoClient>,
    cache: Cache<(Uuid, String), Arc<ReleaseMetadata>>,
}

impl ReleaseCache {
    pub fn new(client: Arc<ForgejoClient>, ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .max_capacity(1024)
            .build();
        Self { client, cache }
    }

    /// Get release metadata, populating cache on miss.
    pub async fn get(
        &self,
        app_id: Uuid,
        owner: &str,
        repo: &str,
        tag: &str,
    ) -> Result<Arc<ReleaseMetadata>, ForgejoError> {
        let key = (app_id, tag.to_string());
        if let Some(hit) = self.cache.get(&key).await {
            return Ok(hit);
        }
        let fresh = self.client.get_release(owner, repo, tag).await?;
        let arc = Arc::new(fresh);
        self.cache.insert(key, arc.clone()).await;
        Ok(arc)
    }

    pub async fn invalidate(&self, app_id: Uuid, tag: &str) {
        self.cache.invalidate(&(app_id, tag.to_string())).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[actix_rt::test]
    async fn second_call_is_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/repos/a8n/rus/releases/tags/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tag_name": "v1",
                "assets": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = Arc::new(ForgejoClient::new(server.uri(), "tok".into()));
        let cache = ReleaseCache::new(client, 300);
        let app_id = Uuid::new_v4();

        let a = cache.get(app_id, "a8n", "rus", "v1").await.unwrap();
        let b = cache.get(app_id, "a8n", "rus", "v1").await.unwrap();
        assert_eq!(a.tag_name, b.tag_name);
    }

    #[actix_rt::test]
    async fn invalidate_forces_refetch() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tag_name": "v1",
                "assets": []
            })))
            .expect(2)
            .mount(&server)
            .await;

        let client = Arc::new(ForgejoClient::new(server.uri(), "tok".into()));
        let cache = ReleaseCache::new(client, 300);
        let app_id = Uuid::new_v4();

        cache.get(app_id, "a8n", "rus", "v1").await.unwrap();
        cache.invalidate(app_id, "v1").await;
        cache.get(app_id, "a8n", "rus", "v1").await.unwrap();
    }
}
