use std::sync::Arc;

use async_trait::async_trait;

use super::{DbError, DbPool};

const CLEANUP_INTERVAL_SECONDS: u64 = 300;

/// Async database-backed SAML assertion ID replay cache.
#[async_trait]
pub trait ReplayCache: Send + Sync + 'static {
    /// Insert `id` if it does not already exist. Returns `true` when the ID was
    /// newly inserted and `false` when it is a replay.
    async fn check_and_insert(
        &self,
        id: &str,
        expiry: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, DbError>;
}

/// Database-backed implementation of the async [`ReplayCache`] trait.
#[derive(Clone)]
pub struct SamlReplayCache {
    pool: DbPool,
    _cleanup_handle: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl SamlReplayCache {
    pub fn new(pool: DbPool) -> Self {
        let handle = spawn_cleanup_task(pool.clone());
        Self {
            pool,
            _cleanup_handle: Arc::new(std::sync::Mutex::new(Some(handle))),
        }
    }

    async fn check_and_insert_inner(
        &self,
        id: &str,
        expiry: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, DbError> {
        let expires_at = time::OffsetDateTime::from_unix_timestamp(expiry.timestamp())
            .unwrap_or_else(|_| {
                time::OffsetDateTime::now_utc() + std::time::Duration::from_secs(3600)
            });

        let result = sqlx::query(
            "INSERT INTO saml_assertion_ids (id, expires_at) VALUES ($1, $2) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }
}

#[async_trait]
impl ReplayCache for SamlReplayCache {
    async fn check_and_insert(
        &self,
        id: &str,
        expiry: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, DbError> {
        self.check_and_insert_inner(id, expiry).await
    }
}

#[async_trait]
impl ReplayCache for gamlastan::security::InMemoryReplayCache {
    async fn check_and_insert(
        &self,
        id: &str,
        expiry: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, DbError> {
        Ok(gamlastan::security::ReplayCache::check_and_insert(
            self, id, expiry,
        ))
    }
}

fn spawn_cleanup_task(pool: DbPool) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECONDS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_saml_replay_cache(&pool).await {
                tracing::warn!("saml replay cache cleanup failed: {}", e);
            }
        }
    })
}

async fn cleanup_saml_replay_cache(pool: &DbPool) -> Result<(), DbError> {
    sqlx::query("DELETE FROM saml_assertion_ids WHERE expires_at < NOW()")
        .execute(pool)
        .await?;
    Ok(())
}

/// Adapter that exposes the async [`ReplayCache`] to gamlastan's synchronous
/// `ReplayCache` trait used during SAML response processing.
///
/// This adapter is intended to be called from a **blocking context**, typically
/// inside `tokio::task::spawn_blocking`. It uses `Handle::block_on` to drive
/// the async cache call. Calling it directly from an async task will panic.
#[derive(Clone)]
pub struct GamlastanReplayAdapter(Arc<dyn ReplayCache>);

impl GamlastanReplayAdapter {
    pub fn new(cache: Arc<dyn ReplayCache>) -> Self {
        Self(cache)
    }
}

impl gamlastan::security::ReplayCache for GamlastanReplayAdapter {
    fn check_and_insert(&self, id: &str, expiry: chrono::DateTime<chrono::Utc>) -> bool {
        let cache = self.0.clone();
        let id = id.to_string();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle
                .block_on(async move { cache.check_and_insert(&id, expiry).await })
                .unwrap_or(false),
            Err(_) => {
                tracing::warn!("no Tokio runtime available for SAML replay cache check");
                false
            }
        }
    }

    fn cleanup(&self) {
        // Cleanup is handled by the background task; the sync trait's cleanup
        // hook is intentionally a no-op.
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use gamlastan::security::ReplayCache as GamlastanReplayCache;

    use super::*;
    use crate::test_support::postgres_pool;

    #[derive(Clone)]
    struct StubReplayCache {
        result: Arc<std::sync::Mutex<Option<Result<bool, DbError>>>>,
    }

    #[async_trait]
    impl ReplayCache for StubReplayCache {
        async fn check_and_insert(
            &self,
            _id: &str,
            _expiry: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, DbError> {
            self.result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }
    }

    #[tokio::test]
    async fn check_and_insert_new_id_returns_true() {
        let cache = SamlReplayCache::new(postgres_pool().await);
        let id = format!("assertion-{}", ulid::Ulid::new());
        let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        assert!(cache.check_and_insert(&id, expiry).await.unwrap());
    }

    #[tokio::test]
    async fn check_and_insert_duplicate_id_returns_false() {
        let cache = SamlReplayCache::new(postgres_pool().await);
        let id = format!("assertion-{}", ulid::Ulid::new());
        let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        assert!(cache.check_and_insert(&id, expiry).await.unwrap());
        assert!(!cache.check_and_insert(&id, expiry).await.unwrap());
    }

    #[tokio::test]
    async fn gamlastan_adapter_delegates_to_async_cache() {
        let stub = Arc::new(StubReplayCache {
            result: Arc::new(std::sync::Mutex::new(Some(Ok(true)))),
        });
        let adapter = GamlastanReplayAdapter::new(stub);
        let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        assert!(tokio::task::spawn_blocking(move || adapter.check_and_insert("id-1", expiry))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn gamlastan_adapter_returns_false_when_cache_errors() {
        let stub = Arc::new(StubReplayCache {
            result: Arc::new(std::sync::Mutex::new(Some(Err(DbError::SamlRequestReplay)))),
        });
        let adapter = GamlastanReplayAdapter::new(stub);
        let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        assert!(!tokio::task::spawn_blocking(move || adapter.check_and_insert("id-1", expiry))
            .await
            .unwrap());
    }

    #[test]
    fn gamlastan_adapter_returns_false_without_tokio_runtime() {
        let stub = Arc::new(StubReplayCache {
            result: Arc::new(std::sync::Mutex::new(Some(Ok(true)))),
        });
        let adapter = GamlastanReplayAdapter::new(stub);
        let cache = adapter.clone();
        let handle = std::thread::spawn(move || {
            let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
            assert!(!cache.check_and_insert("id-1", expiry));
        });
        handle.join().unwrap();
    }
}
