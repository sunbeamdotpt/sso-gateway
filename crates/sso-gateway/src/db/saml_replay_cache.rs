use super::{DbError, DbPool};

/// Database-backed SAML assertion ID replay cache.
#[derive(Clone)]
pub struct SamlReplayCache {
    pool: DbPool,
}

impl SamlReplayCache {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl gamlastan::security::ReplayCache for SamlReplayCache {
    fn check_and_insert(&self, id: &str, expiry: chrono::DateTime<chrono::Utc>) -> bool {
        let Some(expiry) = time::OffsetDateTime::from_unix_timestamp(expiry.timestamp()).ok()
        else {
            return false;
        };
        let pool = self.pool.clone();
        let id = id.to_string();
        // Block the current thread until the async insert completes. This keeps
        // the trait synchronous while allowing a database-backed backend.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(async move {
                    let _ = cleanup_saml_replay_cache(&pool).await;
                    sqlx::query(
                        "INSERT INTO saml_assertion_ids (id, expires_at) VALUES ($1, $2) \
                         ON CONFLICT (id) DO NOTHING",
                    )
                    .bind(&id)
                    .bind(expiry)
                    .execute(&pool)
                    .await
                    .map(|result| result.rows_affected() == 1)
                    .unwrap_or(false)
                })
            }),
            Err(_) => false,
        }
    }

    fn cleanup(&self) {
        let pool = self.pool.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            tokio::task::block_in_place(|| {
                let _ = handle.block_on(cleanup_saml_replay_cache(&pool));
            });
        }
    }
}

async fn cleanup_saml_replay_cache(pool: &DbPool) -> Result<(), DbError> {
    sqlx::query("DELETE FROM saml_assertion_ids WHERE expires_at < NOW()")
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use gamlastan::security::ReplayCache;

    use super::*;
    use crate::test_support::postgres_pool;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn check_and_insert_new_id_returns_true() {
        let cache = SamlReplayCache::new(postgres_pool().await);
        let id = format!("assertion-{}", ulid::Ulid::new());
        let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        assert!(cache.check_and_insert(&id, expiry));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn check_and_insert_duplicate_id_returns_false() {
        let cache = SamlReplayCache::new(postgres_pool().await);
        let id = format!("assertion-{}", ulid::Ulid::new());
        let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        assert!(cache.check_and_insert(&id, expiry));
        assert!(!cache.check_and_insert(&id, expiry));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup_does_not_panic() {
        let cache = SamlReplayCache::new(postgres_pool().await);
        cache.cleanup();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn check_and_insert_without_runtime_returns_false() {
        let cache = SamlReplayCache::new(postgres_pool().await);
        let id = format!("assertion-{}", ulid::Ulid::new());
        let handle = std::thread::spawn(move || {
            let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
            assert!(!cache.check_and_insert(&id, expiry));
        });
        handle.join().unwrap();
    }
}
