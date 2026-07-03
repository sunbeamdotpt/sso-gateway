use async_trait::async_trait;
use base64::Engine;
use sha2::{Digest, Sha256};
use sqlx::Row;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct SamlNameIdMappingRow {
    pub id: String,
    pub tenant_id: String,
    pub sp_entity_id: String,
    pub identity_id: String,
    pub name_id: String,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait SamlNameIdMappingStore: Send + Sync + 'static {
    /// Return the existing pairwise NameID for the identity, creating and
    /// persisting it if necessary.
    async fn get_or_create(
        &self,
        tenant_id: &str,
        sp_entity_id: &str,
        identity_id: &str,
    ) -> Result<String, DbError>;

    /// Look up the identity id associated with a previously issued pairwise
    /// NameID for the given tenant and SP.
    async fn find_by_name_id(
        &self,
        tenant_id: &str,
        sp_entity_id: &str,
        name_id: &str,
    ) -> Result<String, DbError>;
}

#[derive(Clone)]
pub struct PgSamlNameIdMappingStore {
    pool: DbPool,
}

impl PgSamlNameIdMappingStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn get_or_create(
        &self,
        tenant_id: &str,
        sp_entity_id: &str,
        identity_id: &str,
    ) -> Result<String, DbError> {
        let name_id = compute_pairwise_name_id(tenant_id, sp_entity_id, identity_id);
        let row = sqlx::query_as::<_, SamlNameIdMappingRow>(
            "INSERT INTO saml_nameid_mappings \
             (tenant_id, sp_entity_id, identity_id, name_id) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, sp_entity_id, identity_id) DO UPDATE SET updated_at = NOW() \
             RETURNING id, tenant_id, sp_entity_id, identity_id, name_id, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(sp_entity_id)
        .bind(identity_id)
        .bind(&name_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.name_id)
    }

    pub async fn find_by_name_id(
        &self,
        tenant_id: &str,
        sp_entity_id: &str,
        name_id: &str,
    ) -> Result<String, DbError> {
        let row = sqlx::query_as::<_, SamlNameIdMappingRow>(
            "SELECT id, tenant_id, sp_entity_id, identity_id, name_id, created_at, updated_at \
             FROM saml_nameid_mappings \
             WHERE tenant_id = $1 AND sp_entity_id = $2 AND name_id = $3",
        )
        .bind(tenant_id)
        .bind(sp_entity_id)
        .bind(name_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| r.identity_id)
            .ok_or(DbError::SamlNameIdMappingNotFound)
    }
}

#[async_trait]
impl SamlNameIdMappingStore for PgSamlNameIdMappingStore {
    async fn get_or_create(
        &self,
        tenant_id: &str,
        sp_entity_id: &str,
        identity_id: &str,
    ) -> Result<String, DbError> {
        self.get_or_create(tenant_id, sp_entity_id, identity_id)
            .await
    }

    async fn find_by_name_id(
        &self,
        tenant_id: &str,
        sp_entity_id: &str,
        name_id: &str,
    ) -> Result<String, DbError> {
        self.find_by_name_id(tenant_id, sp_entity_id, name_id).await
    }
}

/// Compute a pairwise NameID as `base64url(sha256("{tenant_id}:{sp_entity_id}:{identity_id}"))`.
pub fn compute_pairwise_name_id(tenant_id: &str, sp_entity_id: &str, identity_id: &str) -> String {
    let input = format!("{tenant_id}:{sp_entity_id}:{identity_id}");
    let hash = Sha256::digest(input.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SamlNameIdMappingRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            sp_entity_id: row.try_get("sp_entity_id")?,
            identity_id: row.try_get("identity_id")?,
            name_id: row.try_get("name_id")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::{create_test_tenant, postgres_pool};

    async fn store() -> PgSamlNameIdMappingStore {
        PgSamlNameIdMappingStore::new(postgres_pool().await)
    }

    #[test]
    fn saml_nameid_mapping_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = SamlNameIdMappingRow {
            id: "id".to_string(),
            tenant_id: "tenant".to_string(),
            sp_entity_id: "https://sp/entity".to_string(),
            identity_id: "identity".to_string(),
            name_id: "nameid".to_string(),
            created_at: now,
            updated_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.name_id, "nameid");
    }

    #[test]
    fn compute_pairwise_name_id_is_deterministic() {
        let a = compute_pairwise_name_id("t1", "https://sp/entity", "id-1");
        let b = compute_pairwise_name_id("t1", "https://sp/entity", "id-1");
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn compute_pairwise_name_id_differs_by_component() {
        let by_tenant = compute_pairwise_name_id("t1", "https://sp/entity", "id-1");
        let by_sp = compute_pairwise_name_id("t2", "https://sp/entity", "id-1");
        let by_identity = compute_pairwise_name_id("t2", "https://sp/entity", "id-2");
        assert_ne!(by_tenant, by_sp);
        assert_ne!(by_sp, by_identity);
    }

    #[tokio::test]
    async fn mapping_lifecycle() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", ulid::Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let name_id = store
            .get_or_create(&tenant, "https://sp/entity", "identity-1")
            .await
            .unwrap();
        assert!(!name_id.is_empty());

        // Second call returns the same NameID.
        let name_id_again = store
            .get_or_create(&tenant, "https://sp/entity", "identity-1")
            .await
            .unwrap();
        assert_eq!(name_id, name_id_again);

        let identity_id = store
            .find_by_name_id(&tenant, "https://sp/entity", &name_id)
            .await
            .unwrap();
        assert_eq!(identity_id, "identity-1");

        assert!(matches!(
            store
                .find_by_name_id(&tenant, "https://sp/entity", "unknown")
                .await
                .unwrap_err(),
            DbError::SamlNameIdMappingNotFound
        ));
    }

    #[tokio::test]
    async fn trait_object_methods() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", ulid::Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store: Arc<dyn SamlNameIdMappingStore> = Arc::new(PgSamlNameIdMappingStore::new(pool));

        let name_id = store
            .get_or_create(&tenant, "https://trait-sp/entity", "identity-2")
            .await
            .unwrap();
        let identity_id = store
            .find_by_name_id(&tenant, "https://trait-sp/entity", &name_id)
            .await
            .unwrap();
        assert_eq!(identity_id, "identity-2");
    }
}
