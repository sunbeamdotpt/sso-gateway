use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct SamlIdpKeyRow {
    pub id: String,
    pub tenant_id: String,
    pub key_id: String,
    pub private_key_pem: String,
    pub certificate_pem: String,
    pub is_active: bool,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait SamlIdpKeyStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        key_id: &str,
        private_key_pem: &str,
        certificate_pem: &str,
        is_active: bool,
    ) -> Result<SamlIdpKeyRow, DbError>;

    async fn get_active(&self, tenant_id: &str) -> Result<SamlIdpKeyRow, DbError>;

    async fn list(&self, tenant_id: &str) -> Result<Vec<SamlIdpKeyRow>, DbError>;
}

#[derive(Clone)]
pub struct PgSamlIdpKeyStore {
    pool: DbPool,
}

impl PgSamlIdpKeyStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        key_id: &str,
        private_key_pem: &str,
        certificate_pem: &str,
        is_active: bool,
    ) -> Result<SamlIdpKeyRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, SamlIdpKeyRow>(
            "INSERT INTO saml_idp_keys \
             (id, tenant_id, key_id, private_key_pem, certificate_pem, is_active) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id, tenant_id, key_id, private_key_pem, certificate_pem, is_active, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(key_id)
        .bind(private_key_pem)
        .bind(certificate_pem)
        .bind(is_active)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_active(&self, tenant_id: &str) -> Result<SamlIdpKeyRow, DbError> {
        let row = sqlx::query_as::<_, SamlIdpKeyRow>(
            "SELECT id, tenant_id, key_id, private_key_pem, certificate_pem, is_active, created_at, updated_at \
             FROM saml_idp_keys \
             WHERE tenant_id = $1 AND is_active = true \
             ORDER BY created_at DESC \
             LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlIdpKeyNotFound)
    }

    pub async fn list(&self, tenant_id: &str) -> Result<Vec<SamlIdpKeyRow>, DbError> {
        let rows = sqlx::query_as::<_, SamlIdpKeyRow>(
            "SELECT id, tenant_id, key_id, private_key_pem, certificate_pem, is_active, created_at, updated_at \
             FROM saml_idp_keys \
             WHERE tenant_id = $1 \
             ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

#[async_trait]
impl SamlIdpKeyStore for PgSamlIdpKeyStore {
    async fn create(
        &self,
        tenant_id: &str,
        key_id: &str,
        private_key_pem: &str,
        certificate_pem: &str,
        is_active: bool,
    ) -> Result<SamlIdpKeyRow, DbError> {
        self.create(
            tenant_id,
            key_id,
            private_key_pem,
            certificate_pem,
            is_active,
        )
        .await
    }

    async fn get_active(&self, tenant_id: &str) -> Result<SamlIdpKeyRow, DbError> {
        self.get_active(tenant_id).await
    }

    async fn list(&self, tenant_id: &str) -> Result<Vec<SamlIdpKeyRow>, DbError> {
        self.list(tenant_id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SamlIdpKeyRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            key_id: row.try_get("key_id")?,
            private_key_pem: row.try_get("private_key_pem")?,
            certificate_pem: row.try_get("certificate_pem")?,
            is_active: row.try_get("is_active")?,
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

    async fn store() -> PgSamlIdpKeyStore {
        PgSamlIdpKeyStore::new(postgres_pool().await)
    }

    #[test]
    fn saml_idp_key_row_debug_and_clone() {
        let now = time::OffsetDateTime::UNIX_EPOCH;
        let row = SamlIdpKeyRow {
            id: "id".to_string(),
            tenant_id: "tenant".to_string(),
            key_id: "key".to_string(),
            private_key_pem: "private".to_string(),
            certificate_pem: "cert".to_string(),
            is_active: true,
            created_at: now,
            updated_at: now,
        };
        let _ = format!("{:?}", row);
        let cloned = row.clone();
        assert_eq!(cloned.key_id, "key");
    }

    #[tokio::test]
    async fn idp_key_lifecycle() {
        let store = store().await;
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let key_id = format!("key-{}", Ulid::new());
        let created = store
            .create(&tenant, &key_id, "private-pem", "cert-pem", true)
            .await
            .unwrap();
        assert_eq!(created.key_id, key_id);
        assert!(created.is_active);

        let active = store.get_active(&tenant).await.unwrap();
        assert_eq!(active.id, created.id);

        let list = store.list(&tenant).await.unwrap();
        assert_eq!(list.len(), 1);

        assert!(matches!(
            store.get_active("missing-tenant").await.unwrap_err(),
            DbError::SamlIdpKeyNotFound
        ));
    }

    #[tokio::test]
    async fn trait_object_methods() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;
        let store: Arc<dyn SamlIdpKeyStore> = Arc::new(PgSamlIdpKeyStore::new(pool));

        let key_id = format!("trait-key-{}", Ulid::new());
        store
            .create(&tenant, &key_id, "private", "cert", true)
            .await
            .unwrap();
        assert!(store.get_active(&tenant).await.is_ok());
        assert_eq!(store.list(&tenant).await.unwrap().len(), 1);
    }
}
