use async_trait::async_trait;
use sqlx::Row;
use tracing::warn;
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
    encryption_key: Option<Vec<u8>>,
}

impl PgSamlIdpKeyStore {
    pub fn new(pool: DbPool) -> Self {
        let encryption_key = Self::encryption_key_from_env();
        Self {
            pool,
            encryption_key,
        }
    }

    pub fn with_encryption_key(pool: DbPool, key: Vec<u8>) -> Self {
        Self {
            pool,
            encryption_key: Some(key),
        }
    }

    fn encryption_key_from_env() -> Option<Vec<u8>> {
        let value = std::env::var("SAML_IDP_KEY_ENCRYPTION_KEY").ok()?;
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value.trim())
            .or_else(|_| {
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, value.trim())
            })
            .ok()
            .filter(|k| k.len() >= 32)
    }

    fn encrypt(&self, plaintext: &str) -> Result<String, DbError> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or(DbError::EncryptionKeyMissing)?;
        super::crypto::encrypt(plaintext, key)
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String, DbError> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or(DbError::EncryptionKeyMissing)?;
        super::crypto::decrypt(ciphertext, key)
    }

    async fn decrypt_row(&self, mut row: SamlIdpKeyRow) -> Result<SamlIdpKeyRow, DbError> {
        let encrypted: Option<String> =
            sqlx::query_scalar("SELECT encrypted_private_key FROM saml_idp_keys WHERE id = $1")
                .bind(&row.id)
                .fetch_one(&self.pool)
                .await?;

        if let Some(ciphertext) = encrypted.filter(|s| !s.is_empty()) {
            row.private_key_pem = self.decrypt(&ciphertext)?;
            return Ok(row);
        }

        // Legacy plaintext row: migrate to encrypted storage when a key is available.
        if !row.private_key_pem.is_empty() {
            if let Some(key) = self.encryption_key.as_ref() {
                let ciphertext = super::crypto::encrypt(&row.private_key_pem, key)?;
                sqlx::query(
                    "UPDATE saml_idp_keys \
                     SET encrypted_private_key = $1, private_key_pem = '', updated_at = NOW() \
                     WHERE id = $2",
                )
                .bind(&ciphertext)
                .bind(&row.id)
                .execute(&self.pool)
                .await?;
                return Ok(row);
            }
            warn!(
                tenant_id = %row.tenant_id,
                key_id = %row.key_id,
                "encrypted SAML IdP key requested but no encryption key configured"
            );
            return Err(DbError::EncryptionKeyMissing);
        }

        Err(DbError::SamlIdpKeyNotFound)
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
        let encrypted_private_key = self.encrypt(private_key_pem).ok();
        let stored_private_key = if encrypted_private_key.is_some() {
            ""
        } else {
            private_key_pem
        };

        let row = sqlx::query_as::<_, SamlIdpKeyRow>(
            "INSERT INTO saml_idp_keys \
             (id, tenant_id, key_id, private_key_pem, encrypted_private_key, certificate_pem, is_active) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id, tenant_id, key_id, private_key_pem, certificate_pem, is_active, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(key_id)
        .bind(stored_private_key)
        .bind(encrypted_private_key.as_deref())
        .bind(certificate_pem)
        .bind(is_active)
        .fetch_one(&self.pool)
        .await?;

        if encrypted_private_key.is_some() {
            // Return a usable row to callers.
            let mut row = row;
            row.private_key_pem = private_key_pem.to_string();
            Ok(row)
        } else {
            Ok(row)
        }
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
        match row {
            Some(row) => self.decrypt_row(row).await,
            None => Err(DbError::SamlIdpKeyNotFound),
        }
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

        let mut decrypted = Vec::with_capacity(rows.len());
        for row in rows {
            decrypted.push(self.decrypt_row(row).await?);
        }
        Ok(decrypted)
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

    fn encryption_key() -> Vec<u8> {
        vec![0u8; 32]
    }

    async fn store() -> PgSamlIdpKeyStore {
        PgSamlIdpKeyStore::with_encryption_key(postgres_pool().await, encryption_key())
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
        assert_eq!(created.private_key_pem, "private-pem");

        let active = store.get_active(&tenant).await.unwrap();
        assert_eq!(active.id, created.id);
        assert_eq!(active.private_key_pem, "private-pem");

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
        let store: Arc<dyn SamlIdpKeyStore> = Arc::new(PgSamlIdpKeyStore::with_encryption_key(
            pool,
            encryption_key(),
        ));

        let key_id = format!("trait-key-{}", Ulid::new());
        store
            .create(&tenant, &key_id, "private", "cert", true)
            .await
            .unwrap();
        assert!(store.get_active(&tenant).await.is_ok());
        assert_eq!(store.list(&tenant).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn plaintext_row_without_key_returns_error() {
        let pool = postgres_pool().await;
        let tenant = format!("tenant-{}", Ulid::new());
        create_test_tenant(&pool, &tenant).await;

        let key_id = format!("plain-key-{}", Ulid::new());
        sqlx::query(
            "INSERT INTO saml_idp_keys \
             (id, tenant_id, key_id, private_key_pem, certificate_pem, is_active) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Ulid::new().to_string())
        .bind(&tenant)
        .bind(&key_id)
        .bind("plaintext-private-key")
        .bind("cert-pem")
        .bind(true)
        .execute(&pool)
        .await
        .unwrap();

        let store = PgSamlIdpKeyStore::new(pool);
        let err = store.get_active(&tenant).await.unwrap_err();
        assert!(matches!(err, DbError::EncryptionKeyMissing));
    }
}
