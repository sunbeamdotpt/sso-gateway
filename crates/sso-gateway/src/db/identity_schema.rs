use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct IdentitySchemaRow {
    pub id: String,
    pub tenant_id: String,
    pub schema_id: String,
    pub schema_json: serde_json::Value,
    pub is_default: bool,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait IdentitySchemaStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        schema_id: &str,
        schema_json: serde_json::Value,
        is_default: bool,
    ) -> Result<IdentitySchemaRow, DbError>;

    async fn get_by_schema_id(
        &self,
        tenant_id: &str,
        schema_id: &str,
    ) -> Result<IdentitySchemaRow, DbError>;

    async fn list(&self, tenant_id: &str) -> Result<Vec<IdentitySchemaRow>, DbError>;

    async fn delete(&self, tenant_id: &str, schema_id: &str) -> Result<(), DbError>;

    async fn update(
        &self,
        tenant_id: &str,
        schema_id: &str,
        schema_json: serde_json::Value,
        is_default: bool,
    ) -> Result<IdentitySchemaRow, DbError>;

    async fn set_default(
        &self,
        tenant_id: &str,
        schema_id: &str,
    ) -> Result<IdentitySchemaRow, DbError>;

    async fn get_default(&self, tenant_id: &str) -> Result<IdentitySchemaRow, DbError>;
}

#[derive(Clone)]
pub struct PgIdentitySchemaStore {
    pool: DbPool,
}

impl PgIdentitySchemaStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        schema_id: &str,
        schema_json: serde_json::Value,
        is_default: bool,
    ) -> Result<IdentitySchemaRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, IdentitySchemaRow>(
            "INSERT INTO tenant_identity_schemas \
             (id, tenant_id, schema_id, schema_json, is_default) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id, tenant_id, schema_id, schema_json, is_default, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(schema_id)
        .bind(sqlx::types::Json(schema_json))
        .bind(is_default)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_by_schema_id(
        &self,
        tenant_id: &str,
        schema_id: &str,
    ) -> Result<IdentitySchemaRow, DbError> {
        let row = sqlx::query_as::<_, IdentitySchemaRow>(
            "SELECT id, tenant_id, schema_id, schema_json, is_default, created_at, updated_at \
             FROM tenant_identity_schemas \
             WHERE tenant_id = $1 AND schema_id = $2",
        )
        .bind(tenant_id)
        .bind(schema_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SchemaNotFound)
    }

    pub async fn list(&self, tenant_id: &str) -> Result<Vec<IdentitySchemaRow>, DbError> {
        let rows = sqlx::query_as::<_, IdentitySchemaRow>(
            "SELECT id, tenant_id, schema_id, schema_json, is_default, created_at, updated_at \
             FROM tenant_identity_schemas \
             WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn delete(&self, tenant_id: &str, schema_id: &str) -> Result<(), DbError> {
        let result = sqlx::query(
            "DELETE FROM tenant_identity_schemas WHERE tenant_id = $1 AND schema_id = $2",
        )
        .bind(tenant_id)
        .bind(schema_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::SchemaNotFound);
        }
        Ok(())
    }

    pub async fn update(
        &self,
        tenant_id: &str,
        schema_id: &str,
        schema_json: serde_json::Value,
        is_default: bool,
    ) -> Result<IdentitySchemaRow, DbError> {
        if is_default {
            self.unset_default(tenant_id).await?;
        }
        let row = sqlx::query_as::<_, IdentitySchemaRow>(
            "UPDATE tenant_identity_schemas \
             SET schema_json = $1, is_default = $2, updated_at = NOW() \
             WHERE tenant_id = $3 AND schema_id = $4 \
             RETURNING id, tenant_id, schema_id, schema_json, is_default, created_at, updated_at",
        )
        .bind(sqlx::types::Json(schema_json))
        .bind(is_default)
        .bind(tenant_id)
        .bind(schema_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SchemaNotFound)
    }

    pub async fn set_default(
        &self,
        tenant_id: &str,
        schema_id: &str,
    ) -> Result<IdentitySchemaRow, DbError> {
        self.unset_default(tenant_id).await?;
        let row = sqlx::query_as::<_, IdentitySchemaRow>(
            "UPDATE tenant_identity_schemas \
             SET is_default = TRUE, updated_at = NOW() \
             WHERE tenant_id = $1 AND schema_id = $2 \
             RETURNING id, tenant_id, schema_id, schema_json, is_default, created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(schema_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SchemaNotFound)
    }

    pub async fn get_default(&self, tenant_id: &str) -> Result<IdentitySchemaRow, DbError> {
        let row = sqlx::query_as::<_, IdentitySchemaRow>(
            "SELECT id, tenant_id, schema_id, schema_json, is_default, created_at, updated_at \
             FROM tenant_identity_schemas \
             WHERE tenant_id = $1 AND is_default = TRUE \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SchemaNotFound)
    }

    async fn unset_default(&self, tenant_id: &str) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE tenant_identity_schemas SET is_default = FALSE, updated_at = NOW() WHERE tenant_id = $1 AND is_default = TRUE",
        )
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl IdentitySchemaStore for PgIdentitySchemaStore {
    async fn create(
        &self,
        tenant_id: &str,
        schema_id: &str,
        schema_json: serde_json::Value,
        is_default: bool,
    ) -> Result<IdentitySchemaRow, DbError> {
        self.create(tenant_id, schema_id, schema_json, is_default).await
    }

    async fn get_by_schema_id(
        &self,
        tenant_id: &str,
        schema_id: &str,
    ) -> Result<IdentitySchemaRow, DbError> {
        self.get_by_schema_id(tenant_id, schema_id).await
    }

    async fn list(&self, tenant_id: &str) -> Result<Vec<IdentitySchemaRow>, DbError> {
        self.list(tenant_id).await
    }

    async fn delete(&self, tenant_id: &str, schema_id: &str) -> Result<(), DbError> {
        self.delete(tenant_id, schema_id).await
    }

    async fn update(
        &self,
        tenant_id: &str,
        schema_id: &str,
        schema_json: serde_json::Value,
        is_default: bool,
    ) -> Result<IdentitySchemaRow, DbError> {
        self.update(tenant_id, schema_id, schema_json, is_default).await
    }

    async fn set_default(
        &self,
        tenant_id: &str,
        schema_id: &str,
    ) -> Result<IdentitySchemaRow, DbError> {
        self.set_default(tenant_id, schema_id).await
    }

    async fn get_default(&self, tenant_id: &str) -> Result<IdentitySchemaRow, DbError> {
        self.get_default(tenant_id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for IdentitySchemaRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            schema_id: row.try_get("schema_id")?,
            schema_json: row
                .try_get::<sqlx::types::Json<serde_json::Value>, _>("schema_json")?
                .0,
            is_default: row.try_get("is_default")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::IdentitySchemaRow;

    #[test]
    fn identity_schema_row_from_row_compiles() {
        let _size = std::mem::size_of::<IdentitySchemaRow>();
    }
}
