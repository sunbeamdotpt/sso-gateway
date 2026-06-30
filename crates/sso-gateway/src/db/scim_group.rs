use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct ScimGroupRow {
    pub id: String,
    pub tenant_id: String,
    pub display_name: String,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[async_trait]
pub trait ScimGroupStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        display_name: &str,
    ) -> Result<ScimGroupRow, DbError>;

    async fn get(&self, tenant_id: &str, id: &str) -> Result<ScimGroupRow, DbError>;

    async fn list(&self, tenant_id: &str) -> Result<Vec<ScimGroupRow>, DbError>;

    async fn update(
        &self,
        tenant_id: &str,
        id: &str,
        display_name: &str,
    ) -> Result<ScimGroupRow, DbError>;

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError>;

    async fn add_member(
        &self,
        tenant_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<(), DbError>;

    async fn remove_member(
        &self,
        tenant_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<(), DbError>;

    async fn list_members(&self, group_id: &str) -> Result<Vec<String>, DbError>;

    async fn list_user_groups(&self, user_id: &str) -> Result<Vec<String>, DbError>;

    async fn remove_user_from_all_groups(&self, user_id: &str) -> Result<(), DbError>;
}

#[derive(Clone)]
pub struct PgScimGroupStore {
    pool: DbPool,
}

impl PgScimGroupStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        display_name: &str,
    ) -> Result<ScimGroupRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, ScimGroupRow>(
            "INSERT INTO scim_groups (id, tenant_id, display_name) \
             VALUES ($1, $2, $3) \
             RETURNING id, tenant_id, display_name, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(display_name)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: &str, id: &str) -> Result<ScimGroupRow, DbError> {
        let row = sqlx::query_as::<_, ScimGroupRow>(
            "SELECT id, tenant_id, display_name, created_at, updated_at \
             FROM scim_groups \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::TenantNotFound)
    }

    pub async fn list(&self, tenant_id: &str) -> Result<Vec<ScimGroupRow>, DbError> {
        let rows = sqlx::query_as::<_, ScimGroupRow>(
            "SELECT id, tenant_id, display_name, created_at, updated_at \
             FROM scim_groups \
             WHERE tenant_id = $1 \
             ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn update(
        &self,
        tenant_id: &str,
        id: &str,
        display_name: &str,
    ) -> Result<ScimGroupRow, DbError> {
        let row = sqlx::query_as::<_, ScimGroupRow>(
            "UPDATE scim_groups \
             SET display_name = $1, updated_at = NOW() \
             WHERE tenant_id = $2 AND id = $3 \
             RETURNING id, tenant_id, display_name, created_at, updated_at",
        )
        .bind(display_name)
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::TenantNotFound)
    }

    pub async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError> {
        let result = sqlx::query("DELETE FROM scim_groups WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::TenantNotFound);
        }
        Ok(())
    }

    pub async fn add_member(
        &self,
        tenant_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<(), DbError> {
        // Ensure the group belongs to the tenant before adding a member.
        let _ = self.get(tenant_id, group_id).await?;
        sqlx::query(
            "INSERT INTO scim_group_members (group_id, user_id) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(group_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn remove_member(
        &self,
        _tenant_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<(), DbError> {
        sqlx::query("DELETE FROM scim_group_members WHERE group_id = $1 AND user_id = $2")
            .bind(group_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_members(&self, group_id: &str) -> Result<Vec<String>, DbError> {
        let ids = sqlx::query_scalar(
            "SELECT user_id FROM scim_group_members WHERE group_id = $1 ORDER BY created_at DESC",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(ids)
    }

    pub async fn list_user_groups(&self, user_id: &str) -> Result<Vec<String>, DbError> {
        let ids = sqlx::query_scalar(
            "SELECT group_id FROM scim_group_members WHERE user_id = $1 ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(ids)
    }

    pub async fn remove_user_from_all_groups(&self, user_id: &str) -> Result<(), DbError> {
        sqlx::query("DELETE FROM scim_group_members WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ScimGroupStore for PgScimGroupStore {
    async fn create(
        &self,
        tenant_id: &str,
        display_name: &str,
    ) -> Result<ScimGroupRow, DbError> {
        self.create(tenant_id, display_name).await
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<ScimGroupRow, DbError> {
        self.get(tenant_id, id).await
    }

    async fn list(&self, tenant_id: &str) -> Result<Vec<ScimGroupRow>, DbError> {
        self.list(tenant_id).await
    }

    async fn update(
        &self,
        tenant_id: &str,
        id: &str,
        display_name: &str,
    ) -> Result<ScimGroupRow, DbError> {
        self.update(tenant_id, id, display_name).await
    }

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError> {
        self.delete(tenant_id, id).await
    }

    async fn add_member(
        &self,
        tenant_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<(), DbError> {
        self.add_member(tenant_id, group_id, user_id).await
    }

    async fn remove_member(
        &self,
        tenant_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<(), DbError> {
        self.remove_member(tenant_id, group_id, user_id).await
    }

    async fn list_members(&self, group_id: &str) -> Result<Vec<String>, DbError> {
        self.list_members(group_id).await
    }

    async fn list_user_groups(&self, user_id: &str) -> Result<Vec<String>, DbError> {
        self.list_user_groups(user_id).await
    }

    async fn remove_user_from_all_groups(&self, user_id: &str) -> Result<(), DbError> {
        self.remove_user_from_all_groups(user_id).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ScimGroupRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            display_name: row.try_get("display_name")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}
