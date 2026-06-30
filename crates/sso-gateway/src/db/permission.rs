use async_trait::async_trait;
use sqlx::Row;
use ulid::Ulid;

use super::{DbError, DbPool};

#[derive(Debug, Clone)]
pub struct PermissionTupleRow {
    pub id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub object: String,
    pub relation: String,
    pub subject_id: String,
    pub created_at: time::OffsetDateTime,
}

#[async_trait]
pub trait PermissionTupleStore: Send + Sync + 'static {
    async fn create(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<PermissionTupleRow, DbError>;

    async fn get(&self, tenant_id: &str, id: &str) -> Result<PermissionTupleRow, DbError>;

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError>;

    async fn list(
        &self,
        tenant_id: &str,
        namespace: Option<&str>,
        object: Option<&str>,
        relation: Option<&str>,
    ) -> Result<Vec<PermissionTupleRow>, DbError>;
}

#[derive(Clone)]
pub struct PgPermissionTupleStore {
    pool: DbPool,
}

impl PgPermissionTupleStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<PermissionTupleRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, PermissionTupleRow>(
            "INSERT INTO permission_tuples \
             (id, tenant_id, namespace, object, relation, subject_id) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id, tenant_id, namespace, object, relation, subject_id, created_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(namespace)
        .bind(object)
        .bind(relation)
        .bind(subject_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: &str, id: &str) -> Result<PermissionTupleRow, DbError> {
        let row = sqlx::query_as::<_, PermissionTupleRow>(
            "SELECT id, tenant_id, namespace, object, relation, subject_id, created_at \
             FROM permission_tuples \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::TupleNotFound)
    }

    pub async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError> {
        let result = sqlx::query("DELETE FROM permission_tuples WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::TupleNotFound);
        }
        Ok(())
    }

    pub async fn list(
        &self,
        tenant_id: &str,
        namespace: Option<&str>,
        object: Option<&str>,
        relation: Option<&str>,
    ) -> Result<Vec<PermissionTupleRow>, DbError> {
        let mut query = String::from(
            "SELECT id, tenant_id, namespace, object, relation, subject_id, created_at \
             FROM permission_tuples \
             WHERE tenant_id = $1",
        );
        let mut param_idx = 2;
        if namespace.is_some() {
            query.push_str(&format!(" AND namespace = ${param_idx}"));
            param_idx += 1;
        }
        if object.is_some() {
            query.push_str(&format!(" AND object = ${param_idx}"));
            param_idx += 1;
        }
        if relation.is_some() {
            query.push_str(&format!(" AND relation = ${param_idx}"));
        }
        query.push_str(" ORDER BY created_at DESC");

        let mut q = sqlx::query_as::<_, PermissionTupleRow>(&query).bind(tenant_id);
        if let Some(namespace) = namespace {
            q = q.bind(namespace);
        }
        if let Some(object) = object {
            q = q.bind(object);
        }
        if let Some(relation) = relation {
            q = q.bind(relation);
        }
        let rows = q.fetch_all(&self.pool).await?;
        Ok(rows)
    }
}

#[async_trait]
impl PermissionTupleStore for PgPermissionTupleStore {
    async fn create(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<PermissionTupleRow, DbError> {
        self.create(tenant_id, namespace, object, relation, subject_id).await
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<PermissionTupleRow, DbError> {
        self.get(tenant_id, id).await
    }

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError> {
        self.delete(tenant_id, id).await
    }

    async fn list(
        &self,
        tenant_id: &str,
        namespace: Option<&str>,
        object: Option<&str>,
        relation: Option<&str>,
    ) -> Result<Vec<PermissionTupleRow>, DbError> {
        self.list(tenant_id, namespace, object, relation).await
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for PermissionTupleRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            namespace: row.try_get("namespace")?,
            object: row.try_get("object")?,
            relation: row.try_get("relation")?,
            subject_id: row.try_get("subject_id")?,
            created_at: row.try_get("created_at")?,
        })
    }
}
