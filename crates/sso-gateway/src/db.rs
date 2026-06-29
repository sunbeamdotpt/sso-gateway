use connectrpc::ConnectError;
use sqlx::{Pool, Postgres, Row, migrate::MigrateDatabase};
use thiserror::Error;
use tracing::info;
use ulid::Ulid;

pub type DbPool = Pool<Postgres>;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlx error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("missing system tenant")]
    MissingSystemTenant,

    #[error("tenant not found")]
    TenantNotFound,

    #[error("id mapping not found")]
    MappingNotFound,

    #[error("identity schema not found")]
    SchemaNotFound,

    #[error("permission tuple not found")]
    TupleNotFound,

    #[error("saml provider not found")]
    SamlProviderNotFound,

    #[error("saml request not found")]
    SamlRequestNotFound,

    #[error("saml identity mapping not found")]
    SamlIdentityMappingNotFound,

    #[error("saml idp key not found")]
    SamlIdpKeyNotFound,

    #[error("saml service provider client not found")]
    SamlSpClientNotFound,

    #[error("api key not found or expired")]
    ApiKeyNotFound,
}

impl From<DbError> for sunbeam_g2v::error::ServiceError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::Sqlx(e) => Self::Database(e.to_string()),
            DbError::MissingSystemTenant => Self::Internal("missing system tenant".to_string()),
            DbError::TenantNotFound => Self::NotFound("tenant not found".to_string()),
            DbError::MappingNotFound => Self::NotFound("id mapping not found".to_string()),
            DbError::SchemaNotFound => Self::NotFound("identity schema not found".to_string()),
            DbError::TupleNotFound => Self::NotFound("permission tuple not found".to_string()),
            DbError::SamlProviderNotFound => Self::NotFound("saml provider not found".to_string()),
            DbError::SamlRequestNotFound => Self::NotFound("saml request not found".to_string()),
            DbError::SamlIdentityMappingNotFound => {
                Self::NotFound("saml identity mapping not found".to_string())
            }
            DbError::SamlIdpKeyNotFound => Self::NotFound("saml idp key not found".to_string()),
            DbError::SamlSpClientNotFound => {
                Self::NotFound("saml service provider client not found".to_string())
            }
            DbError::ApiKeyNotFound => {
                Self::Unauthenticated("api key not found or expired".to_string())
            }
        }
    }
}

impl From<DbError> for ConnectError {
    fn from(err: DbError) -> Self {
        let service_err: sunbeam_g2v::error::ServiceError = err.into();
        service_err.into()
    }
}

pub async fn create_pool(database_url: &str) -> Result<DbPool, sqlx::Error> {
    if !Postgres::database_exists(database_url)
        .await
        .unwrap_or(false)
    {
        Postgres::create_database(database_url).await?;
    }

    let pool = Pool::<Postgres>::connect(database_url).await?;
    sqlx::migrate!("../../migrations").run(&pool).await?;
    Ok(pool)
}

pub async fn bootstrap_system_tenant(
    pool: &DbPool,
    system_tenant_ulid: &str,
) -> Result<String, DbError> {
    let existing: Option<String> =
        sqlx::query_scalar("SELECT id FROM tenants WHERE id = $1 AND is_system = TRUE")
            .bind(system_tenant_ulid)
            .fetch_optional(pool)
            .await?;

    if let Some(id) = existing {
        info!("system tenant already bootstrapped: {}", id);
        return Ok(id);
    }

    sqlx::query(
        "INSERT INTO tenants (id, slug, display_name, is_system, settings) VALUES ($1, $2, $3, TRUE, $4)",
    )
    .bind(system_tenant_ulid)
    .bind("system")
    .bind("System")
    .bind(sqlx::types::Json(serde_json::json!({})))
    .execute(pool)
    .await?;

    info!("bootstrapped system tenant: {}", system_tenant_ulid);
    Ok(system_tenant_ulid.to_string())
}

#[derive(Debug, Clone)]
pub struct TenantRow {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub is_system: bool,
    pub settings: serde_json::Value,
}

#[derive(Clone)]
pub struct TenantRepo {
    pool: DbPool,
}

impl TenantRepo {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    pub async fn create(
        &self,
        slug: &str,
        display_name: &str,
        settings: serde_json::Value,
    ) -> Result<TenantRow, DbError> {
        let id = Ulid::new().to_string();

        let row = sqlx::query_as::<_, TenantRow>(
            "INSERT INTO tenants (id, slug, display_name, settings) VALUES ($1, $2, $3, $4) RETURNING id, slug, display_name, is_system, settings",
        )
        .bind(&id)
        .bind(slug)
        .bind(display_name)
        .bind(sqlx::types::Json(settings))
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_by_id(&self, id: &str) -> Result<TenantRow, DbError> {
        let row = sqlx::query_as::<_, TenantRow>(
            "SELECT id, slug, display_name, is_system, settings FROM tenants WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.ok_or(DbError::TenantNotFound)
    }

    pub async fn list(&self) -> Result<Vec<TenantRow>, DbError> {
        let rows = sqlx::query_as::<_, TenantRow>(
            "SELECT id, slug, display_name, is_system, settings FROM tenants ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for TenantRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            slug: row.try_get("slug")?,
            display_name: row.try_get("display_name")?,
            is_system: row.try_get("is_system")?,
            settings: row
                .try_get::<sqlx::types::Json<serde_json::Value>, _>("settings")?
                .0,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TenantApiKeyRow {
    pub id: String,
    pub tenant_id: String,
    pub key_hash: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<time::OffsetDateTime>,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[derive(Clone)]
pub struct TenantApiKeyRepo {
    pool: DbPool,
}

impl TenantApiKeyRepo {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        key_hash: &str,
        scopes: &[String],
        expires_at: Option<time::OffsetDateTime>,
    ) -> Result<TenantApiKeyRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, TenantApiKeyRow>(
            "INSERT INTO tenant_api_keys \
             (id, tenant_id, key_hash, name, scopes, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id, tenant_id, key_hash, name, scopes, expires_at, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(key_hash)
        .bind(name)
        .bind(scopes)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_by_hash(&self, key_hash: &str) -> Result<TenantApiKeyRow, DbError> {
        let row = sqlx::query_as::<_, TenantApiKeyRow>(
            "SELECT id, tenant_id, key_hash, name, scopes, expires_at, created_at, updated_at \
             FROM tenant_api_keys \
             WHERE key_hash = $1",
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                if let Some(expires_at) = r.expires_at
                    && expires_at < time::OffsetDateTime::now_utc()
                {
                    return Err(DbError::ApiKeyNotFound);
                }
                Ok(r)
            }
            None => Err(DbError::ApiKeyNotFound),
        }
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for TenantApiKeyRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            key_hash: row.try_get("key_hash")?,
            name: row.try_get("name")?,
            scopes: row.try_get("scopes")?,
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct IdMappingRow {
    pub id: String,
    pub tenant_id: String,
    pub backend: String,
    pub public_id: String,
    pub ory_global_id: String,
    pub created_at: time::OffsetDateTime,
}

#[derive(Clone)]
pub struct IdMappingRepo {
    pool: DbPool,
}

impl IdMappingRepo {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
        ory_global_id: &str,
    ) -> Result<IdMappingRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, IdMappingRow>(
            "INSERT INTO id_mappings (id, tenant_id, backend, public_id, ory_global_id) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id, tenant_id, backend, public_id, ory_global_id, created_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(backend)
        .bind(public_id)
        .bind(ory_global_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_ory_id(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
    ) -> Result<String, DbError> {
        let id: Option<String> = sqlx::query_scalar(
            "SELECT ory_global_id FROM id_mappings \
             WHERE tenant_id = $1 AND backend = $2 AND public_id = $3",
        )
        .bind(tenant_id)
        .bind(backend)
        .bind(public_id)
        .fetch_optional(&self.pool)
        .await?;
        id.ok_or(DbError::MappingNotFound)
    }

    pub async fn get_public_id(
        &self,
        tenant_id: &str,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<String, DbError> {
        let id: Option<String> = sqlx::query_scalar(
            "SELECT public_id FROM id_mappings \
             WHERE tenant_id = $1 AND backend = $2 AND ory_global_id = $3",
        )
        .bind(tenant_id)
        .bind(backend)
        .bind(ory_global_id)
        .fetch_optional(&self.pool)
        .await?;
        id.ok_or(DbError::MappingNotFound)
    }

    pub async fn delete(
        &self,
        tenant_id: &str,
        backend: &str,
        public_id: &str,
    ) -> Result<(), DbError> {
        let result = sqlx::query(
            "DELETE FROM id_mappings WHERE tenant_id = $1 AND backend = $2 AND public_id = $3",
        )
        .bind(tenant_id)
        .bind(backend)
        .bind(public_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::MappingNotFound);
        }
        Ok(())
    }

    pub async fn list_public_ids(
        &self,
        tenant_id: &str,
        backend: &str,
    ) -> Result<Vec<String>, DbError> {
        let ids = sqlx::query_scalar(
            "SELECT public_id FROM id_mappings \
             WHERE tenant_id = $1 AND backend = $2 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .bind(backend)
        .fetch_all(&self.pool)
        .await?;
        Ok(ids)
    }

    /// Find the tenant that owns a given Ory global id for a backend.
    pub async fn get_tenant_id_by_ory_id(
        &self,
        backend: &str,
        ory_global_id: &str,
    ) -> Result<Option<String>, DbError> {
        let tenant_id: Option<String> = sqlx::query_scalar(
            "SELECT tenant_id FROM id_mappings \
             WHERE backend = $1 AND ory_global_id = $2 LIMIT 1",
        )
        .bind(backend)
        .bind(ory_global_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(tenant_id)
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for IdMappingRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            backend: row.try_get("backend")?,
            public_id: row.try_get("public_id")?,
            ory_global_id: row.try_get("ory_global_id")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

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

#[derive(Clone)]
pub struct IdentitySchemaRepo {
    pool: DbPool,
}

impl IdentitySchemaRepo {
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

#[derive(Clone)]
pub struct PermissionTupleRepo {
    pool: DbPool,
}

impl PermissionTupleRepo {
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

#[derive(Debug, Clone)]
pub struct SamlProviderRow {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub idp_entity_id: String,
    pub idp_sso_url: String,
    pub idp_certificate_pem: Option<String>,
    pub sp_entity_id: String,
    pub acs_url: String,
    pub name_id_format: Option<String>,
    pub schema_id: String,
    pub authn_requests_signed: bool,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[derive(Clone)]
pub struct SamlProviderRepo {
    pool: DbPool,
}

impl SamlProviderRepo {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: &str,
        name: &str,
        idp_entity_id: &str,
        idp_sso_url: &str,
        idp_certificate_pem: Option<&str>,
        sp_entity_id: &str,
        acs_url: &str,
        name_id_format: Option<&str>,
        schema_id: &str,
        authn_requests_signed: bool,
    ) -> Result<SamlProviderRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, SamlProviderRow>(
            "INSERT INTO saml_providers \
             (id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate_pem, sp_entity_id, acs_url, name_id_format, schema_id, authn_requests_signed) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             RETURNING id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate_pem, sp_entity_id, acs_url, name_id_format, schema_id, authn_requests_signed, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(name)
        .bind(idp_entity_id)
        .bind(idp_sso_url)
        .bind(idp_certificate_pem)
        .bind(sp_entity_id)
        .bind(acs_url)
        .bind(name_id_format)
        .bind(schema_id)
        .bind(authn_requests_signed)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: &str, id: &str) -> Result<SamlProviderRow, DbError> {
        let row = sqlx::query_as::<_, SamlProviderRow>(
            "SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate_pem, sp_entity_id, acs_url, name_id_format, schema_id, authn_requests_signed, created_at, updated_at \
             FROM saml_providers \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlProviderNotFound)
    }

    pub async fn get_by_id(&self, id: &str) -> Result<SamlProviderRow, DbError> {
        let row = sqlx::query_as::<_, SamlProviderRow>(
            "SELECT id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate_pem, sp_entity_id, acs_url, name_id_format, schema_id, authn_requests_signed, created_at, updated_at \
             FROM saml_providers \
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlProviderNotFound)
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SamlProviderRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            idp_entity_id: row.try_get("idp_entity_id")?,
            idp_sso_url: row.try_get("idp_sso_url")?,
            idp_certificate_pem: row.try_get("idp_certificate_pem")?,
            sp_entity_id: row.try_get("sp_entity_id")?,
            acs_url: row.try_get("acs_url")?,
            name_id_format: row.try_get("name_id_format")?,
            schema_id: row.try_get("schema_id")?,
            authn_requests_signed: row.try_get("authn_requests_signed")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SamlRequestRow {
    pub id: String,
    pub tenant_id: String,
    pub provider_id: String,
    pub relay_state: String,
    pub created_at: time::OffsetDateTime,
}

#[derive(Clone)]
pub struct SamlRequestRepo {
    pool: DbPool,
}

impl SamlRequestRepo {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        request_id: &str,
        provider_id: &str,
        relay_state: &str,
    ) -> Result<SamlRequestRow, DbError> {
        let row = sqlx::query_as::<_, SamlRequestRow>(
            "INSERT INTO saml_requests \
             (id, tenant_id, provider_id, relay_state) \
             VALUES ($1, $2, $3, $4) \
             RETURNING id, tenant_id, provider_id, relay_state, created_at",
        )
        .bind(request_id)
        .bind(tenant_id)
        .bind(provider_id)
        .bind(relay_state)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: &str, request_id: &str) -> Result<SamlRequestRow, DbError> {
        let row = sqlx::query_as::<_, SamlRequestRow>(
            "SELECT id, tenant_id, provider_id, relay_state, created_at \
             FROM saml_requests \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlRequestNotFound)
    }

    pub async fn delete(&self, tenant_id: &str, request_id: &str) -> Result<(), DbError> {
        let result = sqlx::query("DELETE FROM saml_requests WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(request_id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::SamlRequestNotFound);
        }
        Ok(())
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SamlRequestRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            provider_id: row.try_get("provider_id")?,
            relay_state: row.try_get("relay_state")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SamlIdentityMappingRow {
    pub id: String,
    pub tenant_id: String,
    pub provider_id: String,
    pub name_id: String,
    pub identity_public_id: String,
    pub ory_global_id: String,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[derive(Clone)]
pub struct SamlIdentityMappingRepo {
    pool: DbPool,
}

impl SamlIdentityMappingRepo {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        provider_id: &str,
        name_id: &str,
        identity_public_id: &str,
        ory_global_id: &str,
    ) -> Result<SamlIdentityMappingRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, SamlIdentityMappingRow>(
            "INSERT INTO saml_identity_mappings \
             (id, tenant_id, provider_id, name_id, identity_public_id, ory_global_id) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id, tenant_id, provider_id, name_id, identity_public_id, ory_global_id, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(provider_id)
        .bind(name_id)
        .bind(identity_public_id)
        .bind(ory_global_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get_by_name_id(
        &self,
        tenant_id: &str,
        provider_id: &str,
        name_id: &str,
    ) -> Result<SamlIdentityMappingRow, DbError> {
        let row = sqlx::query_as::<_, SamlIdentityMappingRow>(
            "SELECT id, tenant_id, provider_id, name_id, identity_public_id, ory_global_id, created_at, updated_at \
             FROM saml_identity_mappings \
             WHERE tenant_id = $1 AND provider_id = $2 AND name_id = $3",
        )
        .bind(tenant_id)
        .bind(provider_id)
        .bind(name_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlIdentityMappingNotFound)
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SamlIdentityMappingRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            provider_id: row.try_get("provider_id")?,
            name_id: row.try_get("name_id")?,
            identity_public_id: row.try_get("identity_public_id")?,
            ory_global_id: row.try_get("ory_global_id")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ScimGroupRow {
    pub id: String,
    pub tenant_id: String,
    pub display_name: String,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[derive(Clone)]
pub struct ScimGroupRepo {
    pool: DbPool,
}

impl ScimGroupRepo {
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

#[derive(Clone)]
pub struct SamlIdpKeyRepo {
    pool: DbPool,
}

impl SamlIdpKeyRepo {
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

#[derive(Debug, Clone)]
pub struct SamlSpClientRow {
    pub id: String,
    pub tenant_id: String,
    pub entity_id: String,
    pub acs_url: String,
    pub certificate_pem: Option<String>,
    pub authn_requests_signed: bool,
    pub name_id_format: Option<String>,
    pub created_at: time::OffsetDateTime,
    pub updated_at: time::OffsetDateTime,
}

#[derive(Clone)]
pub struct SamlSpClientRepo {
    pool: DbPool,
}

impl SamlSpClientRepo {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: &str,
        entity_id: &str,
        acs_url: &str,
        certificate_pem: Option<&str>,
        authn_requests_signed: bool,
        name_id_format: Option<&str>,
    ) -> Result<SamlSpClientRow, DbError> {
        let id = Ulid::new().to_string();
        let row = sqlx::query_as::<_, SamlSpClientRow>(
            "INSERT INTO saml_sp_clients \
             (id, tenant_id, entity_id, acs_url, certificate_pem, authn_requests_signed, name_id_format) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id, tenant_id, entity_id, acs_url, certificate_pem, authn_requests_signed, name_id_format, created_at, updated_at",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(entity_id)
        .bind(acs_url)
        .bind(certificate_pem)
        .bind(authn_requests_signed)
        .bind(name_id_format)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    pub async fn get(&self, tenant_id: &str, id: &str) -> Result<SamlSpClientRow, DbError> {
        let row = sqlx::query_as::<_, SamlSpClientRow>(
            "SELECT id, tenant_id, entity_id, acs_url, certificate_pem, authn_requests_signed, name_id_format, created_at, updated_at \
             FROM saml_sp_clients \
             WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlSpClientNotFound)
    }

    pub async fn get_by_id(&self, id: &str) -> Result<SamlSpClientRow, DbError> {
        let row = sqlx::query_as::<_, SamlSpClientRow>(
            "SELECT id, tenant_id, entity_id, acs_url, certificate_pem, authn_requests_signed, name_id_format, created_at, updated_at \
             FROM saml_sp_clients \
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlSpClientNotFound)
    }

    pub async fn get_by_entity_id(
        &self,
        tenant_id: &str,
        entity_id: &str,
    ) -> Result<SamlSpClientRow, DbError> {
        let row = sqlx::query_as::<_, SamlSpClientRow>(
            "SELECT id, tenant_id, entity_id, acs_url, certificate_pem, authn_requests_signed, name_id_format, created_at, updated_at \
             FROM saml_sp_clients \
             WHERE tenant_id = $1 AND entity_id = $2",
        )
        .bind(tenant_id)
        .bind(entity_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(DbError::SamlSpClientNotFound)
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for SamlSpClientRow {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            entity_id: row.try_get("entity_id")?,
            acs_url: row.try_get("acs_url")?,
            certificate_pem: row.try_get("certificate_pem")?,
            authn_requests_signed: row.try_get("authn_requests_signed")?,
            name_id_format: row.try_get("name_id_format")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

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

#[derive(Clone)]
pub struct AuditLogRepo {
    pool: DbPool,
}

impl AuditLogRepo {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn insert(
        &self,
        tenant_id: Option<&str>,
        actor: Option<&str>,
        action: &str,
        resource: &str,
        outcome: &str,
        metadata: serde_json::Value,
    ) -> Result<(), DbError> {
        let id = Ulid::new().to_string();
        sqlx::query(
            "INSERT INTO audit_log \
             (id, tenant_id, actor, action, resource, outcome, metadata) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(actor)
        .bind(action)
        .bind(resource)
        .bind(outcome)
        .bind(sqlx::types::Json(metadata))
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sunbeam_g2v::error::ServiceError;

    #[test]
    fn db_error_into_service_error_maps_all_variants() {
        let cases: Vec<(DbError, ServiceError)> = vec![
            (
                DbError::Sqlx(sqlx::Error::PoolTimedOut),
                ServiceError::Database("sqlx error: PoolTimedOut".into()),
            ),
            (
                DbError::MissingSystemTenant,
                ServiceError::Internal("missing system tenant".into()),
            ),
            (
                DbError::TenantNotFound,
                ServiceError::NotFound("tenant not found".into()),
            ),
            (
                DbError::MappingNotFound,
                ServiceError::NotFound("id mapping not found".into()),
            ),
            (
                DbError::SchemaNotFound,
                ServiceError::NotFound("identity schema not found".into()),
            ),
            (
                DbError::TupleNotFound,
                ServiceError::NotFound("permission tuple not found".into()),
            ),
            (
                DbError::SamlProviderNotFound,
                ServiceError::NotFound("saml provider not found".into()),
            ),
            (
                DbError::SamlRequestNotFound,
                ServiceError::NotFound("saml request not found".into()),
            ),
            (
                DbError::SamlIdentityMappingNotFound,
                ServiceError::NotFound("saml identity mapping not found".into()),
            ),
            (
                DbError::SamlIdpKeyNotFound,
                ServiceError::NotFound("saml idp key not found".into()),
            ),
            (
                DbError::SamlSpClientNotFound,
                ServiceError::NotFound("saml service provider client not found".into()),
            ),
            (
                DbError::ApiKeyNotFound,
                ServiceError::Unauthenticated("api key not found or expired".into()),
            ),
        ];
        for (err, expected) in cases {
            let actual: ServiceError = err.into();
            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
        }
    }

    #[test]
    fn db_error_into_connect_error_round_trips() {
        let err = DbError::TenantNotFound;
        let connect_err: ConnectError = err.into();
        assert_eq!(connect_err.code, connectrpc::ErrorCode::NotFound);
    }

    #[test]
    fn tenant_api_key_row_from_row_requires_all_columns() {
        // Sanity check that FromRow is derived through the full impl block above.
        // The trait impl is exercised by repository tests; this just ensures the
        // struct definition and FromRow impl compile together.
        let _size = std::mem::size_of::<TenantApiKeyRow>();
    }

    #[test]
    fn identity_schema_row_from_row_compiles() {
        let _size = std::mem::size_of::<IdentitySchemaRow>();
    }
}
