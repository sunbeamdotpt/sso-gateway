//! Identity provisioning for upstream federation.
//!
//! `IdentityProvisioner` maps upstream identity claims (email, name, etc.)
//! into gateway public identities backed by Ory Kratos. It creates Kratos
//! identities when none exist and maintains the gateway `id_mappings` table.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use sso_ory_client::{error::OryClientError, kratos::KratosClient};
use sunbeam_g2v::error::ServiceError;
use tracing::{debug, instrument};
use ulid::Ulid;

use crate::db::{
    DbError, IdMappingStore, IdentitySchemaRow, IdentitySchemaStore, SamlIdentityMappingStore,
    TenantMembershipStore,
};
use crate::services::identity::{extract_email, normalize_traits, validate_traits};

const BACKEND_KRATOS: &str = "kratos";

/// Result of provisioning an identity.
#[derive(Debug, Clone)]
pub struct ProvisionedIdentity {
    pub tenant_id: String,
    pub public_id: String,
    pub ory_id: String,
    pub email: String,
}

/// Errors that can occur during identity provisioning.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("missing email claim")]
    MissingEmail,

    #[error("email is not verified")]
    EmailNotVerified,

    #[error("identity schema not configured")]
    MissingSchema,

    #[error("kratos error: {0}")]
    Kratos(#[from] OryClientError),

    #[error("database error: {0}")]
    Database(#[from] DbError),

    #[error("invalid upstream response: {0}")]
    InvalidResponse(String),
}

impl From<ProvisionError> for ServiceError {
    fn from(err: ProvisionError) -> Self {
        match err {
            ProvisionError::MissingEmail => Self::InvalidArgument("missing email claim".into()),
            ProvisionError::EmailNotVerified => {
                Self::InvalidArgument("email is not verified".into())
            }
            ProvisionError::MissingSchema => Self::Configuration("missing identity schema".into()),
            ProvisionError::Kratos(e) => map_ory_error(e),
            ProvisionError::Database(e) => e.into(),
            ProvisionError::InvalidResponse(msg) => Self::Internal(msg),
        }
    }
}

/// Normalize the upstream `name` claim into the object shape expected by the
/// default Kratos identity schema.
///
/// OIDC/OAuth2 userinfo usually returns `name` as a single string; Kratos
/// expects an object. A string is split on the first space into `first`/`last`,
/// and non-object values fall back to an empty object.
fn normalize_name_claim(name: Option<&serde_json::Value>) -> serde_json::Value {
    if let Some(value) = name {
        if let Some(obj) = value.as_object() {
            return serde_json::Value::Object(obj.clone());
        }
        if let Some(s) = value.as_str() {
            let trimmed = s.trim();
            if let Some((first, rest)) = trimmed.split_once(' ') {
                return json!({
                    "first": first.trim(),
                    "last": rest.trim(),
                });
            }
            return json!({"first": trimmed});
        }
    }
    json!({})
}

fn map_ory_error(err: OryClientError) -> ServiceError {
    match err {
        OryClientError::Ory { status, message } => match status {
            400 => ServiceError::InvalidArgument(message),
            401 => ServiceError::Unauthenticated(message),
            403 => ServiceError::PermissionDenied(message),
            404 => ServiceError::NotFound(message),
            409 => ServiceError::AlreadyExists(message),
            503 => ServiceError::Unavailable(message),
            _ => ServiceError::Internal(message),
        },
        OryClientError::Http(e) => ServiceError::Unavailable(e.to_string()),
        OryClientError::Serialization(e) => ServiceError::Serialization(e.to_string()),
        OryClientError::Url(e) => ServiceError::Configuration(e.to_string()),
        OryClientError::InvalidResponse(msg) => ServiceError::Internal(msg),
        OryClientError::MissingTenant => {
            ServiceError::Unauthenticated("missing tenant context".into())
        }
        OryClientError::Redirect { .. } => ServiceError::Internal("unexpected redirect".into()),
    }
}

/// Kratos operations needed by the provisioner.
#[async_trait]
pub trait ProvisionerKratos: Send + Sync + 'static {
    async fn list_identities_by_identifier(
        &self,
        tenant_id: &str,
        identifier: &str,
    ) -> Result<serde_json::Value, OryClientError>;

    async fn create_identity(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError>;
}

#[async_trait]
impl ProvisionerKratos for KratosClient {
    async fn list_identities_by_identifier(
        &self,
        tenant_id: &str,
        identifier: &str,
    ) -> Result<serde_json::Value, OryClientError> {
        self.list_identities_by_identifier(tenant_id, identifier)
            .await
    }

    async fn create_identity(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.create_identity(payload).await
    }
}

/// Provision identities from upstream claims.
#[async_trait]
pub trait IdentityProvisioner: Send + Sync + 'static {
    async fn provision(
        &self,
        tenant_id: &str,
        schema_id: &str,
        claims: &serde_json::Value,
    ) -> Result<ProvisionedIdentity, ProvisionError>;

    /// Provision (or link) an identity from a SAML assertion.
    ///
    /// Prefer the per-provider `saml_identity_mappings` table over a global
    /// email lookup. Email-based linking is only allowed when `email_verified`
    /// is true or the provider is explicitly trusted.
    #[allow(clippy::too_many_arguments)]
    async fn provision_saml(
        &self,
        tenant_id: &str,
        provider_id: &str,
        schema_id: &str,
        name_id: &str,
        email: &str,
        email_verified: bool,
        trusted_provider: bool,
    ) -> Result<ProvisionedIdentity, ProvisionError>;
}

/// Kratos-backed identity provisioner.
pub struct KratosIdentityProvisioner {
    kratos: Arc<dyn ProvisionerKratos>,
    mappings: Arc<dyn IdMappingStore>,
    schemas: Arc<dyn IdentitySchemaStore>,
    memberships: Arc<dyn TenantMembershipStore>,
    saml_mappings: Option<Arc<dyn SamlIdentityMappingStore>>,
    kratos_default_schema_id: String,
}

impl KratosIdentityProvisioner {
    pub fn new(
        kratos: Arc<KratosClient>,
        mappings: Arc<dyn IdMappingStore>,
        schemas: Arc<dyn IdentitySchemaStore>,
        memberships: crate::db::TenantMembershipRepo,
        kratos_default_schema_id: String,
    ) -> Self {
        Self {
            kratos: kratos as Arc<dyn ProvisionerKratos>,
            mappings,
            schemas,
            memberships: Arc::new(memberships) as Arc<dyn TenantMembershipStore>,
            saml_mappings: None,
            kratos_default_schema_id,
        }
    }

    pub fn with_saml_mappings(mut self, mappings: Arc<dyn SamlIdentityMappingStore>) -> Self {
        self.saml_mappings = Some(mappings);
        self
    }

    fn require_email_verified(claims: &serde_json::Value) -> Result<(), ProvisionError> {
        let email_verified = matches!(
            claims.get("email_verified").and_then(|v| v.as_bool()),
            Some(true)
        );
        let trusted_provider = matches!(
            claims.get("trusted_provider").and_then(|v| v.as_bool()),
            Some(true)
        );
        if !email_verified && !trusted_provider {
            return Err(ProvisionError::EmailNotVerified);
        }
        Ok(())
    }

    async fn find_or_create_by_email(
        &self,
        tenant_id: &str,
        schema: &IdentitySchemaRow,
        traits: serde_json::Value,
    ) -> Result<ProvisionedIdentity, ProvisionError> {
        let email =
            extract_email(&traits).map_err(|e| ProvisionError::InvalidResponse(e.to_string()))?;
        let scoped_identifier = format!("{tenant_id}:{email}");
        let existing = self
            .kratos
            .list_identities_by_identifier(tenant_id, &scoped_identifier)
            .await
            .map_err(ProvisionError::Kratos)?;

        let (ory_id, public_id) =
            if let Some(identity) = existing.as_array().and_then(|arr| arr.first()).cloned() {
                let ory_id = identity["id"]
                    .as_str()
                    .ok_or_else(|| ProvisionError::InvalidResponse("identity missing id".into()))?
                    .to_string();
                debug!(%ory_id, "found existing kratos identity");

                let public_id = match self
                    .mappings
                    .get_public_id(tenant_id, BACKEND_KRATOS, &ory_id)
                    .await
                {
                    Ok(id) => id,
                    Err(DbError::MappingNotFound) => {
                        let public_id = Ulid::new().to_string();
                        self.mappings
                            .create(tenant_id, BACKEND_KRATOS, &public_id, &ory_id)
                            .await?;
                        public_id
                    }
                    Err(e) => return Err(e.into()),
                };
                (ory_id, public_id)
            } else {
                // Kratos stores only the base identity ({email}); the gateway owns the
                // full trait document via the membership upserted below.
                let payload = json!({
                    "schema_id": self.kratos_default_schema_id,
                    "traits": { "email": &email },
                });
                let created = self
                    .kratos
                    .create_identity(payload)
                    .await
                    .map_err(ProvisionError::Kratos)?;
                let ory_id = created["id"]
                    .as_str()
                    .ok_or_else(|| {
                        ProvisionError::InvalidResponse("created identity missing id".into())
                    })?
                    .to_string();
                let new_public_id = Ulid::new().to_string();
                let mapping = self
                    .mappings
                    .create(tenant_id, BACKEND_KRATOS, &new_public_id, &ory_id)
                    .await?;
                let public_id = mapping.public_id;
                debug!(%ory_id, %public_id, "created kratos identity");
                (ory_id, public_id)
            };

        self.ensure_membership(tenant_id, &public_id, schema, &traits)
            .await?;

        Ok(ProvisionedIdentity {
            tenant_id: tenant_id.to_string(),
            public_id,
            ory_id,
            email,
        })
    }

    /// Seed a membership on first sight so reads become gateway-authoritative, without
    /// clobbering richer traits an earlier admin/SCIM/SAML-JIT write may have stored.
    async fn ensure_membership(
        &self,
        tenant_id: &str,
        public_id: &str,
        schema: &IdentitySchemaRow,
        traits: &serde_json::Value,
    ) -> Result<(), ProvisionError> {
        match self.memberships.get(tenant_id, public_id).await {
            Ok(_) => Ok(()),
            Err(DbError::MembershipNotFound) => {
                self.memberships
                    .upsert(
                        tenant_id,
                        public_id,
                        &schema.schema_id,
                        schema.version,
                        traits.clone(),
                    )
                    .await?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

#[async_trait]
impl IdentityProvisioner for KratosIdentityProvisioner {
    #[instrument(skip(self, claims), fields(tenant_id = %tenant_id, schema_id = %schema_id))]
    async fn provision(
        &self,
        tenant_id: &str,
        schema_id: &str,
        claims: &serde_json::Value,
    ) -> Result<ProvisionedIdentity, ProvisionError> {
        let email = claims["email"]
            .as_str()
            .ok_or(ProvisionError::MissingEmail)?;

        let schema = self
            .schemas
            .get_by_schema_id(tenant_id, schema_id)
            .await
            .map_err(|_| ProvisionError::MissingSchema)?;

        Self::require_email_verified(claims)?;

        let mut traits = json!({
            "email": email,
            "name": normalize_name_claim(claims.get("name")),
        });
        normalize_traits(&mut traits);
        validate_traits(&schema.schema_json, &traits)
            .map_err(|e| ProvisionError::InvalidResponse(e.to_string()))?;

        self.find_or_create_by_email(tenant_id, &schema, traits)
            .await
    }

    #[instrument(skip(self), fields(tenant_id = %tenant_id, provider_id = %provider_id, schema_id = %schema_id))]
    async fn provision_saml(
        &self,
        tenant_id: &str,
        provider_id: &str,
        schema_id: &str,
        name_id: &str,
        email: &str,
        email_verified: bool,
        trusted_provider: bool,
    ) -> Result<ProvisionedIdentity, ProvisionError> {
        let schema = self
            .schemas
            .get_by_schema_id(tenant_id, schema_id)
            .await
            .map_err(|_| ProvisionError::MissingSchema)?;

        // Prefer per-provider SAML identity mappings over global email lookup.
        if let Some(saml_mappings) = self.saml_mappings.as_ref() {
            match saml_mappings
                .get_by_name_id(tenant_id, provider_id, name_id)
                .await
            {
                Ok(mapping) => {
                    return Ok(ProvisionedIdentity {
                        tenant_id: tenant_id.to_string(),
                        public_id: mapping.identity_public_id,
                        ory_id: mapping.ory_global_id,
                        email: email.to_string(),
                    });
                }
                Err(DbError::SamlIdentityMappingNotFound) => {}
                Err(e) => return Err(e.into()),
            }
        }

        if !email_verified && !trusted_provider {
            return Err(ProvisionError::EmailNotVerified);
        }

        let mut traits = json!({
            "email": email,
            "name": normalize_name_claim(Some(&json!(name_id))),
        });
        normalize_traits(&mut traits);
        validate_traits(&schema.schema_json, &traits)
            .map_err(|e| ProvisionError::InvalidResponse(e.to_string()))?;

        let identity = self
            .find_or_create_by_email(tenant_id, &schema, traits)
            .await?;

        // Record the provider-specific mapping for future logins.
        if let Some(saml_mappings) = self.saml_mappings.as_ref()
            && let Err(e) = saml_mappings
                .create(
                    tenant_id,
                    provider_id,
                    name_id,
                    &identity.public_id,
                    &identity.ory_id,
                )
                .await
        {
            // A duplicate mapping is fine; ignore mapping races.
            if !matches!(e, DbError::Sqlx(_)) {
                return Err(e.into());
            }
        }

        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::json;
    use sso_ory_client::error::OryClientError;

    use super::*;
    use crate::db::{IdMappingRow, IdentitySchemaRow, SamlIdentityMappingRow, TenantMembershipRow};

    #[derive(Clone, Default)]
    struct StubKratos {
        list_result: Arc<Mutex<Option<Result<serde_json::Value, OryClientError>>>>,
        create_result: Arc<Mutex<Option<Result<serde_json::Value, OryClientError>>>>,
    }

    #[async_trait]
    impl ProvisionerKratos for StubKratos {
        async fn list_identities_by_identifier(
            &self,
            _tenant_id: &str,
            _identifier: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            self.list_result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }

        async fn create_identity(
            &self,
            _payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            self.create_result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }
    }

    #[derive(Clone, Default)]
    struct StubMappingStore {
        get_public_id_result: Arc<Mutex<Option<Result<String, DbError>>>>,
        create_result: Arc<Mutex<Option<Result<IdMappingRow, DbError>>>>,
    }

    #[async_trait]
    impl IdMappingStore for StubMappingStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
            _ory_global_id: &str,
        ) -> Result<IdMappingRow, DbError> {
            self.create_result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }

        async fn get_ory_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<String, DbError> {
            unimplemented!()
        }

        async fn get_public_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, DbError> {
            self.get_public_id_result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }

        async fn delete(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn list_public_ids(
            &self,
            _tenant_id: &str,
            _backend: &str,
        ) -> Result<Vec<String>, DbError> {
            unimplemented!()
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, DbError> {
            unimplemented!()
        }
    }

    #[derive(Clone, Default)]
    struct StubSchemaStore {
        get_by_schema_id_result: Arc<Mutex<Option<Result<IdentitySchemaRow, DbError>>>>,
    }

    #[async_trait]
    impl IdentitySchemaStore for StubSchemaStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
            _schema_json: serde_json::Value,
            _is_default: bool,
        ) -> Result<IdentitySchemaRow, DbError> {
            unimplemented!()
        }

        async fn get_by_schema_id(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
        ) -> Result<IdentitySchemaRow, DbError> {
            self.get_by_schema_id_result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }

        async fn list(&self, _tenant_id: &str) -> Result<Vec<IdentitySchemaRow>, DbError> {
            unimplemented!()
        }

        async fn delete(&self, _tenant_id: &str, _schema_id: &str) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn update(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
            _schema_json: serde_json::Value,
            _is_default: bool,
        ) -> Result<IdentitySchemaRow, DbError> {
            unimplemented!()
        }

        async fn set_default(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
        ) -> Result<IdentitySchemaRow, DbError> {
            unimplemented!()
        }

        async fn get_default(&self, _tenant_id: &str) -> Result<IdentitySchemaRow, DbError> {
            unimplemented!()
        }
    }

    #[derive(Clone, Default)]
    struct StubSamlMappingStore {
        get_by_name_id_result: Arc<Mutex<Option<Result<SamlIdentityMappingRow, DbError>>>>,
        create_result: Arc<Mutex<Option<Result<SamlIdentityMappingRow, DbError>>>>,
    }

    #[async_trait]
    impl SamlIdentityMappingStore for StubSamlMappingStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _provider_id: &str,
            _name_id: &str,
            _identity_public_id: &str,
            _ory_global_id: &str,
        ) -> Result<SamlIdentityMappingRow, DbError> {
            self.create_result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }

        async fn get_by_name_id(
            &self,
            _tenant_id: &str,
            _provider_id: &str,
            _name_id: &str,
        ) -> Result<SamlIdentityMappingRow, DbError> {
            self.get_by_name_id_result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
        }
    }

    #[derive(Clone, Default)]
    struct StubMembershipStore {
        get_result: Arc<Mutex<Option<Result<TenantMembershipRow, DbError>>>>,
        upsert_calls: Arc<Mutex<Vec<UpsertCall>>>,
    }

    type UpsertCall = (String, String, String, i64, serde_json::Value);

    #[async_trait]
    impl TenantMembershipStore for StubMembershipStore {
        async fn upsert(
            &self,
            tenant_id: &str,
            identity_id: &str,
            schema_id: &str,
            schema_version: i64,
            traits: serde_json::Value,
        ) -> Result<TenantMembershipRow, DbError> {
            self.upsert_calls.lock().unwrap().push((
                tenant_id.to_string(),
                identity_id.to_string(),
                schema_id.to_string(),
                schema_version,
                traits.clone(),
            ));
            let now = time::OffsetDateTime::now_utc();
            Ok(TenantMembershipRow {
                tenant_id: tenant_id.to_string(),
                identity_id: identity_id.to_string(),
                schema_id: schema_id.to_string(),
                schema_version,
                traits,
                state: "active".into(),
                created_at: now,
                updated_at: now,
            })
        }

        async fn get(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
        ) -> Result<TenantMembershipRow, DbError> {
            self.get_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Err(DbError::MembershipNotFound))
        }

        async fn set_state(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _state: &str,
        ) -> Result<TenantMembershipRow, DbError> {
            unimplemented!()
        }

        async fn list_by_tenant(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<TenantMembershipRow>, DbError> {
            unimplemented!()
        }
    }

    fn provisioner(
        kratos: Arc<dyn ProvisionerKratos>,
        mappings: Arc<dyn IdMappingStore>,
        schemas: Arc<dyn IdentitySchemaStore>,
    ) -> KratosIdentityProvisioner {
        KratosIdentityProvisioner {
            kratos,
            mappings,
            schemas,
            memberships: Arc::new(StubMembershipStore::default()),
            saml_mappings: None,
            kratos_default_schema_id: "default".into(),
        }
    }

    fn provisioner_with_saml(
        kratos: Arc<dyn ProvisionerKratos>,
        mappings: Arc<dyn IdMappingStore>,
        schemas: Arc<dyn IdentitySchemaStore>,
        saml_mappings: Arc<dyn SamlIdentityMappingStore>,
    ) -> KratosIdentityProvisioner {
        KratosIdentityProvisioner {
            kratos,
            mappings,
            schemas,
            memberships: Arc::new(StubMembershipStore::default()),
            saml_mappings: Some(saml_mappings),
            kratos_default_schema_id: "default".into(),
        }
    }

    fn provisioner_with_memberships(
        kratos: Arc<dyn ProvisionerKratos>,
        mappings: Arc<dyn IdMappingStore>,
        schemas: Arc<dyn IdentitySchemaStore>,
        memberships: Arc<StubMembershipStore>,
    ) -> KratosIdentityProvisioner {
        KratosIdentityProvisioner {
            kratos,
            mappings,
            schemas,
            memberships,
            saml_mappings: None,
            kratos_default_schema_id: "default".into(),
        }
    }

    #[tokio::test]
    async fn provision_creates_identity_when_none_exists() {
        let kratos = Arc::new(StubKratos {
            list_result: Arc::new(Mutex::new(Some(Ok(json!([]))))),
            create_result: Arc::new(Mutex::new(Some(Ok(json!({"id": "ory-1"}))))),
        });
        let mappings = Arc::new(StubMappingStore {
            get_public_id_result: Arc::new(Mutex::new(None)),
            create_result: Arc::new(Mutex::new(Some(Ok(IdMappingRow {
                id: "id-1".into(),
                tenant_id: "tenant-1".into(),
                backend: BACKEND_KRATOS.into(),
                public_id: "public-1".into(),
                ory_global_id: "ory-1".into(),
                created_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let schemas = Arc::new(StubSchemaStore {
            get_by_schema_id_result: Arc::new(Mutex::new(Some(Ok(IdentitySchemaRow {
                id: "schema-1".into(),
                tenant_id: "tenant-1".into(),
                schema_id: "default".into(),
                schema_json: json!({}),
                version: 1,
                is_default: true,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let p = provisioner(kratos, mappings, schemas);
        let result = p
            .provision(
                "tenant-1",
                "default",
                &json!({"email": "alice@example.com", "email_verified": true}),
            )
            .await
            .unwrap();
        assert_eq!(result.email, "alice@example.com");
        assert_eq!(result.ory_id, "ory-1");
        assert_eq!(result.public_id, "public-1");
    }

    #[tokio::test]
    async fn provision_reuses_existing_identity() {
        let kratos = Arc::new(StubKratos {
            list_result: Arc::new(Mutex::new(Some(Ok(json!([{"id": "ory-2"}]))))),
            create_result: Arc::new(Mutex::new(None)),
        });
        let mappings = Arc::new(StubMappingStore {
            get_public_id_result: Arc::new(Mutex::new(Some(Ok("public-2".into())))),
            create_result: Arc::new(Mutex::new(None)),
        });
        let schemas = Arc::new(StubSchemaStore {
            get_by_schema_id_result: Arc::new(Mutex::new(Some(Ok(IdentitySchemaRow {
                id: "schema-1".into(),
                tenant_id: "tenant-1".into(),
                schema_id: "default".into(),
                schema_json: json!({}),
                version: 1,
                is_default: true,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let p = provisioner(kratos, mappings, schemas);
        let result = p
            .provision(
                "tenant-1",
                "default",
                &json!({"email": "bob@example.com", "email_verified": true}),
            )
            .await
            .unwrap();
        assert_eq!(result.ory_id, "ory-2");
        assert_eq!(result.public_id, "public-2");
    }

    #[tokio::test]
    async fn provision_isolates_identities_by_tenant() {
        #[derive(Clone)]
        struct TenantAwareStubKratos {
            expected_tenant_id: String,
            expected_identifier: String,
            existing_identity_id: String,
        }

        #[async_trait]
        impl ProvisionerKratos for TenantAwareStubKratos {
            async fn list_identities_by_identifier(
                &self,
                tenant_id: &str,
                identifier: &str,
            ) -> Result<serde_json::Value, OryClientError> {
                if tenant_id == self.expected_tenant_id && identifier == self.expected_identifier {
                    Ok(json!([{ "id": self.existing_identity_id }]))
                } else {
                    Ok(json!([]))
                }
            }

            async fn create_identity(
                &self,
                payload: serde_json::Value,
            ) -> Result<serde_json::Value, OryClientError> {
                let email = payload["traits"]["email"].as_str().unwrap_or("unknown");
                Ok(json!({ "id": format!("ory-created-{email}") }))
            }
        }

        let kratos = Arc::new(TenantAwareStubKratos {
            expected_tenant_id: "tenant-a".into(),
            expected_identifier: "tenant-a:alice@example.com".into(),
            existing_identity_id: "ory-a".into(),
        });
        let mappings = Arc::new(StubMappingStore {
            get_public_id_result: Arc::new(Mutex::new(Some(Ok("public-a".into())))),
            create_result: Arc::new(Mutex::new(Some(Ok(IdMappingRow {
                id: "id-b".into(),
                tenant_id: "tenant-b".into(),
                backend: BACKEND_KRATOS.into(),
                public_id: "public-b".into(),
                ory_global_id: "ory-created-alice@example.com".into(),
                created_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        #[derive(Clone)]
        struct AlwaysSchemaStore;

        #[async_trait]
        impl IdentitySchemaStore for AlwaysSchemaStore {
            async fn create(
                &self,
                _tenant_id: &str,
                _schema_id: &str,
                _schema_json: serde_json::Value,
                _is_default: bool,
            ) -> Result<IdentitySchemaRow, DbError> {
                unimplemented!()
            }

            async fn get_by_schema_id(
                &self,
                _tenant_id: &str,
                _schema_id: &str,
            ) -> Result<IdentitySchemaRow, DbError> {
                Ok(IdentitySchemaRow {
                    id: "schema-1".into(),
                    tenant_id: "tenant-a".into(),
                    schema_id: "default".into(),
                    schema_json: json!({}),
                    version: 1,
                    is_default: true,
                    created_at: time::OffsetDateTime::now_utc(),
                    updated_at: time::OffsetDateTime::now_utc(),
                })
            }

            async fn list(&self, _tenant_id: &str) -> Result<Vec<IdentitySchemaRow>, DbError> {
                unimplemented!()
            }

            async fn delete(&self, _tenant_id: &str, _schema_id: &str) -> Result<(), DbError> {
                unimplemented!()
            }

            async fn update(
                &self,
                _tenant_id: &str,
                _schema_id: &str,
                _schema_json: serde_json::Value,
                _is_default: bool,
            ) -> Result<IdentitySchemaRow, DbError> {
                unimplemented!()
            }

            async fn set_default(
                &self,
                _tenant_id: &str,
                _schema_id: &str,
            ) -> Result<IdentitySchemaRow, DbError> {
                unimplemented!()
            }

            async fn get_default(&self, _tenant_id: &str) -> Result<IdentitySchemaRow, DbError> {
                unimplemented!()
            }
        }

        let schemas = Arc::new(AlwaysSchemaStore);
        let p = provisioner(kratos, mappings, schemas);

        let a = p
            .provision(
                "tenant-a",
                "default",
                &json!({"email": "alice@example.com", "email_verified": true}),
            )
            .await
            .unwrap();
        assert_eq!(a.ory_id, "ory-a");
        assert_eq!(a.public_id, "public-a");

        let b = p
            .provision(
                "tenant-b",
                "default",
                &json!({"email": "alice@example.com", "email_verified": true}),
            )
            .await
            .unwrap();
        assert_eq!(b.ory_id, "ory-created-alice@example.com");
        assert_eq!(b.public_id, "public-b");
        assert_ne!(a.public_id, b.public_id);
    }

    #[tokio::test]
    async fn provision_missing_email_fails() {
        let kratos = Arc::new(StubKratos::default());
        let mappings = Arc::new(StubMappingStore::default());
        let schemas = Arc::new(StubSchemaStore {
            get_by_schema_id_result: Arc::new(Mutex::new(Some(Ok(IdentitySchemaRow {
                id: "schema-1".into(),
                tenant_id: "tenant-1".into(),
                schema_id: "default".into(),
                schema_json: json!({}),
                version: 1,
                is_default: true,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let p = provisioner(kratos, mappings, schemas);
        let err = p
            .provision("tenant-1", "default", &json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::MissingEmail));
    }

    #[tokio::test]
    async fn provision_rejects_unverified_email() {
        let kratos = Arc::new(StubKratos::default());
        let mappings = Arc::new(StubMappingStore::default());
        let schemas = Arc::new(StubSchemaStore {
            get_by_schema_id_result: Arc::new(Mutex::new(Some(Ok(IdentitySchemaRow {
                id: "schema-1".into(),
                tenant_id: "tenant-1".into(),
                schema_id: "default".into(),
                schema_json: json!({}),
                version: 1,
                is_default: true,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let p = provisioner(kratos, mappings, schemas);
        let err = p
            .provision(
                "tenant-1",
                "default",
                &json!({"email": "alice@example.com"}),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::EmailNotVerified));
    }

    #[tokio::test]
    async fn provision_accepts_trusted_provider() {
        let kratos = Arc::new(StubKratos {
            list_result: Arc::new(Mutex::new(Some(Ok(json!([]))))),
            create_result: Arc::new(Mutex::new(Some(Ok(json!({"id": "ory-3"}))))),
        });
        let mappings = Arc::new(StubMappingStore {
            get_public_id_result: Arc::new(Mutex::new(None)),
            create_result: Arc::new(Mutex::new(Some(Ok(IdMappingRow {
                id: "id-3".into(),
                tenant_id: "tenant-1".into(),
                backend: BACKEND_KRATOS.into(),
                public_id: "public-3".into(),
                ory_global_id: "ory-3".into(),
                created_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let schemas = Arc::new(StubSchemaStore {
            get_by_schema_id_result: Arc::new(Mutex::new(Some(Ok(IdentitySchemaRow {
                id: "schema-1".into(),
                tenant_id: "tenant-1".into(),
                schema_id: "default".into(),
                schema_json: json!({}),
                version: 1,
                is_default: true,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let p = provisioner(kratos, mappings, schemas);
        let result = p
            .provision(
                "tenant-1",
                "default",
                &json!({"email": "alice@example.com", "trusted_provider": true}),
            )
            .await
            .unwrap();
        assert_eq!(result.ory_id, "ory-3");
    }

    #[tokio::test]
    async fn provision_writes_base_only_to_kratos_and_full_traits_to_membership() {
        #[derive(Clone, Default)]
        struct CapturingKratos {
            create_payload: Arc<Mutex<Option<serde_json::Value>>>,
        }

        #[async_trait]
        impl ProvisionerKratos for CapturingKratos {
            async fn list_identities_by_identifier(
                &self,
                _tenant_id: &str,
                _identifier: &str,
            ) -> Result<serde_json::Value, OryClientError> {
                Ok(json!([]))
            }

            async fn create_identity(
                &self,
                payload: serde_json::Value,
            ) -> Result<serde_json::Value, OryClientError> {
                *self.create_payload.lock().unwrap() = Some(payload);
                Ok(json!({"id": "ory-new"}))
            }
        }

        let create_payload: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        let kratos = Arc::new(CapturingKratos {
            create_payload: create_payload.clone(),
        });
        let mappings = Arc::new(StubMappingStore {
            get_public_id_result: Arc::new(Mutex::new(None)),
            create_result: Arc::new(Mutex::new(Some(Ok(IdMappingRow {
                id: "id-1".into(),
                tenant_id: "tenant-1".into(),
                backend: BACKEND_KRATOS.into(),
                public_id: "public-1".into(),
                ory_global_id: "ory-new".into(),
                created_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let schemas = Arc::new(StubSchemaStore {
            get_by_schema_id_result: Arc::new(Mutex::new(Some(Ok(IdentitySchemaRow {
                id: "schema-1".into(),
                tenant_id: "tenant-1".into(),
                schema_id: "employee".into(),
                schema_json: json!({
                    "type": "object",
                    "properties": {
                        "email": { "type": "string" },
                        "name": { "type": "object" }
                    }
                }),
                version: 7,
                is_default: true,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let memberships = Arc::new(StubMembershipStore::default());
        let p = provisioner_with_memberships(kratos, mappings, schemas, memberships.clone());
        let result = p
            .provision(
                "tenant-1",
                "employee",
                &json!({"email": "Alice@Example.com", "email_verified": true, "name": "Alice Smith"}),
            )
            .await
            .unwrap();
        // Email is normalized before it reaches either store.
        assert_eq!(result.email, "alice@example.com");

        // Kratos only ever sees the base identity under the Kratos default schema id.
        let payload = create_payload.lock().unwrap().clone().unwrap();
        assert_eq!(payload["schema_id"], "default");
        assert_eq!(payload["traits"], json!({"email": "alice@example.com"}));

        // The membership holds the gateway schema binding and the full trait document.
        let calls = memberships.upsert_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "tenant-1");
        assert_eq!(calls[0].1, "public-1");
        assert_eq!(calls[0].2, "employee");
        assert_eq!(calls[0].3, 7);
        assert_eq!(calls[0].4["email"], "alice@example.com");
        assert_eq!(
            calls[0].4["name"],
            json!({"first": "Alice", "last": "Smith"})
        );
    }

    #[tokio::test]
    async fn provision_saml_prefers_mapping_over_email() {
        let kratos = Arc::new(StubKratos::default());
        let mappings = Arc::new(StubMappingStore::default());
        let schemas = Arc::new(StubSchemaStore {
            get_by_schema_id_result: Arc::new(Mutex::new(Some(Ok(IdentitySchemaRow {
                id: "schema-1".into(),
                tenant_id: "tenant-1".into(),
                schema_id: "default".into(),
                schema_json: json!({}),
                version: 1,
                is_default: true,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let saml_mappings = Arc::new(StubSamlMappingStore {
            get_by_name_id_result: Arc::new(Mutex::new(Some(Ok(SamlIdentityMappingRow {
                id: "m-1".into(),
                tenant_id: "tenant-1".into(),
                provider_id: "provider-1".into(),
                name_id: "nameid-1".into(),
                identity_public_id: "public-saml".into(),
                ory_global_id: "ory-saml".into(),
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })))),
            create_result: Arc::new(Mutex::new(None)),
        });
        let p = provisioner_with_saml(kratos, mappings, schemas, saml_mappings);
        let result = p
            .provision_saml(
                "tenant-1",
                "provider-1",
                "default",
                "nameid-1",
                "alice@example.com",
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!(result.public_id, "public-saml");
        assert_eq!(result.ory_id, "ory-saml");
    }

    #[tokio::test]
    async fn provision_saml_rejects_unverified_email_without_mapping() {
        let kratos = Arc::new(StubKratos::default());
        let mappings = Arc::new(StubMappingStore::default());
        let schemas = Arc::new(StubSchemaStore {
            get_by_schema_id_result: Arc::new(Mutex::new(Some(Ok(IdentitySchemaRow {
                id: "schema-1".into(),
                tenant_id: "tenant-1".into(),
                schema_id: "default".into(),
                schema_json: json!({}),
                version: 1,
                is_default: true,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            })))),
        });
        let saml_mappings = Arc::new(StubSamlMappingStore {
            get_by_name_id_result: Arc::new(Mutex::new(Some(Err(
                DbError::SamlIdentityMappingNotFound,
            )))),
            create_result: Arc::new(Mutex::new(None)),
        });
        let p = provisioner_with_saml(kratos, mappings, schemas, saml_mappings);
        let err = p
            .provision_saml(
                "tenant-1",
                "provider-1",
                "default",
                "nameid-1",
                "alice@example.com",
                false,
                false,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::EmailNotVerified));
    }

    #[test]
    fn map_ory_error_maps_status_codes() {
        assert!(matches!(
            map_ory_error(OryClientError::Ory {
                status: 400,
                message: "bad".into()
            }),
            ServiceError::InvalidArgument(_)
        ));
    }

    #[test]
    fn normalize_name_claim_defaults_to_empty_object() {
        assert_eq!(normalize_name_claim(None), json!({}));
    }

    #[test]
    fn normalize_name_claim_passthrough_object() {
        assert_eq!(
            normalize_name_claim(Some(&json!({"first": "Alice", "last": "Smith"}))),
            json!({"first": "Alice", "last": "Smith"})
        );
    }

    #[test]
    fn normalize_name_claim_splits_string_into_first_and_last() {
        assert_eq!(
            normalize_name_claim(Some(&json!("Alice Smith"))),
            json!({"first": "Alice", "last": "Smith"})
        );
    }

    #[test]
    fn normalize_name_claim_single_word_string_becomes_first_only() {
        assert_eq!(
            normalize_name_claim(Some(&json!("Alice"))),
            json!({"first": "Alice"})
        );
    }
}
