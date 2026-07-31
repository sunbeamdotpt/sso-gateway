use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine;
use buffa_types::google::protobuf::{Empty, Struct as ProtoStruct};
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sso_ory_client::error::OryClientError;
#[cfg(feature = "keto")]
use sso_ory_client::keto::KetoClient;
use sunbeam_g2v::error::ServiceError;
use tracing::instrument;

use crate::{
    auth::{AuthContext, SCOPE_PERMISSION_ADMIN, SCOPE_PERMISSION_READ, require_scope},
    db::{
        IdMappingRepo, IdMappingStore, PermissionTupleRepo, PermissionTupleRow,
        PermissionTupleStore, TupleKeyInput,
    },
    middleware::TenantId,
    proto::iam::v1::{
        CheckPermissionRequest, CheckPermissionResponse, CreateRelationTupleRequest,
        DeletePermissionNamespaceRequest, DeleteRelationTupleRequest,
        EnsurePermissionNamespaceRequest, ExpandObjectsRequest, ExpandObjectsResponse,
        ExpandPermissionsRequest, ExpandPermissionsResponse, GetPermissionNamespaceRequest,
        ListPermissionNamespacesRequest, ListPermissionNamespacesResponse,
        ListRelationTuplesRequest, ListRelationTuplesResponse, ListUsersRequest,
        ListUsersResponse, PermissionNamespace, PermissionService, RelationTuple,
        RelationTupleKey as ProtoRelationTupleKey, WriteRelationTuplesRequest,
        WriteRelationTuplesResponse,
    },
    services::proto_util::json_to_struct,
};

/// Errors that can be returned by a permissions backend.
#[derive(Debug, thiserror::Error)]
pub enum PermissionBackendError {
    #[error("ory backend error: {status} {message}")]
    Ory { status: u16, message: String },

    #[error("openfga backend error: {status} {message}")]
    OpenFga { status: u16, message: String },

    #[error("namespace not configured: {0}")]
    NamespaceNotConfigured(String),

    #[error("namespace type conflict: {0}")]
    Conflict(String),

    #[error("configuration: {0}")]
    Configuration(String),

    #[error("serialization: {0}")]
    Serialization(String),

    #[error("backend unavailable: {0}")]
    Unavailable(String),
}

impl From<OryClientError> for PermissionBackendError {
    fn from(err: OryClientError) -> Self {
        match err {
            OryClientError::Ory { status, message } => Self::Ory { status, message },
            OryClientError::Http(e) => Self::Unavailable(e.to_string()),
            OryClientError::Serialization(e) => Self::Serialization(e.to_string()),
            OryClientError::Url(e) => Self::Configuration(e.to_string()),
            OryClientError::InvalidResponse(msg) => Self::Unavailable(msg),
            OryClientError::MissingTenant => {
                Self::Configuration("missing tenant context".to_string())
            }
            OryClientError::Redirect { .. } => Self::Unavailable("unexpected redirect".into()),
        }
    }
}

#[cfg(feature = "openfga")]
impl From<sso_openfga_client::OpenFgaClientError> for PermissionBackendError {
    fn from(err: sso_openfga_client::OpenFgaClientError) -> Self {
        match err {
            sso_openfga_client::OpenFgaClientError::OpenFga { status, message } => {
                Self::OpenFga { status, message }
            }
            sso_openfga_client::OpenFgaClientError::Http(e) => Self::Unavailable(e.to_string()),
            sso_openfga_client::OpenFgaClientError::Serialization(e) => {
                Self::Serialization(e.to_string())
            }
            sso_openfga_client::OpenFgaClientError::Url(e) => Self::Configuration(e.to_string()),
            sso_openfga_client::OpenFgaClientError::MissingStore => {
                Self::NamespaceNotConfigured("missing OpenFGA store".to_string())
            }
            sso_openfga_client::OpenFgaClientError::InvalidResponse(msg) => {
                Self::Configuration(msg)
            }
        }
    }
}

impl From<PermissionBackendError> for ServiceError {
    fn from(err: PermissionBackendError) -> Self {
        match err {
            PermissionBackendError::Ory { status, message } => match status {
                400 => ServiceError::InvalidArgument(message),
                401 => ServiceError::Unauthenticated(message),
                403 => ServiceError::PermissionDenied(message),
                404 => ServiceError::NotFound(message),
                409 => ServiceError::AlreadyExists(message),
                503 => ServiceError::Unavailable(message),
                _ => ServiceError::Internal(message),
            },
            PermissionBackendError::OpenFga { status, message } => match status {
                400 => ServiceError::InvalidArgument(message),
                401 => ServiceError::Unauthenticated(message),
                403 => ServiceError::PermissionDenied(message),
                404 => ServiceError::NotFound(message),
                409 => ServiceError::AlreadyExists(message),
                503 => ServiceError::Unavailable(message),
                _ => ServiceError::Internal(message),
            },
            PermissionBackendError::NamespaceNotConfigured(msg) => {
                ServiceError::InvalidArgument(msg)
            }
            PermissionBackendError::Conflict(msg) => ServiceError::AlreadyExists(msg),
            PermissionBackendError::Configuration(msg) => ServiceError::Configuration(msg),
            PermissionBackendError::Serialization(msg) => ServiceError::Serialization(msg),
            PermissionBackendError::Unavailable(msg) => ServiceError::Unavailable(msg),
        }
    }
}

impl From<PermissionBackendError> for connectrpc::ConnectError {
    fn from(err: PermissionBackendError) -> Self {
        ServiceError::from(err).into()
    }
}

/// A single relation tuple key as accepted by the gateway.
///
/// `subject_id` may be a bare gateway identifier (treated as a user), a typed
/// subject (`user:<id>`), a userset (`<type>:<id>#<relation>`), or a typed
/// wildcard (`<type>:*`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RelationTupleKey {
    pub namespace: String,
    pub object: String,
    pub relation: String,
    pub subject_id: String,
    pub condition: Option<String>,
    pub condition_context: Option<Value>,
}

/// Optional evaluation parameters for check/expand/list operations.
///
/// Every set field is passed through to OpenFGA verbatim. Backends that do
/// not support these parameters (Keto) reject non-default options.
#[derive(Debug, Clone, Default)]
pub struct QueryOptions {
    pub context: Option<Value>,
    pub contextual_tuples: Vec<RelationTupleKey>,
    pub consistency: Option<String>,
}

impl QueryOptions {
    pub fn is_default(&self) -> bool {
        self.context.is_none() && self.contextual_tuples.is_empty() && self.consistency.is_none()
    }
}

#[allow(clippy::too_many_arguments)]
/// Async trait abstracting the permission operations used by the gateway.
///
/// Implementations are backend-agnostic: the caller provides the gateway
/// `tenant_id` and the backend is responsible for any backend-specific
/// namespacing or store/model resolution.
#[async_trait]
pub trait PermissionBackend: Send + Sync + 'static {
    async fn check_permission(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
        opts: &QueryOptions,
    ) -> Result<bool, PermissionBackendError>;

    async fn create_relation_tuple(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<Value, PermissionBackendError>;

    async fn delete_relation_tuple(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<(), PermissionBackendError>;

    /// Batch create and/or delete relation tuples.
    ///
    /// OpenFGA performs one write per store touched by the keys; Keto loops
    /// over single writes.
    async fn write_tuples(
        &self,
        tenant_id: &str,
        writes: &[RelationTupleKey],
        deletes: &[RelationTupleKey],
    ) -> Result<(), PermissionBackendError>;

    async fn expand(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        opts: &QueryOptions,
    ) -> Result<Value, PermissionBackendError>;

    async fn expand_objects(
        &self,
        tenant_id: &str,
        namespace: &str,
        relation: &str,
        subject_id: Option<&str>,
        subject_set_namespace: Option<&str>,
        subject_set_object: Option<&str>,
        subject_set_relation: Option<&str>,
        max_depth: Option<i32>,
        opts: &QueryOptions,
    ) -> Result<Value, PermissionBackendError>;

    /// List the subjects that have a relation on an object, as canonical
    /// strings (`type:id`, `type:id#relation`, `type:*`).
    async fn list_users(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        user_type_filters: &[String],
        opts: &QueryOptions,
    ) -> Result<Vec<String>, PermissionBackendError>;

    /// Ensure that a namespace exists for the tenant using a flat,
    /// single-type model derived from `relations`.
    ///
    /// Used by first-party flows (SCIM groups) that do not author rich
    /// models. Equivalent to [`PermissionBackend::ensure_model`] with a
    /// synthesized model.
    async fn ensure_namespace(
        &self,
        tenant_id: &str,
        namespace: &str,
        relations: &[String],
    ) -> Result<(), PermissionBackendError>;

    /// Ensure that a namespace exists for the tenant with the given
    /// authorization model.
    ///
    /// Model changes publish a new OpenFGA model version into the existing
    /// store; the store itself is created exactly once and tuples are never
    /// touched. Keto ignores the model because namespaces are not
    /// pre-declared.
    async fn ensure_model(
        &self,
        tenant_id: &str,
        namespace: &str,
        model: &Value,
    ) -> Result<(), PermissionBackendError>;

    /// Tear down backend resources for a namespace (OpenFGA store).
    ///
    /// The mapping row itself is removed by the service layer. Deleting a
    /// store that no longer exists is not an error.
    async fn delete_namespace(
        &self,
        tenant_id: &str,
        namespace: &str,
    ) -> Result<(), PermissionBackendError>;
}

#[cfg(feature = "keto")]
#[async_trait]
impl PermissionBackend for KetoClient {
    async fn check_permission(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
        opts: &QueryOptions,
    ) -> Result<bool, PermissionBackendError> {
        reject_unsupported_opts(opts)?;
        Ok(self
            .check_permission(
                namespace,
                &tenant_object(tenant_id, object),
                relation,
                subject_id,
            )
            .await?)
    }

    async fn create_relation_tuple(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<Value, PermissionBackendError> {
        Ok(self
            .create_relation_tuple(
                namespace,
                &tenant_object(tenant_id, object),
                relation,
                subject_id,
            )
            .await?)
    }

    async fn delete_relation_tuple(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<(), PermissionBackendError> {
        Ok(self
            .delete_relation_tuple(
                namespace,
                &tenant_object(tenant_id, object),
                relation,
                subject_id,
            )
            .await?)
    }

    async fn write_tuples(
        &self,
        tenant_id: &str,
        writes: &[RelationTupleKey],
        deletes: &[RelationTupleKey],
    ) -> Result<(), PermissionBackendError> {
        for key in writes {
            PermissionBackend::create_relation_tuple(
                self,
                tenant_id,
                &key.namespace,
                &key.object,
                &key.relation,
                &key.subject_id,
            )
            .await?;
        }
        for key in deletes {
            PermissionBackend::delete_relation_tuple(
                self,
                tenant_id,
                &key.namespace,
                &key.object,
                &key.relation,
                &key.subject_id,
            )
            .await?;
        }
        Ok(())
    }

    async fn expand(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        opts: &QueryOptions,
    ) -> Result<Value, PermissionBackendError> {
        reject_unsupported_opts(opts)?;
        Ok(self
            .expand(namespace, &tenant_object(tenant_id, object), relation)
            .await?)
    }

    async fn expand_objects(
        &self,
        tenant_id: &str,
        namespace: &str,
        relation: &str,
        subject_id: Option<&str>,
        subject_set_namespace: Option<&str>,
        subject_set_object: Option<&str>,
        subject_set_relation: Option<&str>,
        max_depth: Option<i32>,
        opts: &QueryOptions,
    ) -> Result<Value, PermissionBackendError> {
        reject_unsupported_opts(opts)?;
        let _ = tenant_id;
        let query = sso_ory_client::keto::ExpandObjectsQuery {
            subject_id,
            subject_set_namespace,
            subject_set_object,
            subject_set_relation,
            max_depth,
        };
        Ok(self.expand_objects(namespace, relation, &query).await?)
    }

    async fn list_users(
        &self,
        _tenant_id: &str,
        _namespace: &str,
        _object: &str,
        _relation: &str,
        _user_type_filters: &[String],
        _opts: &QueryOptions,
    ) -> Result<Vec<String>, PermissionBackendError> {
        Err(PermissionBackendError::Configuration(
            "ListUsers is not supported by the keto backend".to_string(),
        ))
    }

    async fn ensure_namespace(
        &self,
        _tenant_id: &str,
        _namespace: &str,
        _relations: &[String],
    ) -> Result<(), PermissionBackendError> {
        // Keto namespaces do not need to be pre-provisioned.
        Ok(())
    }

    async fn ensure_model(
        &self,
        _tenant_id: &str,
        _namespace: &str,
        _model: &Value,
    ) -> Result<(), PermissionBackendError> {
        // Keto namespaces do not need to be pre-provisioned.
        Ok(())
    }

    async fn delete_namespace(
        &self,
        _tenant_id: &str,
        _namespace: &str,
    ) -> Result<(), PermissionBackendError> {
        // Keto keeps no per-namespace resources to tear down.
        Ok(())
    }
}

/// Keto has no notion of evaluation context, contextual tuples, or
/// consistency; reject them explicitly instead of silently dropping them.
#[cfg(feature = "keto")]
fn reject_unsupported_opts(opts: &QueryOptions) -> Result<(), PermissionBackendError> {
    if opts.is_default() {
        return Ok(());
    }
    Err(PermissionBackendError::Configuration(
        "context, contextual tuples, and consistency are not supported by the keto backend"
            .to_string(),
    ))
}

/// A registered tenant namespace and its provisioning state.
///
/// `store_id`/`model_id` are `None` until the backend has provisioned a store
/// (and stay `None` on Keto, which has no stores). `types` lists the object
/// types defined by the current model; they index back to this namespace for
/// tuple/check resolution.
#[derive(Clone, Debug, PartialEq)]
pub struct NamespaceRecord {
    pub namespace: String,
    pub model: Value,
    pub types: Vec<String>,
    pub store_id: Option<String>,
    pub model_id: Option<String>,
    pub created_at: Option<time::OffsetDateTime>,
    pub updated_at: Option<time::OffsetDateTime>,
}

/// Repository that resolves and stores namespace records.
///
/// The OpenFGA backend uses it to resolve stores/models; the permission
/// service uses it for the namespace lifecycle RPCs.
#[async_trait]
pub trait NamespaceMappingRepo: Send + Sync + 'static {
    async fn get(
        &self,
        tenant_id: &str,
        namespace: &str,
    ) -> Result<Option<NamespaceRecord>, PermissionBackendError>;

    /// Resolve the namespace that owns an object type, falling back to
    /// treating the type as a namespace name.
    async fn get_by_type(
        &self,
        tenant_id: &str,
        object_type: &str,
    ) -> Result<Option<NamespaceRecord>, PermissionBackendError>;

    /// Insert or update a record. `None` store/model ids preserve previously
    /// provisioned values (metadata-only update).
    async fn upsert(
        &self,
        tenant_id: &str,
        record: &NamespaceRecord,
    ) -> Result<NamespaceRecord, PermissionBackendError>;

    async fn list(&self, tenant_id: &str) -> Result<Vec<NamespaceRecord>, PermissionBackendError>;

    async fn delete(&self, tenant_id: &str, namespace: &str) -> Result<(), PermissionBackendError>;
}

/// In-memory namespace mapping repo intended for tests.
#[derive(Clone, Default)]
pub struct MemoryNamespaceMappingRepo {
    records: Arc<Mutex<HashMap<(String, String), NamespaceRecord>>>,
}

#[async_trait]
impl NamespaceMappingRepo for MemoryNamespaceMappingRepo {
    async fn get(
        &self,
        tenant_id: &str,
        namespace: &str,
    ) -> Result<Option<NamespaceRecord>, PermissionBackendError> {
        let lock = match self.records.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        Ok(lock.get(&(tenant_id.to_string(), namespace.to_string())).cloned())
    }

    async fn get_by_type(
        &self,
        tenant_id: &str,
        object_type: &str,
    ) -> Result<Option<NamespaceRecord>, PermissionBackendError> {
        let lock = match self.records.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let by_type = lock
            .iter()
            .find(|((t, _), record)| t == tenant_id && record.types.iter().any(|ty| ty == object_type))
            .map(|(_, record)| record.clone());
        match by_type {
            Some(record) => Ok(Some(record)),
            None => Ok(lock.get(&(tenant_id.to_string(), object_type.to_string())).cloned()),
        }
    }

    async fn upsert(
        &self,
        tenant_id: &str,
        record: &NamespaceRecord,
    ) -> Result<NamespaceRecord, PermissionBackendError> {
        let mut lock = match self.records.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        // A type may be owned by exactly one namespace per tenant.
        for ((t, ns), existing) in lock.iter() {
            if t == tenant_id && ns != &record.namespace {
                for ty in &record.types {
                    if existing.types.iter().any(|ety| ety == ty) {
                        return Err(PermissionBackendError::Conflict(format!(
                            "type {ty} is already registered under namespace {ns}"
                        )));
                    }
                }
            }
        }
        let key = (tenant_id.to_string(), record.namespace.clone());
        let now = time::OffsetDateTime::now_utc();
        let merged = match lock.get(&key) {
            Some(existing) => NamespaceRecord {
                store_id: record.store_id.clone().or_else(|| existing.store_id.clone()),
                model_id: record.model_id.clone().or_else(|| existing.model_id.clone()),
                updated_at: Some(now),
                ..record.clone()
            },
            None => NamespaceRecord {
                created_at: Some(now),
                updated_at: Some(now),
                ..record.clone()
            },
        };
        lock.insert(key, merged.clone());
        Ok(merged)
    }

    async fn list(&self, tenant_id: &str) -> Result<Vec<NamespaceRecord>, PermissionBackendError> {
        let lock = match self.records.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut records: Vec<NamespaceRecord> = lock
            .iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, record)| record.clone())
            .collect();
        records.sort_by(|a, b| a.namespace.cmp(&b.namespace));
        Ok(records)
    }

    async fn delete(&self, tenant_id: &str, namespace: &str) -> Result<(), PermissionBackendError> {
        let mut lock = match self.records.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        lock.remove(&(tenant_id.to_string(), namespace.to_string()));
        Ok(())
    }
}

#[async_trait]
impl NamespaceMappingRepo for crate::db::PgPermissionNamespaceStore {
    async fn get(
        &self,
        tenant_id: &str,
        namespace: &str,
    ) -> Result<Option<NamespaceRecord>, PermissionBackendError> {
        self.get(tenant_id, namespace)
            .await
            .map(|row| row.map(namespace_record_from_row))
            .map_err(map_namespace_db_error)
    }

    async fn get_by_type(
        &self,
        tenant_id: &str,
        object_type: &str,
    ) -> Result<Option<NamespaceRecord>, PermissionBackendError> {
        self.get_by_type(tenant_id, object_type)
            .await
            .map(|row| row.map(namespace_record_from_row))
            .map_err(map_namespace_db_error)
    }

    async fn upsert(
        &self,
        tenant_id: &str,
        record: &NamespaceRecord,
    ) -> Result<NamespaceRecord, PermissionBackendError> {
        self.upsert(
            tenant_id,
            &record.namespace,
            &record.model,
            &record.types,
            record.store_id.as_deref(),
            record.model_id.as_deref(),
        )
        .await
        .map(namespace_record_from_row)
        .map_err(map_namespace_db_error)
    }

    async fn list(&self, tenant_id: &str) -> Result<Vec<NamespaceRecord>, PermissionBackendError> {
        self.list(tenant_id)
            .await
            .map(|rows| rows.into_iter().map(namespace_record_from_row).collect())
            .map_err(map_namespace_db_error)
    }

    async fn delete(&self, tenant_id: &str, namespace: &str) -> Result<(), PermissionBackendError> {
        self.delete(tenant_id, namespace)
            .await
            .map_err(map_namespace_db_error)
    }
}

fn namespace_record_from_row(row: crate::db::PermissionNamespaceRow) -> NamespaceRecord {
    NamespaceRecord {
        namespace: row.namespace,
        model: row.model,
        types: row.types,
        store_id: row.store_id,
        model_id: row.model_id,
        created_at: Some(row.created_at),
        updated_at: Some(row.updated_at),
    }
}

fn map_namespace_db_error(err: crate::db::DbError) -> PermissionBackendError {
    match err {
        crate::db::DbError::NamespaceTypeConflict(ty) => {
            PermissionBackendError::Conflict(format!("type {ty} is already registered"))
        }
        other => PermissionBackendError::Unavailable(format!("namespace store: {other}")),
    }
}

/// OpenFGA-backed implementation of [`PermissionBackend`].
///
/// Each tenant namespace is resolved to its own OpenFGA store and authorization
/// model via a [`NamespaceMappingRepo`]. Objects are not tenant-prefixed in
/// OpenFGA; isolation comes from per-tenant stores.
#[cfg(feature = "openfga")]
#[derive(Clone)]
pub struct OpenFgaPermissionBackend {
    client: sso_openfga_client::OpenFgaClient,
    mappings: Arc<dyn NamespaceMappingRepo>,
}

/// Format a gateway subject identifier as an OpenFGA user.
///
/// OpenFGA requires typed users (`user:<id>`). If the caller already supplied
/// a typed identifier (it contains a colon), pass it through unchanged;
/// otherwise treat it as a user.
#[cfg(feature = "openfga")]
fn typed_user(subject_id: &str) -> String {
    if subject_id.contains(':') {
        subject_id.to_string()
    } else {
        format!("user:{subject_id}")
    }
}

/// Extract the sorted object type names defined by an authorization model.
fn model_type_names(model: &Value) -> Vec<String> {
    let mut types: Vec<String> = match model.get("type_definitions").and_then(|v| v.as_array()) {
        Some(defs) => defs
            .iter()
            .filter_map(|def| def.get("type").and_then(|t| t.as_str()).map(String::from))
            .collect(),
        None => Vec::new(),
    };
    types.sort();
    types
}

/// Convert a gateway tuple key into an OpenFGA tuple key.
#[cfg(feature = "openfga")]
fn client_tuple_key(key: &RelationTupleKey) -> sso_openfga_client::TupleKey {
    sso_openfga_client::TupleKey {
        user: typed_user(&key.subject_id),
        relation: key.relation.clone(),
        object: format!("{}:{}", key.namespace, key.object),
        condition_name: key.condition.clone(),
        condition_context: key.condition_context.clone(),
    }
}

/// Convert gateway query options into OpenFGA request options.
#[cfg(feature = "openfga")]
fn client_request_options(opts: &QueryOptions) -> sso_openfga_client::RequestOptions {
    sso_openfga_client::RequestOptions {
        context: opts.context.clone(),
        contextual_tuples: opts.contextual_tuples.iter().map(client_tuple_key).collect(),
        consistency: opts.consistency.clone(),
    }
}

#[cfg(feature = "openfga")]
impl OpenFgaPermissionBackend {
    pub fn new(
        client: sso_openfga_client::OpenFgaClient,
        mappings: Arc<dyn NamespaceMappingRepo>,
    ) -> Self {
        Self { client, mappings }
    }

    async fn resolve_mapping(
        &self,
        tenant_id: &str,
        namespace: &str,
    ) -> Result<NamespaceRecord, PermissionBackendError> {
        let record = self
            .mappings
            .get_by_type(tenant_id, namespace)
            .await?
            .ok_or_else(|| {
                PermissionBackendError::NamespaceNotConfigured(format!(
                    "tenant {tenant_id} namespace {namespace} has no OpenFGA store/model"
                ))
            })?;
        let store_id = match record.store_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        };
        let model_id = match record.model_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        };
        if store_id.is_empty() || model_id.is_empty() {
            return Err(PermissionBackendError::NamespaceNotConfigured(format!(
                "tenant {tenant_id} namespace {namespace} has no OpenFGA store/model"
            )));
        }
        Ok(record)
    }

    /// Persist a converged record (new model id and/or freshly created store).
    #[cfg(feature = "openfga")]
    async fn persist_record(
        &self,
        tenant_id: &str,
        namespace: &str,
        model: &Value,
        store_id: String,
        model_id: String,
    ) -> Result<(), PermissionBackendError> {
        self.mappings
            .upsert(
                tenant_id,
                &NamespaceRecord {
                    namespace: namespace.to_string(),
                    model: model.clone(),
                    types: model_type_names(model),
                    store_id: Some(store_id),
                    model_id: Some(model_id),
                    created_at: None,
                    updated_at: None,
                },
            )
            .await?;
        Ok(())
    }
}

#[cfg(feature = "openfga")]
#[async_trait]
impl PermissionBackend for OpenFgaPermissionBackend {
    async fn check_permission(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
        opts: &QueryOptions,
    ) -> Result<bool, PermissionBackendError> {
        let mapping = self.resolve_mapping(tenant_id, namespace).await?;
        let store_id = match mapping.store_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        };
        let model_id = match mapping.model_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        };
        Ok(self
            .client
            .check(
                &store_id,
                &model_id,
                namespace,
                object,
                relation,
                &typed_user(subject_id),
                &client_request_options(opts),
            )
            .await?)
    }

    async fn create_relation_tuple(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<Value, PermissionBackendError> {
        self.write_tuples(
            tenant_id,
            &[RelationTupleKey {
                namespace: namespace.to_string(),
                object: object.to_string(),
                relation: relation.to_string(),
                subject_id: subject_id.to_string(),
                condition: None,
                condition_context: None,
            }],
            &[],
        )
        .await?;
        Ok(Value::Null)
    }

    async fn delete_relation_tuple(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<(), PermissionBackendError> {
        self.write_tuples(
            tenant_id,
            &[],
            &[RelationTupleKey {
                namespace: namespace.to_string(),
                object: object.to_string(),
                relation: relation.to_string(),
                subject_id: subject_id.to_string(),
                condition: None,
                condition_context: None,
            }],
        )
        .await
    }

    async fn write_tuples(
        &self,
        tenant_id: &str,
        writes: &[RelationTupleKey],
        deletes: &[RelationTupleKey],
    ) -> Result<(), PermissionBackendError> {
        // Group keys by their owning store; OpenFGA writes are per-store.
        let mut records: HashMap<String, NamespaceRecord> = HashMap::new();
        let mut grouped: HashMap<String, (Vec<sso_openfga_client::TupleKey>, Vec<sso_openfga_client::TupleKey>)> =
            HashMap::new();

        for key in writes.iter().chain(deletes.iter()) {
            if !records.contains_key(&key.namespace) {
                let record = self.resolve_mapping(tenant_id, &key.namespace).await?;
                records.insert(key.namespace.clone(), record);
            }
        }
        for key in writes {
            let record = &records[&key.namespace];
            let store_key = match record.store_id.as_deref() {
                Some(id) => id.to_owned(),
                None => String::new(),
            };
            let group = match grouped.entry(store_key) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert((Vec::new(), Vec::new()))
                }
            };
            group.0.push(client_tuple_key(key));
        }
        for key in deletes {
            let record = &records[&key.namespace];
            let store_key = match record.store_id.as_deref() {
                Some(id) => id.to_owned(),
                None => String::new(),
            };
            let group = match grouped.entry(store_key) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert((Vec::new(), Vec::new()))
                }
            };
            group.1.push(client_tuple_key(key));
        }

        for (store_id, (store_writes, store_deletes)) in grouped {
            // Every key in a store shares its current model id.
            let model_id = match records
                .values()
                .find(|r| r.store_id.as_deref() == Some(&store_id))
                .and_then(|r| r.model_id.as_deref())
            {
                Some(id) => id.to_owned(),
                None => String::new(),
            };
            self.client
                .write_tuples(&store_id, &model_id, &store_writes, &store_deletes)
                .await?;
        }
        Ok(())
    }

    async fn expand(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        opts: &QueryOptions,
    ) -> Result<Value, PermissionBackendError> {
        let mapping = self.resolve_mapping(tenant_id, namespace).await?;
        let store_id = match mapping.store_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        };
        let model_id = match mapping.model_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        };
        Ok(self
            .client
            .expand(
                &store_id,
                &model_id,
                namespace,
                object,
                relation,
                &client_request_options(opts),
            )
            .await?)
    }

    async fn expand_objects(
        &self,
        tenant_id: &str,
        namespace: &str,
        relation: &str,
        subject_id: Option<&str>,
        _subject_set_namespace: Option<&str>,
        _subject_set_object: Option<&str>,
        _subject_set_relation: Option<&str>,
        _max_depth: Option<i32>,
        opts: &QueryOptions,
    ) -> Result<Value, PermissionBackendError> {
        // OpenFGA list-objects only supports a direct user subject.
        let user = subject_id.ok_or_else(|| {
            PermissionBackendError::Configuration(
                "OpenFGA expand_objects requires a subject_id".to_string(),
            )
        })?;
        let mapping = self.resolve_mapping(tenant_id, namespace).await?;
        let typed = typed_user(user);
        let store_id = match mapping.store_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        };
        let model_id = match mapping.model_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        };
        let objects = self
            .client
            .list_objects(
                &store_id,
                &model_id,
                namespace,
                relation,
                &typed,
                &client_request_options(opts),
            )
            .await?;
        Ok(
            serde_json::json!({ "relation_tuples": objects.iter().map(|o| {
            serde_json::json!({
                "namespace": namespace,
                "object": o,
                "relation": relation,
                "subject_id": user,
            })
        }).collect::<Vec<_>>() }),
        )
    }

    async fn list_users(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
        user_type_filters: &[String],
        opts: &QueryOptions,
    ) -> Result<Vec<String>, PermissionBackendError> {
        let mapping = self.resolve_mapping(tenant_id, namespace).await?;
        let store_id = match mapping.store_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        };
        let model_id = match mapping.model_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        };
        Ok(self
            .client
            .list_users(
                &store_id,
                &model_id,
                namespace,
                object,
                relation,
                user_type_filters,
                &client_request_options(opts),
            )
            .await?)
    }

    async fn ensure_namespace(
        &self,
        tenant_id: &str,
        namespace: &str,
        relations: &[String],
    ) -> Result<(), PermissionBackendError> {
        let model = sso_openfga_client::flat_model(namespace, relations);
        self.ensure_model(tenant_id, namespace, &model).await
    }

    async fn ensure_model(
        &self,
        tenant_id: &str,
        namespace: &str,
        model: &Value,
    ) -> Result<(), PermissionBackendError> {
        let existing = self.mappings.get(tenant_id, namespace).await?;

        if let Some(record) = existing {
            let provisioned = match record.store_id.as_deref() {
                Some(id) => !id.is_empty(),
                None => false,
            };
            if provisioned {
                if record.model == *model {
                    return Ok(());
                }
                // Model changed: publish a new version into the same store.
                // Tuples are never touched.
                let store_id = match record.store_id.as_deref() {
                    Some(id) => id.to_owned(),
                    None => String::new(),
                };
                let model_id = self.client.write_model(&store_id, model).await?;
                return self
                    .persist_record(tenant_id, namespace, model, store_id, model_id)
                    .await;
            }
        }

        let store_name = format!("{tenant_id}-{namespace}");
        let store_id = self.client.create_store(&store_name).await?;
        let model_id = self.client.write_model(&store_id, model).await?;
        self.persist_record(tenant_id, namespace, model, store_id, model_id)
            .await
    }

    async fn delete_namespace(
        &self,
        tenant_id: &str,
        namespace: &str,
    ) -> Result<(), PermissionBackendError> {
        let Some(record) = self.mappings.get(tenant_id, namespace).await? else {
            return Ok(());
        };
        let store_id = match record.store_id.as_deref() {
            Some(id) => id.to_owned(),
            None => String::new(),
        };
        if store_id.is_empty() {
            return Ok(());
        }
        match self.client.delete_store(&store_id).await {
            Ok(()) => Ok(()),
            Err(sso_openfga_client::OpenFgaClientError::OpenFga { status: 404, .. }) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

#[derive(Clone)]
pub struct PermissionServiceImpl {
    backend: Arc<dyn PermissionBackend>,
    tuples: Arc<dyn PermissionTupleStore>,
    mappings: Arc<dyn IdMappingStore>,
    namespaces: Arc<dyn NamespaceMappingRepo>,
}

impl PermissionServiceImpl {
    pub fn new(
        backend: Arc<dyn PermissionBackend>,
        tuples: PermissionTupleRepo,
        mappings: IdMappingRepo,
        namespaces: Arc<dyn NamespaceMappingRepo>,
    ) -> Self {
        Self {
            backend,
            tuples: Arc::new(tuples) as Arc<dyn PermissionTupleStore>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
            namespaces,
        }
    }
}

#[allow(refining_impl_trait)]
impl PermissionService for PermissionServiceImpl {
    #[instrument(skip(self, request))]
    async fn check_permission(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CheckPermissionRequest>,
    ) -> ServiceResult<CheckPermissionResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_PERMISSION_READ, SCOPE_PERMISSION_ADMIN])?;
        let req = request.to_owned_message();
        let opts = query_options_from(
            req.context.as_option(),
            &req.contextual_tuples,
            &req.consistency,
        )?;
        let allowed = self
            .backend
            .check_permission(
                &tenant_id,
                &req.namespace,
                &req.object,
                &req.relation,
                &req.subject_id,
                &opts,
            )
            .await?;
        Ok(Response::new(CheckPermissionResponse {
            allowed,
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn create_relation_tuple(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateRelationTupleRequest>,
    ) -> ServiceResult<RelationTuple> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_PERMISSION_ADMIN)?;
        let req = request.to_owned_message();

        let row = self
            .tuples
            .create(
                &tenant_id,
                &req.namespace,
                &req.object,
                &req.relation,
                &req.subject_id,
            )
            .await?;

        self.backend
            .create_relation_tuple(
                &tenant_id,
                &req.namespace,
                &req.object,
                &req.relation,
                &req.subject_id,
            )
            .await?;

        Ok(Response::new(row.into_proto()))
    }

    #[instrument(skip(self, request))]
    async fn delete_relation_tuple(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteRelationTupleRequest>,
    ) -> ServiceResult<Empty> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_PERMISSION_ADMIN)?;
        let req = request.to_owned_message();
        let row = self.tuples.get(&tenant_id, &req.id).await?;

        self.backend
            .delete_relation_tuple(
                &tenant_id,
                &row.namespace,
                &row.object,
                &row.relation,
                &row.subject_id,
            )
            .await?;

        self.tuples.delete(&tenant_id, &req.id).await?;
        Ok(Response::new(Empty::default()))
    }

    #[instrument(skip(self, request))]
    async fn expand_permissions(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ExpandPermissionsRequest>,
    ) -> ServiceResult<ExpandPermissionsResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_PERMISSION_READ, SCOPE_PERMISSION_ADMIN])?;
        let req = request.to_owned_message();
        let opts = query_options_from(
            req.context.as_option(),
            &req.contextual_tuples,
            &req.consistency,
        )?;

        let expanded = self
            .backend
            .expand(&tenant_id, &req.namespace, &req.object, &req.relation, &opts)
            .await?;

        let sanitized = sanitize_expand_tree(&expanded, &tenant_id, &self.mappings).await?;
        let tree = serde_json::to_string(&sanitized)
            .map_err(|err| ServiceError::Internal(format!("failed to serialize expand tree: {err}")))?;
        Ok(Response::new(ExpandPermissionsResponse {
            tree,
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn expand_objects(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ExpandObjectsRequest>,
    ) -> ServiceResult<ExpandObjectsResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_PERMISSION_READ, SCOPE_PERMISSION_ADMIN])?;
        let req = request.to_owned_message();
        let opts = query_options_from(
            req.context.as_option(),
            &req.contextual_tuples,
            &req.consistency,
        )?;

        let expanded = self
            .backend
            .expand_objects(
                &tenant_id,
                &req.namespace,
                &req.relation,
                subject_id_filter(&req.subject_id),
                subject_set_filter(&req.subject_set_namespace),
                subject_set_filter(&req.subject_set_object),
                subject_set_filter(&req.subject_set_relation),
                max_depth_filter(req.max_depth),
                &opts,
            )
            .await?;

        let sanitized = sanitize_expand_tree(&expanded, &tenant_id, &self.mappings).await?;

        let objects = match sanitized.get("relation_tuples").and_then(|v| v.as_array()) {
            Some(tuples) => tuples
                .iter()
                .filter_map(|tuple| tuple.get("object").and_then(|o| o.as_str()))
                .map(|object| object.to_string())
                .collect::<Vec<_>>(),
            None => Vec::new(),
        };

        let tree = serde_json::to_string(&sanitized)
            .map_err(|err| ServiceError::Internal(format!("failed to serialize expand tree: {err}")))?;
        Ok(Response::new(ExpandObjectsResponse {
            objects,
            tree,
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn list_relation_tuples(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListRelationTuplesRequest>,
    ) -> ServiceResult<ListRelationTuplesResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_PERMISSION_READ, SCOPE_PERMISSION_ADMIN])?;
        let req = request.to_owned_message();

        let page = req.page.as_option();
        let page_size = match page.map(|p| p.page_size).filter(|&size| size > 0) {
            Some(size) => size,
            None => DEFAULT_PAGE_SIZE,
        }
        .min(MAX_PAGE_SIZE);
        let after = page
            .map(|p| p.page_token.as_str())
            .filter(|token| !token.is_empty())
            .map(decode_page_token)
            .transpose()?;

        let (rows, total) = self
            .tuples
            .list_page(
                &tenant_id,
                namespace_filter(&req.namespace),
                object_filter(&req.object),
                relation_filter(&req.relation),
                page_size,
                after,
            )
            .await?;

        let next_page_token = if rows.len() as u32 == page_size {
            match rows.last() {
                Some(row) => encode_page_token(row.created_at, &row.id),
                None => String::new(),
            }
        } else {
            String::new()
        };

        let tuples = rows.into_iter().map(|r| r.into_proto()).collect();
        Ok(Response::new(ListRelationTuplesResponse {
            tuples,
            page: crate::proto::iam::v1::PageResponse {
                next_page_token,
                total_size: total.clamp(0, i64::from(u32::MAX)) as u32,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn ensure_permission_namespace(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, EnsurePermissionNamespaceRequest>,
    ) -> ServiceResult<PermissionNamespace> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_PERMISSION_ADMIN)?;
        let req = request.to_owned_message();

        validate_namespace_name(&req.namespace)?;
        let model_json = req
            .model
            .as_option()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|err| ServiceError::InvalidArgument(format!("invalid model: {err}")))?
            .ok_or_else(|| ServiceError::InvalidArgument("model is required".into()))?;
        let model = validate_and_normalize_model(model_json)?;

        // Idempotent fast path: an identical model is already registered.
        let current = self.namespaces.get(&tenant_id, &req.namespace).await?;
        if let Some(current) = current.filter(|record| record.model == model) {
            return Ok(Response::new(record_to_proto(&tenant_id, current)?));
        }

        self.backend
            .ensure_model(&tenant_id, &req.namespace, &model)
            .await?;

        // On OpenFGA the backend already persisted the provisioned record;
        // this merge preserves its store/model ids and is the only write on
        // backends without provisioning (Keto).
        let record = self
            .namespaces
            .upsert(
                &tenant_id,
                &NamespaceRecord {
                    namespace: req.namespace.clone(),
                    types: model_type_names(&model),
                    model,
                    store_id: None,
                    model_id: None,
                    created_at: None,
                    updated_at: None,
                },
            )
            .await?;
        Ok(Response::new(record_to_proto(&tenant_id, record)?))
    }

    #[instrument(skip(self, request))]
    async fn get_permission_namespace(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetPermissionNamespaceRequest>,
    ) -> ServiceResult<PermissionNamespace> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_PERMISSION_READ, SCOPE_PERMISSION_ADMIN])?;
        let req = request.to_owned_message();

        let record = self
            .namespaces
            .get(&tenant_id, &req.namespace)
            .await?
            .ok_or_else(|| namespace_not_found(&req.namespace))?;
        Ok(Response::new(record_to_proto(&tenant_id, record)?))
    }

    #[instrument(skip(self, request))]
    async fn list_permission_namespaces(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListPermissionNamespacesRequest>,
    ) -> ServiceResult<ListPermissionNamespacesResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_PERMISSION_READ, SCOPE_PERMISSION_ADMIN])?;
        let _req = request.to_owned_message();

        let records = self.namespaces.list(&tenant_id).await?;
        let total = records.len();
        let namespaces = records
            .into_iter()
            .map(|record| record_to_proto(&tenant_id, record))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Response::new(ListPermissionNamespacesResponse {
            namespaces,
            page: crate::proto::iam::v1::PageResponse {
                total_size: total.min(u32::MAX as usize) as u32,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn delete_permission_namespace(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeletePermissionNamespaceRequest>,
    ) -> ServiceResult<Empty> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_PERMISSION_ADMIN)?;
        let req = request.to_owned_message();

        self.namespaces
            .get(&tenant_id, &req.namespace)
            .await?
            .ok_or_else(|| namespace_not_found(&req.namespace))?;

        // Full teardown: backend store, mirror tuples, then the record.
        self.backend
            .delete_namespace(&tenant_id, &req.namespace)
            .await?;
        self.tuples
            .delete_by_namespace(&tenant_id, &req.namespace)
            .await?;
        self.namespaces.delete(&tenant_id, &req.namespace).await?;
        Ok(Response::new(Empty::default()))
    }

    #[instrument(skip(self, request))]
    async fn write_relation_tuples(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, WriteRelationTuplesRequest>,
    ) -> ServiceResult<WriteRelationTuplesResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_PERMISSION_ADMIN)?;
        let req = request.to_owned_message();

        if req.writes.is_empty() && req.deletes.is_empty() {
            return Err(ServiceError::InvalidArgument("at least one tuple key is required".into()).into());
        }
        for (direction, keys) in [("writes", &req.writes), ("deletes", &req.deletes)] {
            if keys.len() > MAX_BATCH_KEYS {
                return Err(ServiceError::InvalidArgument(format!(
                    "{direction} exceeds the maximum of {MAX_BATCH_KEYS} tuple keys"
                ))
                .into());
            }
        }
        let writes = req
            .writes
            .into_iter()
            .map(tuple_key_from_proto)
            .collect::<Result<Vec<_>, _>>()?;
        let deletes = req
            .deletes
            .into_iter()
            .map(tuple_key_from_proto)
            .collect::<Result<Vec<_>, _>>()?;

        self.backend
            .write_tuples(&tenant_id, &writes, &deletes)
            .await?;

        // Mirror the write set for list/get; deletes remove matching rows.
        let mirror_keys: Vec<TupleKeyInput> = writes
            .iter()
            .map(|key| TupleKeyInput {
                namespace: key.namespace.clone(),
                object: key.object.clone(),
                relation: key.relation.clone(),
                subject_id: key.subject_id.clone(),
            })
            .collect();
        self.tuples.create_many(&tenant_id, &mirror_keys).await?;
        for key in &deletes {
            self.tuples
                .delete_by_key(
                    &tenant_id,
                    &key.namespace,
                    &key.object,
                    &key.relation,
                    &key.subject_id,
                )
                .await?;
        }

        Ok(Response::new(WriteRelationTuplesResponse {
            written: writes.len() as i32,
            deleted: deletes.len() as i32,
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn list_users(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListUsersRequest>,
    ) -> ServiceResult<ListUsersResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_PERMISSION_READ, SCOPE_PERMISSION_ADMIN])?;
        let req = request.to_owned_message();
        let opts = query_options_from(
            req.context.as_option(),
            &req.contextual_tuples,
            &req.consistency,
        )?;

        let users = self
            .backend
            .list_users(
                &tenant_id,
                &req.namespace,
                &req.object,
                &req.relation,
                &req.user_type_filters,
                &opts,
            )
            .await?;
        Ok(Response::new(ListUsersResponse {
            users,
            ..Default::default()
        }))
    }
}

#[cfg(feature = "keto")]
fn tenant_object(tenant_id: &str, object: &str) -> String {
    format!("{tenant_id}:{object}")
}

fn strip_tenant_object_prefix(tenant_id: &str, object: &str) -> Option<String> {
    let prefix = format!("{tenant_id}:");
    object.strip_prefix(&prefix).map(|rest| rest.to_string())
}

/// Recursively rewrite an expand/tree response so that no tenant-prefixed
/// internal object identifiers or backend subject identifiers are exposed.
fn sanitize_expand_tree<'a>(
    value: &'a serde_json::Value,
    tenant_id: &'a str,
    mappings: &'a Arc<dyn IdMappingStore>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<serde_json::Value, ServiceError>> + Send + 'a>,
> {
    Box::pin(async move {
        match value {
            serde_json::Value::Object(map) => {
                let mut out = serde_json::Map::with_capacity(map.len());
                for (k, v) in map {
                    if k == "object" {
                        out.insert(k.clone(), sanitize_object_value(v, tenant_id)?);
                    } else if k == "subject_id" {
                        out.insert(
                            k.clone(),
                            sanitize_subject_id(v, tenant_id, mappings).await?,
                        );
                    } else {
                        out.insert(
                            k.clone(),
                            sanitize_expand_tree(v, tenant_id, mappings).await?,
                        );
                    }
                }
                Ok(serde_json::Value::Object(out))
            }
            serde_json::Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for v in arr {
                    out.push(sanitize_expand_tree(v, tenant_id, mappings).await?);
                }
                Ok(serde_json::Value::Array(out))
            }
            other => Ok(other.clone()),
        }
    })
}

fn sanitize_object_value(
    value: &serde_json::Value,
    tenant_id: &str,
) -> Result<serde_json::Value, ServiceError> {
    match value.as_str() {
        Some(s) => Ok(match strip_tenant_object_prefix(tenant_id, s) {
            Some(stripped) => serde_json::Value::String(stripped),
            None => serde_json::Value::String(s.to_string()),
        }),
        None => Ok(value.clone()),
    }
}

async fn sanitize_subject_id(
    value: &serde_json::Value,
    tenant_id: &str,
    mappings: &Arc<dyn IdMappingStore>,
) -> Result<serde_json::Value, ServiceError> {
    let Some(subject) = value.as_str() else {
        return Ok(value.clone());
    };

    // Subject sets are encoded as "namespace:object#relation" by Keto.
    // Strip the tenant prefix from the object portion if present.
    if subject.contains('#') {
        return Ok(serde_json::Value::String(strip_subject_set_prefix(
            subject, tenant_id,
        )));
    }

    // Try to map a backend identity or client identifier to the gateway public
    // id. If no mapping exists, the value is already a public id or a
    // non-sensitive backend identifier; pass it through unchanged.
    if let Ok(public_id) = mappings.get_public_id(tenant_id, "kratos", subject).await {
        return Ok(serde_json::Value::String(public_id));
    }
    if let Ok(public_id) = mappings.get_public_id(tenant_id, "hydra", subject).await {
        return Ok(serde_json::Value::String(public_id));
    }
    Ok(serde_json::Value::String(subject.to_string()))
}

fn strip_subject_set_prefix(subject: &str, tenant_id: &str) -> String {
    // Keto subject set format: "namespace:object#relation" where the object
    // may be "tenant_id:gateway_object_id".
    let prefix = format!("{tenant_id}:");
    if let Some((left, relation)) = subject.split_once('#') {
        let stripped = match left.strip_prefix(&prefix) {
            Some(rest) => rest,
            None => left,
        };
        format!("{stripped}#{relation}")
    } else {
        subject.to_string()
    }
}

fn namespace_filter(namespace: &str) -> Option<&str> {
    if namespace.is_empty() {
        None
    } else {
        Some(namespace)
    }
}

fn object_filter(object: &str) -> Option<&str> {
    if object.is_empty() {
        None
    } else {
        Some(object)
    }
}

fn relation_filter(relation: &str) -> Option<&str> {
    if relation.is_empty() {
        None
    } else {
        Some(relation)
    }
}

fn subject_id_filter(subject_id: &str) -> Option<&str> {
    if subject_id.is_empty() {
        None
    } else {
        Some(subject_id)
    }
}

fn subject_set_filter(value: &str) -> Option<&str> {
    if value.is_empty() { None } else { Some(value) }
}

fn max_depth_filter(max_depth: i32) -> Option<i32> {
    if max_depth <= 0 {
        None
    } else {
        Some(max_depth)
    }
}

/// Default page size for `ListRelationTuples`.
const DEFAULT_PAGE_SIZE: u32 = 50;
/// Maximum page size for `ListRelationTuples`.
const MAX_PAGE_SIZE: u32 = 200;
/// Maximum tuple keys per direction in `WriteRelationTuples`.
const MAX_BATCH_KEYS: usize = 100;

fn namespace_not_found(namespace: &str) -> ServiceError {
    ServiceError::NotFound(format!("permission namespace not found: {namespace}"))
}

/// Type and namespace names follow the OpenFGA rules: a leading ASCII letter
/// followed by up to 127 ASCII alphanumerics or underscores.
fn is_valid_type_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn validate_namespace_name(name: &str) -> Result<(), ServiceError> {
    if is_valid_type_name(name) {
        return Ok(());
    }
    Err(ServiceError::InvalidArgument(format!(
        "invalid namespace name {name:?}: must match [A-Za-z][A-Za-z0-9_] up to 128 chars"
    )))
}

/// Validate and normalize an OpenFGA authorization model.
///
/// Requires a JSON object with a non-empty `schema_version` string and a
/// non-empty `type_definitions` array whose entries have valid, unique `type`
/// names. The returned model has its type definitions sorted by type name so
/// that model equality comparisons are stable across key orderings.
fn validate_and_normalize_model(mut model: Value) -> Result<Value, ServiceError> {
    if !model.is_object() {
        return Err(ServiceError::InvalidArgument(
            "model must be a JSON object".into(),
        ));
    }
    match model.get("schema_version").and_then(|v| v.as_str()) {
        Some(version) if !version.is_empty() => {}
        _ => {
            return Err(ServiceError::InvalidArgument(
                "model.schema_version must be a non-empty string".into(),
            ));
        }
    }
    let defs = model
        .get_mut("type_definitions")
        .and_then(|v| v.as_array_mut())
        .filter(|defs| !defs.is_empty())
        .ok_or_else(|| {
            ServiceError::InvalidArgument("model.type_definitions must be a non-empty array".into())
        })?;
    let mut seen = std::collections::HashSet::new();
    for def in defs.iter() {
        let ty = def.get("type").and_then(|t| t.as_str()).ok_or_else(|| {
            ServiceError::InvalidArgument("every type definition must have a string type".into())
        })?;
        if !is_valid_type_name(ty) {
            return Err(ServiceError::InvalidArgument(format!(
                "invalid type name {ty:?}: must match [A-Za-z][A-Za-z0-9_] up to 128 chars"
            )));
        }
        if !seen.insert(ty.to_string()) {
            return Err(ServiceError::InvalidArgument(format!(
                "duplicate type definition: {ty}"
            )));
        }
    }
    defs.sort_by(|a, b| {
        let ta = match a.get("type").and_then(|t| t.as_str()) {
            Some(ty) => ty.to_owned(),
            None => String::new(),
        };
        let tb = match b.get("type").and_then(|t| t.as_str()) {
            Some(ty) => ty.to_owned(),
            None => String::new(),
        };
        ta.cmp(&tb)
    });
    Ok(model)
}

/// Convert a protobuf tuple key into the gateway representation.
fn tuple_key_from_proto(key: ProtoRelationTupleKey) -> Result<RelationTupleKey, ServiceError> {
    if key.namespace.is_empty()
        || key.object.is_empty()
        || key.relation.is_empty()
        || key.subject_id.is_empty()
    {
        return Err(ServiceError::InvalidArgument(
            "tuple key requires namespace, object, relation, and subject_id".into(),
        ));
    }
    let condition = if key.condition.is_empty() {
        None
    } else {
        Some(key.condition)
    };
    let condition_context = key
        .condition_context
        .as_option()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|err| ServiceError::InvalidArgument(format!("invalid condition context: {err}")))?;
    Ok(RelationTupleKey {
        namespace: key.namespace,
        object: key.object,
        relation: key.relation,
        subject_id: key.subject_id,
        condition,
        condition_context,
    })
}

/// Assemble query options from the additive request fields.
fn query_options_from(
    context: Option<&ProtoStruct>,
    contextual_tuples: &[ProtoRelationTupleKey],
    consistency: &str,
) -> Result<QueryOptions, ServiceError> {
    let consistency = match consistency {
        "" => None,
        "minimize_latency" | "higher_consistency" => Some(consistency.to_string()),
        other => {
            return Err(ServiceError::InvalidArgument(format!(
                "invalid consistency {other:?}: expected \"minimize_latency\" or \"higher_consistency\""
            )));
        }
    };
    let contextual_tuples = contextual_tuples
        .iter()
        .cloned()
        .map(tuple_key_from_proto)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(QueryOptions {
        context: context
            .map(serde_json::to_value)
            .transpose()
            .map_err(|err| ServiceError::InvalidArgument(format!("invalid context: {err}")))?,
        contextual_tuples,
        consistency,
    })
}

/// Convert a namespace record into its protobuf representation.
fn record_to_proto(
    tenant_id: &str,
    record: NamespaceRecord,
) -> Result<PermissionNamespace, ServiceError> {
    let model = json_to_struct(record.model)
        .ok_or_else(|| ServiceError::Internal("stored namespace model is not an object".into()))?;
    let timestamp = |t: Option<time::OffsetDateTime>| {
        t.map(|t| buffa_types::google::protobuf::Timestamp {
            seconds: t.unix_timestamp(),
            nanos: t.nanosecond() as i32,
            ..Default::default()
        })
        .into()
    };
    Ok(PermissionNamespace {
        tenant_id: tenant_id.to_string(),
        namespace: record.namespace,
        model: Some(model).into(),
        types: record.types,
        created_at: timestamp(record.created_at),
        updated_at: timestamp(record.updated_at),
        ..Default::default()
    })
}

/// Encode a keyset cursor as an opaque page token.
fn encode_page_token(created_at: time::OffsetDateTime, id: &str) -> String {
    let raw = format!("{}:{id}", created_at.unix_timestamp_nanos());
    base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
}

/// Decode a page token back into its keyset cursor.
fn decode_page_token(token: &str) -> Result<(time::OffsetDateTime, String), ServiceError> {
    let invalid = || ServiceError::InvalidArgument("invalid page token".into());
    let raw = base64::engine::general_purpose::STANDARD
        .decode(token)
        .map_err(|_| invalid())?;
    let raw = String::from_utf8(raw).map_err(|_| invalid())?;
    let (nanos, id) = raw.split_once(':').ok_or_else(invalid)?;
    if id.is_empty() {
        return Err(invalid());
    }
    let nanos: i128 = nanos.parse().map_err(|_| invalid())?;
    let created_at =
        time::OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| invalid())?;
    Ok((created_at, id.to_string()))
}

fn require_tenant(ctx: &RequestContext) -> Result<String, ServiceError> {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .ok_or_else(|| ServiceError::Unauthenticated("missing tenant".into()))
}

fn require_scope_any(ctx: &RequestContext, scopes: &[&str]) -> Result<(), ServiceError> {
    let auth = ctx
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| ServiceError::Unauthenticated("missing authentication context".into()))?;
    if !auth.scopes.iter().any(|s| scopes.contains(&s.as_str())) {
        return Err(ServiceError::PermissionDenied(format!(
            "missing required scope: one of {}",
            scopes.join(", ")
        )));
    }
    Ok(())
}

#[cfg(test)]
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

impl PermissionTupleRow {
    fn into_proto(self) -> RelationTuple {
        RelationTuple {
            id: self.id,
            tenant_id: self.tenant_id,
            namespace: self.namespace,
            object: self.object,
            relation: self.relation,
            subject_id: self.subject_id,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::SubjectType;
    use std::sync::Mutex;

    use super::*;
    use crate::db::{DbError, IdMappingRow};

    fn tenant_ctx() -> RequestContext {
        scoped_ctx(&[SCOPE_PERMISSION_READ])
    }

    fn admin_ctx() -> RequestContext {
        scoped_ctx(&[SCOPE_PERMISSION_ADMIN])
    }

    fn no_scope_ctx() -> RequestContext {
        scoped_ctx(&["other:scope"])
    }

    fn scoped_ctx(scopes: &[&str]) -> RequestContext {
        let mut ctx = RequestContext::new(http::HeaderMap::new());
        ctx.extensions_mut().insert(TenantId("tenant-1".into()));
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "sub-1".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            token_hash: "hash".into(),
            authentication_methods: Vec::new(),
        });
        ctx
    }

    fn sample_row() -> PermissionTupleRow {
        PermissionTupleRow {
            id: "t1".into(),
            tenant_id: "tenant-1".into(),
            namespace: "ns".into(),
            object: "obj".into(),
            relation: "viewer".into(),
            subject_id: "user-1".into(),
            created_at: time::OffsetDateTime::now_utc(),
        }
    }

    // -------------------------------------------------------------------------
    // Fakes
    // -------------------------------------------------------------------------

    /// Test-only error representation for `OryClientError`; the real error type
    /// is not `Clone`, so fakes hold a cloneable summary and build the error
    /// when returning.
    #[derive(Debug, Clone)]
    enum BackendError {
        Ory(u16, String),
    }

    impl From<BackendError> for PermissionBackendError {
        fn from(err: BackendError) -> Self {
            match err {
                BackendError::Ory(status, message) => Self::Ory { status, message },
            }
        }
    }

    #[derive(Debug, Clone)]
    struct FakePermissionBackend {
        check_result: Result<bool, BackendError>,
        create_result: Result<Value, BackendError>,
        delete_result: Result<(), BackendError>,
        expand_result: Result<Value, BackendError>,
        expand_objects_result: Result<Value, BackendError>,
        write_tuples_result: Result<(), BackendError>,
        list_users_result: Result<Vec<String>, BackendError>,
        ensure_model_result: Result<(), BackendError>,
        delete_namespace_result: Result<(), BackendError>,
        calls: Arc<Mutex<Vec<BackendCall>>>,
        opts_log: Arc<Mutex<Vec<QueryOptions>>>,
    }

    #[derive(Debug, Clone)]
    enum BackendCall {
        Check {
            tenant_id: String,
            namespace: String,
            object: String,
            relation: String,
            subject_id: String,
        },
        Create {
            tenant_id: String,
            namespace: String,
            object: String,
            relation: String,
            subject_id: String,
        },
        Delete {
            tenant_id: String,
            namespace: String,
            object: String,
            relation: String,
            subject_id: String,
        },
        Expand {
            tenant_id: String,
            namespace: String,
            object: String,
            relation: String,
        },
        ExpandObjects {
            tenant_id: String,
            namespace: String,
            relation: String,
            subject_id: Option<String>,
            subject_set_namespace: Option<String>,
            subject_set_object: Option<String>,
            subject_set_relation: Option<String>,
            max_depth: Option<i32>,
        },
        WriteTuples {
            tenant_id: String,
            writes: Vec<RelationTupleKey>,
            deletes: Vec<RelationTupleKey>,
        },
        ListUsers {
            tenant_id: String,
            namespace: String,
            object: String,
            relation: String,
            user_type_filters: Vec<String>,
        },
        EnsureModel {
            tenant_id: String,
            namespace: String,
            model: Value,
        },
        DeleteNamespace {
            tenant_id: String,
            namespace: String,
        },
    }

    impl FakePermissionBackend {
        fn new() -> Self {
            Self {
                check_result: Ok(false),
                create_result: Ok(Value::Null),
                delete_result: Ok(()),
                expand_result: Ok(Value::Null),
                expand_objects_result: Ok(Value::Null),
                write_tuples_result: Ok(()),
                list_users_result: Ok(Vec::new()),
                ensure_model_result: Ok(()),
                delete_namespace_result: Ok(()),
                calls: Arc::new(Mutex::new(Vec::new())),
                opts_log: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl PermissionBackend for FakePermissionBackend {
        async fn check_permission(
            &self,
            tenant_id: &str,
            namespace: &str,
            object: &str,
            relation: &str,
            subject_id: &str,
            opts: &QueryOptions,
        ) -> Result<bool, PermissionBackendError> {
            self.calls.lock().unwrap().push(BackendCall::Check {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
                subject_id: subject_id.into(),
            });
            self.opts_log.lock().unwrap().push(opts.clone());
            self.check_result.clone().map_err(Into::into)
        }

        async fn create_relation_tuple(
            &self,
            tenant_id: &str,
            namespace: &str,
            object: &str,
            relation: &str,
            subject_id: &str,
        ) -> Result<Value, PermissionBackendError> {
            self.calls.lock().unwrap().push(BackendCall::Create {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
                subject_id: subject_id.into(),
            });
            self.create_result.clone().map_err(Into::into)
        }

        async fn delete_relation_tuple(
            &self,
            tenant_id: &str,
            namespace: &str,
            object: &str,
            relation: &str,
            subject_id: &str,
        ) -> Result<(), PermissionBackendError> {
            self.calls.lock().unwrap().push(BackendCall::Delete {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
                subject_id: subject_id.into(),
            });
            self.delete_result.clone().map_err(Into::into)
        }

        async fn expand(
            &self,
            tenant_id: &str,
            namespace: &str,
            object: &str,
            relation: &str,
            opts: &QueryOptions,
        ) -> Result<Value, PermissionBackendError> {
            self.calls.lock().unwrap().push(BackendCall::Expand {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
            });
            self.opts_log.lock().unwrap().push(opts.clone());
            self.expand_result.clone().map_err(Into::into)
        }

        async fn expand_objects(
            &self,
            tenant_id: &str,
            namespace: &str,
            relation: &str,
            subject_id: Option<&str>,
            subject_set_namespace: Option<&str>,
            subject_set_object: Option<&str>,
            subject_set_relation: Option<&str>,
            max_depth: Option<i32>,
            opts: &QueryOptions,
        ) -> Result<Value, PermissionBackendError> {
            self.calls.lock().unwrap().push(BackendCall::ExpandObjects {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
                relation: relation.into(),
                subject_id: subject_id.map(Into::into),
                subject_set_namespace: subject_set_namespace.map(Into::into),
                subject_set_object: subject_set_object.map(Into::into),
                subject_set_relation: subject_set_relation.map(Into::into),
                max_depth,
            });
            self.opts_log.lock().unwrap().push(opts.clone());
            self.expand_objects_result.clone().map_err(Into::into)
        }

        async fn write_tuples(
            &self,
            tenant_id: &str,
            writes: &[RelationTupleKey],
            deletes: &[RelationTupleKey],
        ) -> Result<(), PermissionBackendError> {
            self.calls.lock().unwrap().push(BackendCall::WriteTuples {
                tenant_id: tenant_id.into(),
                writes: writes.to_vec(),
                deletes: deletes.to_vec(),
            });
            self.write_tuples_result.clone().map_err(Into::into)
        }

        async fn list_users(
            &self,
            tenant_id: &str,
            namespace: &str,
            object: &str,
            relation: &str,
            user_type_filters: &[String],
            opts: &QueryOptions,
        ) -> Result<Vec<String>, PermissionBackendError> {
            self.calls.lock().unwrap().push(BackendCall::ListUsers {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
                user_type_filters: user_type_filters.to_vec(),
            });
            self.opts_log.lock().unwrap().push(opts.clone());
            self.list_users_result.clone().map_err(Into::into)
        }

        async fn ensure_namespace(
            &self,
            _tenant_id: &str,
            _namespace: &str,
            _relations: &[String],
        ) -> Result<(), PermissionBackendError> {
            Ok(())
        }

        async fn ensure_model(
            &self,
            tenant_id: &str,
            namespace: &str,
            model: &Value,
        ) -> Result<(), PermissionBackendError> {
            self.calls.lock().unwrap().push(BackendCall::EnsureModel {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
                model: model.clone(),
            });
            self.ensure_model_result.clone().map_err(Into::into)
        }

        async fn delete_namespace(
            &self,
            tenant_id: &str,
            namespace: &str,
        ) -> Result<(), PermissionBackendError> {
            self.calls.lock().unwrap().push(BackendCall::DeleteNamespace {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
            });
            self.delete_namespace_result.clone().map_err(Into::into)
        }
    }

    /// Test-only error representation for `DbError`; the real error type is not
    /// `Clone`, so fakes hold a cloneable summary and build the error when
    /// returning.
    #[derive(Debug, Clone)]
    enum TupleError {
        NotFound,
        Database,
    }

    impl From<TupleError> for DbError {
        fn from(err: TupleError) -> Self {
            match err {
                TupleError::NotFound => Self::TupleNotFound,
                TupleError::Database => Self::Sqlx(sqlx::Error::PoolTimedOut),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct FakeTupleStore {
        create_result: Result<PermissionTupleRow, TupleError>,
        get_result: Result<PermissionTupleRow, TupleError>,
        delete_result: Result<(), TupleError>,
        list_result: Result<Vec<PermissionTupleRow>, TupleError>,
        list_page_result: Result<(Vec<PermissionTupleRow>, i64), TupleError>,
        calls: Arc<Mutex<Vec<TupleCall>>>,
    }

    #[derive(Debug, Clone)]
    enum TupleCall {
        Create {
            tenant_id: String,
            namespace: String,
            object: String,
            relation: String,
            subject_id: String,
        },
        CreateMany {
            tenant_id: String,
            keys: Vec<TupleKeyInput>,
        },
        Get,
        Delete {
            tenant_id: String,
            id: String,
        },
        DeleteByKey {
            tenant_id: String,
            namespace: String,
            object: String,
            relation: String,
            subject_id: String,
        },
        DeleteByNamespace {
            tenant_id: String,
            namespace: String,
        },
        List,
        ListPage {
            tenant_id: String,
            namespace: Option<String>,
            object: Option<String>,
            relation: Option<String>,
            limit: u32,
            has_cursor: bool,
        },
    }

    impl FakeTupleStore {
        fn new() -> Self {
            Self {
                create_result: Err(TupleError::NotFound),
                get_result: Err(TupleError::NotFound),
                delete_result: Ok(()),
                list_result: Ok(Vec::new()),
                list_page_result: Ok((Vec::new(), 0)),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl PermissionTupleStore for FakeTupleStore {
        async fn create(
            &self,
            tenant_id: &str,
            namespace: &str,
            object: &str,
            relation: &str,
            subject_id: &str,
        ) -> Result<PermissionTupleRow, DbError> {
            self.calls.lock().unwrap().push(TupleCall::Create {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
                subject_id: subject_id.into(),
            });
            self.create_result.clone().map_err(Into::into)
        }

        async fn get(&self, _tenant_id: &str, _id: &str) -> Result<PermissionTupleRow, DbError> {
            self.calls.lock().unwrap().push(TupleCall::Get);
            self.get_result.clone().map_err(Into::into)
        }

        async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), DbError> {
            self.calls.lock().unwrap().push(TupleCall::Delete {
                tenant_id: tenant_id.into(),
                id: id.into(),
            });
            self.delete_result.clone().map_err(Into::into)
        }

        async fn list(
            &self,
            _tenant_id: &str,
            _namespace: Option<&str>,
            _object: Option<&str>,
            _relation: Option<&str>,
        ) -> Result<Vec<PermissionTupleRow>, DbError> {
            self.calls.lock().unwrap().push(TupleCall::List);
            self.list_result.clone().map_err(Into::into)
        }

        async fn create_many(
            &self,
            tenant_id: &str,
            keys: &[TupleKeyInput],
        ) -> Result<Vec<PermissionTupleRow>, DbError> {
            self.calls.lock().unwrap().push(TupleCall::CreateMany {
                tenant_id: tenant_id.into(),
                keys: keys.to_vec(),
            });
            Ok(keys
                .iter()
                .enumerate()
                .map(|(i, key)| PermissionTupleRow {
                    id: format!("batch-{i}"),
                    tenant_id: tenant_id.into(),
                    namespace: key.namespace.clone(),
                    object: key.object.clone(),
                    relation: key.relation.clone(),
                    subject_id: key.subject_id.clone(),
                    created_at: time::OffsetDateTime::now_utc(),
                })
                .collect())
        }

        async fn delete_by_key(
            &self,
            tenant_id: &str,
            namespace: &str,
            object: &str,
            relation: &str,
            subject_id: &str,
        ) -> Result<u64, DbError> {
            self.calls.lock().unwrap().push(TupleCall::DeleteByKey {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
                subject_id: subject_id.into(),
            });
            Ok(1)
        }

        async fn delete_by_namespace(
            &self,
            tenant_id: &str,
            namespace: &str,
        ) -> Result<u64, DbError> {
            self.calls.lock().unwrap().push(TupleCall::DeleteByNamespace {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
            });
            Ok(1)
        }

        async fn list_page(
            &self,
            tenant_id: &str,
            namespace: Option<&str>,
            object: Option<&str>,
            relation: Option<&str>,
            limit: u32,
            after: Option<(time::OffsetDateTime, String)>,
        ) -> Result<(Vec<PermissionTupleRow>, i64), DbError> {
            self.calls.lock().unwrap().push(TupleCall::ListPage {
                tenant_id: tenant_id.into(),
                namespace: namespace.map(Into::into),
                object: object.map(Into::into),
                relation: relation.map(Into::into),
                limit,
                has_cursor: after.is_some(),
            });
            self.list_page_result.clone().map_err(Into::into)
        }
    }

    #[derive(Clone, Default)]
    #[allow(clippy::type_complexity)]
    struct FakeMappingStore {
        mappings: Arc<Mutex<Vec<(String, String, String, String)>>>,
    }

    #[async_trait::async_trait]
    impl IdMappingStore for FakeMappingStore {
        async fn create(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
            ory_global_id: &str,
        ) -> Result<IdMappingRow, DbError> {
            self.mappings.lock().unwrap().push((
                tenant_id.to_string(),
                backend.to_string(),
                public_id.to_string(),
                ory_global_id.to_string(),
            ));
            Ok(IdMappingRow {
                id: "id".into(),
                tenant_id: tenant_id.into(),
                backend: backend.into(),
                public_id: public_id.into(),
                ory_global_id: ory_global_id.into(),
                created_at: time::OffsetDateTime::now_utc(),
            })
        }

        async fn get_ory_id(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
        ) -> Result<String, DbError> {
            self.mappings
                .lock()
                .unwrap()
                .iter()
                .find(|(t, b, p, _)| t == tenant_id && b == backend && p == public_id)
                .map(|(_, _, _, o)| o.clone())
                .ok_or(DbError::MappingNotFound)
        }

        async fn get_public_id(
            &self,
            tenant_id: &str,
            backend: &str,
            ory_global_id: &str,
        ) -> Result<String, DbError> {
            self.mappings
                .lock()
                .unwrap()
                .iter()
                .find(|(t, b, _, o)| t == tenant_id && b == backend && o == ory_global_id)
                .map(|(_, _, p, _)| p.clone())
                .ok_or(DbError::MappingNotFound)
        }

        async fn delete(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<(), DbError> {
            Ok(())
        }

        async fn list_public_ids(
            &self,
            _tenant_id: &str,
            _backend: &str,
        ) -> Result<Vec<String>, DbError> {
            Ok(Vec::new())
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, DbError> {
            Ok(None)
        }
    }

    fn service_with(
        backend: FakePermissionBackend,
        tuples: FakeTupleStore,
    ) -> PermissionServiceImpl {
        service_with_namespaces(backend, tuples, MemoryNamespaceMappingRepo::default())
    }

    fn service_with_namespaces(
        backend: FakePermissionBackend,
        tuples: FakeTupleStore,
        namespaces: MemoryNamespaceMappingRepo,
    ) -> PermissionServiceImpl {
        PermissionServiceImpl {
            backend: Arc::new(backend) as Arc<dyn PermissionBackend>,
            tuples: Arc::new(tuples) as Arc<dyn PermissionTupleStore>,
            mappings: Arc::new(FakeMappingStore::default()) as Arc<dyn IdMappingStore>,
            namespaces: Arc::new(namespaces),
        }
    }

    // -------------------------------------------------------------------------
    // Request helpers
    // -------------------------------------------------------------------------

    fn check_req() -> CheckPermissionRequest {
        CheckPermissionRequest {
            namespace: "ns".into(),
            object: "obj".into(),
            relation: "viewer".into(),
            subject_id: "user-1".into(),
            ..Default::default()
        }
    }

    fn create_req() -> CreateRelationTupleRequest {
        CreateRelationTupleRequest {
            namespace: "ns".into(),
            object: "obj".into(),
            relation: "viewer".into(),
            subject_id: "user-1".into(),
            ..Default::default()
        }
    }

    fn delete_req() -> DeleteRelationTupleRequest {
        DeleteRelationTupleRequest {
            id: "t1".into(),
            ..Default::default()
        }
    }

    fn expand_req() -> ExpandPermissionsRequest {
        ExpandPermissionsRequest {
            namespace: "ns".into(),
            object: "obj".into(),
            relation: "viewer".into(),
            ..Default::default()
        }
    }

    fn expand_objects_req() -> ExpandObjectsRequest {
        ExpandObjectsRequest {
            namespace: "ns".into(),
            relation: "viewer".into(),
            subject_id: "user-1".into(),
            ..Default::default()
        }
    }

    fn list_req() -> ListRelationTuplesRequest {
        ListRelationTuplesRequest {
            namespace: "ns".into(),
            object: "obj".into(),
            relation: "viewer".into(),
            ..Default::default()
        }
    }

    // -------------------------------------------------------------------------
    // check_permission
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn check_permission_allowed() {
        let backend = FakePermissionBackend {
            check_result: Ok(true),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(backend.clone(), tuples);

        let owned =
            crate::proto::iam::v1::CheckPermissionRequestOwnedView::from_owned(&check_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service.check_permission(tenant_ctx(), req).await.unwrap();
        assert!(resp.body.allowed);

        let calls = backend.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(
            matches!(&calls[0], BackendCall::Check { tenant_id, namespace, object, relation, subject_id } if
                tenant_id == "tenant-1" &&
                namespace == "ns" &&
                object == "obj" &&
                relation == "viewer" &&
                subject_id == "user-1"
            )
        );
    }

    #[tokio::test]
    async fn check_permission_denied() {
        let backend = FakePermissionBackend {
            check_result: Ok(false),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(backend, tuples);

        let owned =
            crate::proto::iam::v1::CheckPermissionRequestOwnedView::from_owned(&check_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service.check_permission(tenant_ctx(), req).await.unwrap();
        assert!(!resp.body.allowed);
    }

    #[tokio::test]
    async fn check_permission_missing_tenant() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());
        let ctx = RequestContext::new(http::HeaderMap::new());

        let owned =
            crate::proto::iam::v1::CheckPermissionRequestOwnedView::from_owned(&check_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service.check_permission(ctx, req).await.unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::Unauthenticated,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn check_permission_keto_error_maps_to_service_error() {
        let backend = FakePermissionBackend {
            check_result: Err(BackendError::Ory(500, "keto down".into())),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(backend, tuples);

        let owned =
            crate::proto::iam::v1::CheckPermissionRequestOwnedView::from_owned(&check_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service
            .check_permission(tenant_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::Internal,
                ..
            }
        ));
    }

    // -------------------------------------------------------------------------
    // create_relation_tuple
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn create_relation_tuple_happy_path() {
        let backend = FakePermissionBackend {
            create_result: Ok(serde_json::json!({})),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore {
            create_result: Ok(sample_row()),
            ..FakeTupleStore::new()
        };
        let service = service_with(backend.clone(), tuples.clone());

        let owned =
            crate::proto::iam::v1::CreateRelationTupleRequestOwnedView::from_owned(&create_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service
            .create_relation_tuple(admin_ctx(), req)
            .await
            .unwrap();
        assert_eq!(resp.body.id, "t1");

        let backend_calls = backend.calls.lock().unwrap();
        assert!(
            matches!(&backend_calls[0], BackendCall::Create { tenant_id, namespace, object, relation, subject_id } if
                tenant_id == "tenant-1" && namespace == "ns" && object == "obj" && relation == "viewer" && subject_id == "user-1"
            )
        );

        let tuple_calls = tuples.calls.lock().unwrap();
        assert!(
            matches!(&tuple_calls[0], TupleCall::Create { tenant_id, namespace, object, relation, subject_id } if
                tenant_id == "tenant-1" && namespace == "ns" && object == "obj" && relation == "viewer" && subject_id == "user-1"
            )
        );
    }

    #[tokio::test]
    async fn create_relation_tuple_missing_tenant() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());
        let ctx = RequestContext::new(http::HeaderMap::new());

        let owned =
            crate::proto::iam::v1::CreateRelationTupleRequestOwnedView::from_owned(&create_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service.create_relation_tuple(ctx, req).await.unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::Unauthenticated,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn create_relation_tuple_db_error_does_not_call_keto() {
        let backend = FakePermissionBackend::new();
        let tuples = FakeTupleStore {
            create_result: Err(TupleError::NotFound),
            ..FakeTupleStore::new()
        };
        let service = service_with(backend.clone(), tuples);

        let owned =
            crate::proto::iam::v1::CreateRelationTupleRequestOwnedView::from_owned(&create_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service
            .create_relation_tuple(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::NotFound,
                ..
            }
        ));
        assert!(backend.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_relation_tuple_keto_error_returns_error() {
        let backend = FakePermissionBackend {
            create_result: Err(BackendError::Ory(409, "already exists".into())),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore {
            create_result: Ok(sample_row()),
            ..FakeTupleStore::new()
        };
        let service = service_with(backend, tuples);

        let owned =
            crate::proto::iam::v1::CreateRelationTupleRequestOwnedView::from_owned(&create_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service
            .create_relation_tuple(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::AlreadyExists,
                ..
            }
        ));
    }

    // -------------------------------------------------------------------------
    // delete_relation_tuple
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn delete_relation_tuple_happy_path() {
        let backend = FakePermissionBackend {
            delete_result: Ok(()),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore {
            get_result: Ok(sample_row()),
            delete_result: Ok(()),
            ..FakeTupleStore::new()
        };
        let service = service_with(backend.clone(), tuples.clone());

        let owned =
            crate::proto::iam::v1::DeleteRelationTupleRequestOwnedView::from_owned(&delete_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service
            .delete_relation_tuple(admin_ctx(), req)
            .await
            .unwrap();
        assert_eq!(resp.body, Empty::default());

        let backend_calls = backend.calls.lock().unwrap();
        assert!(
            matches!(&backend_calls[0], BackendCall::Delete { tenant_id, namespace, object, relation, subject_id } if
                tenant_id == "tenant-1" && namespace == "ns" && object == "obj" && relation == "viewer" && subject_id == "user-1"
            )
        );

        let tuple_calls = tuples.calls.lock().unwrap();
        assert!(
            matches!(&tuple_calls[1], TupleCall::Delete { tenant_id, id } if tenant_id == "tenant-1" && id == "t1")
        );
    }

    #[tokio::test]
    async fn delete_relation_tuple_missing_tenant() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());
        let ctx = RequestContext::new(http::HeaderMap::new());

        let owned =
            crate::proto::iam::v1::DeleteRelationTupleRequestOwnedView::from_owned(&delete_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service.delete_relation_tuple(ctx, req).await.unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::Unauthenticated,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn delete_relation_tuple_not_found() {
        let tuples = FakeTupleStore {
            get_result: Err(TupleError::NotFound),
            ..FakeTupleStore::new()
        };
        let backend = FakePermissionBackend::new();
        let service = service_with(backend.clone(), tuples);

        let owned =
            crate::proto::iam::v1::DeleteRelationTupleRequestOwnedView::from_owned(&delete_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service
            .delete_relation_tuple(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::NotFound,
                ..
            }
        ));
        assert!(backend.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_relation_tuple_keto_error_skips_db_delete() {
        let backend = FakePermissionBackend {
            delete_result: Err(BackendError::Ory(404, "not found in keto".into())),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore {
            get_result: Ok(sample_row()),
            ..FakeTupleStore::new()
        };
        let service = service_with(backend, tuples.clone());

        let owned =
            crate::proto::iam::v1::DeleteRelationTupleRequestOwnedView::from_owned(&delete_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service
            .delete_relation_tuple(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::NotFound,
                ..
            }
        ));

        let tuple_calls = tuples.calls.lock().unwrap();
        assert_eq!(tuple_calls.len(), 1); // only get, no delete
    }

    // -------------------------------------------------------------------------
    // expand_permissions
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn expand_permissions_happy_path() {
        let backend = FakePermissionBackend {
            expand_result: Ok(serde_json::json!({ "children": ["a", "b"] })),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(backend.clone(), tuples);

        let owned =
            crate::proto::iam::v1::ExpandPermissionsRequestOwnedView::from_owned(&expand_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service.expand_permissions(tenant_ctx(), req).await.unwrap();
        assert_eq!(resp.body.tree, r#"{"children":["a","b"]}"#);

        let calls = backend.calls.lock().unwrap();
        assert!(
            matches!(&calls[0], BackendCall::Expand { tenant_id, namespace, object, relation } if
                tenant_id == "tenant-1" && namespace == "ns" && object == "obj" && relation == "viewer"
            )
        );
    }

    #[tokio::test]
    async fn expand_permissions_missing_tenant() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());
        let ctx = RequestContext::new(http::HeaderMap::new());

        let owned =
            crate::proto::iam::v1::ExpandPermissionsRequestOwnedView::from_owned(&expand_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service.expand_permissions(ctx, req).await.unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::Unauthenticated,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn expand_permissions_keto_error_maps_to_service_error() {
        let backend = FakePermissionBackend {
            expand_result: Err(BackendError::Ory(503, "keto unavailable".into())),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(backend, tuples);

        let owned =
            crate::proto::iam::v1::ExpandPermissionsRequestOwnedView::from_owned(&expand_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service
            .expand_permissions(tenant_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::Unavailable,
                ..
            }
        ));
    }

    // -------------------------------------------------------------------------
    // expand_objects
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn expand_objects_happy_path() {
        let backend = FakePermissionBackend {
            expand_objects_result: Ok(serde_json::json!({
                "relation_tuples": [
                    { "namespace": "ns", "object": "tenant-1:obj-1", "relation": "viewer", "subject_id": "user-1" },
                    { "namespace": "ns", "object": "tenant-1:obj-2", "relation": "viewer", "subject_id": "user-1" },
                ]
            })),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(backend.clone(), tuples);

        let owned =
            crate::proto::iam::v1::ExpandObjectsRequestOwnedView::from_owned(&expand_objects_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service.expand_objects(tenant_ctx(), req).await.unwrap();
        assert_eq!(resp.body.objects, vec!["obj-1", "obj-2"]);
        assert!(resp.body.tree.contains("relation_tuples"));

        let calls = backend.calls.lock().unwrap();
        assert!(
            matches!(&calls[0], BackendCall::ExpandObjects { tenant_id, namespace, relation, subject_id, .. } if
                tenant_id == "tenant-1" && namespace == "ns" && relation == "viewer" && subject_id.as_deref() == Some("user-1")
            )
        );
    }

    #[tokio::test]
    async fn expand_objects_with_subject_set() {
        let backend = FakePermissionBackend {
            expand_objects_result: Ok(serde_json::json!({
                "relation_tuples": [
                    { "namespace": "ns", "object": "tenant-1:obj-1", "relation": "viewer", "subject_set": { "namespace": "groups", "object": "g1", "relation": "member" } },
                ]
            })),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(backend.clone(), tuples);

        let req = ExpandObjectsRequest {
            namespace: "ns".into(),
            relation: "viewer".into(),
            subject_set_namespace: "groups".into(),
            subject_set_object: "g1".into(),
            subject_set_relation: "member".into(),
            max_depth: 3,
            ..Default::default()
        };
        let owned = crate::proto::iam::v1::ExpandObjectsRequestOwnedView::from_owned(&req).unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service.expand_objects(tenant_ctx(), req).await.unwrap();
        assert_eq!(resp.body.objects, vec!["obj-1"]);

        let calls = backend.calls.lock().unwrap();
        assert!(
            matches!(&calls[0], BackendCall::ExpandObjects { tenant_id, namespace, relation, subject_id, subject_set_namespace, subject_set_object, subject_set_relation, max_depth } if
                tenant_id == "tenant-1" &&
                namespace == "ns" &&
                relation == "viewer" &&
                subject_id.is_none() &&
                subject_set_namespace.as_deref() == Some("groups") &&
                subject_set_object.as_deref() == Some("g1") &&
                subject_set_relation.as_deref() == Some("member") &&
                *max_depth == Some(3)
            )
        );
    }

    #[tokio::test]
    async fn expand_objects_missing_tenant() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());
        let ctx = RequestContext::new(http::HeaderMap::new());

        let owned =
            crate::proto::iam::v1::ExpandObjectsRequestOwnedView::from_owned(&expand_objects_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service.expand_objects(ctx, req).await.unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::Unauthenticated,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn expand_objects_keto_error_maps_to_service_error() {
        let backend = FakePermissionBackend {
            expand_objects_result: Err(BackendError::Ory(503, "keto unavailable".into())),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(backend, tuples);

        let owned =
            crate::proto::iam::v1::ExpandObjectsRequestOwnedView::from_owned(&expand_objects_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service.expand_objects(tenant_ctx(), req).await.unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::Unavailable,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn expand_objects_ignores_empty_filters() {
        let backend = FakePermissionBackend {
            expand_objects_result: Ok(serde_json::json!({ "relation_tuples": [] })),
            ..FakePermissionBackend::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(backend.clone(), tuples);

        let req = ExpandObjectsRequest {
            namespace: "ns".into(),
            relation: "viewer".into(),
            max_depth: 0,
            ..Default::default()
        };
        let owned = crate::proto::iam::v1::ExpandObjectsRequestOwnedView::from_owned(&req).unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        service.expand_objects(tenant_ctx(), req).await.unwrap();

        let calls = backend.calls.lock().unwrap();
        assert!(
            matches!(&calls[0], BackendCall::ExpandObjects { tenant_id, namespace, relation, subject_id, subject_set_namespace, subject_set_object, subject_set_relation, max_depth } if
                tenant_id == "tenant-1" &&
                namespace == "ns" &&
                relation == "viewer" &&
                subject_id.is_none() &&
                subject_set_namespace.is_none() &&
                subject_set_object.is_none() &&
                subject_set_relation.is_none() &&
                max_depth.is_none()
            )
        );
    }

    // -------------------------------------------------------------------------
    // list_relation_tuples
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn list_relation_tuples_happy_path() {
        let tuples = FakeTupleStore {
            list_page_result: Ok((vec![sample_row()], 1)),
            ..FakeTupleStore::new()
        };
        let service = service_with(FakePermissionBackend::new(), tuples.clone());

        let owned =
            crate::proto::iam::v1::ListRelationTuplesRequestOwnedView::from_owned(&list_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service
            .list_relation_tuples(tenant_ctx(), req)
            .await
            .unwrap();
        assert_eq!(resp.body.tuples.len(), 1);
        assert_eq!(resp.body.tuples[0].id, "t1");

        let calls = tuples.calls.lock().unwrap();
        assert!(
            matches!(&calls[0], TupleCall::ListPage { tenant_id, namespace, object, relation, .. } if
                tenant_id == "tenant-1" &&
                namespace.as_deref() == Some("ns") &&
                object.as_deref() == Some("obj") &&
                relation.as_deref() == Some("viewer")
            )
        );
    }

    #[tokio::test]
    async fn list_relation_tuples_missing_tenant() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());
        let ctx = RequestContext::new(http::HeaderMap::new());

        let owned =
            crate::proto::iam::v1::ListRelationTuplesRequestOwnedView::from_owned(&list_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service.list_relation_tuples(ctx, req).await.unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::Unauthenticated,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn list_relation_tuples_db_error_maps_to_service_error() {
        let tuples = FakeTupleStore {
            list_page_result: Err(TupleError::Database),
            ..FakeTupleStore::new()
        };
        let service = service_with(FakePermissionBackend::new(), tuples);

        let owned =
            crate::proto::iam::v1::ListRelationTuplesRequestOwnedView::from_owned(&list_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let err = service
            .list_relation_tuples(tenant_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::Internal,
                ..
            }
        ));
    }

    // -------------------------------------------------------------------------
    // Existing helper tests
    // -------------------------------------------------------------------------

    #[cfg(feature = "keto")]
    #[test]
    fn tenant_object_prefixes_with_colon() {
        assert_eq!(tenant_object("tenant-1", "doc"), "tenant-1:doc");
    }

    #[test]
    fn strip_tenant_object_prefix_strips_matching_prefix() {
        assert_eq!(
            strip_tenant_object_prefix("tenant-1", "tenant-1:doc"),
            Some("doc".into())
        );
    }

    #[test]
    fn strip_tenant_object_prefix_returns_none_for_mismatch() {
        assert_eq!(strip_tenant_object_prefix("tenant-1", "other:doc"), None);
        assert_eq!(strip_tenant_object_prefix("tenant-1", "doc"), None);
    }

    #[tokio::test]
    async fn sanitize_expand_tree_strips_tenant_prefix_and_maps_subjects() {
        let mappings = Arc::new(FakeMappingStore::default()) as Arc<dyn IdMappingStore>;
        mappings
            .create("tenant-1", "kratos", "pub-alice", "ory-alice")
            .await
            .unwrap();
        let tree = serde_json::json!({
            "type": "expand",
            "tuple": {
                "namespace": "files",
                "object": "tenant-1:doc-1",
                "relation": "owner",
                "subject_id": "ory-alice"
            }
        });
        let sanitized = sanitize_expand_tree(&tree, "tenant-1", &mappings)
            .await
            .unwrap();
        assert_eq!(sanitized["tuple"]["object"], "doc-1");
        assert_eq!(sanitized["tuple"]["subject_id"], "pub-alice");
    }

    #[tokio::test]
    async fn sanitize_expand_tree_maps_hydra_subject_ids() {
        let mappings = Arc::new(FakeMappingStore::default()) as Arc<dyn IdMappingStore>;
        mappings
            .create("tenant-1", "hydra", "pub-client", "ory-client")
            .await
            .unwrap();
        let tree = serde_json::json!({
            "relation_tuples": [
                { "namespace": "apps", "object": "tenant-1:app-1", "relation": "user", "subject_id": "ory-client" }
            ]
        });
        let sanitized = sanitize_expand_tree(&tree, "tenant-1", &mappings)
            .await
            .unwrap();
        assert_eq!(sanitized["relation_tuples"][0]["subject_id"], "pub-client");
    }

    #[tokio::test]
    async fn sanitize_expand_tree_strips_subject_set_prefix() {
        let mappings = Arc::new(FakeMappingStore::default()) as Arc<dyn IdMappingStore>;
        let tree = serde_json::json!({
            "tuple": {
                "subject_set": {
                    "namespace": "groups",
                    "object": "tenant-1:group-1",
                    "relation": "member"
                }
            }
        });
        let sanitized = sanitize_expand_tree(&tree, "tenant-1", &mappings)
            .await
            .unwrap();
        assert_eq!(sanitized["tuple"]["subject_set"]["object"], "group-1");
    }

    #[test]
    fn namespace_filter_returns_none_when_empty() {
        assert_eq!(namespace_filter(""), None);
        assert_eq!(namespace_filter("ns"), Some("ns"));
    }

    #[test]
    fn object_filter_returns_none_when_empty() {
        assert_eq!(object_filter(""), None);
        assert_eq!(object_filter("obj"), Some("obj"));
    }

    #[test]
    fn relation_filter_returns_none_when_empty() {
        assert_eq!(relation_filter(""), None);
        assert_eq!(relation_filter("viewer"), Some("viewer"));
    }

    #[test]
    fn permission_tuple_row_into_proto_maps_fields() {
        let row = sample_row();
        let proto = row.into_proto();
        assert_eq!(proto.id, "t1");
        assert_eq!(proto.tenant_id, "tenant-1");
        assert_eq!(proto.namespace, "ns");
        assert_eq!(proto.object, "obj");
        assert_eq!(proto.relation, "viewer");
        assert_eq!(proto.subject_id, "user-1");
    }

    #[test]
    fn map_ory_error_maps_status_codes() {
        for (status, expected) in [
            (400u16, ServiceError::InvalidArgument("".into())),
            (401u16, ServiceError::Unauthenticated("".into())),
            (403u16, ServiceError::PermissionDenied("".into())),
            (404u16, ServiceError::NotFound("".into())),
            (409u16, ServiceError::AlreadyExists("".into())),
            (503u16, ServiceError::Unavailable("".into())),
            (500u16, ServiceError::Internal("".into())),
        ] {
            let err = map_ory_error(OryClientError::Ory {
                status,
                message: "msg".into(),
            });
            assert_eq!(
                std::mem::discriminant(&err),
                std::mem::discriminant(&expected),
                "status {status}"
            );
        }
    }

    #[test]
    fn map_ory_error_maps_non_ory_variants() {
        let err = map_ory_error(OryClientError::Http(
            reqwest::Client::new().get("not-a-url").build().unwrap_err(),
        ));
        assert!(matches!(err, ServiceError::Unavailable(_)), "{err:?}");

        let err = map_ory_error(OryClientError::Serialization(
            serde_json::from_str::<serde_json::Value>("not json").unwrap_err(),
        ));
        assert!(matches!(err, ServiceError::Serialization(_)), "{err:?}");

        let err = map_ory_error(OryClientError::Url(
            reqwest::Url::parse("not a url").unwrap_err(),
        ));
        assert!(matches!(err, ServiceError::Configuration(_)), "{err:?}");

        let err = map_ory_error(OryClientError::InvalidResponse("bad body".into()));
        assert!(matches!(err, ServiceError::Internal(_)), "{err:?}");

        let err = map_ory_error(OryClientError::MissingTenant);
        assert!(matches!(err, ServiceError::Unauthenticated(_)), "{err:?}");
    }

    #[test]
    fn require_tenant_returns_tenant_id_when_present() {
        let mut ctx = RequestContext::new(http::HeaderMap::new());
        ctx.extensions_mut().insert(TenantId("tenant-1".into()));
        assert_eq!(require_tenant(&ctx).unwrap(), "tenant-1");
    }

    #[test]
    fn require_tenant_errors_when_missing() {
        let ctx = RequestContext::new(http::HeaderMap::new());
        assert!(matches!(
            require_tenant(&ctx),
            Err(ServiceError::Unauthenticated(_))
        ));
    }

    #[test]
    fn filters_return_some_for_non_empty_values() {
        assert_eq!(namespace_filter("  "), Some("  "));
        assert_eq!(object_filter("ns:obj"), Some("ns:obj"));
        assert_eq!(relation_filter("member"), Some("member"));
        assert_eq!(subject_id_filter("user-1"), Some("user-1"));
        assert_eq!(subject_set_filter("groups"), Some("groups"));
        assert_eq!(max_depth_filter(3), Some(3));
    }

    #[test]
    fn subject_id_filter_returns_none_when_empty() {
        assert_eq!(subject_id_filter(""), None);
    }

    #[test]
    fn subject_set_filter_returns_none_when_empty() {
        assert_eq!(subject_set_filter(""), None);
    }

    #[test]
    fn max_depth_filter_returns_none_for_non_positive() {
        assert_eq!(max_depth_filter(0), None);
        assert_eq!(max_depth_filter(-1), None);
    }

    #[cfg(feature = "keto")]
    #[tokio::test]
    async fn keto_client_as_permission_backend_delegates() {
        let client = Arc::new(KetoClient::new("http://localhost:1", "http://localhost:1").unwrap())
            as Arc<dyn PermissionBackend>;
        let opts = QueryOptions::default();
        assert!(
            client
                .check_permission("tenant-1", "ns", "obj", "rel", "subject", &opts)
                .await
                .is_err()
        );
        assert!(
            client
                .create_relation_tuple("tenant-1", "ns", "obj", "rel", "subject")
                .await
                .is_err()
        );
        assert!(
            client
                .delete_relation_tuple("tenant-1", "ns", "obj", "rel", "subject")
                .await
                .is_err()
        );
        assert!(
            client
                .expand("tenant-1", "ns", "obj", "rel", &opts)
                .await
                .is_err()
        );
        assert!(
            client
                .expand_objects(
                    "tenant-1",
                    "ns",
                    "rel",
                    Some("subject"),
                    None,
                    None,
                    None,
                    None,
                    &opts,
                )
                .await
                .is_err()
        );
    }

    #[cfg(feature = "keto")]
    #[tokio::test]
    async fn keto_backend_rejects_unsupported_query_options() {
        let client = Arc::new(KetoClient::new("http://localhost:1", "http://localhost:1").unwrap())
            as Arc<dyn PermissionBackend>;
        let opts = QueryOptions {
            consistency: Some("higher_consistency".to_string()),
            ..Default::default()
        };
        let err = client
            .check_permission("tenant-1", "ns", "obj", "rel", "subject", &opts)
            .await
            .unwrap_err();
        assert!(matches!(err, PermissionBackendError::Configuration(_)));

        let opts = QueryOptions {
            context: Some(serde_json::json!({"ip": "10.0.0.1"})),
            ..Default::default()
        };
        let err = client
            .expand("tenant-1", "ns", "obj", "rel", &opts)
            .await
            .unwrap_err();
        assert!(matches!(err, PermissionBackendError::Configuration(_)));

        let err = client
            .list_users("tenant-1", "ns", "obj", "rel", &[], &QueryOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, PermissionBackendError::Configuration(_)));
    }

    #[tokio::test]
    async fn check_permission_requires_read_scope() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());
        let owned =
            crate::proto::iam::v1::CheckPermissionRequestOwnedView::from_owned(&check_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .check_permission(no_scope_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::PermissionDenied,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn check_permission_accepts_admin_scope() {
        let service = service_with(
            FakePermissionBackend {
                check_result: Ok(true),
                ..FakePermissionBackend::new()
            },
            FakeTupleStore::new(),
        );
        let owned =
            crate::proto::iam::v1::CheckPermissionRequestOwnedView::from_owned(&check_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let resp = service.check_permission(admin_ctx(), req).await.unwrap();
        assert!(resp.body.allowed);
    }

    #[tokio::test]
    async fn create_relation_tuple_requires_admin_scope() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());
        let owned =
            crate::proto::iam::v1::CreateRelationTupleRequestOwnedView::from_owned(&create_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .create_relation_tuple(tenant_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::PermissionDenied,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn delete_relation_tuple_requires_admin_scope() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());
        let owned =
            crate::proto::iam::v1::DeleteRelationTupleRequestOwnedView::from_owned(&delete_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .delete_relation_tuple(tenant_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::PermissionDenied,
                ..
            }
        ));
    }

    // -------------------------------------------------------------------------
    // Namespace lifecycle helpers
    // -------------------------------------------------------------------------

    fn rich_model(types: &[&str]) -> Value {
        let defs: Vec<Value> = types
            .iter()
            .map(|ty| {
                if *ty == "user" {
                    serde_json::json!({ "type": "user" })
                } else {
                    serde_json::json!({
                        "type": ty,
                        "relations": { "viewer": {} },
                        "metadata": {
                            "relations": {
                                "viewer": { "directly_related_user_types": [{ "type": "user" }] }
                            }
                        }
                    })
                }
            })
            .collect();
        serde_json::json!({
            "schema_version": "1.1",
            "type_definitions": defs,
        })
    }

    fn struct_field(value: Value) -> buffa_types::google::protobuf::Struct {
        json_to_struct(value).expect("model should convert to struct")
    }

    fn ensure_req(namespace: &str, model: Value) -> EnsurePermissionNamespaceRequest {
        EnsurePermissionNamespaceRequest {
            namespace: namespace.into(),
            model: Some(struct_field(model)).into(),
            ..Default::default()
        }
    }

    fn tuple_key(namespace: &str, object: &str, relation: &str, subject: &str) -> ProtoRelationTupleKey {
        ProtoRelationTupleKey {
            namespace: namespace.into(),
            object: object.into(),
            relation: relation.into(),
            subject_id: subject.into(),
            ..Default::default()
        }
    }

    // -------------------------------------------------------------------------
    // Helper function tests
    // -------------------------------------------------------------------------

    #[test]
    fn validate_namespace_name_accepts_valid_names() {
        assert!(validate_namespace_name("document").is_ok());
        assert!(validate_namespace_name("KanbanProject_2").is_ok());
        assert!(validate_namespace_name("a").is_ok());
        assert!(validate_namespace_name(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn validate_namespace_name_rejects_invalid_names() {
        for name in [
            "",
            "1document",
            "_document",
            "my-namespace",
            "my.namespace",
            "namespace with spaces",
            "café",
            &"a".repeat(129),
        ] {
            assert!(validate_namespace_name(name).is_err(), "expected {name:?} to fail");
        }
    }

    #[test]
    fn validate_model_requires_object_schema_version_and_types() {
        assert!(validate_and_normalize_model(serde_json::json!("nope")).is_err());
        assert!(validate_and_normalize_model(serde_json::json!({})).is_err());
        assert!(
            validate_and_normalize_model(
                serde_json::json!({ "schema_version": "", "type_definitions": [] })
            )
            .is_err()
        );
        assert!(
            validate_and_normalize_model(
                serde_json::json!({ "schema_version": "1.1", "type_definitions": [] })
            )
            .is_err()
        );
        assert!(
            validate_and_normalize_model(
                serde_json::json!({ "schema_version": "1.1", "type_definitions": [{}] })
            )
            .is_err()
        );
        assert!(
            validate_and_normalize_model(serde_json::json!({
                "schema_version": "1.1",
                "type_definitions": [{ "type": "1bad" }]
            }))
            .is_err()
        );
        assert!(
            validate_and_normalize_model(serde_json::json!({
                "schema_version": "1.1",
                "type_definitions": [{ "type": "doc" }, { "type": "doc" }]
            }))
            .is_err()
        );
    }

    #[test]
    fn validate_model_sorts_type_definitions() {
        let model = validate_and_normalize_model(serde_json::json!({
            "schema_version": "1.1",
            "type_definitions": [{ "type": "zebra" }, { "type": "alpha" }]
        }))
        .unwrap();
        let types: Vec<&str> = model
            .get("type_definitions")
            .and_then(|v| v.as_array())
            .unwrap()
            .iter()
            .filter_map(|def| def.get("type").and_then(|t| t.as_str()))
            .collect();
        assert_eq!(types, ["alpha", "zebra"]);
        assert_eq!(model_type_names(&model), vec!["alpha", "zebra"]);
    }

    #[test]
    fn tuple_key_from_proto_converts_condition_fields() {
        let key = ProtoRelationTupleKey {
            condition: "non_expired".into(),
            condition_context: Some(struct_field(serde_json::json!({ "now": "2026-01-01" })))
                .into(),
            ..tuple_key("ns", "obj", "viewer", "user:alice")
        };
        let converted = tuple_key_from_proto(key).unwrap();
        assert_eq!(converted.condition.as_deref(), Some("non_expired"));
        assert_eq!(
            converted.condition_context,
            Some(serde_json::json!({ "now": "2026-01-01" }))
        );

        let converted = tuple_key_from_proto(tuple_key("ns", "obj", "viewer", "user:alice")).unwrap();
        assert!(converted.condition.is_none());
        assert!(converted.condition_context.is_none());
    }

    #[test]
    fn tuple_key_from_proto_requires_all_fields() {
        let mut key = tuple_key("ns", "obj", "viewer", "user:alice");
        key.namespace = String::new();
        assert!(tuple_key_from_proto(key).is_err());
        let mut key = tuple_key("ns", "obj", "viewer", "user:alice");
        key.subject_id = String::new();
        assert!(tuple_key_from_proto(key).is_err());
    }

    #[test]
    fn query_options_from_parses_fields() {
        let opts = query_options_from(None, &[], "").unwrap();
        assert!(opts.is_default());

        let context = struct_field(serde_json::json!({ "ip": "10.0.0.1" }));
        let contextual = [tuple_key("ns", "obj", "viewer", "user:alice")];
        let opts =
            query_options_from(Some(&context), &contextual, "higher_consistency").unwrap();
        assert!(!opts.is_default());
        assert_eq!(opts.context, Some(serde_json::json!({ "ip": "10.0.0.1" })));
        assert_eq!(opts.contextual_tuples.len(), 1);
        assert_eq!(opts.consistency.as_deref(), Some("higher_consistency"));

        assert!(query_options_from(None, &[], "eventually").is_err());
    }

    #[test]
    fn page_token_round_trip() {
        let now = time::OffsetDateTime::now_utc();
        let token = encode_page_token(now, "01JABC");
        let (ts, id) = decode_page_token(&token).unwrap();
        assert_eq!(ts, now);
        assert_eq!(id, "01JABC");

        assert!(decode_page_token("not-base64!!!").is_err());
        assert!(
            decode_page_token(&base64::engine::general_purpose::STANDARD.encode("no-separator"))
                .is_err()
        );
        assert!(
            decode_page_token(
                &base64::engine::general_purpose::STANDARD.encode("notanumber:id")
            )
            .is_err()
        );
        assert!(
            decode_page_token(&base64::engine::general_purpose::STANDARD.encode("123:")).is_err()
        );
    }

    // -------------------------------------------------------------------------
    // ensure/get/list/delete_permission_namespace
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn ensure_namespace_registers_model_and_types() {
        let backend = FakePermissionBackend::new();
        let namespaces = MemoryNamespaceMappingRepo::default();
        let service = service_with_namespaces(backend.clone(), FakeTupleStore::new(), namespaces.clone());

        let owned = crate::proto::iam::v1::EnsurePermissionNamespaceRequestOwnedView::from_owned(
            &ensure_req("kanban", rich_model(&["user", "KanbanProject"])),
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service
            .ensure_permission_namespace(admin_ctx(), req)
            .await
            .unwrap();
        assert_eq!(resp.body.namespace, "kanban");
        assert_eq!(resp.body.tenant_id, "tenant-1");
        assert_eq!(resp.body.types, vec!["KanbanProject", "user"]);

        {
            let calls = backend.calls.lock().unwrap();
            assert!(
                matches!(&calls[0], BackendCall::EnsureModel { tenant_id, namespace, model } if
                    tenant_id == "tenant-1" && namespace == "kanban" &&
                    model.get("schema_version").and_then(|v| v.as_str()) == Some("1.1"))
            );
        }

        let record = namespaces.get("tenant-1", "kanban").await.unwrap().unwrap();
        assert_eq!(record.types, vec!["KanbanProject", "user"]);
        assert!(record.model.get("schema_version").is_some());
    }

    #[tokio::test]
    async fn ensure_namespace_is_idempotent_for_identical_model() {
        let backend = FakePermissionBackend::new();
        let service = service_with_namespaces(
            backend.clone(),
            FakeTupleStore::new(),
            MemoryNamespaceMappingRepo::default(),
        );

        for _ in 0..2 {
            let owned =
                crate::proto::iam::v1::EnsurePermissionNamespaceRequestOwnedView::from_owned(
                    &ensure_req("kanban", rich_model(&["user", "KanbanProject"])),
                )
                .unwrap();
            let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
            service
                .ensure_permission_namespace(admin_ctx(), req)
                .await
                .unwrap();
        }

        // The second call short-circuits before touching the backend.
        let calls = backend.calls.lock().unwrap();
        let ensure_calls = calls
            .iter()
            .filter(|c| matches!(c, BackendCall::EnsureModel { .. }))
            .count();
        assert_eq!(ensure_calls, 1);
    }

    #[tokio::test]
    async fn ensure_namespace_publishes_new_version_on_model_change() {
        let backend = FakePermissionBackend::new();
        let namespaces = MemoryNamespaceMappingRepo::default();
        let service = service_with_namespaces(backend.clone(), FakeTupleStore::new(), namespaces.clone());

        let owned = crate::proto::iam::v1::EnsurePermissionNamespaceRequestOwnedView::from_owned(
            &ensure_req("kanban", rich_model(&["user", "KanbanProject"])),
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        service
            .ensure_permission_namespace(admin_ctx(), req)
            .await
            .unwrap();

        let owned = crate::proto::iam::v1::EnsurePermissionNamespaceRequestOwnedView::from_owned(
            &ensure_req("kanban", rich_model(&["user", "KanbanProject", "KanbanCard"])),
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let resp = service
            .ensure_permission_namespace(admin_ctx(), req)
            .await
            .unwrap();
        assert_eq!(resp.body.types, vec!["KanbanCard", "KanbanProject", "user"]);

        let calls = backend.calls.lock().unwrap();
        let ensure_calls = calls
            .iter()
            .filter(|c| matches!(c, BackendCall::EnsureModel { .. }))
            .count();
        assert_eq!(ensure_calls, 2);
    }

    #[tokio::test]
    async fn ensure_namespace_validates_input() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());

        // Invalid namespace name.
        let owned = crate::proto::iam::v1::EnsurePermissionNamespaceRequestOwnedView::from_owned(
            &ensure_req("bad-name", rich_model(&["user"])),
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .ensure_permission_namespace(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::InvalidArgument,
                ..
            }
        ));

        // Missing model.
        let owned = crate::proto::iam::v1::EnsurePermissionNamespaceRequestOwnedView::from_owned(
            &EnsurePermissionNamespaceRequest {
                namespace: "kanban".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .ensure_permission_namespace(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::InvalidArgument,
                ..
            }
        ));

        // Malformed model.
        let owned = crate::proto::iam::v1::EnsurePermissionNamespaceRequestOwnedView::from_owned(
            &ensure_req("kanban", serde_json::json!({ "schema_version": "1.1" })),
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .ensure_permission_namespace(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::InvalidArgument,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn ensure_namespace_rejects_type_conflicts_across_namespaces() {
        let service = service_with_namespaces(
            FakePermissionBackend::new(),
            FakeTupleStore::new(),
            MemoryNamespaceMappingRepo::default(),
        );

        let owned = crate::proto::iam::v1::EnsurePermissionNamespaceRequestOwnedView::from_owned(
            &ensure_req("kanban", rich_model(&["user", "KanbanProject"])),
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        service
            .ensure_permission_namespace(admin_ctx(), req)
            .await
            .unwrap();

        // A different namespace claiming the same type conflicts.
        let owned = crate::proto::iam::v1::EnsurePermissionNamespaceRequestOwnedView::from_owned(
            &ensure_req("other", rich_model(&["user", "KanbanProject"])),
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .ensure_permission_namespace(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::AlreadyExists,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn namespace_lifecycle_requires_expected_scopes() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());

        let owned = crate::proto::iam::v1::EnsurePermissionNamespaceRequestOwnedView::from_owned(
            &ensure_req("kanban", rich_model(&["user"])),
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .ensure_permission_namespace(tenant_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::PermissionDenied,
                ..
            }
        ));

        let owned =
            crate::proto::iam::v1::DeletePermissionNamespaceRequestOwnedView::from_owned(
                &DeletePermissionNamespaceRequest {
                    namespace: "kanban".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .delete_permission_namespace(tenant_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::PermissionDenied,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn get_and_list_namespaces() {
        let namespaces = MemoryNamespaceMappingRepo::default();
        let service = service_with_namespaces(
            FakePermissionBackend::new(),
            FakeTupleStore::new(),
            namespaces.clone(),
        );
        namespaces
            .upsert(
                "tenant-1",
                &NamespaceRecord {
                    namespace: "kanban".into(),
                    model: rich_model(&["user", "KanbanProject"]),
                    types: vec!["KanbanProject".into(), "user".into()],
                    store_id: Some("store-1".into()),
                    model_id: Some("model-1".into()),
                    created_at: None,
                    updated_at: None,
                },
            )
            .await
            .unwrap();

        // Get with the read scope succeeds.
        let owned = crate::proto::iam::v1::GetPermissionNamespaceRequestOwnedView::from_owned(
            &GetPermissionNamespaceRequest {
                namespace: "kanban".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let resp = service
            .get_permission_namespace(tenant_ctx(), req)
            .await
            .unwrap();
        assert_eq!(resp.body.namespace, "kanban");
        assert_eq!(resp.body.types, vec!["KanbanProject", "user"]);

        // List returns everything registered for the tenant.
        let owned =
            crate::proto::iam::v1::ListPermissionNamespacesRequestOwnedView::from_owned(
                &ListPermissionNamespacesRequest::default(),
            )
            .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let resp = service
            .list_permission_namespaces(tenant_ctx(), req)
            .await
            .unwrap();
        assert_eq!(resp.body.namespaces.len(), 1);
        let page = resp.body.page.as_option().unwrap();
        assert_eq!(page.total_size, 1);

        // Get for an unknown namespace is NotFound.
        let owned = crate::proto::iam::v1::GetPermissionNamespaceRequestOwnedView::from_owned(
            &GetPermissionNamespaceRequest {
                namespace: "nope".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .get_permission_namespace(tenant_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::NotFound,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn delete_namespace_tears_down_backend_tuples_and_record() {
        let backend = FakePermissionBackend::new();
        let tuples = FakeTupleStore::new();
        let namespaces = MemoryNamespaceMappingRepo::default();
        let service = service_with_namespaces(backend.clone(), tuples.clone(), namespaces.clone());
        namespaces
            .upsert(
                "tenant-1",
                &NamespaceRecord {
                    namespace: "kanban".into(),
                    model: rich_model(&["user"]),
                    types: vec!["user".into()],
                    store_id: None,
                    model_id: None,
                    created_at: None,
                    updated_at: None,
                },
            )
            .await
            .unwrap();

        let owned =
            crate::proto::iam::v1::DeletePermissionNamespaceRequestOwnedView::from_owned(
                &DeletePermissionNamespaceRequest {
                    namespace: "kanban".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        service
            .delete_permission_namespace(admin_ctx(), req)
            .await
            .unwrap();

        {
            let backend_calls = backend.calls.lock().unwrap();
            assert!(
                matches!(&backend_calls[0], BackendCall::DeleteNamespace { tenant_id, namespace } if
                    tenant_id == "tenant-1" && namespace == "kanban")
            );
            let tuple_calls = tuples.calls.lock().unwrap();
            assert!(
                matches!(&tuple_calls[0], TupleCall::DeleteByNamespace { tenant_id, namespace } if
                    tenant_id == "tenant-1" && namespace == "kanban")
            );
        }
        assert!(namespaces.get("tenant-1", "kanban").await.unwrap().is_none());

        // Deleting an unknown namespace is NotFound.
        let owned =
            crate::proto::iam::v1::DeletePermissionNamespaceRequestOwnedView::from_owned(
                &DeletePermissionNamespaceRequest {
                    namespace: "kanban".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .delete_permission_namespace(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::NotFound,
                ..
            }
        ));
    }

    // -------------------------------------------------------------------------
    // write_relation_tuples
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn write_relation_tuples_batches_writes_and_deletes() {
        let backend = FakePermissionBackend::new();
        let tuples = FakeTupleStore::new();
        let service = service_with(backend.clone(), tuples.clone());

        let mut write = tuple_key("KanbanProject", "proj-1", "editor", "user:alice");
        write.condition = "non_expired".into();
        let request = WriteRelationTuplesRequest {
            writes: vec![write],
            deletes: vec![tuple_key("KanbanProject", "proj-1", "viewer", "user:bob")],
            ..Default::default()
        };
        let owned =
            crate::proto::iam::v1::WriteRelationTuplesRequestOwnedView::from_owned(&request)
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let resp = service
            .write_relation_tuples(admin_ctx(), req)
            .await
            .unwrap();
        assert_eq!(resp.body.written, 1);
        assert_eq!(resp.body.deleted, 1);

        let backend_calls = backend.calls.lock().unwrap();
        assert!(
            matches!(&backend_calls[0], BackendCall::WriteTuples { tenant_id, writes, deletes } if
                tenant_id == "tenant-1" &&
                writes.len() == 1 &&
                writes[0].namespace == "KanbanProject" &&
                writes[0].condition.as_deref() == Some("non_expired") &&
                deletes.len() == 1 &&
                deletes[0].subject_id == "user:bob")
        );

        let tuple_calls = tuples.calls.lock().unwrap();
        assert!(
            matches!(&tuple_calls[0], TupleCall::CreateMany { tenant_id, keys } if
                tenant_id == "tenant-1" && keys.len() == 1 && keys[0].namespace == "KanbanProject")
        );
        assert!(
            matches!(&tuple_calls[1], TupleCall::DeleteByKey { tenant_id, namespace, object, relation, subject_id } if
                tenant_id == "tenant-1" && namespace == "KanbanProject" &&
                object == "proj-1" && relation == "viewer" && subject_id == "user:bob")
        );
    }

    #[tokio::test]
    async fn write_relation_tuples_validates_batch() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());

        // Empty batch.
        let owned = crate::proto::iam::v1::WriteRelationTuplesRequestOwnedView::from_owned(
            &WriteRelationTuplesRequest::default(),
        )
        .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .write_relation_tuples(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::InvalidArgument,
                ..
            }
        ));

        // Oversized batch.
        let request = WriteRelationTuplesRequest {
            writes: (0..=MAX_BATCH_KEYS)
                .map(|i| tuple_key("ns", &format!("obj-{i}"), "viewer", "user:alice"))
                .collect(),
            deletes: Vec::new(),
            ..Default::default()
        };
        let owned =
            crate::proto::iam::v1::WriteRelationTuplesRequestOwnedView::from_owned(&request)
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .write_relation_tuples(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::InvalidArgument,
                ..
            }
        ));

        // Malformed key.
        let request = WriteRelationTuplesRequest {
            writes: vec![tuple_key("ns", "", "viewer", "user:alice")],
            deletes: Vec::new(),
            ..Default::default()
        };
        let owned =
            crate::proto::iam::v1::WriteRelationTuplesRequestOwnedView::from_owned(&request)
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .write_relation_tuples(admin_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::InvalidArgument,
                ..
            }
        ));

        // Requires the admin scope.
        let request = WriteRelationTuplesRequest {
            writes: vec![tuple_key("ns", "obj", "viewer", "user:alice")],
            deletes: Vec::new(),
            ..Default::default()
        };
        let owned =
            crate::proto::iam::v1::WriteRelationTuplesRequestOwnedView::from_owned(&request)
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .write_relation_tuples(tenant_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::PermissionDenied,
                ..
            }
        ));
    }

    // -------------------------------------------------------------------------
    // list_relation_tuples pagination
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn list_relation_tuples_paginates_with_keyset() {
        let tuples = FakeTupleStore {
            list_page_result: Ok((vec![sample_row(), sample_row()], 5)),
            ..FakeTupleStore::new()
        };
        let service = service_with(FakePermissionBackend::new(), tuples.clone());

        let request = ListRelationTuplesRequest {
            namespace: "ns".into(),
            page: Some(crate::proto::iam::v1::PageRequest {
                page_size: 2,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let owned =
            crate::proto::iam::v1::ListRelationTuplesRequestOwnedView::from_owned(&request)
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let resp = service
            .list_relation_tuples(tenant_ctx(), req)
            .await
            .unwrap();
        assert_eq!(resp.body.tuples.len(), 2);
        let page = resp.body.page.as_option().unwrap();
        assert_eq!(page.total_size, 5);
        assert!(!page.next_page_token.is_empty());

        // The cursor decodes and is forwarded on the next call.
        let request = ListRelationTuplesRequest {
            namespace: "ns".into(),
            page: Some(crate::proto::iam::v1::PageRequest {
                page_size: 2,
                page_token: page.next_page_token.clone(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let owned =
            crate::proto::iam::v1::ListRelationTuplesRequestOwnedView::from_owned(&request)
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        service
            .list_relation_tuples(tenant_ctx(), req)
            .await
            .unwrap();

        let calls = tuples.calls.lock().unwrap();
        assert!(
            matches!(&calls[0], TupleCall::ListPage { limit, has_cursor, .. } if
                *limit == 2 && !has_cursor)
        );
        assert!(
            matches!(&calls[1], TupleCall::ListPage { limit, has_cursor, .. } if
                *limit == 2 && *has_cursor)
        );
    }

    #[tokio::test]
    async fn list_relation_tuples_caps_page_size_and_validates_token() {
        let tuples = FakeTupleStore {
            list_page_result: Ok((Vec::new(), 0)),
            ..FakeTupleStore::new()
        };
        let service = service_with(FakePermissionBackend::new(), tuples.clone());

        let request = ListRelationTuplesRequest {
            page: Some(crate::proto::iam::v1::PageRequest {
                page_size: 10_000,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let owned =
            crate::proto::iam::v1::ListRelationTuplesRequestOwnedView::from_owned(&request)
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        service
            .list_relation_tuples(tenant_ctx(), req)
            .await
            .unwrap();
        {
            let calls = tuples.calls.lock().unwrap();
            assert!(
                matches!(&calls[0], TupleCall::ListPage { limit, .. } if *limit == MAX_PAGE_SIZE)
            );
        }

        let request = ListRelationTuplesRequest {
            page: Some(crate::proto::iam::v1::PageRequest {
                page_token: "bogus-token".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let owned =
            crate::proto::iam::v1::ListRelationTuplesRequestOwnedView::from_owned(&request)
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .list_relation_tuples(tenant_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::InvalidArgument,
                ..
            }
        ));
    }

    // -------------------------------------------------------------------------
    // list_users and query option forwarding
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn list_users_forwards_filters_and_options() {
        let backend = FakePermissionBackend {
            list_users_result: Ok(vec!["user:alice".into(), "team:eng#member".into()]),
            ..FakePermissionBackend::new()
        };
        let service = service_with(backend.clone(), FakeTupleStore::new());

        let request = ListUsersRequest {
            namespace: "KanbanProject".into(),
            object: "proj-1".into(),
            relation: "editor".into(),
            user_type_filters: vec!["user".into()],
            consistency: "higher_consistency".into(),
            ..Default::default()
        };
        let owned = crate::proto::iam::v1::ListUsersRequestOwnedView::from_owned(&request).unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let resp = service.list_users(tenant_ctx(), req).await.unwrap();
        assert_eq!(resp.body.users, vec!["user:alice", "team:eng#member"]);

        let calls = backend.calls.lock().unwrap();
        assert!(
            matches!(&calls[0], BackendCall::ListUsers { tenant_id, namespace, object, relation, user_type_filters } if
                tenant_id == "tenant-1" &&
                namespace == "KanbanProject" &&
                object == "proj-1" &&
                relation == "editor" &&
                user_type_filters == &vec!["user".to_string()])
        );
        let opts = backend.opts_log.lock().unwrap();
        assert_eq!(opts[0].consistency.as_deref(), Some("higher_consistency"));
    }

    #[tokio::test]
    async fn check_permission_forwards_context_and_contextual_tuples() {
        let backend = FakePermissionBackend {
            check_result: Ok(true),
            ..FakePermissionBackend::new()
        };
        let service = service_with(backend.clone(), FakeTupleStore::new());

        let request = CheckPermissionRequest {
            context: Some(struct_field(serde_json::json!({ "now": "2026-01-01" }))).into(),
            contextual_tuples: vec![tuple_key("ns", "obj", "viewer", "user:alice")],
            consistency: "minimize_latency".into(),
            ..check_req()
        };
        let owned =
            crate::proto::iam::v1::CheckPermissionRequestOwnedView::from_owned(&request).unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        service.check_permission(tenant_ctx(), req).await.unwrap();

        let opts = backend.opts_log.lock().unwrap();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].context, Some(serde_json::json!({ "now": "2026-01-01" })));
        assert_eq!(opts[0].contextual_tuples.len(), 1);
        assert_eq!(opts[0].consistency.as_deref(), Some("minimize_latency"));
    }

    #[tokio::test]
    async fn check_permission_rejects_unknown_consistency() {
        let service = service_with(FakePermissionBackend::new(), FakeTupleStore::new());
        let request = CheckPermissionRequest {
            consistency: "eventually".into(),
            ..check_req()
        };
        let owned =
            crate::proto::iam::v1::CheckPermissionRequestOwnedView::from_owned(&request).unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());
        let err = service
            .check_permission(tenant_ctx(), req)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            connectrpc::ConnectError {
                code: connectrpc::ErrorCode::InvalidArgument,
                ..
            }
        ));
    }

    // -------------------------------------------------------------------------
    // Memory namespace repo
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn memory_namespace_repo_resolves_by_type_and_isolates_tenants() {
        let repo = MemoryNamespaceMappingRepo::default();
        repo.upsert(
            "tenant-1",
            &NamespaceRecord {
                namespace: "kanban".into(),
                model: rich_model(&["user", "KanbanProject"]),
                types: vec!["KanbanProject".into(), "user".into()],
                store_id: None,
                model_id: None,
                created_at: None,
                updated_at: None,
            },
        )
        .await
        .unwrap();

        // Type resolution finds the owning namespace.
        let record = repo.get_by_type("tenant-1", "KanbanProject").await.unwrap().unwrap();
        assert_eq!(record.namespace, "kanban");
        // Unknown types fall back to a direct namespace lookup.
        assert!(repo.get_by_type("tenant-1", "kanban").await.unwrap().is_some());
        assert!(repo.get_by_type("tenant-1", "unknown").await.unwrap().is_none());
        // Records are isolated per tenant.
        assert!(repo.get("tenant-2", "kanban").await.unwrap().is_none());
        assert!(repo.list("tenant-2").await.unwrap().is_empty());

        // Metadata-only upserts preserve provisioned ids.
        repo.upsert(
            "tenant-1",
            &NamespaceRecord {
                namespace: "kanban".into(),
                model: rich_model(&["user", "KanbanProject"]),
                types: vec!["KanbanProject".into(), "user".into()],
                store_id: Some("store-1".into()),
                model_id: Some("model-1".into()),
                created_at: None,
                updated_at: None,
            },
        )
        .await
        .unwrap();
        let record = repo
            .upsert(
                "tenant-1",
                &NamespaceRecord {
                    namespace: "kanban".into(),
                    model: rich_model(&["user"]),
                    types: vec!["user".into()],
                    store_id: None,
                    model_id: None,
                    created_at: None,
                    updated_at: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(record.store_id.as_deref(), Some("store-1"));
        assert_eq!(record.model_id.as_deref(), Some("model-1"));

        repo.delete("tenant-1", "kanban").await.unwrap();
        assert!(repo.get("tenant-1", "kanban").await.unwrap().is_none());
    }

    // -------------------------------------------------------------------------
    // OpenFGA backend unit tests
    // -------------------------------------------------------------------------

    #[cfg(feature = "openfga")]
    mod openfga_backend {
        use axum::{
            Json, Router,
            extract::{Path, State},
            http::StatusCode,
            routing::{get, post},
        };
        use serde_json::{Value, json};
        use std::sync::{Arc, Mutex};

        use super::*;

        #[derive(Clone, Default)]
        struct FakeOpenFgaState {
            stores: Arc<Mutex<Vec<Value>>>,
            models: Arc<Mutex<Vec<Value>>>,
            tuples: Arc<Mutex<Vec<Value>>>,
        }

        fn fake_openfga_app(state: FakeOpenFgaState) -> Router {
            Router::new()
                .route("/stores", post(create_store).get(list_stores))
                .route("/stores/{store_id}", get(get_store).delete(delete_store))
                .route(
                    "/stores/{store_id}/authorization-models",
                    post(write_model).get(list_models),
                )
                .route(
                    "/stores/{store_id}/authorization-models/{model_id}",
                    get(get_model),
                )
                .route("/stores/{store_id}/write", post(write_tuple))
                .route("/stores/{store_id}/check", post(check))
                .route("/stores/{store_id}/expand", post(expand))
                .route("/stores/{store_id}/list-objects", post(list_objects))
                .with_state(state)
        }

        async fn create_store(
            State(state): State<FakeOpenFgaState>,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            let id = format!("store-{}", state.stores.lock().unwrap().len());
            let store = json!({ "id": id, "name": body["name"] });
            state.stores.lock().unwrap().push(store.clone());
            Json(store)
        }

        async fn list_stores(State(state): State<FakeOpenFgaState>) -> Json<Value> {
            let stores = state.stores.lock().unwrap().clone();
            Json(json!({ "stores": stores }))
        }

        async fn get_store(
            State(state): State<FakeOpenFgaState>,
            Path(store_id): Path<String>,
        ) -> Json<Value> {
            let stores = state.stores.lock().unwrap();
            let store = stores
                .iter()
                .find(|s| s.get("id").and_then(|v| v.as_str()) == Some(&store_id))
                .cloned()
                .unwrap_or_else(|| json!({ "id": store_id, "name": "unknown" }));
            Json(store)
        }

        async fn delete_store(
            State(state): State<FakeOpenFgaState>,
            Path(store_id): Path<String>,
        ) -> StatusCode {
            let mut stores = state.stores.lock().unwrap();
            stores.retain(|s| s.get("id").and_then(|v| v.as_str()) != Some(&store_id));
            StatusCode::NO_CONTENT
        }

        async fn write_model(
            State(state): State<FakeOpenFgaState>,
            Path(store_id): Path<String>,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            let model_id = format!("model-{}", state.models.lock().unwrap().len());
            let model = json!({
                "authorization_model_id": model_id,
                "store_id": store_id,
                "schema_version": body["schema_version"],
                "type_definitions": body["type_definitions"],
            });
            state.models.lock().unwrap().push(model.clone());
            Json(json!({ "authorization_model_id": model_id }))
        }

        async fn list_models(State(state): State<FakeOpenFgaState>) -> Json<Value> {
            let models = state.models.lock().unwrap().clone();
            Json(json!({ "authorization_models": models }))
        }

        async fn get_model(
            State(state): State<FakeOpenFgaState>,
            Path((_, model_id)): Path<(String, String)>,
        ) -> Json<Value> {
            let models = state.models.lock().unwrap();
            let model = models
                .iter()
                .find(|m| {
                    m.get("authorization_model_id").and_then(|v| v.as_str()) == Some(&model_id)
                })
                .cloned()
                .unwrap_or_default();
            Json(model)
        }

        async fn write_tuple(
            State(state): State<FakeOpenFgaState>,
            Path(store_id): Path<String>,
            Json(body): Json<Value>,
        ) -> StatusCode {
            if let Some(writes) = body.get("writes").and_then(|w| w.get("tuple_keys")) {
                for tuple in writes.as_array().unwrap_or(&vec![]) {
                    let mut t = tuple.clone();
                    t["store_id"] = json!(store_id);
                    state.tuples.lock().unwrap().push(t);
                }
            }
            if let Some(deletes) = body.get("deletes").and_then(|d| d.get("tuple_keys")) {
                let keys = deletes.as_array().unwrap_or(&vec![]).clone();
                let mut tuples = state.tuples.lock().unwrap();
                for key in keys {
                    tuples.retain(|t| {
                        t.get("user") != key.get("user")
                            || t.get("relation") != key.get("relation")
                            || t.get("object") != key.get("object")
                    });
                }
            }
            StatusCode::OK
        }

        async fn check(
            State(state): State<FakeOpenFgaState>,
            Path(store_id): Path<String>,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            let key = body.get("tuple_key").cloned().unwrap_or_default();
            let user = key.get("user").and_then(|v| v.as_str()).unwrap_or("");
            let relation = key.get("relation").and_then(|v| v.as_str()).unwrap_or("");
            let object = key.get("object").and_then(|v| v.as_str()).unwrap_or("");
            let allowed = state.tuples.lock().unwrap().iter().any(|t| {
                t.get("store_id").and_then(|v| v.as_str()) == Some(&store_id)
                    && t.get("user").and_then(|v| v.as_str()) == Some(user)
                    && t.get("relation").and_then(|v| v.as_str()) == Some(relation)
                    && t.get("object").and_then(|v| v.as_str()) == Some(object)
            });
            Json(json!({ "allowed": allowed }))
        }

        async fn expand(Json(_): Json<Value>) -> Json<Value> {
            Json(json!({ "tree": { "root": {} } }))
        }

        async fn list_objects(
            State(state): State<FakeOpenFgaState>,
            Path(store_id): Path<String>,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            let user = body.get("user").and_then(|v| v.as_str()).unwrap_or("");
            let relation = body.get("relation").and_then(|v| v.as_str()).unwrap_or("");
            let objects: Vec<String> = state
                .tuples
                .lock()
                .unwrap()
                .iter()
                .filter(|t| {
                    t.get("store_id").and_then(|v| v.as_str()) == Some(&store_id)
                        && t.get("user").and_then(|v| v.as_str()) == Some(user)
                        && t.get("relation").and_then(|v| v.as_str()) == Some(relation)
                })
                .filter_map(|t| t.get("object").and_then(|v| v.as_str()).map(String::from))
                .collect();
            Json(json!({ "objects": objects }))
        }

        async fn start_fake_openfga() -> (tokio::task::JoinHandle<()>, String) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let state = FakeOpenFgaState::default();
            let handle = tokio::spawn(async move {
                axum::serve(listener, fake_openfga_app(state))
                    .await
                    .unwrap();
            });
            (handle, format!("http://{addr}"))
        }

        #[tokio::test]
        async fn openfga_backend_ensure_namespace_creates_store_and_model() {
            let (_handle, url) = start_fake_openfga().await;
            let client = sso_openfga_client::OpenFgaClient::new(&url).unwrap();
            let mappings: Arc<dyn NamespaceMappingRepo> =
                Arc::new(MemoryNamespaceMappingRepo::default());
            let backend = OpenFgaPermissionBackend::new(client, mappings);

            backend
                .ensure_namespace("tenant-1", "document", &["reader".into()])
                .await
                .unwrap();

            let mapping = backend
                .resolve_mapping("tenant-1", "document")
                .await
                .unwrap();
            assert!(
                mapping
                    .store_id
                    .as_deref()
                    .is_some_and(|id| id.starts_with("store-"))
            );
            assert!(
                mapping
                    .model_id
                    .as_deref()
                    .is_some_and(|id| id.starts_with("model-"))
            );
        }

        #[tokio::test]
        async fn openfga_backend_tuple_lifecycle() {
            let (_handle, url) = start_fake_openfga().await;
            let client = sso_openfga_client::OpenFgaClient::new(&url).unwrap();
            let mappings: Arc<dyn NamespaceMappingRepo> =
                Arc::new(MemoryNamespaceMappingRepo::default());
            let backend = OpenFgaPermissionBackend::new(client, mappings);
            let opts = QueryOptions::default();

            backend
                .ensure_namespace("tenant-1", "document", &["reader".into()])
                .await
                .unwrap();

            assert!(
                !backend
                    .check_permission("tenant-1", "document", "doc-1", "reader", "user:alice", &opts)
                    .await
                    .unwrap()
            );

            backend
                .create_relation_tuple("tenant-1", "document", "doc-1", "reader", "user:alice")
                .await
                .unwrap();

            assert!(
                backend
                    .check_permission("tenant-1", "document", "doc-1", "reader", "user:alice", &opts)
                    .await
                    .unwrap()
            );

            let objects = backend
                .expand_objects(
                    "tenant-1",
                    "document",
                    "reader",
                    Some("user:alice"),
                    None,
                    None,
                    None,
                    None,
                    &opts,
                )
                .await
                .unwrap();
            let tuples = objects.get("relation_tuples").and_then(|v| v.as_array());
            assert!(tuples.is_some());
            assert_eq!(tuples.unwrap().len(), 1);

            backend
                .delete_relation_tuple("tenant-1", "document", "doc-1", "reader", "user:alice")
                .await
                .unwrap();

            assert!(
                !backend
                    .check_permission("tenant-1", "document", "doc-1", "reader", "user:alice", &opts)
                    .await
                    .unwrap()
            );
        }

        #[tokio::test]
        async fn openfga_backend_unconfigured_namespace_returns_error() {
            let (_handle, url) = start_fake_openfga().await;
            let client = sso_openfga_client::OpenFgaClient::new(&url).unwrap();
            let mappings: Arc<dyn NamespaceMappingRepo> =
                Arc::new(MemoryNamespaceMappingRepo::default());
            let backend = OpenFgaPermissionBackend::new(client, mappings);

            let err = backend
                .check_permission(
                    "tenant-1",
                    "document",
                    "doc-1",
                    "reader",
                    "user:alice",
                    &QueryOptions::default(),
                )
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                PermissionBackendError::NamespaceNotConfigured(_)
            ));
        }
    }
}
