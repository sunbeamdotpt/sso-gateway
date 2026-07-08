use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use buffa_types::google::protobuf::Empty;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sso_ory_client::error::OryClientError;
#[cfg(feature = "keto")]
use sso_ory_client::keto::KetoClient;
use sunbeam_g2v::error::ServiceError;
use tracing::instrument;

use crate::{
    auth::{AuthContext, SCOPE_PERMISSION_ADMIN, SCOPE_PERMISSION_READ, require_scope},
    db::{PermissionTupleRepo, PermissionTupleRow, PermissionTupleStore},
    middleware::TenantId,
    proto::iam::v1::{
        CheckPermissionRequest, CheckPermissionResponse, CreateRelationTupleRequest,
        DeleteRelationTupleRequest, ExpandObjectsRequest, ExpandObjectsResponse,
        ExpandPermissionsRequest, ExpandPermissionsResponse, ListRelationTuplesRequest,
        ListRelationTuplesResponse, PermissionService, RelationTuple,
    },
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

    async fn expand(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
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
    ) -> Result<Value, PermissionBackendError>;

    /// Ensure that a namespace exists for the tenant, creating any required
    /// backend resources (store, authorization model) if necessary.
    ///
    /// The `relations` hint is used by OpenFGA when authoring a new model;
    /// Keto ignores it because namespaces are not pre-declared.
    async fn ensure_namespace(
        &self,
        tenant_id: &str,
        namespace: &str,
        relations: &[String],
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
    ) -> Result<bool, PermissionBackendError> {
        Ok(self
            .check_permission(namespace, &tenant_object(tenant_id, object), relation, subject_id)
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
            .create_relation_tuple(namespace, &tenant_object(tenant_id, object), relation, subject_id)
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
            .delete_relation_tuple(namespace, &tenant_object(tenant_id, object), relation, subject_id)
            .await?)
    }

    async fn expand(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
    ) -> Result<Value, PermissionBackendError> {
        Ok(self.expand(namespace, &tenant_object(tenant_id, object), relation).await?)
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
    ) -> Result<Value, PermissionBackendError> {
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

    async fn ensure_namespace(
        &self,
        _tenant_id: &str,
        _namespace: &str,
        _relations: &[String],
    ) -> Result<(), PermissionBackendError> {
        // Keto namespaces do not need to be pre-provisioned.
        Ok(())
    }
}

/// Mapping from a gateway tenant namespace to a backend store/model pair.
#[derive(Clone, Debug)]
pub struct NamespaceMapping {
    pub store_id: String,
    pub model_id: String,
}

/// Repository that resolves and stores namespace mappings for the OpenFGA backend.
#[async_trait]
pub trait NamespaceMappingRepo: Send + Sync + 'static {
    async fn get(
        &self,
        tenant_id: &str,
        namespace: &str,
    ) -> Result<Option<NamespaceMapping>, PermissionBackendError>;

    async fn set(
        &self,
        tenant_id: &str,
        namespace: &str,
        mapping: NamespaceMapping,
    ) -> Result<(), PermissionBackendError>;
}

/// In-memory namespace mapping repo intended for tests and for bootstrapping
/// before the real persistence layer is wired.
#[derive(Clone, Default)]
pub struct MemoryNamespaceMappingRepo {
    mappings: Arc<Mutex<HashMap<(String, String), NamespaceMapping>>>,
}

#[async_trait]
impl NamespaceMappingRepo for MemoryNamespaceMappingRepo {
    async fn get(
        &self,
        tenant_id: &str,
        namespace: &str,
    ) -> Result<Option<NamespaceMapping>, PermissionBackendError> {
        let lock = self.mappings.lock().unwrap();
        Ok(lock.get(&(tenant_id.to_string(), namespace.to_string())).cloned())
    }

    async fn set(
        &self,
        tenant_id: &str,
        namespace: &str,
        mapping: NamespaceMapping,
    ) -> Result<(), PermissionBackendError> {
        let mut lock = self.mappings.lock().unwrap();
        lock.insert(
            (tenant_id.to_string(), namespace.to_string()),
            mapping,
        );
        Ok(())
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
    ) -> Result<NamespaceMapping, PermissionBackendError> {
        self.mappings
            .get(tenant_id, namespace)
            .await?
            .ok_or_else(|| {
                PermissionBackendError::NamespaceNotConfigured(format!(
                    "tenant {tenant_id} namespace {namespace} has no OpenFGA store/model"
                ))
            })
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
    ) -> Result<bool, PermissionBackendError> {
        let mapping = self.resolve_mapping(tenant_id, namespace).await?;
        Ok(self
            .client
            .check(
                &mapping.store_id,
                &mapping.model_id,
                namespace,
                object,
                relation,
                &typed_user(subject_id),
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
        let mapping = self.resolve_mapping(tenant_id, namespace).await?;
        self.client
            .write_tuple(
                &mapping.store_id,
                &mapping.model_id,
                namespace,
                object,
                relation,
                &typed_user(subject_id),
                sso_openfga_client::WriteTupleOp::Insert,
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
        let mapping = self.resolve_mapping(tenant_id, namespace).await?;
        self.client
            .write_tuple(
                &mapping.store_id,
                &mapping.model_id,
                namespace,
                object,
                relation,
                &typed_user(subject_id),
                sso_openfga_client::WriteTupleOp::Delete,
            )
            .await?;
        Ok(())
    }

    async fn expand(
        &self,
        tenant_id: &str,
        namespace: &str,
        object: &str,
        relation: &str,
    ) -> Result<Value, PermissionBackendError> {
        let mapping = self.resolve_mapping(tenant_id, namespace).await?;
        Ok(self
            .client
            .expand(
                &mapping.store_id,
                &mapping.model_id,
                namespace,
                object,
                relation,
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
    ) -> Result<Value, PermissionBackendError> {
        // OpenFGA list-objects only supports a direct user subject.
        let user = subject_id.ok_or_else(|| {
            PermissionBackendError::Configuration(
                "OpenFGA expand_objects requires a subject_id".to_string(),
            )
        })?;
        let mapping = self.resolve_mapping(tenant_id, namespace).await?;
        let typed = typed_user(user);
        let objects = self
            .client
            .list_objects(
                &mapping.store_id,
                &mapping.model_id,
                namespace,
                relation,
                &typed,
            )
            .await?;
        Ok(serde_json::json!({ "relation_tuples": objects.iter().map(|o| {
            serde_json::json!({
                "namespace": namespace,
                "object": o,
                "relation": relation,
                "subject_id": user,
            })
        }).collect::<Vec<_>>() }))
    }

    async fn ensure_namespace(
        &self,
        tenant_id: &str,
        namespace: &str,
        relations: &[String],
    ) -> Result<(), PermissionBackendError> {
        if self.resolve_mapping(tenant_id, namespace).await.is_ok() {
            return Ok(());
        }

        let store_name = format!("{tenant_id}-{namespace}");
        let store_id = self.client.create_store(&store_name).await?;
        let model_id = self
            .client
            .write_authorization_model(&store_id, namespace, relations)
            .await?;

        self.mappings
            .set(
                tenant_id,
                namespace,
                NamespaceMapping {
                    store_id,
                    model_id,
                },
            )
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PermissionServiceImpl {
    backend: Arc<dyn PermissionBackend>,
    tuples: Arc<dyn PermissionTupleStore>,
}

impl PermissionServiceImpl {
    pub fn new(backend: Arc<dyn PermissionBackend>, tuples: PermissionTupleRepo) -> Self {
        Self {
            backend,
            tuples: Arc::new(tuples) as Arc<dyn PermissionTupleStore>,
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
        let allowed = self
            .backend
            .check_permission(
                &tenant_id,
                &req.namespace,
                &req.object,
                &req.relation,
                &req.subject_id,
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

        let expanded = self
            .backend
            .expand(&tenant_id, &req.namespace, &req.object, &req.relation)
            .await?;

        let tree = serde_json::to_string(&expanded).unwrap_or_default();
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
            )
            .await?;

        let objects = expanded
            .get("relation_tuples")
            .and_then(|v| v.as_array())
            .map(|tuples| {
                tuples
                    .iter()
                    .filter_map(|tuple| tuple.get("object").and_then(|o| o.as_str()))
                    .filter_map(|object| strip_tenant_object_prefix(&tenant_id, object))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let tree = serde_json::to_string(&expanded).unwrap_or_default();
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
        let rows = self
            .tuples
            .list(
                &tenant_id,
                namespace_filter(&req.namespace),
                object_filter(&req.object),
                relation_filter(&req.relation),
            )
            .await?;

        let tuples = rows.into_iter().map(|r| r.into_proto()).collect();
        Ok(Response::new(ListRelationTuplesResponse {
            tuples,
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
    object
        .strip_prefix(&prefix)
        .map(|rest| rest.to_string())
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
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn max_depth_filter(max_depth: i32) -> Option<i32> {
    if max_depth <= 0 {
        None
    } else {
        Some(max_depth)
    }
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
    use std::sync::Mutex;

    use super::*;
    use crate::db::DbError;

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
        calls: Arc<Mutex<Vec<BackendCall>>>,
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
    }

    impl FakePermissionBackend {
        fn new() -> Self {
            Self {
                check_result: Ok(false),
                create_result: Ok(Value::Null),
                delete_result: Ok(()),
                expand_result: Ok(Value::Null),
                expand_objects_result: Ok(Value::Null),
                calls: Arc::new(Mutex::new(Vec::new())),
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
        ) -> Result<bool, PermissionBackendError> {
            self.calls.lock().unwrap().push(BackendCall::Check {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
                subject_id: subject_id.into(),
            });
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
        ) -> Result<Value, PermissionBackendError> {
            self.calls.lock().unwrap().push(BackendCall::Expand {
                tenant_id: tenant_id.into(),
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
            });
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
        ) -> Result<Value, PermissionBackendError> {
            self.calls
                .lock()
                .unwrap()
                .push(BackendCall::ExpandObjects {
                    tenant_id: tenant_id.into(),
                    namespace: namespace.into(),
                    relation: relation.into(),
                    subject_id: subject_id.map(Into::into),
                    subject_set_namespace: subject_set_namespace.map(Into::into),
                    subject_set_object: subject_set_object.map(Into::into),
                    subject_set_relation: subject_set_relation.map(Into::into),
                    max_depth,
                });
            self.expand_objects_result.clone().map_err(Into::into)
        }

        async fn ensure_namespace(
            &self,
            _tenant_id: &str,
            _namespace: &str,
            _relations: &[String],
        ) -> Result<(), PermissionBackendError> {
            Ok(())
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
        Get,
        Delete {
            tenant_id: String,
            id: String,
        },
        List {
            tenant_id: String,
            namespace: Option<String>,
            object: Option<String>,
            relation: Option<String>,
        },
    }

    impl FakeTupleStore {
        fn new() -> Self {
            Self {
                create_result: Err(TupleError::NotFound),
                get_result: Err(TupleError::NotFound),
                delete_result: Ok(()),
                list_result: Ok(Vec::new()),
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
            tenant_id: &str,
            namespace: Option<&str>,
            object: Option<&str>,
            relation: Option<&str>,
        ) -> Result<Vec<PermissionTupleRow>, DbError> {
            self.calls.lock().unwrap().push(TupleCall::List {
                tenant_id: tenant_id.into(),
                namespace: namespace.map(Into::into),
                object: object.map(Into::into),
                relation: relation.map(Into::into),
            });
            self.list_result.clone().map_err(Into::into)
        }
    }

    fn service_with(
        backend: FakePermissionBackend,
        tuples: FakeTupleStore,
    ) -> PermissionServiceImpl {
        PermissionServiceImpl {
            backend: Arc::new(backend) as Arc<dyn PermissionBackend>,
            tuples: Arc::new(tuples) as Arc<dyn PermissionTupleStore>,
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
        let owned =
            crate::proto::iam::v1::ExpandObjectsRequestOwnedView::from_owned(&req).unwrap();
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
        let owned =
            crate::proto::iam::v1::ExpandObjectsRequestOwnedView::from_owned(&req).unwrap();
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
            list_result: Ok(vec![sample_row()]),
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
            matches!(&calls[0], TupleCall::List { tenant_id, namespace, object, relation } if
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
            list_result: Err(TupleError::Database),
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
        assert!(
            client
                .check_permission("tenant-1", "ns", "obj", "rel", "subject")
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
        assert!(client.expand("tenant-1", "ns", "obj", "rel").await.is_err());
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
                )
                .await
                .is_err()
        );
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
                    m.get("authorization_model_id")
                        .and_then(|v| v.as_str())
                        == Some(&model_id)
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
            let allowed = state
                .tuples
                .lock()
                .unwrap()
                .iter()
                .any(|t| {
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
                axum::serve(listener, fake_openfga_app(state)).await.unwrap();
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
            assert!(mapping.store_id.starts_with("store-"));
            assert!(mapping.model_id.starts_with("model-"));
        }

        #[tokio::test]
        async fn openfga_backend_tuple_lifecycle() {
            let (_handle, url) = start_fake_openfga().await;
            let client = sso_openfga_client::OpenFgaClient::new(&url).unwrap();
            let mappings: Arc<dyn NamespaceMappingRepo> =
                Arc::new(MemoryNamespaceMappingRepo::default());
            let backend = OpenFgaPermissionBackend::new(client, mappings);

            backend
                .ensure_namespace("tenant-1", "document", &["reader".into()])
                .await
                .unwrap();

            assert!(
                !backend
                    .check_permission("tenant-1", "document", "doc-1", "reader", "user:alice")
                    .await
                    .unwrap()
            );

            backend
                .create_relation_tuple(
                    "tenant-1",
                    "document",
                    "doc-1",
                    "reader",
                    "user:alice",
                )
                .await
                .unwrap();

            assert!(
                backend
                    .check_permission("tenant-1", "document", "doc-1", "reader", "user:alice")
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
                )
                .await
                .unwrap();
            let tuples = objects.get("relation_tuples").and_then(|v| v.as_array());
            assert!(tuples.is_some());
            assert_eq!(tuples.unwrap().len(), 1);

            backend
                .delete_relation_tuple(
                    "tenant-1",
                    "document",
                    "doc-1",
                    "reader",
                    "user:alice",
                )
                .await
                .unwrap();

            assert!(
                !backend
                    .check_permission("tenant-1", "document", "doc-1", "reader", "user:alice")
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
                .check_permission("tenant-1", "document", "doc-1", "reader", "user:alice")
                .await
                .unwrap_err();
            assert!(matches!(err, PermissionBackendError::NamespaceNotConfigured(_)));
        }
    }
}
