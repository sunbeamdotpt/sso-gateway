use std::sync::Arc;

use async_trait::async_trait;
use buffa_types::google::protobuf::Empty;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sso_ory_client::{error::OryClientError, keto::KetoClient};
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

/// Async trait abstracting the Keto operations used by the permission service.
#[async_trait]
trait PermissionKeto: Send + Sync + 'static {
    async fn check_permission(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<bool, OryClientError>;

    async fn create_relation_tuple(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<Value, OryClientError>;

    async fn delete_relation_tuple(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<(), OryClientError>;

    async fn expand(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
    ) -> Result<Value, OryClientError>;

    async fn expand_objects(
        &self,
        namespace: &str,
        relation: &str,
        query: &sso_ory_client::keto::ExpandObjectsQuery<'_>,
    ) -> Result<Value, OryClientError>;
}

#[async_trait]
impl PermissionKeto for KetoClient {
    async fn check_permission(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<bool, OryClientError> {
        self.check_permission(namespace, object, relation, subject_id)
            .await
    }

    async fn create_relation_tuple(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<Value, OryClientError> {
        self.create_relation_tuple(namespace, object, relation, subject_id)
            .await
    }

    async fn delete_relation_tuple(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
        subject_id: &str,
    ) -> Result<(), OryClientError> {
        self.delete_relation_tuple(namespace, object, relation, subject_id)
            .await
    }

    async fn expand(
        &self,
        namespace: &str,
        object: &str,
        relation: &str,
    ) -> Result<Value, OryClientError> {
        self.expand(namespace, object, relation).await
    }

    async fn expand_objects(
        &self,
        namespace: &str,
        relation: &str,
        query: &sso_ory_client::keto::ExpandObjectsQuery<'_>,
    ) -> Result<Value, OryClientError> {
        self.expand_objects(namespace, relation, query).await
    }
}

#[derive(Clone)]
pub struct PermissionServiceImpl {
    keto: Arc<dyn PermissionKeto>,
    tuples: Arc<dyn PermissionTupleStore>,
}

impl PermissionServiceImpl {
    pub fn new(keto: Arc<KetoClient>, tuples: PermissionTupleRepo) -> Self {
        Self {
            keto: keto as Arc<dyn PermissionKeto>,
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
            .keto
            .check_permission(
                &req.namespace,
                &tenant_object(&tenant_id, &req.object),
                &req.relation,
                &req.subject_id,
            )
            .await
            .map_err(map_ory_error)?;
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
        let object = tenant_object(&tenant_id, &req.object);

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

        self.keto
            .create_relation_tuple(&req.namespace, &object, &req.relation, &req.subject_id)
            .await
            .map_err(map_ory_error)?;

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
        let object = tenant_object(&tenant_id, &row.object);

        self.keto
            .delete_relation_tuple(&row.namespace, &object, &row.relation, &row.subject_id)
            .await
            .map_err(map_ory_error)?;

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
        let object = tenant_object(&tenant_id, &req.object);

        let expanded = self
            .keto
            .expand(&req.namespace, &object, &req.relation)
            .await
            .map_err(map_ory_error)?;

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

        let query = sso_ory_client::keto::ExpandObjectsQuery {
            subject_id: subject_id_filter(&req.subject_id),
            subject_set_namespace: subject_set_filter(&req.subject_set_namespace),
            subject_set_object: subject_set_filter(&req.subject_set_object),
            subject_set_relation: subject_set_filter(&req.subject_set_relation),
            max_depth: max_depth_filter(req.max_depth),
        };
        let expanded = self
            .keto
            .expand_objects(&req.namespace, &req.relation, &query)
            .await
            .map_err(map_ory_error)?;

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
    enum KetoError {
        Ory(u16, String),
    }

    impl From<KetoError> for OryClientError {
        fn from(err: KetoError) -> Self {
            match err {
                KetoError::Ory(status, message) => Self::Ory { status, message },
            }
        }
    }

    #[derive(Debug, Clone)]
    struct FakeKeto {
        check_result: Result<bool, KetoError>,
        create_result: Result<Value, KetoError>,
        delete_result: Result<(), KetoError>,
        expand_result: Result<Value, KetoError>,
        expand_objects_result: Result<Value, KetoError>,
        calls: Arc<Mutex<Vec<KetoCall>>>,
    }

    #[derive(Debug, Clone)]
    enum KetoCall {
        Check {
            namespace: String,
            object: String,
            relation: String,
            subject_id: String,
        },
        Create {
            namespace: String,
            object: String,
            relation: String,
            subject_id: String,
        },
        Delete {
            namespace: String,
            object: String,
            relation: String,
            subject_id: String,
        },
        Expand {
            namespace: String,
            object: String,
            relation: String,
        },
        ExpandObjects {
            namespace: String,
            relation: String,
            subject_id: Option<String>,
            subject_set_namespace: Option<String>,
            subject_set_object: Option<String>,
            subject_set_relation: Option<String>,
            max_depth: Option<i32>,
        },
    }

    impl FakeKeto {
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
    impl PermissionKeto for FakeKeto {
        async fn check_permission(
            &self,
            namespace: &str,
            object: &str,
            relation: &str,
            subject_id: &str,
        ) -> Result<bool, OryClientError> {
            self.calls.lock().unwrap().push(KetoCall::Check {
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
                subject_id: subject_id.into(),
            });
            self.check_result.clone().map_err(Into::into)
        }

        async fn create_relation_tuple(
            &self,
            namespace: &str,
            object: &str,
            relation: &str,
            subject_id: &str,
        ) -> Result<Value, OryClientError> {
            self.calls.lock().unwrap().push(KetoCall::Create {
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
                subject_id: subject_id.into(),
            });
            self.create_result.clone().map_err(Into::into)
        }

        async fn delete_relation_tuple(
            &self,
            namespace: &str,
            object: &str,
            relation: &str,
            subject_id: &str,
        ) -> Result<(), OryClientError> {
            self.calls.lock().unwrap().push(KetoCall::Delete {
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
                subject_id: subject_id.into(),
            });
            self.delete_result.clone().map_err(Into::into)
        }

        async fn expand(
            &self,
            namespace: &str,
            object: &str,
            relation: &str,
        ) -> Result<Value, OryClientError> {
            self.calls.lock().unwrap().push(KetoCall::Expand {
                namespace: namespace.into(),
                object: object.into(),
                relation: relation.into(),
            });
            self.expand_result.clone().map_err(Into::into)
        }

        async fn expand_objects(
            &self,
            namespace: &str,
            relation: &str,
            query: &sso_ory_client::keto::ExpandObjectsQuery<'_>,
        ) -> Result<Value, OryClientError> {
            self.calls.lock().unwrap().push(KetoCall::ExpandObjects {
                namespace: namespace.into(),
                relation: relation.into(),
                subject_id: query.subject_id.map(Into::into),
                subject_set_namespace: query.subject_set_namespace.map(Into::into),
                subject_set_object: query.subject_set_object.map(Into::into),
                subject_set_relation: query.subject_set_relation.map(Into::into),
                max_depth: query.max_depth,
            });
            self.expand_objects_result.clone().map_err(Into::into)
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

    fn service_with(keto: FakeKeto, tuples: FakeTupleStore) -> PermissionServiceImpl {
        PermissionServiceImpl {
            keto: Arc::new(keto) as Arc<dyn PermissionKeto>,
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
        let keto = FakeKeto {
            check_result: Ok(true),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(keto.clone(), tuples);

        let owned =
            crate::proto::iam::v1::CheckPermissionRequestOwnedView::from_owned(&check_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service.check_permission(tenant_ctx(), req).await.unwrap();
        assert!(resp.body.allowed);

        let calls = keto.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(
            matches!(&calls[0], KetoCall::Check { namespace, object, relation, subject_id } if
                namespace == "ns" &&
                object == "tenant-1:obj" &&
                relation == "viewer" &&
                subject_id == "user-1"
            )
        );
    }

    #[tokio::test]
    async fn check_permission_denied() {
        let keto = FakeKeto {
            check_result: Ok(false),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(keto, tuples);

        let owned =
            crate::proto::iam::v1::CheckPermissionRequestOwnedView::from_owned(&check_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service.check_permission(tenant_ctx(), req).await.unwrap();
        assert!(!resp.body.allowed);
    }

    #[tokio::test]
    async fn check_permission_missing_tenant() {
        let service = service_with(FakeKeto::new(), FakeTupleStore::new());
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
        let keto = FakeKeto {
            check_result: Err(KetoError::Ory(500, "keto down".into())),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(keto, tuples);

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
        let keto = FakeKeto {
            create_result: Ok(serde_json::json!({})),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore {
            create_result: Ok(sample_row()),
            ..FakeTupleStore::new()
        };
        let service = service_with(keto.clone(), tuples.clone());

        let owned =
            crate::proto::iam::v1::CreateRelationTupleRequestOwnedView::from_owned(&create_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service
            .create_relation_tuple(admin_ctx(), req)
            .await
            .unwrap();
        assert_eq!(resp.body.id, "t1");

        let keto_calls = keto.calls.lock().unwrap();
        assert!(
            matches!(&keto_calls[0], KetoCall::Create { namespace, object, relation, subject_id } if
                namespace == "ns" && object == "tenant-1:obj" && relation == "viewer" && subject_id == "user-1"
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
        let service = service_with(FakeKeto::new(), FakeTupleStore::new());
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
        let keto = FakeKeto::new();
        let tuples = FakeTupleStore {
            create_result: Err(TupleError::NotFound),
            ..FakeTupleStore::new()
        };
        let service = service_with(keto.clone(), tuples);

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
        assert!(keto.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_relation_tuple_keto_error_returns_error() {
        let keto = FakeKeto {
            create_result: Err(KetoError::Ory(409, "already exists".into())),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore {
            create_result: Ok(sample_row()),
            ..FakeTupleStore::new()
        };
        let service = service_with(keto, tuples);

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
        let keto = FakeKeto {
            delete_result: Ok(()),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore {
            get_result: Ok(sample_row()),
            delete_result: Ok(()),
            ..FakeTupleStore::new()
        };
        let service = service_with(keto.clone(), tuples.clone());

        let owned =
            crate::proto::iam::v1::DeleteRelationTupleRequestOwnedView::from_owned(&delete_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service
            .delete_relation_tuple(admin_ctx(), req)
            .await
            .unwrap();
        assert_eq!(resp.body, Empty::default());

        let keto_calls = keto.calls.lock().unwrap();
        assert!(
            matches!(&keto_calls[0], KetoCall::Delete { namespace, object, relation, subject_id } if
                namespace == "ns" && object == "tenant-1:obj" && relation == "viewer" && subject_id == "user-1"
            )
        );

        let tuple_calls = tuples.calls.lock().unwrap();
        assert!(
            matches!(&tuple_calls[1], TupleCall::Delete { tenant_id, id } if tenant_id == "tenant-1" && id == "t1")
        );
    }

    #[tokio::test]
    async fn delete_relation_tuple_missing_tenant() {
        let service = service_with(FakeKeto::new(), FakeTupleStore::new());
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
        let keto = FakeKeto::new();
        let service = service_with(keto.clone(), tuples);

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
        assert!(keto.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_relation_tuple_keto_error_skips_db_delete() {
        let keto = FakeKeto {
            delete_result: Err(KetoError::Ory(404, "not found in keto".into())),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore {
            get_result: Ok(sample_row()),
            ..FakeTupleStore::new()
        };
        let service = service_with(keto, tuples.clone());

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
        let keto = FakeKeto {
            expand_result: Ok(serde_json::json!({ "children": ["a", "b"] })),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(keto.clone(), tuples);

        let owned =
            crate::proto::iam::v1::ExpandPermissionsRequestOwnedView::from_owned(&expand_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service.expand_permissions(tenant_ctx(), req).await.unwrap();
        assert_eq!(resp.body.tree, r#"{"children":["a","b"]}"#);

        let calls = keto.calls.lock().unwrap();
        assert!(
            matches!(&calls[0], KetoCall::Expand { namespace, object, relation } if
                namespace == "ns" && object == "tenant-1:obj" && relation == "viewer"
            )
        );
    }

    #[tokio::test]
    async fn expand_permissions_missing_tenant() {
        let service = service_with(FakeKeto::new(), FakeTupleStore::new());
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
        let keto = FakeKeto {
            expand_result: Err(KetoError::Ory(503, "keto unavailable".into())),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(keto, tuples);

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
        let keto = FakeKeto {
            expand_objects_result: Ok(serde_json::json!({
                "relation_tuples": [
                    { "namespace": "ns", "object": "tenant-1:obj-1", "relation": "viewer", "subject_id": "user-1" },
                    { "namespace": "ns", "object": "tenant-1:obj-2", "relation": "viewer", "subject_id": "user-1" },
                ]
            })),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(keto.clone(), tuples);

        let owned =
            crate::proto::iam::v1::ExpandObjectsRequestOwnedView::from_owned(&expand_objects_req())
                .unwrap();
        let req = ServiceRequest::from_parts(owned.view(), owned.bytes());

        let resp = service.expand_objects(tenant_ctx(), req).await.unwrap();
        assert_eq!(resp.body.objects, vec!["obj-1", "obj-2"]);
        assert!(resp.body.tree.contains("relation_tuples"));

        let calls = keto.calls.lock().unwrap();
        assert!(
            matches!(&calls[0], KetoCall::ExpandObjects { namespace, relation, subject_id, .. } if
                namespace == "ns" && relation == "viewer" && subject_id.as_deref() == Some("user-1")
            )
        );
    }

    #[tokio::test]
    async fn expand_objects_with_subject_set() {
        let keto = FakeKeto {
            expand_objects_result: Ok(serde_json::json!({
                "relation_tuples": [
                    { "namespace": "ns", "object": "tenant-1:obj-1", "relation": "viewer", "subject_set": { "namespace": "groups", "object": "g1", "relation": "member" } },
                ]
            })),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(keto.clone(), tuples);

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

        let calls = keto.calls.lock().unwrap();
        assert!(
            matches!(&calls[0], KetoCall::ExpandObjects { namespace, relation, subject_id, subject_set_namespace, subject_set_object, subject_set_relation, max_depth } if
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
        let service = service_with(FakeKeto::new(), FakeTupleStore::new());
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
        let keto = FakeKeto {
            expand_objects_result: Err(KetoError::Ory(503, "keto unavailable".into())),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(keto, tuples);

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
        let keto = FakeKeto {
            expand_objects_result: Ok(serde_json::json!({ "relation_tuples": [] })),
            ..FakeKeto::new()
        };
        let tuples = FakeTupleStore::new();
        let service = service_with(keto.clone(), tuples);

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

        let calls = keto.calls.lock().unwrap();
        assert!(
            matches!(&calls[0], KetoCall::ExpandObjects { namespace, relation, subject_id, subject_set_namespace, subject_set_object, subject_set_relation, max_depth } if
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
        let service = service_with(FakeKeto::new(), tuples.clone());

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
        let service = service_with(FakeKeto::new(), FakeTupleStore::new());
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
        let service = service_with(FakeKeto::new(), tuples);

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

    #[tokio::test]
    async fn keto_client_as_permission_keto_delegates() {
        let client = Arc::new(KetoClient::new("http://localhost:1", "http://localhost:1").unwrap())
            as Arc<dyn PermissionKeto>;
        assert!(
            client
                .check_permission("ns", "obj", "rel", "subject")
                .await
                .is_err()
        );
        assert!(
            client
                .create_relation_tuple("ns", "obj", "rel", "subject")
                .await
                .is_err()
        );
        assert!(
            client
                .delete_relation_tuple("ns", "obj", "rel", "subject")
                .await
                .is_err()
        );
        assert!(client.expand("ns", "obj", "rel").await.is_err());
        assert!(
            client
                .expand_objects(
                    "ns",
                    "rel",
                    &sso_ory_client::keto::ExpandObjectsQuery {
                        subject_id: Some("subject"),
                        ..Default::default()
                    }
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn check_permission_requires_read_scope() {
        let service = service_with(FakeKeto::new(), FakeTupleStore::new());
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
            FakeKeto {
                check_result: Ok(true),
                ..FakeKeto::new()
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
        let service = service_with(FakeKeto::new(), FakeTupleStore::new());
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
        let service = service_with(FakeKeto::new(), FakeTupleStore::new());
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
}
