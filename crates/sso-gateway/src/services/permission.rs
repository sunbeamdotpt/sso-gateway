use std::sync::Arc;

use buffa_types::google::protobuf::Empty;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use sso_ory_client::{error::OryClientError, keto::KetoClient};
use sunbeam_g2v::error::ServiceError;
use tracing::instrument;

use crate::{
    db::{PermissionTupleRepo, PermissionTupleRow},
    middleware::TenantId,
    proto::iam::v1::{
        CheckPermissionRequest, CheckPermissionResponse, CreateRelationTupleRequest,
        DeleteRelationTupleRequest, ExpandPermissionsRequest, ExpandPermissionsResponse,
        ListRelationTuplesRequest, ListRelationTuplesResponse, PermissionService, RelationTuple,
    },
};

#[derive(Clone)]
pub struct PermissionServiceImpl {
    keto: Arc<KetoClient>,
    tuples: PermissionTupleRepo,
}

impl PermissionServiceImpl {
    pub fn new(keto: Arc<KetoClient>, tuples: PermissionTupleRepo) -> Self {
        Self { keto, tuples }
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
    async fn list_relation_tuples(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListRelationTuplesRequest>,
    ) -> ServiceResult<ListRelationTuplesResponse> {
        let tenant_id = require_tenant(&ctx)?;
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

fn require_tenant(ctx: &RequestContext) -> Result<String, ServiceError> {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .ok_or_else(|| ServiceError::Unauthenticated("missing x-tenant-id".into()))
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
    use super::*;

    #[test]
    fn tenant_object_prefixes_with_colon() {
        assert_eq!(tenant_object("tenant-1", "doc"), "tenant-1:doc");
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
        let row = PermissionTupleRow {
            id: "t1".into(),
            tenant_id: "tenant-1".into(),
            namespace: "ns".into(),
            object: "obj".into(),
            relation: "viewer".into(),
            subject_id: "user-1".into(),
            created_at: time::OffsetDateTime::now_utc(),
        };
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
}
