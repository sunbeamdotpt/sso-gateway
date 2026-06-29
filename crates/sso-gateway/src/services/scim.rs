use std::sync::Arc;

use buffa::Message;
use buffa::bytes::Bytes;
use buffa::view::{HasMessageView, MessageView};
use buffa_types::google::protobuf::Empty;
use buffa_types::google::protobuf::Struct as ProtoStruct;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use http::HeaderMap;
use serde_json::json;
use sso_ory_client::{error::OryClientError, keto::KetoClient, kratos::KratosClient};
use sunbeam_g2v::error::ServiceError;
use tracing::{debug, instrument};
use ulid::Ulid;

use crate::{
    db::{IdMappingRepo, IdentitySchemaRepo, ScimGroupRepo},
    middleware::TenantId,
    proto::iam::v1::{
        ScimCreateGroupRequest, ScimCreateUserRequest, ScimDeleteGroupRequest,
        ScimDeleteUserRequest, ScimGetGroupRequest, ScimGetUserRequest, ScimGroup,
        ScimListGroupsRequest, ScimListGroupsResponse, ScimListUsersRequest, ScimListUsersResponse,
        ScimMember, ScimService, ScimUpdateGroupRequest, ScimUpdateUserRequest, ScimUser,
    },
};

const BACKEND_KRATOS: &str = "kratos";
const SCIM_GROUP_NAMESPACE: &str = "scim_group";
const SCIM_GROUP_RELATION: &str = "member";

fn decode_request<'a, Req: HasMessageView>(
    bytes: &'a Bytes,
) -> Result<Req::View<'a>, ServiceError> {
    Req::View::decode_view(bytes)
        .map_err(|e| ServiceError::Internal(format!("failed to decode self-encoded request: {e}")))
}

macro_rules! svc_req {
    ($id:ident, $req:expr, $ty:ty) => {
        let bytes = Bytes::from($req.encode_to_vec());
        let view = decode_request::<$ty>(&bytes)?;
        let $id = ServiceRequest::<$ty>::from_parts(&view, &bytes);
    };
}

#[derive(Clone)]
pub struct ScimServiceImpl {
    kratos: Arc<KratosClient>,
    keto: Arc<KetoClient>,
    mappings: IdMappingRepo,
    schemas: IdentitySchemaRepo,
    groups: ScimGroupRepo,
}

impl ScimServiceImpl {
    pub fn new(
        kratos: Arc<KratosClient>,
        keto: Arc<KetoClient>,
        mappings: IdMappingRepo,
        schemas: IdentitySchemaRepo,
        groups: ScimGroupRepo,
    ) -> Self {
        Self {
            kratos,
            keto,
            mappings,
            schemas,
            groups,
        }
    }
}

#[allow(refining_impl_trait)]
impl ScimService for ScimServiceImpl {
    #[instrument(skip(self, request))]
    async fn list_users(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ScimListUsersRequest>,
    ) -> ServiceResult<ScimListUsersResponse> {
        let tenant_id = require_tenant(&ctx)?;
        let _req = request.to_owned_message();

        let public_ids = self
            .mappings
            .list_public_ids(&tenant_id, BACKEND_KRATOS)
            .await?;
        let mut users = Vec::with_capacity(public_ids.len());
        for public_id in public_ids {
            match self.load_user(&tenant_id, &public_id).await {
                Ok(user) => users.push(user),
                Err(err) => debug!(%public_id, "failed to load scim user: {}", err),
            }
        }

        Ok(Response::new(ScimListUsersResponse {
            users,
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn get_user(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ScimGetUserRequest>,
    ) -> ServiceResult<ScimUser> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let user = self.load_user(&tenant_id, &req.id).await?;
        Ok(Response::new(user))
    }

    #[instrument(skip(self, request))]
    async fn create_user(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ScimCreateUserRequest>,
    ) -> ServiceResult<ScimUser> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let input = req
            .user
            .as_option()
            .ok_or_else(|| ServiceError::InvalidArgument("user is required".into()))?;

        let traits = scim_user_to_traits(input);
        let schema = self.resolve_schema(&tenant_id, "").await?;
        crate::services::identity::validate_traits(&schema.schema_json, &traits)?;

        let payload = serde_json::json!({
            "schema_id": schema.schema_id,
            "traits": traits,
        });
        let created = self
            .kratos
            .create_identity(payload)
            .await
            .map_err(map_ory_error)?;
        let ory_id = created["id"]
            .as_str()
            .ok_or_else(|| ServiceError::Internal("kratos response missing id".into()))?;
        let public_id = Ulid::new().to_string();
        self.mappings
            .create(&tenant_id, BACKEND_KRATOS, &public_id, ory_id)
            .await?;

        for group_id in &input.groups {
            self.add_user_to_group(&tenant_id, &public_id, group_id)
                .await?;
        }

        let user = self.load_user(&tenant_id, &public_id).await?;
        Ok(Response::new(user))
    }

    #[instrument(skip(self, request))]
    async fn update_user(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ScimUpdateUserRequest>,
    ) -> ServiceResult<ScimUser> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let input = req
            .user
            .as_option()
            .ok_or_else(|| ServiceError::InvalidArgument("user is required".into()))?;

        let (ory_id, _) = self.resolve_identity(&tenant_id, &req.id).await?;
        let traits = scim_user_to_traits(input);
        let schema = self.resolve_schema(&tenant_id, "").await?;
        crate::services::identity::validate_traits(&schema.schema_json, &traits)?;

        let payload = serde_json::json!({
            "schema_id": schema.schema_id,
            "traits": traits,
        });
        self.kratos
            .update_identity(&ory_id, payload)
            .await
            .map_err(map_ory_error)?;

        // Replace group memberships when the groups field is populated.
        if !input.groups.is_empty() {
            self.groups.remove_user_from_all_groups(&req.id).await?;
            for group_id in &input.groups {
                self.add_user_to_group(&tenant_id, &req.id, group_id)
                    .await?;
            }
        }

        let user = self.load_user(&tenant_id, &req.id).await?;
        Ok(Response::new(user))
    }

    #[instrument(skip(self, request))]
    async fn delete_user(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ScimDeleteUserRequest>,
    ) -> ServiceResult<Empty> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let ory_id = self
            .mappings
            .get_ory_id(&tenant_id, BACKEND_KRATOS, &req.id)
            .await?;

        self.groups.remove_user_from_all_groups(&req.id).await?;
        self.kratos
            .delete_identity(&ory_id)
            .await
            .map_err(map_ory_error)?;
        self.mappings
            .delete(&tenant_id, BACKEND_KRATOS, &req.id)
            .await?;

        Ok(Response::new(Empty::default()))
    }

    #[instrument(skip(self, request))]
    async fn list_groups(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ScimListGroupsRequest>,
    ) -> ServiceResult<ScimListGroupsResponse> {
        let tenant_id = require_tenant(&ctx)?;
        let _req = request.to_owned_message();
        let rows = self.groups.list(&tenant_id).await?;
        let mut groups = Vec::with_capacity(rows.len());
        for row in rows {
            groups.push(self.load_group(&tenant_id, &row).await?);
        }
        Ok(Response::new(ScimListGroupsResponse {
            groups,
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn get_group(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ScimGetGroupRequest>,
    ) -> ServiceResult<ScimGroup> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let row = self.groups.get(&tenant_id, &req.id).await?;
        let group = self.load_group(&tenant_id, &row).await?;
        Ok(Response::new(group))
    }

    #[instrument(skip(self, request))]
    async fn create_group(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ScimCreateGroupRequest>,
    ) -> ServiceResult<ScimGroup> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let input = req
            .group
            .as_option()
            .ok_or_else(|| ServiceError::InvalidArgument("group is required".into()))?;

        let row = self.groups.create(&tenant_id, &input.display_name).await?;
        for member in &input.members {
            if member.r#type == "User" || member.r#type.is_empty() {
                self.add_user_to_group(&tenant_id, &member.value, &row.id)
                    .await?;
            }
        }

        let group = self.load_group(&tenant_id, &row).await?;
        Ok(Response::new(group))
    }

    #[instrument(skip(self, request))]
    async fn update_group(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ScimUpdateGroupRequest>,
    ) -> ServiceResult<ScimGroup> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let input = req
            .group
            .as_option()
            .ok_or_else(|| ServiceError::InvalidArgument("group is required".into()))?;

        let row = self
            .groups
            .update(&tenant_id, &req.id, &input.display_name)
            .await?;

        // Replace memberships.
        let existing = self.groups.list_members(&req.id).await?;
        for user_id in &existing {
            self.groups
                .remove_member(&tenant_id, &req.id, user_id)
                .await?;
            let _ = self
                .keto
                .delete_relation_tuple(SCIM_GROUP_NAMESPACE, &req.id, SCIM_GROUP_RELATION, user_id)
                .await
                .map_err(map_ory_error);
        }
        for member in &input.members {
            if member.r#type == "User" || member.r#type.is_empty() {
                self.add_user_to_group(&tenant_id, &member.value, &req.id)
                    .await?;
            }
        }

        let group = self.load_group(&tenant_id, &row).await?;
        Ok(Response::new(group))
    }

    #[instrument(skip(self, request))]
    async fn delete_group(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ScimDeleteGroupRequest>,
    ) -> ServiceResult<Empty> {
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();

        let members = self.groups.list_members(&req.id).await?;
        for user_id in members {
            let _ = self
                .keto
                .delete_relation_tuple(SCIM_GROUP_NAMESPACE, &req.id, SCIM_GROUP_RELATION, &user_id)
                .await
                .map_err(map_ory_error);
        }

        self.groups.delete(&tenant_id, &req.id).await?;
        Ok(Response::new(Empty::default()))
    }
}

impl ScimServiceImpl {
    async fn resolve_identity(
        &self,
        tenant_id: &str,
        public_id: &str,
    ) -> Result<(String, String), ServiceError> {
        let ory_id = self
            .mappings
            .get_ory_id(tenant_id, BACKEND_KRATOS, public_id)
            .await?;
        let schema_id = match self.kratos.get_identity(&ory_id).await {
            Ok(identity) => identity["schema_id"]
                .as_str()
                .unwrap_or("default")
                .to_string(),
            Err(_) => "default".to_string(),
        };
        Ok((ory_id, schema_id))
    }

    async fn resolve_schema(
        &self,
        tenant_id: &str,
        schema_id: &str,
    ) -> Result<crate::db::IdentitySchemaRow, ServiceError> {
        if schema_id.is_empty() {
            self.schemas
                .get_default(tenant_id)
                .await
                .map_err(|e| e.into())
        } else {
            self.schemas
                .get_by_schema_id(tenant_id, schema_id)
                .await
                .map_err(|e| e.into())
        }
    }

    async fn load_user(&self, tenant_id: &str, public_id: &str) -> Result<ScimUser, ServiceError> {
        let (ory_id, _) = self.resolve_identity(tenant_id, public_id).await?;
        let identity = self
            .kratos
            .get_identity(&ory_id)
            .await
            .map_err(map_ory_error)?;
        let traits = &identity["traits"];

        let email = traits["email"].as_str().unwrap_or("").to_string();
        let emails = if email.is_empty() {
            Vec::new()
        } else {
            vec![proto_struct(json!({
                "value": email,
                "primary": true,
                "type": "work"
            }))]
        };

        let group_ids = self.groups.list_user_groups(public_id).await?;

        Ok(ScimUser {
            id: public_id.to_string(),
            user_name: traits["userName"].as_str().unwrap_or(&email).to_string(),
            name: proto_struct_opt(traits.get("name").cloned())
                .map(Into::into)
                .unwrap_or_default(),
            emails,
            active: traits["active"].as_bool().unwrap_or(true),
            groups: group_ids,
            meta: Some(proto_struct(json!({"resourceType": "User"}))).into(),
            ..Default::default()
        })
    }

    async fn load_group(
        &self,
        tenant_id: &str,
        row: &crate::db::ScimGroupRow,
    ) -> Result<ScimGroup, ServiceError> {
        let member_ids = self.groups.list_members(&row.id).await?;
        let mut members = Vec::with_capacity(member_ids.len());
        for user_id in member_ids {
            // Resolve display name from the user's traits.
            let display = match self.load_user(tenant_id, &user_id).await {
                Ok(user) => user.user_name,
                Err(_) => user_id.clone(),
            };
            members.push(ScimMember {
                value: user_id,
                display,
                r#type: "User".to_string(),
                ..Default::default()
            });
        }

        Ok(ScimGroup {
            id: row.id.clone(),
            display_name: row.display_name.clone(),
            members,
            meta: Some(proto_struct(json!({"resourceType": "Group"}))).into(),
            ..Default::default()
        })
    }

    async fn add_user_to_group(
        &self,
        tenant_id: &str,
        user_id: &str,
        group_id: &str,
    ) -> Result<(), ServiceError> {
        // Verify the user belongs to the tenant.
        let _ = self
            .mappings
            .get_ory_id(tenant_id, BACKEND_KRATOS, user_id)
            .await?;
        self.groups.add_member(tenant_id, group_id, user_id).await?;
        self.keto
            .create_relation_tuple(SCIM_GROUP_NAMESPACE, group_id, SCIM_GROUP_RELATION, user_id)
            .await
            .map_err(map_ory_error)?;
        Ok(())
    }
}

fn scim_user_to_traits(user: &ScimUser) -> serde_json::Value {
    let email = user
        .emails
        .first()
        .and_then(|e| e.fields.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let name_json = user
        .name
        .as_option()
        .map(|s| serde_json::to_value(s).unwrap_or_default())
        .unwrap_or_default();
    serde_json::json!({
        "userName": user.user_name,
        "email": email,
        "name": name_json,
        "active": user.active,
    })
}

fn proto_struct(value: serde_json::Value) -> ProtoStruct {
    serde_json::from_value(value).unwrap_or_default()
}

fn proto_struct_opt(value: Option<serde_json::Value>) -> Option<ProtoStruct> {
    value.and_then(|v| serde_json::from_value(v).ok())
}

fn require_tenant(ctx: &RequestContext) -> Result<String, ServiceError> {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .ok_or_else(|| ServiceError::Unauthenticated("missing x-tenant-id".into()))
}

impl ScimServiceImpl {
    /// HTTP-facing helper that wraps the generated `ScimService` RPC trait.
    pub async fn list_users_http(
        &self,
        tenant_id: String,
    ) -> Result<Response<ScimListUsersResponse>, connectrpc::ConnectError> {
        let req = ScimListUsersRequest::default();
        svc_req!(svc_req, req, ScimListUsersRequest);
        ScimService::list_users(self, request_context(tenant_id), svc_req).await
    }

    pub async fn get_user_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<Response<ScimUser>, connectrpc::ConnectError> {
        let req = ScimGetUserRequest {
            id,
            ..Default::default()
        };
        svc_req!(svc_req, req, ScimGetUserRequest);
        ScimService::get_user(self, request_context(tenant_id), svc_req).await
    }

    pub async fn create_user_http(
        &self,
        tenant_id: String,
        user: ScimUser,
    ) -> Result<Response<ScimUser>, connectrpc::ConnectError> {
        let req = ScimCreateUserRequest {
            user: Some(user).into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, ScimCreateUserRequest);
        ScimService::create_user(self, request_context(tenant_id), svc_req).await
    }

    pub async fn update_user_http(
        &self,
        tenant_id: String,
        id: String,
        user: ScimUser,
    ) -> Result<Response<ScimUser>, connectrpc::ConnectError> {
        let req = ScimUpdateUserRequest {
            id,
            user: Some(user).into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, ScimUpdateUserRequest);
        ScimService::update_user(self, request_context(tenant_id), svc_req).await
    }

    pub async fn delete_user_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<Response<Empty>, connectrpc::ConnectError> {
        let req = ScimDeleteUserRequest {
            id,
            ..Default::default()
        };
        svc_req!(svc_req, req, ScimDeleteUserRequest);
        ScimService::delete_user(self, request_context(tenant_id), svc_req).await
    }

    pub async fn list_groups_http(
        &self,
        tenant_id: String,
    ) -> Result<Response<ScimListGroupsResponse>, connectrpc::ConnectError> {
        let req = ScimListGroupsRequest::default();
        svc_req!(svc_req, req, ScimListGroupsRequest);
        ScimService::list_groups(self, request_context(tenant_id), svc_req).await
    }

    pub async fn get_group_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<Response<ScimGroup>, connectrpc::ConnectError> {
        let req = ScimGetGroupRequest {
            id,
            ..Default::default()
        };
        svc_req!(svc_req, req, ScimGetGroupRequest);
        ScimService::get_group(self, request_context(tenant_id), svc_req).await
    }

    pub async fn create_group_http(
        &self,
        tenant_id: String,
        group: ScimGroup,
    ) -> Result<Response<ScimGroup>, connectrpc::ConnectError> {
        let req = ScimCreateGroupRequest {
            group: Some(group).into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, ScimCreateGroupRequest);
        ScimService::create_group(self, request_context(tenant_id), svc_req).await
    }

    pub async fn update_group_http(
        &self,
        tenant_id: String,
        id: String,
        group: ScimGroup,
    ) -> Result<Response<ScimGroup>, connectrpc::ConnectError> {
        let req = ScimUpdateGroupRequest {
            id,
            group: Some(group).into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, ScimUpdateGroupRequest);
        ScimService::update_group(self, request_context(tenant_id), svc_req).await
    }

    pub async fn delete_group_http(
        &self,
        tenant_id: String,
        id: String,
    ) -> Result<Response<Empty>, connectrpc::ConnectError> {
        let req = ScimDeleteGroupRequest {
            id,
            ..Default::default()
        };
        svc_req!(svc_req, req, ScimDeleteGroupRequest);
        ScimService::delete_group(self, request_context(tenant_id), svc_req).await
    }
}

fn request_context(tenant_id: String) -> RequestContext {
    let mut ctx = RequestContext::new(HeaderMap::new());
    ctx.extensions_mut().insert(TenantId(tenant_id));
    ctx
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn email_field(value: &str) -> ProtoStruct {
        proto_struct(json!({"value": value, "primary": true, "type": "work"}))
    }

    #[test]
    fn scim_user_to_traits_extracts_email_and_name() {
        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            active: true,
            ..Default::default()
        };
        let traits = scim_user_to_traits(&user);
        assert_eq!(traits["userName"], "alice");
        assert_eq!(traits["email"], "alice@example.com");
        assert_eq!(traits["active"], true);
    }

    #[test]
    fn scim_user_to_traits_defaults_missing_email() {
        let user = ScimUser {
            user_name: "bob".into(),
            active: false,
            ..Default::default()
        };
        let traits = scim_user_to_traits(&user);
        assert_eq!(traits["email"], "");
        assert_eq!(traits["active"], false);
    }

    #[test]
    fn proto_struct_parses_valid_object() {
        let s = proto_struct(json!({"a": "b"}));
        assert_eq!(s.fields.get("a").unwrap().as_str().unwrap(), "b");
    }

    #[test]
    fn proto_struct_defaults_for_invalid() {
        let s = proto_struct(json!("not-an-object"));
        assert!(s.fields.is_empty());
    }

    #[test]
    fn proto_struct_opt_returns_some_for_valid() {
        let s = proto_struct_opt(Some(json!({"a": "b"})));
        assert!(s.is_some());
    }

    #[test]
    fn proto_struct_opt_returns_none_for_invalid() {
        let s = proto_struct_opt(Some(json!("not-an-object")));
        assert!(s.is_none());
    }

    #[test]
    fn request_context_carries_tenant_id() {
        let ctx = request_context("tenant-1".into());
        assert_eq!(ctx.extensions().get::<TenantId>().unwrap().0, "tenant-1");
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

    #[tokio::test]
    async fn map_ory_error_maps_non_ory_variants() {
        assert!(matches!(
            map_ory_error(OryClientError::Http(
                reqwest::get("http://localhost:1").await.unwrap_err()
            )),
            ServiceError::Unavailable(_)
        ));
        assert!(matches!(
            map_ory_error(OryClientError::Serialization(
                serde_json::from_str::<serde_json::Value>("not json").unwrap_err()
            )),
            ServiceError::Serialization(_)
        ));
        assert!(matches!(
            map_ory_error(OryClientError::Url(
                reqwest::Url::parse("not-a-url").unwrap_err()
            )),
            ServiceError::Configuration(_)
        ));
        assert!(matches!(
            map_ory_error(OryClientError::InvalidResponse("bad".into())),
            ServiceError::Internal(_)
        ));
        assert!(matches!(
            map_ory_error(OryClientError::MissingTenant),
            ServiceError::Unauthenticated(_)
        ));
    }
}
