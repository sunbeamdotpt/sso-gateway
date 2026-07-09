use std::sync::Arc;

use async_trait::async_trait;
use buffa::Message;
use buffa::bytes::Bytes;
use buffa::view::{HasMessageView, MessageView};
use buffa_types::google::protobuf::Empty;
use buffa_types::google::protobuf::Struct as ProtoStruct;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use http::HeaderMap;
use serde_json::{Value, json};
#[cfg(all(feature = "keto", test))]
use sso_ory_client::keto::KetoClient;
use sso_ory_client::{error::OryClientError, kratos::KratosClient};
use sunbeam_g2v::error::ServiceError;
use tracing::{debug, instrument};
use ulid::Ulid;

use crate::{
    auth::{AuthContext, SCOPE_SCIM_ADMIN, SCOPE_SCIM_READ, require_scope},
    db::{
        IdMappingRepo, IdMappingStore, IdentitySchemaRepo, IdentitySchemaRow, IdentitySchemaStore,
        ScimGroupRepo, ScimGroupRow, ScimGroupStore,
    },
    middleware::TenantId,
    proto::iam::v1::{
        ScimCreateGroupRequest, ScimCreateUserRequest, ScimDeleteGroupRequest,
        ScimDeleteUserRequest, ScimGetGroupRequest, ScimGetUserRequest, ScimGroup,
        ScimListGroupsRequest, ScimListGroupsResponse, ScimListUsersRequest, ScimListUsersResponse,
        ScimMember, ScimService, ScimUpdateGroupRequest, ScimUpdateUserRequest, ScimUser,
    },
    services::permission::PermissionBackend,
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

/// Async trait for the Kratos operations used by the SCIM service.
#[async_trait]
pub trait ScimKratos: Send + Sync + 'static {
    async fn create_identity(&self, payload: Value) -> Result<Value, OryClientError>;
    async fn get_identity(&self, id: &str) -> Result<Value, OryClientError>;
    async fn update_identity(&self, id: &str, payload: Value) -> Result<Value, OryClientError>;
    async fn delete_identity(&self, id: &str) -> Result<(), OryClientError>;
}

#[async_trait]
impl ScimKratos for KratosClient {
    async fn create_identity(&self, payload: Value) -> Result<Value, OryClientError> {
        self.create_identity(payload).await
    }

    async fn get_identity(&self, id: &str) -> Result<Value, OryClientError> {
        self.get_identity(id).await
    }

    async fn update_identity(&self, id: &str, payload: Value) -> Result<Value, OryClientError> {
        self.update_identity(id, payload).await
    }

    async fn delete_identity(&self, id: &str) -> Result<(), OryClientError> {
        self.delete_identity(id).await
    }
}

#[derive(Clone)]
pub struct ScimServiceImpl {
    kratos: Arc<dyn ScimKratos>,
    backend: Arc<dyn PermissionBackend>,
    mappings: Arc<dyn IdMappingStore>,
    schemas: Arc<dyn IdentitySchemaStore>,
    groups: Arc<dyn ScimGroupStore>,
}

impl ScimServiceImpl {
    pub fn new(
        kratos: Arc<KratosClient>,
        backend: Arc<dyn PermissionBackend>,
        mappings: IdMappingRepo,
        schemas: IdentitySchemaRepo,
        groups: ScimGroupRepo,
    ) -> Self {
        Self {
            kratos: kratos as Arc<dyn ScimKratos>,
            backend,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
            schemas: Arc::new(schemas) as Arc<dyn IdentitySchemaStore>,
            groups: Arc::new(groups) as Arc<dyn ScimGroupStore>,
        }
    }
}

#[cfg(test)]
impl ScimServiceImpl {
    fn new_for_test(
        kratos: Arc<dyn ScimKratos>,
        backend: Arc<dyn PermissionBackend>,
        mappings: Arc<dyn IdMappingStore>,
        schemas: Arc<dyn IdentitySchemaStore>,
        groups: Arc<dyn ScimGroupStore>,
    ) -> Self {
        Self {
            kratos,
            backend,
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
        require_scope_any(&ctx, &[SCOPE_SCIM_READ, SCOPE_SCIM_ADMIN])?;
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
        require_scope_any(&ctx, &[SCOPE_SCIM_READ, SCOPE_SCIM_ADMIN])?;
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
        require_scope(&ctx, SCOPE_SCIM_ADMIN)?;
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
        require_scope(&ctx, SCOPE_SCIM_ADMIN)?;
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
        require_scope(&ctx, SCOPE_SCIM_ADMIN)?;
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
        require_scope_any(&ctx, &[SCOPE_SCIM_READ, SCOPE_SCIM_ADMIN])?;
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
        require_scope_any(&ctx, &[SCOPE_SCIM_READ, SCOPE_SCIM_ADMIN])?;
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
        require_scope(&ctx, SCOPE_SCIM_ADMIN)?;
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
        require_scope(&ctx, SCOPE_SCIM_ADMIN)?;
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
        self.backend
            .ensure_namespace(
                &tenant_id,
                SCIM_GROUP_NAMESPACE,
                &[SCIM_GROUP_RELATION.into()],
            )
            .await?;
        let existing = self.groups.list_members(&req.id).await?;
        for user_id in &existing {
            self.groups
                .remove_member(&tenant_id, &req.id, user_id)
                .await?;
            let _ = self
                .backend
                .delete_relation_tuple(
                    &tenant_id,
                    SCIM_GROUP_NAMESPACE,
                    &req.id,
                    SCIM_GROUP_RELATION,
                    user_id,
                )
                .await;
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
        require_scope(&ctx, SCOPE_SCIM_ADMIN)?;
        let req = request.to_owned_message();

        self.backend
            .ensure_namespace(
                &tenant_id,
                SCIM_GROUP_NAMESPACE,
                &[SCIM_GROUP_RELATION.into()],
            )
            .await?;
        let members = self.groups.list_members(&req.id).await?;
        for user_id in members {
            let _ = self
                .backend
                .delete_relation_tuple(
                    &tenant_id,
                    SCIM_GROUP_NAMESPACE,
                    &req.id,
                    SCIM_GROUP_RELATION,
                    &user_id,
                )
                .await;
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
    ) -> Result<IdentitySchemaRow, ServiceError> {
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
        row: &ScimGroupRow,
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
        self.backend
            .ensure_namespace(
                tenant_id,
                SCIM_GROUP_NAMESPACE,
                &[SCIM_GROUP_RELATION.into()],
            )
            .await?;
        self.backend
            .create_relation_tuple(
                tenant_id,
                SCIM_GROUP_NAMESPACE,
                group_id,
                SCIM_GROUP_RELATION,
                user_id,
            )
            .await?;
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
    ctx.extensions_mut().insert(TenantId(tenant_id.clone()));
    ctx.extensions_mut().insert(AuthContext {
        tenant_id,
        subject: "scim-subject".into(),
        scopes: vec![SCOPE_SCIM_READ.into(), SCOPE_SCIM_ADMIN.into()],
        token_hash: "hash".into(),
        authentication_methods: Vec::new(),
    });
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
        OryClientError::Redirect { .. } => ServiceError::Internal("unexpected redirect".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    type StringQuadList = Arc<Mutex<Vec<(String, String, String, String)>>>;

    fn email_field(value: &str) -> ProtoStruct {
        proto_struct(json!({"value": value, "primary": true, "type": "work"}))
    }

    fn make_service() -> ScimServiceImpl {
        ScimServiceImpl::new_for_test(
            Arc::new(StubKratos::default()),
            Arc::new(StubPermissionBackend::default()),
            Arc::new(StubMappings::default()),
            Arc::new(StubSchemas::valid()),
            Arc::new(StubGroups::default()),
        )
    }

    #[derive(Clone, Default)]
    struct StubKratos {
        identities: Arc<Mutex<HashMap<String, Value>>>,
    }

    impl StubKratos {
        #[allow(dead_code)]
        fn with_identity(id: &str, identity: Value) -> Self {
            let mut map = HashMap::new();
            map.insert(id.to_string(), identity);
            Self {
                identities: Arc::new(Mutex::new(map)),
            }
        }
    }

    #[async_trait]
    impl ScimKratos for StubKratos {
        async fn create_identity(&self, payload: Value) -> Result<Value, OryClientError> {
            let id = format!("ory-{}", Ulid::new());
            let mut identity = payload;
            identity["id"] = id.clone().into();
            self.identities
                .lock()
                .await
                .insert(id.clone(), identity.clone());
            Ok(identity)
        }

        async fn get_identity(&self, id: &str) -> Result<Value, OryClientError> {
            self.identities
                .lock()
                .await
                .get(id)
                .cloned()
                .ok_or_else(|| OryClientError::Ory {
                    status: 404,
                    message: "identity not found".into(),
                })
        }

        async fn update_identity(&self, id: &str, payload: Value) -> Result<Value, OryClientError> {
            let mut lock = self.identities.lock().await;
            if !lock.contains_key(id) {
                return Err(OryClientError::Ory {
                    status: 404,
                    message: "identity not found".into(),
                });
            }
            let mut identity = payload;
            identity["id"] = id.into();
            lock.insert(id.to_string(), identity.clone());
            Ok(identity)
        }

        async fn delete_identity(&self, id: &str) -> Result<(), OryClientError> {
            self.identities.lock().await.remove(id);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FailingKratos {
        status: u16,
        message: String,
    }

    impl FailingKratos {
        #[allow(dead_code)]
        fn not_found() -> Self {
            Self {
                status: 404,
                message: "not found".into(),
            }
        }
    }

    #[async_trait]
    impl ScimKratos for FailingKratos {
        async fn create_identity(&self, _payload: Value) -> Result<Value, OryClientError> {
            Err(OryClientError::Ory {
                status: self.status,
                message: self.message.clone(),
            })
        }

        async fn get_identity(&self, _id: &str) -> Result<Value, OryClientError> {
            Err(OryClientError::Ory {
                status: self.status,
                message: self.message.clone(),
            })
        }

        async fn update_identity(
            &self,
            _id: &str,
            _payload: Value,
        ) -> Result<Value, OryClientError> {
            Err(OryClientError::Ory {
                status: self.status,
                message: self.message.clone(),
            })
        }

        async fn delete_identity(&self, _id: &str) -> Result<(), OryClientError> {
            Err(OryClientError::Ory {
                status: self.status,
                message: self.message.clone(),
            })
        }
    }

    type StringQuintList = Arc<tokio::sync::Mutex<Vec<(String, String, String, String, String)>>>;

    #[derive(Clone, Default)]
    struct StubPermissionBackend {
        tuples: StringQuintList,
    }

    #[async_trait]
    impl PermissionBackend for StubPermissionBackend {
        async fn check_permission(
            &self,
            _tenant_id: &str,
            _namespace: &str,
            _object: &str,
            _relation: &str,
            _subject_id: &str,
        ) -> Result<bool, crate::services::permission::PermissionBackendError> {
            Ok(false)
        }

        async fn create_relation_tuple(
            &self,
            tenant_id: &str,
            namespace: &str,
            object: &str,
            relation: &str,
            subject_id: &str,
        ) -> Result<Value, crate::services::permission::PermissionBackendError> {
            self.tuples.lock().await.push((
                tenant_id.to_string(),
                namespace.to_string(),
                object.to_string(),
                relation.to_string(),
                subject_id.to_string(),
            ));
            Ok(Value::Object(Default::default()))
        }

        async fn delete_relation_tuple(
            &self,
            tenant_id: &str,
            namespace: &str,
            object: &str,
            relation: &str,
            subject_id: &str,
        ) -> Result<(), crate::services::permission::PermissionBackendError> {
            self.tuples.lock().await.retain(|t| {
                !(t.0 == tenant_id
                    && t.1 == namespace
                    && t.2 == object
                    && t.3 == relation
                    && t.4 == subject_id)
            });
            Ok(())
        }

        async fn expand(
            &self,
            _tenant_id: &str,
            _namespace: &str,
            _object: &str,
            _relation: &str,
        ) -> Result<Value, crate::services::permission::PermissionBackendError> {
            Ok(Value::Null)
        }

        async fn expand_objects(
            &self,
            _tenant_id: &str,
            _namespace: &str,
            _relation: &str,
            _subject_id: Option<&str>,
            _subject_set_namespace: Option<&str>,
            _subject_set_object: Option<&str>,
            _subject_set_relation: Option<&str>,
            _max_depth: Option<i32>,
        ) -> Result<Value, crate::services::permission::PermissionBackendError> {
            Ok(Value::Null)
        }

        async fn ensure_namespace(
            &self,
            _tenant_id: &str,
            _namespace: &str,
            _relations: &[String],
        ) -> Result<(), crate::services::permission::PermissionBackendError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct StubMappings {
        mappings: StringQuadList,
    }

    #[async_trait]
    impl IdMappingStore for StubMappings {
        async fn create(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
            ory_global_id: &str,
        ) -> Result<crate::db::IdMappingRow, crate::db::DbError> {
            self.mappings.lock().await.push((
                tenant_id.to_string(),
                backend.to_string(),
                public_id.to_string(),
                ory_global_id.to_string(),
            ));
            Ok(crate::db::IdMappingRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                backend: backend.to_string(),
                public_id: public_id.to_string(),
                ory_global_id: ory_global_id.to_string(),
                created_at: time::OffsetDateTime::UNIX_EPOCH,
            })
        }

        async fn get_ory_id(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
        ) -> Result<String, crate::db::DbError> {
            let lock = self.mappings.lock().await;
            lock.iter()
                .find(|(t, b, p, _)| t == tenant_id && b == backend && p == public_id)
                .map(|(_, _, _, o)| o.clone())
                .ok_or(crate::db::DbError::MappingNotFound)
        }

        async fn get_public_id(
            &self,
            tenant_id: &str,
            backend: &str,
            ory_global_id: &str,
        ) -> Result<String, crate::db::DbError> {
            let lock = self.mappings.lock().await;
            lock.iter()
                .find(|(t, b, _, o)| t == tenant_id && b == backend && o == ory_global_id)
                .map(|(_, _, p, _)| p.clone())
                .ok_or(crate::db::DbError::MappingNotFound)
        }

        async fn delete(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
        ) -> Result<(), crate::db::DbError> {
            let mut lock = self.mappings.lock().await;
            let initial = lock.len();
            lock.retain(|(t, b, p, _)| !(t == tenant_id && b == backend && p == public_id));
            if lock.len() == initial {
                return Err(crate::db::DbError::MappingNotFound);
            }
            Ok(())
        }

        async fn list_public_ids(
            &self,
            tenant_id: &str,
            backend: &str,
        ) -> Result<Vec<String>, crate::db::DbError> {
            let lock = self.mappings.lock().await;
            Ok(lock
                .iter()
                .filter(|(t, b, _, _)| t == tenant_id && b == backend)
                .map(|(_, _, p, _)| p.clone())
                .collect())
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            backend: &str,
            ory_global_id: &str,
        ) -> Result<Option<String>, crate::db::DbError> {
            let lock = self.mappings.lock().await;
            Ok(lock
                .iter()
                .find(|(_, b, _, o)| b == backend && o == ory_global_id)
                .map(|(t, _, _, _)| t.clone()))
        }
    }

    #[derive(Clone)]
    struct StubSchemas {
        schema_json: Value,
    }

    impl StubSchemas {
        fn valid() -> Self {
            Self {
                schema_json: json!({"type": "object"}),
            }
        }

        fn invalid() -> Self {
            Self {
                schema_json: json!({"type": "string"}),
            }
        }

        fn row(&self, tenant_id: &str) -> IdentitySchemaRow {
            IdentitySchemaRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                schema_id: "default".to_string(),
                schema_json: self.schema_json.clone(),
                is_default: true,
                created_at: time::OffsetDateTime::UNIX_EPOCH,
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
            }
        }
    }

    #[async_trait]
    impl IdentitySchemaStore for StubSchemas {
        async fn create(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
            _schema_json: Value,
            _is_default: bool,
        ) -> Result<IdentitySchemaRow, crate::db::DbError> {
            unimplemented!()
        }

        async fn get_by_schema_id(
            &self,
            tenant_id: &str,
            _schema_id: &str,
        ) -> Result<IdentitySchemaRow, crate::db::DbError> {
            Ok(self.row(tenant_id))
        }

        async fn list(
            &self,
            _tenant_id: &str,
        ) -> Result<Vec<IdentitySchemaRow>, crate::db::DbError> {
            unimplemented!()
        }

        async fn delete(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
        ) -> Result<(), crate::db::DbError> {
            unimplemented!()
        }

        async fn update(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
            _schema_json: Value,
            _is_default: bool,
        ) -> Result<IdentitySchemaRow, crate::db::DbError> {
            unimplemented!()
        }

        async fn set_default(
            &self,
            _tenant_id: &str,
            _schema_id: &str,
        ) -> Result<IdentitySchemaRow, crate::db::DbError> {
            unimplemented!()
        }

        async fn get_default(
            &self,
            tenant_id: &str,
        ) -> Result<IdentitySchemaRow, crate::db::DbError> {
            Ok(self.row(tenant_id))
        }
    }

    #[derive(Clone, Default)]
    struct StubGroups {
        groups: Arc<Mutex<Vec<ScimGroupRow>>>,
        members: Arc<Mutex<Vec<(String, String)>>>,
    }

    #[async_trait]
    impl ScimGroupStore for StubGroups {
        async fn create(
            &self,
            tenant_id: &str,
            display_name: &str,
        ) -> Result<ScimGroupRow, crate::db::DbError> {
            let row = ScimGroupRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                display_name: display_name.to_string(),
                created_at: time::OffsetDateTime::UNIX_EPOCH,
                updated_at: time::OffsetDateTime::UNIX_EPOCH,
            };
            self.groups.lock().await.push(row.clone());
            Ok(row)
        }

        async fn get(&self, tenant_id: &str, id: &str) -> Result<ScimGroupRow, crate::db::DbError> {
            self.groups
                .lock()
                .await
                .iter()
                .find(|g| g.tenant_id == tenant_id && g.id == id)
                .cloned()
                .ok_or(crate::db::DbError::TenantNotFound)
        }

        async fn list(&self, tenant_id: &str) -> Result<Vec<ScimGroupRow>, crate::db::DbError> {
            Ok(self
                .groups
                .lock()
                .await
                .iter()
                .filter(|g| g.tenant_id == tenant_id)
                .cloned()
                .collect())
        }

        async fn update(
            &self,
            tenant_id: &str,
            id: &str,
            display_name: &str,
        ) -> Result<ScimGroupRow, crate::db::DbError> {
            let mut lock = self.groups.lock().await;
            let row = lock
                .iter_mut()
                .find(|g| g.tenant_id == tenant_id && g.id == id)
                .ok_or(crate::db::DbError::TenantNotFound)?;
            row.display_name = display_name.to_string();
            row.updated_at = time::OffsetDateTime::UNIX_EPOCH;
            Ok(row.clone())
        }

        async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), crate::db::DbError> {
            let mut lock = self.groups.lock().await;
            let initial = lock.len();
            lock.retain(|g| !(g.tenant_id == tenant_id && g.id == id));
            if lock.len() == initial {
                return Err(crate::db::DbError::TenantNotFound);
            }
            Ok(())
        }

        async fn add_member(
            &self,
            _tenant_id: &str,
            group_id: &str,
            user_id: &str,
        ) -> Result<(), crate::db::DbError> {
            self.members
                .lock()
                .await
                .push((group_id.to_string(), user_id.to_string()));
            Ok(())
        }

        async fn remove_member(
            &self,
            _tenant_id: &str,
            group_id: &str,
            user_id: &str,
        ) -> Result<(), crate::db::DbError> {
            self.members
                .lock()
                .await
                .retain(|m| !(m.0 == group_id && m.1 == user_id));
            Ok(())
        }

        async fn list_members(&self, group_id: &str) -> Result<Vec<String>, crate::db::DbError> {
            Ok(self
                .members
                .lock()
                .await
                .iter()
                .filter(|m| m.0 == group_id)
                .map(|m| m.1.clone())
                .collect())
        }

        async fn list_user_groups(&self, user_id: &str) -> Result<Vec<String>, crate::db::DbError> {
            Ok(self
                .members
                .lock()
                .await
                .iter()
                .filter(|m| m.1 == user_id)
                .map(|m| m.0.clone())
                .collect())
        }

        async fn remove_user_from_all_groups(
            &self,
            user_id: &str,
        ) -> Result<(), crate::db::DbError> {
            self.members.lock().await.retain(|m| m.1 != user_id);
            Ok(())
        }
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

    #[test]
    fn decode_request_decodes_valid_message() {
        let req = ScimGetUserRequest {
            id: "user-1".into(),
            ..Default::default()
        };
        let bytes = Bytes::from(req.encode_to_vec());
        let view = decode_request::<ScimGetUserRequest>(&bytes).expect("decode");
        assert_eq!(view.id, "user-1");
    }

    #[test]
    fn decode_request_returns_internal_error_for_bad_bytes() {
        let bytes = Bytes::from_static(b"not-a-proto-message");
        let err = decode_request::<ScimGetUserRequest>(&bytes).expect_err("decode");
        assert!(matches!(err, ServiceError::Internal(_)));
    }

    #[test]
    fn require_tenant_extracts_tenant_id() {
        let ctx = request_context("tenant-1".into());
        assert_eq!(require_tenant(&ctx).unwrap(), "tenant-1");
    }

    #[test]
    fn require_tenant_missing_returns_unauthenticated() {
        let ctx = RequestContext::new(HeaderMap::new());
        let err = require_tenant(&ctx).expect_err("tenant");
        assert!(matches!(err, ServiceError::Unauthenticated(_)));
    }

    #[tokio::test]
    async fn scim_service_impl_new_stores_dependencies() {
        let pool =
            sqlx::PgPool::connect_lazy("postgres://localhost:5432/unused").expect("lazy pool");
        let kratos = Arc::new(KratosClient::new("http://localhost:1").unwrap());
        let backend: Arc<dyn PermissionBackend> = Arc::new(StubPermissionBackend::default());
        let mappings = IdMappingRepo::new(pool.clone());
        let schemas = IdentitySchemaRepo::new(pool.clone());
        let groups = ScimGroupRepo::new(pool);
        let service = ScimServiceImpl::new(kratos, backend, mappings, schemas, groups);
        // Exercise Clone to ensure the struct fields are consistent.
        let _cloned = service.clone();
    }

    #[tokio::test]
    async fn create_user_creates_identity_and_mapping() {
        let service = make_service();
        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let resp = service
            .create_user_http("tenant-1".into(), user)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.user_name, "alice");
        assert_eq!(resp.emails.len(), 1);
        assert!(!resp.id.is_empty());
    }

    #[tokio::test]
    async fn create_user_adds_group_memberships() {
        let service = make_service();
        let group = ScimGroup {
            display_name: "admins".into(),
            ..Default::default()
        };
        let group = service
            .create_group_http("tenant-1".into(), group)
            .await
            .unwrap()
            .body;

        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            groups: vec![group.id.clone()],
            ..Default::default()
        };
        let resp = service
            .create_user_http("tenant-1".into(), user)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.groups, vec![group.id]);
    }

    #[tokio::test]
    async fn create_user_requires_user_body() {
        let service = make_service();
        let req = ScimCreateUserRequest::default();
        let bytes = Bytes::from(req.encode_to_vec());
        let view = decode_request::<ScimCreateUserRequest>(&bytes).expect("decode");
        let svc_req = ServiceRequest::<ScimCreateUserRequest>::from_parts(&view, &bytes);
        let err = ScimService::create_user(&service, request_context("tenant-1".into()), svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn create_user_invalid_traits_returns_invalid_argument() {
        let service = ScimServiceImpl::new_for_test(
            Arc::new(StubKratos::default()),
            Arc::new(StubPermissionBackend::default()),
            Arc::new(StubMappings::default()),
            Arc::new(StubSchemas::invalid()),
            Arc::new(StubGroups::default()),
        );
        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let err = service
            .create_user_http("tenant-1".into(), user)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn create_user_kratos_error_maps_to_unavailable() {
        let service = ScimServiceImpl::new_for_test(
            Arc::new(FailingKratos {
                status: 503,
                message: "down".into(),
            }),
            Arc::new(StubPermissionBackend::default()),
            Arc::new(StubMappings::default()),
            Arc::new(StubSchemas::valid()),
            Arc::new(StubGroups::default()),
        );
        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let err = service
            .create_user_http("tenant-1".into(), user)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn get_user_returns_user() {
        let service = make_service();
        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let created = service
            .create_user_http("tenant-1".into(), user)
            .await
            .unwrap()
            .body;
        let fetched = service
            .get_user_http("tenant-1".into(), created.id)
            .await
            .unwrap()
            .body;
        assert_eq!(fetched.user_name, "alice");
    }

    #[tokio::test]
    async fn get_user_missing_mapping_returns_not_found() {
        let service = make_service();
        let err = service
            .get_user_http("tenant-1".into(), "missing".into())
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn list_users_returns_created_users() {
        let service = make_service();
        let u1 = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let u2 = ScimUser {
            user_name: "bob".into(),
            emails: vec![email_field("bob@example.com")],
            ..Default::default()
        };
        service
            .create_user_http("tenant-1".into(), u1)
            .await
            .unwrap();
        service
            .create_user_http("tenant-1".into(), u2)
            .await
            .unwrap();
        let resp = service
            .list_users_http("tenant-1".into())
            .await
            .unwrap()
            .body;
        assert_eq!(resp.users.len(), 2);
    }

    #[tokio::test]
    async fn update_user_updates_identity_and_group_memberships() {
        let service = make_service();
        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let created = service
            .create_user_http("tenant-1".into(), user)
            .await
            .unwrap()
            .body;

        let group = ScimGroup {
            display_name: "admins".into(),
            ..Default::default()
        };
        let group = service
            .create_group_http("tenant-1".into(), group)
            .await
            .unwrap()
            .body;

        let updated_user = ScimUser {
            user_name: "alicia".into(),
            emails: vec![email_field("alicia@example.com")],
            groups: vec![group.id.clone()],
            ..Default::default()
        };
        let resp = service
            .update_user_http("tenant-1".into(), created.id, updated_user)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.user_name, "alicia");
        assert_eq!(resp.groups, vec![group.id]);
    }

    #[tokio::test]
    async fn update_user_missing_mapping_returns_not_found() {
        let service = make_service();
        let user = ScimUser {
            user_name: "alice".into(),
            ..Default::default()
        };
        let err = service
            .update_user_http("tenant-1".into(), "missing".into(), user)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn delete_user_removes_identity_and_mapping() {
        let service = make_service();
        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let created = service
            .create_user_http("tenant-1".into(), user)
            .await
            .unwrap()
            .body;
        service
            .delete_user_http("tenant-1".into(), created.id.clone())
            .await
            .unwrap();
        let err = service
            .get_user_http("tenant-1".into(), created.id)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn delete_user_missing_mapping_returns_not_found() {
        let service = make_service();
        let err = service
            .delete_user_http("tenant-1".into(), "missing".into())
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn create_group_creates_group_and_adds_members() {
        let service = make_service();
        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let user = service
            .create_user_http("tenant-1".into(), user)
            .await
            .unwrap()
            .body;

        let mut group = ScimGroup {
            display_name: "admins".into(),
            ..Default::default()
        };
        group.members.push(ScimMember {
            value: user.id.clone(),
            ..Default::default()
        });
        let group = service
            .create_group_http("tenant-1".into(), group)
            .await
            .unwrap()
            .body;
        assert_eq!(group.display_name, "admins");
        assert_eq!(group.members.len(), 1);
        assert_eq!(group.members[0].value, user.id);
    }

    #[tokio::test]
    async fn create_group_requires_group_body() {
        let service = make_service();
        let req = ScimCreateGroupRequest::default();
        let bytes = Bytes::from(req.encode_to_vec());
        let view = decode_request::<ScimCreateGroupRequest>(&bytes).expect("decode");
        let svc_req = ServiceRequest::<ScimCreateGroupRequest>::from_parts(&view, &bytes);
        let err = ScimService::create_group(&service, request_context("tenant-1".into()), svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn get_group_returns_group_with_members() {
        let service = make_service();
        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let user = service
            .create_user_http("tenant-1".into(), user)
            .await
            .unwrap()
            .body;

        let mut group = ScimGroup {
            display_name: "admins".into(),
            ..Default::default()
        };
        group.members.push(ScimMember {
            value: user.id.clone(),
            ..Default::default()
        });
        let group = service
            .create_group_http("tenant-1".into(), group)
            .await
            .unwrap()
            .body;

        let fetched = service
            .get_group_http("tenant-1".into(), group.id)
            .await
            .unwrap()
            .body;
        assert_eq!(fetched.display_name, "admins");
        assert_eq!(fetched.members.len(), 1);
        assert_eq!(fetched.members[0].value, user.id);
    }

    #[tokio::test]
    async fn get_group_missing_returns_not_found() {
        let service = make_service();
        let err = service
            .get_group_http("tenant-1".into(), "missing".into())
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn list_groups_returns_groups() {
        let service = make_service();
        let g1 = ScimGroup {
            display_name: "admins".into(),
            ..Default::default()
        };
        let g2 = ScimGroup {
            display_name: "users".into(),
            ..Default::default()
        };
        service
            .create_group_http("tenant-1".into(), g1)
            .await
            .unwrap();
        service
            .create_group_http("tenant-1".into(), g2)
            .await
            .unwrap();
        let resp = service
            .list_groups_http("tenant-1".into())
            .await
            .unwrap()
            .body;
        assert_eq!(resp.groups.len(), 2);
    }

    #[tokio::test]
    async fn update_group_replaces_members() {
        let service = make_service();
        let user1 = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let user1 = service
            .create_user_http("tenant-1".into(), user1)
            .await
            .unwrap()
            .body;
        let user2 = ScimUser {
            user_name: "bob".into(),
            emails: vec![email_field("bob@example.com")],
            ..Default::default()
        };
        let user2 = service
            .create_user_http("tenant-1".into(), user2)
            .await
            .unwrap()
            .body;

        let mut group = ScimGroup {
            display_name: "admins".into(),
            ..Default::default()
        };
        group.members.push(ScimMember {
            value: user1.id.clone(),
            ..Default::default()
        });
        let group = service
            .create_group_http("tenant-1".into(), group)
            .await
            .unwrap()
            .body;
        assert_eq!(group.members.len(), 1);

        let mut updated = ScimGroup {
            display_name: "super-admins".into(),
            ..Default::default()
        };
        updated.members.push(ScimMember {
            value: user2.id.clone(),
            ..Default::default()
        });
        let group = service
            .update_group_http("tenant-1".into(), group.id, updated)
            .await
            .unwrap()
            .body;
        assert_eq!(group.display_name, "super-admins");
        assert_eq!(group.members.len(), 1);
        assert_eq!(group.members[0].value, user2.id);
    }

    #[tokio::test]
    async fn delete_group_removes_group() {
        let service = make_service();
        let group = ScimGroup {
            display_name: "admins".into(),
            ..Default::default()
        };
        let group = service
            .create_group_http("tenant-1".into(), group)
            .await
            .unwrap()
            .body;
        service
            .delete_group_http("tenant-1".into(), group.id.clone())
            .await
            .unwrap();
        let err = service
            .get_group_http("tenant-1".into(), group.id)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn missing_tenant_returns_unauthenticated() {
        let service = make_service();
        let req = ScimListUsersRequest::default();
        let bytes = Bytes::from(req.encode_to_vec());
        let view = decode_request::<ScimListUsersRequest>(&bytes).expect("decode");
        let svc_req = ServiceRequest::<ScimListUsersRequest>::from_parts(&view, &bytes);
        let err = ScimService::list_users(&service, RequestContext::new(HeaderMap::new()), svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::Unauthenticated);
    }

    fn scoped_request_context(tenant_id: &str, scopes: &[&str]) -> RequestContext {
        let mut ctx = RequestContext::new(HeaderMap::new());
        ctx.extensions_mut().insert(TenantId(tenant_id.into()));
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: tenant_id.into(),
            subject: "scim-subject".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            token_hash: "hash".into(),
            authentication_methods: Vec::new(),
        });
        ctx
    }

    #[tokio::test]
    async fn create_user_requires_scim_admin_scope() {
        let service = make_service();
        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let req = ScimCreateUserRequest {
            user: Some(user).into(),
            ..Default::default()
        };
        let bytes = Bytes::from(req.encode_to_vec());
        let view = decode_request::<ScimCreateUserRequest>(&bytes).expect("decode");
        let svc_req = ServiceRequest::<ScimCreateUserRequest>::from_parts(&view, &bytes);
        let err = ScimService::create_user(
            &service,
            scoped_request_context("tenant-1", &[SCOPE_SCIM_READ]),
            svc_req,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn get_user_accepts_scim_read_scope() {
        let service = make_service();
        let user = ScimUser {
            user_name: "alice".into(),
            emails: vec![email_field("alice@example.com")],
            ..Default::default()
        };
        let created = service
            .create_user_http("tenant-1".into(), user)
            .await
            .unwrap()
            .body;
        let fetched = service
            .get_user_http("tenant-1".into(), created.id)
            .await
            .unwrap()
            .body;
        assert_eq!(fetched.user_name, "alice");
    }

    #[tokio::test]
    async fn get_user_requires_scim_read_or_admin_scope() {
        let service = make_service();
        let req = ScimGetUserRequest {
            id: "u1".into(),
            ..Default::default()
        };
        let bytes = Bytes::from(req.encode_to_vec());
        let view = decode_request::<ScimGetUserRequest>(&bytes).expect("decode");
        let svc_req = ServiceRequest::<ScimGetUserRequest>::from_parts(&view, &bytes);
        let err = ScimService::get_user(
            &service,
            scoped_request_context("tenant-1", &["other:scope"]),
            svc_req,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn delete_group_requires_scim_admin_scope() {
        let service = make_service();
        let req = ScimDeleteGroupRequest {
            id: "g1".into(),
            ..Default::default()
        };
        let bytes = Bytes::from(req.encode_to_vec());
        let view = decode_request::<ScimDeleteGroupRequest>(&bytes).expect("decode");
        let svc_req = ServiceRequest::<ScimDeleteGroupRequest>::from_parts(&view, &bytes);
        let err = ScimService::delete_group(
            &service,
            scoped_request_context("tenant-1", &[SCOPE_SCIM_READ]),
            svc_req,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn kratos_client_as_scim_kratos_delegates() {
        let client =
            Arc::new(KratosClient::new("http://localhost:1").unwrap()) as Arc<dyn ScimKratos>;
        assert!(client.create_identity(json!({})).await.is_err());
        assert!(client.get_identity("id").await.is_err());
        assert!(client.update_identity("id", json!({})).await.is_err());
        assert!(client.delete_identity("id").await.is_err());
    }

    #[cfg(feature = "keto")]
    #[tokio::test]
    async fn keto_client_as_permission_backend_delegates() {
        let client = Arc::new(KetoClient::new("http://localhost:1", "http://localhost:1").unwrap())
            as Arc<dyn PermissionBackend>;
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
    }
}
