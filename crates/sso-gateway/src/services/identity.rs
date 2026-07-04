use std::sync::Arc;

use buffa_types::google::protobuf::Struct as ProtoStruct;
use buffa_types::google::protobuf::{Empty, Timestamp};
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use sso_ory_client::{
    error::OryClientError,
    kratos::{KratosClient, KratosResponse},
};
use sunbeam_g2v::error::ServiceError;
use tracing::{debug, instrument};
use ulid::Ulid;

use crate::{
    auth::{AuthContext, SCOPE_IDENTITY_ADMIN, SCOPE_IDENTITY_READ, require_scope},
    db::{IdMappingStore, IdentitySchemaRow, IdentitySchemaStore},
    middleware::TenantId,
    proto::iam::v1::{
        CreateIdentityRequest, CreateIdentitySchemaRequest, CreateLoginFlowRequest,
        CreateRecoveryLinkRequest, CreateRegistrationFlowRequest, DeleteIdentityRequest,
        DeleteIdentitySchemaRequest, DeleteSessionRequest, Flow, GetIdentityRequest,
        GetIdentitySchemaRequest, GetSessionRequest, GetVerificationMessageRequest, Identity,
        IdentitySchema, IdentityService, ListIdentitiesRequest, ListIdentitiesResponse,
        ListIdentitySchemasRequest, ListIdentitySchemasResponse, ListSessionsRequest,
        ListSessionsResponse, RecoveryLink, Session, SetDefaultIdentitySchemaRequest,
        UpdateIdentityRequest, UpdateIdentitySchemaRequest, VerificationMessage,
    },
};

const BACKEND_KRATOS: &str = "kratos";

/// Local async trait for the subset of Kratos operations used by identity
/// service. Keeps the service implementation testable without a real Ory
/// backend.
#[async_trait::async_trait]
pub trait IdentityKratos: Send + Sync + 'static {
    async fn create_identity(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError>;

    async fn get_identity(&self, id: &str) -> Result<serde_json::Value, OryClientError>;

    async fn update_identity(
        &self,
        id: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError>;

    async fn delete_identity(&self, id: &str) -> Result<(), OryClientError>;

    async fn create_login_flow(
        &self,
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, OryClientError>;

    async fn create_registration_flow(
        &self,
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, OryClientError>;

    async fn admin_get_session(&self, id: &str) -> Result<serde_json::Value, OryClientError>;

    async fn list_sessions_by_identity(
        &self,
        identity_id: &str,
    ) -> Result<serde_json::Value, OryClientError>;

    async fn delete_session(&self, id: &str) -> Result<(), OryClientError>;

    async fn create_recovery_link(
        &self,
        identity_id: &str,
        expires_in_seconds: Option<i64>,
    ) -> Result<KratosResponse, OryClientError>;

    async fn list_courier_messages(
        &self,
        identity_id: Option<&str>,
        message_type: Option<&str>,
    ) -> Result<serde_json::Value, OryClientError>;
}

#[async_trait::async_trait]
impl IdentityKratos for KratosClient {
    async fn create_identity(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.create_identity(payload).await
    }

    async fn get_identity(&self, id: &str) -> Result<serde_json::Value, OryClientError> {
        self.get_identity(id).await
    }

    async fn update_identity(
        &self,
        id: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, OryClientError> {
        self.update_identity(id, payload).await
    }

    async fn delete_identity(&self, id: &str) -> Result<(), OryClientError> {
        self.delete_identity(id).await
    }

    async fn create_login_flow(
        &self,
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, OryClientError> {
        self.create_login_flow(query).await
    }

    async fn create_registration_flow(
        &self,
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, OryClientError> {
        self.create_registration_flow(query).await
    }

    async fn admin_get_session(&self, id: &str) -> Result<serde_json::Value, OryClientError> {
        self.admin_get_session(id).await
    }

    async fn list_sessions_by_identity(
        &self,
        identity_id: &str,
    ) -> Result<serde_json::Value, OryClientError> {
        self.list_sessions_by_identity(identity_id).await
    }

    async fn delete_session(&self, id: &str) -> Result<(), OryClientError> {
        self.delete_session(id).await
    }

    async fn create_recovery_link(
        &self,
        identity_id: &str,
        expires_in_seconds: Option<i64>,
    ) -> Result<KratosResponse, OryClientError> {
        self.create_recovery_link(identity_id, expires_in_seconds)
            .await
    }

    async fn list_courier_messages(
        &self,
        identity_id: Option<&str>,
        message_type: Option<&str>,
    ) -> Result<serde_json::Value, OryClientError> {
        self.list_courier_messages(identity_id, message_type).await
    }
}

#[derive(Clone)]
pub struct IdentityServiceImpl {
    kratos: Arc<dyn IdentityKratos>,
    mappings: Arc<dyn IdMappingStore>,
    schemas: Arc<dyn IdentitySchemaStore>,
    ui_public_url: String,
}

impl IdentityServiceImpl {
    pub fn new(
        kratos: Arc<KratosClient>,
        mappings: crate::db::IdMappingRepo,
        schemas: crate::db::IdentitySchemaRepo,
        ui_public_url: String,
    ) -> Self {
        Self {
            kratos: kratos as Arc<dyn IdentityKratos>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
            schemas: Arc::new(schemas) as Arc<dyn IdentitySchemaStore>,
            ui_public_url,
        }
    }
}

#[allow(refining_impl_trait)]
impl IdentityService for IdentityServiceImpl {
    #[instrument(skip(self, request))]
    async fn create_identity(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateIdentityRequest>,
    ) -> ServiceResult<Identity> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_IDENTITY_ADMIN)?;
        let req = request.to_owned_message();

        let schema = self.resolve_schema(&tenant_id, &req.schema_id).await?;
        let traits_json = req
            .traits
            .as_option()
            .map(|s| serde_json::to_value(s).unwrap_or_default())
            .unwrap_or_else(|| serde_json::json!({}));
        validate_traits(&schema.schema_json, &traits_json)?;

        let payload = build_kratos_identity_payload(&schema.schema_id, traits_json, &req.password);
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

        Ok(Response::new(kratos_to_identity(
            &created,
            &tenant_id,
            &public_id,
            &schema.schema_id,
        )))
    }

    #[instrument(skip(self, request))]
    async fn get_identity(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetIdentityRequest>,
    ) -> ServiceResult<Identity> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_IDENTITY_READ, SCOPE_IDENTITY_ADMIN])?;
        let req = request.to_owned_message();
        let (ory_id, schema_id) = self.resolve_identity(&tenant_id, &req.id).await?;

        let identity = self
            .kratos
            .get_identity(&ory_id)
            .await
            .map_err(map_ory_error)?;

        Ok(Response::new(kratos_to_identity(
            &identity, &tenant_id, &req.id, &schema_id,
        )))
    }

    #[instrument(skip(self, _request))]
    async fn list_identities(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListIdentitiesRequest>,
    ) -> ServiceResult<ListIdentitiesResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_IDENTITY_READ, SCOPE_IDENTITY_ADMIN])?;
        let public_ids = self
            .mappings
            .list_public_ids(&tenant_id, BACKEND_KRATOS)
            .await?;

        let mut identities = Vec::with_capacity(public_ids.len());
        for public_id in public_ids {
            match self.resolve_identity(&tenant_id, &public_id).await {
                Ok((ory_id, schema_id)) => match self.kratos.get_identity(&ory_id).await {
                    Ok(identity) => identities.push(kratos_to_identity(
                        &identity, &tenant_id, &public_id, &schema_id,
                    )),
                    Err(err) => debug!(%public_id, "failed to fetch kratos identity: {}", err),
                },
                Err(err) => debug!(%public_id, "mapping lookup failed: {}", err),
            }
        }

        Ok(Response::new(ListIdentitiesResponse {
            identities,
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn update_identity(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateIdentityRequest>,
    ) -> ServiceResult<Identity> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_IDENTITY_ADMIN)?;
        let req = request.to_owned_message();
        let (ory_id, current_schema_id) = self.resolve_identity(&tenant_id, &req.id).await?;

        let schema_id = if req.schema_id.is_empty() {
            current_schema_id
        } else {
            req.schema_id
        };
        let schema = self.resolve_schema(&tenant_id, &schema_id).await?;

        let traits_json = req
            .traits
            .as_option()
            .map(|s| serde_json::to_value(s).unwrap_or_default())
            .unwrap_or_else(|| serde_json::json!({}));
        validate_traits(&schema.schema_json, &traits_json)?;

        let payload = build_kratos_identity_payload(&schema.schema_id, traits_json, "");
        let updated = self
            .kratos
            .update_identity(&ory_id, payload)
            .await
            .map_err(map_ory_error)?;

        Ok(Response::new(kratos_to_identity(
            &updated,
            &tenant_id,
            &req.id,
            &schema.schema_id,
        )))
    }

    #[instrument(skip(self, request))]
    async fn delete_identity(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteIdentityRequest>,
    ) -> ServiceResult<Empty> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_IDENTITY_ADMIN)?;
        let req = request.to_owned_message();
        let ory_id = self
            .mappings
            .get_ory_id(&tenant_id, BACKEND_KRATOS, &req.id)
            .await?;

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
    async fn create_identity_schema(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateIdentitySchemaRequest>,
    ) -> ServiceResult<IdentitySchema> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_IDENTITY_ADMIN)?;
        let req = request.to_owned_message();
        let schema_json = req
            .schema_json
            .as_option()
            .map(|s| serde_json::to_value(s).unwrap_or_default())
            .unwrap_or_else(|| serde_json::json!({}));
        let row = self
            .schemas
            .create(&tenant_id, &req.schema_id, schema_json, req.is_default)
            .await?;
        Ok(Response::new(schema_row_to_proto(row)))
    }

    #[instrument(skip(self, request))]
    async fn get_identity_schema(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetIdentitySchemaRequest>,
    ) -> ServiceResult<IdentitySchema> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_IDENTITY_READ, SCOPE_IDENTITY_ADMIN])?;
        let req = request.to_owned_message();
        let row = self
            .schemas
            .get_by_schema_id(&tenant_id, &req.schema_id)
            .await?;
        Ok(Response::new(schema_row_to_proto(row)))
    }

    #[instrument(skip(self, _request))]
    async fn list_identity_schemas(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListIdentitySchemasRequest>,
    ) -> ServiceResult<ListIdentitySchemasResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_IDENTITY_READ, SCOPE_IDENTITY_ADMIN])?;
        let rows = self.schemas.list(&tenant_id).await?;
        let schemas = rows.into_iter().map(schema_row_to_proto).collect();
        Ok(Response::new(ListIdentitySchemasResponse {
            schemas,
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn update_identity_schema(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateIdentitySchemaRequest>,
    ) -> ServiceResult<IdentitySchema> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_IDENTITY_ADMIN)?;
        let req = request.to_owned_message();
        let schema_json = req
            .schema_json
            .as_option()
            .map(|s| serde_json::to_value(s).unwrap_or_default())
            .unwrap_or_else(|| serde_json::json!({}));
        let row = self
            .schemas
            .update(&tenant_id, &req.schema_id, schema_json, req.is_default)
            .await?;
        Ok(Response::new(schema_row_to_proto(row)))
    }

    #[instrument(skip(self, request))]
    async fn delete_identity_schema(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteIdentitySchemaRequest>,
    ) -> ServiceResult<Empty> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_IDENTITY_ADMIN)?;
        let req = request.to_owned_message();
        self.schemas.delete(&tenant_id, &req.schema_id).await?;
        Ok(Response::new(Empty::default()))
    }

    #[instrument(skip(self, request))]
    async fn set_default_identity_schema(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetDefaultIdentitySchemaRequest>,
    ) -> ServiceResult<IdentitySchema> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_IDENTITY_ADMIN)?;
        let req = request.to_owned_message();
        let row = self.schemas.set_default(&tenant_id, &req.schema_id).await?;
        Ok(Response::new(schema_row_to_proto(row)))
    }

    #[instrument(skip(self, request))]
    async fn create_login_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateLoginFlowRequest>,
    ) -> ServiceResult<Flow> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_IDENTITY_READ, SCOPE_IDENTITY_ADMIN])?;
        let req = request.to_owned_message();
        let mut query = Vec::<(&str, &str)>::new();
        if !req.return_to.is_empty() {
            query.push(("return_to", req.return_to.as_str()));
        }
        if !req.aal.is_empty() {
            query.push(("aal", req.aal.as_str()));
        }
        if req.refresh {
            query.push(("refresh", "true"));
        }
        if !req.organization.is_empty() {
            query.push(("organization", req.organization.as_str()));
        }
        if !req.via.is_empty() {
            query.push(("via", req.via.as_str()));
        }
        if !req.login_challenge.is_empty() {
            query.push(("login_challenge", req.login_challenge.as_str()));
        }
        if !req.identity_schema.is_empty() {
            query.push(("identity_schema", req.identity_schema.as_str()));
        }
        let flow = self
            .kratos
            .create_login_flow(&query)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(kratos_flow_to_flow(&flow, &tenant_id)))
    }

    #[instrument(skip(self, request))]
    async fn create_registration_flow(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateRegistrationFlowRequest>,
    ) -> ServiceResult<Flow> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_IDENTITY_READ, SCOPE_IDENTITY_ADMIN])?;
        let req = request.to_owned_message();
        let mut query = Vec::<(&str, &str)>::new();
        if !req.return_to.is_empty() {
            query.push(("return_to", req.return_to.as_str()));
        }
        if !req.login_challenge.is_empty() {
            query.push(("login_challenge", req.login_challenge.as_str()));
        }
        if !req.identity_schema.is_empty() {
            query.push(("identity_schema", req.identity_schema.as_str()));
        }
        let flow = self
            .kratos
            .create_registration_flow(&query)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(kratos_flow_to_flow(&flow, &tenant_id)))
    }

    #[instrument(skip(self, request))]
    async fn get_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetSessionRequest>,
    ) -> ServiceResult<Session> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_IDENTITY_READ, SCOPE_IDENTITY_ADMIN])?;
        let req = request.to_owned_message();
        let session = self
            .kratos
            .admin_get_session(&req.id)
            .await
            .map_err(map_ory_error)?;

        let identity_id = session["identity_id"].as_str().unwrap_or("");
        let public_identity_id = self
            .mappings
            .get_public_id(&tenant_id, BACKEND_KRATOS, identity_id)
            .await?;

        Ok(Response::new(Session {
            id: req.id,
            identity_id: public_identity_id,
            tenant_id,
            active: session["active"].as_bool().unwrap_or(false),
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn list_sessions(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListSessionsRequest>,
    ) -> ServiceResult<ListSessionsResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_IDENTITY_READ, SCOPE_IDENTITY_ADMIN])?;
        let req = request.to_owned_message();

        if req.identity_id.is_empty() {
            return Err(ServiceError::InvalidArgument("identity_id is required".into()).into());
        }

        let ory_id = self
            .mappings
            .get_ory_id(&tenant_id, BACKEND_KRATOS, &req.identity_id)
            .await?;

        let sessions = self
            .kratos
            .list_sessions_by_identity(&ory_id)
            .await
            .map_err(map_ory_error)?;

        let items = sessions
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|s| kratos_session_to_session(s, &tenant_id, &req.identity_id))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Response::new(ListSessionsResponse {
            sessions: items,
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn delete_session(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteSessionRequest>,
    ) -> ServiceResult<Empty> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_IDENTITY_ADMIN)?;
        let req = request.to_owned_message();

        let session = self
            .kratos
            .admin_get_session(&req.id)
            .await
            .map_err(map_ory_error)?;
        let identity_id = session["identity_id"].as_str().unwrap_or("");
        // Verify the session belongs to an identity in the caller's tenant.
        let _ = self
            .mappings
            .get_public_id(&tenant_id, BACKEND_KRATOS, identity_id)
            .await?;

        self.kratos
            .delete_session(&req.id)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(Empty::default()))
    }

    #[instrument(skip(self, request))]
    async fn create_recovery_link(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateRecoveryLinkRequest>,
    ) -> ServiceResult<RecoveryLink> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_IDENTITY_ADMIN)?;
        let req = request.to_owned_message();

        let (ory_id, _) = self.resolve_identity(&tenant_id, &req.identity_id).await?;
        let response = self
            .kratos
            .create_recovery_link(&ory_id, Some(req.expires_in_seconds))
            .await
            .map_err(map_ory_error)?;

        let recovery_link = response.body["recovery_link"].as_str().ok_or_else(|| {
            ServiceError::Internal("kratos response missing recovery_link".into())
        })?;
        let recovery_url = reqwest::Url::parse(recovery_link).map_err(|e| {
            ServiceError::Internal(format!("kratos recovery_link is not a valid URL: {e}"))
        })?;
        let recovery_token = response.body["recovery_token"]
            .as_str()
            .map(|t| t.to_string())
            .or_else(|| {
                recovery_url
                    .query_pairs()
                    .find(|(k, _)| k == "token")
                    .map(|(_, v)| v.into_owned())
            })
            .ok_or_else(|| {
                ServiceError::Internal(
                    "kratos response missing recovery_token and token query param".into(),
                )
            })?;
        let flow = recovery_url
            .query_pairs()
            .find(|(k, _)| k == "flow")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();

        let gateway_link = if flow.is_empty() {
            format!(
                "{}/recovery?token={}",
                self.ui_public_url.trim_end_matches('/'),
                urlencoding::encode(&recovery_token)
            )
        } else {
            format!(
                "{}/recovery?flow={}&token={}",
                self.ui_public_url.trim_end_matches('/'),
                urlencoding::encode(&flow),
                urlencoding::encode(&recovery_token)
            )
        };

        Ok(Response::new(RecoveryLink {
            recovery_link: gateway_link,
            recovery_token: recovery_token.to_string(),
            flow,
            expires_at: response.body["expires_at"]
                .as_str()
                .and_then(parse_timestamp)
                .map(Into::into)
                .unwrap_or_default(),
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn get_verification_message(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetVerificationMessageRequest>,
    ) -> ServiceResult<VerificationMessage> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_IDENTITY_ADMIN)?;
        let req = request.to_owned_message();

        let (ory_id, _) = self.resolve_identity(&tenant_id, &req.identity_id).await?;
        let messages = self
            .kratos
            .list_courier_messages(Some(&ory_id), Some("verification"))
            .await
            .map_err(map_ory_error)?;
        let messages = messages.as_array().ok_or_else(|| {
            ServiceError::Internal("invalid courier messages response from kratos".into())
        })?;

        let message = if req.message_id.is_empty() {
            messages
                .iter()
                .rev()
                .find(|m| m["template_type"].as_str() == Some("verification"))
                .or_else(|| messages.last())
        } else {
            messages.iter().find(|m| {
                m["id"]
                    .as_str()
                    .map(|id| id == req.message_id)
                    .unwrap_or(false)
            })
        }
        .ok_or_else(|| ServiceError::NotFound("verification message not found".into()))?;

        let body = message["body"].as_str().unwrap_or("");
        let (link, flow) = extract_first_self_service_link(body)
            .and_then(|url| {
                reqwest::Url::parse(&url).ok().map(|u| {
                    let token = u
                        .query_pairs()
                        .find(|(k, _)| k == "token")
                        .map(|(_, v)| v.into_owned())
                        .unwrap_or_default();
                    let flow = u
                        .query_pairs()
                        .find(|(k, _)| k == "flow")
                        .map(|(_, v)| v.into_owned())
                        .unwrap_or_default();
                    let link = if token.is_empty() {
                        String::new()
                    } else if flow.is_empty() {
                        format!(
                            "{}/verification?token={}",
                            self.ui_public_url.trim_end_matches('/'),
                            urlencoding::encode(&token)
                        )
                    } else {
                        format!(
                            "{}/verification?flow={}&token={}",
                            self.ui_public_url.trim_end_matches('/'),
                            urlencoding::encode(&flow),
                            urlencoding::encode(&token)
                        )
                    };
                    (link, flow)
                })
            })
            .unwrap_or_default();

        Ok(Response::new(VerificationMessage {
            id: message["id"].as_str().unwrap_or("").to_string(),
            r#type: message["type"].as_str().unwrap_or("").to_string(),
            subject: message["subject"].as_str().unwrap_or("").to_string(),
            body: body.to_string(),
            status: message["status"].as_str().unwrap_or("").to_string(),
            recipient: message["recipient"].as_str().unwrap_or("").to_string(),
            sent_at: message["sent_at"]
                .as_str()
                .and_then(parse_timestamp)
                .map(Into::into)
                .unwrap_or_default(),
            link,
            flow,
            ..Default::default()
        }))
    }
}

impl IdentityServiceImpl {
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
}

const MAX_SCHEMA_SIZE_BYTES: usize = 64 * 1024;
const MAX_SCHEMA_DEPTH: usize = 10;

pub(crate) fn validate_traits(
    schema_json: &serde_json::Value,
    traits: &serde_json::Value,
) -> Result<(), ServiceError> {
    // Tenant schemas may be stored either as the full Kratos identity schema
    // (which wraps traits under `properties.traits`) or directly as the traits
    // schema. Prefer the traits subschema when it exists.
    let traits_schema = schema_json
        .get("properties")
        .and_then(|p| p.get("traits"))
        .unwrap_or(schema_json);

    validate_schema_size(traits_schema)?;
    validate_schema_depth(traits_schema, 0)?;
    reject_remote_refs(traits_schema)?;
    validate_schema_depth(traits, 0)?;

    let validator = jsonschema::validator_for(traits_schema)
        .map_err(|e| ServiceError::InvalidArgument(format!("invalid identity schema: {e}")))?;
    if let Err(error) = validator.validate(traits) {
        return Err(ServiceError::InvalidArgument(format!(
            "traits validation failed: {error}"
        )));
    }
    Ok(())
}

fn validate_schema_size(schema: &serde_json::Value) -> Result<(), ServiceError> {
    let size = serde_json::to_string(schema)
        .map(|s| s.len())
        .unwrap_or(usize::MAX);
    if size > MAX_SCHEMA_SIZE_BYTES {
        return Err(ServiceError::InvalidArgument(
            "identity schema exceeds maximum size of 64KiB".into(),
        ));
    }
    Ok(())
}

fn validate_schema_depth(value: &serde_json::Value, depth: usize) -> Result<(), ServiceError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(ServiceError::InvalidArgument(
            "identity schema exceeds maximum depth of 10".into(),
        ));
    }
    match value {
        serde_json::Value::Object(map) => {
            for child in map.values() {
                validate_schema_depth(child, depth + 1)?;
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                validate_schema_depth(child, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_remote_refs(value: &serde_json::Value) -> Result<(), ServiceError> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(r)) = map.get("$ref")
                && !r.starts_with('#')
            {
                return Err(ServiceError::InvalidArgument(
                    "identity schema contains remote $ref".into(),
                ));
            }
            for child in map.values() {
                reject_remote_refs(child)?;
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                reject_remote_refs(child)?;
            }
        }
        _ => {}
    }
    Ok(())
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

/// Extract the first self-service URL from a message body.
///
/// Kratos courier message bodies embed the recovery/verification URL in an
/// HTML anchor or as plain text. This helper finds the first URL that looks
/// like a gateway-recoverable self-service link.
fn extract_first_self_service_link(body: &str) -> Option<String> {
    // Prefer an explicit anchor href.
    if let Some(start) = body.find("href=\"") {
        let rest = &body[start + 6..];
        if let Some(end) = rest.find('"') {
            let url = &rest[..end];
            if url.contains("/self-service/") {
                return Some(url.to_string());
            }
        }
    }
    // Fall back to the first absolute URL containing a self-service path.
    for word in body.split_whitespace() {
        let stripped = word.trim_matches(|c: char| c == '"' || c == '\'' || c == '<' || c == '>');
        if (stripped.starts_with("http://") || stripped.starts_with("https://"))
            && stripped.contains("/self-service/")
        {
            return Some(stripped.to_string());
        }
    }
    None
}

fn build_kratos_identity_payload(
    schema_id: &str,
    traits: serde_json::Value,
    password: &str,
) -> serde_json::Value {
    if password.is_empty() {
        serde_json::json!({
            "schema_id": schema_id,
            "traits": traits,
        })
    } else {
        serde_json::json!({
            "schema_id": schema_id,
            "traits": traits,
            "credentials": {
                "password": {
                    "config": {
                        "password": password,
                    },
                },
            },
        })
    }
}

fn kratos_to_identity(
    identity: &serde_json::Value,
    tenant_id: &str,
    public_id: &str,
    schema_id: &str,
) -> Identity {
    let traits_struct = match serde_json::from_value::<ProtoStruct>(identity["traits"].clone()) {
        Ok(s) => Some(s),
        Err(err) => {
            tracing::warn!("failed to decode identity traits: {}", err);
            None
        }
    };
    Identity {
        id: public_id.to_string(),
        tenant_id: tenant_id.to_string(),
        schema_id: schema_id.to_string(),
        traits: traits_struct.map(Into::into).unwrap_or_default(),
        ..Default::default()
    }
}

fn kratos_session_to_session(
    session: &serde_json::Value,
    tenant_id: &str,
    public_identity_id: &str,
) -> Session {
    Session {
        id: session["id"].as_str().unwrap_or("").to_string(),
        identity_id: public_identity_id.to_string(),
        tenant_id: tenant_id.to_string(),
        active: session["active"].as_bool().unwrap_or(false),
        ..Default::default()
    }
}

fn schema_row_to_proto(row: IdentitySchemaRow) -> IdentitySchema {
    let schema_struct = serde_json::from_value::<ProtoStruct>(row.schema_json).unwrap_or_default();
    IdentitySchema {
        id: row.id,
        tenant_id: row.tenant_id,
        schema_id: row.schema_id,
        schema_json: Some(schema_struct).into(),
        is_default: row.is_default,
        created_at: None.into(),
        updated_at: None.into(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn kratos_flow_to_flow(flow: &serde_json::Value, tenant_id: &str) -> Flow {
    let ui_struct = serde_json::from_value::<ProtoStruct>(flow["ui"].clone()).unwrap_or_default();
    Flow {
        id: flow["id"].as_str().unwrap_or("").to_string(),
        r#type: flow["type"].as_str().unwrap_or("").to_string(),
        tenant_id: tenant_id.to_string(),
        identity_id: flow["identity"]["id"].as_str().unwrap_or("").to_string(),
        expires_at: flow["expires_at"]
            .as_str()
            .and_then(parse_timestamp)
            .map(Into::into)
            .unwrap_or_default(),
        ui: Some(ui_struct).into(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn parse_timestamp(value: &str) -> Option<Timestamp> {
    // Kratos returns RFC3339 timestamps; parse with chrono then convert.
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
            ..Default::default()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use async_trait::async_trait;
    use buffa::Message;
    use buffa::bytes::Bytes;
    use buffa::view::{HasMessageView, MessageView};
    use http::HeaderMap;
    use serde_json::json;
    use tokio::sync::Mutex;

    use crate::auth::AuthContext;
    use crate::db::{DbError, IdMappingRepo, IdMappingRow, IdentitySchemaRepo};

    macro_rules! svc_req {
        ($id:ident, $req:expr, $ty:ty) => {
            let bytes = Bytes::from($req.encode_to_vec());
            let view = decode_request::<$ty>(&bytes).expect("valid encoded request");
            let $id = ServiceRequest::<$ty>::from_parts(&view, &bytes);
        };
    }

    fn decode_request<'a, Req: HasMessageView>(
        bytes: &'a Bytes,
    ) -> Result<Req::View<'a>, ServiceError> {
        Req::View::<'a>::decode_view(bytes)
            .map_err(|e| ServiceError::Internal(format!("failed to decode request: {e}")))
    }

    fn request_context(tenant_id: &str, scopes: &[&str]) -> RequestContext {
        let mut ctx = RequestContext::new(HeaderMap::new());
        ctx.extensions_mut().insert(TenantId(tenant_id.to_string()));
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: tenant_id.to_string(),
            subject: "sub-1".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            token_hash: "hash".into(),
            authentication_methods: Vec::new(),
        });
        ctx
    }

    fn admin_ctx(tenant_id: &str) -> RequestContext {
        request_context(tenant_id, &[SCOPE_IDENTITY_ADMIN])
    }

    fn read_ctx(tenant_id: &str) -> RequestContext {
        request_context(tenant_id, &[SCOPE_IDENTITY_READ])
    }

    fn no_scope_ctx(tenant_id: &str) -> RequestContext {
        request_context(tenant_id, &["other:scope"])
    }

    fn schema_row(
        tenant_id: &str,
        schema_id: &str,
        schema_json: serde_json::Value,
        is_default: bool,
    ) -> IdentitySchemaRow {
        IdentitySchemaRow {
            id: Ulid::new().to_string(),
            tenant_id: tenant_id.to_string(),
            schema_id: schema_id.to_string(),
            schema_json,
            is_default,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn email_schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "email": { "type": "string", "format": "email" }
            },
            "required": ["email"]
        })
    }

    fn proto_struct(value: serde_json::Value) -> ProtoStruct {
        serde_json::from_value(value).unwrap_or_default()
    }

    #[derive(Default)]
    struct StubKratos {
        identities: Mutex<HashMap<String, serde_json::Value>>,
        sessions: Mutex<HashMap<String, serde_json::Value>>,
        sessions_by_identity: Mutex<HashMap<String, serde_json::Value>>,
        flows: Mutex<Vec<serde_json::Value>>,
        recovery_link: Mutex<Option<KratosResponse>>,
        courier_messages: Mutex<Option<serde_json::Value>>,
        error: Mutex<Option<OryClientError>>,
    }

    impl StubKratos {
        fn with_identity(id: &str, identity: serde_json::Value) -> Self {
            let mut map = HashMap::new();
            map.insert(id.to_string(), identity);
            Self {
                identities: Mutex::new(map),
                ..Default::default()
            }
        }

        fn with_recovery_link(link: KratosResponse) -> Self {
            Self {
                recovery_link: Mutex::new(Some(link)),
                ..Default::default()
            }
        }

        fn with_courier_messages(messages: serde_json::Value) -> Self {
            Self {
                courier_messages: Mutex::new(Some(messages)),
                ..Default::default()
            }
        }

        fn with_error(err: OryClientError) -> Self {
            Self {
                error: Mutex::new(Some(err)),
                ..Default::default()
            }
        }
    }

    #[async_trait]
    impl IdentityKratos for StubKratos {
        async fn create_identity(
            &self,
            payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            if let Some(err) = self.error.lock().await.take() {
                return Err(err);
            }
            let id = Ulid::new().to_string();
            let mut identity = payload.clone();
            identity["id"] = json!(id);
            self.identities
                .lock()
                .await
                .insert(id.clone(), identity.clone());
            Ok(identity)
        }

        async fn get_identity(&self, id: &str) -> Result<serde_json::Value, OryClientError> {
            if let Some(err) = self.error.lock().await.take() {
                return Err(err);
            }
            self.identities
                .lock()
                .await
                .get(id)
                .cloned()
                .ok_or_else(|| OryClientError::Ory {
                    status: 404,
                    message: "not found".into(),
                })
        }

        async fn update_identity(
            &self,
            id: &str,
            payload: serde_json::Value,
        ) -> Result<serde_json::Value, OryClientError> {
            if let Some(err) = self.error.lock().await.take() {
                return Err(err);
            }
            let mut identity = payload;
            identity["id"] = json!(id);
            self.identities
                .lock()
                .await
                .insert(id.to_string(), identity.clone());
            Ok(identity)
        }

        async fn delete_identity(&self, id: &str) -> Result<(), OryClientError> {
            if let Some(err) = self.error.lock().await.take() {
                return Err(err);
            }
            self.identities.lock().await.remove(id);
            Ok(())
        }

        async fn create_login_flow(
            &self,
            _query: &[(&str, &str)],
        ) -> Result<serde_json::Value, OryClientError> {
            if let Some(err) = self.error.lock().await.take() {
                return Err(err);
            }
            let flow = json!({
                "id": "flow-login",
                "type": "login",
                "expires_at": "2026-06-28T12:00:00Z",
                "ui": {"nodes": []}
            });
            self.flows.lock().await.push(flow.clone());
            Ok(flow)
        }

        async fn create_registration_flow(
            &self,
            _query: &[(&str, &str)],
        ) -> Result<serde_json::Value, OryClientError> {
            if let Some(err) = self.error.lock().await.take() {
                return Err(err);
            }
            let flow = json!({
                "id": "flow-register",
                "type": "registration",
                "expires_at": "2026-06-28T12:00:00Z",
                "ui": {"nodes": []}
            });
            self.flows.lock().await.push(flow.clone());
            Ok(flow)
        }

        async fn admin_get_session(&self, id: &str) -> Result<serde_json::Value, OryClientError> {
            if let Some(err) = self.error.lock().await.take() {
                return Err(err);
            }
            self.sessions
                .lock()
                .await
                .get(id)
                .cloned()
                .ok_or_else(|| OryClientError::Ory {
                    status: 404,
                    message: "not found".into(),
                })
        }

        async fn list_sessions_by_identity(
            &self,
            identity_id: &str,
        ) -> Result<serde_json::Value, OryClientError> {
            if let Some(err) = self.error.lock().await.take() {
                return Err(err);
            }
            Ok(self
                .sessions_by_identity
                .lock()
                .await
                .get(identity_id)
                .cloned()
                .unwrap_or_else(|| json!([])))
        }

        async fn delete_session(&self, _id: &str) -> Result<(), OryClientError> {
            if let Some(err) = self.error.lock().await.take() {
                return Err(err);
            }
            Ok(())
        }

        async fn create_recovery_link(
            &self,
            _identity_id: &str,
            _expires_in_seconds: Option<i64>,
        ) -> Result<KratosResponse, OryClientError> {
            if let Some(err) = self.error.lock().await.take() {
                return Err(err);
            }
            self.recovery_link
                .lock()
                .await
                .take()
                .ok_or_else(|| OryClientError::Ory {
                    status: 404,
                    message: "recovery link not found".into(),
                })
        }

        async fn list_courier_messages(
            &self,
            _identity_id: Option<&str>,
            _message_type: Option<&str>,
        ) -> Result<serde_json::Value, OryClientError> {
            if let Some(err) = self.error.lock().await.take() {
                return Err(err);
            }
            self.courier_messages
                .lock()
                .await
                .take()
                .ok_or_else(|| OryClientError::Ory {
                    status: 404,
                    message: "courier messages not found".into(),
                })
        }
    }

    #[derive(Default)]
    struct StubMappingStore {
        rows: Mutex<Vec<IdMappingRow>>,
    }

    impl StubMappingStore {
        fn with_mapping(
            tenant_id: &str,
            backend: &str,
            public_id: &str,
            ory_global_id: &str,
        ) -> Self {
            let row = IdMappingRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                backend: backend.to_string(),
                public_id: public_id.to_string(),
                ory_global_id: ory_global_id.to_string(),
                created_at: time::OffsetDateTime::now_utc(),
            };
            Self {
                rows: Mutex::new(vec![row]),
            }
        }
    }

    #[async_trait]
    impl IdMappingStore for StubMappingStore {
        async fn create(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
            ory_global_id: &str,
        ) -> Result<IdMappingRow, DbError> {
            let row = IdMappingRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                backend: backend.to_string(),
                public_id: public_id.to_string(),
                ory_global_id: ory_global_id.to_string(),
                created_at: time::OffsetDateTime::now_utc(),
            };
            self.rows.lock().await.push(row.clone());
            Ok(row)
        }

        async fn get_ory_id(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
        ) -> Result<String, DbError> {
            self.rows
                .lock()
                .await
                .iter()
                .find(|r| {
                    r.tenant_id == tenant_id && r.backend == backend && r.public_id == public_id
                })
                .map(|r| r.ory_global_id.clone())
                .ok_or(DbError::MappingNotFound)
        }

        async fn get_public_id(
            &self,
            tenant_id: &str,
            backend: &str,
            ory_global_id: &str,
        ) -> Result<String, DbError> {
            self.rows
                .lock()
                .await
                .iter()
                .find(|r| {
                    r.tenant_id == tenant_id
                        && r.backend == backend
                        && r.ory_global_id == ory_global_id
                })
                .map(|r| r.public_id.clone())
                .ok_or(DbError::MappingNotFound)
        }

        async fn delete(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
        ) -> Result<(), DbError> {
            let mut rows = self.rows.lock().await;
            let pos = rows.iter().position(|r| {
                r.tenant_id == tenant_id && r.backend == backend && r.public_id == public_id
            });
            pos.map(|i| rows.remove(i))
                .map(|_| ())
                .ok_or(DbError::MappingNotFound)
        }

        async fn list_public_ids(
            &self,
            tenant_id: &str,
            backend: &str,
        ) -> Result<Vec<String>, DbError> {
            Ok(self
                .rows
                .lock()
                .await
                .iter()
                .filter(|r| r.tenant_id == tenant_id && r.backend == backend)
                .map(|r| r.public_id.clone())
                .collect())
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, DbError> {
            Ok(None)
        }
    }

    #[derive(Default)]
    struct StubSchemaStore {
        rows: Mutex<Vec<IdentitySchemaRow>>,
    }

    impl StubSchemaStore {
        fn with_row(row: IdentitySchemaRow) -> Self {
            Self {
                rows: Mutex::new(vec![row]),
            }
        }
    }

    #[async_trait]
    impl IdentitySchemaStore for StubSchemaStore {
        async fn create(
            &self,
            tenant_id: &str,
            schema_id: &str,
            schema_json: serde_json::Value,
            is_default: bool,
        ) -> Result<IdentitySchemaRow, DbError> {
            let row = schema_row(tenant_id, schema_id, schema_json, is_default);
            self.rows.lock().await.push(row.clone());
            Ok(row)
        }

        async fn get_by_schema_id(
            &self,
            tenant_id: &str,
            schema_id: &str,
        ) -> Result<IdentitySchemaRow, DbError> {
            self.rows
                .lock()
                .await
                .iter()
                .find(|r| r.tenant_id == tenant_id && r.schema_id == schema_id)
                .cloned()
                .ok_or(DbError::SchemaNotFound)
        }

        async fn list(&self, tenant_id: &str) -> Result<Vec<IdentitySchemaRow>, DbError> {
            Ok(self
                .rows
                .lock()
                .await
                .iter()
                .filter(|r| r.tenant_id == tenant_id)
                .cloned()
                .collect())
        }

        async fn delete(&self, tenant_id: &str, schema_id: &str) -> Result<(), DbError> {
            let mut rows = self.rows.lock().await;
            let pos = rows
                .iter()
                .position(|r| r.tenant_id == tenant_id && r.schema_id == schema_id);
            pos.map(|i| rows.remove(i))
                .map(|_| ())
                .ok_or(DbError::SchemaNotFound)
        }

        async fn update(
            &self,
            tenant_id: &str,
            schema_id: &str,
            schema_json: serde_json::Value,
            is_default: bool,
        ) -> Result<IdentitySchemaRow, DbError> {
            let mut rows = self.rows.lock().await;
            let row = rows
                .iter_mut()
                .find(|r| r.tenant_id == tenant_id && r.schema_id == schema_id)
                .ok_or(DbError::SchemaNotFound)?;
            row.schema_json = schema_json;
            row.is_default = is_default;
            row.updated_at = time::OffsetDateTime::now_utc();
            Ok(row.clone())
        }

        async fn set_default(
            &self,
            tenant_id: &str,
            schema_id: &str,
        ) -> Result<IdentitySchemaRow, DbError> {
            let mut rows = self.rows.lock().await;
            for row in rows.iter_mut() {
                if row.tenant_id == tenant_id {
                    row.is_default = row.schema_id == schema_id;
                    row.updated_at = time::OffsetDateTime::now_utc();
                }
            }
            rows.iter()
                .find(|r| r.tenant_id == tenant_id && r.schema_id == schema_id)
                .cloned()
                .ok_or(DbError::SchemaNotFound)
        }

        async fn get_default(&self, tenant_id: &str) -> Result<IdentitySchemaRow, DbError> {
            self.rows
                .lock()
                .await
                .iter()
                .find(|r| r.tenant_id == tenant_id && r.is_default)
                .cloned()
                .ok_or(DbError::SchemaNotFound)
        }
    }

    fn make_service(
        kratos: StubKratos,
        mappings: StubMappingStore,
        schemas: StubSchemaStore,
    ) -> IdentityServiceImpl {
        IdentityServiceImpl {
            kratos: Arc::new(kratos),
            mappings: Arc::new(mappings),
            schemas: Arc::new(schemas),
            ui_public_url: "https://ui.example.com".to_string(),
        }
    }

    #[test]
    fn validate_traits_accepts_valid_email() {
        let schema = email_schema();
        let traits = json!({ "email": "alice@example.com" });
        assert!(validate_traits(&schema, &traits).is_ok());
    }

    #[test]
    fn validate_traits_rejects_missing_required_field() {
        let schema = email_schema();
        let traits = json!({});
        assert!(validate_traits(&schema, &traits).is_err());
    }

    #[test]
    fn validate_traits_extracts_kratos_traits_subschema() {
        let full_kratos_schema = json!({
            "type": "object",
            "properties": {
                "traits": {
                    "type": "object",
                    "properties": {
                        "email": { "type": "string" }
                    },
                    "required": ["email"]
                }
            }
        });
        let traits = json!({ "email": "alice@example.com" });
        assert!(validate_traits(&full_kratos_schema, &traits).is_ok());
    }

    #[test]
    fn parse_timestamp_handles_rfc3339() {
        let ts = parse_timestamp("2026-06-28T12:00:00Z").expect("valid timestamp");
        assert_eq!(ts.seconds, 1_782_648_000);
    }

    #[test]
    fn build_kratos_identity_payload_includes_password_when_set() {
        let payload =
            build_kratos_identity_payload("default", json!({"email": "a@b.com"}), "secret");
        assert_eq!(payload["schema_id"], "default");
        assert_eq!(payload["traits"]["email"], "a@b.com");
        assert_eq!(
            payload["credentials"]["password"]["config"]["password"],
            "secret"
        );
    }

    #[test]
    fn build_kratos_identity_payload_omits_password_when_empty() {
        let payload = build_kratos_identity_payload("default", json!({"email": "a@b.com"}), "");
        assert!(payload["credentials"].is_null());
    }

    #[test]
    fn kratos_to_identity_handles_valid_traits() {
        let identity = json!({
            "id": "ory-1",
            "traits": {"email": "a@b.com", "userName": "alice"}
        });
        let app = kratos_to_identity(&identity, "tenant-1", "pub-1", "default");
        assert_eq!(app.id, "pub-1");
        assert_eq!(app.tenant_id, "tenant-1");
        assert_eq!(app.schema_id, "default");
        assert!(!app.traits.fields.is_empty());
    }

    #[test]
    fn kratos_to_identity_handles_invalid_traits() {
        let identity = json!({"id": "ory-1", "traits": "not-an-object"});
        let app = kratos_to_identity(&identity, "tenant-1", "pub-1", "default");
        assert_eq!(app.id, "pub-1");
        assert!(app.traits.fields.is_empty());
    }

    #[test]
    fn kratos_session_to_session_extracts_fields() {
        let session = json!({"id": "sess-1", "active": true});
        let s = kratos_session_to_session(&session, "tenant-1", "pub-1");
        assert_eq!(s.id, "sess-1");
        assert_eq!(s.identity_id, "pub-1");
        assert_eq!(s.tenant_id, "tenant-1");
        assert!(s.active);
    }

    #[test]
    fn schema_row_to_proto_maps_fields() {
        let row = IdentitySchemaRow {
            id: "id-1".into(),
            tenant_id: "tenant-1".into(),
            schema_id: "default".into(),
            schema_json: json!({"type": "object"}),
            is_default: true,
            created_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
        };
        let proto = schema_row_to_proto(row);
        assert_eq!(proto.id, "id-1");
        assert_eq!(proto.schema_id, "default");
        assert!(proto.is_default);
    }

    #[test]
    fn kratos_flow_to_flow_extracts_fields() {
        let flow = json!({
            "id": "flow-1",
            "type": "login",
            "expires_at": "2026-06-28T12:00:00Z",
            "ui": {"nodes": []}
        });
        let f = kratos_flow_to_flow(&flow, "tenant-1");
        assert_eq!(f.id, "flow-1");
        assert_eq!(f.r#type, "login");
        assert_eq!(f.tenant_id, "tenant-1");
    }

    #[test]
    fn parse_timestamp_rejects_invalid_rfc3339() {
        assert!(parse_timestamp("not-a-timestamp").is_none());
    }

    #[test]
    fn validate_traits_rejects_invalid_schema() {
        let invalid_schema = json!({"type": "totally-invalid-type"});
        let traits = json!({"email": "alice@example.com"});
        assert!(validate_traits(&invalid_schema, &traits).is_err());
    }

    #[tokio::test]
    async fn map_ory_error_maps_status_codes() {
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
    fn test_require_tenant_returns_tenant_id() {
        let mut ctx = RequestContext::new(http::HeaderMap::new());
        ctx.extensions_mut().insert(TenantId("tenant-1".into()));
        assert_eq!(require_tenant(&ctx).unwrap(), "tenant-1");
    }

    #[test]
    fn test_require_tenant_missing() {
        let ctx = RequestContext::new(http::HeaderMap::new());
        assert!(matches!(
            require_tenant(&ctx),
            Err(ServiceError::Unauthenticated(_))
        ));
    }

    #[tokio::test]
    async fn create_identity_happy_path() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::with_row(schema_row("tenant-1", "default", email_schema(), true)),
        );
        let req = CreateIdentityRequest {
            schema_id: "default".into(),
            traits: Some(proto_struct(json!({"email": "alice@example.com"}))).into(),
            password: "secret".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, CreateIdentityRequest);
        let resp = IdentityService::create_identity(&svc, admin_ctx("tenant-1"), svc_req)
            .await
            .unwrap();
        assert_eq!(resp.body.tenant_id, "tenant-1");
        assert_eq!(resp.body.schema_id, "default");
        assert!(!resp.body.id.is_empty());
    }

    #[tokio::test]
    async fn create_identity_rejects_invalid_traits() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::with_row(schema_row("tenant-1", "default", email_schema(), true)),
        );
        let req = CreateIdentityRequest {
            schema_id: "default".into(),
            traits: Some(proto_struct(json!({"email": 123}))).into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, CreateIdentityRequest);
        let err = IdentityService::create_identity(&svc, admin_ctx("tenant-1"), svc_req)
            .await
            .unwrap_err();
        assert!(matches!(err, connectrpc::ConnectError { .. }));
    }

    #[tokio::test]
    async fn create_identity_propagates_ory_error() {
        let svc = make_service(
            StubKratos::with_error(OryClientError::Ory {
                status: 503,
                message: "down".into(),
            }),
            StubMappingStore::default(),
            StubSchemaStore::with_row(schema_row("tenant-1", "default", email_schema(), true)),
        );
        let req = CreateIdentityRequest {
            schema_id: "default".into(),
            traits: Some(proto_struct(json!({"email": "alice@example.com"}))).into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, CreateIdentityRequest);
        let err = IdentityService::create_identity(&svc, admin_ctx("tenant-1"), svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::Unavailable);
    }

    #[tokio::test]
    async fn get_identity_happy_path() {
        let svc = make_service(
            StubKratos::with_identity(
                "ory-1",
                json!({"id": "ory-1", "schema_id": "default", "traits": {"email": "a@b.com"}}),
            ),
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
        );
        let req = GetIdentityRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, GetIdentityRequest);
        let resp = IdentityService::get_identity(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.id, "pub-1");
        assert_eq!(resp.schema_id, "default");
    }

    #[tokio::test]
    async fn get_identity_mapping_not_found() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::default(),
        );
        let req = GetIdentityRequest {
            id: "missing".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, GetIdentityRequest);
        let err = IdentityService::get_identity(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn list_identities_returns_resolved_identities() {
        let kratos = StubKratos::with_identity(
            "ory-1",
            json!({"id": "ory-1", "schema_id": "default", "traits": {}}),
        );
        let mappings = StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1");
        let svc = make_service(kratos, mappings, StubSchemaStore::default());
        let req = ListIdentitiesRequest::default();
        svc_req!(svc_req, req, ListIdentitiesRequest);
        let resp = IdentityService::list_identities(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.identities.len(), 1);
        assert_eq!(resp.identities[0].id, "pub-1");
    }

    #[tokio::test]
    async fn update_identity_happy_path() {
        let kratos = StubKratos::with_identity(
            "ory-1",
            json!({"id": "ory-1", "schema_id": "default", "traits": {"email": "old@example.com"}}),
        );
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::with_row(schema_row("tenant-1", "default", email_schema(), true)),
        );
        let req = UpdateIdentityRequest {
            id: "pub-1".into(),
            schema_id: "default".into(),
            traits: Some(proto_struct(json!({"email": "new@example.com"}))).into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, UpdateIdentityRequest);
        let resp = IdentityService::update_identity(&svc, admin_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.id, "pub-1");
        assert_eq!(resp.schema_id, "default");
    }

    #[tokio::test]
    async fn delete_identity_happy_path() {
        let kratos = StubKratos::with_identity("ory-1", json!({"id": "ory-1"}));
        let mappings = StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1");
        let svc = make_service(kratos, mappings, StubSchemaStore::default());
        let req = DeleteIdentityRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, DeleteIdentityRequest);
        IdentityService::delete_identity(&svc, admin_ctx("tenant-1"), svc_req)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn identity_schema_lifecycle() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::default(),
        );
        let tenant_id = "tenant-1";

        // create
        let create_req = CreateIdentitySchemaRequest {
            schema_id: "custom".into(),
            schema_json: Some(proto_struct(json!({"type": "object"}))).into(),
            is_default: false,
            ..Default::default()
        };
        svc_req!(svc_req, create_req, CreateIdentitySchemaRequest);
        let created = IdentityService::create_identity_schema(&svc, admin_ctx(tenant_id), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(created.schema_id, "custom");

        // get
        let get_req = GetIdentitySchemaRequest {
            schema_id: "custom".into(),
            ..Default::default()
        };
        svc_req!(svc_req, get_req, GetIdentitySchemaRequest);
        let got = IdentityService::get_identity_schema(&svc, read_ctx(tenant_id), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(got.schema_id, "custom");

        // list
        let list_req = ListIdentitySchemasRequest::default();
        svc_req!(svc_req, list_req, ListIdentitySchemasRequest);
        let listed = IdentityService::list_identity_schemas(&svc, read_ctx(tenant_id), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(listed.schemas.len(), 1);

        // update
        let update_req = UpdateIdentitySchemaRequest {
            schema_id: "custom".into(),
            schema_json: Some(proto_struct(json!({"type": "array"}))).into(),
            is_default: true,
            ..Default::default()
        };
        svc_req!(svc_req, update_req, UpdateIdentitySchemaRequest);
        let updated = IdentityService::update_identity_schema(&svc, admin_ctx(tenant_id), svc_req)
            .await
            .unwrap()
            .body;
        assert!(updated.is_default);

        // set default
        let set_req = SetDefaultIdentitySchemaRequest {
            schema_id: "custom".into(),
            ..Default::default()
        };
        svc_req!(svc_req, set_req, SetDefaultIdentitySchemaRequest);
        let defaulted =
            IdentityService::set_default_identity_schema(&svc, admin_ctx(tenant_id), svc_req)
                .await
                .unwrap()
                .body;
        assert!(defaulted.is_default);

        // delete
        let del_req = DeleteIdentitySchemaRequest {
            schema_id: "custom".into(),
            ..Default::default()
        };
        svc_req!(svc_req, del_req, DeleteIdentitySchemaRequest);
        IdentityService::delete_identity_schema(&svc, admin_ctx(tenant_id), svc_req)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_login_flow_happy_path() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::default(),
        );
        let req = CreateLoginFlowRequest {
            return_to: "https://app.example.com/callback".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, CreateLoginFlowRequest);
        let resp = IdentityService::create_login_flow(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.r#type, "login");
        assert_eq!(resp.tenant_id, "tenant-1");
    }

    #[tokio::test]
    async fn create_registration_flow_happy_path() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::default(),
        );
        let req = CreateRegistrationFlowRequest {
            return_to: "https://app.example.com/callback".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, CreateRegistrationFlowRequest);
        let resp = IdentityService::create_registration_flow(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.r#type, "registration");
    }

    #[tokio::test]
    async fn get_session_resolves_identity_id() {
        let kratos = StubKratos::default();
        kratos.sessions.lock().await.insert(
            "sess-1".into(),
            json!({"id": "sess-1", "identity_id": "ory-1", "active": true}),
        );
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
        );
        let req = GetSessionRequest {
            id: "sess-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, GetSessionRequest);
        let resp = IdentityService::get_session(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.id, "sess-1");
        assert_eq!(resp.identity_id, "pub-1");
        assert!(resp.active);
    }

    #[tokio::test]
    async fn list_sessions_requires_identity_id() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::default(),
        );
        let req = ListSessionsRequest::default();
        svc_req!(svc_req, req, ListSessionsRequest);
        let err = IdentityService::list_sessions(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn list_sessions_returns_sessions() {
        let kratos = StubKratos::default();
        kratos
            .sessions_by_identity
            .lock()
            .await
            .insert("ory-1".into(), json!([{"id": "sess-1", "active": true}]));
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
        );
        let req = ListSessionsRequest {
            identity_id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, ListSessionsRequest);
        let resp = IdentityService::list_sessions(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.sessions.len(), 1);
        assert_eq!(resp.sessions[0].id, "sess-1");
    }

    #[tokio::test]
    async fn delete_session_happy_path() {
        let kratos = StubKratos::default();
        kratos.sessions.lock().await.insert(
            "sess-1".into(),
            json!({"id": "sess-1", "identity_id": "ory-1", "active": true}),
        );
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
        );
        let req = DeleteSessionRequest {
            id: "sess-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, DeleteSessionRequest);
        IdentityService::delete_session(&svc, admin_ctx("tenant-1"), svc_req)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_recovery_link_returns_gateway_url_with_flow() {
        let kratos = StubKratos::with_recovery_link(KratosResponse {
            body: json!({
                "recovery_link": "http://kratos.example.com/self-service/recovery?flow=flow-abc&token=abc",
                "recovery_token": "abc",
                "expires_at": "2026-01-01T00:00:00Z",
            }),
            headers: http::HeaderMap::new(),
        });
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
        );
        let req = CreateRecoveryLinkRequest {
            identity_id: "pub-1".into(),
            expires_in_seconds: 3600,
            ..Default::default()
        };
        svc_req!(svc_req, req, CreateRecoveryLinkRequest);
        let resp = IdentityService::create_recovery_link(&svc, admin_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(
            resp.recovery_link,
            "https://ui.example.com/recovery?flow=flow-abc&token=abc"
        );
        assert_eq!(resp.recovery_token, "abc");
        assert_eq!(resp.flow, "flow-abc");
        assert!(resp.expires_at.is_set());
    }

    #[tokio::test]
    async fn create_recovery_link_parses_token_and_flow_from_url_when_token_field_missing() {
        let kratos = StubKratos::with_recovery_link(KratosResponse {
            body: json!({
                "recovery_link": "http://kratos.example.com/self-service/recovery?flow=flow-v25&token=kratos-v25-token",
                "expires_at": "2026-01-01T00:00:00Z",
            }),
            headers: http::HeaderMap::new(),
        });
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
        );
        let req = CreateRecoveryLinkRequest {
            identity_id: "pub-1".into(),
            expires_in_seconds: 3600,
            ..Default::default()
        };
        svc_req!(svc_req, req, CreateRecoveryLinkRequest);
        let resp = IdentityService::create_recovery_link(&svc, admin_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(
            resp.recovery_link,
            "https://ui.example.com/recovery?flow=flow-v25&token=kratos-v25-token"
        );
        assert_eq!(resp.recovery_token, "kratos-v25-token");
        assert_eq!(resp.flow, "flow-v25");
        assert!(resp.expires_at.is_set());
    }

    #[tokio::test]
    async fn get_verification_message_returns_gateway_link_with_flow() {
        let kratos = StubKratos::with_courier_messages(json!([
            {
                "id": "msg-1",
                "type": "email",
                "subject": "Verify",
                "body": "<a href=\"http://kratos.example.com/self-service/verification?flow=flow-v1&token=v1\">verify</a>",
                "status": "sent",
                "recipient": "a@example.com",
                "sent_at": "2025-01-01T00:00:00Z",
                "template_type": "verification",
            }
        ]));
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
        );
        let req = GetVerificationMessageRequest {
            identity_id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, GetVerificationMessageRequest);
        let resp = IdentityService::get_verification_message(&svc, admin_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.id, "msg-1");
        assert_eq!(
            resp.link,
            "https://ui.example.com/verification?flow=flow-v1&token=v1"
        );
        assert_eq!(resp.flow, "flow-v1");
    }

    #[test]
    fn extract_first_self_service_link_prefers_anchor_href() {
        let body =
            r#"<a href="http://kratos.example.com/self-service/verification?token=abc">link</a>"#;
        assert_eq!(
            extract_first_self_service_link(body),
            Some("http://kratos.example.com/self-service/verification?token=abc".to_string())
        );
    }

    #[test]
    fn extract_first_self_service_link_falls_back_to_plain_url() {
        let body = "Visit http://kratos.example.com/self-service/recovery?token=abc to recover";
        assert_eq!(
            extract_first_self_service_link(body),
            Some("http://kratos.example.com/self-service/recovery?token=abc".to_string())
        );
    }

    #[tokio::test]
    async fn missing_tenant_returns_unauthenticated() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::default(),
        );
        let req = ListIdentitiesRequest::default();
        svc_req!(svc_req, req, ListIdentitiesRequest);
        let ctx = RequestContext::new(http::HeaderMap::new());
        let err = IdentityService::list_identities(&svc, ctx, svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::Unauthenticated);
    }

    #[tokio::test]
    async fn test_identity_service_impl_new() {
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost:5432/unused").unwrap();
        let kratos = Arc::new(KratosClient::new_with_public("http://a", "http://b").unwrap());
        let service = IdentityServiceImpl::new(
            kratos.clone(),
            IdMappingRepo::new(pool.clone()),
            IdentitySchemaRepo::new(pool),
            "https://ui.example.com".to_string(),
        );
        let _cloned = service.clone();
    }

    #[test]
    fn service_impl_cloneable() {
        let svc = IdentityServiceImpl {
            kratos: Arc::new(StubKratos::default()),
            mappings: Arc::new(StubMappingStore::default()),
            schemas: Arc::new(StubSchemaStore::default()),
            ui_public_url: "https://ui.example.com".to_string(),
        };
        let _cloned = svc.clone();
    }

    #[tokio::test]
    async fn kratos_client_as_identity_kratos_delegates() {
        let client = Arc::new(
            KratosClient::new_with_public("http://localhost:1", "http://localhost:1").unwrap(),
        ) as Arc<dyn IdentityKratos>;
        assert!(client.create_identity(json!({})).await.is_err());
        assert!(client.get_identity("id").await.is_err());
        assert!(client.update_identity("id", json!({})).await.is_err());
        assert!(client.delete_identity("id").await.is_err());
        assert!(client.create_login_flow(&[]).await.is_err());
        assert!(client.create_registration_flow(&[]).await.is_err());
        assert!(client.admin_get_session("id").await.is_err());
        assert!(client.list_sessions_by_identity("id").await.is_err());
        assert!(client.delete_session("id").await.is_err());
        assert!(client.create_recovery_link("id", Some(3600)).await.is_err());
        assert!(
            client
                .list_courier_messages(Some("id"), Some("verification"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn create_identity_requires_admin_scope() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::with_row(schema_row("tenant-1", "default", email_schema(), true)),
        );
        let req = CreateIdentityRequest {
            schema_id: "default".into(),
            traits: Some(proto_struct(json!({"email": "alice@example.com"}))).into(),
            password: "secret".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, CreateIdentityRequest);
        let err = IdentityService::create_identity(&svc, no_scope_ctx("tenant-1"), svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn get_identity_rejects_read_scope_missing() {
        let svc = make_service(
            StubKratos::with_identity(
                "ory-1",
                json!({"id": "ory-1", "schema_id": "default", "traits": {"email": "a@b.com"}}),
            ),
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
        );
        let req = GetIdentityRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, GetIdentityRequest);
        let err = IdentityService::get_identity(&svc, no_scope_ctx("tenant-1"), svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn get_identity_accepts_admin_scope() {
        let svc = make_service(
            StubKratos::with_identity(
                "ory-1",
                json!({"id": "ory-1", "schema_id": "default", "traits": {"email": "a@b.com"}}),
            ),
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
        );
        let req = GetIdentityRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, GetIdentityRequest);
        let resp = IdentityService::get_identity(&svc, admin_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.id, "pub-1");
    }

    #[tokio::test]
    async fn delete_session_requires_admin_scope() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::default(),
        );
        let req = DeleteSessionRequest {
            id: "sess-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, DeleteSessionRequest);
        let err = IdentityService::delete_session(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn delete_session_rejects_foreign_tenant_session() {
        let kratos = StubKratos::default();
        kratos.sessions.lock().await.insert(
            "sess-1".into(),
            json!({"id": "sess-1", "identity_id": "ory-1", "active": true}),
        );
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-2", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
        );
        let req = DeleteSessionRequest {
            id: "sess-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, DeleteSessionRequest);
        let err = IdentityService::delete_session(&svc, admin_ctx("tenant-1"), svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn get_session_rejects_foreign_tenant_session() {
        let kratos = StubKratos::default();
        kratos.sessions.lock().await.insert(
            "sess-1".into(),
            json!({"id": "sess-1", "identity_id": "ory-1", "active": true}),
        );
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-2", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
        );
        let req = GetSessionRequest {
            id: "sess-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, GetSessionRequest);
        let err = IdentityService::get_session(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }

    #[test]
    fn validate_traits_rejects_oversized_schema() {
        let mut props = serde_json::Map::new();
        let filler = "x".repeat(1024);
        for i in 0..70 {
            props.insert(
                format!("field{i}"),
                json!({ "type": "string", "description": &filler }),
            );
        }
        let schema = json!({"type": "object", "properties": props});
        let traits = json!({});
        assert!(validate_traits(&schema, &traits).is_err());
    }

    #[test]
    fn validate_traits_rejects_deep_schema() {
        let mut schema = json!({"type": "object"});
        for _ in 0..15 {
            schema = json!({"type": "object", "properties": {"nested": schema}});
        }
        let traits = json!({});
        assert!(validate_traits(&schema, &traits).is_err());
    }

    #[test]
    fn validate_traits_rejects_remote_ref() {
        let schema = json!({
            "type": "object",
            "properties": {
                "email": { "$ref": "https://example.com/schema.json" }
            }
        });
        let traits = json!({"email": "alice@example.com"});
        assert!(validate_traits(&schema, &traits).is_err());
    }

    #[test]
    fn validate_traits_rejects_deep_traits() {
        let schema = json!({"type": "object"});
        let mut traits = json!({"value": "x"});
        for _ in 0..15 {
            traits = json!({"nested": traits});
        }
        assert!(validate_traits(&schema, &traits).is_err());
    }

    #[test]
    fn validate_traits_accepts_local_ref() {
        let schema = json!({
            "type": "object",
            "definitions": {
                "email": { "type": "string", "format": "email" }
            },
            "properties": {
                "email": { "$ref": "#/definitions/email" }
            }
        });
        let traits = json!({"email": "alice@example.com"});
        assert!(validate_traits(&schema, &traits).is_ok());
    }
}
