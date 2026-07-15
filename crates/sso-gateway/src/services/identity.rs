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
    db::{
        DbError, IdMappingStore, IdentitySchemaRow, IdentitySchemaStore, TOKEN_TYPE_FLOW,
        TOKEN_TYPE_LOGIN_CHALLENGE, TOKEN_TYPE_RECOVERY_TOKEN, TOKEN_TYPE_SESSION,
        TOKEN_TYPE_VERIFICATION_TOKEN, TenantMembershipRow, TenantMembershipStore,
        TransientTokenStore,
    },
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
const BACKEND_HYDRA: &str = "hydra";

fn transient_expiry() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::hours(1)
}

/// Resolve a login challenge to the Hydra challenge Kratos expects, passing
/// the raw Hydra challenge through unchanged when no gateway mapping exists.
///
/// See `identity_self_service::resolve_login_challenge` for the rationale: the
/// standard Ory login flow delivers Hydra's raw challenge to the login UI via
/// the redirect query string, and Kratos accepts that value as-is. Failing with
/// `not_found` on a lookup miss would trap the browser in a redirect loop.
async fn resolve_login_challenge(
    transient: &dyn TransientTokenStore,
    tenant_id: &str,
    login_challenge: &str,
) -> Result<String, ServiceError> {
    match transient
        .get_ory_token(
            tenant_id,
            BACKEND_HYDRA,
            TOKEN_TYPE_LOGIN_CHALLENGE,
            login_challenge,
        )
        .await
    {
        Ok(ory_challenge) => Ok(ory_challenge),
        Err(DbError::MappingNotFound) => Ok(login_challenge.to_string()),
        Err(err) => Err(err.into()),
    }
}

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
    memberships: Arc<dyn TenantMembershipStore>,
    transient: Arc<dyn TransientTokenStore>,
    ui_public_url: String,
    kratos_default_schema_id: String,
}

impl IdentityServiceImpl {
    pub fn new(
        kratos: Arc<KratosClient>,
        mappings: crate::db::IdMappingRepo,
        schemas: crate::db::IdentitySchemaRepo,
        memberships: crate::db::TenantMembershipRepo,
        transient: crate::db::TransientTokenRepo,
        ui_public_url: String,
        kratos_default_schema_id: String,
    ) -> Self {
        Self {
            kratos: kratos as Arc<dyn IdentityKratos>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
            schemas: Arc::new(schemas) as Arc<dyn IdentitySchemaStore>,
            memberships: Arc::new(memberships) as Arc<dyn TenantMembershipStore>,
            transient: Arc::new(transient) as Arc<dyn TransientTokenStore>,
            ui_public_url,
            kratos_default_schema_id,
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
        let mut traits_json = req
            .traits
            .as_option()
            .map(|s| serde_json::to_value(s).unwrap_or_default())
            .unwrap_or_else(|| serde_json::json!({}));
        normalize_traits(&mut traits_json);
        validate_traits(&schema.schema_json, &traits_json)?;
        let email = extract_email(&traits_json)?;

        let payload =
            build_kratos_identity_payload(&self.kratos_default_schema_id, &email, &req.password);
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

        // The gateway owns the full trait document and the schema binding; Kratos holds
        // only {email}. If the membership write fails, roll back the Kratos identity so
        // the two stores stay converged.
        if let Err(err) = self
            .memberships
            .upsert(
                &tenant_id,
                &public_id,
                &schema.schema_id,
                schema.version,
                traits_json.clone(),
            )
            .await
        {
            let _ = self.kratos.delete_identity(ory_id).await;
            return Err(err.into());
        }

        Ok(Response::new(identity_from_traits(
            &tenant_id,
            &public_id,
            &schema.schema_id,
            &traits_json,
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
        let (_ory_id, membership) = self.resolve_identity(&tenant_id, &req.id).await?;
        Ok(Response::new(identity_from_traits(
            &tenant_id,
            &req.id,
            &membership.schema_id,
            &membership.traits,
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
                Ok((_ory_id, membership)) => identities.push(identity_from_traits(
                    &tenant_id,
                    &public_id,
                    &membership.schema_id,
                    &membership.traits,
                )),
                Err(err) => debug!(%public_id, "identity resolution failed: {}", err),
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
        let (ory_id, current) = self.resolve_identity(&tenant_id, &req.id).await?;

        let schema_id = if req.schema_id.is_empty() {
            current.schema_id.clone()
        } else {
            req.schema_id
        };
        let schema = self.resolve_schema(&tenant_id, &schema_id).await?;

        let mut traits_json = req
            .traits
            .as_option()
            .map(|s| serde_json::to_value(s).unwrap_or_default())
            .unwrap_or_else(|| serde_json::json!({}));
        normalize_traits(&mut traits_json);
        validate_traits(&schema.schema_json, &traits_json)?;
        let email = extract_email(&traits_json)?;

        // Email is the Kratos identifier and is immutable.
        let current_email = current
            .traits
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !current_email.is_empty() && email != current_email {
            return Err(ServiceError::InvalidArgument("email is immutable".into()).into());
        }

        // Traits-only Kratos update of {email}; Kratos preserves the omitted credentials
        // block (verified against v25.4 by an integration test).
        let payload = build_kratos_identity_payload(&self.kratos_default_schema_id, &email, "");
        self.kratos
            .update_identity(&ory_id, payload)
            .await
            .map_err(map_ory_error)?;

        let membership = self
            .memberships
            .upsert(
                &tenant_id,
                &req.id,
                &schema.schema_id,
                schema.version,
                traits_json.clone(),
            )
            .await?;

        Ok(Response::new(identity_from_traits(
            &tenant_id,
            &req.id,
            &membership.schema_id,
            &traits_json,
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
        require_email_string_schema(&schema_json)?;
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
        require_email_string_schema(&schema_json)?;
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
        let mut query_owned = Vec::<(&str, String)>::new();
        if !req.return_to.is_empty() {
            query_owned.push(("return_to", req.return_to));
        }
        if !req.aal.is_empty() {
            query_owned.push(("aal", req.aal));
        }
        if req.refresh {
            query_owned.push(("refresh", "true".to_string()));
        }
        if !req.organization.is_empty() {
            query_owned.push(("organization", req.organization));
        }
        if !req.via.is_empty() {
            query_owned.push(("via", req.via));
        }
        if !req.login_challenge.is_empty() {
            let ory_challenge =
                resolve_login_challenge(self.transient.as_ref(), &tenant_id, &req.login_challenge)
                    .await?;
            query_owned.push(("login_challenge", ory_challenge));
        }
        if !req.identity_schema.is_empty() {
            query_owned.push(("identity_schema", req.identity_schema));
        }
        let query_refs: Vec<(&str, &str)> =
            query_owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let flow = self
            .kratos
            .create_login_flow(&query_refs)
            .await
            .map_err(map_ory_error)?;
        let public_flow = self.public_flow(&tenant_id, &flow).await?;
        let public_identity_id = self.public_identity_in_flow(&tenant_id, &flow).await?;
        Ok(Response::new(kratos_flow_to_flow(
            &flow,
            &tenant_id,
            &public_flow,
            &public_identity_id,
        )))
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
        let mut query_owned = Vec::<(&str, String)>::new();
        if !req.return_to.is_empty() {
            query_owned.push(("return_to", req.return_to));
        }
        if !req.login_challenge.is_empty() {
            let ory_challenge =
                resolve_login_challenge(self.transient.as_ref(), &tenant_id, &req.login_challenge)
                    .await?;
            query_owned.push(("login_challenge", ory_challenge));
        }
        if !req.identity_schema.is_empty() {
            query_owned.push(("identity_schema", req.identity_schema));
        }
        let query_refs: Vec<(&str, &str)> =
            query_owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let flow = self
            .kratos
            .create_registration_flow(&query_refs)
            .await
            .map_err(map_ory_error)?;
        let public_flow = self.public_flow(&tenant_id, &flow).await?;
        let public_identity_id = self.public_identity_in_flow(&tenant_id, &flow).await?;
        Ok(Response::new(kratos_flow_to_flow(
            &flow,
            &tenant_id,
            &public_flow,
            &public_identity_id,
        )))
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
        let ory_session_id = self
            .transient
            .get_ory_token(&tenant_id, BACKEND_KRATOS, TOKEN_TYPE_SESSION, &req.id)
            .await?;
        let session = self
            .kratos
            .admin_get_session(&ory_session_id)
            .await
            .map_err(map_ory_error)?;

        let identity_id = session["identity_id"].as_str().unwrap_or("");
        let public_identity_id = self
            .mappings
            .get_public_id(&tenant_id, BACKEND_KRATOS, identity_id)
            .await?;
        let public_session_id = self.public_session(&tenant_id, &session).await?;

        Ok(Response::new(Session {
            id: public_session_id,
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

        let mut items = Vec::new();
        if let Some(arr) = sessions.as_array() {
            for s in arr {
                let public_session_id = self.public_session(&tenant_id, s).await?;
                items.push(Session {
                    id: public_session_id,
                    identity_id: req.identity_id.clone(),
                    tenant_id: tenant_id.clone(),
                    active: s["active"].as_bool().unwrap_or(false),
                    ..Default::default()
                });
            }
        }

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
        let ory_session_id = self
            .transient
            .get_ory_token(&tenant_id, BACKEND_KRATOS, TOKEN_TYPE_SESSION, &req.id)
            .await?;

        let session = self
            .kratos
            .admin_get_session(&ory_session_id)
            .await
            .map_err(map_ory_error)?;
        let identity_id = session["identity_id"].as_str().unwrap_or("");
        // Verify the session belongs to an identity in the caller's tenant.
        let _ = self
            .mappings
            .get_public_id(&tenant_id, BACKEND_KRATOS, identity_id)
            .await?;

        self.kratos
            .delete_session(&ory_session_id)
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

        let public_recovery_token = self
            .transient
            .create(
                &tenant_id,
                BACKEND_KRATOS,
                TOKEN_TYPE_RECOVERY_TOKEN,
                &recovery_token,
                transient_expiry(),
            )
            .await?;
        let public_flow = if flow.is_empty() {
            String::new()
        } else {
            self.transient
                .create(
                    &tenant_id,
                    BACKEND_KRATOS,
                    TOKEN_TYPE_FLOW,
                    &flow,
                    transient_expiry(),
                )
                .await?
        };

        let gateway_link = if public_flow.is_empty() {
            format!(
                "{}/recovery?token={}",
                self.ui_public_url.trim_end_matches('/'),
                urlencoding::encode(&public_recovery_token)
            )
        } else {
            format!(
                "{}/recovery?flow={}&token={}",
                self.ui_public_url.trim_end_matches('/'),
                urlencoding::encode(&public_flow),
                urlencoding::encode(&public_recovery_token)
            )
        };

        Ok(Response::new(RecoveryLink {
            recovery_link: gateway_link,
            recovery_token: public_recovery_token,
            flow: public_flow,
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
        let (raw_token, raw_flow) = extract_first_self_service_link(body)
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
                    (token, flow)
                })
            })
            .unwrap_or_default();

        let public_token = if raw_token.is_empty() {
            String::new()
        } else {
            self.transient
                .create(
                    &tenant_id,
                    BACKEND_KRATOS,
                    TOKEN_TYPE_VERIFICATION_TOKEN,
                    &raw_token,
                    transient_expiry(),
                )
                .await?
        };
        let public_flow = if raw_flow.is_empty() {
            String::new()
        } else {
            self.transient
                .create(
                    &tenant_id,
                    BACKEND_KRATOS,
                    TOKEN_TYPE_FLOW,
                    &raw_flow,
                    transient_expiry(),
                )
                .await?
        };

        let link = if public_token.is_empty() {
            String::new()
        } else if public_flow.is_empty() {
            format!(
                "{}/verification?token={}",
                self.ui_public_url.trim_end_matches('/'),
                urlencoding::encode(&public_token)
            )
        } else {
            format!(
                "{}/verification?flow={}&token={}",
                self.ui_public_url.trim_end_matches('/'),
                urlencoding::encode(&public_flow),
                urlencoding::encode(&public_token)
            )
        };

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
            flow: public_flow,
            ..Default::default()
        }))
    }
}

impl IdentityServiceImpl {
    async fn resolve_identity(
        &self,
        tenant_id: &str,
        public_id: &str,
    ) -> Result<(String, TenantMembershipRow), ServiceError> {
        let ory_id = self
            .mappings
            .get_ory_id(tenant_id, BACKEND_KRATOS, public_id)
            .await?;
        match self.memberships.get(tenant_id, public_id).await {
            Ok(membership) => Ok((ory_id, membership)),
            Err(DbError::MembershipNotFound) => {
                // Pre-migration identity: backfill a membership from the current Kratos
                // state so reads become gateway-authoritative from here on.
                let identity = self
                    .kratos
                    .get_identity(&ory_id)
                    .await
                    .map_err(map_ory_error)?;
                let schema_id = identity["schema_id"]
                    .as_str()
                    .unwrap_or("default")
                    .to_string();
                let traits = if identity["traits"].is_object() {
                    identity["traits"].clone()
                } else {
                    serde_json::json!({})
                };
                let membership = self
                    .memberships
                    .upsert(tenant_id, public_id, &schema_id, 1, traits)
                    .await?;
                Ok((ory_id, membership))
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn public_flow(
        &self,
        tenant_id: &str,
        flow: &serde_json::Value,
    ) -> Result<String, ServiceError> {
        let ory_flow_id = flow["id"].as_str().unwrap_or("");
        if ory_flow_id.is_empty() {
            return Ok(String::new());
        }
        self.transient
            .create(
                tenant_id,
                BACKEND_KRATOS,
                TOKEN_TYPE_FLOW,
                ory_flow_id,
                transient_expiry(),
            )
            .await
            .map_err(|e| e.into())
    }

    async fn public_identity_in_flow(
        &self,
        tenant_id: &str,
        flow: &serde_json::Value,
    ) -> Result<String, ServiceError> {
        let ory_identity_id = flow["identity"]["id"].as_str().unwrap_or("");
        if ory_identity_id.is_empty() {
            return Ok(String::new());
        }
        self.mappings
            .get_public_id(tenant_id, BACKEND_KRATOS, ory_identity_id)
            .await
            .map_err(|e| e.into())
    }

    async fn public_session(
        &self,
        tenant_id: &str,
        session: &serde_json::Value,
    ) -> Result<String, ServiceError> {
        let ory_session_id = session["id"].as_str().unwrap_or("");
        if ory_session_id.is_empty() {
            return Ok(String::new());
        }
        self.transient
            .create(
                tenant_id,
                BACKEND_KRATOS,
                TOKEN_TYPE_SESSION,
                ory_session_id,
                transient_expiry(),
            )
            .await
            .map_err(|e| e.into())
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

pub(crate) fn traits_subschema(schema_json: &serde_json::Value) -> &serde_json::Value {
    schema_json
        .get("properties")
        .and_then(|p| p.get("traits"))
        .unwrap_or(schema_json)
}

/// Lowercase + trim `traits.email` so the Kratos identifier, the validated value, and
/// the gateway-stored traits all agree on a single canonical form. No-op when traits is
/// not an object or has no string email.
pub(crate) fn normalize_traits(traits: &mut serde_json::Value) {
    if let Some(email) = traits.get("email").and_then(|v| v.as_str()) {
        let normalized = email.trim().to_ascii_lowercase();
        if normalized != email {
            traits["email"] = serde_json::Value::String(normalized);
        }
    }
}

pub(crate) fn extract_email(traits: &serde_json::Value) -> Result<String, ServiceError> {
    traits
        .get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ServiceError::InvalidArgument("traits.email is required".into()))
}

/// Superset rule: every tenant schema must declare `traits.email` as a string so the
/// gateway can always project the base Kratos identity `{ email }` from it.
pub(crate) fn require_email_string_schema(
    schema_json: &serde_json::Value,
) -> Result<(), ServiceError> {
    let traits_schema = traits_subschema(schema_json);
    let email_ty = traits_schema
        .get("properties")
        .and_then(|p| p.get("email"))
        .and_then(|e| e.get("type"))
        .and_then(|t| t.as_str());
    match email_ty {
        Some("string") => Ok(()),
        _ => Err(ServiceError::InvalidArgument(
            "identity schema must declare traits.email as a string".into(),
        )),
    }
}

pub(crate) fn validate_traits(
    schema_json: &serde_json::Value,
    traits: &serde_json::Value,
) -> Result<(), ServiceError> {
    // Tenant schemas may be stored either as the full Kratos identity schema
    // (which wraps traits under `properties.traits`) or directly as the traits
    // schema. Prefer the traits subschema when it exists. Callers are expected to
    // run `normalize_traits` first so the value validated here is the value they
    // persist and forward.
    let traits_schema = traits_subschema(schema_json);

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
        OryClientError::Redirect { .. } => ServiceError::Internal("unexpected redirect".into()),
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
    base_schema_id: &str,
    email: &str,
    password: &str,
) -> serde_json::Value {
    // Kratos only ever stores the base identity: the email (its password identifier,
    // recovery/verification target) plus optional credentials. The full trait document
    // lives in the gateway membership, never here.
    let mut payload = serde_json::json!({
        "schema_id": base_schema_id,
        "traits": { "email": email },
    });
    if !password.is_empty() {
        payload["credentials"] = serde_json::json!({
            "password": { "config": { "password": password } },
        });
    }
    payload
}

fn identity_from_traits(
    tenant_id: &str,
    public_id: &str,
    schema_id: &str,
    traits: &serde_json::Value,
) -> Identity {
    let traits_struct = match serde_json::from_value::<ProtoStruct>(traits.clone()) {
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

fn kratos_flow_to_flow(
    flow: &serde_json::Value,
    tenant_id: &str,
    public_flow_id: &str,
    public_identity_id: &str,
) -> Flow {
    let ui_struct = serde_json::from_value::<ProtoStruct>(flow["ui"].clone()).unwrap_or_default();
    Flow {
        id: public_flow_id.to_string(),
        r#type: flow["type"].as_str().unwrap_or("").to_string(),
        tenant_id: tenant_id.to_string(),
        identity_id: public_identity_id.to_string(),
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
    use crate::auth::SubjectType;
    use std::collections::HashMap;

    use async_trait::async_trait;
    use buffa::Message;
    use buffa::bytes::Bytes;
    use buffa::view::{HasMessageView, MessageView};
    use http::HeaderMap;
    use serde_json::json;
    use tokio::sync::Mutex;

    use crate::auth::AuthContext;
    use crate::db::{
        DbError, IdMappingRepo, IdMappingRow, IdentitySchemaRepo, TransientTokenRepo,
        TransientTokenRow, TransientTokenStore,
    };

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
            subject_type: SubjectType::User,
            actor: None,
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
            version: 1,
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

        async fn add_identity(&self, id: &str, identity: serde_json::Value) {
            self.identities
                .lock()
                .await
                .insert(id.to_string(), identity);
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
    struct StubTransientTokenStore {
        rows: std::sync::Mutex<Vec<TransientTokenRow>>,
    }

    impl StubTransientTokenStore {
        fn seed(
            &self,
            tenant_id: &str,
            backend: &str,
            token_type: &str,
            public_token: &str,
            ory_token: &str,
        ) {
            self.rows.lock().unwrap().push(TransientTokenRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                backend: backend.to_string(),
                token_type: token_type.to_string(),
                public_token: public_token.to_string(),
                ory_token: ory_token.to_string(),
                expires_at: transient_expiry(),
                created_at: time::OffsetDateTime::now_utc(),
            });
        }
    }

    #[async_trait]
    impl TransientTokenStore for StubTransientTokenStore {
        async fn create(
            &self,
            tenant_id: &str,
            backend: &str,
            token_type: &str,
            ory_token: &str,
            expires_at: time::OffsetDateTime,
        ) -> Result<String, DbError> {
            let rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter().find(|r| {
                r.backend == backend && r.token_type == token_type && r.ory_token == ory_token
            }) {
                return Ok(row.public_token.clone());
            }
            drop(rows);
            let public_token = Ulid::new().to_string();
            self.rows.lock().unwrap().push(TransientTokenRow {
                id: Ulid::new().to_string(),
                tenant_id: tenant_id.to_string(),
                backend: backend.to_string(),
                token_type: token_type.to_string(),
                public_token: public_token.clone(),
                ory_token: ory_token.to_string(),
                expires_at,
                created_at: time::OffsetDateTime::now_utc(),
            });
            Ok(public_token)
        }

        async fn get_ory_token(
            &self,
            _tenant_id: &str,
            backend: &str,
            token_type: &str,
            public_token: &str,
        ) -> Result<String, DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| {
                    r.backend == backend
                        && r.token_type == token_type
                        && r.public_token == public_token
                })
                .map(|r| r.ory_token.clone())
                .ok_or(DbError::MappingNotFound)
        }

        async fn get_public_token(
            &self,
            _tenant_id: &str,
            backend: &str,
            token_type: &str,
            ory_token: &str,
        ) -> Result<String, DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| {
                    r.backend == backend && r.token_type == token_type && r.ory_token == ory_token
                })
                .map(|r| r.public_token.clone())
                .ok_or(DbError::MappingNotFound)
        }

        async fn delete(&self, _tenant_id: &str, public_token: &str) -> Result<(), DbError> {
            let mut rows = self.rows.lock().unwrap();
            let pos = rows.iter().position(|r| r.public_token == public_token);
            pos.map(|i| rows.remove(i))
                .map(|_| ())
                .ok_or(DbError::MappingNotFound)
        }

        async fn get_ory_token_global(
            &self,
            backend: &str,
            token_type: &str,
            public_token: &str,
        ) -> Result<(String, String), DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| {
                    r.backend == backend
                        && r.token_type == token_type
                        && r.public_token == public_token
                })
                .map(|r| (r.tenant_id.clone(), r.ory_token.clone()))
                .ok_or(DbError::MappingNotFound)
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

    #[derive(Default)]
    struct StubMembershipStore {
        rows: Mutex<Vec<TenantMembershipRow>>,
    }

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
            let mut rows = self.rows.lock().await;
            if let Some(row) = rows
                .iter_mut()
                .find(|r| r.tenant_id == tenant_id && r.identity_id == identity_id)
            {
                row.schema_id = schema_id.to_string();
                row.schema_version = schema_version;
                row.traits = traits;
                row.updated_at = time::OffsetDateTime::now_utc();
                return Ok(row.clone());
            }
            let row = TenantMembershipRow {
                tenant_id: tenant_id.to_string(),
                identity_id: identity_id.to_string(),
                schema_id: schema_id.to_string(),
                schema_version,
                traits,
                state: "active".to_string(),
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            };
            rows.push(row.clone());
            Ok(row)
        }

        async fn get(
            &self,
            tenant_id: &str,
            identity_id: &str,
        ) -> Result<TenantMembershipRow, DbError> {
            self.rows
                .lock()
                .await
                .iter()
                .find(|r| r.tenant_id == tenant_id && r.identity_id == identity_id)
                .cloned()
                .ok_or(DbError::MembershipNotFound)
        }

        async fn set_state(
            &self,
            tenant_id: &str,
            identity_id: &str,
            state: &str,
        ) -> Result<TenantMembershipRow, DbError> {
            let mut rows = self.rows.lock().await;
            let row = rows
                .iter_mut()
                .find(|r| r.tenant_id == tenant_id && r.identity_id == identity_id)
                .ok_or(DbError::MembershipNotFound)?;
            row.state = state.to_string();
            row.updated_at = time::OffsetDateTime::now_utc();
            Ok(row.clone())
        }

        async fn list_by_tenant(
            &self,
            tenant_id: &str,
        ) -> Result<Vec<TenantMembershipRow>, DbError> {
            Ok(self
                .rows
                .lock()
                .await
                .iter()
                .filter(|r| r.tenant_id == tenant_id)
                .cloned()
                .collect())
        }
    }

    fn make_service(
        kratos: StubKratos,
        mappings: StubMappingStore,
        schemas: StubSchemaStore,
        transient: StubTransientTokenStore,
    ) -> IdentityServiceImpl {
        IdentityServiceImpl {
            kratos: Arc::new(kratos),
            mappings: Arc::new(mappings),
            schemas: Arc::new(schemas),
            memberships: Arc::new(StubMembershipStore::default()),
            transient: Arc::new(transient),
            ui_public_url: "https://ui.example.com".to_string(),
            kratos_default_schema_id: "default".to_string(),
        }
    }

    fn default_transient_store() -> StubTransientTokenStore {
        let store = StubTransientTokenStore::default();
        store.seed(
            "tenant-1",
            BACKEND_KRATOS,
            TOKEN_TYPE_SESSION,
            "pub-sess-1",
            "sess-1",
        );
        store.seed(
            "tenant-1",
            BACKEND_KRATOS,
            TOKEN_TYPE_FLOW,
            "flow-abc",
            "flow-abc",
        );
        store.seed(
            "tenant-1",
            BACKEND_KRATOS,
            TOKEN_TYPE_FLOW,
            "flow-v25",
            "flow-v25",
        );
        store.seed(
            "tenant-1",
            BACKEND_KRATOS,
            TOKEN_TYPE_RECOVERY_TOKEN,
            "pub-recovery-abc",
            "abc",
        );
        store.seed(
            "tenant-1",
            BACKEND_KRATOS,
            TOKEN_TYPE_RECOVERY_TOKEN,
            "pub-recovery-kratos-v25",
            "kratos-v25-token",
        );
        store.seed(
            "tenant-1",
            BACKEND_KRATOS,
            TOKEN_TYPE_VERIFICATION_TOKEN,
            "pub-token-v1",
            "v1",
        );
        store.seed(
            "tenant-1",
            BACKEND_KRATOS,
            TOKEN_TYPE_FLOW,
            "pub-flow-v1",
            "flow-v1",
        );
        store
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
        let payload = build_kratos_identity_payload("default", "a@b.com", "secret");
        assert_eq!(payload["schema_id"], "default");
        assert_eq!(payload["traits"]["email"], "a@b.com");
        assert_eq!(
            payload["credentials"]["password"]["config"]["password"],
            "secret"
        );
    }

    #[test]
    fn build_kratos_identity_payload_omits_password_when_empty() {
        let payload = build_kratos_identity_payload("default", "a@b.com", "");
        assert!(payload["credentials"].is_null());
    }

    #[test]
    fn identity_from_traits_handles_valid_traits() {
        let traits = json!({"email": "a@b.com", "userName": "alice"});
        let app = identity_from_traits("tenant-1", "pub-1", "default", &traits);
        assert_eq!(app.id, "pub-1");
        assert_eq!(app.tenant_id, "tenant-1");
        assert_eq!(app.schema_id, "default");
        assert!(!app.traits.fields.is_empty());
    }

    #[test]
    fn identity_from_traits_handles_invalid_traits() {
        let traits = json!("not-an-object");
        let app = identity_from_traits("tenant-1", "pub-1", "default", &traits);
        assert_eq!(app.id, "pub-1");
        assert!(app.traits.fields.is_empty());
    }

    #[test]
    fn session_proto_extracts_fields() {
        let session = json!({"id": "sess-1", "active": true});
        let s = Session {
            id: "pub-sess-1".into(),
            identity_id: "pub-1".into(),
            tenant_id: "tenant-1".into(),
            active: session["active"].as_bool().unwrap_or(false),
            ..Default::default()
        };
        assert_eq!(s.id, "pub-sess-1");
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
            version: 1,
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
        let f = kratos_flow_to_flow(&flow, "tenant-1", "pub-flow-1", "pub-identity-1");
        assert_eq!(f.id, "pub-flow-1");
        assert_eq!(f.r#type, "login");
        assert_eq!(f.tenant_id, "tenant-1");
        assert_eq!(f.identity_id, "pub-identity-1");
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

    #[test]
    fn normalize_traits_lowercases_and_trims_email() {
        let mut traits = json!({"email": "  Alice@Example.COM  ", "name": {"first": "Alice"}});
        normalize_traits(&mut traits);
        assert_eq!(traits["email"], "alice@example.com");
        // Other fields are untouched.
        assert_eq!(traits["name"]["first"], "Alice");
    }

    #[test]
    fn normalize_traits_is_noop_without_string_email() {
        let mut non_object = json!(["not", "an", "object"]);
        normalize_traits(&mut non_object);
        assert_eq!(non_object, json!(["not", "an", "object"]));

        let mut no_email = json!({"name": "alice"});
        normalize_traits(&mut no_email);
        assert_eq!(no_email, json!({"name": "alice"}));
    }

    #[test]
    fn extract_email_returns_value_and_errors_when_missing() {
        assert_eq!(
            extract_email(&json!({"email": "a@b.com"})).unwrap(),
            "a@b.com"
        );
        assert!(extract_email(&json!({})).is_err());
        assert!(extract_email(&json!({"email": ""})).is_err());
        assert!(extract_email(&json!({"email": 42})).is_err());
    }

    #[test]
    fn require_email_string_schema_accepts_full_kratos_and_direct_traits_schemas() {
        let full_kratos = json!({
            "type": "object",
            "properties": {
                "traits": {
                    "type": "object",
                    "properties": { "email": { "type": "string" } }
                }
            }
        });
        assert!(require_email_string_schema(&full_kratos).is_ok());

        let direct_traits = json!({
            "type": "object",
            "properties": { "email": { "type": "string" } }
        });
        assert!(require_email_string_schema(&direct_traits).is_ok());
    }

    #[test]
    fn require_email_string_schema_rejects_missing_or_non_string_email() {
        let missing_email = json!({
            "type": "object",
            "properties": { "traits": { "type": "object", "properties": {} } }
        });
        assert!(require_email_string_schema(&missing_email).is_err());

        let non_string_email = json!({
            "type": "object",
            "properties": {
                "traits": {
                    "type": "object",
                    "properties": { "email": { "type": "number" } }
                }
            }
        });
        assert!(require_email_string_schema(&non_string_email).is_err());
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
            default_transient_store(),
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
            default_transient_store(),
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
            default_transient_store(),
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
            default_transient_store(),
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
            default_transient_store(),
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
        let svc = make_service(
            kratos,
            mappings,
            StubSchemaStore::default(),
            default_transient_store(),
        );
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
            default_transient_store(),
        );
        let req = UpdateIdentityRequest {
            id: "pub-1".into(),
            schema_id: "default".into(),
            traits: Some(proto_struct(json!({"email": "old@example.com"}))).into(),
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
        let svc = make_service(
            kratos,
            mappings,
            StubSchemaStore::default(),
            default_transient_store(),
        );
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
            default_transient_store(),
        );
        let tenant_id = "tenant-1";

        // create
        let create_req = CreateIdentitySchemaRequest {
            schema_id: "custom".into(),
            schema_json: Some(proto_struct(json!({"type": "object", "properties": {"traits": {"type": "object", "properties": {"email": {"type": "string"}}}}}))).into(),
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
            schema_json: Some(proto_struct(json!({"type": "object", "title": "v2", "properties": {"traits": {"type": "object", "properties": {"email": {"type": "string"}}}}}))).into(),
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
            default_transient_store(),
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
            default_transient_store(),
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

    // Regression: Hydra delivers its raw login challenge to the login UI via the
    // redirect query string. The gateway has no transient mapping for it, so it
    // must forward it to Kratos instead of failing with `not_found`.
    #[tokio::test]
    async fn create_login_flow_passes_through_raw_hydra_challenge() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::default(),
            default_transient_store(),
        );
        let req = CreateLoginFlowRequest {
            login_challenge: "raw-hydra-challenge-not-in-store".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, CreateLoginFlowRequest);
        let resp = IdentityService::create_login_flow(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.r#type, "login");
    }

    #[tokio::test]
    async fn create_registration_flow_passes_through_raw_hydra_challenge() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::default(),
            default_transient_store(),
        );
        let req = CreateRegistrationFlowRequest {
            login_challenge: "raw-hydra-challenge-not-in-store".into(),
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
            default_transient_store(),
        );
        let req = GetSessionRequest {
            id: "pub-sess-1".into(),
            ..Default::default()
        };
        svc_req!(svc_req, req, GetSessionRequest);
        let resp = IdentityService::get_session(&svc, read_ctx("tenant-1"), svc_req)
            .await
            .unwrap()
            .body;
        assert_eq!(resp.id, "pub-sess-1");
        assert_eq!(resp.identity_id, "pub-1");
        assert!(resp.active);
    }

    #[tokio::test]
    async fn list_sessions_requires_identity_id() {
        let svc = make_service(
            StubKratos::default(),
            StubMappingStore::default(),
            StubSchemaStore::default(),
            default_transient_store(),
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
            default_transient_store(),
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
        assert_eq!(resp.sessions[0].id, "pub-sess-1");
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
            default_transient_store(),
        );
        let req = DeleteSessionRequest {
            id: "pub-sess-1".into(),
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
        kratos
            .add_identity(
                "ory-1",
                json!({"id": "ory-1", "schema_id": "default", "traits": {"email": "a@example.com"}}),
            )
            .await;
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
            default_transient_store(),
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
            "https://ui.example.com/recovery?flow=flow-abc&token=pub-recovery-abc"
        );
        assert_eq!(resp.recovery_token, "pub-recovery-abc");
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
        kratos
            .add_identity(
                "ory-1",
                json!({"id": "ory-1", "schema_id": "default", "traits": {"email": "a@example.com"}}),
            )
            .await;
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
            default_transient_store(),
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
            "https://ui.example.com/recovery?flow=flow-v25&token=pub-recovery-kratos-v25"
        );
        assert_eq!(resp.recovery_token, "pub-recovery-kratos-v25");
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
        kratos
            .add_identity(
                "ory-1",
                json!({"id": "ory-1", "schema_id": "default", "traits": {"email": "a@example.com"}}),
            )
            .await;
        let svc = make_service(
            kratos,
            StubMappingStore::with_mapping("tenant-1", BACKEND_KRATOS, "pub-1", "ory-1"),
            StubSchemaStore::default(),
            default_transient_store(),
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
            "https://ui.example.com/verification?flow=pub-flow-v1&token=pub-token-v1"
        );
        assert_eq!(resp.flow, "pub-flow-v1");
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
            default_transient_store(),
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
            IdentitySchemaRepo::new(pool.clone()),
            crate::db::TenantMembershipRepo::new(pool.clone()),
            TransientTokenRepo::new(pool),
            "https://ui.example.com".to_string(),
            "default".to_string(),
        );
        let _cloned = service.clone();
    }

    #[test]
    fn service_impl_cloneable() {
        let svc = IdentityServiceImpl {
            kratos: Arc::new(StubKratos::default()),
            mappings: Arc::new(StubMappingStore::default()),
            schemas: Arc::new(StubSchemaStore::default()),
            memberships: Arc::new(StubMembershipStore::default()),
            transient: Arc::new(StubTransientTokenStore::default()),
            ui_public_url: "https://ui.example.com".to_string(),
            kratos_default_schema_id: "default".to_string(),
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
            default_transient_store(),
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
            default_transient_store(),
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
            default_transient_store(),
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
            default_transient_store(),
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
            default_transient_store(),
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
            default_transient_store(),
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
