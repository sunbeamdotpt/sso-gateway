use std::sync::Arc;

use async_trait::async_trait;
use buffa_types::google::protobuf::Empty;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sso_ory_client::{error::OryClientError, hydra::HydraClient};
use sunbeam_g2v::error::ServiceError;
use tracing::{debug, instrument};
use ulid::Ulid;

use crate::{
    auth::{AuthContext, SCOPE_APPLICATION_ADMIN, SCOPE_APPLICATION_READ, require_scope},
    db::{IdMappingRepo, IdMappingStore},
    middleware::TenantId,
    proto::iam::v1::{
        ClientCredential, ClientCredentialSecret, ClientCredentialService,
        CreateClientCredentialRequest, DeleteClientCredentialRequest, GetClientCredentialRequest,
        ListClientCredentialsRequest, ListClientCredentialsResponse,
        RotateClientCredentialSecretRequest, UpdateClientCredentialRequest,
    },
};

const BACKEND_HYDRA: &str = "hydra";
const GRANT_TYPE_CLIENT_CREDENTIALS: &str = "client_credentials";

/// Async trait abstracting the Hydra operations used by [`ClientCredentialServiceImpl`].
#[async_trait]
pub trait ClientCredentialHydra: Send + Sync + 'static {
    async fn create_oauth2_client(&self, payload: Value) -> Result<Value, OryClientError>;
    async fn get_oauth2_client(&self, id: &str) -> Result<Value, OryClientError>;
    async fn update_oauth2_client(&self, id: &str, payload: Value)
    -> Result<Value, OryClientError>;
    async fn delete_oauth2_client(&self, id: &str) -> Result<(), OryClientError>;
    async fn rotate_client_secret(&self, id: &str) -> Result<Value, OryClientError>;
}

#[async_trait]
impl ClientCredentialHydra for HydraClient {
    async fn create_oauth2_client(&self, payload: Value) -> Result<Value, OryClientError> {
        self.create_oauth2_client(payload).await
    }

    async fn get_oauth2_client(&self, id: &str) -> Result<Value, OryClientError> {
        self.get_oauth2_client(id).await
    }

    async fn update_oauth2_client(
        &self,
        id: &str,
        payload: Value,
    ) -> Result<Value, OryClientError> {
        self.update_oauth2_client(id, payload).await
    }

    async fn delete_oauth2_client(&self, id: &str) -> Result<(), OryClientError> {
        self.delete_oauth2_client(id).await
    }

    async fn rotate_client_secret(&self, id: &str) -> Result<Value, OryClientError> {
        self.rotate_client_secret(id).await
    }
}

#[derive(Clone)]
pub struct ClientCredentialServiceImpl {
    hydra: Arc<dyn ClientCredentialHydra>,
    mappings: Arc<dyn IdMappingStore>,
}

impl ClientCredentialServiceImpl {
    pub fn new(hydra: Arc<HydraClient>, mappings: IdMappingRepo) -> Self {
        Self {
            hydra: hydra as Arc<dyn ClientCredentialHydra>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
        }
    }
}

#[allow(refining_impl_trait)]
impl ClientCredentialService for ClientCredentialServiceImpl {
    #[instrument(skip(self))]
    async fn create_client_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateClientCredentialRequest>,
    ) -> ServiceResult<ClientCredential> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_APPLICATION_ADMIN)?;
        let req = request.to_owned_message();

        validate_scopes(&req.scope)?;
        let token_endpoint_auth_method =
            validate_or_default_token_endpoint_auth_method(&req.token_endpoint_auth_method)?;

        let public_id = Ulid::new().to_string();
        let payload = build_hydra_payload(&req, &token_endpoint_auth_method, &public_id);
        let created = self
            .hydra
            .create_oauth2_client(payload)
            .await
            .map_err(map_ory_error)?;

        let ory_id = created["client_id"]
            .as_str()
            .ok_or_else(|| ServiceError::Internal("hydra response missing client_id".into()))?;
        let client_secret = match created["client_secret"].as_str() {
            Some(secret) => secret.to_string(),
            None => String::new(),
        };

        self.mappings
            .create(&tenant_id, BACKEND_HYDRA, &public_id, ory_id)
            .await?;

        let mut credential = hydra_to_client_credential(&created, &tenant_id, &public_id);
        credential.client_secret = client_secret;
        Ok(Response::new(credential))
    }

    #[instrument(skip(self))]
    async fn get_client_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetClientCredentialRequest>,
    ) -> ServiceResult<ClientCredential> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_APPLICATION_READ, SCOPE_APPLICATION_ADMIN])?;
        let req = request.to_owned_message();
        let ory_id = self
            .mappings
            .get_ory_id(&tenant_id, BACKEND_HYDRA, &req.id)
            .await?;

        let client = self
            .hydra
            .get_oauth2_client(&ory_id)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(hydra_to_client_credential(
            &client, &tenant_id, &req.id,
        )))
    }

    #[instrument(skip(self))]
    async fn list_client_credentials(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListClientCredentialsRequest>,
    ) -> ServiceResult<ListClientCredentialsResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_APPLICATION_READ, SCOPE_APPLICATION_ADMIN])?;
        let public_ids = self
            .mappings
            .list_public_ids(&tenant_id, BACKEND_HYDRA)
            .await?;

        let mut credentials = Vec::with_capacity(public_ids.len());
        for public_id in public_ids {
            match self
                .mappings
                .get_ory_id(&tenant_id, BACKEND_HYDRA, &public_id)
                .await
            {
                Ok(ory_id) => match self.hydra.get_oauth2_client(&ory_id).await {
                    Ok(client) => credentials
                        .push(hydra_to_client_credential(&client, &tenant_id, &public_id)),
                    Err(err) => debug!(%public_id, "failed to fetch hydra client: {}", err),
                },
                Err(err) => debug!(%public_id, "mapping lookup failed: {}", err),
            }
        }

        Ok(Response::new(ListClientCredentialsResponse {
            client_credentials: credentials,
            ..Default::default()
        }))
    }

    #[instrument(skip(self))]
    async fn update_client_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateClientCredentialRequest>,
    ) -> ServiceResult<ClientCredential> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_APPLICATION_ADMIN)?;
        let req = request.to_owned_message();

        validate_scopes(&req.scope)?;
        let token_endpoint_auth_method =
            validate_or_default_token_endpoint_auth_method(&req.token_endpoint_auth_method)?;

        let ory_id = self
            .mappings
            .get_ory_id(&tenant_id, BACKEND_HYDRA, &req.id)
            .await?;

        let payload = build_hydra_update_payload(&req, &ory_id, &token_endpoint_auth_method);
        let updated = self
            .hydra
            .update_oauth2_client(&ory_id, payload)
            .await
            .map_err(map_ory_error)?;

        Ok(Response::new(hydra_to_client_credential(
            &updated, &tenant_id, &req.id,
        )))
    }

    #[instrument(skip(self))]
    async fn delete_client_credential(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteClientCredentialRequest>,
    ) -> ServiceResult<Empty> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_APPLICATION_ADMIN)?;
        let req = request.to_owned_message();
        let ory_id = self
            .mappings
            .get_ory_id(&tenant_id, BACKEND_HYDRA, &req.id)
            .await?;

        self.hydra
            .delete_oauth2_client(&ory_id)
            .await
            .map_err(map_ory_error)?;
        self.mappings
            .delete(&tenant_id, BACKEND_HYDRA, &req.id)
            .await?;

        Ok(Response::new(Empty::default()))
    }

    #[instrument(skip(self))]
    async fn rotate_client_credential_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RotateClientCredentialSecretRequest>,
    ) -> ServiceResult<ClientCredentialSecret> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_APPLICATION_ADMIN)?;
        let req = request.to_owned_message();
        let ory_id = self
            .mappings
            .get_ory_id(&tenant_id, BACKEND_HYDRA, &req.id)
            .await?;

        let rotated = self
            .hydra
            .rotate_client_secret(&ory_id)
            .await
            .map_err(map_ory_error)?;

        let client_secret = rotated["client_secret"]
            .as_str()
            .ok_or_else(|| ServiceError::Internal("hydra response missing client_secret".into()))?
            .to_string();

        Ok(Response::new(ClientCredentialSecret {
            client_id: req.id,
            client_secret,
            ..Default::default()
        }))
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

fn validate_scopes(scopes: &[String]) -> Result<(), ServiceError> {
    if scopes.is_empty() {
        return Err(ServiceError::InvalidArgument(
            "at least one scope is required".into(),
        ));
    }
    for scope in scopes {
        if !crate::auth::KNOWN_SCOPES.contains(&scope.as_str()) {
            return Err(ServiceError::InvalidArgument(format!(
                "unknown scope: {scope}"
            )));
        }
    }
    Ok(())
}

fn validate_or_default_token_endpoint_auth_method(method: &str) -> Result<String, ServiceError> {
    if method.is_empty() {
        return Ok("client_secret_basic".to_string());
    }
    const ALLOWED: &[&str] = &["client_secret_post", "client_secret_basic"];
    if !ALLOWED.contains(&method) {
        return Err(ServiceError::InvalidArgument(format!(
            "token_endpoint_auth_method must be one of {:?}",
            ALLOWED
        )));
    }
    Ok(method.to_string())
}

pub(crate) fn map_ory_error(err: OryClientError) -> ServiceError {
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

fn build_hydra_payload(
    req: &CreateClientCredentialRequest,
    method: &str,
    client_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "client_id": client_id,
        "client_name": req.name,
        "grant_types": [GRANT_TYPE_CLIENT_CREDENTIALS],
        "scope": req.scope.join(" "),
        "token_endpoint_auth_method": method,
    })
}

fn build_hydra_update_payload(
    req: &UpdateClientCredentialRequest,
    ory_id: &str,
    method: &str,
) -> serde_json::Value {
    serde_json::json!({
        "client_id": ory_id,
        "client_name": req.name,
        "grant_types": [GRANT_TYPE_CLIENT_CREDENTIALS],
        "scope": req.scope.join(" "),
        "token_endpoint_auth_method": method,
    })
}

fn hydra_to_client_credential(
    client: &serde_json::Value,
    tenant_id: &str,
    public_id: &str,
) -> ClientCredential {
    ClientCredential {
        id: public_id.to_string(),
        tenant_id: tenant_id.to_string(),
        name: match client["client_name"].as_str() {
            Some(name) => name.to_string(),
            None => String::new(),
        },
        scope: match client["scope"].as_str() {
            Some(scope) if !scope.is_empty() => {
                scope.split(' ').map(|s| s.to_string()).collect()
            }
            _ => Vec::new(),
        },
        token_endpoint_auth_method: match client["token_endpoint_auth_method"].as_str() {
            Some(method) => method.to_string(),
            None => String::new(),
        },
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::auth::SubjectType;
    use crate::db::{DbError, IdMappingRow};
    use crate::proto::iam::v1::ClientCredentialService;
    use buffa::bytes::Bytes;
    use buffa::view::MessageView;
    use buffa::{HasMessageView, Message};
    use serde_json::json;

    macro_rules! svc_req {
        ($id:ident, $req:expr, $ty:ty) => {
            let bytes = Bytes::from($req.encode_to_vec());
            let view = <$ty as HasMessageView>::View::decode_view(&bytes).unwrap();
            let $id = ServiceRequest::<$ty>::from_parts(&view, &bytes);
        };
    }

    fn tenant_context(tenant_id: &str) -> RequestContext {
        scoped_context(tenant_id, &[SCOPE_APPLICATION_READ])
    }

    fn admin_context(tenant_id: &str) -> RequestContext {
        scoped_context(tenant_id, &[SCOPE_APPLICATION_ADMIN])
    }

    fn no_scope_context(tenant_id: &str) -> RequestContext {
        scoped_context(tenant_id, &["other:scope"])
    }

    fn scoped_context(tenant_id: &str, scopes: &[&str]) -> RequestContext {
        let mut ctx = RequestContext::new(http::HeaderMap::new());
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

    fn mapping_row(tenant_id: &str, backend: &str, public_id: &str, ory_id: &str) -> IdMappingRow {
        IdMappingRow {
            id: "id".to_string(),
            tenant_id: tenant_id.to_string(),
            backend: backend.to_string(),
            public_id: public_id.to_string(),
            ory_global_id: ory_id.to_string(),
            created_at: time::OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn hydra_client_response() -> Value {
        json!({
            "client_id": "ory-123",
            "client_name": "test-credential",
            "client_secret": "secret-123",
            "scope": "tenant:read application:read",
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_basic",
        })
    }

    fn ory_not_found() -> OryClientError {
        OryClientError::Ory {
            status: 404,
            message: "not found".into(),
        }
    }

    // -----------------------------------------------------------------------
    // Stub implementations
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct StubHydra {
        create_result: Mutex<Option<Result<Value, OryClientError>>>,
        get_results: Mutex<Vec<Result<Value, OryClientError>>>,
        update_result: Mutex<Option<Result<Value, OryClientError>>>,
        delete_result: Mutex<Option<Result<(), OryClientError>>>,
        rotate_result: Mutex<Option<Result<Value, OryClientError>>>,
    }

    #[async_trait]
    impl ClientCredentialHydra for StubHydra {
        async fn create_oauth2_client(&self, _payload: Value) -> Result<Value, OryClientError> {
            self.create_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::InvalidResponse("stub create".into())))
        }

        async fn get_oauth2_client(&self, _id: &str) -> Result<Value, OryClientError> {
            let mut results = self.get_results.lock().unwrap();
            if results.is_empty() {
                return Err(OryClientError::InvalidResponse("stub get".into()));
            }
            results.remove(0)
        }

        async fn update_oauth2_client(
            &self,
            _id: &str,
            _payload: Value,
        ) -> Result<Value, OryClientError> {
            self.update_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::InvalidResponse("stub update".into())))
        }

        async fn delete_oauth2_client(&self, _id: &str) -> Result<(), OryClientError> {
            self.delete_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::InvalidResponse("stub delete".into())))
        }

        async fn rotate_client_secret(&self, _id: &str) -> Result<Value, OryClientError> {
            self.rotate_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::InvalidResponse("stub rotate".into())))
        }
    }

    #[derive(Default)]
    struct StubMappings {
        create_result: Mutex<Option<Result<IdMappingRow, DbError>>>,
        get_ory_id_results: Mutex<Vec<Result<String, DbError>>>,
        list_public_ids_result: Mutex<Option<Result<Vec<String>, DbError>>>,
        delete_result: Mutex<Option<Result<(), DbError>>>,
    }

    fn take_result<T>(slot: &Mutex<Option<Result<T, DbError>>>) -> Result<T, DbError> {
        slot.lock()
            .unwrap()
            .take()
            .unwrap_or(Err(DbError::MappingNotFound))
    }

    #[async_trait]
    impl IdMappingStore for StubMappings {
        async fn create(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
            _ory_global_id: &str,
        ) -> Result<IdMappingRow, DbError> {
            take_result(&self.create_result)
        }

        async fn get_ory_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<String, DbError> {
            let mut results = self.get_ory_id_results.lock().unwrap();
            if results.is_empty() {
                return Err(DbError::MappingNotFound);
            }
            results.remove(0)
        }

        async fn delete(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<(), DbError> {
            take_result(&self.delete_result)
        }

        async fn list_public_ids(
            &self,
            _tenant_id: &str,
            _backend: &str,
        ) -> Result<Vec<String>, DbError> {
            take_result(&self.list_public_ids_result)
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, DbError> {
            Ok(None)
        }

        async fn get_public_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, DbError> {
            Err(DbError::MappingNotFound)
        }
    }

    fn service(
        hydra: Arc<dyn ClientCredentialHydra>,
        mappings: Arc<dyn IdMappingStore>,
    ) -> ClientCredentialServiceImpl {
        ClientCredentialServiceImpl { hydra, mappings }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn list_requires_application_read_or_admin_scope() {
        let hydra: Arc<dyn ClientCredentialHydra> = Arc::new(StubHydra::default());
        let mappings: Arc<dyn IdMappingStore> = Arc::new(StubMappings::default());
        let svc = service(hydra, mappings);

        let req = ListClientCredentialsRequest::default();
        svc_req!(r, req, ListClientCredentialsRequest);

        let err = svc
            .list_client_credentials(no_scope_context("t1"), r)
            .await
            .unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
    }

    #[tokio::test]
    async fn create_requires_application_admin_scope() {
        let hydra: Arc<dyn ClientCredentialHydra> = Arc::new(StubHydra::default());
        let mappings: Arc<dyn IdMappingStore> = Arc::new(StubMappings::default());
        let svc = service(hydra, mappings);

        let req = CreateClientCredentialRequest {
            name: "test".into(),
            scope: vec!["tenant:read".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            ..Default::default()
        };
        svc_req!(r, req, CreateClientCredentialRequest);

        let err = svc
            .create_client_credential(tenant_context("t1"), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing required scope"));
    }

    #[tokio::test]
    async fn create_rejects_unknown_scope() {
        let hydra: Arc<dyn ClientCredentialHydra> = Arc::new(StubHydra::default());
        let mappings: Arc<dyn IdMappingStore> = Arc::new(StubMappings::default());
        let svc = service(hydra, mappings);

        let req = CreateClientCredentialRequest {
            name: "test".into(),
            scope: vec!["custom:scope".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            ..Default::default()
        };
        svc_req!(r, req, CreateClientCredentialRequest);

        let err = svc
            .create_client_credential(admin_context("t1"), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown scope"));
    }

    #[tokio::test]
    async fn create_rejects_forbidden_auth_method() {
        let hydra: Arc<dyn ClientCredentialHydra> = Arc::new(StubHydra::default());
        let mappings: Arc<dyn IdMappingStore> = Arc::new(StubMappings::default());
        let svc = service(hydra, mappings);

        let req = CreateClientCredentialRequest {
            name: "test".into(),
            scope: vec!["tenant:read".into()],
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        };
        svc_req!(r, req, CreateClientCredentialRequest);

        let err = svc
            .create_client_credential(admin_context("t1"), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("token_endpoint_auth_method"));
    }

    #[tokio::test]
    async fn create_persists_mapping_and_returns_secret() {
        let hydra = Arc::new(StubHydra {
            create_result: Mutex::new(Some(Ok(hydra_client_response()))),
            ..Default::default()
        });
        let mappings = Arc::new(StubMappings {
            create_result: Mutex::new(Some(Ok(mapping_row("t1", "hydra", "pub-1", "ory-123")))),
            ..Default::default()
        });
        let svc = service(hydra, mappings);

        let req = CreateClientCredentialRequest {
            name: "test-credential".into(),
            scope: vec!["tenant:read".into(), "application:read".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            ..Default::default()
        };
        svc_req!(r, req, CreateClientCredentialRequest);

        let resp = svc
            .create_client_credential(admin_context("t1"), r)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.name, "test-credential");
        assert_eq!(resp.client_secret, "secret-123");
        assert_eq!(resp.scope, vec!["tenant:read", "application:read"]);
        assert_eq!(resp.token_endpoint_auth_method, "client_secret_basic");
    }

    #[tokio::test]
    async fn get_returns_hydra_client() {
        let hydra = Arc::new(StubHydra {
            get_results: Mutex::new(vec![Ok(hydra_client_response())]),
            ..Default::default()
        });
        let mappings = Arc::new(StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        });
        let svc = service(hydra, mappings);

        let req = GetClientCredentialRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(r, req, GetClientCredentialRequest);

        let resp = svc
            .get_client_credential(tenant_context("t1"), r)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.id, "pub-1");
        assert_eq!(resp.name, "test-credential");
        assert!(resp.client_secret.is_empty());
    }

    #[tokio::test]
    async fn list_returns_mapped_credentials() {
        let hydra = Arc::new(StubHydra {
            get_results: Mutex::new(vec![Ok(hydra_client_response())]),
            ..Default::default()
        });
        let mappings = Arc::new(StubMappings {
            list_public_ids_result: Mutex::new(Some(Ok(vec!["pub-1".into()]))),
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        });
        let svc = service(hydra, mappings);

        let req = ListClientCredentialsRequest::default();
        svc_req!(r, req, ListClientCredentialsRequest);

        let resp = svc
            .list_client_credentials(tenant_context("t1"), r)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.client_credentials.len(), 1);
        assert_eq!(resp.client_credentials[0].id, "pub-1");
    }

    #[tokio::test]
    async fn update_rejects_empty_scope() {
        let hydra: Arc<dyn ClientCredentialHydra> = Arc::new(StubHydra::default());
        let mappings: Arc<dyn IdMappingStore> = Arc::new(StubMappings::default());
        let svc = service(hydra, mappings);

        let req = UpdateClientCredentialRequest {
            id: "pub-1".into(),
            name: "updated".into(),
            scope: vec![],
            token_endpoint_auth_method: "client_secret_basic".into(),
            ..Default::default()
        };
        svc_req!(r, req, UpdateClientCredentialRequest);

        let err = svc
            .update_client_credential(admin_context("t1"), r)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("at least one scope"));
    }

    #[tokio::test]
    async fn update_applies_changes() {
        let hydra = Arc::new(StubHydra {
            get_results: Mutex::new(vec![Ok(hydra_client_response())]),
            update_result: Mutex::new(Some(Ok(json!({
                "client_id": "ory-123",
                "client_name": "updated-credential",
                "scope": "tenant:admin",
                "grant_types": ["client_credentials"],
                "token_endpoint_auth_method": "client_secret_post",
            })))),
            ..Default::default()
        });
        let mappings = Arc::new(StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        });
        let svc = service(hydra, mappings);

        let req = UpdateClientCredentialRequest {
            id: "pub-1".into(),
            name: "updated-credential".into(),
            scope: vec!["tenant:admin".into()],
            token_endpoint_auth_method: "client_secret_post".into(),
            ..Default::default()
        };
        svc_req!(r, req, UpdateClientCredentialRequest);

        let resp = svc
            .update_client_credential(admin_context("t1"), r)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.name, "updated-credential");
        assert_eq!(resp.scope, vec!["tenant:admin"]);
        assert_eq!(resp.token_endpoint_auth_method, "client_secret_post");
    }

    #[tokio::test]
    async fn delete_removes_hydra_client_and_mapping() {
        let hydra = Arc::new(StubHydra {
            delete_result: Mutex::new(Some(Ok(()))),
            ..Default::default()
        });
        let mappings = Arc::new(StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            delete_result: Mutex::new(Some(Ok(()))),
            ..Default::default()
        });
        let svc = service(hydra, mappings);

        let req = DeleteClientCredentialRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(r, req, DeleteClientCredentialRequest);

        svc.delete_client_credential(admin_context("t1"), r)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rotate_returns_new_secret() {
        let hydra = Arc::new(StubHydra {
            rotate_result: Mutex::new(Some(Ok(json!({
                "client_id": "ory-123",
                "client_secret": "new-secret",
            })))),
            ..Default::default()
        });
        let mappings = Arc::new(StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        });
        let svc = service(hydra, mappings);

        let req = RotateClientCredentialSecretRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(r, req, RotateClientCredentialSecretRequest);

        let resp = svc
            .rotate_client_credential_secret(admin_context("t1"), r)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.client_id, "pub-1");
        assert_eq!(resp.client_secret, "new-secret");
    }

    #[tokio::test]
    async fn missing_mapping_returns_not_found() {
        let hydra = Arc::new(StubHydra {
            get_results: Mutex::new(vec![Err(ory_not_found())]),
            ..Default::default()
        });
        let mappings = Arc::new(StubMappings {
            get_ory_id_results: Mutex::new(vec![Err(DbError::MappingNotFound)]),
            ..Default::default()
        });
        let svc = service(hydra, mappings);

        let req = GetClientCredentialRequest {
            id: "missing".into(),
            ..Default::default()
        };
        svc_req!(r, req, GetClientCredentialRequest);

        let err = svc
            .get_client_credential(tenant_context("t1"), r)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("not found") || err.to_string().contains("MappingNotFound")
        );
    }
}
