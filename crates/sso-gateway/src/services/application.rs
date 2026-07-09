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
        Application, ApplicationSecret, CreateApplicationRequest, DeleteApplicationRequest,
        GetApplicationRequest, ListApplicationsRequest, ListApplicationsResponse,
        RotateSecretRequest, UpdateApplicationRequest,
    },
};

pub(crate) const BACKEND_HYDRA: &str = "hydra";

/// Async trait abstracting the Hydra operations used by [`ApplicationServiceImpl`].
#[async_trait]
pub trait ApplicationHydra: Send + Sync + 'static {
    async fn create_oauth2_client(&self, payload: Value) -> Result<Value, OryClientError>;
    async fn get_oauth2_client(&self, id: &str) -> Result<Value, OryClientError>;
    async fn update_oauth2_client(&self, id: &str, payload: Value)
    -> Result<Value, OryClientError>;
    async fn delete_oauth2_client(&self, id: &str) -> Result<(), OryClientError>;
    async fn rotate_client_secret(&self, id: &str) -> Result<Value, OryClientError>;
}

#[async_trait]
impl ApplicationHydra for HydraClient {
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
pub struct ApplicationServiceImpl {
    hydra: Arc<dyn ApplicationHydra>,
    mappings: Arc<dyn IdMappingStore>,
    allow_http_redirect_uris: bool,
}

impl ApplicationServiceImpl {
    pub fn new(hydra: Arc<HydraClient>, mappings: IdMappingRepo) -> Self {
        Self {
            hydra: hydra as Arc<dyn ApplicationHydra>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
            allow_http_redirect_uris: false,
        }
    }

    /// Allow `http` redirect URIs in addition to `https`. Intended for tests;
    /// production should keep the default https-only restriction.
    #[must_use]
    pub fn with_allow_http_redirect_uris(mut self, allow: bool) -> Self {
        self.allow_http_redirect_uris = allow;
        self
    }
}

#[allow(refining_impl_trait)]
impl crate::proto::iam::v1::ApplicationService for ApplicationServiceImpl {
    #[instrument(skip(self))]
    async fn create_application(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateApplicationRequest>,
    ) -> ServiceResult<Application> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_APPLICATION_ADMIN)?;
        let req = request.to_owned_message();

        validate_redirect_uris(&req.redirect_uris, self.allow_http_redirect_uris)?;
        validate_token_endpoint_auth_method(&req.token_endpoint_auth_method)?;

        let payload = build_hydra_payload(&req);
        let created = self
            .hydra
            .create_oauth2_client(payload)
            .await
            .map_err(map_ory_error)?;

        let ory_id = created["client_id"]
            .as_str()
            .ok_or_else(|| ServiceError::Internal("hydra response missing client_id".into()))?;
        let client_secret = created["client_secret"].as_str().unwrap_or("").to_string();

        let public_id = Ulid::new().to_string();
        self.mappings
            .create(&tenant_id, BACKEND_HYDRA, &public_id, ory_id)
            .await?;

        let mut app = hydra_to_application(&created, &tenant_id, &public_id);
        app.client_secret = client_secret;
        Ok(Response::new(app))
    }

    #[instrument(skip(self))]
    async fn get_application(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetApplicationRequest>,
    ) -> ServiceResult<Application> {
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
        Ok(Response::new(hydra_to_application(
            &client, &tenant_id, &req.id,
        )))
    }

    #[instrument(skip(self))]
    async fn list_applications(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListApplicationsRequest>,
    ) -> ServiceResult<ListApplicationsResponse> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_APPLICATION_READ, SCOPE_APPLICATION_ADMIN])?;
        let public_ids = self
            .mappings
            .list_public_ids(&tenant_id, BACKEND_HYDRA)
            .await?;

        let mut applications = Vec::with_capacity(public_ids.len());
        for public_id in public_ids {
            match self
                .mappings
                .get_ory_id(&tenant_id, BACKEND_HYDRA, &public_id)
                .await
            {
                Ok(ory_id) => match self.hydra.get_oauth2_client(&ory_id).await {
                    Ok(client) => {
                        applications.push(hydra_to_application(&client, &tenant_id, &public_id))
                    }
                    Err(err) => debug!(%public_id, "failed to fetch hydra client: {}", err),
                },
                Err(err) => debug!(%public_id, "mapping lookup failed: {}", err),
            }
        }

        Ok(Response::new(ListApplicationsResponse {
            applications,
            ..Default::default()
        }))
    }

    #[instrument(skip(self))]
    async fn update_application(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateApplicationRequest>,
    ) -> ServiceResult<Application> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_APPLICATION_ADMIN)?;
        let req = request.to_owned_message();
        validate_redirect_uris(&req.redirect_uris, self.allow_http_redirect_uris)?;
        validate_token_endpoint_auth_method(&req.token_endpoint_auth_method)?;

        let ory_id = self
            .mappings
            .get_ory_id(&tenant_id, BACKEND_HYDRA, &req.id)
            .await?;

        let payload = build_hydra_update_payload(&req, &ory_id);
        let updated = self
            .hydra
            .update_oauth2_client(&ory_id, payload)
            .await
            .map_err(map_ory_error)?;

        Ok(Response::new(hydra_to_application(
            &updated, &tenant_id, &req.id,
        )))
    }

    #[instrument(skip(self))]
    async fn delete_application(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeleteApplicationRequest>,
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
    async fn rotate_secret(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RotateSecretRequest>,
    ) -> ServiceResult<ApplicationSecret> {
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

        let client_id = rotated["client_id"].as_str().unwrap_or(&ory_id).to_string();
        let client_secret = rotated["client_secret"]
            .as_str()
            .ok_or_else(|| ServiceError::Internal("hydra response missing client_secret".into()))?
            .to_string();

        Ok(Response::new(ApplicationSecret {
            client_id,
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

fn is_loopback_host(parsed: &reqwest::Url) -> bool {
    parsed
        .host()
        .map(|host| match host {
            url::Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
            url::Host::Ipv4(ip) => ip.is_loopback(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
        })
        .unwrap_or(false)
}

pub fn validate_redirect_uris(uris: &[String], allow_http: bool) -> Result<(), ServiceError> {
    for uri in uris {
        if uri.contains('*') {
            return Err(ServiceError::InvalidArgument(format!(
                "redirect_uri contains wildcard: {uri}"
            )));
        }
        let parsed = reqwest::Url::parse(uri).map_err(|e| {
            ServiceError::InvalidArgument(format!("invalid redirect_uri {uri}: {e}"))
        })?;
        let scheme = parsed.scheme();
        match scheme {
            "https" => {}
            "http" if allow_http || is_loopback_host(&parsed) => {}
            "javascript" | "data" => {
                return Err(ServiceError::InvalidArgument(format!(
                    "redirect_uri uses forbidden scheme: {scheme}"
                )));
            }
            _ => {
                return Err(ServiceError::InvalidArgument(format!(
                    "redirect_uri must use https scheme: {uri}"
                )));
            }
        }
    }
    Ok(())
}

pub fn validate_token_endpoint_auth_method(method: &str) -> Result<(), ServiceError> {
    if method.is_empty() {
        return Ok(());
    }
    const ALLOWED: &[&str] = &["client_secret_post", "client_secret_basic", "none"];
    if !ALLOWED.contains(&method) {
        return Err(ServiceError::InvalidArgument(format!(
            "token_endpoint_auth_method must be one of {:?}",
            ALLOWED
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

fn build_hydra_payload(req: &CreateApplicationRequest) -> serde_json::Value {
    serde_json::json!({
        "client_name": req.name,
        "redirect_uris": req.redirect_uris,
        "grant_types": req.grant_types,
        "response_types": req.response_types,
        "scope": req.scope.join(" "),
        "token_endpoint_auth_method": req.token_endpoint_auth_method,
    })
}

fn build_hydra_update_payload(req: &UpdateApplicationRequest, ory_id: &str) -> serde_json::Value {
    serde_json::json!({
        "client_id": ory_id,
        "client_name": req.name,
        "redirect_uris": req.redirect_uris,
        "grant_types": req.grant_types,
        "response_types": req.response_types,
        "scope": req.scope.join(" "),
        "token_endpoint_auth_method": req.token_endpoint_auth_method,
    })
}

fn hydra_to_application(
    client: &serde_json::Value,
    tenant_id: &str,
    public_id: &str,
) -> Application {
    let scope_string = client["scope"].as_str().unwrap_or("");
    Application {
        id: public_id.to_string(),
        tenant_id: tenant_id.to_string(),
        name: client["client_name"].as_str().unwrap_or("").to_string(),
        redirect_uris: json_string_array(&client["redirect_uris"]),
        grant_types: json_string_array(&client["grant_types"]),
        response_types: json_string_array(&client["response_types"]),
        scope: if scope_string.is_empty() {
            Vec::new()
        } else {
            scope_string.split(' ').map(|s| s.to_string()).collect()
        },
        token_endpoint_auth_method: client["token_endpoint_auth_method"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        ..Default::default()
    }
}

fn json_string_array(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::db::{DbError, IdMappingRow};
    use crate::proto::iam::v1::ApplicationService;
    use buffa::bytes::Bytes;
    use buffa::view::MessageView;
    use buffa::{HasMessageView, Message};
    use serde_json::json;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

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
            "client_name": "test-app",
            "client_secret": "secret-123",
            "scope": "openid profile",
            "redirect_uris": ["https://a/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
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
    impl ApplicationHydra for StubHydra {
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
        get_public_id_result: Mutex<Option<Result<String, DbError>>>,
        get_tenant_id_result: Mutex<Option<Result<Option<String>, DbError>>>,
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

        async fn get_public_id(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, DbError> {
            take_result(&self.get_public_id_result)
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
            take_result(&self.get_tenant_id_result)
        }
    }

    fn build_service(hydra: StubHydra, mappings: StubMappings) -> ApplicationServiceImpl {
        ApplicationServiceImpl {
            hydra: Arc::new(hydra),
            mappings: Arc::new(mappings),
            allow_http_redirect_uris: false,
        }
    }

    fn build_service_allow_http(
        hydra: StubHydra,
        mappings: StubMappings,
    ) -> ApplicationServiceImpl {
        ApplicationServiceImpl {
            hydra: Arc::new(hydra),
            mappings: Arc::new(mappings),
            allow_http_redirect_uris: true,
        }
    }

    // -----------------------------------------------------------------------
    // create_application
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_application_happy_path() {
        let hydra = StubHydra {
            create_result: Mutex::new(Some(Ok(hydra_client_response()))),
            ..Default::default()
        };
        let mappings = StubMappings {
            create_result: Mutex::new(Some(Ok(mapping_row(
                "tenant-1",
                BACKEND_HYDRA,
                "pub-1",
                "ory-123",
            )))),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = CreateApplicationRequest {
            name: "test-app".into(),
            redirect_uris: vec!["https://a/callback".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            scope: vec!["openid".into(), "profile".into()],
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        };
        svc_req!(request, req, CreateApplicationRequest);

        let resp = service
            .create_application(admin_context("tenant-1"), request)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.tenant_id, "tenant-1");
        assert_eq!(resp.name, "test-app");
        assert_eq!(resp.client_secret, "secret-123");
        assert_eq!(resp.scope, vec!["openid", "profile"]);
        assert!(!resp.id.is_empty());
    }

    #[tokio::test]
    async fn create_application_missing_tenant() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = CreateApplicationRequest::default();
        svc_req!(request, req, CreateApplicationRequest);

        let err = service
            .create_application(RequestContext::new(http::HeaderMap::new()), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::Unauthenticated, "{err:?}");
    }

    #[tokio::test]
    async fn create_application_hydra_error() {
        let hydra = StubHydra {
            create_result: Mutex::new(Some(Err(ory_not_found()))),
            ..Default::default()
        };
        let service = build_service(hydra, StubMappings::default());
        let req = CreateApplicationRequest::default();
        svc_req!(request, req, CreateApplicationRequest);

        let err = service
            .create_application(admin_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::NotFound, "{err:?}");
    }

    #[tokio::test]
    async fn create_application_missing_client_id() {
        let hydra = StubHydra {
            create_result: Mutex::new(Some(Ok(json!({"client_secret": "secret"})))),
            ..Default::default()
        };
        let service = build_service(hydra, StubMappings::default());
        let req = CreateApplicationRequest::default();
        svc_req!(request, req, CreateApplicationRequest);

        let err = service
            .create_application(admin_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::Internal, "{err:?}");
    }

    // -----------------------------------------------------------------------
    // get_application
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_application_happy_path() {
        let hydra = StubHydra {
            get_results: Mutex::new(vec![Ok(hydra_client_response())]),
            ..Default::default()
        };
        let mappings = StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = GetApplicationRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, GetApplicationRequest);

        let resp = service
            .get_application(tenant_context("tenant-1"), request)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.id, "pub-1");
        assert_eq!(resp.tenant_id, "tenant-1");
        assert_eq!(resp.name, "test-app");
    }

    #[tokio::test]
    async fn get_application_mapping_not_found() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = GetApplicationRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, GetApplicationRequest);

        let err = service
            .get_application(tenant_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::NotFound, "{err:?}");
    }

    // -----------------------------------------------------------------------
    // list_applications
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn list_applications_happy_path() {
        let hydra = StubHydra {
            get_results: Mutex::new(vec![
                Ok(hydra_client_response()),
                Ok(json!({
                    "client_id": "ory-456",
                    "client_name": "second-app",
                    "scope": "",
                })),
            ]),
            ..Default::default()
        };
        let mappings = StubMappings {
            list_public_ids_result: Mutex::new(Some(Ok(vec!["pub-1".into(), "pub-2".into()]))),
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into()), Ok("ory-456".into())]),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = ListApplicationsRequest::default();
        svc_req!(request, req, ListApplicationsRequest);

        let resp = service
            .list_applications(tenant_context("tenant-1"), request)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.applications.len(), 2);
        assert_eq!(resp.applications[0].name, "test-app");
        assert_eq!(resp.applications[1].name, "second-app");
    }

    #[tokio::test]
    async fn list_applications_skips_unresolvable_clients() {
        let hydra = StubHydra {
            get_results: Mutex::new(vec![Ok(hydra_client_response())]),
            ..Default::default()
        };
        let mappings = StubMappings {
            list_public_ids_result: Mutex::new(Some(Ok(vec!["pub-1".into(), "pub-2".into()]))),
            get_ory_id_results: Mutex::new(vec![
                Ok("ory-123".into()),
                Err(DbError::MappingNotFound),
            ]),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = ListApplicationsRequest::default();
        svc_req!(request, req, ListApplicationsRequest);

        let resp = service
            .list_applications(tenant_context("tenant-1"), request)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.applications.len(), 1);
        assert_eq!(resp.applications[0].id, "pub-1");
    }

    #[tokio::test]
    async fn list_applications_skips_hydra_failures() {
        let hydra = StubHydra {
            get_results: Mutex::new(vec![Err(ory_not_found()), Ok(hydra_client_response())]),
            ..Default::default()
        };
        let mappings = StubMappings {
            list_public_ids_result: Mutex::new(Some(Ok(vec!["pub-1".into(), "pub-2".into()]))),
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into()), Ok("ory-456".into())]),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = ListApplicationsRequest::default();
        svc_req!(request, req, ListApplicationsRequest);

        let resp = service
            .list_applications(tenant_context("tenant-1"), request)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.applications.len(), 1);
        assert_eq!(resp.applications[0].id, "pub-2");
    }

    // -----------------------------------------------------------------------
    // update_application
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn update_application_happy_path() {
        let hydra = StubHydra {
            update_result: Mutex::new(Some(Ok(hydra_client_response()))),
            ..Default::default()
        };
        let mappings = StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = UpdateApplicationRequest {
            id: "pub-1".into(),
            name: "updated".into(),
            redirect_uris: vec!["https://b/callback".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            scope: vec!["openid".into()],
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        };
        svc_req!(request, req, UpdateApplicationRequest);

        let resp = service
            .update_application(admin_context("tenant-1"), request)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.id, "pub-1");
        assert_eq!(resp.name, "test-app");
    }

    #[tokio::test]
    async fn update_application_mapping_not_found() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = UpdateApplicationRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, UpdateApplicationRequest);

        let err = service
            .update_application(admin_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::NotFound, "{err:?}");
    }

    // -----------------------------------------------------------------------
    // delete_application
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delete_application_happy_path() {
        let hydra = StubHydra {
            delete_result: Mutex::new(Some(Ok(()))),
            ..Default::default()
        };
        let mappings = StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            delete_result: Mutex::new(Some(Ok(()))),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = DeleteApplicationRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, DeleteApplicationRequest);

        service
            .delete_application(admin_context("tenant-1"), request)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_application_hydra_error() {
        let hydra = StubHydra {
            delete_result: Mutex::new(Some(Err(ory_not_found()))),
            ..Default::default()
        };
        let mappings = StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = DeleteApplicationRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, DeleteApplicationRequest);

        let err = service
            .delete_application(admin_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::NotFound, "{err:?}");
    }

    // -----------------------------------------------------------------------
    // rotate_secret
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rotate_secret_happy_path() {
        let hydra = StubHydra {
            rotate_result: Mutex::new(Some(Ok(json!({
                "client_id": "ory-123",
                "client_secret": "rotated-secret",
            })))),
            ..Default::default()
        };
        let mappings = StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = RotateSecretRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, RotateSecretRequest);

        let resp = service
            .rotate_secret(admin_context("tenant-1"), request)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.client_id, "ory-123");
        assert_eq!(resp.client_secret, "rotated-secret");
    }

    #[tokio::test]
    async fn rotate_secret_missing_secret() {
        let hydra = StubHydra {
            rotate_result: Mutex::new(Some(Ok(json!({"client_id": "ory-123"})))),
            ..Default::default()
        };
        let mappings = StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = RotateSecretRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, RotateSecretRequest);

        let err = service
            .rotate_secret(admin_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::Internal, "{err:?}");
    }

    // -----------------------------------------------------------------------
    // Existing pure-function tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_hydra_payload_maps_fields() {
        let req = CreateApplicationRequest {
            name: "app".into(),
            redirect_uris: vec!["https://a".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            scope: vec!["openid".into(), "profile".into()],
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        };
        let payload = build_hydra_payload(&req);
        assert_eq!(payload["client_name"], "app");
        assert_eq!(payload["scope"], "openid profile");
    }

    #[test]
    fn build_hydra_update_payload_includes_client_id() {
        let req = UpdateApplicationRequest {
            name: "updated".into(),
            redirect_uris: vec!["https://b".into()],
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            scope: vec!["openid".into()],
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        };
        let payload = build_hydra_update_payload(&req, "ory-123");
        assert_eq!(payload["client_id"], "ory-123");
        assert_eq!(payload["client_name"], "updated");
    }

    #[test]
    fn hydra_to_application_splits_scope_string() {
        let client = json!({
            "client_name": "app",
            "scope": "openid profile",
            "redirect_uris": ["https://a"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        });
        let app = hydra_to_application(&client, "tenant-1", "pub-1");
        assert_eq!(app.id, "pub-1");
        assert_eq!(app.tenant_id, "tenant-1");
        assert_eq!(app.name, "app");
        assert_eq!(app.scope, vec!["openid", "profile"]);
        assert_eq!(app.redirect_uris, vec!["https://a"]);
    }

    #[test]
    fn hydra_to_application_handles_empty_scope() {
        let client = json!({});
        let app = hydra_to_application(&client, "tenant-1", "pub-1");
        assert!(app.scope.is_empty());
    }

    #[test]
    fn json_string_array_extracts_strings_and_skips_non_strings() {
        let value = json!(["a", 1, "b", null]);
        assert_eq!(json_string_array(&value), vec!["a", "b"]);
    }

    #[test]
    fn json_string_array_defaults_for_non_array() {
        assert!(json_string_array(&json!("not-array")).is_empty());
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
    fn hydra_to_application_handles_missing_fields() {
        let client = json!({"scope": ""});
        let app = hydra_to_application(&client, "tenant-1", "pub-1");
        assert_eq!(app.id, "pub-1");
        assert_eq!(app.tenant_id, "tenant-1");
        assert!(app.name.is_empty());
        assert!(app.redirect_uris.is_empty());
        assert!(app.grant_types.is_empty());
        assert!(app.response_types.is_empty());
        assert!(app.scope.is_empty());
        assert!(app.token_endpoint_auth_method.is_empty());
    }

    #[test]
    fn hydra_to_application_skips_non_string_array_items() {
        let client = json!({
            "redirect_uris": ["https://a", 1, null],
            "grant_types": [true, "authorization_code"],
            "response_types": ["code", {"nested": 1}],
            "scope": "openid profile"
        });
        let app = hydra_to_application(&client, "tenant-1", "pub-1");
        assert_eq!(app.redirect_uris, vec!["https://a"]);
        assert_eq!(app.grant_types, vec!["authorization_code"]);
        assert_eq!(app.response_types, vec!["code"]);
        assert_eq!(app.scope, vec!["openid", "profile"]);
    }

    #[tokio::test]
    async fn hydra_client_as_application_hydra_delegates() {
        let client = Arc::new(HydraClient::new("http://localhost:1", "http://localhost:1").unwrap())
            as Arc<dyn ApplicationHydra>;
        assert!(client.create_oauth2_client(json!({})).await.is_err());
        assert!(client.get_oauth2_client("id").await.is_err());
        assert!(client.update_oauth2_client("id", json!({})).await.is_err());
        assert!(client.delete_oauth2_client("id").await.is_err());
        assert!(client.rotate_client_secret("id").await.is_err());
    }

    #[tokio::test]
    async fn get_application_does_not_return_client_secret() {
        let hydra = StubHydra {
            get_results: Mutex::new(vec![Ok(hydra_client_response())]),
            ..Default::default()
        };
        let mappings = StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = GetApplicationRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, GetApplicationRequest);

        let resp = service
            .get_application(tenant_context("tenant-1"), request)
            .await
            .unwrap()
            .body;

        assert!(resp.client_secret.is_empty());
    }

    #[tokio::test]
    async fn list_applications_does_not_return_client_secret() {
        let hydra = StubHydra {
            get_results: Mutex::new(vec![Ok(hydra_client_response())]),
            ..Default::default()
        };
        let mappings = StubMappings {
            list_public_ids_result: Mutex::new(Some(Ok(vec!["pub-1".into()]))),
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = ListApplicationsRequest::default();
        svc_req!(request, req, ListApplicationsRequest);

        let resp = service
            .list_applications(tenant_context("tenant-1"), request)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.applications.len(), 1);
        assert!(resp.applications[0].client_secret.is_empty());
    }

    #[tokio::test]
    async fn create_application_rejects_http_redirect_uri_by_default() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = CreateApplicationRequest {
            name: "app".into(),
            redirect_uris: vec!["http://a/callback".into()],
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        };
        svc_req!(request, req, CreateApplicationRequest);

        let err = service
            .create_application(admin_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument, "{err:?}");
    }

    #[tokio::test]
    async fn create_application_allows_http_redirect_uri_when_configured() {
        let hydra = StubHydra {
            create_result: Mutex::new(Some(Ok(hydra_client_response()))),
            ..Default::default()
        };
        let mappings = StubMappings {
            create_result: Mutex::new(Some(Ok(mapping_row(
                "tenant-1",
                BACKEND_HYDRA,
                "pub-1",
                "ory-123",
            )))),
            ..Default::default()
        };
        let service = build_service_allow_http(hydra, mappings);

        let req = CreateApplicationRequest {
            name: "app".into(),
            redirect_uris: vec!["http://a/callback".into()],
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        };
        svc_req!(request, req, CreateApplicationRequest);

        let resp = service
            .create_application(admin_context("tenant-1"), request)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.tenant_id, "tenant-1");
    }

    #[tokio::test]
    async fn create_application_rejects_javascript_redirect_uri() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = CreateApplicationRequest {
            name: "app".into(),
            redirect_uris: vec!["javascript://alert(1)".into()],
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        };
        svc_req!(request, req, CreateApplicationRequest);

        let err = service
            .create_application(admin_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument, "{err:?}");
    }

    #[tokio::test]
    async fn create_application_rejects_wildcard_redirect_uri() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = CreateApplicationRequest {
            name: "app".into(),
            redirect_uris: vec!["https://*.example.com/callback".into()],
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        };
        svc_req!(request, req, CreateApplicationRequest);

        let err = service
            .create_application(admin_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument, "{err:?}");
    }

    #[tokio::test]
    async fn create_application_rejects_invalid_token_endpoint_auth_method() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = CreateApplicationRequest {
            name: "app".into(),
            redirect_uris: vec!["https://a/callback".into()],
            token_endpoint_auth_method: "client_secret_jwt".into(),
            ..Default::default()
        };
        svc_req!(request, req, CreateApplicationRequest);

        let err = service
            .create_application(admin_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument, "{err:?}");
    }

    #[tokio::test]
    async fn create_application_requires_admin_scope() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = CreateApplicationRequest::default();
        svc_req!(request, req, CreateApplicationRequest);

        let err = service
            .create_application(no_scope_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
    }

    #[tokio::test]
    async fn get_application_requires_read_scope() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = GetApplicationRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, GetApplicationRequest);

        let err = service
            .get_application(no_scope_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
    }

    #[tokio::test]
    async fn get_application_accepts_admin_scope() {
        let hydra = StubHydra {
            get_results: Mutex::new(vec![Ok(hydra_client_response())]),
            ..Default::default()
        };
        let mappings = StubMappings {
            get_ory_id_results: Mutex::new(vec![Ok("ory-123".into())]),
            ..Default::default()
        };
        let service = build_service(hydra, mappings);

        let req = GetApplicationRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, GetApplicationRequest);

        let resp = service
            .get_application(admin_context("tenant-1"), request)
            .await
            .unwrap()
            .body;

        assert_eq!(resp.id, "pub-1");
    }

    #[tokio::test]
    async fn update_application_requires_admin_scope() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = UpdateApplicationRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, UpdateApplicationRequest);

        let err = service
            .update_application(no_scope_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
    }

    #[tokio::test]
    async fn delete_application_requires_admin_scope() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = DeleteApplicationRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, DeleteApplicationRequest);

        let err = service
            .delete_application(no_scope_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
    }

    #[tokio::test]
    async fn rotate_secret_requires_admin_scope() {
        let service = build_service(StubHydra::default(), StubMappings::default());
        let req = RotateSecretRequest {
            id: "pub-1".into(),
            ..Default::default()
        };
        svc_req!(request, req, RotateSecretRequest);

        let err = service
            .rotate_secret(no_scope_context("tenant-1"), request)
            .await
            .unwrap_err();

        assert_eq!(err.code, connectrpc::ErrorCode::PermissionDenied, "{err:?}");
    }

    #[test]
    fn validate_redirect_uris_accepts_https() {
        assert!(validate_redirect_uris(&["https://example.com/callback".into()], false,).is_ok());
    }

    #[test]
    fn validate_redirect_uris_rejects_http_when_not_allowed() {
        assert!(validate_redirect_uris(&["http://example.com/callback".into()], false,).is_err());
    }

    #[test]
    fn validate_redirect_uris_allows_http_when_allowed() {
        assert!(validate_redirect_uris(&["http://example.com/callback".into()], true,).is_ok());
    }

    #[test]
    fn validate_redirect_uris_allows_http_localhost_without_flag() {
        assert!(
            validate_redirect_uris(&["http://localhost:3000/callback".into()], false,).is_ok()
        );
        assert!(validate_redirect_uris(&["http://localhost/callback".into()], false,).is_ok());
    }

    #[test]
    fn validate_redirect_uris_allows_http_loopback_without_flag() {
        assert!(
            validate_redirect_uris(&["http://127.0.0.1:3000/callback".into()], false,).is_ok()
        );
        assert!(validate_redirect_uris(&["http://[::1]/callback".into()], false,).is_ok());
    }

    #[test]
    fn validate_redirect_uris_rejects_javascript_scheme() {
        assert!(validate_redirect_uris(&["javascript://alert(1)".into()], false,).is_err());
    }

    #[test]
    fn validate_redirect_uris_rejects_wildcard() {
        assert!(
            validate_redirect_uris(&["https://*.example.com/callback".into()], false,).is_err()
        );
    }

    #[test]
    fn validate_token_endpoint_auth_method_accepts_allowed_values() {
        for method in ["client_secret_post", "client_secret_basic", "none"] {
            assert!(validate_token_endpoint_auth_method(method).is_ok());
        }
    }

    #[test]
    fn validate_token_endpoint_auth_method_rejects_invalid_value() {
        assert!(validate_token_endpoint_auth_method("client_secret_jwt").is_err());
    }

    #[test]
    fn validate_token_endpoint_auth_method_allows_empty() {
        assert!(validate_token_endpoint_auth_method("").is_ok());
    }
}
