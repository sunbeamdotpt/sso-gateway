use std::sync::Arc;

use async_trait::async_trait;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sso_ory_client::{error::OryClientError, hydra::HydraClient};
use sunbeam_g2v::error::ServiceError;
use tracing::instrument;

use crate::auth::{AuthContext, SCOPE_APPLICATION_ADMIN, SCOPE_TENANT_ADMIN};
use crate::db::{
    DbError, IdMappingRepo, IdMappingStore, TOKEN_TYPE_DEVICE_CHALLENGE, TransientTokenRepo,
    TransientTokenStore,
};
use crate::middleware::TenantId;
use crate::proto::iam::v1::{
    AcceptDeviceVerificationRequest, AcceptDeviceVerificationResponse, DeviceAuthorizationRequest,
    DeviceAuthorizationResponse, DeviceTokenRequest, DeviceTokenResponse,
    GetDeviceVerificationRequest, GetDeviceVerificationResponse, OAuth2DeviceService,
};

const BACKEND_HYDRA: &str = "hydra";

fn map_db_error(err: DbError) -> ServiceError {
    match err {
        DbError::MappingNotFound => ServiceError::NotFound("mapping not found".into()),
        _ => ServiceError::Database(err.to_string()),
    }
}

fn transient_expiry() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::hours(1)
}

/// Hydra operations used by the OAuth2 device service.
#[async_trait]
pub trait DeviceHydra: Send + Sync {
    async fn device_authorize(&self, form: Vec<(String, String)>) -> Result<Value, OryClientError>;

    /// Poll the standard token endpoint with the device-code grant (RFC 8628
    /// §3.4 — there is no dedicated device token endpoint).
    async fn token(&self, form: Vec<(String, String)>) -> Result<Value, OryClientError>;

    async fn get_device_verify(
        &self,
        query: Vec<(String, String)>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError>;

    async fn accept_device_verification(
        &self,
        challenge: &str,
        user_code: &str,
    ) -> Result<Value, OryClientError>;
}

#[async_trait]
impl DeviceHydra for HydraClient {
    async fn device_authorize(&self, form: Vec<(String, String)>) -> Result<Value, OryClientError> {
        self.device("auth", form, None).await
    }

    async fn token(&self, form: Vec<(String, String)>) -> Result<Value, OryClientError> {
        self.token(form, None).await
    }

    async fn get_device_verify(
        &self,
        query: Vec<(String, String)>,
        cookie: Option<&str>,
    ) -> Result<Value, OryClientError> {
        self.get_device_verify(query, cookie).await
    }

    async fn accept_device_verification(
        &self,
        challenge: &str,
        user_code: &str,
    ) -> Result<Value, OryClientError> {
        self.accept_device_verification(challenge, user_code).await
    }
}

#[derive(Clone)]
pub struct OAuth2DeviceServiceImpl {
    hydra: Arc<dyn DeviceHydra>,
    mappings: Arc<dyn IdMappingStore>,
    transient: Arc<dyn TransientTokenStore>,
}

impl OAuth2DeviceServiceImpl {
    pub fn new(
        hydra: Arc<HydraClient>,
        mappings: IdMappingRepo,
        transient: TransientTokenRepo,
    ) -> Self {
        Self {
            hydra: hydra as Arc<dyn DeviceHydra>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
            transient: Arc::new(transient) as Arc<dyn TransientTokenStore>,
        }
    }
}

fn require_device_admin(ctx: &RequestContext) -> Result<(), ServiceError> {
    if require_scope(ctx, SCOPE_TENANT_ADMIN).is_ok()
        || require_scope(ctx, SCOPE_APPLICATION_ADMIN).is_ok()
    {
        return Ok(());
    }
    Err(ServiceError::PermissionDenied(
        "missing required scope: tenant:admin or application:admin".into(),
    ))
}

fn require_scope(ctx: &RequestContext, scope: &str) -> Result<(), ServiceError> {
    let auth = ctx
        .extensions()
        .get::<AuthContext>()
        .ok_or_else(|| ServiceError::Unauthenticated("missing authentication context".into()))?;
    if !auth.scopes.iter().any(|s| s == scope) {
        return Err(ServiceError::PermissionDenied(format!(
            "missing required scope: {scope}"
        )));
    }
    Ok(())
}

fn require_tenant(ctx: &RequestContext) -> Result<String, ServiceError> {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .ok_or_else(|| ServiceError::Unauthenticated("missing tenant".into()))
}

impl OAuth2DeviceServiceImpl {
    async fn ory_client_id(
        &self,
        tenant_id: &str,
        public_client_id: &str,
    ) -> Result<String, ServiceError> {
        if public_client_id.is_empty() {
            return Ok(String::new());
        }
        self.mappings
            .get_ory_id(tenant_id, BACKEND_HYDRA, public_client_id)
            .await
            .map_err(map_db_error)
    }

    /// Resolve a device challenge supplied by the caller to the Hydra
    /// challenge Hydra expects.
    ///
    /// Challenges minted by [`Self::get_device_verification`] are looked up in
    /// the transient token store. Hydra's raw challenge is also delivered to
    /// the verification app via the `device_challenge` query parameter of
    /// Hydra's redirect, in which case there is no mapping to resolve — on a
    /// lookup miss the value is passed through unchanged. Hydra still
    /// validates the challenge cryptographically, so passthrough is safe. This
    /// mirrors the login/consent challenge passthrough.
    async fn resolve_device_challenge(
        &self,
        tenant_id: &str,
        challenge: &str,
    ) -> Result<String, ServiceError> {
        match self
            .transient
            .get_ory_token(
                tenant_id,
                BACKEND_HYDRA,
                TOKEN_TYPE_DEVICE_CHALLENGE,
                challenge,
            )
            .await
        {
            Ok(ory) => Ok(ory),
            Err(DbError::MappingNotFound) => Ok(challenge.to_string()),
            Err(err) => Err(map_db_error(err)),
        }
    }

    /// Replace the backend `client_id` embedded in Hydra's `redirect_to` with
    /// the gateway's public client id, so the browser never sees it.
    async fn public_redirect_to(
        &self,
        tenant_id: &str,
        redirect_to: &str,
    ) -> Result<String, ServiceError> {
        let Ok(mut url) = url::Url::parse(redirect_to) else {
            return Err(ServiceError::Internal(
                "invalid redirect_to from upstream".into(),
            ));
        };
        let ory_client_id = url
            .query_pairs()
            .find(|(k, _)| k == "client_id")
            .map(|(_, v)| v.into_owned());
        let Some(ory_client_id) = ory_client_id else {
            return Ok(redirect_to.to_string());
        };
        let public_id = self
            .mappings
            .get_public_id(tenant_id, BACKEND_HYDRA, &ory_client_id)
            .await
            .map_err(map_db_error)?;
        let query: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| {
                if k == "client_id" {
                    (k.into_owned(), public_id.clone())
                } else {
                    (k.into_owned(), v.into_owned())
                }
            })
            .collect();
        url.set_query(None);
        url.query_pairs_mut().extend_pairs(query);
        Ok(url.to_string())
    }
}

#[allow(refining_impl_trait)]
impl OAuth2DeviceService for OAuth2DeviceServiceImpl {
    #[instrument(skip(self, request))]
    async fn authorize_device(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeviceAuthorizationRequest>,
    ) -> ServiceResult<DeviceAuthorizationResponse> {
        require_device_admin(&ctx)?;
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let ory_client_id = self.ory_client_id(&tenant_id, &req.client_id).await?;
        let mut form = vec![("client_id", ory_client_id)];
        if !req.scope.is_empty() {
            form.push(("scope", req.scope.join(" ")));
        }
        let value = self
            .hydra
            .device_authorize(form.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_device_auth_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn get_device_token(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DeviceTokenRequest>,
    ) -> ServiceResult<DeviceTokenResponse> {
        require_device_admin(&ctx)?;
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let ory_client_id = self.ory_client_id(&tenant_id, &req.client_id).await?;
        let form = vec![
            (
                "grant_type".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ),
            ("client_id".to_string(), ory_client_id),
            ("device_code".to_string(), req.device_code),
        ];
        let value = self.hydra.token(form).await.map_err(map_ory_error)?;
        Ok(Response::new(ory_token_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn get_device_verification(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetDeviceVerificationRequest>,
    ) -> ServiceResult<GetDeviceVerificationResponse> {
        require_device_admin(&ctx)?;
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let query = vec![("user_code".to_string(), req.user_code.clone())];
        let err = match self.hydra.get_device_verify(query, None).await {
            Ok(_) => {
                return Err(ServiceError::Internal(
                    "unexpected upstream response for device verification".into(),
                )
                .into());
            }
            Err(err) => err,
        };
        let OryClientError::Redirect {
            location,
            set_cookies,
        } = err
        else {
            return Err(map_ory_error(err).into());
        };
        let ory_challenge = device_challenge_from_location(&location)?;
        let public_challenge = self
            .transient
            .create(
                &tenant_id,
                BACKEND_HYDRA,
                TOKEN_TYPE_DEVICE_CHALLENGE,
                &ory_challenge,
                transient_expiry(),
            )
            .await
            .map_err(map_db_error)?;
        let mut response = Response::new(GetDeviceVerificationResponse {
            challenge: public_challenge,
            user_code: req.user_code,
            ..Default::default()
        });
        for cookie in set_cookies {
            if let Ok(value) = http::HeaderValue::from_str(&cookie) {
                response.headers.append("set-cookie", value);
            }
        }
        Ok(response)
    }

    #[instrument(skip(self, request))]
    async fn accept_device_verification(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AcceptDeviceVerificationRequest>,
    ) -> ServiceResult<AcceptDeviceVerificationResponse> {
        require_device_admin(&ctx)?;
        let tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let ory_challenge = self
            .resolve_device_challenge(&tenant_id, &req.challenge)
            .await?;
        let value = self
            .hydra
            .accept_device_verification(&ory_challenge, &req.user_code)
            .await
            .map_err(map_ory_error)?;
        let redirect_to = json_str(&value, "redirect_to");
        let redirect_to = self.public_redirect_to(&tenant_id, &redirect_to).await?;
        Ok(Response::new(AcceptDeviceVerificationResponse {
            redirect_to,
            ..Default::default()
        }))
    }
}

/// Extract the `device_challenge` query parameter from Hydra's redirect
/// location.
fn device_challenge_from_location(location: &str) -> Result<String, ServiceError> {
    let url = url::Url::parse(location)
        .map_err(|_| ServiceError::Internal("invalid redirect location from upstream".into()))?;
    url.query_pairs()
        .find(|(k, _)| k == "device_challenge")
        .map(|(_, v)| v.into_owned())
        .ok_or_else(|| {
            ServiceError::Internal("upstream redirect is missing device_challenge".into())
        })
}

fn ory_device_auth_to_proto(value: &Value) -> DeviceAuthorizationResponse {
    DeviceAuthorizationResponse {
        device_code: json_str(value, "device_code"),
        user_code: json_str(value, "user_code"),
        verification_uri: json_str(value, "verification_uri"),
        verification_uri_complete: json_str(value, "verification_uri_complete"),
        expires_in: json_i32(value, "expires_in"),
        interval: json_i32(value, "interval"),
        ..Default::default()
    }
}

fn ory_token_to_proto(value: &Value) -> DeviceTokenResponse {
    DeviceTokenResponse {
        access_token: json_str(value, "access_token"),
        token_type: json_str(value, "token_type"),
        expires_in: json_i32(value, "expires_in"),
        refresh_token: json_str(value, "refresh_token"),
        scope: json_str(value, "scope"),
        id_token: json_str(value, "id_token"),
        ..Default::default()
    }
}

fn json_str(value: &Value, key: &str) -> String {
    match value.get(key).and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => String::new(),
    }
}

fn json_i32(value: &Value, key: &str) -> i32 {
    match value.get(key).and_then(|v| v.as_i64()) {
        Some(n) => n as i32,
        None => 0,
    }
}

fn map_ory_error(err: OryClientError) -> ServiceError {
    use sso_ory_client::error::OryClientError;
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
        OryClientError::Http(_) | OryClientError::Url(_) => {
            ServiceError::Unavailable("upstream identity service unreachable".into())
        }
        OryClientError::Serialization(_) | OryClientError::InvalidResponse(_) => {
            ServiceError::Internal("invalid upstream response".into())
        }
        OryClientError::MissingTenant => ServiceError::Unauthenticated("missing tenant".into()),
        OryClientError::Redirect { .. } => ServiceError::Internal("unexpected redirect".into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::SubjectType;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use buffa::{HasMessageView, Message, MessageView, bytes::Bytes};
    use connectrpc::{ErrorCode, RequestContext, ServiceRequest};
    use http::HeaderMap;
    use serde_json::{Value, json};
    use sso_ory_client::{error::OryClientError, hydra::HydraClient};
    use sunbeam_g2v::error::ServiceError;
    use ulid::Ulid;

    use crate::auth::{AuthContext, SCOPE_APPLICATION_ADMIN, SCOPE_TENANT_ADMIN};
    use crate::db::{
        DbError, IdMappingRow, IdMappingStore, TOKEN_TYPE_DEVICE_CHALLENGE, TransientTokenRow,
        TransientTokenStore,
    };
    use crate::middleware::TenantId;
    use crate::proto::iam::v1::{
        AcceptDeviceVerificationRequest, DeviceAuthorizationRequest, DeviceTokenRequest,
        GetDeviceVerificationRequest, OAuth2DeviceService,
    };

    use super::{DeviceHydra, OAuth2DeviceServiceImpl, map_ory_error};

    fn service_request<Req>(msg: Req) -> ServiceRequest<'static, Req>
    where
        Req: Message + HasMessageView,
    {
        let bytes = Bytes::from(msg.encode_to_vec());
        let bytes: &'static Bytes = Box::leak(Box::new(bytes));
        let view = Req::View::decode_view(bytes).unwrap();
        let view: &'static Req::View<'static> = Box::leak(Box::new(view));
        ServiceRequest::from_parts(view, bytes)
    }

    fn auth_context(scopes: &[&str]) -> RequestContext {
        let mut ctx = RequestContext::new(HeaderMap::new());
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: "tenant-1".into(),
            subject: "subject-1".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            token_hash: "hash".into(),
            authentication_methods: Vec::new(),
        });
        ctx.extensions_mut().insert(TenantId("tenant-1".into()));
        ctx
    }

    #[derive(Default, Clone)]
    struct FakeHydra {
        device_auth: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
        device_token: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
        device_verify: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
        device_accept: Arc<Mutex<Option<Result<Value, OryClientError>>>>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl DeviceHydra for FakeHydra {
        async fn device_authorize(
            &self,
            form: Vec<(String, String)>,
        ) -> Result<Value, OryClientError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("device_authorize(form={form:?})"));
            self.device_auth
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }

        async fn token(&self, form: Vec<(String, String)>) -> Result<Value, OryClientError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("token(form={form:?})"));
            self.device_token
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }

        async fn get_device_verify(
            &self,
            query: Vec<(String, String)>,
            cookie: Option<&str>,
        ) -> Result<Value, OryClientError> {
            self.calls.lock().unwrap().push(format!(
                "get_device_verify(query={query:?}, cookie={cookie:?})"
            ));
            self.device_verify
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }

        async fn accept_device_verification(
            &self,
            challenge: &str,
            user_code: &str,
        ) -> Result<Value, OryClientError> {
            self.calls.lock().unwrap().push(format!(
                "accept_device_verification(challenge={challenge}, user_code={user_code})"
            ));
            self.device_accept
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(OryClientError::MissingTenant))
        }
    }

    #[derive(Default)]
    struct StubTransientTokenStore {
        rows: Mutex<Vec<TransientTokenRow>>,
    }

    impl StubTransientTokenStore {
        fn seed(&self, public_token: &str, ory_token: &str) {
            self.rows.lock().unwrap().push(TransientTokenRow {
                id: Ulid::new().to_string(),
                tenant_id: "tenant-1".to_string(),
                backend: super::BACKEND_HYDRA.to_string(),
                token_type: TOKEN_TYPE_DEVICE_CHALLENGE.to_string(),
                public_token: public_token.to_string(),
                ory_token: ory_token.to_string(),
                expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
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
            _backend: &str,
            _token_type: &str,
            _ory_token: &str,
        ) -> Result<String, DbError> {
            unimplemented!()
        }

        async fn delete(&self, _tenant_id: &str, _public_token: &str) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn get_ory_token_global(
            &self,
            _backend: &str,
            _token_type: &str,
            _public_token: &str,
        ) -> Result<(String, String), DbError> {
            unimplemented!()
        }
    }

    #[derive(Default, Clone)]
    struct StubMappingStore {
        rows: Arc<Mutex<Vec<IdMappingRow>>>,
    }

    impl StubMappingStore {
        fn with_mapping(
            &self,
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
            self.rows.lock().unwrap().push(row);
            Self {
                rows: Arc::new(Mutex::new(std::mem::take(&mut *self.rows.lock().unwrap()))),
            }
        }
    }

    #[async_trait]
    impl IdMappingStore for StubMappingStore {
        async fn create(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
            _ory_global_id: &str,
        ) -> Result<IdMappingRow, DbError> {
            unimplemented!()
        }

        async fn get_ory_id(
            &self,
            tenant_id: &str,
            backend: &str,
            public_id: &str,
        ) -> Result<String, DbError> {
            self.rows
                .lock()
                .unwrap()
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
                .unwrap()
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
            _tenant_id: &str,
            _backend: &str,
            _public_id: &str,
        ) -> Result<(), DbError> {
            unimplemented!()
        }

        async fn list_public_ids(
            &self,
            _tenant_id: &str,
            _backend: &str,
        ) -> Result<Vec<String>, DbError> {
            unimplemented!()
        }

        async fn get_tenant_id_by_ory_id(
            &self,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<Option<String>, DbError> {
            Ok(None)
        }
    }

    fn default_mapping_store() -> StubMappingStore {
        StubMappingStore::default().with_mapping(
            "tenant-1",
            super::BACKEND_HYDRA,
            "pub-client-1",
            "client-1",
        )
    }

    fn service(hydra: FakeHydra) -> OAuth2DeviceServiceImpl {
        service_with_transient(hydra, StubTransientTokenStore::default())
    }

    fn service_with_transient(
        hydra: FakeHydra,
        transient: StubTransientTokenStore,
    ) -> OAuth2DeviceServiceImpl {
        OAuth2DeviceServiceImpl {
            hydra: Arc::new(hydra),
            mappings: Arc::new(default_mapping_store()),
            transient: Arc::new(transient),
        }
    }

    #[tokio::test]
    async fn authorize_device_happy_path() {
        let fake = FakeHydra {
            device_auth: Arc::new(Mutex::new(Some(Ok(json!({
                "device_code": "device-1",
                "user_code": "user-1",
                "verification_uri": "https://gateway.example.com/device",
                "verification_uri_complete": "https://gateway.example.com/device?user_code=user-1",
                "expires_in": 600,
                "interval": 5,
            }))))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let req = service_request(DeviceAuthorizationRequest {
            client_id: "pub-client-1".to_string(),
            scope: vec!["openid".to_string(), "profile".to_string()],
            ..Default::default()
        });

        let resp = svc
            .authorize_device(auth_context(&[SCOPE_TENANT_ADMIN]), req)
            .await
            .unwrap();
        assert_eq!(resp.body.device_code, "device-1");
        assert_eq!(resp.body.user_code, "user-1");
        assert_eq!(resp.body.expires_in, 600);
        assert_eq!(resp.body.interval, 5);
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
        let call = &fake.calls.lock().unwrap()[0];
        assert!(call.contains("device_authorize("));
        assert!(call.contains(r#"("client_id", "client-1")"#));
        assert!(call.contains("scope"));
    }

    #[tokio::test]
    async fn authorize_device_rejects_missing_scope() {
        let fake = FakeHydra::default();
        let svc = service(fake);
        let ctx = RequestContext::new(HeaderMap::new());
        let req = service_request(DeviceAuthorizationRequest::default());

        let err = svc.authorize_device(ctx, req).await.unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn authorize_device_error_path() {
        let fake = FakeHydra {
            device_auth: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 400,
                message: "invalid client".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let req = service_request(DeviceAuthorizationRequest::default());

        let err = svc
            .authorize_device(auth_context(&[SCOPE_APPLICATION_ADMIN]), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn get_device_token_happy_path() {
        let fake = FakeHydra {
            device_token: Arc::new(Mutex::new(Some(Ok(json!({
                "access_token": "access-1",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-1",
                "scope": "openid profile",
                "id_token": "id-1",
            }))))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let req = service_request(DeviceTokenRequest {
            client_id: "pub-client-1".to_string(),
            device_code: "device-1".to_string(),
            ..Default::default()
        });

        let resp = svc
            .get_device_token(auth_context(&[SCOPE_APPLICATION_ADMIN]), req)
            .await
            .unwrap();
        assert_eq!(resp.body.access_token, "access-1");
        assert_eq!(resp.body.token_type, "Bearer");
        assert_eq!(resp.body.expires_in, 3600);
        assert_eq!(resp.body.refresh_token, "refresh-1");
        assert_eq!(resp.body.scope, "openid profile");
        assert_eq!(resp.body.id_token, "id-1");
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
        let call = &fake.calls.lock().unwrap()[0];
        assert!(call.contains("token("));
        assert!(call.contains("grant_type"));
        assert!(call.contains(r#"("client_id", "client-1")"#));
    }

    #[tokio::test]
    async fn get_device_token_rejects_missing_scope() {
        let fake = FakeHydra::default();
        let svc = service(fake);
        let req = service_request(DeviceTokenRequest::default());

        let err = svc
            .get_device_token(RequestContext::new(HeaderMap::new()), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn get_device_token_error_path() {
        let fake = FakeHydra {
            device_token: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 401,
                message: "unauthorized".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let req = service_request(DeviceTokenRequest::default());

        let err = svc
            .get_device_token(auth_context(&[SCOPE_TENANT_ADMIN]), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Unauthenticated);
    }

    #[test]
    fn map_ory_error_status_codes() {
        let cases = vec![
            (400, "InvalidArgument"),
            (401, "Unauthenticated"),
            (403, "PermissionDenied"),
            (404, "NotFound"),
            (409, "AlreadyExists"),
            (503, "Unavailable"),
            (500, "Internal"),
        ];
        for (status, expected) in cases {
            let err = map_ory_error(OryClientError::Ory {
                status,
                message: "msg".into(),
            });
            let name = format!("{err:?}");
            assert!(
                name.contains(expected),
                "status {status} should map to {expected}, got {name}"
            );
        }
    }

    #[test]
    fn map_ory_error_transport_and_serialization() {
        let http = map_ory_error(OryClientError::Http(
            reqwest::Client::new().get("not-a-url").build().unwrap_err(),
        ));
        let url = map_ory_error(OryClientError::Url(
            reqwest::Url::parse("not a url").unwrap_err(),
        ));
        let ser = map_ory_error(OryClientError::Serialization(
            serde_json::from_str::<serde_json::Value>("not json").unwrap_err(),
        ));
        let missing = map_ory_error(OryClientError::MissingTenant);

        assert!(matches!(http, ServiceError::Unavailable(_)));
        assert!(matches!(url, ServiceError::Unavailable(_)));
        assert!(matches!(ser, ServiceError::Internal(_)));
        assert!(matches!(missing, ServiceError::Unauthenticated(_)));
    }

    #[tokio::test]
    async fn hydra_client_as_device_hydra_delegates() {
        let client = Arc::new(HydraClient::new("http://localhost:1", "http://localhost:1").unwrap())
            as Arc<dyn DeviceHydra>;
        assert!(client.device_authorize(vec![]).await.is_err());
        assert!(client.token(vec![]).await.is_err());
        assert!(client.get_device_verify(vec![], None).await.is_err());
        assert!(
            client
                .accept_device_verification("challenge", "code")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn get_device_verification_mints_public_challenge_and_forwards_cookies() {
        let fake = FakeHydra {
            device_verify: Arc::new(Mutex::new(Some(Err(OryClientError::Redirect {
                location: "https://login.example.com/device?device_challenge=ory-challenge-1&user_code=ABCD-EFGH".into(),
                set_cookies: vec!["ory_hydra_device_csrf=csrf; Path=/; HttpOnly".into()],
            })))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let req = service_request(GetDeviceVerificationRequest {
            user_code: "ABCD-EFGH".to_string(),
            ..Default::default()
        });

        let resp = svc
            .get_device_verification(auth_context(&[SCOPE_TENANT_ADMIN]), req)
            .await
            .unwrap();
        assert_eq!(resp.body.user_code, "ABCD-EFGH");
        // The public challenge must be an opaque ULID, not Hydra's raw value.
        assert_ne!(resp.body.challenge, "ory-challenge-1");
        Ulid::from_string(&resp.body.challenge).expect("public challenge is a ULID");
        let cookies: Vec<_> = resp.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 1);
        assert!(
            cookies[0]
                .to_str()
                .unwrap()
                .starts_with("ory_hydra_device_csrf=")
        );
        let call = &fake.calls.lock().unwrap()[0];
        assert!(call.contains(r#"("user_code", "ABCD-EFGH")"#));
    }

    #[tokio::test]
    async fn get_device_verification_rejects_missing_scope() {
        let svc = service(FakeHydra::default());
        let req = service_request(GetDeviceVerificationRequest::default());
        let err = svc
            .get_device_verification(RequestContext::new(HeaderMap::new()), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn get_device_verification_maps_upstream_error() {
        let fake = FakeHydra {
            device_verify: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 400,
                message: "invalid user code".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let req = service_request(GetDeviceVerificationRequest::default());
        let err = svc
            .get_device_verification(auth_context(&[SCOPE_APPLICATION_ADMIN]), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn get_device_verification_rejects_redirect_without_challenge() {
        let fake = FakeHydra {
            device_verify: Arc::new(Mutex::new(Some(Err(OryClientError::Redirect {
                location: "https://login.example.com/device".into(),
                set_cookies: vec![],
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let req = service_request(GetDeviceVerificationRequest::default());
        let err = svc
            .get_device_verification(auth_context(&[SCOPE_TENANT_ADMIN]), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Internal);
    }

    #[tokio::test]
    async fn accept_device_verification_resolves_public_challenge_and_rewrites_client_id() {
        let transient = StubTransientTokenStore::default();
        transient.seed("pub-challenge-1", "ory-challenge-1");
        let fake = FakeHydra {
            device_accept: Arc::new(Mutex::new(Some(Ok(json!({
                "redirect_to": "https://gateway.example.com/oauth2/device/verify?device_verifier=v1&client_id=client-1",
            }))))),
            ..Default::default()
        };
        let svc = service_with_transient(fake.clone(), transient);
        let req = service_request(AcceptDeviceVerificationRequest {
            challenge: "pub-challenge-1".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            ..Default::default()
        });

        let resp = svc
            .accept_device_verification(auth_context(&[SCOPE_TENANT_ADMIN]), req)
            .await
            .unwrap();
        // Hydra saw the resolved raw challenge, and the browser-facing URL
        // carries the public client id, never the backend one.
        assert!(fake.calls.lock().unwrap()[0].contains("challenge=ory-challenge-1"));
        assert!(resp.body.redirect_to.contains("device_verifier=v1"));
        assert!(resp.body.redirect_to.contains("client_id=pub-client-1"));
        assert!(!resp.body.redirect_to.contains("client_id=client-1&"));
        assert!(!resp.body.redirect_to.contains("client_id=client-1"));
    }

    #[tokio::test]
    async fn accept_device_verification_passes_through_raw_challenge() {
        let fake = FakeHydra {
            device_accept: Arc::new(Mutex::new(Some(Ok(json!({
                "redirect_to": "https://gateway.example.com/oauth2/device/verify?device_verifier=v1",
            }))))),
            ..Default::default()
        };
        let svc = service(fake.clone());
        let req = service_request(AcceptDeviceVerificationRequest {
            challenge: "raw-hydra-challenge".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            ..Default::default()
        });

        let resp = svc
            .accept_device_verification(auth_context(&[SCOPE_APPLICATION_ADMIN]), req)
            .await
            .unwrap();
        assert!(fake.calls.lock().unwrap()[0].contains("challenge=raw-hydra-challenge"));
        assert!(resp.body.redirect_to.contains("device_verifier=v1"));
    }

    #[tokio::test]
    async fn accept_device_verification_rejects_missing_scope() {
        let svc = service(FakeHydra::default());
        let req = service_request(AcceptDeviceVerificationRequest::default());
        let err = svc
            .accept_device_verification(RequestContext::new(HeaderMap::new()), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
    }

    #[tokio::test]
    async fn accept_device_verification_maps_upstream_error() {
        let fake = FakeHydra {
            device_accept: Arc::new(Mutex::new(Some(Err(OryClientError::Ory {
                status: 400,
                message: "user code expired".into(),
            })))),
            ..Default::default()
        };
        let svc = service(fake);
        let req = service_request(AcceptDeviceVerificationRequest {
            challenge: "raw-hydra-challenge".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            ..Default::default()
        });
        let err = svc
            .accept_device_verification(auth_context(&[SCOPE_TENANT_ADMIN]), req)
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }
}
