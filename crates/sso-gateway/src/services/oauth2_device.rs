use std::sync::Arc;

use async_trait::async_trait;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use serde_json::Value;
use sso_ory_client::{error::OryClientError, hydra::HydraClient};
use sunbeam_g2v::error::ServiceError;
use tracing::instrument;

use crate::auth::{AuthContext, SCOPE_APPLICATION_ADMIN, SCOPE_TENANT_ADMIN};
use crate::db::{DbError, IdMappingRepo, IdMappingStore};
use crate::middleware::TenantId;
use crate::proto::iam::v1::{
    DeviceAuthorizationRequest, DeviceAuthorizationResponse, DeviceTokenRequest,
    DeviceTokenResponse, OAuth2DeviceService,
};

const BACKEND_HYDRA: &str = "hydra";

fn map_db_error(err: DbError) -> ServiceError {
    match err {
        DbError::MappingNotFound => ServiceError::NotFound("mapping not found".into()),
        _ => ServiceError::Database(err.to_string()),
    }
}

/// Hydra operations used by the OAuth2 device service.
#[async_trait]
pub trait DeviceHydra: Send + Sync {
    async fn device(
        &self,
        path: String,
        form: Vec<(String, String)>,
    ) -> Result<Value, OryClientError>;
}

#[async_trait]
impl DeviceHydra for HydraClient {
    async fn device(
        &self,
        path: String,
        form: Vec<(String, String)>,
    ) -> Result<Value, OryClientError> {
        self.device(&path, form, None).await
    }
}

#[derive(Clone)]
pub struct OAuth2DeviceServiceImpl {
    hydra: Arc<dyn DeviceHydra>,
    mappings: Arc<dyn IdMappingStore>,
}

impl OAuth2DeviceServiceImpl {
    pub fn new(hydra: Arc<HydraClient>, mappings: IdMappingRepo) -> Self {
        Self {
            hydra: hydra as Arc<dyn DeviceHydra>,
            mappings: Arc::new(mappings) as Arc<dyn IdMappingStore>,
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
            .device(
                "auth".to_string(),
                form.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            )
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
        let value = self
            .hydra
            .device("token".to_string(), form)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_token_to_proto(&value)))
    }
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
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

fn json_i32(value: &Value, key: &str) -> i32 {
    value.get(key).and_then(|v| v.as_i64()).unwrap_or(0) as i32
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
    use crate::db::{DbError, IdMappingRow, IdMappingStore};
    use crate::middleware::TenantId;
    use crate::proto::iam::v1::{
        DeviceAuthorizationRequest, DeviceTokenRequest, OAuth2DeviceService,
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
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl DeviceHydra for FakeHydra {
        async fn device(
            &self,
            path: String,
            form: Vec<(String, String)>,
        ) -> Result<Value, OryClientError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("device(path={path}, form={form:?})"));
            if path == "auth" {
                self.device_auth
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap_or_else(|| Err(OryClientError::MissingTenant))
            } else {
                self.device_token
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap_or_else(|| Err(OryClientError::MissingTenant))
            }
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
            _tenant_id: &str,
            _backend: &str,
            _ory_global_id: &str,
        ) -> Result<String, DbError> {
            unimplemented!()
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
        OAuth2DeviceServiceImpl {
            hydra: Arc::new(hydra),
            mappings: Arc::new(default_mapping_store()),
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
        assert!(call.contains("path=auth"));
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
        assert!(call.contains("path=token"));
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
        assert!(client.device("auth".to_string(), vec![]).await.is_err());
        assert!(client.device("token".to_string(), vec![]).await.is_err());
    }
}
