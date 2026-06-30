use std::sync::Arc;

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use rand::distributions::{Alphanumeric, DistString};
use tracing::instrument;

use crate::db::{TenantApiKeyStore, TenantRow, TenantStore};
use crate::middleware::{TenantId, hash_api_key, require_scope};
use crate::proto::iam::v1::{
    ApiKey, CreateTenantRequest, GetTenantRequest, ListTenantsRequest, ListTenantsResponse,
    RotateApiKeyRequest, Tenant, TenantService,
};
use sunbeam_g2v::error::ServiceError;

const SCOPE_TENANT_ADMIN: &str = "tenant:admin";

#[derive(Clone)]
pub struct TenantServiceImpl {
    repo: Arc<dyn TenantStore>,
    api_keys: Arc<dyn TenantApiKeyStore>,
    #[allow(dead_code)]
    system_tenant_ulid: String,
}

impl TenantServiceImpl {
    pub fn new<R, A>(repo: R, api_keys: A, system_tenant_ulid: String) -> Self
    where
        R: TenantStore + 'static,
        A: TenantApiKeyStore + 'static,
    {
        Self {
            repo: Arc::new(repo) as Arc<dyn TenantStore>,
            api_keys: Arc::new(api_keys) as Arc<dyn TenantApiKeyStore>,
            system_tenant_ulid,
        }
    }
}

#[allow(refining_impl_trait)]
impl TenantService for TenantServiceImpl {
    #[instrument(skip(self, request))]
    async fn create_tenant(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CreateTenantRequest>,
    ) -> ServiceResult<Tenant> {
        let _tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let settings = serde_json::Value::Object(
            req.settings
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect(),
        );
        let row = self
            .repo
            .create(&req.slug, &req.display_name, settings)
            .await?;
        Ok(Response::new(row.into_proto()))
    }

    #[instrument(skip(self, request))]
    async fn get_tenant(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetTenantRequest>,
    ) -> ServiceResult<Tenant> {
        let _tenant_id = require_tenant(&ctx)?;
        let req = request.to_owned_message();
        let row = self.repo.get_by_id(&req.id).await?;
        Ok(Response::new(row.into_proto()))
    }

    #[instrument(skip(self, _request))]
    async fn list_tenants(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListTenantsRequest>,
    ) -> ServiceResult<ListTenantsResponse> {
        let _tenant_id = require_tenant(&ctx)?;
        let rows = self.repo.list().await?;
        let tenants: Vec<Tenant> = rows.into_iter().map(TenantRow::into_proto).collect();
        Ok(Response::new(ListTenantsResponse {
            tenants,
            page: None.into(),
            ..Default::default()
        }))
    }

    #[instrument(skip(self, request))]
    async fn rotate_api_key(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, RotateApiKeyRequest>,
    ) -> ServiceResult<ApiKey> {
        let tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_TENANT_ADMIN)?;
        let req = request.to_owned_message();

        if req.tenant_id != tenant_id {
            return Err(ServiceError::PermissionDenied(
                "cannot rotate api key for a different tenant".into(),
            )
            .into());
        }

        let plaintext = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        let key_hash = hash_api_key(&plaintext);
        let scopes: Vec<String> = req.scopes;
        let expires_at = req.expires_at.as_option().and_then(ts_to_offset);

        let row = self
            .api_keys
            .create(&tenant_id, &req.name, &key_hash, &scopes, expires_at)
            .await?;

        Ok(Response::new(ApiKey {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            scopes: row.scopes,
            plaintext,
            expires_at: None.into(),
            created_at: None.into(),
            __buffa_unknown_fields: Default::default(),
        }))
    }
}

impl TenantRow {
    pub fn into_proto(self) -> Tenant {
        Tenant {
            id: self.id,
            slug: self.slug,
            display_name: self.display_name,
            settings: self
                .settings
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| {
                            let s = match v {
                                serde_json::Value::String(s) => s.clone(),
                                _ => v.to_string(),
                            };
                            (k.clone(), s)
                        })
                        .collect::<std::collections::HashMap<_, _>>()
                })
                .unwrap_or_default(),
            ..Default::default()
        }
    }
}

fn require_tenant(ctx: &RequestContext) -> Result<String, ServiceError> {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .ok_or_else(|| ServiceError::Unauthenticated("missing x-tenant-id".into()))
}

fn ts_to_offset(ts: &buffa_types::google::protobuf::Timestamp) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(ts.seconds)
        .ok()
        .map(|dt| dt + time::Duration::nanoseconds(ts.nanos.into()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use buffa::Message;
    use buffa::bytes::Bytes;
    use buffa::view::MessageView;

    use super::*;
    use crate::db::{DbError, TenantApiKeyRow};
    use crate::middleware::ApiKeyContext;
    use serde_json::json;

    macro_rules! svc_req {
        ($id:ident, $req:expr, $ty:ty) => {
            let bytes = Bytes::from($req.encode_to_vec());
            let view = <$ty as buffa::HasMessageView>::View::decode_view(&bytes).unwrap();
            let $id = ServiceRequest::<$ty>::from_parts(&view, &bytes);
        };
    }

    fn tenant_ctx(tenant_id: &str) -> RequestContext {
        let mut ctx = RequestContext::new(http::HeaderMap::new());
        ctx.extensions_mut().insert(TenantId(tenant_id.into()));
        ctx
    }

    fn admin_ctx(tenant_id: &str) -> RequestContext {
        let mut ctx = tenant_ctx(tenant_id);
        ctx.extensions_mut().insert(ApiKeyContext {
            key_id: "key-1".into(),
            tenant_id: tenant_id.into(),
            scopes: vec![SCOPE_TENANT_ADMIN.into()],
        });
        ctx
    }

    fn ctx_without_scope(tenant_id: &str) -> RequestContext {
        let mut ctx = tenant_ctx(tenant_id);
        ctx.extensions_mut().insert(ApiKeyContext {
            key_id: "key-1".into(),
            tenant_id: tenant_id.into(),
            scopes: vec!["other:scope".into()],
        });
        ctx
    }

    #[derive(Default)]
    struct StubTenantStore {
        next_create: Mutex<Option<Result<TenantRow, DbError>>>,
        next_get: Mutex<Option<Result<TenantRow, DbError>>>,
        next_list: Mutex<Option<Result<Vec<TenantRow>, DbError>>>,
    }

    impl StubTenantStore {
        fn with_create(row: TenantRow) -> Self {
            Self {
                next_create: Mutex::new(Some(Ok(row))),
                ..Default::default()
            }
        }

        fn with_create_err(err: DbError) -> Self {
            Self {
                next_create: Mutex::new(Some(Err(err))),
                ..Default::default()
            }
        }

        fn with_get(row: TenantRow) -> Self {
            Self {
                next_get: Mutex::new(Some(Ok(row))),
                ..Default::default()
            }
        }

        fn with_get_err(err: DbError) -> Self {
            Self {
                next_get: Mutex::new(Some(Err(err))),
                ..Default::default()
            }
        }

        fn with_list(rows: Vec<TenantRow>) -> Self {
            Self {
                next_list: Mutex::new(Some(Ok(rows))),
                ..Default::default()
            }
        }

        fn with_list_err(err: DbError) -> Self {
            Self {
                next_list: Mutex::new(Some(Err(err))),
                ..Default::default()
            }
        }
    }

    #[async_trait]
    impl TenantStore for StubTenantStore {
        async fn create(
            &self,
            slug: &str,
            display_name: &str,
            settings: serde_json::Value,
        ) -> Result<TenantRow, DbError> {
            self.next_create
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Ok(TenantRow {
                        id: "tid".into(),
                        slug: slug.into(),
                        display_name: display_name.into(),
                        is_system: false,
                        settings,
                    })
                })
        }

        async fn get_by_id(&self, id: &str) -> Result<TenantRow, DbError> {
            self.next_get.lock().unwrap().take().unwrap_or_else(|| {
                Ok(TenantRow {
                    id: id.into(),
                    slug: "default".into(),
                    display_name: "Default".into(),
                    is_system: false,
                    settings: serde_json::Value::Object(Default::default()),
                })
            })
        }

        async fn list(&self) -> Result<Vec<TenantRow>, DbError> {
            self.next_list.lock().unwrap().take().unwrap_or_else(|| Ok(vec![]))
        }
    }

    #[derive(Default)]
    struct StubApiKeyStore {
        next_create: Mutex<Option<Result<TenantApiKeyRow, DbError>>>,
    }

    impl StubApiKeyStore {
        fn with_create(row: TenantApiKeyRow) -> Self {
            Self {
                next_create: Mutex::new(Some(Ok(row))),
            }
        }

        fn with_create_err(err: DbError) -> Self {
            Self {
                next_create: Mutex::new(Some(Err(err))),
            }
        }
    }

    #[async_trait]
    impl TenantApiKeyStore for StubApiKeyStore {
        async fn create(
            &self,
            tenant_id: &str,
            name: &str,
            key_hash: &str,
            scopes: &[String],
            expires_at: Option<time::OffsetDateTime>,
        ) -> Result<TenantApiKeyRow, DbError> {
            self.next_create
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    let now = time::OffsetDateTime::now_utc();
                    Ok(TenantApiKeyRow {
                        id: "key-1".into(),
                        tenant_id: tenant_id.into(),
                        key_hash: key_hash.into(),
                        name: name.into(),
                        scopes: scopes.to_vec(),
                        expires_at,
                        created_at: now,
                        updated_at: now,
                    })
                })
        }

        async fn get_by_hash(&self, _key_hash: &str) -> Result<TenantApiKeyRow, DbError> {
            Err(DbError::ApiKeyNotFound)
        }
    }

    #[test]
    fn tenant_row_into_proto_maps_string_settings() {
        let row = TenantRow {
            id: "t1".into(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            is_system: false,
            settings: json!({"domain": "acme.com"}),
        };
        let proto = row.into_proto();
        assert_eq!(proto.id, "t1");
        assert_eq!(proto.slug, "acme");
        assert_eq!(proto.settings.get("domain").unwrap(), "acme.com");
    }

    #[test]
    fn tenant_row_into_proto_stringifies_non_string_settings() {
        let row = TenantRow {
            id: "t1".into(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            is_system: false,
            settings: json!({"enabled": true}),
        };
        let proto = row.into_proto();
        assert_eq!(proto.settings.get("enabled").unwrap(), "true");
    }

    #[test]
    fn tenant_row_into_proto_defaults_empty_settings() {
        let row = TenantRow {
            id: "t1".into(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            is_system: false,
            settings: json!("not-an-object"),
        };
        let proto = row.into_proto();
        assert!(proto.settings.is_empty());
    }

    #[test]
    fn ts_to_offset_maps_timestamp() {
        let ts = buffa_types::google::protobuf::Timestamp {
            seconds: 1_782_648_000,
            nanos: 500_000_000,
            ..Default::default()
        };
        let dt = ts_to_offset(&ts).expect("valid");
        assert_eq!(dt.unix_timestamp(), 1_782_648_000);
    }

    #[test]
    fn ts_to_offset_rejects_invalid_seconds() {
        let ts = buffa_types::google::protobuf::Timestamp {
            seconds: i64::MAX,
            nanos: 0,
            ..Default::default()
        };
        assert!(ts_to_offset(&ts).is_none());
    }

    #[test]
    fn ts_to_offset_zero_and_negative_seconds() {
        let ts = buffa_types::google::protobuf::Timestamp {
            seconds: 0,
            nanos: 0,
            ..Default::default()
        };
        let dt = ts_to_offset(&ts).expect("epoch");
        assert_eq!(dt.unix_timestamp(), 0);

        let ts = buffa_types::google::protobuf::Timestamp {
            seconds: -1,
            nanos: 0,
            ..Default::default()
        };
        let dt = ts_to_offset(&ts).expect("negative");
        assert_eq!(dt.unix_timestamp(), -1);
    }

    #[test]
    fn ts_to_offset_adds_nanos() {
        let ts = buffa_types::google::protobuf::Timestamp {
            seconds: 1_000,
            nanos: 1_000_000,
            ..Default::default()
        };
        let dt = ts_to_offset(&ts).expect("valid");
        assert_eq!(dt.unix_timestamp_nanos(), 1_000_001_000_000);
    }

    #[test]
    fn tenant_row_into_proto_stringifies_numeric_and_null_settings() {
        let row = TenantRow {
            id: "t1".into(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            is_system: false,
            settings: json!({"count": 42, "enabled": null}),
        };
        let proto = row.into_proto();
        assert_eq!(proto.settings.get("count").unwrap(), "42");
        assert_eq!(proto.settings.get("enabled").unwrap(), "null");
    }

    #[test]
    fn tenant_row_into_proto_stringifies_nested_object_settings() {
        let row = TenantRow {
            id: "t1".into(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            is_system: false,
            settings: json!({"theme": {"primary": "blue"}}),
        };
        let proto = row.into_proto();
        assert_eq!(
            proto.settings.get("theme").unwrap(),
            &json!({"primary": "blue"}).to_string()
        );
    }

    #[test]
    fn tenant_row_into_proto_empty_object_becomes_empty_map() {
        let row = TenantRow {
            id: "t1".into(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            is_system: false,
            settings: json!({}),
        };
        let proto = row.into_proto();
        assert!(proto.settings.is_empty());
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

    #[tokio::test]
    async fn create_tenant_happy_path() {
        let service = TenantServiceImpl::new(
            StubTenantStore::with_create(TenantRow {
                id: "tenant-1".into(),
                slug: "acme".into(),
                display_name: "Acme Corp".into(),
                is_system: false,
                settings: json!({"domain": "acme.com"}),
            }),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = tenant_ctx("tenant-1");
        let req_msg = CreateTenantRequest {
            slug: "acme".into(),
            display_name: "Acme Corp".into(),
            settings: [("domain".into(), "acme.com".into())].into_iter().collect(),
            ..Default::default()
        };
        svc_req!(request, req_msg, CreateTenantRequest);
        let response = service.create_tenant(ctx, request).await.unwrap();
        assert_eq!(response.body.id, "tenant-1");
        assert_eq!(response.body.slug, "acme");
        assert_eq!(response.body.display_name, "Acme Corp");
        assert_eq!(response.body.settings.get("domain").unwrap(), "acme.com");
    }

    #[tokio::test]
    async fn create_tenant_requires_tenant() {
        let service = TenantServiceImpl::new(
            StubTenantStore::default(),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = RequestContext::new(http::HeaderMap::new());
        let req_msg = CreateTenantRequest::default();
        svc_req!(request, req_msg, CreateTenantRequest);
        let err: ServiceError = service.create_tenant(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::Unauthenticated(_)));
    }

    #[tokio::test]
    async fn create_tenant_propagates_repo_error() {
        let service = TenantServiceImpl::new(
            StubTenantStore::with_create_err(DbError::TenantNotFound),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = tenant_ctx("tenant-1");
        let req_msg = CreateTenantRequest {
            slug: "acme".into(),
            display_name: "Acme".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, CreateTenantRequest);
        let err: ServiceError = service.create_tenant(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::NotFound(_)));
    }

    #[tokio::test]
    async fn get_tenant_happy_path() {
        let service = TenantServiceImpl::new(
            StubTenantStore::with_get(TenantRow {
                id: "tenant-1".into(),
                slug: "acme".into(),
                display_name: "Acme".into(),
                is_system: false,
                settings: json!({}),
            }),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = tenant_ctx("tenant-1");
        let req_msg = GetTenantRequest {
            id: "tenant-1".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, GetTenantRequest);
        let response = service.get_tenant(ctx, request).await.unwrap();
        assert_eq!(response.body.id, "tenant-1");
    }

    #[tokio::test]
    async fn get_tenant_requires_tenant() {
        let service = TenantServiceImpl::new(
            StubTenantStore::default(),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = RequestContext::new(http::HeaderMap::new());
        let req_msg = GetTenantRequest::default();
        svc_req!(request, req_msg, GetTenantRequest);
        let err: ServiceError = service.get_tenant(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::Unauthenticated(_)));
    }

    #[tokio::test]
    async fn get_tenant_propagates_not_found() {
        let service = TenantServiceImpl::new(
            StubTenantStore::with_get_err(DbError::TenantNotFound),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = tenant_ctx("tenant-1");
        let req_msg = GetTenantRequest {
            id: "missing".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, GetTenantRequest);
        let err: ServiceError = service.get_tenant(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::NotFound(_)));
    }

    #[tokio::test]
    async fn list_tenants_happy_path() {
        let service = TenantServiceImpl::new(
            StubTenantStore::with_list(vec![TenantRow {
                id: "tenant-1".into(),
                slug: "acme".into(),
                display_name: "Acme".into(),
                is_system: false,
                settings: json!({}),
            }]),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = tenant_ctx("tenant-1");
        let req_msg = ListTenantsRequest::default();
        svc_req!(request, req_msg, ListTenantsRequest);
        let response = service.list_tenants(ctx, request).await.unwrap();
        assert_eq!(response.body.tenants.len(), 1);
        assert_eq!(response.body.tenants[0].id, "tenant-1");
    }

    #[tokio::test]
    async fn list_tenants_requires_tenant() {
        let service = TenantServiceImpl::new(
            StubTenantStore::default(),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = RequestContext::new(http::HeaderMap::new());
        let req_msg = ListTenantsRequest::default();
        svc_req!(request, req_msg, ListTenantsRequest);
        let err: ServiceError = service.list_tenants(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::Unauthenticated(_)));
    }

    #[tokio::test]
    async fn list_tenants_propagates_repo_error() {
        let service = TenantServiceImpl::new(
            StubTenantStore::with_list_err(DbError::Sqlx(sqlx::Error::PoolTimedOut)),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = tenant_ctx("tenant-1");
        let req_msg = ListTenantsRequest::default();
        svc_req!(request, req_msg, ListTenantsRequest);
        let err: ServiceError = service.list_tenants(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::Internal(_)));
    }

    #[tokio::test]
    async fn rotate_api_key_happy_path() {
        let service = TenantServiceImpl::new(
            StubTenantStore::default(),
            StubApiKeyStore::with_create(TenantApiKeyRow {
                id: "key-1".into(),
                tenant_id: "tenant-1".into(),
                key_hash: "hash".into(),
                name: "admin-key".into(),
                scopes: vec![SCOPE_TENANT_ADMIN.into()],
                expires_at: None,
                created_at: time::OffsetDateTime::now_utc(),
                updated_at: time::OffsetDateTime::now_utc(),
            }),
            "system".into(),
        );
        let ctx = admin_ctx("tenant-1");
        let req_msg = RotateApiKeyRequest {
            tenant_id: "tenant-1".into(),
            name: "admin-key".into(),
            scopes: vec![SCOPE_TENANT_ADMIN.into()],
            ..Default::default()
        };
        svc_req!(request, req_msg, RotateApiKeyRequest);
        let response = service.rotate_api_key(ctx, request).await.unwrap();
        assert_eq!(response.body.id, "key-1");
        assert_eq!(response.body.tenant_id, "tenant-1");
        assert_eq!(response.body.name, "admin-key");
        assert!(!response.body.plaintext.is_empty());
    }

    #[tokio::test]
    async fn rotate_api_key_requires_tenant() {
        let service = TenantServiceImpl::new(
            StubTenantStore::default(),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = RequestContext::new(http::HeaderMap::new());
        let req_msg = RotateApiKeyRequest::default();
        svc_req!(request, req_msg, RotateApiKeyRequest);
        let err: ServiceError = service.rotate_api_key(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::Unauthenticated(_)));
    }

    #[tokio::test]
    async fn rotate_api_key_requires_admin_scope() {
        let service = TenantServiceImpl::new(
            StubTenantStore::default(),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = ctx_without_scope("tenant-1");
        let req_msg = RotateApiKeyRequest {
            tenant_id: "tenant-1".into(),
            name: "key".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, RotateApiKeyRequest);
        let err: ServiceError = service.rotate_api_key(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn rotate_api_key_rejects_cross_tenant_rotation() {
        let service = TenantServiceImpl::new(
            StubTenantStore::default(),
            StubApiKeyStore::default(),
            "system".into(),
        );
        let ctx = admin_ctx("tenant-1");
        let req_msg = RotateApiKeyRequest {
            tenant_id: "tenant-2".into(),
            name: "key".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, RotateApiKeyRequest);
        let err: ServiceError = service.rotate_api_key(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn rotate_api_key_propagates_repo_error() {
        let service = TenantServiceImpl::new(
            StubTenantStore::default(),
            StubApiKeyStore::with_create_err(DbError::TenantNotFound),
            "system".into(),
        );
        let ctx = admin_ctx("tenant-1");
        let req_msg = RotateApiKeyRequest {
            tenant_id: "tenant-1".into(),
            name: "key".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, RotateApiKeyRequest);
        let err: ServiceError = service.rotate_api_key(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::NotFound(_)));
    }
}
