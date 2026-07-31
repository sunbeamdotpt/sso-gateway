use std::sync::Arc;

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use tracing::instrument;

use crate::auth::{AuthContext, SCOPE_TENANT_ADMIN, SCOPE_TENANT_READ, require_scope};
use crate::db::{TenantRow, TenantStore};
use crate::middleware::TenantId;
use crate::proto::iam::v1::{
    CreateTenantRequest, GetTenantRequest, ListTenantsRequest, ListTenantsResponse, Tenant,
    TenantService,
};
use crate::services::entitlement::EntitlementService;
use sunbeam_g2v::error::ServiceError;

#[derive(Clone)]
pub struct TenantServiceImpl {
    repo: Arc<dyn TenantStore>,
    #[allow(dead_code)]
    system_tenant_ulid: String,
    entitlements: Arc<dyn EntitlementService>,
}

impl TenantServiceImpl {
    pub fn new<R>(repo: R, system_tenant_ulid: String, entitlements: Arc<dyn EntitlementService>) -> Self
    where
        R: TenantStore + 'static,
    {
        Self {
            repo: Arc::new(repo) as Arc<dyn TenantStore>,
            system_tenant_ulid,
            entitlements,
        }
    }

    fn is_system_tenant(&self, ctx: &RequestContext) -> bool {
        match ctx.extensions().get::<AuthContext>() {
            Some(auth) => auth.tenant_id == self.system_tenant_ulid,
            None => false,
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
        let caller_tenant_id = require_tenant(&ctx)?;
        require_scope(&ctx, SCOPE_TENANT_ADMIN)?;
        if caller_tenant_id != self.system_tenant_ulid {
            return Err(ServiceError::PermissionDenied(
                "only the system tenant can create tenants".into(),
            )
            .into());
        }
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
        self.entitlements.ensure_namespace(&row.id).await?;
        Ok(Response::new(row.into_proto()))
    }

    #[instrument(skip(self, request))]
    async fn get_tenant(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, GetTenantRequest>,
    ) -> ServiceResult<Tenant> {
        let caller_tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_TENANT_READ, SCOPE_TENANT_ADMIN])?;
        let req = request.to_owned_message();
        if req.id != caller_tenant_id && !self.is_system_tenant(&ctx) {
            return Err(ServiceError::PermissionDenied("cannot access tenant".into()).into());
        }
        let row = self.repo.get_by_id(&req.id).await?;
        Ok(Response::new(row.into_proto()))
    }

    #[instrument(skip(self, _request))]
    async fn list_tenants(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, ListTenantsRequest>,
    ) -> ServiceResult<ListTenantsResponse> {
        let caller_tenant_id = require_tenant(&ctx)?;
        require_scope_any(&ctx, &[SCOPE_TENANT_READ, SCOPE_TENANT_ADMIN])?;
        let rows = self.repo.list().await?;
        let tenants: Vec<Tenant> = if self.is_system_tenant(&ctx) {
            rows.into_iter().map(TenantRow::into_proto).collect()
        } else {
            rows.into_iter()
                .filter(|r| r.id == caller_tenant_id)
                .map(TenantRow::into_proto)
                .collect()
        };
        Ok(Response::new(ListTenantsResponse {
            tenants,
            page: None.into(),
            ..Default::default()
        }))
    }
}

impl TenantRow {
    pub fn into_proto(self) -> Tenant {
        Tenant {
            id: self.id,
            slug: self.slug,
            display_name: self.display_name,
            settings: match self.settings.as_object() {
                Some(m) => m
                    .iter()
                    .map(|(k, v)| {
                        let s = match v {
                            serde_json::Value::String(s) => s.clone(),
                            _ => v.to_string(),
                        };
                        (k.clone(), s)
                    })
                    .collect::<std::collections::HashMap<_, _>>(),
                None => std::collections::HashMap::new(),
            },
            ..Default::default()
        }
    }
}

fn require_tenant(ctx: &RequestContext) -> Result<String, ServiceError> {
    ctx.extensions()
        .get::<TenantId>()
        .map(|t| t.0.clone())
        .or_else(|| {
            ctx.extensions()
                .get::<AuthContext>()
                .map(|a| a.tenant_id.clone())
        })
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

#[cfg(test)]
mod tests {
    use crate::auth::SubjectType;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use buffa::Message;
    use buffa::bytes::Bytes;
    use buffa::view::MessageView;
    use serde_json::{Value, json};

    use super::*;
    use crate::db::DbError;
    use crate::services::entitlement::{EntitlementLevel, EntitlementService};

    #[derive(Default, Clone)]
    struct NoopEntitlementService;

    #[async_trait]
    impl EntitlementService for NoopEntitlementService {
        async fn ensure_namespace(&self, _tenant_id: &str) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn seed_application(
            &self,
            _tenant_id: &str,
            _app_public_id: &str,
            _groups: &[String],
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn remove_application(
            &self,
            _tenant_id: &str,
            _app_public_id: &str,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn check(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _app_public_id: &str,
            _relation: &str,
        ) -> Result<bool, ServiceError> {
            Ok(true)
        }

        async fn effective_scope_ceiling(&self, _tenant_id: &str, _identity_id: &str) -> Vec<String> {
            vec![]
        }

        async fn grant(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _app_public_id: &str,
            _level: EntitlementLevel,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn revoke(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _app_public_id: &str,
            _level: EntitlementLevel,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn set_group_membership(
            &self,
            _tenant_id: &str,
            _group_name: &str,
            _identity_id: &str,
            _member: bool,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn remove_all_for_identity(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn mint_claim(&self, _tenant_id: &str, _identity_id: &str, _app_public_id: &str) -> Value {
            Value::Null
        }
    }

    fn entitlements() -> Arc<dyn EntitlementService> {
        Arc::new(NoopEntitlementService)
    }

    #[derive(Default, Clone)]
    struct RecordingEntitlementService {
        ensured: Arc<Mutex<Vec<String>>>,
        seeded: Arc<Mutex<Vec<(String, String)>>>,
    }

    #[async_trait]
    impl EntitlementService for RecordingEntitlementService {
        async fn ensure_namespace(&self, tenant_id: &str) -> Result<(), ServiceError> {
            self.ensured.lock().unwrap().push(tenant_id.to_string());
            Ok(())
        }

        async fn seed_application(
            &self,
            tenant_id: &str,
            app_public_id: &str,
            _groups: &[String],
        ) -> Result<(), ServiceError> {
            self.seeded
                .lock()
                .unwrap()
                .push((tenant_id.to_string(), app_public_id.to_string()));
            Ok(())
        }

        async fn remove_application(
            &self,
            _tenant_id: &str,
            _app_public_id: &str,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn check(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _app_public_id: &str,
            _relation: &str,
        ) -> Result<bool, ServiceError> {
            Ok(true)
        }

        async fn effective_scope_ceiling(&self, _tenant_id: &str, _identity_id: &str) -> Vec<String> {
            vec![]
        }

        async fn grant(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _app_public_id: &str,
            _level: EntitlementLevel,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn revoke(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
            _app_public_id: &str,
            _level: EntitlementLevel,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn set_group_membership(
            &self,
            _tenant_id: &str,
            _group_name: &str,
            _identity_id: &str,
            _member: bool,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn remove_all_for_identity(
            &self,
            _tenant_id: &str,
            _identity_id: &str,
        ) -> Result<(), ServiceError> {
            Ok(())
        }

        async fn mint_claim(&self, _tenant_id: &str, _identity_id: &str, _app_public_id: &str) -> Value {
            Value::Null
        }
    }

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
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: tenant_id.into(),
            subject: "sub-1".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec![SCOPE_TENANT_READ.into()],
            token_hash: "hash".into(),
            authentication_methods: Vec::new(),
        });
        ctx
    }

    fn admin_ctx(tenant_id: &str) -> RequestContext {
        let mut ctx = RequestContext::new(http::HeaderMap::new());
        ctx.extensions_mut().insert(TenantId(tenant_id.into()));
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: tenant_id.into(),
            subject: "sub-1".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec![SCOPE_TENANT_ADMIN.into()],
            token_hash: "hash".into(),
            authentication_methods: Vec::new(),
        });
        ctx
    }

    fn ctx_without_scope(tenant_id: &str) -> RequestContext {
        let mut ctx = RequestContext::new(http::HeaderMap::new());
        ctx.extensions_mut().insert(TenantId(tenant_id.into()));
        ctx.extensions_mut().insert(AuthContext {
            tenant_id: tenant_id.into(),
            subject: "sub-1".into(),
            subject_type: SubjectType::User,
            actor: None,
            scopes: vec!["other:scope".into()],
            token_hash: "hash".into(),
            authentication_methods: Vec::new(),
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
            self.next_create.lock().unwrap().take().unwrap_or_else(|| {
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
            self.next_list
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Ok(vec![]))
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
            "system".into(),
            entitlements(),
        );
        let ctx = admin_ctx("system");
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
    async fn create_tenant_ensures_entitlement_namespace() {
        let entitlements = Arc::new(RecordingEntitlementService::default());
        let service = TenantServiceImpl::new(
            StubTenantStore::with_create(TenantRow {
                id: "tenant-1".into(),
                slug: "acme".into(),
                display_name: "Acme Corp".into(),
                is_system: false,
                settings: json!({}),
            }),
            "system".into(),
            entitlements.clone(),
        );
        let ctx = admin_ctx("system");
        let req_msg = CreateTenantRequest {
            slug: "acme".into(),
            display_name: "Acme".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, CreateTenantRequest);
        service.create_tenant(ctx, request).await.unwrap();
        assert_eq!(entitlements.ensured.lock().unwrap().as_slice(), &["tenant-1"]);
    }

    #[tokio::test]
    async fn create_tenant_requires_admin_scope() {
        let service = TenantServiceImpl::new(StubTenantStore::default(), "system".into(), entitlements());
        let ctx = ctx_without_scope("tenant-1");
        let req_msg = CreateTenantRequest {
            slug: "acme".into(),
            display_name: "Acme".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, CreateTenantRequest);
        let err: ServiceError = service
            .create_tenant(ctx, request)
            .await
            .unwrap_err()
            .into();
        assert!(matches!(err, ServiceError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn create_tenant_requires_tenant() {
        let service = TenantServiceImpl::new(StubTenantStore::default(), "system".into(), entitlements());
        let ctx = RequestContext::new(http::HeaderMap::new());
        let req_msg = CreateTenantRequest::default();
        svc_req!(request, req_msg, CreateTenantRequest);
        let err: ServiceError = service
            .create_tenant(ctx, request)
            .await
            .unwrap_err()
            .into();
        assert!(matches!(err, ServiceError::Unauthenticated(_)));
    }

    #[tokio::test]
    async fn create_tenant_propagates_repo_error() {
        let service = TenantServiceImpl::new(
            StubTenantStore::with_create_err(DbError::TenantNotFound),
            "system".into(),
            entitlements(),
        );
        let ctx = admin_ctx("system");
        let req_msg = CreateTenantRequest {
            slug: "acme".into(),
            display_name: "Acme".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, CreateTenantRequest);
        let err: ServiceError = service
            .create_tenant(ctx, request)
            .await
            .unwrap_err()
            .into();
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
            "system".into(),
            entitlements(),
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
        let service = TenantServiceImpl::new(StubTenantStore::default(), "system".into(), entitlements());
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
            "system".into(),
            entitlements(),
        );
        let ctx = tenant_ctx("system");
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
            "system".into(),
            entitlements(),
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
        let service = TenantServiceImpl::new(StubTenantStore::default(), "system".into(), entitlements());
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
            "system".into(),
            entitlements(),
        );
        let ctx = tenant_ctx("tenant-1");
        let req_msg = ListTenantsRequest::default();
        svc_req!(request, req_msg, ListTenantsRequest);
        let err: ServiceError = service.list_tenants(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::Internal(_)));
    }

    #[tokio::test]
    async fn create_tenant_rejects_non_system_tenant() {
        let service = TenantServiceImpl::new(StubTenantStore::default(), "system".into(), entitlements());
        let ctx = admin_ctx("tenant-1");
        let req_msg = CreateTenantRequest {
            slug: "acme".into(),
            display_name: "Acme".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, CreateTenantRequest);
        let err: ServiceError = service
            .create_tenant(ctx, request)
            .await
            .unwrap_err()
            .into();
        assert!(matches!(err, ServiceError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn get_tenant_rejects_other_tenant() {
        let service = TenantServiceImpl::new(
            StubTenantStore::with_get(TenantRow {
                id: "tenant-2".into(),
                slug: "other".into(),
                display_name: "Other".into(),
                is_system: false,
                settings: json!({}),
            }),
            "system".into(),
            entitlements(),
        );
        let ctx = tenant_ctx("tenant-1");
        let req_msg = GetTenantRequest {
            id: "tenant-2".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, GetTenantRequest);
        let err: ServiceError = service.get_tenant(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn get_tenant_system_can_access_any() {
        let service = TenantServiceImpl::new(
            StubTenantStore::with_get(TenantRow {
                id: "tenant-2".into(),
                slug: "other".into(),
                display_name: "Other".into(),
                is_system: false,
                settings: json!({}),
            }),
            "system".into(),
            entitlements(),
        );
        let ctx = tenant_ctx("system");
        let req_msg = GetTenantRequest {
            id: "tenant-2".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, GetTenantRequest);
        let response = service.get_tenant(ctx, request).await.unwrap();
        assert_eq!(response.body.id, "tenant-2");
    }

    #[tokio::test]
    async fn list_tenants_filters_non_system() {
        let service = TenantServiceImpl::new(
            StubTenantStore::with_list(vec![
                TenantRow {
                    id: "tenant-1".into(),
                    slug: "acme".into(),
                    display_name: "Acme".into(),
                    is_system: false,
                    settings: json!({}),
                },
                TenantRow {
                    id: "tenant-2".into(),
                    slug: "other".into(),
                    display_name: "Other".into(),
                    is_system: false,
                    settings: json!({}),
                },
            ]),
            "system".into(),
            entitlements(),
        );
        let ctx = tenant_ctx("tenant-1");
        let req_msg = ListTenantsRequest::default();
        svc_req!(request, req_msg, ListTenantsRequest);
        let response = service.list_tenants(ctx, request).await.unwrap();
        assert_eq!(response.body.tenants.len(), 1);
        assert_eq!(response.body.tenants[0].id, "tenant-1");
    }

    #[tokio::test]
    async fn list_tenants_system_sees_all() {
        let service = TenantServiceImpl::new(
            StubTenantStore::with_list(vec![
                TenantRow {
                    id: "tenant-1".into(),
                    slug: "acme".into(),
                    display_name: "Acme".into(),
                    is_system: false,
                    settings: json!({}),
                },
                TenantRow {
                    id: "tenant-2".into(),
                    slug: "other".into(),
                    display_name: "Other".into(),
                    is_system: false,
                    settings: json!({}),
                },
            ]),
            "system".into(),
            entitlements(),
        );
        let ctx = tenant_ctx("system");
        let req_msg = ListTenantsRequest::default();
        svc_req!(request, req_msg, ListTenantsRequest);
        let response = service.list_tenants(ctx, request).await.unwrap();
        assert_eq!(response.body.tenants.len(), 2);
    }

    #[tokio::test]
    async fn get_tenant_requires_read_scope() {
        let service = TenantServiceImpl::new(StubTenantStore::default(), "system".into(), entitlements());
        let ctx = ctx_without_scope("tenant-1");
        let req_msg = GetTenantRequest {
            id: "tenant-1".into(),
            ..Default::default()
        };
        svc_req!(request, req_msg, GetTenantRequest);
        let err: ServiceError = service.get_tenant(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::PermissionDenied(_)));
    }

    #[tokio::test]
    async fn list_tenants_requires_read_scope() {
        let service = TenantServiceImpl::new(StubTenantStore::default(), "system".into(), entitlements());
        let ctx = ctx_without_scope("tenant-1");
        let req_msg = ListTenantsRequest::default();
        svc_req!(request, req_msg, ListTenantsRequest);
        let err: ServiceError = service.list_tenants(ctx, request).await.unwrap_err().into();
        assert!(matches!(err, ServiceError::PermissionDenied(_)));
    }
}
