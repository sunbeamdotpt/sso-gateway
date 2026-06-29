use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use rand::distributions::{Alphanumeric, DistString};
use tracing::instrument;

use crate::db::{TenantApiKeyRepo, TenantRepo, TenantRow};
use crate::middleware::{TenantId, hash_api_key, require_scope};
use crate::proto::iam::v1::{
    ApiKey, CreateTenantRequest, GetTenantRequest, ListTenantsRequest, ListTenantsResponse,
    RotateApiKeyRequest, Tenant, TenantService,
};
use sunbeam_g2v::error::ServiceError;

const SCOPE_TENANT_ADMIN: &str = "tenant:admin";

#[derive(Clone)]
pub struct TenantServiceImpl {
    repo: TenantRepo,
    api_keys: TenantApiKeyRepo,
    #[allow(dead_code)]
    system_tenant_ulid: String,
}

impl TenantServiceImpl {
    pub fn new(repo: TenantRepo, api_keys: TenantApiKeyRepo, system_tenant_ulid: String) -> Self {
        Self {
            repo,
            api_keys,
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
    use super::*;
    use serde_json::json;

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
}
