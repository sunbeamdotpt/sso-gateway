use std::sync::Arc;

use buffa_types::google::protobuf::Empty;
use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use sso_ory_client::{error::OryClientError, hydra::HydraClient};
use sunbeam_g2v::error::ServiceError;
use tracing::{debug, instrument};
use ulid::Ulid;

use crate::{
    db::IdMappingRepo,
    middleware::TenantId,
    proto::iam::v1::{
        Application, ApplicationSecret, CreateApplicationRequest, DeleteApplicationRequest,
        GetApplicationRequest, ListApplicationsRequest, ListApplicationsResponse,
        RotateSecretRequest, UpdateApplicationRequest,
    },
};

const BACKEND_HYDRA: &str = "hydra";

#[derive(Clone)]
pub struct ApplicationServiceImpl {
    hydra: Arc<HydraClient>,
    mappings: IdMappingRepo,
}

impl ApplicationServiceImpl {
    pub fn new(hydra: Arc<HydraClient>, mappings: IdMappingRepo) -> Self {
        Self { hydra, mappings }
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
        let req = request.to_owned_message();

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
        let req = request.to_owned_message();
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
        .ok_or_else(|| ServiceError::Unauthenticated("missing x-tenant-id".into()))
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
    use super::*;
    use serde_json::json;

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
}
