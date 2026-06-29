use std::sync::Arc;

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use sso_ory_client::{error::OryClientError, hydra::HydraClient};
use sunbeam_g2v::error::ServiceError;
use tracing::instrument;

use crate::proto::iam::v1::{
    AcceptConsentRequest, AcceptLogoutRequest, ConsentRequest, ConsentResponse,
    GetChallengeRequest, LogoutRequest, LogoutResponse, OAuth2ConsentService, RejectConsentRequest,
    RejectLogoutRequest,
};

use super::oauth2_consent_mapper::{
    accept_consent_request_to_json, accept_logout_request_to_json, ory_consent_request_to_proto,
    ory_consent_response_to_proto, ory_logout_request_to_proto, ory_logout_response_to_proto,
    reject_consent_request_to_json, reject_logout_request_to_json,
};

#[derive(Clone)]
pub struct OAuth2ConsentServiceImpl {
    hydra: Arc<HydraClient>,
}

impl OAuth2ConsentServiceImpl {
    pub fn new(hydra: Arc<HydraClient>) -> Self {
        Self { hydra }
    }
}

#[allow(refining_impl_trait)]
impl OAuth2ConsentService for OAuth2ConsentServiceImpl {
    #[instrument(skip(self, request))]
    async fn get_consent_request(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetChallengeRequest>,
    ) -> ServiceResult<ConsentRequest> {
        let req = request.to_owned_message();
        let value = self
            .hydra
            .get_consent_request(&req.challenge)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_consent_request_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn accept_consent(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, AcceptConsentRequest>,
    ) -> ServiceResult<ConsentResponse> {
        let req = request.to_owned_message();
        let challenge = req.challenge.clone();
        let body = accept_consent_request_to_json(&req);
        let value = self
            .hydra
            .accept_consent_request(&challenge, body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_consent_response_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn reject_consent(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, RejectConsentRequest>,
    ) -> ServiceResult<ConsentResponse> {
        let req = request.to_owned_message();
        let challenge = req.challenge.clone();
        let body = reject_consent_request_to_json(&req);
        let value = self
            .hydra
            .reject_consent_request(&challenge, body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_consent_response_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn get_logout_request(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetChallengeRequest>,
    ) -> ServiceResult<LogoutRequest> {
        let req = request.to_owned_message();
        let value = self
            .hydra
            .get_logout_request(&req.challenge)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_logout_request_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn accept_logout(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, AcceptLogoutRequest>,
    ) -> ServiceResult<LogoutResponse> {
        let req = request.to_owned_message();
        let challenge = req.challenge.clone();
        let body = accept_logout_request_to_json(&req);
        let value = self
            .hydra
            .accept_logout_request(&challenge, body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_logout_response_to_proto(&value)))
    }

    #[instrument(skip(self, request))]
    async fn reject_logout(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, RejectLogoutRequest>,
    ) -> ServiceResult<LogoutResponse> {
        let req = request.to_owned_message();
        let challenge = req.challenge.clone();
        let body = reject_logout_request_to_json(&req);
        let value = self
            .hydra
            .reject_logout_request(&challenge, body)
            .await
            .map_err(map_ory_error)?;
        Ok(Response::new(ory_logout_response_to_proto(&value)))
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
            ServiceError::Unavailable("upstream oauth2 service unreachable".into())
        }
        OryClientError::Serialization(_) | OryClientError::InvalidResponse(_) => {
            ServiceError::Internal("invalid upstream response".into())
        }
        OryClientError::MissingTenant => ServiceError::Unauthenticated("missing tenant".into()),
    }
}

#[cfg(test)]
mod tests {
    use sso_ory_client::error::OryClientError;
    use sunbeam_g2v::error::ServiceError;

    use super::map_ory_error;

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
}
