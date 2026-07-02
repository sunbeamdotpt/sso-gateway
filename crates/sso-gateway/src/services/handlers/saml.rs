use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    extract::{Query, State},
    http::{Response, StatusCode},
    response::IntoResponse,
    routing::get,
};
use tracing::warn;

use crate::services::federation::FederationServiceImpl;

const SAML_METADATA_CONTENT_TYPE: &str = "application/samlmetadata+xml";

#[derive(Debug)]
pub enum SamlError {
    Response(Box<Response<Body>>),
}

impl IntoResponse for SamlError {
    fn into_response(self) -> Response<Body> {
        match self {
            SamlError::Response(resp) => *resp,
        }
    }
}

impl From<crate::db::DbError> for SamlError {
    fn from(err: crate::db::DbError) -> Self {
        let status = match err {
            crate::db::DbError::SamlProviderNotFound => StatusCode::NOT_FOUND,
            _ => {
                warn!("saml metadata db error: {}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        Self::Response(Box::new(saml_error(status, "metadata unavailable")))
    }
}

impl From<sunbeam_g2v::error::ServiceError> for SamlError {
    fn from(err: sunbeam_g2v::error::ServiceError) -> Self {
        warn!("saml metadata service error: {}", err);
        Self::Response(Box::new(saml_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "metadata unavailable",
        )))
    }
}

/// Async trait for SAML SP metadata generation used by the HTTP handler.
#[async_trait]
pub trait SamlMetadataService: Send + Sync + 'static {
    async fn generate_metadata(&self, provider_id: &str) -> Result<String, SamlError>;
}

#[async_trait]
impl SamlMetadataService for FederationServiceImpl {
    async fn generate_metadata(&self, provider_id: &str) -> Result<String, SamlError> {
        let provider = self.providers.get_by_id(provider_id).await?;
        let xml = self.generate_sp_metadata(&provider)?;
        Ok(xml)
    }
}

#[derive(Clone)]
pub struct SamlState {
    pub(crate) service: Arc<dyn SamlMetadataService>,
}

impl SamlState {
    pub fn new(service: Arc<FederationServiceImpl>) -> Self {
        Self {
            service: service as Arc<dyn SamlMetadataService>,
        }
    }
}

pub fn router(state: Arc<SamlState>) -> Router {
    Router::new()
        .route("/saml/metadata", get(metadata))
        .with_state(state)
}

fn build_metadata_response(xml: String) -> Result<Response<Body>, SamlError> {
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, SAML_METADATA_CONTENT_TYPE)
        .body(Body::from(xml))
        .map_err(|e| {
            warn!("saml metadata response builder error: {e}");
            SamlError::Response(Box::new(saml_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "metadata unavailable",
            )))
        })
}

async fn metadata(
    State(state): State<Arc<SamlState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, SamlError> {
    let provider_id = params.get("provider_id").ok_or_else(|| {
        SamlError::Response(Box::new(saml_error(
            StatusCode::BAD_REQUEST,
            "missing provider_id",
        )))
    })?;

    let xml = state.service.generate_metadata(provider_id).await?;

    build_metadata_response(xml)
}

fn saml_error(status: StatusCode, detail: &str) -> Response<Body> {
    let body = Body::from(format!("{{\"error\":\"{detail}\"}}"));
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbError;
    use http_body_util::BodyExt;
    use sunbeam_g2v::error::ServiceError;

    enum StubMetadataResult {
        Ok(String),
        Db(DbError),
        Service(ServiceError),
    }

    #[derive(Clone, Default)]
    struct StubMetadataService {
        result: Arc<std::sync::Mutex<Option<StubMetadataResult>>>,
    }

    #[async_trait]
    impl SamlMetadataService for StubMetadataService {
        async fn generate_metadata(&self, _provider_id: &str) -> Result<String, SamlError> {
            match self
                .result
                .lock()
                .unwrap()
                .take()
                .expect("stub not configured")
            {
                StubMetadataResult::Ok(xml) => Ok(xml),
                StubMetadataResult::Db(err) => Err(err.into()),
                StubMetadataResult::Service(err) => Err(err.into()),
            }
        }
    }

    fn test_state(result: Option<StubMetadataResult>) -> Arc<SamlState> {
        Arc::new(SamlState {
            service: Arc::new(StubMetadataService {
                result: Arc::new(std::sync::Mutex::new(result)),
            }),
        })
    }

    async fn body_to_string(resp: Response<Body>) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn saml_error_builds_json_response() {
        let resp = saml_error(StatusCode::NOT_FOUND, "missing provider");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/json"
        );
    }

    #[test]
    fn saml_error_from_db_error_maps_provider_not_found() {
        let err: SamlError = crate::db::DbError::SamlProviderNotFound.into();
        assert_eq!(err.into_response().status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn saml_error_from_db_error_maps_other_to_internal() {
        let err: SamlError = crate::db::DbError::Sqlx(sqlx::Error::PoolTimedOut).into();
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn saml_error_from_service_error_maps_internal() {
        let err: SamlError = sunbeam_g2v::error::ServiceError::Internal("fail".into()).into();
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn saml_error_body_contains_detail() {
        let resp = saml_error(StatusCode::BAD_REQUEST, "bad");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("bad"));
    }

    #[tokio::test]
    async fn build_metadata_response_sets_content_type_and_body() {
        let resp = build_metadata_response("<EntityDescriptor/>".to_string()).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            SAML_METADATA_CONTENT_TYPE
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("<EntityDescriptor/>"));
    }

    #[tokio::test]
    async fn metadata_returns_bad_request_when_provider_id_missing() {
        let state = test_state(None);
        let params = HashMap::new();
        let resp = metadata(State(state), Query(params))
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_to_string(resp).await;
        assert!(body.contains("missing provider_id"));
    }

    #[tokio::test]
    async fn metadata_returns_not_found_when_provider_missing() {
        let state = test_state(Some(StubMetadataResult::Db(
            crate::db::DbError::SamlProviderNotFound,
        )));
        let mut params = HashMap::new();
        params.insert("provider_id".to_string(), "missing".to_string());
        let resp = metadata(State(state), Query(params))
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn metadata_returns_xml_when_generation_succeeds() {
        let state = test_state(Some(StubMetadataResult::Ok(
            "<EntityDescriptor id='p1'/>".to_string(),
        )));
        let mut params = HashMap::new();
        params.insert("provider_id".to_string(), "p1".to_string());
        let resp = metadata(State(state), Query(params)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            SAML_METADATA_CONTENT_TYPE
        );
        let body = body_to_string(resp).await;
        assert!(body.contains("<EntityDescriptor id='p1'/>"));
    }

    #[tokio::test]
    async fn metadata_returns_internal_when_generation_fails() {
        let state = test_state(Some(StubMetadataResult::Service(
            sunbeam_g2v::error::ServiceError::Internal("boom".into()),
        )));
        let mut params = HashMap::new();
        params.insert("provider_id".to_string(), "p1".to_string());
        let resp = metadata(State(state), Query(params))
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn router_exposes_metadata_route() {
        let state = Arc::new(SamlState {
            service: Arc::new(StubMetadataService::default()),
        });
        let _router = router(state);
    }
}
