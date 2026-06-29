use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{Query, State},
    http::{StatusCode, Response},
    response::IntoResponse,
    routing::get,
};
use tracing::warn;

use crate::services::federation::FederationServiceImpl;

const SAML_METADATA_CONTENT_TYPE: &str = "application/samlmetadata+xml";

#[derive(Debug)]
enum SamlError {
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

#[derive(Clone)]
pub struct SamlState {
    pub service: Arc<FederationServiceImpl>,
}

pub fn router(state: Arc<SamlState>) -> Router {
    Router::new()
        .route("/saml/metadata", get(metadata))
        .with_state(state)
}

async fn metadata(
    State(state): State<Arc<SamlState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, SamlError> {
    let provider_id = params
        .get("provider_id")
        .ok_or_else(|| SamlError::Response(Box::new(saml_error(
            StatusCode::BAD_REQUEST,
            "missing provider_id",
        ))))?;

    let provider = state.service.providers.get_by_id(provider_id).await?;
    let xml = state.service.generate_sp_metadata(&provider)?;

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
    use http_body_util::BodyExt;

    #[test]
    fn saml_error_builds_json_response() {
        let resp = saml_error(StatusCode::NOT_FOUND, "missing provider");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
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
        assert_eq!(err.into_response().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn saml_error_from_service_error_maps_internal() {
        let err: SamlError = sunbeam_g2v::error::ServiceError::Internal("fail".into()).into();
        assert_eq!(err.into_response().status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn saml_error_body_contains_detail() {
        let resp = saml_error(StatusCode::BAD_REQUEST, "bad");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("bad"));
    }
}
