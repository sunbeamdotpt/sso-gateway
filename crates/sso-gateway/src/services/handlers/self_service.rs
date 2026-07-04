use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE, header::LOCATION},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use serde_json::Value;
use tracing::{instrument, warn};

use crate::services::self_service_url_rewriter::{rewrite_json_urls, rewrite_url};

/// State shared by the public self-service proxy handlers.
#[derive(Clone)]
pub struct SelfServiceState {
    client: reqwest::Client,
    kratos_public_url: String,
    gateway_public_url: String,
}

impl SelfServiceState {
    pub fn new(kratos_public_url: String, gateway_public_url: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            kratos_public_url,
            gateway_public_url,
        }
    }

    /// Create a state from an existing reqwest client. Useful for tests.
    #[cfg(test)]
    pub fn with_client(
        client: reqwest::Client,
        kratos_public_url: String,
        gateway_public_url: String,
    ) -> Self {
        Self {
            client,
            kratos_public_url,
            gateway_public_url,
        }
    }
}

pub fn router(state: Arc<SelfServiceState>) -> Router {
    Router::new()
        .route("/self-service/{*path}", any(proxy_self_service))
        .route("/.well-known/ory/webauthn.js", get(proxy_webauthn_js))
        .with_state(state)
}

#[instrument(skip(state, request))]
async fn proxy_self_service(
    State(state): State<Arc<SelfServiceState>>,
    Path(path): Path<String>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    request: Request,
) -> impl IntoResponse {
    let upstream_url = match build_upstream_url(&state.kratos_public_url, &format!("self-service/{path}"), &query) {
        Ok(url) => url,
        Err(err) => {
            warn!(%err, "failed to build upstream self-service URL");
            return (StatusCode::BAD_GATEWAY, "failed to build upstream URL").into_response();
        }
    };

    proxy_request(state, request, upstream_url, true).await
}

#[instrument(skip(state, request))]
async fn proxy_webauthn_js(
    State(state): State<Arc<SelfServiceState>>,
    request: Request,
) -> impl IntoResponse {
    let upstream_url = match build_upstream_url(
        &state.kratos_public_url,
        ".well-known/ory/webauthn.js",
        &std::collections::HashMap::new(),
    ) {
        Ok(url) => url,
        Err(err) => {
            warn!(%err, "failed to build upstream webauthn URL");
            return (StatusCode::BAD_GATEWAY, "failed to build upstream URL").into_response();
        }
    };

    proxy_request(state, request, upstream_url, false).await
}

fn build_upstream_url(
    base: &str,
    path: &str,
    query: &std::collections::HashMap<String, String>,
) -> Result<reqwest::Url, url::ParseError> {
    let base = base.trim_end_matches('/');
    let mut url = reqwest::Url::parse(&format!("{}/{}", base, path.trim_start_matches('/')))?;
    if !query.is_empty() {
        url.query_pairs_mut()
            .extend_pairs(query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    }
    Ok(url)
}

async fn proxy_request(
    state: Arc<SelfServiceState>,
    request: Request,
    upstream_url: reqwest::Url,
    rewrite_urls: bool,
) -> Response {
    let method = request.method().clone();
    let headers = request.headers().clone();
    let body_bytes = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(%err, "failed to read request body");
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };

    let mut upstream_request = state
        .client
        .request(method, upstream_url)
        .body(body_bytes.to_vec());

    for (name, value) in headers.iter() {
        if is_hop_by_hop_header(name.as_str()) {
            continue;
        }
        upstream_request = upstream_request.header(name.as_str(), value.as_bytes());
    }

    let upstream_response = match upstream_request.send().await {
        Ok(resp) => resp,
        Err(err) => {
            warn!(%err, "upstream self-service request failed");
            return (
                StatusCode::BAD_GATEWAY,
                "upstream self-service request failed",
            )
                .into_response();
        }
    };

    let status = StatusCode::from_u16(upstream_response.status().as_u16())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream_response.headers().iter() {
        if is_hop_by_hop_header(name.as_str()) {
            continue;
        }
        let rewritten = if rewrite_urls && name == LOCATION {
            value
                .to_str()
                .ok()
                .map(|s| rewrite_url(s, &state.kratos_public_url, &state.gateway_public_url))
                .and_then(|s| HeaderValue::from_str(&s).ok())
                .unwrap_or_else(|| value.clone())
        } else {
            value.clone()
        };
        if let Ok(value) = HeaderValue::from_bytes(rewritten.as_bytes()) {
            response_headers.insert(name, value);
        }
    }

    let content_type = upstream_response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body_bytes = match upstream_response.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(%err, "failed to read upstream response body");
            return (
                StatusCode::BAD_GATEWAY,
                "failed to read upstream response body",
            )
                .into_response();
        }
    };

    let final_body = if rewrite_urls && content_type.as_deref().map(is_json_content_type).unwrap_or(false) {
        match serde_json::from_slice::<Value>(&body_bytes) {
            Ok(mut value) => {
                rewrite_json_urls(
                    &mut value,
                    &state.kratos_public_url,
                    &state.gateway_public_url,
                );
                Body::from(value.to_string())
            }
            Err(_) => Body::from(body_bytes),
        }
    } else if rewrite_urls && content_type.as_deref().map(is_html_content_type).unwrap_or(false) {
        // Courier message bodies and some Kratos error pages are HTML. Replace
        // every occurrence of the Kratos public origin so that embedded
        // self-service links point at the gateway.
        let text = String::from_utf8_lossy(&body_bytes);
        let rewritten = text.replace(
            state.kratos_public_url.trim_end_matches('/'),
            state.gateway_public_url.trim_end_matches('/'),
        );
        Body::from(rewritten)
    } else {
        Body::from(body_bytes)
    };

    (status, response_headers, final_body).into_response()
}

fn is_json_content_type(content_type: &str) -> bool {
    content_type.starts_with("application/json")
}

fn is_html_content_type(content_type: &str) -> bool {
    content_type.starts_with("text/html")
}

fn is_hop_by_hop_header(name: &str) -> bool {
    const HOP_BY_HOP: &[&str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
    ];
    HOP_BY_HOP.contains(&name.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    fn test_state(upstream_url: String) -> Arc<SelfServiceState> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Arc::new(SelfServiceState::with_client(
            client,
            upstream_url.clone(),
            "https://gateway.example.com".to_string(),
        ))
    }

    #[tokio::test]
    async fn proxy_rewrites_kratos_urls_in_json() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_origin = format!("http://{addr}");
        let app = {
            let upstream_origin = upstream_origin.clone();
            axum::Router::new().route(
                "/self-service/{*path}",
                get(move || {
                    let upstream_origin = upstream_origin.clone();
                    async move {
                        axum::Json(serde_json::json!({
                            "id": "flow-1",
                            "ui": {
                                "action": format!("{upstream_origin}/self-service/login?flow=flow-1")
                            }
                        }))
                    }
                }),
            )
        };
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let state = test_state(upstream_origin);
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/self-service/login/browser")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["ui"]["action"],
            "https://gateway.example.com/self-service/login?flow=flow-1"
        );
    }

    #[test]
    fn is_hop_by_hop_header_rejects_connection() {
        assert!(is_hop_by_hop_header("Connection"));
        assert!(!is_hop_by_hop_header("Accept"));
    }

    #[test]
    fn build_upstream_url_preserves_query() {
        let mut query = std::collections::HashMap::new();
        query.insert("flow".to_string(), "flow-1".to_string());
        let url = build_upstream_url("http://kratos.example.com", "self-service/login/browser", &query)
            .unwrap();
        assert_eq!(url.as_str(), "http://kratos.example.com/self-service/login/browser?flow=flow-1");
    }

    #[tokio::test]
    async fn proxy_rewrites_kratos_urls_in_html() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_origin = format!("http://{addr}");
        let app = {
            let upstream_origin = upstream_origin.clone();
            axum::Router::new().route(
                "/self-service/recovery",
                get(move || {
                    let upstream_origin = upstream_origin.clone();
                    async move {
                        (
                            [(CONTENT_TYPE, "text/html; charset=utf-8")],
                            format!(
                                r#"<a href="{}/self-service/recovery?token=abc">recover</a>"#,
                                upstream_origin
                            ),
                        )
                    }
                }),
            )
        };
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let state = test_state(upstream_origin);
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/self-service/recovery?token=abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body.contains("https://gateway.example.com/self-service/recovery?token=abc"));
    }

    #[tokio::test]
    async fn proxy_passthrough_non_json_html_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_origin = format!("http://{addr}");
        let app = axum::Router::new().route(
            "/self-service/verify",
            get(|| async { ([(CONTENT_TYPE, "text/plain")], "plain body") }),
        );
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let state = test_state(upstream_origin);
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/self-service/verify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes, "plain body");
    }

    #[tokio::test]
    async fn proxy_returns_bad_gateway_when_upstream_unreachable() {
        let state = test_state("http://127.0.0.1:1".to_string());
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/self-service/login/browser")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn proxy_webauthn_js_happy_path() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_origin = format!("http://{addr}");
        let app = axum::Router::new().route(
            "/.well-known/ory/webauthn.js",
            get(|| async { ([(CONTENT_TYPE, "application/javascript")], "window.WebAuthn={};") }),
        );
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let state = test_state(upstream_origin);
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/.well-known/ory/webauthn.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes, "window.WebAuthn={};");
    }

    #[test]
    fn build_upstream_url_rejects_invalid_base() {
        let query = std::collections::HashMap::new();
        assert!(build_upstream_url("not a url", "self-service/login", &query).is_err());
    }

    #[test]
    fn is_hop_by_hop_header_rejects_known_hop_by_hop_headers() {
        for name in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "host",
        ] {
            assert!(is_hop_by_hop_header(name), "{name} should be hop-by-hop");
        }
    }

    #[tokio::test]
    async fn proxy_does_not_follow_upstream_redirect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_origin = format!("http://{addr}");
        let app = {
            let upstream_origin = upstream_origin.clone();
            axum::Router::new().route(
                "/self-service/verify",
                get(move || {
                    let upstream_origin = upstream_origin.clone();
                    async move {
                        (
                            StatusCode::FOUND,
                            [(
                                axum::http::header::LOCATION,
                                format!("{upstream_origin}/self-service/verification?token=abc"),
                            )],
                        )
                    }
                }),
            )
        };
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let state = test_state(upstream_origin);
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/self-service/verify?token=abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            location,
            "https://gateway.example.com/self-service/verification?token=abc"
        );
    }
}
