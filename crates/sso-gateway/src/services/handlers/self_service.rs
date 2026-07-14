use std::sync::Arc;

#[cfg(test)]
use axum::http::header::CONTENT_TYPE;
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use tracing::{instrument, warn};

/// State shared by the public self-service proxy handlers.
#[derive(Clone)]
pub struct SelfServiceState {
    client: reqwest::Client,
    kratos_public_url: String,
}

impl SelfServiceState {
    pub fn new(kratos_public_url: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            kratos_public_url,
        }
    }

    /// Create a state from an existing reqwest client. Useful for tests.
    #[cfg(test)]
    pub fn with_client(client: reqwest::Client, kratos_public_url: String) -> Self {
        Self {
            client,
            kratos_public_url,
        }
    }
}

pub fn router(state: Arc<SelfServiceState>) -> Router {
    Router::new()
        .route("/.well-known/ory/webauthn.js", get(proxy_webauthn_js))
        .with_state(state)
}

#[instrument(skip(state, request))]
async fn proxy_webauthn_js(
    State(state): State<Arc<SelfServiceState>>,
    request: Request,
) -> impl IntoResponse {
    let upstream_url =
        match build_upstream_url(&state.kratos_public_url, ".well-known/ory/webauthn.js") {
            Ok(url) => url,
            Err(err) => {
                warn!(%err, "failed to build upstream webauthn URL");
                return (StatusCode::BAD_GATEWAY, "failed to build upstream URL").into_response();
            }
        };

    proxy_request(state, request, upstream_url).await
}

fn build_upstream_url(base: &str, path: &str) -> Result<reqwest::Url, url::ParseError> {
    let base = base.trim_end_matches('/');
    reqwest::Url::parse(&format!("{}/{}", base, path.trim_start_matches('/')))
}

async fn proxy_request(
    state: Arc<SelfServiceState>,
    request: Request,
    upstream_url: reqwest::Url,
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
    // Preserve every upstream header value, including repeated header names.
    // `HeaderMap::insert` overwrites earlier values for the same name, which
    // silently drops all but the last `Set-Cookie` (e.g. losing the Kratos
    // session or CSRF cookie). `append` keeps every value so the browser
    // receives the full set.
    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream_response.headers().iter() {
        if is_hop_by_hop_header(name.as_str()) {
            continue;
        }
        if let Ok(value) = HeaderValue::from_bytes(value.as_bytes()) {
            response_headers.append(name.clone(), value);
        }
    }

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

    (status, response_headers, Body::from(body_bytes)).into_response()
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
        Arc::new(SelfServiceState::with_client(client, upstream_url.clone()))
    }

    #[test]
    fn is_hop_by_hop_header_rejects_connection() {
        assert!(is_hop_by_hop_header("Connection"));
        assert!(!is_hop_by_hop_header("Accept"));
    }

    #[test]
    fn build_upstream_url_builds_well_known_path() {
        let url =
            build_upstream_url("http://kratos.example.com", ".well-known/ory/webauthn.js").unwrap();
        assert_eq!(
            url.as_str(),
            "http://kratos.example.com/.well-known/ory/webauthn.js"
        );
    }

    #[test]
    fn build_upstream_url_rejects_invalid_base() {
        assert!(build_upstream_url("not a url", ".well-known/ory/webauthn.js").is_err());
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
    async fn proxy_webauthn_js_happy_path() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_origin = format!("http://{addr}");
        let app = axum::Router::new().route(
            "/.well-known/ory/webauthn.js",
            get(|| async {
                (
                    [(CONTENT_TYPE, "application/javascript")],
                    "window.WebAuthn={};",
                )
            }),
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

    #[tokio::test]
    async fn proxy_webauthn_js_returns_bad_gateway_when_upstream_unreachable() {
        let state = test_state("http://127.0.0.1:1".to_string());
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/.well-known/ory/webauthn.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn general_self_service_route_is_not_registered() {
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
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn proxy_request_preserves_multiple_set_cookie_headers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_origin = format!("http://{addr}");
        let app = axum::Router::new().route(
            "/.well-known/ory/webauthn.js",
            get(|| async {
                let mut headers = axum::http::HeaderMap::new();
                headers.append(
                    axum::http::header::SET_COOKIE,
                    "ory_kratos_session=abc; Path=/; HttpOnly".parse().unwrap(),
                );
                headers.append(
                    axum::http::header::SET_COOKIE,
                    "csrf_token=def; Path=/; HttpOnly".parse().unwrap(),
                );
                (headers, "ok")
            }),
        );
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let state = test_state(upstream_origin.clone());
        let upstream_url =
            build_upstream_url(&upstream_origin, ".well-known/ory/webauthn.js").unwrap();
        let request = Request::get("/.well-known/ory/webauthn.js")
            .body(Body::empty())
            .unwrap();
        let response = proxy_request(state, request, upstream_url).await;

        assert_eq!(response.status(), StatusCode::OK);
        let cookies: Vec<_> = response.headers().get_all("set-cookie").iter().collect();
        assert_eq!(
            cookies.len(),
            2,
            "both upstream Set-Cookie headers must be forwarded"
        );
        assert!(
            cookies
                .iter()
                .any(|c| c.to_str().unwrap().starts_with("ory_kratos_session="))
        );
        assert!(
            cookies
                .iter()
                .any(|c| c.to_str().unwrap().starts_with("csrf_token="))
        );
    }

    #[tokio::test]
    async fn proxy_request_forwards_incoming_cookie_to_upstream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream_origin = format!("http://{addr}");
        let app = axum::Router::new().route(
            "/.well-known/ory/webauthn.js",
            get(|headers: axum::http::HeaderMap| async move {
                headers
                    .get_all("cookie")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .collect::<Vec<_>>()
                    .join("|")
            }),
        );
        let _handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let state = test_state(upstream_origin.clone());
        let upstream_url =
            build_upstream_url(&upstream_origin, ".well-known/ory/webauthn.js").unwrap();
        let request = Request::get("/.well-known/ory/webauthn.js")
            .header("cookie", "ory_kratos_session=abc; csrf_token=def")
            .body(Body::empty())
            .unwrap();
        let response = proxy_request(state, request, upstream_url).await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let echoed = std::str::from_utf8(&bytes).unwrap();
        assert!(
            echoed.contains("ory_kratos_session=abc"),
            "session cookie was not forwarded upstream: {echoed}"
        );
        assert!(
            echoed.contains("csrf_token=def"),
            "csrf cookie was not forwarded upstream: {echoed}"
        );
    }
}
