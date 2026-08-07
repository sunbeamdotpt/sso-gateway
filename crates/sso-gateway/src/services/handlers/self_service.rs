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

use crate::config::SelfServicePaths;
use crate::db::TransientTokenStore;
use crate::services::identity_self_service::scrub_flow_id_in_url;
use crate::services::self_service_url_rewriter::rewrite_gateway_facing_url;

/// State shared by the public self-service proxy handlers.
#[derive(Clone)]
pub struct SelfServiceState {
    client: reqwest::Client,
    kratos_public_url: String,
    gateway_public_url: String,
    paths: SelfServicePaths,
    transient: Arc<dyn TransientTokenStore>,
    system_tenant_id: String,
}

impl SelfServiceState {
    pub fn new(
        kratos_public_url: String,
        gateway_public_url: String,
        paths: SelfServicePaths,
        transient: Arc<dyn TransientTokenStore>,
        system_tenant_id: String,
    ) -> Self {
        Self {
            client: match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
            {
                Ok(client) => client,
                Err(_) => reqwest::Client::new(),
            },
            kratos_public_url,
            gateway_public_url,
            paths,
            transient,
            system_tenant_id,
        }
    }

    /// Create a state from an existing reqwest client. Useful for tests.
    #[cfg(test)]
    pub fn with_client(
        client: reqwest::Client,
        kratos_public_url: String,
        gateway_public_url: String,
        paths: SelfServicePaths,
        transient: Arc<dyn TransientTokenStore>,
        system_tenant_id: String,
    ) -> Self {
        Self {
            client,
            kratos_public_url,
            gateway_public_url,
            paths,
            transient,
            system_tenant_id,
        }
    }
}

/// The branded browser surface: every route a browser may be sent to by a
/// Kratos-emitted URL, proxied to the corresponding Kratos public route.
///
/// Kratos email links (recovery/verification) are emitted with Kratos' own
/// path shape regardless of configuration; they land on the
/// `/self-service/{recovery,verification}` shims and are bounced to the
/// branded surface so the address bar never shows an Ory path.
pub fn router(state: Arc<SelfServiceState>) -> Router {
    let paths = &state.paths;
    let mut router = Router::new();
    for path in [
        &paths.login,
        &paths.registration,
        &paths.settings,
        &paths.recovery,
        &paths.verification,
        &paths.logout,
        &paths.errors,
        &paths.webauthn_js,
    ] {
        router = router.route(path, get(proxy_branded));
    }
    // The OIDC callback accepts both GET and POST (form_post response mode)
    // and carries the upstream provider as a path segment.
    router
        .route(&paths.oidc_callback, get(proxy_branded).post(proxy_branded))
        .route(
            &format!("{}/{{provider}}", paths.oidc_callback),
            get(proxy_branded).post(proxy_branded),
        )
        .route("/self-service/recovery", get(redirect_to_branded))
        .route("/self-service/verification", get(redirect_to_branded))
        .with_state(state)
}

/// Proxy a branded browser route to its Kratos upstream equivalent.
///
/// Token-bearing links (recovery/verification emails, logout) target the
/// Kratos submission route rather than the flow-init route: the reverse
/// translation always yields the init route, so a `token` query parameter
/// switches the upstream to the submission path.
#[instrument(skip(state, request))]
async fn proxy_branded(
    State(state): State<Arc<SelfServiceState>>,
    request: Request,
) -> impl IntoResponse {
    let path = request.uri().path().to_string();
    let Some(kratos_path) = state.paths.kratos_path_for_gateway(&path) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let kratos_path = if carries_token(request.uri().query()) {
        token_submission_path(&kratos_path)
    } else {
        kratos_path
    };

    let upstream_url = match build_upstream_url(&state.kratos_public_url, &kratos_path) {
        Ok(mut url) => {
            url.set_query(request.uri().query());
            url
        }
        Err(err) => {
            warn!(%err, "failed to build upstream self-service URL");
            return (StatusCode::BAD_GATEWAY, "failed to build upstream URL").into_response();
        }
    };

    proxy_request(state, request, upstream_url).await
}

/// Bounce a Kratos-shaped email link (`/self-service/recovery?token=…`) to
/// the branded surface. The token is not consumed by the redirect; the
/// branded route's proxy forwards it upstream.
#[instrument(skip(state, request))]
async fn redirect_to_branded(
    State(state): State<Arc<SelfServiceState>>,
    request: Request,
) -> impl IntoResponse {
    let path = request.uri().path();
    let Some(branded) = state.paths.gateway_path_for_kratos(path) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let mut location = format!(
        "{}{}",
        state.gateway_public_url.trim_end_matches('/'),
        branded
    );
    if let Some(query) = request.uri().query() {
        location.push('?');
        location.push_str(query);
    }
    (
        StatusCode::FOUND,
        [(axum::http::header::LOCATION, location)],
    )
        .into_response()
}

fn carries_token(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == "token")
    })
}

/// Map a flow-init path to its token-submission counterpart. Only recovery,
/// verification, and logout accept token submissions; anything else keeps
/// the init path.
fn token_submission_path(kratos_path: &str) -> String {
    for flow in ["recovery", "verification", "logout"] {
        let init = format!("/self-service/{flow}/browser");
        if kratos_path == init {
            return format!("/self-service/{flow}");
        }
    }
    kratos_path.to_string()
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
    let forwarded_host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
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
    // Tell Kratos who the browser is actually talking to so any
    // request-derived URLs it builds point back at the gateway.
    if let Some(host) = forwarded_host {
        upstream_request = upstream_request.header("x-forwarded-host", host);
    }
    if let Some(proto) = state
        .gateway_public_url
        .split_once("://")
        .map(|(scheme, _)| scheme.to_string())
    {
        upstream_request = upstream_request.header("x-forwarded-proto", proto);
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

    let status = match StatusCode::from_u16(upstream_response.status().as_u16()) {
        Ok(status) => status,
        Err(err) => {
            tracing::warn!(%err, "upstream status not representable; responding 502");
            StatusCode::BAD_GATEWAY
        }
    };
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
        // Redirect targets are gateway-facing URLs: brand them so a Kratos
        // redirect never sends the browser to an Ory path.
        if name.as_str() == "location" {
            if let Ok(value) = value.to_str() {
                let rewritten = rewrite_gateway_facing_url(
                    &state.paths,
                    value,
                    &state.kratos_public_url,
                    &state.gateway_public_url,
                );
                // A Kratos redirect that creates or references a flow (e.g.
                // the AAL2 step-up init) carries the raw Kratos flow UUID as
                // `?flow=<uuid>`. Mint the transient mapping and swap in the
                // public ULID so the RPC surface can resolve the flow the
                // browser was sent to (SSO-041). The proxy serves browsers,
                // not tenants, so the mapping rides on the system tenant.
                let scrubbed = match scrub_flow_id_in_url(
                    state.transient.as_ref(),
                    &state.system_tenant_id,
                    &rewritten,
                    false,
                )
                .await
                {
                    Ok(scrubbed) => scrubbed,
                    Err(err) => {
                        warn!(%err, "failed to map kratos flow id in redirect location");
                        return (
                            StatusCode::BAD_GATEWAY,
                            "failed to map flow id in redirect location",
                        )
                            .into_response();
                    }
                };
                if let Ok(value) = HeaderValue::from_str(&scrubbed) {
                    response_headers.append(name.clone(), value);
                }
            }
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
    use std::sync::Mutex;
    use tower::ServiceExt;

    use crate::db::{DbError, TOKEN_TYPE_FLOW};

    const GATEWAY: &str = "https://gateway.example.com";
    const SYSTEM_TENANT: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const BACKEND_KRATOS: &str = "kratos";

    /// In-memory transient token store recording (tenant, ory_token,
    /// public_token) rows so tests can assert which flow ids were mapped and
    /// under which tenant.
    #[derive(Default)]
    struct StubTransientStore {
        rows: Mutex<Vec<(String, String, String)>>,
        fail_creates: std::sync::atomic::AtomicBool,
    }

    impl StubTransientStore {
        fn public_for(&self, ory_token: &str) -> Option<String> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.1 == ory_token)
                .map(|r| r.2.clone())
        }

        fn is_empty(&self) -> bool {
            self.rows.lock().unwrap().is_empty()
        }
    }

    #[async_trait::async_trait]
    impl TransientTokenStore for StubTransientStore {
        async fn create(
            &self,
            tenant_id: &str,
            _backend: &str,
            _token_type: &str,
            ory_token: &str,
            _expires_at: time::OffsetDateTime,
        ) -> Result<String, DbError> {
            if self.fail_creates.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(DbError::Sqlx(sqlx::Error::PoolTimedOut));
            }
            let mut rows = self.rows.lock().unwrap();
            if let Some(row) = rows.iter().find(|r| r.1 == ory_token) {
                return Ok(row.2.clone());
            }
            let public = ulid::Ulid::new().to_string();
            rows.push((
                tenant_id.to_string(),
                ory_token.to_string(),
                public.clone(),
            ));
            Ok(public)
        }

        async fn get_ory_token(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _token_type: &str,
            public_token: &str,
        ) -> Result<String, DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.2 == public_token)
                .map(|r| r.1.clone())
                .ok_or(DbError::MappingNotFound)
        }

        async fn get_public_token(
            &self,
            _tenant_id: &str,
            _backend: &str,
            _token_type: &str,
            ory_token: &str,
        ) -> Result<String, DbError> {
            self.public_for(ory_token).ok_or(DbError::MappingNotFound)
        }

        async fn delete(&self, _tenant_id: &str, public_token: &str) -> Result<(), DbError> {
            let mut rows = self.rows.lock().unwrap();
            let pos = rows.iter().position(|r| r.2 == public_token);
            pos.map(|i| rows.remove(i))
                .map(|_| ())
                .ok_or(DbError::MappingNotFound)
        }

        async fn get_ory_token_global(
            &self,
            _backend: &str,
            _token_type: &str,
            public_token: &str,
        ) -> Result<(String, String), DbError> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.2 == public_token)
                .map(|r| (r.0.clone(), r.1.clone()))
                .ok_or(DbError::MappingNotFound)
        }
    }

    fn test_state_with_store(
        upstream_url: String,
        store: Arc<StubTransientStore>,
    ) -> Arc<SelfServiceState> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Arc::new(SelfServiceState::with_client(
            client,
            upstream_url.clone(),
            GATEWAY.to_string(),
            SelfServicePaths::default(),
            store,
            SYSTEM_TENANT.to_string(),
        ))
    }

    fn test_state(upstream_url: String) -> Arc<SelfServiceState> {
        test_state_with_store(upstream_url, Arc::new(StubTransientStore::default()))
    }

    async fn spawn_upstream(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[test]
    fn is_hop_by_hop_header_rejects_connection() {
        assert!(is_hop_by_hop_header("Connection"));
        assert!(!is_hop_by_hop_header("Accept"));
    }

    #[test]
    fn build_upstream_url_builds_path() {
        let url =
            build_upstream_url("http://kratos.example.com", "/self-service/login/browser").unwrap();
        assert_eq!(
            url.as_str(),
            "http://kratos.example.com/self-service/login/browser"
        );
    }

    #[test]
    fn build_upstream_url_rejects_invalid_base() {
        assert!(build_upstream_url("not a url", "/self-service/login/browser").is_err());
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

    #[test]
    fn token_submission_path_maps_only_token_flows() {
        assert_eq!(
            token_submission_path("/self-service/recovery/browser"),
            "/self-service/recovery"
        );
        assert_eq!(
            token_submission_path("/self-service/verification/browser"),
            "/self-service/verification"
        );
        assert_eq!(
            token_submission_path("/self-service/logout/browser"),
            "/self-service/logout"
        );
        assert_eq!(
            token_submission_path("/self-service/login/browser"),
            "/self-service/login/browser"
        );
    }

    #[test]
    fn carries_token_detects_token_param() {
        assert!(carries_token(Some("token=abc&flow=f")));
        assert!(carries_token(Some("flow=f&token=")));
        assert!(!carries_token(Some("flow=f&aal=aal2")));
        assert!(!carries_token(None));
        assert!(!carries_token(Some("csrf_token=abc")));
    }

    #[tokio::test]
    async fn branded_webauthn_js_is_proxied() {
        let upstream_origin = spawn_upstream(Router::new().route(
            "/.well-known/ory/webauthn.js",
            get(|| async {
                (
                    [(CONTENT_TYPE, "application/javascript")],
                    "window.WebAuthn={};",
                )
            }),
        ))
        .await;

        let state = test_state(upstream_origin);
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/identity/webauthn.js")
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
    async fn branded_login_init_is_proxied_with_query() {
        let upstream_origin = spawn_upstream(Router::new().route(
            "/self-service/login/browser",
            get(|uri: axum::http::Uri| async move { uri.query().unwrap_or_default().to_string() }),
        ))
        .await;

        let state = test_state(upstream_origin);
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/identity/login?aal=aal2&refresh=true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes, "aal=aal2&refresh=true");
    }

    #[tokio::test]
    async fn branded_recovery_with_token_hits_submission_route() {
        let upstream_origin = spawn_upstream(
            Router::new()
                .route("/self-service/recovery", get(|| async { "submission" }))
                .route("/self-service/recovery/browser", get(|| async { "init" })),
        )
        .await;

        let state = test_state(upstream_origin);
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/identity/recovery?token=t&flow=f")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes, "submission");
    }

    #[tokio::test]
    async fn branded_recovery_without_token_hits_init_route() {
        let upstream_origin = spawn_upstream(
            Router::new()
                .route("/self-service/recovery", get(|| async { "submission" }))
                .route("/self-service/recovery/browser", get(|| async { "init" })),
        )
        .await;

        let state = test_state(upstream_origin);
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/identity/recovery?return_to=https%3A%2F%2Fui.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes, "init");
    }

    #[tokio::test]
    async fn oidc_callback_is_proxied_for_get_and_post_with_provider() {
        let upstream_origin = spawn_upstream(Router::new().route(
            "/self-service/methods/oidc/callback/{provider}",
            get(|| async { "get-callback" }).post(|| async { "post-callback" }),
        ))
        .await;

        let state = test_state(upstream_origin);
        let app = router(state);
        let response = app
            .clone()
            .oneshot(
                Request::get("/identity/oidc/callback/google?code=c&state=s")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes, "get-callback");

        let response = app
            .oneshot(
                Request::post("/identity/oidc/callback/google")
                    .body(Body::from("code=c&state=s"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes, "post-callback");
    }

    #[tokio::test]
    async fn email_link_shim_redirects_to_branded_path() {
        let state = test_state("http://127.0.0.1:1".to_string());
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/self-service/recovery?token=t&flow=f")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://gateway.example.com/identity/recovery?token=t&flow=f"
        );
    }

    #[tokio::test]
    async fn email_link_shim_redirects_verification_without_query() {
        let state = test_state("http://127.0.0.1:1".to_string());
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/self-service/verification")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://gateway.example.com/identity/verification"
        );
    }

    #[tokio::test]
    async fn upstream_redirect_location_is_branded() {
        // The upstream emits a redirect carrying its own host and a Kratos
        // path; the proxy must rewrite it to the branded gateway surface.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let location = format!("http://{addr}/self-service/settings/browser?flow=1");
        tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/self-service/login/browser",
                    get(|| async move {
                        (
                            StatusCode::SEE_OTHER,
                            [(axum::http::header::LOCATION, location)],
                            "",
                        )
                    }),
                ),
            )
            .await
            .unwrap();
        });
        let upstream = format!("http://{addr}");

        let store = Arc::new(StubTransientStore::default());
        let state = test_state_with_store(upstream, store.clone());
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/identity/login?aal=aal2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        // The path is branded and the raw flow id is swapped for the public
        // mapping minted under the system tenant.
        let public = store.public_for("1").expect("flow id should be mapped");
        assert_eq!(
            location,
            format!("https://gateway.example.com/identity/settings?flow={public}")
        );
    }

    #[tokio::test]
    async fn upstream_redirect_flow_id_is_minted_and_resolvable() {
        // SSO-041: Kratos answers the browser flow init with a 303 to the
        // login UI URL carrying the raw Kratos flow UUID. The proxy must mint
        // the transient mapping and relay the public ULID instead, so the
        // RPC surface (resolve_flow) can resolve the flow the browser was
        // sent to. The UI URL is application-owned: host and unrelated
        // parameters are preserved.
        let raw_flow_id = "7b8a5f2e-7b7a-4c7a-9a5b-9f0e6c3d2b1a";
        let location =
            format!("https://ui.example.com/login?flow={raw_flow_id}&aal=aal2&refresh=true");
        let upstream_origin = spawn_upstream(Router::new().route(
            "/self-service/login/browser",
            get(|| async move {
                (
                    StatusCode::SEE_OTHER,
                    [(axum::http::header::LOCATION, location)],
                    "",
                )
            }),
        ))
        .await;

        let store = Arc::new(StubTransientStore::default());
        let state = test_state_with_store(upstream_origin, store.clone());
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/identity/login?aal=aal2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();

        let public = store
            .public_for(raw_flow_id)
            .expect("proxy should have minted a flow mapping");
        assert_ne!(public, raw_flow_id);
        assert_eq!(
            location,
            format!("https://ui.example.com/login?flow={public}&aal=aal2&refresh=true")
        );
        // The mapping is minted under the system tenant: the proxy serves
        // browsers, which carry no tenant context.
        let (tenant, ory) = store
            .get_ory_token_global(BACKEND_KRATOS, TOKEN_TYPE_FLOW, &public)
            .await
            .unwrap();
        assert_eq!(tenant, SYSTEM_TENANT);
        assert_eq!(ory, raw_flow_id);
    }

    #[tokio::test]
    async fn upstream_redirect_without_flow_id_is_relayed_untouched() {
        let location = "https://ui.example.com/login?aal=aal2".to_string();
        let upstream_origin = spawn_upstream(Router::new().route(
            "/self-service/login/browser",
            get(|| async move {
                (
                    StatusCode::SEE_OTHER,
                    [(axum::http::header::LOCATION, location)],
                    "",
                )
            }),
        ))
        .await;

        let store = Arc::new(StubTransientStore::default());
        let state = test_state_with_store(upstream_origin, store.clone());
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/identity/login?aal=aal2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "https://ui.example.com/login?aal=aal2"
        );
        assert!(
            store.is_empty(),
            "no mapping should be minted for a flowless redirect"
        );
    }

    #[tokio::test]
    async fn upstream_redirect_flow_mapping_failure_is_bad_gateway() {
        // Relaying the raw Kratos flow id would recreate SSO-041 silently;
        // when the mapping cannot be minted the proxy fails the redirect
        // instead of leaking the backend identifier.
        let location =
            "https://ui.example.com/login?flow=7b8a5f2e-7b7a-4c7a-9a5b-9f0e6c3d2b1a".to_string();
        let upstream_origin = spawn_upstream(Router::new().route(
            "/self-service/login/browser",
            get(|| async move {
                (
                    StatusCode::SEE_OTHER,
                    [(axum::http::header::LOCATION, location)],
                    "",
                )
            }),
        ))
        .await;

        let store = Arc::new(StubTransientStore::default());
        store
            .fail_creates
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let state = test_state_with_store(upstream_origin, store);
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/identity/login?aal=aal2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn proxy_sets_forwarded_headers_upstream() {
        let upstream_origin = spawn_upstream(Router::new().route(
            "/self-service/login/browser",
            get(|headers: HeaderMap| async move {
                format!(
                    "{}|{}",
                    headers
                        .get("x-forwarded-host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default(),
                    headers
                        .get("x-forwarded-proto")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default(),
                )
            }),
        ))
        .await;

        let state = test_state(upstream_origin);
        let app = router(state);
        let response = app
            .oneshot(
                Request::get("/identity/login")
                    .header("host", "gateway.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes, "gateway.example.com|https");
    }

    #[tokio::test]
    async fn proxy_returns_bad_gateway_when_upstream_unreachable() {
        let state = test_state("http://127.0.0.1:1".to_string());
        let app = router(state);
        let response = app
            .oneshot(Request::get("/identity/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn kratos_init_route_is_not_registered_directly() {
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
        let upstream_origin = spawn_upstream(Router::new().route(
            "/.well-known/ory/webauthn.js",
            get(|| async {
                let mut headers = axum::http::HeaderMap::new();
                headers.append(
                    axum::http::header::SET_COOKIE,
                    "sunbeam_session=abc; Path=/; HttpOnly".parse().unwrap(),
                );
                headers.append(
                    axum::http::header::SET_COOKIE,
                    "csrf_token=def; Path=/; HttpOnly".parse().unwrap(),
                );
                (headers, "ok")
            }),
        ))
        .await;

        let state = test_state(upstream_origin.clone());
        let upstream_url =
            build_upstream_url(&upstream_origin, ".well-known/ory/webauthn.js").unwrap();
        let request = Request::get("/identity/webauthn.js")
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
                .any(|c| c.to_str().unwrap().starts_with("sunbeam_session="))
        );
        assert!(
            cookies
                .iter()
                .any(|c| c.to_str().unwrap().starts_with("csrf_token="))
        );
    }

    #[tokio::test]
    async fn proxy_request_forwards_incoming_cookie_to_upstream() {
        let upstream_origin = spawn_upstream(Router::new().route(
            "/.well-known/ory/webauthn.js",
            get(|headers: axum::http::HeaderMap| async move {
                headers
                    .get_all("cookie")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .collect::<Vec<_>>()
                    .join("|")
            }),
        ))
        .await;

        let state = test_state(upstream_origin.clone());
        let upstream_url =
            build_upstream_url(&upstream_origin, ".well-known/ory/webauthn.js").unwrap();
        let request = Request::get("/identity/webauthn.js")
            .header("cookie", "sunbeam_session=abc; csrf_token=def")
            .body(Body::empty())
            .unwrap();
        let response = proxy_request(state, request, upstream_url).await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let echoed = std::str::from_utf8(&bytes).unwrap();
        assert!(
            echoed.contains("sunbeam_session=abc"),
            "session cookie was not forwarded upstream: {echoed}"
        );
        assert!(
            echoed.contains("csrf_token=def"),
            "csrf cookie was not forwarded upstream: {echoed}"
        );
    }
}
