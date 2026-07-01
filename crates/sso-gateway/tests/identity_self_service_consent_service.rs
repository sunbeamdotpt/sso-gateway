use std::sync::Arc;

use axum::{
    Extension, Json, Router, middleware::from_fn, routing::get, routing::post, routing::put,
};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::{
    db::{IdMappingRepo, TenantApiKeyRepo, bootstrap_system_tenant, create_pool},
    middleware::auth_middleware,
    proto::iam::v1::{IdentitySelfServiceExt, OAuth2ConsentServiceExt},
    services::{
        identity_self_service::IdentitySelfServiceImpl, oauth2_consent::OAuth2ConsentServiceImpl,
    },
};
use sso_ory_client::{HydraClient, KratosClient};
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};

mod support;

fn kratos_app() -> Router {
    Router::new()
        .route("/sessions/whoami", get(kratos_whoami))
        .route("/self-service/login/flows", get(kratos_get_flow))
        .route("/self-service/login", post(kratos_submit_flow))
        .route("/self-service/registration/flows", get(kratos_get_flow))
        .route("/self-service/registration", post(kratos_submit_flow))
        .route("/self-service/settings/flows", get(kratos_get_flow))
        .route("/self-service/settings", post(kratos_submit_flow))
        .route("/self-service/recovery/flows", get(kratos_get_flow))
        .route("/self-service/recovery", post(kratos_submit_flow))
        .route("/self-service/verification/flows", get(kratos_get_flow))
        .route("/self-service/verification", post(kratos_submit_flow))
        .route("/self-service/{flow}/browser", get(kratos_get_flow))
        .route(
            "/self-service/logout/browser",
            get(kratos_create_logout_flow),
        )
        .route("/self-service/logout", get(kratos_submit_logout_flow))
        .route("/self-service/errors", get(kratos_get_flow_error))
        .route("/.well-known/ory/webauthn.js", get(kratos_webauthn_js))
}

async fn kratos_whoami(headers: axum::http::HeaderMap) -> Json<serde_json::Value> {
    let cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    Json(json!({
        "id": "session-1",
        "active": true,
        "identity": {
            "id": "identity-1",
            "traits": { "email": "user@example.com" }
        },
        "cookie": cookie,
    }))
}

async fn kratos_get_flow(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> (
    axum::http::StatusCode,
    axum::http::HeaderMap,
    Json<serde_json::Value>,
) {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "set-cookie",
        "ory_kratos_session=mock; Path=/; HttpOnly".parse().unwrap(),
    );
    (
        axum::http::StatusCode::OK,
        headers,
        Json(json!({
            "id": params.get("id").cloned().unwrap_or_else(|| "flow-1".into()),
            "type": "login",
            "state": "choose_method",
            "ui": {
                "action": "http://action",
                "method": "POST",
                "nodes": [
                    {
                        "type": "input",
                        "group": "password",
                        "attributes": {
                            "node_type": "input",
                            "name": "password",
                            "type": "password"
                        }
                    }
                ]
            }
        })),
    )
}

async fn kratos_submit_flow(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    Json(_body): Json<serde_json::Value>,
) -> (
    axum::http::StatusCode,
    axum::http::HeaderMap,
    Json<serde_json::Value>,
) {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "set-cookie",
        "ory_kratos_session=mock; Path=/; HttpOnly".parse().unwrap(),
    );
    (
        axum::http::StatusCode::OK,
        headers,
        Json(json!({
            "id": params.get("flow").cloned().unwrap_or_else(|| "flow-1".into()),
            "type": "login",
            "state": "passed_challenge"
        })),
    )
}

async fn kratos_create_logout_flow() -> (
    axum::http::StatusCode,
    axum::http::HeaderMap,
    Json<serde_json::Value>,
) {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "set-cookie",
        "ory_kratos_session=; Path=/; Max-Age=0; HttpOnly"
            .parse()
            .unwrap(),
    );
    (
        axum::http::StatusCode::OK,
        headers,
        Json(json!({
            "id": "logout-1",
            "logout_url": "http://logout",
            "logout_token": "token-1"
        })),
    )
}

async fn kratos_submit_logout_flow() -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}

async fn kratos_get_flow_error(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    Json(json!({
        "id": params.get("id").cloned().unwrap_or_default(),
        "error": { "message": "oops" }
    }))
}

async fn kratos_webauthn_js() -> &'static str {
    "console.log('webauthn');"
}

fn hydra_app() -> Router {
    Router::new()
        .route(
            "/admin/oauth2/auth/requests/consent",
            get(hydra_get_consent),
        )
        .route(
            "/admin/oauth2/auth/requests/consent/accept",
            put(hydra_accept_consent),
        )
        .route(
            "/admin/oauth2/auth/requests/consent/reject",
            put(hydra_reject_consent),
        )
        .route("/admin/oauth2/auth/requests/logout", get(hydra_get_logout))
        .route(
            "/admin/oauth2/auth/requests/logout/accept",
            put(hydra_accept_logout),
        )
        .route(
            "/admin/oauth2/auth/requests/logout/reject",
            put(hydra_reject_logout),
        )
}

async fn hydra_get_consent(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    Json(json!({
        "challenge": params.get("consent_challenge").cloned().unwrap_or_default(),
        "client": { "client_id": "client-1", "client_name": "App" },
        "subject": "subject-1",
        "requested_scope": ["openid"],
        "skip": false
    }))
}

async fn hydra_accept_consent() -> Json<serde_json::Value> {
    Json(json!({ "redirect_to": "http://redirect" }))
}

async fn hydra_reject_consent() -> Json<serde_json::Value> {
    Json(json!({ "redirect_to": "http://redirect" }))
}

async fn hydra_get_logout(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    Json(json!({
        "challenge": params.get("logout_challenge").cloned().unwrap_or_default(),
        "subject": "subject-1",
        "client": { "client_id": "client-1" }
    }))
}

async fn hydra_accept_logout() -> Json<serde_json::Value> {
    Json(json!({ "redirect_to": "http://redirect" }))
}

async fn hydra_reject_logout() -> Json<serde_json::Value> {
    Json(json!({ "redirect_to": "http://redirect" }))
}

async fn start_mock_kratos() -> (tokio::task::JoinHandle<()>, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, kratos_app()).await.unwrap();
    });
    (handle, format!("http://{addr}"))
}

async fn start_mock_hydra() -> (tokio::task::JoinHandle<()>, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, hydra_app()).await.unwrap();
    });
    (handle, format!("http://{addr}"))
}

#[tokio::test]
async fn self_service_and_consent_round_trip() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_kratos_handle, kratos_url) = start_mock_kratos().await;
    let (_hydra_handle, hydra_url) = start_mock_hydra().await;

    let pool = create_pool(&database_url)
        .await
        .expect("database pool should be created");
    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");

    let kratos = Arc::new(
        KratosClient::new_with_public(&kratos_url, &kratos_url)
            .expect("kratos client should build"),
    );
    let hydra =
        Arc::new(HydraClient::new(&hydra_url, &hydra_url).expect("hydra client should build"));
    let mappings = IdMappingRepo::new(pool.clone());
    mappings
        .create(&system_tenant_ulid, "kratos", "public-1", "identity-1")
        .await
        .expect("mapping should be created");
    let api_keys = TenantApiKeyRepo::new(pool);

    let self_service = Arc::new(IdentitySelfServiceImpl::new(kratos.clone()));
    let consent_service = Arc::new(OAuth2ConsentServiceImpl::new(hydra.clone()));

    let connect_router: ConnectRouter = self_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = consent_service.register(connect_router);
    let service_router = ServiceRouter::from_router(connect_router);

    let server = ServerBuilder::new()
        .with_router(service_router)
        .with_health(HealthRouter::new())
        .build_axum()
        .expect("server should build");

    let app = server
        .app()
        .layer(from_fn(auth_middleware))
        .layer(Extension(api_keys))
        .layer(Extension(kratos))
        .layer(Extension(mappings));

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let tenant_header = &system_tenant_ulid;

    // IdentitySelfService::ToSession
    let resp = client
        .post(format!("{base}/iam.v1.IdentitySelfService/ToSession"))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({}))
        .send()
        .await
        .expect("to_session request should succeed");
    assert!(
        resp.status().is_success(),
        "to_session failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::GetLoginFlow
    let resp = client
        .post(format!("{base}/iam.v1.IdentitySelfService/GetLoginFlow"))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": "flow-1" }))
        .send()
        .await
        .expect("get_login_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "get_login_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );
    assert!(
        resp.headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap_or("").contains("ory_kratos_session")),
        "get_login_flow should propagate Set-Cookie headers"
    );

    // IdentitySelfService::SubmitLoginFlow
    let resp = client
        .post(format!("{base}/iam.v1.IdentitySelfService/SubmitLoginFlow"))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": "flow-1", "body": { "identifier": "a" } }))
        .send()
        .await
        .expect("submit_login_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "submit_login_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );
    assert!(
        resp.headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap_or("").contains("ory_kratos_session")),
        "submit_login_flow should propagate Set-Cookie headers"
    );

    // IdentitySelfService::CreateLoginFlow
    let resp = client
        .post(format!("{base}/iam.v1.IdentitySelfService/CreateLoginFlow"))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "returnTo": "http://return" }))
        .send()
        .await
        .expect("create_login_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "create_login_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let set_cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().collect();
    assert!(
        set_cookies
            .iter()
            .any(|v| v.to_str().unwrap_or("").contains("ory_kratos_session")),
        "create_login_flow should propagate Set-Cookie headers"
    );

    // IdentitySelfService::CreateRegistrationFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/CreateRegistrationFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "returnTo": "http://return" }))
        .send()
        .await
        .expect("create_registration_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "create_registration_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::CreateSettingsFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/CreateSettingsFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "returnTo": "http://return" }))
        .send()
        .await
        .expect("create_settings_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "create_settings_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::CreateRecoveryFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/CreateRecoveryFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "returnTo": "http://return" }))
        .send()
        .await
        .expect("create_recovery_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "create_recovery_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::GetRegistrationFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/GetRegistrationFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": "flow-1" }))
        .send()
        .await
        .expect("get_registration_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "get_registration_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::SubmitRegistrationFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/SubmitRegistrationFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": "flow-1", "body": { "traits": { "email": "a@b.com" } } }))
        .send()
        .await
        .expect("submit_registration_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "submit_registration_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::GetSettingsFlow
    let resp = client
        .post(format!("{base}/iam.v1.IdentitySelfService/GetSettingsFlow"))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": "flow-1" }))
        .send()
        .await
        .expect("get_settings_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "get_settings_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::SubmitSettingsFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/SubmitSettingsFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": "flow-1", "body": { "traits": {} } }))
        .send()
        .await
        .expect("submit_settings_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "submit_settings_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::GetRecoveryFlow
    let resp = client
        .post(format!("{base}/iam.v1.IdentitySelfService/GetRecoveryFlow"))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": "flow-1" }))
        .send()
        .await
        .expect("get_recovery_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "get_recovery_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::SubmitRecoveryFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/SubmitRecoveryFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": "flow-1", "body": { "email": "a@b.com" } }))
        .send()
        .await
        .expect("submit_recovery_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "submit_recovery_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::GetVerificationFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/GetVerificationFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": "flow-1" }))
        .send()
        .await
        .expect("get_verification_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "get_verification_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::SubmitVerificationFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/SubmitVerificationFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": "flow-1", "body": { "code": "123456" } }))
        .send()
        .await
        .expect("submit_verification_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "submit_verification_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::CreateVerificationFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/CreateVerificationFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "returnTo": "http://return" }))
        .send()
        .await
        .expect("create_verification_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "create_verification_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::CreateLogoutFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/CreateLogoutFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "returnTo": "http://return" }))
        .send()
        .await
        .expect("create_logout_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "create_logout_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );
    assert!(
        resp.headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap_or("").contains("ory_kratos_session")),
        "create_logout_flow should propagate Set-Cookie headers"
    );

    // IdentitySelfService::SubmitLogoutFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/SubmitLogoutFlow"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "token": "token-1" }))
        .send()
        .await
        .expect("submit_logout_flow request should succeed");
    assert!(
        resp.status().is_success(),
        "submit_logout_flow failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::GetFlowError
    let resp = client
        .post(format!("{base}/iam.v1.IdentitySelfService/GetFlowError"))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .json(&json!({ "id": "error-1" }))
        .send()
        .await
        .expect("get_flow_error request should succeed");
    assert!(
        resp.status().is_success(),
        "get_flow_error failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // IdentitySelfService::GetWebAuthnJavaScript
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/GetWebAuthnJavaScript"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("get_webauthn_js request should succeed");
    assert!(
        resp.status().is_success(),
        "get_webauthn_js failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // OAuth2ConsentService::GetConsentRequest
    let resp = client
        .post(format!(
            "{base}/iam.v1.OAuth2ConsentService/GetConsentRequest"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .json(&json!({ "challenge": "challenge-1" }))
        .send()
        .await
        .expect("get_consent_request request should succeed");
    assert!(
        resp.status().is_success(),
        "get_consent_request failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // OAuth2ConsentService::AcceptConsent
    let resp = client
        .post(format!("{base}/iam.v1.OAuth2ConsentService/AcceptConsent"))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .json(&json!({ "challenge": "challenge-1", "grantScope": ["openid"] }))
        .send()
        .await
        .expect("accept_consent request should succeed");
    assert!(
        resp.status().is_success(),
        "accept_consent failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // OAuth2ConsentService::RejectConsent
    let resp = client
        .post(format!("{base}/iam.v1.OAuth2ConsentService/RejectConsent"))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .json(&json!({ "challenge": "challenge-1", "error": "access_denied" }))
        .send()
        .await
        .expect("reject_consent request should succeed");
    assert!(
        resp.status().is_success(),
        "reject_consent failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // OAuth2ConsentService::GetLogoutRequest
    let resp = client
        .post(format!(
            "{base}/iam.v1.OAuth2ConsentService/GetLogoutRequest"
        ))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .json(&json!({ "challenge": "logout-1" }))
        .send()
        .await
        .expect("get_logout_request request should succeed");
    assert!(
        resp.status().is_success(),
        "get_logout_request failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // OAuth2ConsentService::AcceptLogout
    let resp = client
        .post(format!("{base}/iam.v1.OAuth2ConsentService/AcceptLogout"))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .json(&json!({ "challenge": "logout-1" }))
        .send()
        .await
        .expect("accept_logout request should succeed");
    assert!(
        resp.status().is_success(),
        "accept_logout failed: {}",
        resp.text().await.unwrap_or_default()
    );

    // OAuth2ConsentService::RejectLogout
    let resp = client
        .post(format!("{base}/iam.v1.OAuth2ConsentService/RejectLogout"))
        .header("x-tenant-id", tenant_header)
        .header("content-type", "application/json")
        .json(&json!({ "challenge": "logout-1", "error": "invalid_request" }))
        .send()
        .await
        .expect("reject_logout request should succeed");
    assert!(
        resp.status().is_success(),
        "reject_logout failed: {}",
        resp.text().await.unwrap_or_default()
    );

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
