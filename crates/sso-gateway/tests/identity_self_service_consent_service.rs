use std::sync::Arc;

use axum::{
    Extension, Json, Router, middleware::from_fn, routing::get, routing::post, routing::put,
};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::{
    db::{
        IdMappingRepo, IdMappingStore, TOKEN_TYPE_CONSENT_CHALLENGE, TOKEN_TYPE_FLOW,
        TOKEN_TYPE_LOGOUT_CHALLENGE, TOKEN_TYPE_LOGOUT_TOKEN, TOKEN_TYPE_RECOVERY_TOKEN,
        TOKEN_TYPE_VERIFICATION_TOKEN, TransientTokenRepo, bootstrap_system_tenant, create_pool,
    },
    middleware::auth_middleware,
    proto::iam::v1::{IdentitySelfServiceExt, OAuth2ConsentServiceExt},
    services::{
        identity_self_service::IdentitySelfServiceImpl, oauth2_consent::OAuth2ConsentServiceImpl,
    },
    session_token::SessionTokenSigner,
};
use sso_ory_client::{HydraClient, KratosClient};
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};
use time::{Duration, OffsetDateTime};

mod support;

/// Seed a transient token mapping so integration tests can present opaque
/// public tokens at the API boundary while the mock backends continue to use
/// their fixed Ory identifiers.
async fn seed_token(
    transient: &TransientTokenRepo,
    tenant_id: &str,
    backend: &str,
    token_type: &str,
    ory_token: &str,
) -> String {
    transient
        .create(
            tenant_id,
            backend,
            token_type,
            ory_token,
            OffsetDateTime::now_utc() + Duration::seconds(3600),
        )
        .await
        .expect("transient token should be seeded")
}
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
        .route(
            "/self-service/recovery",
            get(kratos_submit_recovery_token).post(kratos_submit_flow),
        )
        .route("/self-service/verification/flows", get(kratos_get_flow))
        .route(
            "/self-service/verification",
            get(kratos_submit_verification_token).post(kratos_submit_flow),
        )
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

async fn kratos_submit_recovery_token(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> Result<
    (
        axum::http::StatusCode,
        axum::http::HeaderMap,
        Json<serde_json::Value>,
    ),
    axum::http::StatusCode,
> {
    let token = params.get("token").cloned().unwrap_or_default();
    let flow = params.get("flow").cloned().unwrap_or_default();
    if token != "valid-recovery-token" || flow != "recovery-flow-id" {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut resp_headers = axum::http::HeaderMap::new();
    resp_headers.append(
        "set-cookie",
        format!("ory_kratos_session=recovery-{csrf}; Path=/; HttpOnly")
            .parse()
            .unwrap(),
    );
    resp_headers.append(
        "set-cookie",
        "csrf_token_1234=abc; Path=/; HttpOnly".parse().unwrap(),
    );
    resp_headers.insert(
        "location",
        "https://ui.example.com/settings?flow=3fa85f64-5717-4562-b3fc-2c963f66afa6&foo=bar"
            .parse()
            .unwrap(),
    );
    Ok((
        axum::http::StatusCode::SEE_OTHER,
        resp_headers,
        Json(json!({})),
    ))
}

async fn kratos_submit_verification_token(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> Result<
    (
        axum::http::StatusCode,
        axum::http::HeaderMap,
        Json<serde_json::Value>,
    ),
    axum::http::StatusCode,
> {
    let token = params.get("token").cloned().unwrap_or_default();
    let flow = params.get("flow").cloned().unwrap_or_default();
    if token != "valid-verification-token" || flow != "verification-flow-id" {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }
    let cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut resp_headers = axum::http::HeaderMap::new();
    resp_headers.insert(
        "set-cookie",
        "ory_kratos_session=verification; Path=/; HttpOnly"
            .parse()
            .unwrap(),
    );
    resp_headers.insert(
        "location",
        format!("https://ui.example.com/welcome?verified={cookie}")
            .parse()
            .unwrap(),
    );
    Ok((
        axum::http::StatusCode::SEE_OTHER,
        resp_headers,
        Json(json!({})),
    ))
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

    let pool = create_pool(&database_url, false)
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
    mappings
        .create(&system_tenant_ulid, "hydra", "public-client-1", "client-1")
        .await
        .expect("client mapping should be created");
    mappings
        .create(
            &system_tenant_ulid,
            "kratos",
            "public-subject-1",
            "subject-1",
        )
        .await
        .expect("subject mapping should be created");
    support::bootstrap_test_subject_mapping(&pool, &system_tenant_ulid).await;

    let transient = TransientTokenRepo::new(pool.clone());
    let pub_flow = seed_token(
        &transient,
        &system_tenant_ulid,
        "kratos",
        TOKEN_TYPE_FLOW,
        "flow-1",
    )
    .await;
    let pub_recovery_flow = seed_token(
        &transient,
        &system_tenant_ulid,
        "kratos",
        TOKEN_TYPE_FLOW,
        "recovery-flow-id",
    )
    .await;
    let pub_verification_flow = seed_token(
        &transient,
        &system_tenant_ulid,
        "kratos",
        TOKEN_TYPE_FLOW,
        "verification-flow-id",
    )
    .await;
    let pub_error = seed_token(
        &transient,
        &system_tenant_ulid,
        "kratos",
        TOKEN_TYPE_FLOW,
        "error-1",
    )
    .await;
    let pub_consent = seed_token(
        &transient,
        &system_tenant_ulid,
        "hydra",
        TOKEN_TYPE_CONSENT_CHALLENGE,
        "challenge-1",
    )
    .await;
    let pub_logout_challenge = seed_token(
        &transient,
        &system_tenant_ulid,
        "hydra",
        TOKEN_TYPE_LOGOUT_CHALLENGE,
        "logout-1",
    )
    .await;
    let pub_logout_token = seed_token(
        &transient,
        &system_tenant_ulid,
        "kratos",
        TOKEN_TYPE_LOGOUT_TOKEN,
        "token-1",
    )
    .await;
    let pub_recovery_token = seed_token(
        &transient,
        &system_tenant_ulid,
        "kratos",
        TOKEN_TYPE_RECOVERY_TOKEN,
        "valid-recovery-token",
    )
    .await;
    let pub_verification_token = seed_token(
        &transient,
        &system_tenant_ulid,
        "kratos",
        TOKEN_TYPE_VERIFICATION_TOKEN,
        "valid-verification-token",
    )
    .await;

    let self_service = Arc::new(IdentitySelfServiceImpl::new(
        kratos.clone(),
        TransientTokenRepo::new(pool.clone()),
        mappings.clone(),
        sso_gateway::db::IdentitySchemaRepo::new(pool.clone()),
        sso_gateway::db::TenantMembershipRepo::new(pool.clone()),
        true,
        kratos_url.clone(),
        "http://gateway.test".to_string(),
        "default".to_string(),
    ));
    let consent_service = Arc::new(OAuth2ConsentServiceImpl::new(
        hydra.clone(),
        TransientTokenRepo::new(pool.clone()),
        mappings.clone(),
    ));

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
        .layer(Extension(SessionTokenSigner::new(
            "test-secret-that-is-at-least-32-bytes-long",
            3600,
            "https://gateway.example.com",
        )))
        .layer(Extension(support::test_introspector()))
        .layer(Extension(support::test_session_store()))
        .layer(Extension(kratos))
        .layer(Extension(Arc::new(mappings) as Arc<dyn IdMappingStore>));

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

    // IdentitySelfService::ToSession
    let resp = client
        .post(format!("{base}/iam.v1.IdentitySelfService/ToSession"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": &pub_flow }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": &pub_flow, "body": { "identifier": "a" } }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": &pub_flow }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": &pub_flow, "body": { "traits": { "email": "a@b.com" } } }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": &pub_flow }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": &pub_flow, "body": { "method": "password", "password": "hunter2hunter2" } }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": &pub_flow }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": &pub_flow, "body": { "email": "a@b.com" } }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": &pub_flow }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": &pub_flow, "body": { "code": "123456" } }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
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

    // IdentitySelfService::SubmitRecoveryToken
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/SubmitRecoveryToken"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .header("x-csrf-token", "csrf-1")
        .json(&json!({ "token": &pub_recovery_token, "flow": &pub_recovery_flow }))
        .send()
        .await
        .expect("submit_recovery_token request should succeed");
    assert!(
        resp.status().is_success(),
        "submit_recovery_token failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let recovery_cookies: Vec<_> = resp.headers().get_all("set-cookie").iter().collect();
    assert!(
        recovery_cookies
            .iter()
            .any(|v| v.to_str().unwrap_or("").contains("ory_kratos_session")),
        "submit_recovery_token should propagate Set-Cookie headers"
    );
    let recovery_submit: serde_json::Value = resp
        .json()
        .await
        .expect("submit_recovery_token response should be json");
    let redirect_to = recovery_submit["redirectTo"]
        .as_str()
        .expect("redirectTo should be a string");
    let redirect = reqwest::Url::parse(redirect_to).expect("redirectTo should be a URL");
    assert_eq!(redirect.host_str(), Some("ui.example.com"));
    assert_eq!(redirect.path(), "/settings");
    let redirect_pairs: std::collections::HashMap<_, _> =
        redirect.query_pairs().into_owned().collect();
    assert_eq!(redirect_pairs.get("foo").map(String::as_str), Some("bar"));
    let continuation_flow = redirect_pairs
        .get("flow")
        .expect("redirectTo should carry a flow param");
    assert_ne!(
        continuation_flow, "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        "redirectTo must not leak the raw Kratos flow id"
    );
    assert!(
        ulid::Ulid::from_string(continuation_flow).is_ok(),
        "flow param should be a public ULID, got {continuation_flow}"
    );
    assert!(!redirect_to.contains("3fa85f64-5717-4562-b3fc-2c963f66afa6"));

    // The scrubbed continuation must round-trip: GetSettingsFlow resolves the
    // public ULID back to the Kratos settings flow.
    let resp = client
        .post(format!("{base}/iam.v1.IdentitySelfService/GetSettingsFlow"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "id": continuation_flow }))
        .send()
        .await
        .expect("get_settings_flow continuation request should succeed");
    assert!(
        resp.status().is_success(),
        "get_settings_flow continuation failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let settings_flow: serde_json::Value = resp
        .json()
        .await
        .expect("get_settings_flow continuation response should be json");
    assert_eq!(
        settings_flow["id"].as_str().unwrap_or(""),
        continuation_flow,
        "GetSettingsFlow should echo the public flow ULID"
    );

    // IdentitySelfService::SubmitVerificationToken
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/SubmitVerificationToken"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "token": &pub_verification_token, "flow": &pub_verification_flow }))
        .send()
        .await
        .expect("submit_verification_token request should succeed");
    assert!(
        resp.status().is_success(),
        "submit_verification_token failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let verification_submit: serde_json::Value = resp
        .json()
        .await
        .expect("submit_verification_token response should be json");
    assert!(
        verification_submit["redirectTo"]
            .as_str()
            .unwrap_or("")
            .contains("https://ui.example.com/welcome?verified="),
        "unexpected redirect: {}",
        verification_submit["redirectTo"].as_str().unwrap_or("")
    );

    // IdentitySelfService::CreateLogoutFlow
    let resp = client
        .post(format!(
            "{base}/iam.v1.IdentitySelfService/CreateLogoutFlow"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .header("cookie", "ory_kratos_session=abc")
        .json(&json!({ "token": &pub_logout_token }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": &pub_error }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "challenge": &pub_consent }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "challenge": &pub_consent, "grantScope": ["openid"] }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "challenge": &pub_consent, "error": "access_denied" }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "challenge": &pub_logout_challenge }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "challenge": &pub_logout_challenge }))
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
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "challenge": &pub_logout_challenge, "error": "invalid_request" }))
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
