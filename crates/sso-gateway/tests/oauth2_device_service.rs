// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)
)]

use std::sync::Arc;

use axum::{Extension, middleware::from_fn};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::session_token::SessionTokenSigner;
use sso_gateway::{
    db::{IdMappingRepo, IdMappingStore, TransientTokenRepo, bootstrap_system_tenant, create_pool},
    middleware::auth_middleware,
    proto::iam::v1::OAuth2DeviceServiceExt,
    services::handlers::oauth2::{Oauth2State, router as oauth2_router},
    services::oauth2_device::OAuth2DeviceServiceImpl,
};
use sso_ory_client::{HydraClient, KratosClient};
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};

mod support;

/// Full RFC 8628 device verification round trip against a real Hydra v25.4.0:
/// AuthorizeDevice → GetDeviceVerification (challenge mint + CSRF cookie) →
/// AcceptDeviceVerification (challenge resolve + redirect_to scrub) → the
/// browser verifier leg through the gateway's `/oauth2/device/verify` proxy.
#[tokio::test]
async fn oauth2_device_verification_round_trip() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");
    let base = format!("http://{addr}");

    // Hydra's public URL falls back to the issuer, so pointing the issuer at
    // the gateway makes Hydra build its device RequestURL (the URL its accept
    // response redirects the browser to) against the gateway's proxy route.
    let (_hydra, hydra_admin_url, hydra_public_url) = support::start_hydra_with_issuer(&base)
        .await
        .expect("hydra should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");
    support::bootstrap_test_subject_mapping(&pool, &system_tenant_ulid).await;

    let hydra = Arc::new(
        HydraClient::new(&hydra_admin_url, &hydra_public_url).expect("hydra client should build"),
    );
    let mappings = IdMappingRepo::new(pool.clone());

    // Register a public device-grant client directly in Hydra and seed the
    // gateway mapping so only the public ULID crosses the API boundary.
    let client = reqwest::Client::new();
    let ory_client_id = "device-client-1";
    let create_client = client
        .post(format!("{hydra_admin_url}/admin/clients"))
        .json(&json!({
            "client_id": ory_client_id,
            "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
            "response_types": ["token"],
            "token_endpoint_auth_method": "none",
            "scope": "openid"
        }))
        .send()
        .await
        .expect("hydra client create request should complete");
    assert!(
        create_client.status().is_success(),
        "hydra client create failed: {}",
        create_client.text().await.unwrap_or_default()
    );

    let public_client_id = ulid::Ulid::new().to_string();
    mappings
        .create(
            &system_tenant_ulid,
            "hydra",
            &public_client_id,
            ory_client_id,
        )
        .await
        .expect("client mapping should be created");

    let device_service = Arc::new(OAuth2DeviceServiceImpl::new(
        hydra.clone(),
        mappings.clone(),
        TransientTokenRepo::new(pool.clone()),
    ));

    let connect_router: ConnectRouter = device_service.register(ConnectRouter::new());
    let service_router = ServiceRouter::from_router(connect_router);

    let oauth_state = Arc::new(Oauth2State::new(
        hydra,
        mappings.clone(),
        base.clone(),
        sso_gateway::services::entitlement::test_helpers::entitlements(),
        Arc::new(sso_gateway::db::MemoryApplicationStore::default()),
        std::time::Duration::from_secs(604_800),
    ));

    let server = ServerBuilder::new()
        .with_router(service_router)
        .with_health(HealthRouter::new())
        .build_axum()
        .expect("server should build");

    let kratos = Arc::new(
        KratosClient::new_with_public("http://localhost:1", "http://localhost:1")
            .expect("fake kratos client should build"),
    );

    let app = server
        .app()
        .merge(oauth2_router(oauth_state))
        .layer(from_fn(auth_middleware))
        .layer(Extension(SessionTokenSigner::new(
            "test-secret-that-is-at-least-32-bytes-long",
            3600,
            "https://gateway.example.com",
        )))
        .layer(Extension(support::test_introspector()))
        .layer(Extension(support::test_session_store()))
        .layer(Extension(kratos))
        .layer(Extension(
            Arc::new(mappings.clone()) as Arc<dyn IdMappingStore>
        ));

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });

    // 1. The device initiates the flow.
    let resp = client
        .post(format!("{base}/iam.v1.OAuth2DeviceService/AuthorizeDevice"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "clientId": public_client_id, "scope": ["openid"] }))
        .send()
        .await
        .expect("authorize_device request should complete");
    assert!(
        resp.status().is_success(),
        "authorize_device failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let auth: serde_json::Value = resp.json().await.expect("response should be json");
    let device_code = auth["deviceCode"]
        .as_str()
        .expect("deviceCode should exist");
    let user_code = auth["userCode"].as_str().expect("userCode should exist");
    assert!(!device_code.is_empty());
    assert!(!user_code.is_empty());

    // 2. Polling before the user approved the code must fail with
    // authorization_pending.
    let resp = client
        .post(format!("{base}/iam.v1.OAuth2DeviceService/GetDeviceToken"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "clientId": public_client_id, "deviceCode": device_code }))
        .send()
        .await
        .expect("get_device_token request should complete");
    assert!(
        resp.status().is_client_error(),
        "polling before approval must not succeed"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("pending"),
        "expected an authorization_pending error, got: {body}"
    );

    // 3. The verification app exchanges the user code for a challenge. The
    // gateway mints an opaque ULID challenge and relays Hydra's device CSRF
    // cookie.
    let resp = client
        .post(format!(
            "{base}/iam.v1.OAuth2DeviceService/GetDeviceVerification"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "userCode": user_code }))
        .send()
        .await
        .expect("get_device_verification request should complete");
    assert!(
        resp.status().is_success(),
        "get_device_verification failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let set_cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();
    assert!(
        !set_cookies.is_empty(),
        "get_device_verification should forward Hydra's device CSRF cookie"
    );
    let cookie_header = set_cookies
        .iter()
        .filter_map(|c| c.split(';').next().map(str::to_owned))
        .collect::<Vec<_>>()
        .join("; ");
    let verification: serde_json::Value = resp.json().await.expect("response should be json");
    let challenge = verification["challenge"]
        .as_str()
        .expect("challenge should exist");
    assert!(
        ulid::Ulid::from_string(challenge).is_ok(),
        "challenge should be an opaque ULID, got {challenge}"
    );
    assert_eq!(
        verification["userCode"].as_str(),
        Some(user_code),
        "user code should be echoed"
    );

    // 4. The verification app approves the code. The returned redirect carries
    // the device verifier and must point at the gateway with the public client
    // id — never at Hydra, never with the backend client id.
    let resp = client
        .post(format!(
            "{base}/iam.v1.OAuth2DeviceService/AcceptDeviceVerification"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "challenge": challenge, "userCode": user_code }))
        .send()
        .await
        .expect("accept_device_verification request should complete");
    assert!(
        resp.status().is_success(),
        "accept_device_verification failed: {}",
        resp.text().await.unwrap_or_default()
    );
    let accepted: serde_json::Value = resp.json().await.expect("response should be json");
    let redirect_to = accepted["redirectTo"]
        .as_str()
        .expect("redirectTo should exist");
    assert!(
        redirect_to.starts_with(&base),
        "redirectTo should point at the gateway, got {redirect_to}"
    );
    assert!(
        !redirect_to.contains(ory_client_id),
        "redirectTo must not leak the Hydra client id: {redirect_to}"
    );
    let redirect = reqwest::Url::parse(redirect_to).expect("redirectTo should be a URL");
    let redirect_pairs: std::collections::HashMap<_, _> =
        redirect.query_pairs().into_owned().collect();
    assert!(
        redirect_pairs
            .get("device_verifier")
            .is_some_and(|v| !v.is_empty()),
        "redirectTo should carry a device_verifier"
    );
    assert_eq!(
        redirect_pairs.get("client_id").map(String::as_str),
        Some(public_client_id.as_str()),
        "redirectTo should carry the public client id"
    );

    // 5. The browser follows redirectTo through the gateway proxy with the
    // device CSRF cookie. Hydra validates the verifier and cookie, then chains
    // into the login flow.
    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client should build");
    let resp = no_redirect
        .get(redirect_to)
        .header("cookie", &cookie_header)
        .send()
        .await
        .expect("device verify leg should complete");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FOUND,
        "device verify leg should redirect into the login flow"
    );
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        location.contains("login_challenge="),
        "device verify leg should chain into login, got: {location}"
    );

    // 6. Without the CSRF cookie the verifier leg must fail — this is the
    // "No CSRF value available in the session cookie" guard.
    let resp = no_redirect
        .get(redirect_to)
        .send()
        .await
        .expect("device verify leg without cookie should complete");
    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "device verify leg without the CSRF cookie must be rejected, got {}",
        resp.status()
    );

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
