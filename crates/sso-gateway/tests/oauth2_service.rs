use std::sync::Arc;

use axum::{Extension, middleware::from_fn};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::session_token::SessionTokenSigner;
use sso_gateway::services::entitlement::test_helpers::entitlements;
use sso_gateway::{
    db::{ApplicationRepo, IdMappingRepo, IdMappingStore, TenantRepo, bootstrap_system_tenant, create_pool},
    middleware::auth_middleware,
    proto::iam::v1::{ApplicationServiceExt, TenantServiceExt},
    services::handlers::oauth2::{Oauth2State, router as oauth2_router},
    services::{application::ApplicationServiceImpl, tenant::TenantServiceImpl},
};
use sso_ory_client::{HydraClient, KratosClient};
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};

mod support;

#[tokio::test]
async fn oauth2_public_endpoints_round_trip() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");
    let base = format!("http://{addr}");

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
    let tenant_repo = TenantRepo::new(pool.clone());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
        entitlements(),
    ));
    let application_repo = ApplicationRepo::new(pool.clone());
    let application_service = Arc::new(ApplicationServiceImpl::new(
        hydra.clone(),
        mappings.clone(),
        application_repo,
        entitlements(),
        system_tenant_ulid.clone(),
    ));

    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = application_service.register(connect_router);
    let service_router = ServiceRouter::from_router(connect_router);

    let oauth_state = Arc::new(Oauth2State::new(hydra, mappings.clone(), base.clone()));

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

    let client = reqwest::Client::new();

    // Create an application for client-credentials grants.
    let create_resp = client
        .post(format!(
            "{base}/iam.v1.ApplicationService/CreateApplication"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "name": "oauth-test-app",
            "redirectUris": ["https://localhost/callback"],
            "grantTypes": ["client_credentials"],
            "responseTypes": ["token"],
            "scope": ["openid"],
            "tokenEndpointAuthMethod": "client_secret_post"
        }))
        .send()
        .await
        .expect("create application request should succeed");

    assert!(
        create_resp.status().is_success(),
        "create application failed: {}",
        create_resp.text().await.unwrap_or_default()
    );

    let app: serde_json::Value = create_resp
        .json()
        .await
        .expect("application should be json");
    let app_id = app["id"].as_str().expect("application id should exist");

    // The Hydra client_id is exposed through the RotateSecret RPC.
    let rotate_resp = client
        .post(format!("{base}/iam.v1.ApplicationService/RotateSecret"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": app_id }))
        .send()
        .await
        .expect("rotate secret request should succeed");
    assert!(
        rotate_resp.status().is_success(),
        "rotate secret failed: {}",
        rotate_resp.text().await.unwrap_or_default()
    );
    let rotated: serde_json::Value = rotate_resp.json().await.expect("secret should be json");
    let client_id = rotated["clientId"]
        .as_str()
        .expect("client_id should exist");
    let client_secret = rotated["clientSecret"]
        .as_str()
        .expect("client_secret should exist");

    // OpenID Connect discovery returns gateway URLs.
    let discovery_resp = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .expect("discovery request should succeed");
    assert!(discovery_resp.status().is_success(), "discovery failed");
    let discovery: serde_json::Value = discovery_resp
        .json()
        .await
        .expect("discovery should be json");
    assert_eq!(discovery["issuer"], base);
    assert_eq!(discovery["token_endpoint"], format!("{base}/oauth2/token"));

    // JWKS proxied from Hydra.
    let jwks_resp = client
        .get(format!("{base}/.well-known/jwks.json"))
        .send()
        .await
        .expect("jwks request should succeed");
    assert!(jwks_resp.status().is_success(), "jwks failed");
    let jwks: serde_json::Value = jwks_resp.json().await.expect("jwks should be json");
    assert!(jwks["keys"].is_array(), "jwks keys should be an array");

    // Token endpoint returns an access token for the registered client.
    let token_resp = client
        .post(format!("{base}/oauth2/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", "openid"),
        ])
        .send()
        .await
        .expect("token request should succeed");
    assert!(
        token_resp.status().is_success(),
        "token request failed: {}",
        token_resp.text().await.unwrap_or_default()
    );
    let token: serde_json::Value = token_resp.json().await.expect("token should be json");
    let access_token = token["access_token"]
        .as_str()
        .expect("access_token should exist");

    // Introspection is an admin endpoint; authenticate with the test token.
    let introspect_resp = client
        .post(format!("{base}/oauth2/introspect"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .form(&[("token", access_token)])
        .send()
        .await
        .expect("introspect request should succeed");
    assert!(introspect_resp.status().is_success(), "introspect failed");
    let introspect: serde_json::Value = introspect_resp
        .json()
        .await
        .expect("introspect should be json");
    assert_eq!(introspect["active"], true);
    assert_eq!(
        introspect["tenant_id"].as_str(),
        Some(system_tenant_ulid.as_str()),
        "introspection response must include the token's tenant_id"
    );

    // Regression (agent-mail #78): Hydra 4xx error bodies must be relayed
    // verbatim instead of being masked as `server_error`, so callers can see
    // e.g. which scope was rejected.
    let bad_scope_resp = client
        .post(format!("{base}/oauth2/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", "openid bogus:scope"),
        ])
        .send()
        .await
        .expect("bad-scope token request should complete");
    assert_eq!(
        bad_scope_resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "out-of-ceiling scope should be rejected"
    );
    let bad_scope: serde_json::Value = bad_scope_resp
        .json()
        .await
        .expect("error body should be json");
    assert_eq!(bad_scope["error"], "invalid_scope");
    assert!(
        bad_scope["error_description"]
            .as_str()
            .unwrap_or_default()
            .contains("bogus:scope"),
        "error_description must name the rejected scope: {bad_scope}"
    );

    // Same relay guarantee on the device authorization endpoint (the original
    // production repro from the `sunbeam auth login` incident).
    let device_app_resp = client
        .post(format!(
            "{base}/iam.v1.ApplicationService/CreateApplication"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "name": "oauth-device-app",
            "redirectUris": ["https://localhost/callback"],
            "grantTypes": ["urn:ietf:params:oauth:grant-type:device_code"],
            "responseTypes": ["token"],
            "scope": ["openid"],
            "tokenEndpointAuthMethod": "none"
        }))
        .send()
        .await
        .expect("create device application request should succeed");
    assert!(
        device_app_resp.status().is_success(),
        "create device application failed: {}",
        device_app_resp.text().await.unwrap_or_default()
    );
    let device_app: serde_json::Value = device_app_resp
        .json()
        .await
        .expect("device application should be json");
    let device_app_id = device_app["id"]
        .as_str()
        .expect("device application id should exist");

    let device_resp = client
        .post(format!("{base}/oauth2/device/auth"))
        .form(&[
            ("client_id", device_app_id),
            ("scope", "openid bogus:scope"),
        ])
        .send()
        .await
        .expect("device auth request should complete");
    assert_eq!(
        device_resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "device auth with bogus scope should be rejected"
    );
    let device_err: serde_json::Value = device_resp
        .json()
        .await
        .expect("device error body should be json");
    assert_eq!(device_err["error"], "invalid_scope");
    assert!(
        device_err["error_description"]
            .as_str()
            .unwrap_or_default()
            .contains("bogus:scope"),
        "device error_description must name the rejected scope: {device_err}"
    );

    // Unknown client_id is rejected.
    let unknown_auth_resp = client
        .get(format!("{base}/oauth2/auth"))
        .query(&[
            ("client_id", "unknown-client-id"),
            ("response_type", "token"),
        ])
        .send()
        .await
        .expect("authorize request should complete");
    assert!(
        unknown_auth_resp.status().is_client_error(),
        "unknown client_id should be rejected"
    );

    // Revoke the token.
    let revoke_resp = client
        .post(format!("{base}/oauth2/revoke"))
        .form(&[
            ("token", access_token),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await
        .expect("revoke request should succeed");
    assert!(
        revoke_resp.status().is_success(),
        "revoke failed: {}",
        revoke_resp.text().await.unwrap_or_default()
    );

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

#[tokio::test]
async fn oauth2_missing_client_id_is_rejected() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");
    let base = format!("http://{addr}");

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
    let tenant_repo = TenantRepo::new(pool.clone());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
        entitlements(),
    ));
    let application_repo = ApplicationRepo::new(pool.clone());
    let application_service = Arc::new(ApplicationServiceImpl::new(
        hydra.clone(),
        mappings.clone(),
        application_repo,
        entitlements(),
        system_tenant_ulid.clone(),
    ));

    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = application_service.register(connect_router);
    let service_router = ServiceRouter::from_router(connect_router);

    let oauth_state = Arc::new(Oauth2State::new(hydra, mappings.clone(), base.clone()));

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

    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{base}/oauth2/token"))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .expect("request should complete");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    let resp = client
        .get(format!("{base}/oauth2/userinfo"))
        .send()
        .await
        .expect("request should complete");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

/// SSO-013: RFC 7591 dynamic client registration is public (Matrix Element
/// registers anonymously), the CORS preflight never dies in the auth
/// middleware, and a registered client can introspect with its own
/// client_secret_basic credentials.
#[tokio::test]
async fn oauth2_dynamic_client_registration_is_public() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");
    let base = format!("http://{addr}");

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

    let oauth_state = Arc::new(
        Oauth2State::new(hydra, mappings.clone(), base.clone())
            .with_system_tenant_id(system_tenant_ulid.clone()),
    );

    let connect_router: ConnectRouter = ConnectRouter::new();
    let service_router = ServiceRouter::from_router(connect_router);

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

    let client = reqwest::Client::new();

    // The browser preflight must not hit the auth middleware.
    let preflight_resp = client
        .request(
            reqwest::Method::OPTIONS,
            format!("{base}/oauth2/register"),
        )
        .header("origin", "https://app.element.io")
        .header("access-control-request-method", "POST")
        .send()
        .await
        .expect("preflight request should complete");
    assert_eq!(
        preflight_resp.status(),
        reqwest::StatusCode::NO_CONTENT,
        "OPTIONS preflight must return 204"
    );
    assert_eq!(
        preflight_resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*")
    );
    assert_eq!(
        preflight_resp
            .headers()
            .get("access-control-allow-methods")
            .and_then(|v| v.to_str().ok()),
        Some("GET, POST, OPTIONS")
    );

    // Unauthenticated DCR succeeds; out-of-ceiling scopes are dropped.
    let register_resp = client
        .post(format!("{base}/oauth2/register"))
        .json(&json!({
            "client_name": "element-web",
            "redirect_uris": ["https://app.element.io/callback"],
            "grant_types": ["client_credentials"],
            "response_types": ["token"],
            "scope": "openid offline_access tenant:admin",
            "token_endpoint_auth_method": "client_secret_basic"
        }))
        .send()
        .await
        .expect("register request should complete");
    assert_eq!(
        register_resp.status(),
        reqwest::StatusCode::OK,
        "public DCR failed: {}",
        register_resp.text().await.unwrap_or_default()
    );
    let registered: serde_json::Value = register_resp
        .json()
        .await
        .expect("register response should be json");
    let client_id = registered["client_id"]
        .as_str()
        .expect("client_id should exist")
        .to_string();
    let client_secret = registered["client_secret"]
        .as_str()
        .expect("client_secret should exist")
        .to_string();
    assert_eq!(registered["scope"], "openid offline_access");

    // The discovery document advertises registration and PKCE.
    let discovery_resp = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .expect("discovery request should succeed");
    let discovery: serde_json::Value = discovery_resp
        .json()
        .await
        .expect("discovery should be json");
    assert_eq!(
        discovery["registration_endpoint"],
        format!("{base}/oauth2/register")
    );
    assert_eq!(
        discovery["introspection_endpoint"],
        format!("{base}/oauth2/introspect")
    );
    assert_eq!(
        discovery["code_challenge_methods_supported"],
        json!(["S256"])
    );

    // The registered client can get a token with the honored scopes.
    let token_resp = client
        .post(format!("{base}/oauth2/token"))
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[("grant_type", "client_credentials"), ("scope", "openid")])
        .send()
        .await
        .expect("token request should complete");
    assert_eq!(
        token_resp.status(),
        reqwest::StatusCode::OK,
        "token request failed: {}",
        token_resp.text().await.unwrap_or_default()
    );
    let token: serde_json::Value = token_resp.json().await.expect("token should be json");
    let access_token = token["access_token"]
        .as_str()
        .expect("access_token should exist");

    // ... and introspect it with its own client_secret_basic credentials,
    // no bearer token involved.
    let introspect_resp = client
        .post(format!("{base}/oauth2/introspect"))
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[("token", access_token)])
        .send()
        .await
        .expect("introspect request should complete");
    assert_eq!(
        introspect_resp.status(),
        reqwest::StatusCode::OK,
        "client-basic introspect failed: {}",
        introspect_resp.text().await.unwrap_or_default()
    );
    let introspect: serde_json::Value = introspect_resp
        .json()
        .await
        .expect("introspect should be json");
    assert_eq!(introspect["active"], true);
    assert_eq!(
        introspect["tenant_id"].as_str(),
        Some(system_tenant_ulid.as_str()),
        "client-basic introspection must resolve the system tenant"
    );
    assert_eq!(
        introspect["client_id"].as_str(),
        Some(client_id.as_str()),
        "client_id must be translated back to the public ULID"
    );

    // Bad client credentials are rejected by Hydra and relayed as 401.
    let bad_auth_resp = client
        .post(format!("{base}/oauth2/introspect"))
        .basic_auth(&client_id, Some("wrong-secret"))
        .form(&[("token", access_token)])
        .send()
        .await
        .expect("bad-auth introspect request should complete");
    assert_eq!(
        bad_auth_resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "bad client secret must yield 401"
    );

    // SSO-015 self-heal: a client whose id_mapping row was lost still
    // resolves via Hydra, and the mapping is backfilled on the way.
    sqlx::query("DELETE FROM id_mappings WHERE backend = 'hydra' AND public_id = $1")
        .bind(&client_id)
        .execute(&pool)
        .await
        .expect("mapping row should delete");

    let token_resp = client
        .post(format!("{base}/oauth2/token"))
        .basic_auth(&client_id, Some(&client_secret))
        .form(&[("grant_type", "client_credentials"), ("scope", "openid")])
        .send()
        .await
        .expect("self-heal token request should complete");
    assert_eq!(
        token_resp.status(),
        reqwest::StatusCode::OK,
        "token request with deleted mapping failed: {}",
        token_resp.text().await.unwrap_or_default()
    );

    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM id_mappings WHERE backend = 'hydra' AND public_id = $1")
            .bind(&client_id)
            .fetch_one(&pool)
            .await
            .expect("mapping count should query");
    assert_eq!(count, 1, "mapping row should be backfilled by self-heal");

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
