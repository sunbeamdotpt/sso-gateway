use std::sync::Arc;

use axum::{Extension, middleware::from_fn};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::{
    db::{IdMappingRepo, IdMappingStore, TenantRepo, bootstrap_system_tenant, create_pool},
    middleware::auth_middleware,
    proto::iam::v1::{ApplicationServiceExt, TenantServiceExt},
    services::{application::ApplicationServiceImpl, tenant::TenantServiceImpl},
    session_token::SessionTokenSigner,
};
use sso_ory_client::{HydraClient, KratosClient};
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};

mod support;

#[tokio::test]
async fn application_service_round_trip() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_hydra, hydra_admin_url, hydra_public_url) =
        support::start_hydra().await.expect("hydra should start");

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
    let kratos = Arc::new(
        KratosClient::new_with_public("http://localhost:1", "http://localhost:1")
            .expect("kratos client should build"),
    );
    let mappings = IdMappingRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool.clone());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
    ));
    let application_service = Arc::new(ApplicationServiceImpl::new(hydra, mappings.clone()));

    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = application_service.register(connect_router);
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

    // Create an application.
    let create_resp = client
        .post(format!(
            "{base}/iam.v1.ApplicationService/CreateApplication"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "name": "test-app",
            "redirectUris": ["https://localhost/callback"],
            "grantTypes": ["authorization_code", "refresh_token"],
            "responseTypes": ["code", "id_token"],
            "scope": ["openid", "profile"],
            "tokenEndpointAuthMethod": "client_secret_basic"
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
    assert_eq!(app["name"], "test-app");
    assert_eq!(app["redirectUris"], json![["https://localhost/callback"]]);
    assert_eq!(
        app["grantTypes"],
        json![["authorization_code", "refresh_token"]]
    );
    assert_eq!(app["responseTypes"], json![["code", "id_token"]]);
    assert_eq!(app["scope"], json![["openid", "profile"]]);
    assert_eq!(app["tokenEndpointAuthMethod"], "client_secret_basic");
    assert!(!app["clientSecret"].as_str().unwrap_or("").is_empty());

    // Get the application.
    let get_resp = client
        .post(format!("{base}/iam.v1.ApplicationService/GetApplication"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": app_id }))
        .send()
        .await
        .expect("get application request should succeed");

    assert!(get_resp.status().is_success(), "get application failed");
    let fetched: serde_json::Value = get_resp.json().await.expect("application should be json");
    assert_eq!(fetched["id"], app_id);
    assert_eq!(fetched["name"], "test-app");

    // Update the application.
    let update_resp = client
        .post(format!(
            "{base}/iam.v1.ApplicationService/UpdateApplication"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "id": app_id,
            "name": "test-app-updated",
            "redirectUris": ["https://localhost/callback", "https://localhost/callback2"],
            "grantTypes": ["authorization_code", "refresh_token"],
            "responseTypes": ["code", "id_token"],
            "scope": ["openid"],
            "tokenEndpointAuthMethod": "client_secret_basic"
        }))
        .send()
        .await
        .expect("update application request should succeed");

    assert!(
        update_resp.status().is_success(),
        "update application failed"
    );
    let updated: serde_json::Value = update_resp
        .json()
        .await
        .expect("application should be json");
    assert_eq!(updated["name"], "test-app-updated");
    assert_eq!(updated["scope"], json![["openid"]]);

    // List applications.
    let list_resp = client
        .post(format!("{base}/iam.v1.ApplicationService/ListApplications"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("list applications request should succeed");

    assert!(list_resp.status().is_success(), "list applications failed");
    let listed: serde_json::Value = list_resp
        .json()
        .await
        .expect("list response should be json");
    let applications = listed["applications"]
        .as_array()
        .expect("applications array should exist");
    assert_eq!(applications.len(), 1);
    assert_eq!(applications[0]["id"], app_id);

    // Rotate secret.
    let rotate_resp = client
        .post(format!("{base}/iam.v1.ApplicationService/RotateSecret"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": app_id }))
        .send()
        .await
        .expect("rotate secret request should succeed");

    let rotate_status = rotate_resp.status();
    let rotate_body = rotate_resp.text().await.unwrap_or_default();
    assert!(
        rotate_status.is_success(),
        "rotate secret failed: {rotate_body}"
    );
    let rotated: serde_json::Value =
        serde_json::from_str(&rotate_body).expect("secret should be json");
    assert!(!rotated["clientSecret"].as_str().unwrap_or("").is_empty());

    // Delete the application.
    let delete_resp = client
        .post(format!(
            "{base}/iam.v1.ApplicationService/DeleteApplication"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": app_id }))
        .send()
        .await
        .expect("delete application request should succeed");

    assert!(
        delete_resp.status().is_success(),
        "delete application failed"
    );

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
