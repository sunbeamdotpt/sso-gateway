use std::sync::Arc;

use axum::{Extension, middleware::from_fn};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::{
    db::{IdMappingRepo, IdMappingStore, TenantRepo, bootstrap_system_tenant, create_pool},
    middleware::auth_middleware,
    proto::iam::v1::TenantServiceExt,
    services::tenant::TenantServiceImpl,
    session_token::SessionTokenSigner,
};
use sso_ory_client::KratosClient;
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};

mod support;

#[tokio::test]
async fn tenant_service_round_trip() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");
    support::bootstrap_test_subject_mapping(&pool, &system_tenant_ulid).await;

    let repo = TenantRepo::new(pool.clone());
    let mappings = IdMappingRepo::new(pool.clone());
    let kratos = Arc::new(
        KratosClient::new_with_public("http://localhost:1", "http://localhost:1")
            .expect("fake kratos client should build"),
    );
    let tenant_service = Arc::new(TenantServiceImpl::new(repo, system_tenant_ulid.clone()));
    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
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

    // Create a tenant.
    let create_resp = client
        .post(format!("{base}/iam.v1.TenantService/CreateTenant"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "slug": "acme",
            "displayName": "Acme Corp",
            "settings": { "region": "us-east-1" }
        }))
        .send()
        .await
        .expect("create tenant request should succeed");

    assert!(
        create_resp.status().is_success(),
        "create tenant failed: {}",
        create_resp.text().await.unwrap_or_default()
    );

    let tenant: serde_json::Value = create_resp.json().await.expect("tenant should be json");
    let tenant_id = tenant["id"].as_str().expect("tenant id should exist");
    assert_eq!(tenant["slug"], "acme");
    assert_eq!(tenant["displayName"], "Acme Corp");
    assert_eq!(tenant["settings"]["region"], "us-east-1");

    // Get the tenant by id.
    let get_resp = client
        .post(format!("{base}/iam.v1.TenantService/GetTenant"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": tenant_id }))
        .send()
        .await
        .expect("get tenant request should succeed");

    assert!(get_resp.status().is_success(), "get tenant failed");
    let fetched: serde_json::Value = get_resp.json().await.expect("tenant should be json");
    assert_eq!(fetched["id"], tenant_id);

    // List tenants should include the system tenant and the created tenant.
    let list_resp = client
        .post(format!("{base}/iam.v1.TenantService/ListTenants"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("list tenants request should succeed");

    assert!(list_resp.status().is_success(), "list tenants failed");
    let listed: serde_json::Value = list_resp
        .json()
        .await
        .expect("list response should be json");
    let tenants = listed["tenants"]
        .as_array()
        .expect("tenants array should exist");
    assert!(tenants.len() >= 2, "should list system + created tenants");

    // Missing authorization header should be rejected before reaching the service.
    let no_header_resp = client
        .post(format!("{base}/iam.v1.TenantService/ListTenants"))
        .header("content-type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("request should complete");
    assert_eq!(no_header_resp.status(), 401);

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
