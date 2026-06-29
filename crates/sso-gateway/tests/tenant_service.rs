use std::sync::Arc;

use axum::{Extension, middleware::from_fn};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::{
    db::{TenantApiKeyRepo, TenantRepo, bootstrap_system_tenant, create_pool},
    middleware::auth_middleware,
    proto::iam::v1::TenantServiceExt,
    services::tenant::TenantServiceImpl,
};
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

    let pool = create_pool(&database_url)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");

    let repo = TenantRepo::new(pool.clone());
    let api_keys = TenantApiKeyRepo::new(pool);
    let tenant_service = Arc::new(TenantServiceImpl::new(
        repo,
        api_keys.clone(),
        system_tenant_ulid.clone(),
    ));
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
        .layer(Extension(api_keys));

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
        .header("x-tenant-id", &system_tenant_ulid)
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
        .header("x-tenant-id", &system_tenant_ulid)
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
        .header("x-tenant-id", &system_tenant_ulid)
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

    // Missing x-tenant-id should be rejected before reaching the service.
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

#[tokio::test]
async fn tenant_api_key_auth_round_trip() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let pool = create_pool(&database_url)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");

    let repo = TenantRepo::new(pool.clone());
    let api_keys = TenantApiKeyRepo::new(pool);
    let tenant_service = Arc::new(TenantServiceImpl::new(
        repo,
        api_keys.clone(),
        system_tenant_ulid.clone(),
    ));
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
        .layer(Extension(api_keys));

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

    // Rotate an admin API key for the system tenant.
    let rotate_resp = client
        .post(format!("{base}/iam.v1.TenantService/RotateApiKey"))
        .header("x-tenant-id", &system_tenant_ulid)
        .header("content-type", "application/json")
        .json(&json!({
            "tenantId": system_tenant_ulid,
            "name": "admin",
            "scopes": ["tenant:admin"]
        }))
        .send()
        .await
        .expect("rotate api key request should succeed");

    assert!(
        rotate_resp.status().is_success(),
        "rotate api key failed: {}",
        rotate_resp.text().await.unwrap_or_default()
    );
    let key: serde_json::Value = rotate_resp.json().await.expect("api key should be json");
    let plaintext = key["plaintext"].as_str().expect("plaintext should exist");
    assert_eq!(key["tenantId"], system_tenant_ulid);
    assert_eq!(key["name"], "admin");

    // Use the API key to call GetTenant without an x-tenant-id header.
    let get_resp = client
        .post(format!("{base}/iam.v1.TenantService/GetTenant"))
        .header("x-api-key", plaintext)
        .header("content-type", "application/json")
        .json(&json!({ "id": system_tenant_ulid }))
        .send()
        .await
        .expect("get tenant with api key should succeed");

    assert!(
        get_resp.status().is_success(),
        "get tenant with api key failed: {}",
        get_resp.text().await.unwrap_or_default()
    );
    let fetched: serde_json::Value = get_resp.json().await.expect("tenant should be json");
    assert_eq!(fetched["id"], system_tenant_ulid);

    // A read-only key cannot rotate keys.
    let rotate_read_resp = client
        .post(format!("{base}/iam.v1.TenantService/RotateApiKey"))
        .header("x-tenant-id", &system_tenant_ulid)
        .header("content-type", "application/json")
        .json(&json!({
            "tenantId": system_tenant_ulid,
            "name": "reader",
            "scopes": ["tenant:read"]
        }))
        .send()
        .await
        .expect("rotate reader key request should succeed");
    assert!(rotate_read_resp.status().is_success());
    let reader_key: serde_json::Value = rotate_read_resp
        .json()
        .await
        .expect("reader key should be json");
    let reader_plaintext = reader_key["plaintext"]
        .as_str()
        .expect("reader plaintext should exist");

    let forbidden_resp = client
        .post(format!("{base}/iam.v1.TenantService/RotateApiKey"))
        .header("x-api-key", reader_plaintext)
        .header("content-type", "application/json")
        .json(&json!({
            "tenantId": system_tenant_ulid,
            "name": "other",
            "scopes": ["tenant:admin"]
        }))
        .send()
        .await
        .expect("rotate with reader key request should complete");
    assert_eq!(forbidden_resp.status(), 403);

    // An unknown API key is rejected.
    let unknown_resp = client
        .post(format!("{base}/iam.v1.TenantService/GetTenant"))
        .header("x-api-key", "not-a-real-key")
        .header("content-type", "application/json")
        .json(&json!({ "id": system_tenant_ulid }))
        .send()
        .await
        .expect("request with unknown key should complete");
    assert_eq!(unknown_resp.status(), 401);

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
