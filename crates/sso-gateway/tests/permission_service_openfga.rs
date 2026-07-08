#![cfg(feature = "openfga")]

use std::sync::Arc;

use axum::{Extension, middleware::from_fn};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::{
    db::{
        IdMappingRepo, IdMappingStore, PermissionTupleRepo, TenantRepo, bootstrap_system_tenant,
        create_pool,
    },
    middleware::auth_middleware,
    proto::iam::v1::{PermissionServiceExt, TenantServiceExt},
    services::{
        permission::{
            MemoryNamespaceMappingRepo, OpenFgaPermissionBackend, PermissionBackend,
            PermissionServiceImpl,
        },
        tenant::TenantServiceImpl,
    },
    session_token::SessionTokenSigner,
};
use sso_openfga_client::OpenFgaClient;
use sso_ory_client::KratosClient;
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};

mod support;

#[tokio::test]
async fn permission_service_openfga_round_trip() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_openfga, openfga_url) =
        support::start_openfga().await.expect("openfga should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");
    support::bootstrap_test_subject_mapping(&pool, &system_tenant_ulid).await;

    let openfga = Arc::new(
        OpenFgaPermissionBackend::new(
            OpenFgaClient::new(&openfga_url).expect("openfga client should build"),
            Arc::new(MemoryNamespaceMappingRepo::default()),
        ),
    );

    // Pre-provision the namespace so the service can write tuples.
    openfga
        .ensure_namespace(&system_tenant_ulid, "document", &["reader".into(), "owner".into()])
        .await
        .expect("namespace should be ensured");

    let tuples = PermissionTupleRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool.clone());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
    ));
    let permission_service = Arc::new(PermissionServiceImpl::new(openfga, tuples));

    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = permission_service.register(connect_router);
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
    let mappings = IdMappingRepo::new(pool.clone());

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
        .layer(Extension::<Arc<dyn IdMappingStore>>(Arc::new(mappings)))
        .layer(Extension(kratos));

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");
    let base = format!("http://{addr}");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should serve");
    });

    let client = reqwest::Client::new();
    let url = format!("{base}/iam.v1.PermissionService/CreateRelationTuple");
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .header("authorization", "Bearer integration-test-token")
        .json(&json!({
            "namespace": "document",
            "object": "doc-1",
            "relation": "reader",
            "subjectId": "user:alice",
        }))
        .send()
        .await
        .expect("request should send");
    assert_eq!(resp.status(), 200, "create tuple failed: {:?}", resp.text().await);

    let url = format!("{base}/iam.v1.PermissionService/CheckPermission");
    let resp = client
        .post(&url)
        .header("content-type", "application/json")
        .header("authorization", "Bearer integration-test-token")
        .json(&json!({
            "namespace": "document",
            "object": "doc-1",
            "relation": "reader",
            "subjectId": "user:alice",
        }))
        .send()
        .await
        .expect("request should send");
    assert_eq!(resp.status(), 200);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["allowed"], true);

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}
