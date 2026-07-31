// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods))]

#![cfg(feature = "keto")]

use std::sync::Arc;

use axum::{Extension, middleware::from_fn};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::{
    db::{
        IdMappingRepo, IdMappingStore, PermissionNamespaceRepo, PermissionTupleRepo, TenantRepo,
        bootstrap_system_tenant, create_pool,
    },
    middleware::auth_middleware,
    proto::iam::v1::{PermissionServiceExt, TenantServiceExt},
    services::{permission::PermissionServiceImpl, tenant::TenantServiceImpl},
    session_token::SessionTokenSigner,
};
use sso_gateway::services::entitlement::test_helpers::entitlements;
use sso_ory_client::{KetoClient, KratosClient};
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};

mod support;

#[tokio::test]
async fn permission_service_round_trip() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_keto, keto_read_url, keto_write_url) =
        support::start_keto().await.expect("keto should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");
    support::bootstrap_test_subject_mapping(&pool, &system_tenant_ulid).await;

    let keto = Arc::new(
        KetoClient::new(&keto_read_url, &keto_write_url).expect("keto client should build"),
    );
    let tuples = PermissionTupleRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool.clone());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
        entitlements(),
    ));
    let permission_service = Arc::new(PermissionServiceImpl::new(
        keto,
        tuples,
        IdMappingRepo::new(pool.clone()),
        Arc::new(PermissionNamespaceRepo::new(pool.clone())),
    ));

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

    // Initially Alice has no access.
    let check_resp = client
        .post(format!("{base}/iam.v1.PermissionService/CheckPermission"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "namespace": "app",
            "object": "doc-1",
            "relation": "read",
            "subjectId": "alice"
        }))
        .send()
        .await
        .expect("check permission request should succeed");

    assert!(
        check_resp.status().is_success(),
        "check permission failed: {}",
        check_resp.text().await.unwrap_or_default()
    );
    let check: serde_json::Value = check_resp.json().await.expect("check should be json");
    assert!(!check["allowed"].as_bool().unwrap_or(false));

    // Grant Alice read access.
    let create_resp = client
        .post(format!(
            "{base}/iam.v1.PermissionService/CreateRelationTuple"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "namespace": "app",
            "object": "doc-1",
            "relation": "read",
            "subjectId": "alice"
        }))
        .send()
        .await
        .expect("create tuple request should succeed");

    assert!(
        create_resp.status().is_success(),
        "create tuple failed: {}",
        create_resp.text().await.unwrap_or_default()
    );
    let tuple: serde_json::Value = create_resp.json().await.expect("tuple should be json");
    let tuple_id = tuple["id"].as_str().expect("tuple id should exist");
    assert_eq!(tuple["namespace"], "app");
    assert_eq!(tuple["object"], "doc-1");
    assert_eq!(tuple["relation"], "read");
    assert_eq!(tuple["subjectId"], "alice");

    // Alice can now read; Bob still cannot.
    let check_resp = client
        .post(format!("{base}/iam.v1.PermissionService/CheckPermission"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "namespace": "app",
            "object": "doc-1",
            "relation": "read",
            "subjectId": "alice"
        }))
        .send()
        .await
        .expect("check permission request should succeed");

    assert!(check_resp.status().is_success(), "check permission failed");
    let check: serde_json::Value = check_resp.json().await.expect("check should be json");
    assert_eq!(check["allowed"], true);

    let check_bob_resp = client
        .post(format!("{base}/iam.v1.PermissionService/CheckPermission"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "namespace": "app",
            "object": "doc-1",
            "relation": "read",
            "subjectId": "bob"
        }))
        .send()
        .await
        .expect("check permission request should succeed");

    assert!(check_bob_resp.status().is_success(), "check bob failed");
    let check_bob: serde_json::Value = check_bob_resp.json().await.expect("check should be json");
    assert!(!check_bob["allowed"].as_bool().unwrap_or(false));

    // List tuples.
    let list_resp = client
        .post(format!(
            "{base}/iam.v1.PermissionService/ListRelationTuples"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("list tuples request should succeed");

    assert!(list_resp.status().is_success(), "list tuples failed");
    let listed: serde_json::Value = list_resp
        .json()
        .await
        .expect("list response should be json");
    let tuples = listed["tuples"]
        .as_array()
        .expect("tuples array should exist");
    assert_eq!(tuples.len(), 1);
    assert_eq!(tuples[0]["id"], tuple_id);

    // Expand permissions.
    let expand_resp = client
        .post(format!("{base}/iam.v1.PermissionService/ExpandPermissions"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "namespace": "app",
            "object": "doc-1",
            "relation": "read"
        }))
        .send()
        .await
        .expect("expand request should succeed");

    assert!(expand_resp.status().is_success(), "expand failed");
    let expanded: serde_json::Value = expand_resp.json().await.expect("expand should be json");
    assert!(expanded["tree"].as_str().is_some());

    // Expand objects for alice.
    let expand_objects_resp = client
        .post(format!("{base}/iam.v1.PermissionService/ExpandObjects"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "namespace": "app",
            "relation": "read",
            "subjectId": "alice"
        }))
        .send()
        .await
        .expect("expand objects request should succeed");

    assert!(
        expand_objects_resp.status().is_success(),
        "expand objects failed: {}",
        expand_objects_resp.text().await.unwrap_or_default()
    );
    let expanded_objects: serde_json::Value = expand_objects_resp
        .json()
        .await
        .expect("expand objects should be json");
    let objects = expanded_objects["objects"]
        .as_array()
        .expect("objects array should exist");
    assert!(objects.iter().any(|o| o == "doc-1"));

    // Delete the tuple.
    let delete_resp = client
        .post(format!(
            "{base}/iam.v1.PermissionService/DeleteRelationTuple"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": tuple_id }))
        .send()
        .await
        .expect("delete tuple request should succeed");

    assert!(delete_resp.status().is_success(), "delete tuple failed");

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

/// The namespace lifecycle RPCs work on Keto too: the model is recorded as
/// metadata while tuples flow without any provisioning.
#[tokio::test]
async fn permission_service_keto_namespace_metadata() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_keto, keto_read_url, keto_write_url) =
        support::start_keto().await.expect("keto should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");
    support::bootstrap_test_subject_mapping(&pool, &system_tenant_ulid).await;

    let keto = Arc::new(
        KetoClient::new(&keto_read_url, &keto_write_url).expect("keto client should build"),
    );
    let tuples = PermissionTupleRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool.clone());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
        entitlements(),
    ));
    let permission_service = Arc::new(PermissionServiceImpl::new(
        keto,
        tuples,
        IdMappingRepo::new(pool.clone()),
        Arc::new(PermissionNamespaceRepo::new(pool.clone())),
    ));

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
    let post = |rpc: &str, body: serde_json::Value| {
        let client = client.clone();
        let url = format!("{base}/iam.v1.PermissionService/{rpc}");
        async move {
            client
                .post(&url)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
                .json(&body)
                .send()
                .await
                .expect("request should send")
        }
    };

    // Ensure records the model metadata; Keto needs no store provisioning.
    let resp = post(
        "EnsurePermissionNamespace",
        json!({
            "namespace": "app",
            "model": {
                "schema_version": "1.1",
                "type_definitions": [
                    { "type": "user" },
                    {
                        "type": "document",
                        "relations": { "reader": {} },
                        "metadata": {
                            "relations": {
                                "reader": {
                                    "directly_related_user_types": [{ "type": "user" }]
                                }
                            }
                        }
                    }
                ]
            }
        }),
    )
    .await;
    assert_eq!(resp.status(), 200, "ensure failed: {:?}", resp.text().await);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["types"], json!(["document", "user"]));

    let resp = post("GetPermissionNamespace", json!({ "namespace": "app" })).await;
    assert_eq!(resp.status(), 200);

    let resp = post("ListPermissionNamespaces", json!({})).await;
    assert_eq!(resp.status(), 200);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["namespaces"].as_array().unwrap().len(), 1);

    // Tuples flow without any store initialization.
    let resp = post(
        "CreateRelationTuple",
        json!({
            "namespace": "app",
            "object": "doc-1",
            "relation": "reader",
            "subjectId": "alice"
        }),
    )
    .await;
    assert_eq!(resp.status(), 200, "create failed: {:?}", resp.text().await);

    // Teardown removes the record and the mirrored tuples.
    let resp = post("DeletePermissionNamespace", json!({ "namespace": "app" })).await;
    assert_eq!(resp.status(), 200);

    let resp = post("GetPermissionNamespace", json!({ "namespace": "app" })).await;
    assert_eq!(resp.status(), 404);

    let resp = post("ListRelationTuples", json!({ "namespace": "app" })).await;
    assert_eq!(resp.status(), 200);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    // Empty repeated fields are omitted from Connect JSON responses.
    assert_eq!(body["tuples"].as_array().map(|t| t.len()).unwrap_or(0), 0);

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
