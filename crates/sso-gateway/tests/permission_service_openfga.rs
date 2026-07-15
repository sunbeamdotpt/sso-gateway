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
    let (_openfga, openfga_url) = support::start_openfga()
        .await
        .expect("openfga should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");
    support::bootstrap_test_subject_mapping(&pool, &system_tenant_ulid).await;

    // The backend and the service share one mapping repo so that namespaces
    // provisioned through either side are visible to the other.
    let namespaces = Arc::new(MemoryNamespaceMappingRepo::default());
    let openfga = Arc::new(OpenFgaPermissionBackend::new(
        OpenFgaClient::new(&openfga_url).expect("openfga client should build"),
        namespaces.clone(),
    ));

    // Pre-provision the namespace so the service can write tuples.
    openfga
        .ensure_namespace(
            &system_tenant_ulid,
            "document",
            &["reader".into(), "owner".into()],
        )
        .await
        .expect("namespace should be ensured");

    let tuples = PermissionTupleRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool.clone());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
    ));
    let permission_service = Arc::new(PermissionServiceImpl::new(
        openfga,
        tuples,
        IdMappingRepo::new(pool.clone()),
        namespaces,
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
    assert_eq!(
        resp.status(),
        200,
        "create tuple failed: {:?}",
        resp.text().await
    );

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

/// End-to-end namespace lifecycle, mirroring how a third-party service
/// (Kanban) registers its own rich OpenFGA model and manages tuples.
#[tokio::test]
async fn permission_service_openfga_namespace_lifecycle() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_openfga, openfga_url) = support::start_openfga()
        .await
        .expect("openfga should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");
    support::bootstrap_test_subject_mapping(&pool, &system_tenant_ulid).await;

    let namespaces = Arc::new(MemoryNamespaceMappingRepo::default());
    let openfga = Arc::new(OpenFgaPermissionBackend::new(
        OpenFgaClient::new(&openfga_url).expect("openfga client should build"),
        namespaces.clone(),
    ));
    let tuples = PermissionTupleRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool.clone());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
    ));
    let permission_service = Arc::new(PermissionServiceImpl::new(
        openfga,
        tuples,
        IdMappingRepo::new(pool.clone()),
        namespaces,
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
                .header("authorization", "Bearer integration-test-token")
                .json(&body)
                .send()
                .await
                .expect("request should send")
        }
    };

    // A rich multi-type model with a tuple-to-userset rewrite: card editors
    // inherit from the parent project's editors. Direct relations use the
    // canonical `{"this": {}}` form the OpenFGA DSL compiles to.
    let kanban_model = |project_relations: &[&str]| {
        let direct: serde_json::Map<String, serde_json::Value> = project_relations
            .iter()
            .map(|relation| (relation.to_string(), json!({ "this": {} })))
            .collect();
        let direct_metadata: serde_json::Map<String, serde_json::Value> = project_relations
            .iter()
            .map(|relation| {
                (
                    relation.to_string(),
                    json!({ "directly_related_user_types": [{ "type": "user" }] }),
                )
            })
            .collect();
        json!({
            "schema_version": "1.1",
            "type_definitions": [
                { "type": "user" },
                {
                    "type": "KanbanProject",
                    "relations": direct,
                    "metadata": { "relations": direct_metadata },
                },
                {
                    "type": "KanbanCard",
                    "relations": {
                        "parent": { "this": {} },
                        "editor": {
                            "union": {
                                "child": [
                                    { "this": {} },
                                    {
                                        "tupleToUserset": {
                                            "tupleset": { "relation": "parent" },
                                            "computedUserset": { "relation": "editor" },
                                        }
                                    },
                                ],
                            },
                        },
                    },
                    "metadata": {
                        "relations": {
                            "parent": {
                                "directly_related_user_types": [{ "type": "KanbanProject" }]
                            },
                            "editor": {
                                "directly_related_user_types": [{ "type": "user" }]
                            },
                        },
                    },
                },
            ],
        })
    };
    let model_v1 = kanban_model(&["editor", "viewer"]);

    // Before the namespace is ensured, tuple/check calls fail like the Keto
    // "unknown namespace" error: this is the gap the lifecycle RPCs close.
    let resp = post(
        "CheckPermission",
        json!({
            "namespace": "KanbanProject",
            "object": "proj-1",
            "relation": "editor",
            "subjectId": "user:alice",
        }),
    )
    .await;
    assert_eq!(resp.status(), 400, "unconfigured namespace should fail");

    // Ensure registers the namespace and provisions the OpenFGA store.
    let resp = post(
        "EnsurePermissionNamespace",
        json!({ "namespace": "kanban", "model": model_v1 }),
    )
    .await;
    assert_eq!(resp.status(), 200, "ensure failed: {:?}", resp.text().await);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["namespace"], "kanban");
    assert_eq!(
        body["types"],
        json!(["KanbanCard", "KanbanProject", "user"]),
        "types should be normalized and sorted"
    );

    // Get and list reflect the registration.
    let resp = post("GetPermissionNamespace", json!({ "namespace": "kanban" })).await;
    assert_eq!(resp.status(), 200);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["model"]["schema_version"], "1.1");

    let resp = post("ListPermissionNamespaces", json!({})).await;
    assert_eq!(resp.status(), 200);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["namespaces"].as_array().unwrap().len(), 1);

    // Batch write: alice edits proj-1, card-1's parent is proj-1.
    let resp = post(
        "WriteRelationTuples",
        json!({
            "writes": [
                {
                    "namespace": "KanbanProject",
                    "object": "proj-1",
                    "relation": "editor",
                    "subjectId": "user:alice",
                },
                {
                    "namespace": "KanbanCard",
                    "object": "card-1",
                    "relation": "parent",
                    "subjectId": "KanbanProject:proj-1",
                },
            ],
        }),
    )
    .await;
    assert_eq!(resp.status(), 200, "batch write failed: {:?}", resp.text().await);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["written"], 2);

    // The check resolves through the tuple-to-userset rewrite.
    let resp = post(
        "CheckPermission",
        json!({
            "namespace": "KanbanCard",
            "object": "card-1",
            "relation": "editor",
            "subjectId": "user:alice",
        }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["allowed"], true, "editor should inherit from parent");

    // ListUsers returns canonical subjects.
    let resp = post(
        "ListUsers",
        json!({
            "namespace": "KanbanCard",
            "object": "card-1",
            "relation": "editor",
            "userTypeFilters": ["user"],
        }),
    )
    .await;
    assert_eq!(resp.status(), 200, "list users failed: {:?}", resp.text().await);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    let users = body["users"].as_array().unwrap();
    assert!(
        users.iter().any(|u| u == "user:alice"),
        "expected user:alice in {users:?}"
    );

    // Ensuring the identical model is a no-op.
    let resp = post(
        "EnsurePermissionNamespace",
        json!({ "namespace": "kanban", "model": model_v1 }),
    )
    .await;
    assert_eq!(resp.status(), 200);

    // A model change publishes a new model version into the same store;
    // existing tuples are untouched, so no re-initialization is needed.
    let model_v2 = kanban_model(&["editor", "viewer", "commenter"]);
    let resp = post(
        "EnsurePermissionNamespace",
        json!({ "namespace": "kanban", "model": model_v2 }),
    )
    .await;
    assert_eq!(resp.status(), 200, "model update failed: {:?}", resp.text().await);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert!(
        body["model"]["type_definitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|def| def["type"] == "KanbanProject"
                && def["relations"].as_object().unwrap().contains_key("commenter")),
        "updated model should include the new relation"
    );

    let resp = post(
        "CheckPermission",
        json!({
            "namespace": "KanbanCard",
            "object": "card-1",
            "relation": "editor",
            "subjectId": "user:alice",
        }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        body["allowed"], true,
        "tuples must survive a model version change"
    );

    // Keyset pagination over the mirrored tuples.
    let resp = post("ListRelationTuples", json!({ "page": { "pageSize": 1 } })).await;
    assert_eq!(resp.status(), 200);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["tuples"].as_array().unwrap().len(), 1);
    assert_eq!(body["page"]["totalSize"], 2);
    let next_page_token = body["page"]["nextPageToken"].as_str().unwrap();
    assert!(!next_page_token.is_empty());

    let resp = post(
        "ListRelationTuples",
        json!({ "page": { "pageSize": 1, "pageToken": next_page_token } }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.json::<serde_json::Value>().await.unwrap();
    assert_eq!(body["tuples"].as_array().unwrap().len(), 1);

    // Full teardown: store, mirror tuples, and the record itself.
    let resp = post(
        "DeletePermissionNamespace",
        json!({ "namespace": "kanban" }),
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = post("GetPermissionNamespace", json!({ "namespace": "kanban" })).await;
    assert_eq!(resp.status(), 404);

    let resp = post(
        "CheckPermission",
        json!({
            "namespace": "KanbanCard",
            "object": "card-1",
            "relation": "editor",
            "subjectId": "user:alice",
        }),
    )
    .await;
    assert_eq!(resp.status(), 400, "deleted namespace should be unconfigured");

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}
