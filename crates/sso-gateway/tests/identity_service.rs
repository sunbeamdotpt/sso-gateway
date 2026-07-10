use std::sync::Arc;

use axum::{Extension, middleware::from_fn};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::{
    db::{
        IdMappingRepo, IdMappingStore, IdentitySchemaRepo, TenantRepo, TransientTokenRepo,
        bootstrap_system_tenant, create_pool,
    },
    middleware::auth_middleware,
    proto::iam::v1::{IdentityServiceExt, TenantServiceExt},
    services::{identity::IdentityServiceImpl, tenant::TenantServiceImpl},
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
async fn identity_service_round_trip() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_kratos, kratos_admin_url, _kratos_public_url) =
        support::start_kratos().await.expect("kratos should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let system_tenant_ulid = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &system_tenant_ulid)
        .await
        .expect("system tenant should bootstrap");
    support::bootstrap_test_subject_mapping(&pool, &system_tenant_ulid).await;

    // Register the default identity schema for this tenant so the service accepts it.
    let schemas = IdentitySchemaRepo::new(pool.clone());
    schemas
        .create(
            &system_tenant_ulid,
            "default",
            json!({
                "$id": "https://schemas.ory.sh/presets/kratos/quickstart/email-password/identity.schema.json",
                "$schema": "http://json-schema.org/draft-07/schema#",
                "title": "Person",
                "type": "object",
                "properties": {
                    "traits": {
                        "type": "object",
                        "properties": {
                            "email": {
                                "type": "string",
                                "format": "email",
                                "title": "E-Mail",
                                "ory.sh/kratos": {
                                    "credentials": { "password": { "identifier": true } },
                                    "recovery": { "via": "email" },
                                    "verification": { "via": "email" }
                                }
                            },
                            "tenant_id": { "type": "string" }
                        },
                        "required": ["email"],
                        "additionalProperties": false
                    }
                }
            }),
            true,
        )
        .await
        .expect("schema should be registered");

    let kratos = Arc::new(
        KratosClient::new_with_public(&kratos_admin_url, &_kratos_public_url)
            .expect("kratos client should build"),
    );
    let mappings = IdMappingRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool.clone());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
    ));
    let identity_service = Arc::new(IdentityServiceImpl::new(
        kratos.clone(),
        mappings.clone(),
        schemas,
        sso_gateway::db::TenantMembershipRepo::new(pool.clone()),
        TransientTokenRepo::new(pool.clone()),
        "http://ui.test".to_string(),
        "default".to_string(),
    ));

    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = identity_service.register(connect_router);
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

    // Create an identity.
    let create_resp = client
        .post(format!("{base}/iam.v1.IdentityService/CreateIdentity"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "schemaId": "default",
            "traits": { "email": "alice@example.com" },
            "password": "a-very-strong-password-123"
        }))
        .send()
        .await
        .expect("create identity request should succeed");

    assert!(
        create_resp.status().is_success(),
        "create identity failed: {}",
        create_resp.text().await.unwrap_or_default()
    );

    let identity: serde_json::Value = create_resp.json().await.expect("identity should be json");
    let identity_id = identity["id"].as_str().expect("identity id should exist");
    assert_eq!(identity["schemaId"], "default");
    assert_eq!(identity["traits"]["email"], "alice@example.com");

    // Get the identity.
    let get_resp = client
        .post(format!("{base}/iam.v1.IdentityService/GetIdentity"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": identity_id }))
        .send()
        .await
        .expect("get identity request should succeed");

    assert!(get_resp.status().is_success(), "get identity failed");
    let fetched: serde_json::Value = get_resp.json().await.expect("identity should be json");
    assert_eq!(fetched["id"], identity_id);
    assert_eq!(fetched["traits"]["email"], "alice@example.com");

    // Update the identity.
    let update_resp = client
        .post(format!("{base}/iam.v1.IdentityService/UpdateIdentity"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "id": identity_id,
            "schemaId": "default",
            "traits": { "email": "alice-updated@example.com" }
        }))
        .send()
        .await
        .expect("update identity request should succeed");

    assert!(update_resp.status().is_success(), "update identity failed");
    let updated: serde_json::Value = update_resp.json().await.expect("identity should be json");
    assert_eq!(updated["traits"]["email"], "alice-updated@example.com");

    // List identities.
    let list_resp = client
        .post(format!("{base}/iam.v1.IdentityService/ListIdentities"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("list identities request should succeed");

    assert!(list_resp.status().is_success(), "list identities failed");
    let listed: serde_json::Value = list_resp
        .json()
        .await
        .expect("list response should be json");
    let identities = listed["identities"]
        .as_array()
        .expect("identities array should exist");
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0]["id"], identity_id);

    // Create an identity using the default schema when schemaId is omitted.
    let default_resp = client
        .post(format!("{base}/iam.v1.IdentityService/CreateIdentity"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "traits": { "email": "default@example.com" },
            "password": "a-very-strong-password-123"
        }))
        .send()
        .await
        .expect("create identity with default schema request should succeed");
    assert!(
        default_resp.status().is_success(),
        "create identity with default schema failed: {}",
        default_resp.text().await.unwrap_or_default()
    );
    let default_identity: serde_json::Value = default_resp
        .json()
        .await
        .expect("default identity should be json");
    assert_eq!(default_identity["schemaId"], "default");

    // Schema registry CRUD.
    let schema_resp = client
        .post(format!(
            "{base}/iam.v1.IdentityService/CreateIdentitySchema"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "schemaId": "custom",
            "schemaJson": {
                "type": "object",
                "properties": {
                    "email": { "type": "string", "format": "email" },
                    "nickname": { "type": "string" }
                },
                "required": ["email"]
            },
            "isDefault": false
        }))
        .send()
        .await
        .expect("create schema request should succeed");
    assert!(
        schema_resp.status().is_success(),
        "create schema failed: {}",
        schema_resp.text().await.unwrap_or_default()
    );
    let custom_schema: serde_json::Value = schema_resp.json().await.expect("schema should be json");
    assert_eq!(custom_schema["schemaId"], "custom");

    let get_schema_resp = client
        .post(format!("{base}/iam.v1.IdentityService/GetIdentitySchema"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "schemaId": "custom" }))
        .send()
        .await
        .expect("get schema request should succeed");
    assert!(get_schema_resp.status().is_success(), "get schema failed");

    let update_schema_resp = client
        .post(format!(
            "{base}/iam.v1.IdentityService/UpdateIdentitySchema"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "schemaId": "custom",
            "schemaJson": {
                "type": "object",
                "properties": {
                    "email": { "type": "string", "format": "email" },
                    "nickname": { "type": "string" },
                    "age": { "type": "integer" }
                },
                "required": ["email"]
            },
            "isDefault": false
        }))
        .send()
        .await
        .expect("update schema request should succeed");
    assert!(
        update_schema_resp.status().is_success(),
        "update schema failed"
    );

    let list_schema_resp = client
        .post(format!("{base}/iam.v1.IdentityService/ListIdentitySchemas"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("list schemas request should succeed");
    assert!(
        list_schema_resp.status().is_success(),
        "list schemas failed"
    );
    let listed_schemas: serde_json::Value = list_schema_resp
        .json()
        .await
        .expect("schema list should be json");
    let schemas_arr = listed_schemas["schemas"]
        .as_array()
        .expect("schemas array should exist");
    let schema_ids: Vec<&str> = schemas_arr
        .iter()
        .filter_map(|s| s["schemaId"].as_str())
        .collect();
    assert!(schema_ids.contains(&"custom"));
    assert!(schema_ids.contains(&"default"));

    let set_default_resp = client
        .post(format!(
            "{base}/iam.v1.IdentityService/SetDefaultIdentitySchema"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "schemaId": "custom" }))
        .send()
        .await
        .expect("set default schema request should succeed");
    assert!(
        set_default_resp.status().is_success(),
        "set default schema failed"
    );

    // Self-service flows are backed by Kratos public API.
    let login_resp = client
        .post(format!("{base}/iam.v1.IdentityService/CreateLoginFlow"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("create login flow request should succeed");
    assert!(
        login_resp.status().is_success(),
        "create login flow failed: {}",
        login_resp.text().await.unwrap_or_default()
    );
    let login_flow: serde_json::Value = login_resp.json().await.expect("login flow should be json");
    assert!(!login_flow["id"].as_str().unwrap_or("").is_empty());
    assert!(!login_flow["type"].as_str().unwrap_or("").is_empty());

    let reg_resp = client
        .post(format!(
            "{base}/iam.v1.IdentityService/CreateRegistrationFlow"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("create registration flow request should succeed");
    assert!(
        reg_resp.status().is_success(),
        "create registration flow failed: {}",
        reg_resp.text().await.unwrap_or_default()
    );
    let reg_flow: serde_json::Value = reg_resp
        .json()
        .await
        .expect("registration flow should be json");
    assert!(!reg_flow["id"].as_str().unwrap_or("").is_empty());
    assert!(!reg_flow["type"].as_str().unwrap_or("").is_empty());

    // Trait validation rejects traits that do not match the registered schema.
    let invalid_resp = client
        .post(format!("{base}/iam.v1.IdentityService/CreateIdentity"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "schemaId": "custom",
            "traits": { "email": "not-an-email" }
        }))
        .send()
        .await
        .expect("invalid create identity request should complete");
    assert!(
        invalid_resp.status().is_client_error(),
        "invalid traits should be rejected"
    );

    // Delete the identities.
    for id in [identity_id, default_identity["id"].as_str().unwrap()] {
        let delete_resp = client
            .post(format!("{base}/iam.v1.IdentityService/DeleteIdentity"))
            .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
            .header("content-type", "application/json")
            .json(&json!({ "id": id }))
            .send()
            .await
            .expect("delete identity request should succeed");
        assert!(delete_resp.status().is_success(), "delete identity failed");
    }

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
