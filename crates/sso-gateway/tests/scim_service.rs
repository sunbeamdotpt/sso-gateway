use std::sync::Arc;

use axum::{Extension, middleware::from_fn};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::{
    db::{
        IdMappingRepo, IdMappingStore, IdentitySchemaRepo, ScimGroupRepo, TenantRepo,
        bootstrap_system_tenant, create_pool,
    },
    middleware::auth_middleware,
    proto::iam::v1::{ApplicationServiceExt, IdentityServiceExt, ScimServiceExt, TenantServiceExt},
    services::handlers::oauth2::{Oauth2State, router as oauth2_router},
    services::handlers::scim::{ScimState, router as scim_router},
    services::{
        application::ApplicationServiceImpl, identity::IdentityServiceImpl, scim::ScimServiceImpl,
        tenant::TenantServiceImpl,
    },
    session_token::SessionTokenSigner,
};
use sso_ory_client::{HydraClient, KetoClient, KratosClient};
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};

mod support;

#[tokio::test]
async fn scim_users_and_groups_round_trip() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_hydra, hydra_admin_url, hydra_public_url) =
        support::start_hydra().await.expect("hydra should start");
    let (_kratos, kratos_admin_url, _kratos_public_url) =
        support::start_kratos().await.expect("kratos should start");
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

    let hydra = Arc::new(
        HydraClient::new(&hydra_admin_url, &hydra_public_url).expect("hydra client should build"),
    );
    let kratos =
        Arc::new(KratosClient::new(&kratos_admin_url).expect("kratos client should build"));
    let keto = Arc::new(
        KetoClient::new(&keto_read_url, &keto_write_url).expect("keto client should build"),
    );

    let mappings = IdMappingRepo::new(pool.clone());
    let schemas = IdentitySchemaRepo::new(pool.clone());
    let groups = ScimGroupRepo::new(pool.clone());
    let tenant_repo = TenantRepo::new(pool.clone());

    let tenant_service = Arc::new(TenantServiceImpl::new(
        tenant_repo,
        system_tenant_ulid.clone(),
    ));
    let application_service =
        Arc::new(ApplicationServiceImpl::new(hydra.clone(), mappings.clone()));
    let identity_service = Arc::new(IdentityServiceImpl::new(
        kratos.clone(),
        mappings.clone(),
        schemas.clone(),
    ));
    let scim_service = Arc::new(ScimServiceImpl::new(
        kratos.clone(),
        keto.clone(),
        mappings.clone(),
        schemas.clone(),
        groups.clone(),
    ));

    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = application_service.register(connect_router);
    let connect_router: ConnectRouter = identity_service.register(connect_router);
    let connect_router: ConnectRouter = scim_service.clone().register(connect_router);
    let service_router = ServiceRouter::from_router(connect_router);

    let (listener, addr) = bind_random_port("127.0.0.1")
        .await
        .expect("random port should bind");
    let base = format!("http://{addr}");

    let oauth_state = Arc::new(Oauth2State::new(
        hydra.clone(),
        mappings.clone(),
        base.clone(),
    ));
    let scim_state = Arc::new(ScimState::new(scim_service.clone()));

    let server = ServerBuilder::new()
        .with_router(service_router)
        .with_health(HealthRouter::new())
        .build_axum()
        .expect("server should build");

    let app = server
        .app()
        .merge(oauth2_router(oauth_state))
        .merge(scim_router(scim_state))
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

    // Create a tenant that will own the SCIM resources.
    let create_resp = client
        .post(format!("{base}/iam.v1.TenantService/CreateTenant"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "slug": "scim-tenant",
            "displayName": "SCIM Tenant",
            "settings": {}
        }))
        .send()
        .await
        .expect("create tenant request should succeed");
    assert!(
        create_resp.status().is_success(),
        "create tenant failed: {}",
        create_resp.text().await.unwrap_or_default()
    );
    let _tenant: serde_json::Value = create_resp.json().await.expect("tenant should be json");

    // Create and default an identity schema so SCIM users validate.
    let schema_resp = client
        .post(format!(
            "{base}/iam.v1.IdentityService/CreateIdentitySchema"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "schemaId": "default",
            "schemaJson": {
                "type": "object",
                "properties": {
                    "email": { "type": "string", "format": "email" },
                    "userName": { "type": "string" },
                    "name": { "type": "object" },
                    "active": { "type": "boolean" }
                },
                "required": ["email"]
            },
            "isDefault": true
        }))
        .send()
        .await
        .expect("create schema request should succeed");
    assert!(
        schema_resp.status().is_success(),
        "create schema failed: {}",
        schema_resp.text().await.unwrap_or_default()
    );

    let set_default_resp = client
        .post(format!(
            "{base}/iam.v1.IdentityService/SetDefaultIdentitySchema"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "schemaId": "default" }))
        .send()
        .await
        .expect("set default schema request should succeed");
    assert!(
        set_default_resp.status().is_success(),
        "set default schema failed: {}",
        set_default_resp.text().await.unwrap_or_default()
    );

    // SCIM requests use the test introspector token.
    let scim_headers = || {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", support::TEST_TOKEN).parse().unwrap(),
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/scim+json".parse().unwrap(),
        );
        headers
    };

    // ServiceProviderConfig
    let spc_resp = client
        .get(format!("{base}/scim/v2/ServiceProviderConfig"))
        .headers(scim_headers())
        .send()
        .await
        .expect("service provider config request should succeed");
    assert!(
        spc_resp.status().is_success(),
        "service provider config failed: {}",
        spc_resp.text().await.unwrap_or_default()
    );

    // ResourceTypes and Schemas
    let rt_resp = client
        .get(format!("{base}/scim/v2/ResourceTypes"))
        .headers(scim_headers())
        .send()
        .await
        .expect("resource types request should succeed");
    assert!(rt_resp.status().is_success(), "resource types failed");

    let schemas_resp = client
        .get(format!("{base}/scim/v2/Schemas"))
        .headers(scim_headers())
        .send()
        .await
        .expect("schemas request should succeed");
    assert!(schemas_resp.status().is_success(), "schemas failed");

    // Create a user via SCIM.
    let create_user_resp = client
        .post(format!("{base}/scim/v2/Users"))
        .headers(scim_headers())
        .json(&json!({
            "userName": "alice",
            "active": true,
            "emails": [{"value": "alice@example.com", "primary": true}],
            "name": {"givenName": "Alice", "familyName": "Example"}
        }))
        .send()
        .await
        .expect("create user request should succeed");
    assert!(
        create_user_resp.status().is_success(),
        "create user failed: {}",
        create_user_resp.text().await.unwrap_or_default()
    );
    let user: serde_json::Value = create_user_resp.json().await.expect("user should be json");
    let user_id = user["id"].as_str().expect("user id should exist");
    assert_eq!(user["userName"], "alice");

    // List users.
    let list_users_resp = client
        .get(format!("{base}/scim/v2/Users"))
        .headers(scim_headers())
        .send()
        .await
        .expect("list users request should succeed");
    assert!(list_users_resp.status().is_success(), "list users failed");
    let users_list: serde_json::Value = list_users_resp
        .json()
        .await
        .expect("users list should be json");
    assert_eq!(users_list["totalResults"], 1);

    // Get user.
    let get_user_resp = client
        .get(format!("{base}/scim/v2/Users/{user_id}"))
        .headers(scim_headers())
        .send()
        .await
        .expect("get user request should succeed");
    assert!(get_user_resp.status().is_success(), "get user failed");

    // Update user.
    let update_user_resp = client
        .put(format!("{base}/scim/v2/Users/{user_id}"))
        .headers(scim_headers())
        .json(&json!({
            "userName": "alice.updated",
            "active": true,
            "emails": [{"value": "alice-new@example.com", "primary": true}],
            "name": {"givenName": "Alice", "familyName": "Updated"}
        }))
        .send()
        .await
        .expect("update user request should succeed");
    assert!(
        update_user_resp.status().is_success(),
        "update user failed: {}",
        update_user_resp.text().await.unwrap_or_default()
    );
    let updated_user: serde_json::Value = update_user_resp
        .json()
        .await
        .expect("updated user should be json");
    assert_eq!(updated_user["userName"], "alice.updated");

    // Create a group containing the user.
    let create_group_resp = client
        .post(format!("{base}/scim/v2/Groups"))
        .headers(scim_headers())
        .json(&json!({
            "displayName": "Engineering",
            "members": [{"value": user_id, "display": "alice", "type": "User"}]
        }))
        .send()
        .await
        .expect("create group request should succeed");
    assert!(
        create_group_resp.status().is_success(),
        "create group failed: {}",
        create_group_resp.text().await.unwrap_or_default()
    );
    let group: serde_json::Value = create_group_resp
        .json()
        .await
        .expect("group should be json");
    let group_id = group["id"].as_str().expect("group id should exist");
    assert_eq!(group["displayName"], "Engineering");
    let members = group["members"]
        .as_array()
        .expect("members should be array");
    assert_eq!(members.len(), 1);

    // List groups.
    let list_groups_resp = client
        .get(format!("{base}/scim/v2/Groups"))
        .headers(scim_headers())
        .send()
        .await
        .expect("list groups request should succeed");
    assert!(list_groups_resp.status().is_success(), "list groups failed");

    // Update group.
    let update_group_resp = client
        .put(format!("{base}/scim/v2/Groups/{group_id}"))
        .headers(scim_headers())
        .json(&json!({
            "displayName": "Engineering-Updated",
            "members": []
        }))
        .send()
        .await
        .expect("update group request should succeed");
    assert!(
        update_group_resp.status().is_success(),
        "update group failed: {}",
        update_group_resp.text().await.unwrap_or_default()
    );
    let updated_group: serde_json::Value = update_group_resp
        .json()
        .await
        .expect("updated group should be json");
    assert_eq!(updated_group["displayName"], "Engineering-Updated");

    // Delete group and user.
    let delete_group_resp = client
        .delete(format!("{base}/scim/v2/Groups/{group_id}"))
        .headers(scim_headers())
        .send()
        .await
        .expect("delete group request should succeed");
    assert_eq!(delete_group_resp.status(), reqwest::StatusCode::NO_CONTENT);

    let delete_user_resp = client
        .delete(format!("{base}/scim/v2/Users/{user_id}"))
        .headers(scim_headers())
        .send()
        .await
        .expect("delete user request should succeed");
    assert_eq!(delete_user_resp.status(), reqwest::StatusCode::NO_CONTENT);

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
