// SSO-027: tests may unwrap/expect freely; the panic/default bans target production code.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods))]

use std::sync::Arc;

use axum::{Extension, middleware::from_fn};
use connectrpc::Router as ConnectRouter;
use serde_json::json;
use sso_gateway::{
    db::{IdMappingRepo, IdMappingStore, TenantRepo, bootstrap_system_tenant, create_pool},
    middleware::auth_middleware,
    proto::iam::v1::{ClientCredentialServiceExt, TenantServiceExt},
    services::{client_credential::ClientCredentialServiceImpl, tenant::TenantServiceImpl},
    session_token::SessionTokenSigner,
};
use sso_gateway::services::entitlement::test_helpers::entitlements;
use sso_ory_client::{HydraClient, KratosClient};
use sunbeam_g2v::{
    health::HealthRouter,
    router::ServiceRouter,
    server::{axum::bind_random_port, builder::ServerBuilder},
};

mod support;

#[tokio::test]
async fn client_credential_service_round_trip() {
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
        entitlements(),
    ));
    let client_credential_service =
        Arc::new(ClientCredentialServiceImpl::new(hydra, mappings.clone()));

    let connect_router: ConnectRouter = tenant_service.register(ConnectRouter::new());
    let connect_router: ConnectRouter = client_credential_service.register(connect_router);
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

    // Create a client credential.
    let create_resp = client
        .post(format!(
            "{base}/iam.v1.ClientCredentialService/CreateClientCredential"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "name": "test-credential",
            "scope": ["tenant:read", "application:read"],
            "tokenEndpointAuthMethod": "client_secret_basic"
        }))
        .send()
        .await
        .expect("create client credential request should succeed");

    assert!(
        create_resp.status().is_success(),
        "create client credential failed: {}",
        create_resp.text().await.unwrap_or_default()
    );

    let credential: serde_json::Value = create_resp
        .json()
        .await
        .expect("client credential should be json");
    let credential_id = credential["id"]
        .as_str()
        .expect("credential id should exist");
    assert_eq!(credential["name"], "test-credential");
    assert_eq!(
        credential["scope"],
        json![["tenant:read", "application:read"]]
    );
    assert_eq!(credential["tokenEndpointAuthMethod"], "client_secret_basic");
    assert!(!credential["clientSecret"].as_str().unwrap_or("").is_empty());

    // Get the credential.
    let get_resp = client
        .post(format!(
            "{base}/iam.v1.ClientCredentialService/GetClientCredential"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": credential_id }))
        .send()
        .await
        .expect("get client credential request should succeed");

    assert!(
        get_resp.status().is_success(),
        "get client credential failed"
    );
    let fetched: serde_json::Value = get_resp
        .json()
        .await
        .expect("client credential should be json");
    assert_eq!(fetched["id"], credential_id);
    assert_eq!(fetched["name"], "test-credential");

    // Update the credential.
    let update_resp = client
        .post(format!(
            "{base}/iam.v1.ClientCredentialService/UpdateClientCredential"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({
            "id": credential_id,
            "name": "test-credential-updated",
            "scope": ["tenant:admin"],
            "tokenEndpointAuthMethod": "client_secret_post"
        }))
        .send()
        .await
        .expect("update client credential request should succeed");

    assert!(
        update_resp.status().is_success(),
        "update client credential failed"
    );
    let updated: serde_json::Value = update_resp
        .json()
        .await
        .expect("client credential should be json");
    assert_eq!(updated["name"], "test-credential-updated");
    assert_eq!(updated["scope"], json![["tenant:admin"]]);
    assert_eq!(updated["tokenEndpointAuthMethod"], "client_secret_post");

    // List credentials.
    let list_resp = client
        .post(format!(
            "{base}/iam.v1.ClientCredentialService/ListClientCredentials"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({}))
        .send()
        .await
        .expect("list client credentials request should succeed");

    assert!(
        list_resp.status().is_success(),
        "list client credentials failed"
    );
    let listed: serde_json::Value = list_resp
        .json()
        .await
        .expect("list response should be json");
    let credentials = listed["clientCredentials"]
        .as_array()
        .expect("clientCredentials array should exist");
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0]["id"], credential_id);

    // Rotate secret.
    let rotate_resp = client
        .post(format!(
            "{base}/iam.v1.ClientCredentialService/RotateClientCredentialSecret"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": credential_id }))
        .send()
        .await
        .expect("rotate client credential secret request should succeed");

    let rotate_status = rotate_resp.status();
    let rotate_body = rotate_resp.text().await.unwrap_or_default();
    assert!(
        rotate_status.is_success(),
        "rotate client credential secret failed: {rotate_body}"
    );
    let rotated: serde_json::Value =
        serde_json::from_str(&rotate_body).expect("secret should be json");
    assert!(!rotated["clientSecret"].as_str().unwrap_or("").is_empty());

    // Delete the credential.
    let delete_resp = client
        .post(format!(
            "{base}/iam.v1.ClientCredentialService/DeleteClientCredential"
        ))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("content-type", "application/json")
        .json(&json!({ "id": credential_id }))
        .send()
        .await
        .expect("delete client credential request should succeed");

    assert!(
        delete_resp.status().is_success(),
        "delete client credential failed"
    );

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
