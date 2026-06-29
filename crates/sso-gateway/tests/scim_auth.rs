use std::sync::Arc;

use axum::Router;
use reqwest::StatusCode;
use serde_json::json;
use sso_gateway::{
    db::{
        DbPool, IdMappingRepo, IdentitySchemaRepo, ScimGroupRepo, bootstrap_system_tenant,
        create_pool,
    },
    scim::{ScimState, router as scim_router},
    services::scim::ScimServiceImpl,
};
use sso_ory_client::{HydraClient, KetoClient, KratosClient};
use tokio::net::TcpListener;

mod support;

fn broken_hydra() -> Arc<HydraClient> {
    Arc::new(
        HydraClient::new("http://localhost:1", "http://localhost:1")
            .expect("broken hydra client should build"),
    )
}

fn fake_kratos() -> Arc<KratosClient> {
    Arc::new(
        KratosClient::new("http://localhost:1").expect("fake kratos client should build"),
    )
}

fn fake_keto() -> Arc<KetoClient> {
    Arc::new(
        KetoClient::new("http://localhost:1", "http://localhost:1")
            .expect("fake keto client should build"),
    )
}

fn scim_state(pool: DbPool, hydra: Arc<HydraClient>) -> Arc<ScimState> {
    let mappings = IdMappingRepo::new(pool.clone());
    let schemas = IdentitySchemaRepo::new(pool.clone());
    let groups = ScimGroupRepo::new(pool);
    let service = Arc::new(ScimServiceImpl::new(
        fake_kratos(),
        fake_keto(),
        mappings.clone(),
        schemas,
        groups,
    ));
    Arc::new(ScimState {
        service,
        hydra,
        mappings,
    })
}

async fn serve(app: Router) -> (tokio::task::JoinHandle<()>, String, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("random port should bind");
    let addr = listener.local_addr().expect("local addr should exist");
    let base = format!("http://{addr}");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server should run");
    });
    (handle, base, shutdown_tx)
}

async fn scim_users_status(base: &str, token: Option<&str>) -> StatusCode {
    let client = reqwest::Client::new();
    let mut request = client.get(format!("{base}/scim/v2/Users"));
    if let Some(t) = token {
        request = request.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
    }
    request
        .send()
        .await
        .expect("scim request should complete")
        .status()
}

#[tokio::test]
async fn scim_auth_error_branches() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");
    let (_hydra, hydra_admin_url, hydra_public_url) =
        support::start_hydra().await.expect("hydra should start");

    let pool = create_pool(&database_url)
        .await
        .expect("database pool should be created");

    let tenant_id = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &tenant_id)
        .await
        .expect("system tenant should bootstrap");

    let hydra = Arc::new(
        HydraClient::new(&hydra_admin_url, &hydra_public_url).expect("hydra client should build"),
    );

    // Create an OAuth2 client directly in Hydra and map it to the test tenant.
    let client_payload = json!({
        "client_name": "scim-auth-test",
        "redirect_uris": ["http://localhost/callback"],
        "grant_types": ["client_credentials"],
        "response_types": ["token"],
        "scope": "openid",
        "token_endpoint_auth_method": "client_secret_post"
    });
    let created = hydra
        .create_oauth2_client(client_payload)
        .await
        .expect("hydra client should be created");
    let client_id = created["client_id"]
        .as_str()
        .expect("client_id should exist");
    let client_secret = created["client_secret"]
        .as_str()
        .expect("client_secret should exist");

    let public_id = ulid::Ulid::new().to_string();
    let mappings = IdMappingRepo::new(pool.clone());
    mappings
        .create(&tenant_id, "hydra", &public_id, client_id)
        .await
        .expect("mapping should be created");

    let token_resp = hydra
        .token(vec![
            ("grant_type".to_string(), "client_credentials".to_string()),
            ("client_id".to_string(), client_id.to_string()),
            ("client_secret".to_string(), client_secret.to_string()),
            ("scope".to_string(), "openid".to_string()),
        ])
        .await
        .expect("token request should succeed");
    let access_token = token_resp["access_token"]
        .as_str()
        .expect("access_token should exist");

    let state = scim_state(pool.clone(), hydra.clone());
    let app = scim_router(state);
    let (handle, base, shutdown_tx) = serve(app).await;

    // Missing authorization header.
    assert_eq!(
        scim_users_status(&base, None).await,
        StatusCode::UNAUTHORIZED
    );

    // Non-Bearer authorization scheme.
    let client = reqwest::Client::new();
    let basic_resp = client
        .get(format!("{base}/scim/v2/Users"))
        .header(reqwest::header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
        .send()
        .await
        .expect("basic auth request should complete");
    assert_eq!(basic_resp.status(), StatusCode::UNAUTHORIZED);

    // Random / malformed bearer token is reported as inactive.
    assert_eq!(
        scim_users_status(&base, Some("not-a-real-token")).await,
        StatusCode::UNAUTHORIZED
    );

    // Revoke the token and confirm SCIM treats it as inactive.
    hydra
        .revoke(vec![
            ("token".to_string(), access_token.to_string()),
            ("client_id".to_string(), client_id.to_string()),
            ("client_secret".to_string(), client_secret.to_string()),
        ])
        .await
        .expect("token should be revoked");
    assert_eq!(
        scim_users_status(&base, Some(access_token)).await,
        StatusCode::UNAUTHORIZED
    );

    // Issue a fresh token and delete the id mapping so the subject is unknown.
    let token_resp = hydra
        .token(vec![
            ("grant_type".to_string(), "client_credentials".to_string()),
            ("client_id".to_string(), client_id.to_string()),
            ("client_secret".to_string(), client_secret.to_string()),
            ("scope".to_string(), "openid".to_string()),
        ])
        .await
        .expect("second token request should succeed");
    let fresh_token = token_resp["access_token"]
        .as_str()
        .expect("access_token should exist");

    mappings
        .delete(&tenant_id, "hydra", &public_id)
        .await
        .expect("mapping should be deleted");
    assert_eq!(
        scim_users_status(&base, Some(fresh_token)).await,
        StatusCode::UNAUTHORIZED
    );

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");

    // A separate router with an unreachable Hydra covers the introspection-failure branch.
    let broken_state = scim_state(pool, broken_hydra());
    let broken_app = scim_router(broken_state);
    let (broken_handle, broken_base, broken_shutdown_tx) = serve(broken_app).await;

    assert_eq!(
        scim_users_status(&broken_base, None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        scim_users_status(&broken_base, Some("any-token")).await,
        StatusCode::UNAUTHORIZED
    );

    let _ = broken_shutdown_tx.send(());
    broken_handle.await.expect("broken server task should finish");
}
