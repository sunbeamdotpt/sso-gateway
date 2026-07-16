use std::sync::Arc;

use axum::{Extension, Router, middleware::from_fn, response::IntoResponse, routing::get};
use sso_gateway::{
    db::{ApplicationRepo, ApplicationStore, IdMappingRepo, IdMappingStore, bootstrap_system_tenant, create_pool},
    middleware::{TenantId, audit_middleware, auth_middleware},
    services::handlers::oauth2::{Oauth2State, router as oauth2_router},
    session_token::SessionTokenSigner,
};
use sso_ory_client::{HydraClient, KratosClient};
use tokio::net::TcpListener;

mod support;

async fn echo(Extension(tenant): Extension<TenantId>) -> impl IntoResponse {
    tenant.0.clone()
}

async fn serve(
    app: Router,
) -> (
    tokio::task::JoinHandle<()>,
    String,
    tokio::sync::oneshot::Sender<()>,
) {
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

#[tokio::test]
async fn auth_middleware_public_path_bypass_and_rejections() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let tenant_id = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &tenant_id)
        .await
        .expect("system tenant should bootstrap");

    support::bootstrap_test_subject_mapping(&pool, &tenant_id).await;

    let hydra = Arc::new(
        HydraClient::new("http://localhost:1", "http://localhost:1")
            .expect("fake hydra client should build"),
    );
    let oauth_state = Arc::new(Oauth2State::new(
        hydra,
        IdMappingRepo::new(pool.clone()),
        "http://localhost".to_string(),
    ));
    let mappings = IdMappingRepo::new(pool.clone());
    let kratos = Arc::new(
        KratosClient::new_with_public("http://localhost:1", "http://localhost:1")
            .expect("fake kratos client should build"),
    );

    let app = Router::new()
        .route("/echo", get(echo))
        .merge(oauth2_router(oauth_state))
        .layer(from_fn(audit_middleware))
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

    let (handle, base, shutdown_tx) = serve(app).await;
    let client = reqwest::Client::new();

    // Public discovery path bypasses API-key / tenant-id checks.
    let public_resp = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .expect("public request should complete");
    assert_eq!(public_resp.status(), reqwest::StatusCode::OK);

    // Protected path without any credentials is rejected.
    let missing_resp = client
        .get(format!("{base}/echo"))
        .send()
        .await
        .expect("missing creds request should complete");
    assert_eq!(missing_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Invalid bearer token is rejected.
    let bad_token_resp = client
        .get(format!("{base}/echo"))
        .header("authorization", "Bearer invalid-token")
        .send()
        .await
        .expect("bad token request should complete");
    assert_eq!(bad_token_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Valid bearer token resolves the tenant and reaches the handler.
    let token_resp = client
        .get(format!("{base}/echo"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .send()
        .await
        .expect("valid token request should complete");
    assert_eq!(token_resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        token_resp.text().await.expect("body should be text"),
        tenant_id
    );

    // Legacy tenant header is no longer accepted on its own.
    let tenant_resp = client
        .get(format!("{base}/echo"))
        .header("x-tenant-id", &tenant_id)
        .send()
        .await
        .expect("tenant header request should complete");
    assert_eq!(tenant_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}

#[tokio::test]
async fn cross_tenant_header_routes_to_target_tenant() {
    let (_pg, database_url) = support::start_postgres()
        .await
        .expect("postgres should start");

    let pool = create_pool(&database_url, false)
        .await
        .expect("database pool should be created");

    let tenant_id = ulid::Ulid::new().to_string();
    bootstrap_system_tenant(&pool, &tenant_id)
        .await
        .expect("system tenant should bootstrap");
    support::bootstrap_test_subject_mapping(&pool, &tenant_id).await;

    let apps = ApplicationRepo::new(pool.clone());
    apps.create(&tenant_id, support::TEST_SUBJECT, true)
        .await
        .expect("cross-tenant application should be created");

    let hydra = Arc::new(
        HydraClient::new("http://localhost:1", "http://localhost:1")
            .expect("fake hydra client should build"),
    );
    let oauth_state = Arc::new(Oauth2State::new(
        hydra,
        IdMappingRepo::new(pool.clone()),
        "http://localhost".to_string(),
    ));
    let mappings = IdMappingRepo::new(pool.clone());
    let kratos = Arc::new(
        KratosClient::new_with_public("http://localhost:1", "http://localhost:1")
            .expect("fake kratos client should build"),
    );

    let app = Router::new()
        .route("/echo", get(echo))
        .merge(oauth2_router(oauth_state))
        .layer(from_fn(audit_middleware))
        .layer(from_fn(auth_middleware))
        .layer(Extension(SessionTokenSigner::new(
            "test-secret-that-is-at-least-32-bytes-long",
            3600,
            "https://gateway.example.com",
        )))
        .layer(Extension(support::test_introspector()))
        .layer(Extension(support::test_session_store()))
        .layer(Extension(kratos))
        .layer(Extension(Arc::new(mappings) as Arc<dyn IdMappingStore>))
        .layer(Extension(Arc::new(apps) as Arc<dyn ApplicationStore>));

    let (handle, base, shutdown_tx) = serve(app).await;
    let client = reqwest::Client::new();

    let target_tenant = ulid::Ulid::new().to_string();
    let cross_tenant_resp = client
        .get(format!("{base}/echo"))
        .header("authorization", format!("Bearer {}", support::TEST_TOKEN))
        .header("x-tenant-id", &target_tenant)
        .send()
        .await
        .expect("cross-tenant request should complete");
    assert_eq!(cross_tenant_resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        cross_tenant_resp.text().await.expect("body should be text"),
        target_tenant
    );

    let _ = shutdown_tx.send(());
    handle.await.expect("server task should finish");
}
